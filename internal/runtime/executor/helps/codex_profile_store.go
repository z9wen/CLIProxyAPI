package helps

import (
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	tls "github.com/refraction-networking/utls"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/util"
	log "github.com/sirupsen/logrus"
)

// Captured ClientHello profiles live beside the configuration as raw records.
//
// Storing the record rather than a Go literal is what makes a capture applicable
// without a rebuild: uTLS turns it back into a ClientHelloSpec here, with the same
// Fingerprinter tools/codexfp uses. Storing a spec directly is not an option —
// it carries function fields and unexported methods, so it does not round-trip
// through JSON.
//
// Whatever the files contain replaces the built-in specs. That is the intended
// effect: once a capture exists it is authoritative, because it came from the
// client this proxy is standing in for.
const (
	// CodexProfileHTTPFile is the HTTP/SSE path's captured ClientHello.
	CodexProfileHTTPFile = "codex-http-clienthello.bin"
	// CodexProfileWebSocketFile is the primary WebSocket capture. Additional
	// samples sit beside it; see CodexProfileWebSocketGlob.
	CodexProfileWebSocketFile = "codex-websocket-clienthello.bin"
	// CodexProfileWebSocketGlob matches every captured WebSocket handshake.
	//
	// One capture is one ordering, and the WebSocket transport needs several: the
	// client it reproduces runs rustls, which reorders its extensions on every
	// connection, so a replay that sends one fixed order gives every handshake the
	// same JA3 while a real client's changes each time. The primary capture is the
	// one whose extension order is regenerated per handshake; the samples beside
	// it each record another order the client really emitted, and serve as the
	// fallback when no order can be drawn.
	CodexProfileWebSocketGlob = "codex-websocket-clienthello*.bin"
	// CodexProfileWebSocketSampleFormat names the samples after the first, which
	// is CodexProfileWebSocketFile.
	CodexProfileWebSocketSampleFormat = "codex-websocket-clienthello.%d.bin"
)

type codexProfileKind int

const (
	codexProfileHTTP codexProfileKind = iota
	codexProfileWebSocket
)

func (k codexProfileKind) fileName() string {
	if k == codexProfileWebSocket {
		return CodexProfileWebSocketFile
	}
	return CodexProfileHTTPFile
}

func (k codexProfileKind) label() string {
	if k == codexProfileWebSocket {
		return "websocket"
	}
	return "http"
}

var (
	codexProfileMu  sync.RWMutex
	codexProfileDir string
	// codexProfileHTTPSpec is the HTTP/SSE path's profile. That path runs OpenSSL,
	// which orders its extensions deterministically — three captures of the real
	// client agreed byte for byte — so one capture describes it completely.
	codexProfileHTTPSpec *tls.ClientHelloSpec
	// codexProfileWebSockets is every captured WebSocket handshake, one ordering
	// each. See CodexProfileWebSocketGlob.
	codexProfileWebSockets []*tls.ClientHelloSpec
	// codexProfileWebSocketRaw is the primary capture as the raw record. The
	// WebSocket path re-derives its extension order from these bytes for every
	// handshake, which needs the types still on the wire; a parsed spec has
	// already turned them into typed extensions. See codex_hello_order.go.
	codexProfileWebSocketRaw []byte
)

// CodexProfileDir returns the directory captured profiles are read from, or ""
// when none has been configured.
func CodexProfileDir() string {
	codexProfileMu.RLock()
	defer codexProfileMu.RUnlock()
	return codexProfileDir
}

// DefaultCodexProfileDir resolves where captures are stored, mirroring the
// management asset directory so a deployment keeps both beside its writable path.
// CODEX_PROFILE_PATH overrides it.
func DefaultCodexProfileDir(configFilePath string) string {
	if override := strings.TrimSpace(os.Getenv("CODEX_PROFILE_PATH")); override != "" {
		return filepath.Clean(override)
	}
	if writable := util.WritablePath(); writable != "" {
		return filepath.Join(writable, "codex-profile")
	}
	configFilePath = strings.TrimSpace(configFilePath)
	if configFilePath == "" {
		return ""
	}
	return filepath.Join(filepath.Dir(configFilePath), "codex-profile")
}

// SetCodexProfileDir points the loader at the directory holding captured
// profiles and loads whatever is already there.
//
// An empty directory, or one without captures, leaves the built-in specs in
// place. A capture that fails to parse is reported and ignored rather than
// aborting startup: the built-in profile is a working fallback, and refusing to
// serve because a file is corrupt would be worse than serving with it.
func SetCodexProfileDir(dir string) error {
	codexProfileMu.Lock()
	codexProfileDir = dir
	codexProfileMu.Unlock()
	return ReloadCodexProfiles()
}

// ReloadCodexProfiles re-reads the profile directory, so a capture applies
// without a restart.
func ReloadCodexProfiles() error {
	codexProfileMu.RLock()
	dir := codexProfileDir
	codexProfileMu.RUnlock()
	if dir == "" {
		return nil
	}

	var firstErr error
	httpSpec, errHTTP := loadCodexProfileFile(filepath.Join(dir, codexProfileHTTP.fileName()))
	if errHTTP != nil {
		if !errors.Is(errHTTP, os.ErrNotExist) {
			firstErr = errHTTP
		}
		httpSpec = nil
	}

	webSockets, errWebSockets := loadCodexWebSocketProfiles(dir)
	if errWebSockets != nil && firstErr == nil {
		firstErr = errWebSockets
	}

	var webSocketRaw []byte
	if loaded, errRead := os.ReadFile(filepath.Join(dir, CodexProfileWebSocketFile)); errRead == nil {
		webSocketRaw = loaded
	}

	codexProfileMu.Lock()
	codexProfileHTTPSpec = httpSpec
	codexProfileWebSockets = webSockets
	codexProfileWebSocketRaw = webSocketRaw
	codexProfileMu.Unlock()

	if httpSpec != nil || len(webSockets) > 0 {
		kinds := make([]string, 0, 2)
		if httpSpec != nil {
			kinds = append(kinds, codexProfileHTTP.label())
		}
		if len(webSockets) > 0 {
			kinds = append(kinds, fmt.Sprintf("%s x%d", codexProfileWebSocket.label(), len(webSockets)))
		}
		log.Infof("codex tls: using captured ClientHello profiles from %s (%s)", dir, strings.Join(kinds, ", "))
	}
	return firstErr
}

// loadCodexWebSocketProfiles reads every captured WebSocket handshake, in a
// stable order so a given deployment rotates through the same set.
func loadCodexWebSocketProfiles(dir string) ([]*tls.ClientHelloSpec, error) {
	matches, errGlob := filepath.Glob(filepath.Join(dir, CodexProfileWebSocketGlob))
	if errGlob != nil {
		return nil, fmt.Errorf("codex tls: scan %s: %w", dir, errGlob)
	}
	sort.Strings(matches)

	specs := make([]*tls.ClientHelloSpec, 0, len(matches))
	var firstErr error
	for _, path := range matches {
		spec, errLoad := loadCodexProfileFile(path)
		if errLoad != nil {
			// One unreadable sample must not cost the others: they are independent
			// orderings of the same handshake.
			if firstErr == nil {
				firstErr = errLoad
			}
			continue
		}
		specs = append(specs, spec)
	}
	return specs, firstErr
}

// capturedCodexWebSocketProfile returns a WebSocket profile carrying an
// extension order drawn for this handshake, or nil when the built-in should be
// used. Callers must not cache the result: it is a per-handshake choice.
//
// The order is regenerated rather than replayed, because the client this
// reproduces draws a fresh one per connection: rotating over a fixed set of
// captures removed the constant but still only ever sent a handful of the
// orderings a real client produces. See codex_hello_order.go.
func capturedCodexWebSocketProfile() *tls.ClientHelloSpec {
	codexProfileMu.RLock()
	raw := codexProfileWebSocketRaw
	samples := codexProfileWebSockets
	codexProfileMu.RUnlock()

	if spec := codexWebSocketProfileWithDrawnOrder(raw); spec != nil {
		return spec
	}
	// No usable raw capture: send one of the captured orderings verbatim, which
	// is still the client's own, in preference to the built-in literal.
	if len(samples) == 0 {
		return nil
	}
	index, errRand := rand.Int(rand.Reader, big.NewInt(int64(len(samples))))
	if errRand != nil {
		log.Debugf("codex tls: choose a WebSocket profile: %v", errRand)
		return cloneClientHelloSpec(samples[0])
	}
	return cloneClientHelloSpec(samples[index.Int64()])
}

// codexWebSocketProfileWithDrawnOrder rewrites the captured record's extension
// order for one handshake. It returns nil when the record cannot be used, so the
// caller can fall back instead of failing the connection.
func codexWebSocketProfileWithDrawnOrder(raw []byte) *tls.ClientHelloSpec {
	if len(raw) == 0 {
		return nil
	}
	seed, errSeed := randomRustlsOrderSeed()
	if errSeed != nil {
		log.Debugf("codex tls: draw a WebSocket extension order: %v", errSeed)
		return nil
	}
	reordered, errOrder := reorderClientHelloExtensions(raw, seed)
	if errOrder != nil {
		log.Debugf("codex tls: reorder WebSocket extensions: %v", errOrder)
		return nil
	}
	spec, errFingerprint := (&tls.Fingerprinter{AllowBluntMimicry: true}).FingerprintClientHello(reordered)
	if errFingerprint != nil {
		log.Debugf("codex tls: reordered WebSocket profile is not a ClientHello: %v", errFingerprint)
		return nil
	}
	return spec
}

// capturedCodexProfile returns the captured spec for a path, or nil when the
// built-in one should be used.
func capturedCodexProfile(kind codexProfileKind) *tls.ClientHelloSpec {
	if kind == codexProfileWebSocket {
		return capturedCodexWebSocketProfile()
	}
	codexProfileMu.RLock()
	defer codexProfileMu.RUnlock()
	// Copied on the way out: see cloneClientHelloSpec. Handing the cached one to
	// uTLS would let the first handshake fill in its key shares, and every later
	// one would then replay that first connection's keys.
	return cloneClientHelloSpec(codexProfileHTTPSpec)
}

func loadCodexProfileFile(path string) (*tls.ClientHelloSpec, error) {
	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		return nil, errRead
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("codex tls: profile %s is empty", filepath.Base(path))
	}
	spec, errFingerprint := (&tls.Fingerprinter{AllowBluntMimicry: true}).FingerprintClientHello(raw)
	if errFingerprint != nil {
		return nil, fmt.Errorf("codex tls: profile %s is not a ClientHello: %w", filepath.Base(path), errFingerprint)
	}
	return spec, nil
}
