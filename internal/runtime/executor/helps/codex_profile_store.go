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
	// same JA3 while a real client's changes each time. Rotating among real
	// captures keeps that spread without inventing an order no client would send.
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

	codexProfileMu.Lock()
	codexProfileHTTPSpec = httpSpec
	codexProfileWebSockets = webSockets
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

// capturedCodexWebSocketProfile returns one captured WebSocket profile, chosen
// at random when several are present, or nil when the built-in should be used.
func capturedCodexWebSocketProfile() *tls.ClientHelloSpec {
	codexProfileMu.RLock()
	defer codexProfileMu.RUnlock()
	if len(codexProfileWebSockets) == 0 {
		return nil
	}
	if len(codexProfileWebSockets) == 1 {
		return codexProfileWebSockets[0]
	}
	index, errRand := rand.Int(rand.Reader, big.NewInt(int64(len(codexProfileWebSockets))))
	if errRand != nil {
		// Every sample is a valid handshake, so a failed draw is not a reason to
		// fall back to the built-in one.
		log.Debugf("codex tls: choose a WebSocket profile: %v", errRand)
		return codexProfileWebSockets[0]
	}
	return codexProfileWebSockets[index.Int64()]
}

// capturedCodexProfile returns the captured spec for a path, or nil when the
// built-in one should be used.
func capturedCodexProfile(kind codexProfileKind) *tls.ClientHelloSpec {
	if kind == codexProfileWebSocket {
		return capturedCodexWebSocketProfile()
	}
	codexProfileMu.RLock()
	defer codexProfileMu.RUnlock()
	return codexProfileHTTPSpec
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
