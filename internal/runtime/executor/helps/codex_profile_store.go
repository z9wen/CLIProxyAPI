package helps

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	// CodexProfileWebSocketFile is the WebSocket path's captured ClientHello.
	CodexProfileWebSocketFile = "codex-websocket-clienthello.bin"
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
	codexProfileMu       sync.RWMutex
	codexProfileDir      string
	codexProfileCaptured map[codexProfileKind]*tls.ClientHelloSpec
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

	loaded := make(map[codexProfileKind]*tls.ClientHelloSpec)
	var firstErr error
	for _, kind := range []codexProfileKind{codexProfileHTTP, codexProfileWebSocket} {
		spec, err := loadCodexProfileFile(filepath.Join(dir, kind.fileName()))
		if err != nil {
			if !errors.Is(err, os.ErrNotExist) && firstErr == nil {
				firstErr = err
			}
			continue
		}
		loaded[kind] = spec
	}

	codexProfileMu.Lock()
	codexProfileCaptured = loaded
	codexProfileMu.Unlock()

	if len(loaded) > 0 {
		kinds := make([]string, 0, len(loaded))
		for kind := range loaded {
			kinds = append(kinds, kind.label())
		}
		log.Infof("codex tls: using captured ClientHello profiles from %s (%v)", dir, kinds)
	}
	return firstErr
}

// capturedCodexProfile returns the captured spec for a path, or nil when the
// built-in one should be used.
func capturedCodexProfile(kind codexProfileKind) *tls.ClientHelloSpec {
	codexProfileMu.RLock()
	defer codexProfileMu.RUnlock()
	return codexProfileCaptured[kind]
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
