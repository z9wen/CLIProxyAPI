package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"

	log "github.com/sirupsen/logrus"
)

// CodexProfileBaseline identifies the Codex release whose handshake the captured
// profiles currently in force reproduce.
//
// The release version is only half of it: the TLS dependencies decide the shape
// of the ClientHello, so they are what a drift check compares against. See
// warnIfCodexTLSStackDrifted.
type CodexProfileBaseline struct {
	Version    string `json:"version"`
	OpenSSLSys string `json:"openssl_sys"`
	Rustls     string `json:"rustls"`
}

// CodexProfileBaselineFile records the baseline beside the captures themselves.
//
// It is persisted rather than kept in memory because the freeze it exists to
// lift survives restarts: without a record on disk, a re-captured install would
// come back up on the compiled-in pins, decide the release it just captured from
// has drifted, and hold the advertised version back again.
const CodexProfileBaselineFile = "codex-profile.json"

// codexProfileBaseline is the live baseline, seeded from the compiled-in
// constants and moved by a capture. See AdoptCodexProfileBaseline.
var codexProfileBaseline atomic.Value // CodexProfileBaseline

// codexProfileBaselineDir is where a capture records its baseline, empty when
// none has been configured.
var codexProfileBaselineDir atomic.Value // string

// BuiltinCodexProfileBaseline is the release the profiles compiled into this
// binary were captured from.
//
// It is the correct starting point for an install that has never captured, and
// the value a capture supersedes.
func BuiltinCodexProfileBaseline() CodexProfileBaseline {
	return CodexProfileBaseline{
		Version:    CodexProfileVersion,
		OpenSSLSys: codexProfileBuiltinOpenSSLSys,
		Rustls:     codexProfileBuiltinRustls,
	}
}

// CurrentCodexProfileBaseline returns the baseline the profiles in force
// describe: the compiled-in one until a capture replaces it.
func CurrentCodexProfileBaseline() CodexProfileBaseline {
	if baseline, ok := codexProfileBaseline.Load().(CodexProfileBaseline); ok {
		return baseline
	}
	return BuiltinCodexProfileBaseline()
}

// matches reports whether a release's resolved TLS stack is the one this
// baseline was captured from.
func (b CodexProfileBaseline) matches(stack codexTLSStack) bool {
	return singleVersionEquals(stack.OpenSSLSys, b.OpenSSLSys) &&
		singleVersionEquals(stack.Rustls, b.Rustls)
}

// LookupCodexProfileBaseline reads which TLS dependencies a release resolved to,
// which is what a capture needs to record a usable baseline for the release it
// captured.
//
// The versions come from the release's Cargo.lock rather than from the capture
// itself: a ClientHello shows the shape of a handshake, not the crate versions
// that produced it.
func LookupCodexProfileBaseline(ctx context.Context, version string) (CodexProfileBaseline, error) {
	version = strings.TrimSpace(version)
	if !isCodexVersion(version) {
		return CodexProfileBaseline{}, fmt.Errorf("codex: %q is not a usable release version", version)
	}
	stack, errStack := fetchCodexTLSStack(ctx, "rust-v"+version)
	if errStack != nil {
		return CodexProfileBaseline{}, fmt.Errorf("codex: read the TLS stack for %s: %w", version, errStack)
	}
	// A baseline names one version per crate. A lock that resolved several is
	// mid-upgrade, and picking one of them would pin a baseline that may never
	// have been built.
	if len(stack.OpenSSLSys) != 1 || len(stack.Rustls) != 1 {
		return CodexProfileBaseline{}, fmt.Errorf(
			"codex: release %s resolved openssl-sys %v / rustls %v; a baseline needs exactly one of each",
			version, stack.OpenSSLSys, stack.Rustls)
	}
	return CodexProfileBaseline{
		Version:    version,
		OpenSSLSys: stack.OpenSSLSys[0],
		Rustls:     stack.Rustls[0],
	}, nil
}

// SetCodexProfileBaselineDir points the baseline at the directory holding the
// captures and adopts the baseline a previous capture recorded there.
//
// A missing record is not an error: an install that has never captured is
// correctly described by the compiled-in baseline.
func SetCodexProfileBaselineDir(dir string) error {
	dir = strings.TrimSpace(dir)
	codexProfileBaselineDir.Store(dir)
	if dir == "" {
		return nil
	}
	path := filepath.Join(dir, CodexProfileBaselineFile)
	raw, errRead := os.ReadFile(path)
	if errRead != nil {
		if errors.Is(errRead, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("codex: read %s: %w", path, errRead)
	}
	var baseline CodexProfileBaseline
	if errUnmarshal := json.Unmarshal(raw, &baseline); errUnmarshal != nil {
		return fmt.Errorf("codex: parse %s: %w", path, errUnmarshal)
	}
	// Already on disk: adopt the values, do not write them back.
	return adoptCodexProfileBaseline(baseline, false)
}

// AdoptCodexProfileBaseline records that the captured profiles now describe
// baseline, which is what a successful capture establishes.
//
// This is the other half of the freeze in warnIfCodexTLSStackDrifted. A capture
// that only wrote profile files would leave the drift check comparing the
// release it captured from against the old pins, so the check would keep
// freezing the advertised version and the panel would keep reporting a stale
// profile — the refresh button would appear to do nothing. Moving the baseline
// with the profiles is what makes the two agree again.
func AdoptCodexProfileBaseline(baseline CodexProfileBaseline) error {
	return adoptCodexProfileBaseline(baseline, true)
}

func adoptCodexProfileBaseline(baseline CodexProfileBaseline, persist bool) error {
	baseline.Version = strings.TrimSpace(baseline.Version)
	baseline.OpenSSLSys = strings.TrimSpace(baseline.OpenSSLSys)
	baseline.Rustls = strings.TrimSpace(baseline.Rustls)
	if !isCodexVersion(baseline.Version) || baseline.OpenSSLSys == "" || baseline.Rustls == "" {
		return fmt.Errorf("codex: refusing an unusable profile baseline (%+v)", baseline)
	}

	codexProfileBaseline.Store(baseline)
	// The profiles were captured from this release, so claiming its version is
	// accurate and the identity is coherent again.
	codexProfileCurrent.Store(true)
	codexClientVersion.Store(baseline.Version)
	// A later drift on this same version is a new event and must warn again.
	codexDriftWarned.Clear()

	log.Infof("codex: profile baseline is now %s (openssl-sys %s / rustls %s)",
		baseline.Version, baseline.OpenSSLSys, baseline.Rustls)

	if !persist {
		return nil
	}
	if errPersist := persistCodexProfileBaseline(baseline); errPersist != nil {
		return errPersist
	}
	return nil
}

func persistCodexProfileBaseline(baseline CodexProfileBaseline) error {
	dir, _ := codexProfileBaselineDir.Load().(string)
	if strings.TrimSpace(dir) == "" {
		// Nothing was configured to persist to; runtime state still moved.
		return nil
	}
	raw, errMarshal := json.MarshalIndent(baseline, "", "  ")
	if errMarshal != nil {
		return fmt.Errorf("codex: encode profile baseline: %w", errMarshal)
	}
	raw = append(raw, '\n')
	path := filepath.Join(dir, CodexProfileBaselineFile)
	if errWrite := os.WriteFile(path, raw, 0o600); errWrite != nil {
		return fmt.Errorf("codex: write %s: %w", path, errWrite)
	}
	return nil
}
