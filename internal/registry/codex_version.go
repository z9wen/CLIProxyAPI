package registry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/tidwall/gjson"
)

// CodexProfileVersion is the Codex release the captured TLS profile in
// internal/runtime/executor/helps was taken from, and the version the rest of
// the wire identity is written against.
//
// Bump it only alongside a fresh capture (tools/codexfp), because the advertised
// version and the handshake have to describe the same build: a client that
// claims a release whose ClientHello the proxy does not reproduce is precisely
// the mismatch this machinery exists to remove.
const CodexProfileVersion = "0.154.0"

// codexProfileBuiltinOpenSSLSys and codexProfileBuiltinRustls pin the TLS
// dependencies the ClientHello profiles compiled into this binary came from.
//
// These, not the release version, decide when a re-capture is due. The Codex
// client iterates quickly — releases land constantly — but its TLS stack does
// not move with them: openssl-sys 0.9.111 and rustls 0.23.36 were unchanged
// across at least rust-v0.150.0 through rust-v0.154.0. Warning on every release
// would be noise, and noise gets ignored.
//
// They seed the baseline a never-captured install starts on. A capture
// supersedes them at runtime; see CodexProfileBaseline.
const (
	codexProfileBuiltinOpenSSLSys = "0.9.111"
	codexProfileBuiltinRustls     = "0.23.36"
)

// codexLockURLTemplate fetches a release's Cargo.lock. That file is a few
// hundred kilobytes, so the check costs a request rather than the ~90 MB the
// release binary would.
const codexLockURLTemplate = "https://raw.githubusercontent.com/openai/codex/%s/codex-rs/Cargo.lock"

const maxCodexLockBody = 4 << 20

// codexLockPackagePattern matches a Cargo.lock [[package]] block's name and
// version, which are adjacent lines.
var codexLockPackagePattern = regexp.MustCompile(`(?m)^name = "([^"]+)"\nversion = "([^"]+)"`)

// codexTLSStack is the part of a release's dependency set that determines the
// shape of its ClientHello. Each crate keeps every version the lock resolved,
// not just one.
type codexTLSStack struct {
	OpenSSLSys []string
	Rustls     []string
}

// singleVersionEquals reports whether a crate resolved to exactly the pinned
// version.
//
// Requiring a single resolution matters: mid-upgrade a lock can carry both the
// old and the new version, and accepting the old one because it is still present
// would be a false negative at precisely the moment the profile went stale.
func singleVersionEquals(versions []string, want string) bool {
	return len(versions) == 1 && versions[0] == want
}

// String renders the resolved versions for the drift warning.
func (s codexTLSStack) String() string {
	return fmt.Sprintf("openssl-sys %s / rustls %s",
		strings.Join(s.OpenSSLSys, "+"), strings.Join(s.Rustls, "+"))
}

// fetchCodexTLSStack reads the TLS dependency versions for a release tag such as
// "rust-v0.155.0". An HTTP or parse failure is not fatal: the caller keeps the
// current version and simply cannot tell whether a re-capture is due.
func fetchCodexTLSStack(ctx context.Context, tag string) (codexTLSStack, error) {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return codexTLSStack{}, errors.New("empty release tag")
	}
	reqCtx, cancel := context.WithTimeout(ctx, codexVersionFetchTimeout)
	defer cancel()

	req, errRequest := http.NewRequestWithContext(reqCtx, http.MethodGet, fmt.Sprintf(codexLockURLTemplate, tag), nil)
	if errRequest != nil {
		return codexTLSStack{}, fmt.Errorf("build request: %w", errRequest)
	}
	resp, errDo := (&http.Client{Timeout: codexVersionFetchTimeout}).Do(req)
	if errDo != nil {
		return codexTLSStack{}, fmt.Errorf("request: %w", errDo)
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Debugf("codex version: close Cargo.lock response: %v", errClose)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return codexTLSStack{}, fmt.Errorf("status %d", resp.StatusCode)
	}
	body, errRead := io.ReadAll(io.LimitReader(resp.Body, maxCodexLockBody))
	if errRead != nil {
		return codexTLSStack{}, fmt.Errorf("read body: %w", errRead)
	}
	return parseCodexTLSStack(body)
}

// parseCodexTLSStack pulls the two versions that decide the ClientHello shape
// out of a Cargo.lock document.
func parseCodexTLSStack(body []byte) (codexTLSStack, error) {
	var stack codexTLSStack
	for _, match := range codexLockPackagePattern.FindAllSubmatch(body, -1) {
		version := string(match[2])
		switch string(match[1]) {
		case "openssl-sys":
			stack.OpenSSLSys = append(stack.OpenSSLSys, version)
		case "rustls":
			stack.Rustls = append(stack.Rustls, version)
		}
	}
	if len(stack.OpenSSLSys) == 0 && len(stack.Rustls) == 0 {
		return codexTLSStack{}, errors.New("neither openssl-sys nor rustls found")
	}
	return stack, nil
}

const (
	// The releases page redirects to the tag, so the tag can be read without the
	// API's rate limit. codexReleaseAPIPath is the fallback.
	codexLatestReleaseURL = "https://github.com/openai/codex/releases/latest"
	codexReleaseAPIPath   = "https://api.github.com/repos/openai/codex/releases/latest"

	codexVersionFetchTimeout = 15 * time.Second
	// Daily. Polling more often buys very little: a version a few hours behind is
	// indistinguishable from a real user who has not upgraded yet, and real users
	// lag by days. The same pass also re-reads the release's TLS stack, which is
	// what actually decides whether a re-capture is due.
	codexVersionRefreshInterval = 24 * time.Hour
	maxCodexReleaseBody         = 1 << 20
)

// codexReleaseTagPattern matches the tag a release is published under, e.g.
// "rust-v0.154.0".
var codexReleaseTagPattern = regexp.MustCompile(`^rust-v(\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?)$`)

// codexVersionPattern validates a bare version string before it is advertised.
var codexVersionPattern = regexp.MustCompile(`^\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?$`)

// codexClientVersion holds the version advertised in the User-Agent and the
// version header. It starts at the captured profile version and follows upstream
// releases from there.
var codexClientVersion atomic.Value

// codexProfileCurrent records whether the newest release still uses the TLS stack
// the captured profiles came from.
//
// While it holds, the advertised version may advance: an unchanged stack means
// the release handshakes exactly like the captured one, so claiming its version
// is accurate. Once it stops holding, the version is held at CodexProfileVersion,
// because advancing it would advertise a release whose handshake this proxy does
// not reproduce — the very incoherence these profiles exist to remove. Staying
// put instead reads as a user who has not upgraded, which is unremarkable.
var codexProfileCurrent atomic.Bool

func init() {
	codexProfileBaseline.Store(BuiltinCodexProfileBaseline())
	codexClientVersion.Store(CodexProfileVersion)
	// True by construction: the pinned version is the one that was captured.
	codexProfileCurrent.Store(true)
}

// CodexClientVersion returns the Codex release the wire identity advertises.
func CodexClientVersion() string {
	baseline := CurrentCodexProfileBaseline()
	if !codexProfileCurrent.Load() {
		return baseline.Version
	}
	if version, ok := codexClientVersion.Load().(string); ok && version != "" {
		return version
	}
	return baseline.Version
}

// CodexProfileIsCurrent reports whether the advertised identity still describes
// the handshake this proxy sends.
func CodexProfileIsCurrent() bool {
	return codexProfileCurrent.Load()
}

// codexDriftWarned deduplicates the profile-drift warning. The updater runs on a
// timer, so warning on every pass would turn one stale capture into a log flood.
var codexDriftWarned sync.Map

// SetCodexClientVersion records the version to advertise. Empty and
// unparseable values are ignored so a bad fetch can never blank the identity.
func SetCodexClientVersion(version string) {
	version = strings.TrimSpace(version)
	if version == "" || !isCodexVersion(version) {
		return
	}
	if CodexClientVersion() == version {
		return
	}
	baseline := CurrentCodexProfileBaseline()
	if !codexProfileCurrent.Load() {
		log.Debugf("codex: ignoring version %s; the advertised version is held at %s until the profile is re-captured",
			version, baseline.Version)
		return
	}
	codexClientVersion.Store(version)

	if version != baseline.Version {
		// No warning here. A new release does not mean the profile is stale: the
		// TLS stack moves far more slowly than the release cadence, and warning on
		// every release produces noise that gets ignored. refreshCodexVersion
		// reads the stack itself and warns only when the profiles really are out
		// of date.
		log.Infof("codex: advertising %s, profile captured from %s", version, baseline.Version)
	}
}

func isCodexVersion(version string) bool {
	return codexVersionPattern.MatchString(version)
}

var codexVersionUpdaterOnce sync.Once

// StartCodexVersionUpdater follows the latest Codex release so the advertised
// version does not go stale when a release lands. Safe to call multiple times;
// only one updater will run.
func StartCodexVersionUpdater(ctx context.Context) {
	codexVersionUpdaterOnce.Do(func() {
		go runCodexVersionUpdater(ctx)
	})
}

func runCodexVersionUpdater(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	refreshCodexVersion(ctx, "startup Codex version refresh")

	ticker := time.NewTicker(codexVersionRefreshInterval)
	defer ticker.Stop()
	log.Infof("periodic Codex version refresh started (interval=%s)", codexVersionRefreshInterval)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			refreshCodexVersion(ctx, "periodic Codex version refresh")
		}
	}
}

func refreshCodexVersion(ctx context.Context, label string) {
	version, source, err := fetchLatestCodexVersion(ctx)
	if err != nil {
		log.Warnf("%s: %v; keeping current version %s", label, err, CodexClientVersion())
		return
	}
	// Checked before advancing: a drifted stack freezes the version, and doing it
	// the other way round would briefly advertise an identity we cannot back up.
	warnIfCodexTLSStackDrifted(ctx, version)

	if CodexClientVersion() == version {
		log.Infof("%s completed from %s, already at %s", label, source, version)
		return
	}
	SetCodexClientVersion(version)
	log.Infof("%s completed from %s, now advertising %s", label, source, version)
}

// warnIfCodexTLSStackDrifted reports when a release's TLS dependencies no longer
// match the ones the captured profiles came from.
//
// This, not the release version, is the signal that a re-capture is due. It
// costs one Cargo.lock fetch, and a lookup failure only means the check could
// not run — never that the profile is fine.
func warnIfCodexTLSStackDrifted(ctx context.Context, version string) {
	stack, errStack := fetchCodexTLSStack(ctx, "rust-v"+version)
	if errStack != nil {
		log.Debugf("codex: could not read the TLS stack for %s: %v", version, errStack)
		return
	}
	baseline := CurrentCodexProfileBaseline()
	if baseline.matches(stack) {
		return
	}
	// Freeze before warning so the identity is coherent even if the log is missed.
	codexProfileCurrent.Store(false)
	if _, warned := codexDriftWarned.LoadOrStore(version, struct{}{}); warned {
		return
	}
	log.Warnf("codex: holding the advertised version at %s; %s ships %s, but the profiles were captured from "+
		"openssl-sys %s / rustls %s. Re-capture from the management panel's Codex profile notice, or with "+
		"tools/codexfp (see tools/codexfp/README.md); until then this proxy keeps claiming %s, which is coherent "+
		"but older than upstream.",
		baseline.Version, version, stack, baseline.OpenSSLSys, baseline.Rustls, baseline.Version)
}

// LatestCodexRelease returns the newest published Codex release version.
//
// A capture targets this rather than the advertised version. The advertised one
// is held back exactly when the profiles are behind, so capturing it again would
// reproduce the handshake already in place and leave the drift in force.
func LatestCodexRelease(ctx context.Context) (string, error) {
	version, _, errVersion := fetchLatestCodexVersion(ctx)
	if errVersion != nil {
		return "", fmt.Errorf("codex: look up the latest release: %w", errVersion)
	}
	return version, nil
}

func fetchLatestCodexVersion(ctx context.Context) (string, string, error) {
	redirectTag, errRedirect := fetchCodexTagFromRedirect(ctx)
	if errRedirect == nil {
		return redirectTag, codexLatestReleaseURL, nil
	}
	apiTag, errAPI := fetchCodexTagFromAPI(ctx)
	if errAPI == nil {
		return apiTag, codexReleaseAPIPath, nil
	}
	return "", "", fmt.Errorf("release lookup failed (redirect: %v; api: %v)", errRedirect, errAPI)
}

// fetchCodexTagFromRedirect reads the tag out of the releases/latest redirect.
// It costs no API quota, which matters because the alternative is rate limited
// per address.
func fetchCodexTagFromRedirect(ctx context.Context) (string, error) {
	client := &http.Client{
		Timeout: codexVersionFetchTimeout,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	reqCtx, cancel := context.WithTimeout(ctx, codexVersionFetchTimeout)
	defer cancel()

	req, errRequest := http.NewRequestWithContext(reqCtx, http.MethodGet, codexLatestReleaseURL, nil)
	if errRequest != nil {
		return "", fmt.Errorf("build request: %w", errRequest)
	}
	resp, errDo := client.Do(req)
	if errDo != nil {
		return "", fmt.Errorf("request: %w", errDo)
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Debugf("codex version: close redirect response: %v", errClose)
		}
	}()

	location := strings.TrimSpace(resp.Header.Get("Location"))
	if location == "" {
		return "", fmt.Errorf("no Location header (status %d)", resp.StatusCode)
	}
	parsed, errParse := url.Parse(location)
	if errParse != nil {
		return "", fmt.Errorf("parse Location %q: %w", location, errParse)
	}
	tag := parsed.Path[strings.LastIndex(parsed.Path, "/")+1:]
	return parseCodexReleaseTag(tag)
}

func fetchCodexTagFromAPI(ctx context.Context) (string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, codexVersionFetchTimeout)
	defer cancel()

	req, errRequest := http.NewRequestWithContext(reqCtx, http.MethodGet, codexReleaseAPIPath, nil)
	if errRequest != nil {
		return "", fmt.Errorf("build request: %w", errRequest)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, errDo := (&http.Client{Timeout: codexVersionFetchTimeout}).Do(req)
	if errDo != nil {
		return "", fmt.Errorf("request: %w", errDo)
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Debugf("codex version: close API response: %v", errClose)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status %d", resp.StatusCode)
	}

	body, errRead := io.ReadAll(io.LimitReader(resp.Body, maxCodexReleaseBody))
	if errRead != nil {
		return "", fmt.Errorf("read body: %w", errRead)
	}
	tag := gjson.GetBytes(body, "tag_name").String()
	if strings.TrimSpace(tag) == "" {
		return "", errors.New("tag_name missing")
	}
	return parseCodexReleaseTag(tag)
}

// parseCodexReleaseTag turns "rust-v0.154.0" into "0.154.0".
func parseCodexReleaseTag(tag string) (string, error) {
	tag = strings.TrimSpace(tag)
	match := codexReleaseTagPattern.FindStringSubmatch(tag)
	if match == nil {
		return "", fmt.Errorf("unexpected release tag %q", tag)
	}
	return match[1], nil
}
