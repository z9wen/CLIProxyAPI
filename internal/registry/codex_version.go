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

const (
	// The releases page redirects to the tag, so the tag can be read without the
	// API's rate limit. codexReleaseAPIPath is the fallback.
	codexLatestReleaseURL = "https://github.com/openai/codex/releases/latest"
	codexReleaseAPIPath   = "https://api.github.com/repos/openai/codex/releases/latest"

	codexVersionFetchTimeout = 15 * time.Second
	// Daily. Polling more often buys very little: a version a few hours behind is
	// indistinguishable from a real user who has not upgraded yet, and real users
	// lag by days. What genuinely has to keep up is the TLS profile, and that
	// cannot be polled for at all — see the drift warning in
	// SetCodexClientVersion, which is the signal that actually matters.
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

func init() {
	codexClientVersion.Store(CodexProfileVersion)
}

// CodexClientVersion returns the Codex release the wire identity advertises.
func CodexClientVersion() string {
	if version, ok := codexClientVersion.Load().(string); ok && version != "" {
		return version
	}
	return CodexProfileVersion
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
	codexClientVersion.Store(version)

	if version != CodexProfileVersion {
		if _, warned := codexDriftWarned.LoadOrStore(version, struct{}{}); !warned {
			log.Warnf("codex: upstream released %s but the TLS profile was captured from %s; "+
				"re-capture with tools/codexfp (see tools/codexfp/README.md) so the handshake matches the advertised version",
				version, CodexProfileVersion)
		}
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
	if CodexClientVersion() == version {
		log.Infof("%s completed from %s, already at %s", label, source, version)
		return
	}
	SetCodexClientVersion(version)
	log.Infof("%s completed from %s, now advertising %s", label, source, version)
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
