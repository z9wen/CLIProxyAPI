package management

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	log "github.com/sirupsen/logrus"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/codexcapture"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
)

// codexProfileCaptureTimeout bounds a refresh from end to end. The individual
// steps have their own limits; this is the backstop for one that wedges between
// them, so a capture cannot leave the endpoint reporting "running" forever.
const codexProfileCaptureTimeout = 30 * time.Minute

// codexProfileCapture tracks the capture a refresh may have running.
//
// One at a time, process-wide: two would drive two clients against two listeners
// and race to write the same profiles. codexcapture serializes them as well; this
// is what lets the endpoint answer "already running" rather than block a request
// behind a multi-minute download.
var codexProfileCapture struct {
	mu         sync.Mutex
	running    bool
	startedAt  time.Time
	finishedAt time.Time
	version    string
	profiles   []string
	err        string
}

// GetCodexProfile reports the state of the captured Codex TLS profiles.
func (h *Handler) GetCodexProfile(c *gin.Context) {
	c.JSON(http.StatusOK, codexProfileStatus())
}

// PostCodexProfileRefresh starts a capture in the background and returns the
// state it started from.
//
// Behind the management key like the rest of this group, which matters more here
// than anywhere else on it: a capture downloads the official Codex release and
// runs it, so this endpoint is a code execution surface by design and the key is
// what keeps it to the operator.
func (h *Handler) PostCodexProfileRefresh(c *gin.Context) {
	dir := helps.CodexProfileDir()
	if dir == "" {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error":   "no_profile_dir",
			"message": "no Codex profile directory is configured, so there is nowhere to write a capture",
		})
		return
	}

	codexProfileCapture.mu.Lock()
	if codexProfileCapture.running {
		started := codexProfileCapture.startedAt
		codexProfileCapture.mu.Unlock()
		c.JSON(http.StatusConflict, gin.H{
			"error":      "capture_running",
			"message":    "a capture is already running",
			"started_at": started.UTC().Format(time.RFC3339),
		})
		return
	}
	codexProfileCapture.running = true
	codexProfileCapture.startedAt = time.Now()
	codexProfileCapture.finishedAt = time.Time{}
	codexProfileCapture.version = ""
	codexProfileCapture.profiles = nil
	codexProfileCapture.err = ""
	codexProfileCapture.mu.Unlock()

	go runCodexProfileCapture(dir)

	c.JSON(http.StatusAccepted, codexProfileStatus())
}

// codexProfileStatus is the state the panel and any monitoring reads.
func codexProfileStatus() gin.H {
	baseline := registry.CurrentCodexProfileBaseline()
	status := gin.H{
		"advertised_version": registry.CodexClientVersion(),
		"profile_version":    baseline.Version,
		"current":            registry.CodexProfileIsCurrent(),
		"profile_dir":        helps.CodexProfileDir(),
		"tls_stack": gin.H{
			"openssl_sys": baseline.OpenSSLSys,
			"rustls":      baseline.Rustls,
		},
	}

	codexProfileCapture.mu.Lock()
	defer codexProfileCapture.mu.Unlock()
	capture := gin.H{"running": codexProfileCapture.running}
	if !codexProfileCapture.startedAt.IsZero() {
		capture["started_at"] = codexProfileCapture.startedAt.UTC().Format(time.RFC3339)
	}
	if !codexProfileCapture.finishedAt.IsZero() {
		capture["finished_at"] = codexProfileCapture.finishedAt.UTC().Format(time.RFC3339)
	}
	if codexProfileCapture.version != "" {
		capture["version"] = codexProfileCapture.version
	}
	if len(codexProfileCapture.profiles) > 0 {
		capture["profiles"] = codexProfileCapture.profiles
	}
	if codexProfileCapture.err != "" {
		capture["error"] = codexProfileCapture.err
	}
	status["capture"] = capture
	return status
}

func runCodexProfileCapture(dir string) {
	defer func() {
		codexProfileCapture.mu.Lock()
		codexProfileCapture.running = false
		codexProfileCapture.finishedAt = time.Now()
		codexProfileCapture.mu.Unlock()
	}()

	// Deliberately not the request's context: the capture outlives the request
	// that started it, and the panel polls this endpoint for the outcome.
	ctx, cancel := context.WithTimeout(context.Background(), codexProfileCaptureTimeout)
	defer cancel()

	// The newest release, not the advertised one: the advertised version is held
	// back precisely when the profiles are behind, so capturing it would reproduce
	// the handshake already in place.
	version, errVersion := registry.LatestCodexRelease(ctx)
	if errVersion != nil {
		recordCodexProfileCapture("", nil, errVersion)
		log.Errorf("codex profile capture: %v", errVersion)
		return
	}

	log.Infof("codex profile capture: capturing the profiles from Codex %s", version)
	result, errCapture := codexcapture.Capture(ctx, codexcapture.Options{ProfileDir: dir, Version: version})
	if errCapture != nil {
		recordCodexProfileCapture(version, nil, errCapture)
		log.Errorf("codex profile capture: %v", errCapture)
		return
	}
	recordCodexProfileCapture(result.Version, result.Profiles, nil)
}

func recordCodexProfileCapture(version string, profiles []string, err error) {
	codexProfileCapture.mu.Lock()
	defer codexProfileCapture.mu.Unlock()
	codexProfileCapture.version = version
	codexProfileCapture.profiles = profiles
	if err != nil {
		codexProfileCapture.err = err.Error()
		return
	}
	codexProfileCapture.err = ""
}
