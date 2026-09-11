// Package codexcapture re-captures the Codex client's TLS ClientHello profiles
// from the official released binary, in process.
//
// The profiles this proxy reproduces are a copy of a real client's handshake, and
// they go stale when the client's TLS stack moves. Keeping them current used to
// mean running tools/codexfp by hand on a machine with the right toolchain. This
// package makes it an operation the proxy can run on demand: download the release,
// drive it against a local listener, keep the handshakes it emits.
package codexcapture

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/registry"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
)

const captureUserAgent = "CLIProxyAPI-codex-capture"

// Release assets, addressed by tag.
const (
	codexReleaseDownloadTemplate  = "https://github.com/openai/codex/releases/download/rust-v%s/codex-package-%s-unknown-linux-musl.tar.gz"
	codexReleaseChecksumsTemplate = "https://github.com/openai/codex/releases/download/rust-v%s/codex-package_SHA256SUMS"
)

// codexPackageBinaryEntry is where the package variant keeps the client.
//
// The package variant is used rather than the bare binary because it is the one
// the release publishes a checksum for; the plain tarball has none.
const codexPackageBinaryEntry = "bin/codex"

const (
	codexHomeDirName = ".codex"
	codexConfigName  = "config.toml"

	// A placeholder. The handshake is produced before the client authenticates,
	// and the connection is cut off before any request could be sent, so no real
	// credential is involved at any point.
	captureAPIKey = "dummy-key-for-capture"
)

const (
	// The package tarball is ~112 MB. This bound covers the whole transfer and is
	// deliberately generous: a capture runs rarely, on demand, and a slow link
	// should not turn into a failed one.
	captureDownloadTimeout = 15 * time.Minute
	// The captured client is a real application being deliberately cut off, and it
	// will retry against a proxy that never answers. It has to be stopped.
	captureRunTimeout = 2 * time.Minute
	// How long to keep reading handshakes. The second one only arrives after the
	// client has given up on the first, so this is longer than a handshake takes.
	captureCollectionTimeout = 45 * time.Second
	// How many WebSocket orderings a capture keeps. The client reorders its
	// extensions per connection, so every run adds one; a handful is enough to
	// stop the order being a constant, and each extra run costs a client start-up.
	webSocketSamples = 6
	// Caps the extracted binary. The real one is ~90 MB; the bound exists so a
	// malformed archive cannot fill the disk.
	maxCodexBinarySize = 512 << 20
	maxChecksumsBody   = 1 << 20
	// Child output is kept for diagnostics on failure only, and bounded.
	maxChildOutput = 8 << 10
)

// captureMu serializes captures. Two at once would drive two clients against two
// listeners and race to write the same files.
var captureMu sync.Mutex

// Options configures a capture.
type Options struct {
	// ProfileDir is the directory the profile loader reads from, and where the
	// capture is written. Required.
	ProfileDir string
	// Version is the Codex release to capture from, such as "0.155.0". Required.
	Version string
}

func (o Options) validate() error {
	if strings.TrimSpace(o.ProfileDir) == "" {
		return errors.New("codexcapture: no profile directory is configured")
	}
	if strings.TrimSpace(o.Version) == "" {
		return errors.New("codexcapture: no release version was given")
	}
	return nil
}

// Result describes a completed capture.
type Result struct {
	// Version is the release the profiles were captured from.
	Version string
	// Profiles are the file names written, for reporting.
	Profiles []string
}

// Capture replaces the profiles on disk with fresh ones captured from the
// official Codex client, and moves the recorded baseline with them so the
// advertised identity stays coherent.
//
// The handshakes are genuine: they come from the released binary, run under a
// throwaway home directory with its traffic pointed at a local listener. That
// listener answers CONNECT itself and closes the connection as soon as the
// ClientHello is read, so nothing is sent to OpenAI and no credential is used.
//
// The binary is downloaded from the official release and checked against that
// release's published SHA256SUMS before it is run. Those checksums come from the
// same origin as the artifact, so this establishes integrity rather than
// provenance: it catches a corrupted or truncated download, not a compromised
// upstream.
func Capture(ctx context.Context, opts Options) (Result, error) {
	if errValidate := opts.validate(); errValidate != nil {
		return Result{}, errValidate
	}
	// Codex publishes Linux builds only, so there is nothing to run elsewhere.
	// The deployments this serves are Linux; a laptop is not.
	if runtime.GOOS != "linux" {
		return Result{}, fmt.Errorf(
			"codexcapture: capturing needs a Linux host, because the Codex releases are Linux builds (this is %s)",
			runtime.GOOS)
	}
	arch, errArch := linuxArch()
	if errArch != nil {
		return Result{}, errArch
	}

	captureMu.Lock()
	defer captureMu.Unlock()

	workDir, errWork := createWorkDir(opts.ProfileDir)
	if errWork != nil {
		return Result{}, errWork
	}
	defer func() {
		if errRemove := os.RemoveAll(workDir); errRemove != nil {
			log.Warnf("codexcapture: remove work directory %s: %v", workDir, errRemove)
		}
	}()

	tarballName := fmt.Sprintf("codex-package-%s-unknown-linux-musl.tar.gz", arch)
	tarballPath := filepath.Join(workDir, tarballName)

	// The checksums are fetched first so a release that cannot be verified is
	// rejected before the ~112 MB download is spent.
	checksums, errChecksums := fetchChecksums(ctx, opts.Version)
	if errChecksums != nil {
		return Result{}, fmt.Errorf("codexcapture: read the release checksums: %w", errChecksums)
	}
	want, ok := checksums[tarballName]
	if !ok {
		return Result{}, fmt.Errorf("codexcapture: release %s publishes no checksum for %s", opts.Version, tarballName)
	}

	log.Infof("codexcapture: downloading %s from the Codex %s release", tarballName, opts.Version)
	downloadURL := fmt.Sprintf(codexReleaseDownloadTemplate, opts.Version, arch)
	if errDownload := downloadToFile(ctx, downloadURL, tarballPath); errDownload != nil {
		return Result{}, fmt.Errorf("codexcapture: download %s: %w", tarballName, errDownload)
	}
	if errVerify := verifySHA256(tarballPath, want); errVerify != nil {
		return Result{}, fmt.Errorf("codexcapture: %s: %w", tarballName, errVerify)
	}
	log.Infof("codexcapture: %s matches the published SHA256", tarballName)

	binaryPath := filepath.Join(workDir, "codex")
	if errExtract := extractCodexBinary(tarballPath, binaryPath); errExtract != nil {
		return Result{}, errExtract
	}
	// The extracted binary is what gets run; the archive is dead weight, and the
	// host may be short on space.
	if errRemove := os.Remove(tarballPath); errRemove != nil {
		log.Debugf("codexcapture: remove %s: %v", tarballPath, errRemove)
	}

	home := filepath.Join(workDir, "home")
	if errHome := writeThrowawayHome(home); errHome != nil {
		return Result{}, errHome
	}

	listener, errListener := newClientHelloListener()
	if errListener != nil {
		return Result{}, errListener
	}
	defer func() {
		if errClose := listener.Close(); errClose != nil {
			log.Debugf("codexcapture: close listener: %v", errClose)
		}
	}()

	httpRecord, webSockets, errCollect := collectProfiles(ctx, listener, binaryPath, home)
	if errCollect != nil {
		return Result{}, errCollect
	}

	// Resolved before anything is written. A capture that cannot establish its
	// baseline would otherwise leave new profiles in place while the drift check
	// still reads them against the old pins — stale files that the notice would
	// keep reporting and a refresh could not clear.
	baseline, errBaseline := registry.LookupCodexProfileBaseline(ctx, opts.Version)
	if errBaseline != nil {
		return Result{}, fmt.Errorf("codexcapture: %w", errBaseline)
	}

	written, errWrite := writeProfiles(opts.ProfileDir, httpRecord, webSockets)
	if errWrite != nil {
		return Result{}, errWrite
	}
	if errReload := helps.ReloadCodexProfiles(); errReload != nil {
		return Result{}, fmt.Errorf("codexcapture: reload the captured profiles: %w", errReload)
	}
	if errAdopt := registry.AdoptCodexProfileBaseline(baseline); errAdopt != nil {
		return Result{}, fmt.Errorf("codexcapture: record the profile baseline: %w", errAdopt)
	}

	log.Infof("codexcapture: captured %d profiles from Codex %s (%s)",
		len(written), opts.Version, strings.Join(written, ", "))
	return Result{Version: opts.Version, Profiles: written}, nil
}

// createWorkDir makes the scratch directory a capture downloads and runs in.
//
// Placed beside the profile directory rather than in the system temp directory.
// The hosts this runs on are routers, where /tmp is tmpfs: a 112 MB archive plus
// a ~90 MB binary would be ~200 MB of resident memory, most of a small router's
// free RAM. The profile directory's filesystem is persistent storage that is
// writable by construction, so the artifacts land where the space is.
func createWorkDir(profileDir string) (string, error) {
	parent := filepath.Dir(profileDir)
	if errMkdir := os.MkdirAll(parent, 0o700); errMkdir != nil {
		return "", fmt.Errorf("codexcapture: create %s: %w", parent, errMkdir)
	}
	workDir, errWork := os.MkdirTemp(parent, ".codexcapture-")
	if errWork != nil {
		return "", fmt.Errorf("codexcapture: create a work directory in %s: %w", parent, errWork)
	}
	return workDir, nil
}

// linuxArch maps the host architecture onto the name Codex publishes builds for.
func linuxArch() (string, error) {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64", nil
	case "arm64":
		return "aarch64", nil
	default:
		return "", fmt.Errorf("codexcapture: Codex publishes no build for %s", runtime.GOARCH)
	}
}

// collectProfiles runs the captured client and returns the handshakes it emits:
// the one HTTP/SSE profile, and one WebSocket profile per run.
//
// The client tries the WebSocket transport first, because the throwaway
// configuration enables it, and falls back to HTTP/SSE once the listener closes
// that connection — so both handshakes pass through in every run. The WebSocket
// path runs rustls, which reorders its extensions per connection, so each run
// contributes a different ordering; several are kept so the transport can rotate
// instead of replaying one order forever. The HTTP path runs OpenSSL, which is
// deterministic, so the first one captured describes it completely.
func collectProfiles(ctx context.Context, listener *clientHelloListener, binaryPath, home string) ([]byte, [][]byte, error) {
	var (
		httpRecord []byte
		webSockets [][]byte
		lastRun    childRun
		stderr     string
	)

	for attempt := 0; attempt < webSocketSamples && len(webSockets) < webSocketSamples; attempt++ {
		http, webSocket, run := captureRun(ctx, listener, binaryPath, home)
		lastRun = run
		if run.stderr != "" {
			stderr = run.stderr
		}
		if http != nil && httpRecord == nil {
			httpRecord = http
		}
		if webSocket != nil {
			webSockets = append(webSockets, webSocket)
			continue
		}
		// A run that produced no WebSocket handshake will not produce one on the
		// next either — the client is not exercising that transport — so the
		// remaining attempts would only cost time.
		break
	}

	if httpRecord != nil && len(webSockets) > 0 {
		return httpRecord, webSockets, nil
	}
	if httpRecord == nil && len(webSockets) == 0 {
		if stderr != "" {
			return nil, nil, fmt.Errorf("codexcapture: the client produced no handshake; it said: %s", stderr)
		}
		if lastRun.err != nil {
			return nil, nil, fmt.Errorf("codexcapture: the client produced no handshake: %w", lastRun.err)
		}
		return nil, nil, errors.New("codexcapture: the client produced no handshake")
	}
	// A partial capture is refused rather than written. Replacing one transport's
	// profile while the other keeps the old handshake would advertise an identity
	// no single client sends, which is the mismatch this machinery exists to
	// remove. Nothing has been written at this point, so the previous profiles
	// stay in force.
	missing := profileWebSocket
	if len(webSockets) == 0 {
		missing = profileHTTP
	}
	return nil, nil, fmt.Errorf(
		"codexcapture: captured only the %s handshake; the client did not exercise the %s transport, so neither profile was replaced",
		missing.other(), missing)
}

// captureRun starts the client once, reads the handshakes it emits, and stops it.
func captureRun(ctx context.Context, listener *clientHelloListener, binaryPath, home string) (httpRecord, webSocketRecord []byte, run childRun) {
	runCtx, cancelRun := context.WithTimeout(ctx, captureRunTimeout)
	defer cancelRun()

	runResult := make(chan childRun, 1)
	go func() {
		runResult <- runChild(runCtx, binaryPath, home, listener.ProxyURL())
	}()

	collectCtx, cancelCollect := context.WithTimeout(ctx, captureCollectionTimeout)
	defer cancelCollect()

	for httpRecord == nil || webSocketRecord == nil {
		hello, errNext := listener.Next(collectCtx)
		if errNext != nil {
			break
		}
		kind, errClassify := classify(hello.record)
		if errClassify != nil {
			// A handshake we cannot place is not written anywhere: see classify.
			log.Debugf("codexcapture: ignoring a handshake for %s: %v", hello.target, errClassify)
			continue
		}
		log.Infof("codexcapture: captured the %s handshake from %s", kind, hello.target)
		if kind == profileHTTP {
			if httpRecord == nil {
				httpRecord = hello.record
			}
			continue
		}
		if webSocketRecord == nil {
			webSocketRecord = hello.record
		}
	}

	// The client is still retrying against a listener that will never answer it.
	// Stopping it is the caller's job, and its exit status says nothing useful.
	cancelRun()
	run = <-runResult
	return httpRecord, webSocketRecord, run
}

// writeProfiles writes the captured handshakes under the names the loader reads.
//
// Earlier WebSocket samples are removed first rather than added to: samples kept
// from a previous capture would carry a different release's orderings, and the
// set is meant to describe one client.
func writeProfiles(dir string, httpRecord []byte, webSockets [][]byte) ([]string, error) {
	if errMkdir := os.MkdirAll(dir, 0o700); errMkdir != nil {
		return nil, fmt.Errorf("codexcapture: create %s: %w", dir, errMkdir)
	}
	stale, errGlob := filepath.Glob(filepath.Join(dir, helps.CodexProfileWebSocketGlob))
	if errGlob != nil {
		return nil, fmt.Errorf("codexcapture: scan %s for earlier samples: %w", dir, errGlob)
	}
	for _, path := range stale {
		if errRemove := os.Remove(path); errRemove != nil {
			return nil, fmt.Errorf("codexcapture: remove the earlier sample %s: %w", path, errRemove)
		}
	}

	httpPath := filepath.Join(dir, helps.CodexProfileHTTPFile)
	if errWrite := os.WriteFile(httpPath, httpRecord, 0o600); errWrite != nil {
		return nil, fmt.Errorf("codexcapture: write %s: %w", httpPath, errWrite)
	}
	names := []string{helps.CodexProfileHTTPFile}

	for i, record := range webSockets {
		name := helps.CodexProfileWebSocketFile
		if i > 0 {
			name = fmt.Sprintf(helps.CodexProfileWebSocketSampleFormat, i+1)
		}
		path := filepath.Join(dir, name)
		if errWrite := os.WriteFile(path, record, 0o600); errWrite != nil {
			return nil, fmt.Errorf("codexcapture: write %s: %w", path, errWrite)
		}
		names = append(names, name)
	}
	return names, nil
}

// fetchChecksums reads a release's published SHA256SUMS.
func fetchChecksums(ctx context.Context, version string) (map[string]string, error) {
	reqCtx, cancel := context.WithTimeout(ctx, captureDownloadTimeout)
	defer cancel()

	url := fmt.Sprintf(codexReleaseChecksumsTemplate, version)
	req, errRequest := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if errRequest != nil {
		return nil, fmt.Errorf("build request: %w", errRequest)
	}
	req.Header.Set("User-Agent", captureUserAgent)

	resp, errDo := http.DefaultClient.Do(req)
	if errDo != nil {
		return nil, fmt.Errorf("request: %w", errDo)
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Debugf("codexcapture: close checksums response: %v", errClose)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	body, errRead := io.ReadAll(io.LimitReader(resp.Body, maxChecksumsBody))
	if errRead != nil {
		return nil, fmt.Errorf("read body: %w", errRead)
	}
	return parseChecksums(body), nil
}

// parseChecksums reads the "<hex>  <name>" lines of a SHA256SUMS file.
func parseChecksums(body []byte) map[string]string {
	sums := make(map[string]string)
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		// sha256sum prefixes the name with '*' when it hashed in binary mode.
		sums[strings.TrimPrefix(fields[1], "*")] = strings.ToLower(fields[0])
	}
	return sums
}

func downloadToFile(ctx context.Context, url, path string) error {
	reqCtx, cancel := context.WithTimeout(ctx, captureDownloadTimeout)
	defer cancel()

	req, errRequest := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if errRequest != nil {
		return fmt.Errorf("build request: %w", errRequest)
	}
	req.Header.Set("User-Agent", captureUserAgent)

	resp, errDo := http.DefaultClient.Do(req)
	if errDo != nil {
		return fmt.Errorf("request: %w", errDo)
	}
	defer func() {
		if errClose := resp.Body.Close(); errClose != nil {
			log.Debugf("codexcapture: close download response: %v", errClose)
		}
	}()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}

	file, errCreate := os.Create(path)
	if errCreate != nil {
		return fmt.Errorf("create %s: %w", path, errCreate)
	}
	if _, errCopy := io.Copy(file, resp.Body); errCopy != nil {
		if errClose := file.Close(); errClose != nil {
			log.Debugf("codexcapture: close %s after a failed copy: %v", path, errClose)
		}
		return fmt.Errorf("write %s: %w", path, errCopy)
	}
	// Reported rather than logged: a failed close can mean unwritten data, and the
	// checksum that follows is what would catch it.
	if errClose := file.Close(); errClose != nil {
		return fmt.Errorf("close %s: %w", path, errClose)
	}
	return nil
}

func verifySHA256(path, want string) error {
	file, errOpen := os.Open(path)
	if errOpen != nil {
		return fmt.Errorf("open: %w", errOpen)
	}
	defer func() {
		if errClose := file.Close(); errClose != nil {
			log.Debugf("codexcapture: close %s: %v", path, errClose)
		}
	}()

	hasher := sha256.New()
	if _, errCopy := io.Copy(hasher, file); errCopy != nil {
		return fmt.Errorf("hash: %w", errCopy)
	}
	if got := hex.EncodeToString(hasher.Sum(nil)); !strings.EqualFold(got, want) {
		return fmt.Errorf("checksum mismatch: got %s, want %s", got, want)
	}
	return nil
}

// extractCodexBinary writes the package's bin/codex out of the archive.
//
// Only that one entry is read, matched by exact name, so nothing inside the
// archive gets to choose where a file lands.
func extractCodexBinary(tarballPath, destPath string) error {
	file, errOpen := os.Open(tarballPath)
	if errOpen != nil {
		return fmt.Errorf("codexcapture: open %s: %w", tarballPath, errOpen)
	}
	defer func() {
		if errClose := file.Close(); errClose != nil {
			log.Debugf("codexcapture: close %s: %v", tarballPath, errClose)
		}
	}()

	gz, errGzip := gzip.NewReader(file)
	if errGzip != nil {
		return fmt.Errorf("codexcapture: %s is not gzip: %w", tarballPath, errGzip)
	}
	defer func() {
		if errClose := gz.Close(); errClose != nil {
			log.Debugf("codexcapture: close gzip reader: %v", errClose)
		}
	}()

	reader := tar.NewReader(gz)
	for {
		header, errNext := reader.Next()
		if errors.Is(errNext, io.EOF) {
			return fmt.Errorf("codexcapture: %s is not in the release archive", codexPackageBinaryEntry)
		}
		if errNext != nil {
			return fmt.Errorf("codexcapture: read archive: %w", errNext)
		}
		if header.Name != codexPackageBinaryEntry {
			continue
		}
		if header.Size <= 0 || header.Size > maxCodexBinarySize {
			return fmt.Errorf("codexcapture: %s is %d bytes, refusing it", codexPackageBinaryEntry, header.Size)
		}
		out, errCreate := os.OpenFile(destPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o700)
		if errCreate != nil {
			return fmt.Errorf("codexcapture: create %s: %w", destPath, errCreate)
		}
		if _, errCopy := io.CopyN(out, reader, header.Size); errCopy != nil {
			if errClose := out.Close(); errClose != nil {
				log.Debugf("codexcapture: close %s after a failed copy: %v", destPath, errClose)
			}
			return fmt.Errorf("codexcapture: write %s: %w", destPath, errCopy)
		}
		if errClose := out.Close(); errClose != nil {
			return fmt.Errorf("codexcapture: close %s: %w", destPath, errClose)
		}
		return nil
	}
}

// throwawayConfig is the configuration the captured client runs under.
//
// It points the client at the real Codex endpoint so the handshake carries the
// production SNI, and nothing else. The connection is answered by the local
// listener and cut off, so no request is sent and no account is involved.
// requires_openai_auth is off so the client dials instead of stopping to look for
// credentials first.
//
// supports_websockets is what makes one run produce both profiles: the client
// tries the WebSocket transport first, and falls back to HTTP/SSE once the
// listener closes that connection.
const throwawayConfig = `# Written by CLIProxyAPI for a TLS fingerprint capture. Throwaway.
model_provider = "capture"
model = "gpt-5.5"

[model_providers.capture]
name = "capture"
base_url = "https://chatgpt.com/backend-api/codex"
wire_api = "responses"
requires_openai_auth = false
env_key = "OPENAI_API_KEY"
supports_websockets = true
`

func writeThrowawayHome(home string) error {
	dir := filepath.Join(home, codexHomeDirName)
	if errMkdir := os.MkdirAll(dir, 0o700); errMkdir != nil {
		return fmt.Errorf("codexcapture: create %s: %w", dir, errMkdir)
	}
	path := filepath.Join(dir, codexConfigName)
	if errWrite := os.WriteFile(path, []byte(throwawayConfig), 0o600); errWrite != nil {
		return fmt.Errorf("codexcapture: write %s: %w", path, errWrite)
	}
	return nil
}

// childEnv builds the environment the captured client runs under.
//
// Set explicitly rather than inherited. The client reads proxy and CA settings
// from the environment, and anything left over from the host would change the
// handshake being observed: a NO_PROXY covering chatgpt.com would let it bypass
// the listener entirely, and CODEX_CA_CERTIFICATE or SSL_CERT_FILE would switch
// the HTTP path to rustls — the WebSocket path's TLS stack — so the capture would
// describe a connection the client does not actually make.
func childEnv(home, proxyURL string) []string {
	return []string{
		"HOME=" + home,
		"CODEX_HOME=" + filepath.Join(home, codexHomeDirName),
		"HTTPS_PROXY=" + proxyURL,
		"HTTP_PROXY=" + proxyURL,
		"OPENAI_API_KEY=" + captureAPIKey,
		"PATH=" + os.Getenv("PATH"),
	}
}

// childRun is the outcome of the captured client's process.
type childRun struct {
	stderr string
	err    error
}

func runChild(ctx context.Context, binaryPath, home, proxyURL string) childRun {
	output := &boundedBuffer{limit: maxChildOutput}
	cmd := exec.CommandContext(ctx, binaryPath, "exec", "--skip-git-repo-check", "capture")
	// The work directory is not a git repository, and the client refuses to run
	// outside one without being told to.
	cmd.Dir = home
	cmd.Env = childEnv(home, proxyURL)
	cmd.Stdout = output
	cmd.Stderr = output
	return childRun{stderr: strings.TrimSpace(output.String()), err: cmd.Run()}
}

// boundedBuffer collects at most limit bytes and discards the rest, so a client
// that decides to log in a loop cannot grow the proxy with it.
type boundedBuffer struct {
	limit int
	buf   bytes.Buffer
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	if room := b.limit - b.buf.Len(); room > 0 {
		if len(p) > room {
			b.buf.Write(p[:room])
		} else {
			b.buf.Write(p)
		}
	}
	// Always report a full write: a short write would be read as an error by the
	// child and could change the behaviour being captured.
	return len(p), nil
}

func (b *boundedBuffer) String() string {
	return b.buf.String()
}
