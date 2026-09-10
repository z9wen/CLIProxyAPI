package helps

import (
	"os"
	"path/filepath"
	"testing"
)

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	raw, errRead := os.ReadFile(filepath.Join("testdata", name))
	if errRead != nil {
		t.Fatalf("read testdata/%s: %v", name, errRead)
	}
	return raw
}

// A capture on disk must replace the built-in literal.
//
// The websocket capture is fed in as the HTTP profile on purpose: it carries ten
// cipher suites against the built-in's thirty, so the assertion cannot pass by
// accident if the file was ignored.
func TestCapturedProfileReplacesBuiltin(t *testing.T) {
	// Not parallel: it mutates the package-level profile directory.
	previousDir := CodexProfileDir()
	t.Cleanup(func() {
		if err := SetCodexProfileDir(previousDir); err != nil {
			t.Logf("restore profile dir: %v", err)
		}
	})

	dir := t.TempDir()
	capture := readTestdata(t, "codex-websocket-clienthello.bin")
	if err := os.WriteFile(filepath.Join(dir, CodexProfileHTTPFile), capture, 0o644); err != nil {
		t.Fatalf("write capture: %v", err)
	}
	if err := SetCodexProfileDir(dir); err != nil {
		t.Fatalf("SetCodexProfileDir: %v", err)
	}

	got := codexOpenSSLClientHelloSpec()
	if want := 10; len(got.CipherSuites) != want {
		t.Fatalf("HTTP path returned %d cipher suites, want %d from the capture", len(got.CipherSuites), want)
	}
	// The websocket slot has no capture, so it must still serve its built-in.
	if got := CodexWebSocketClientHelloSpec(); len(got.CipherSuites) == 0 {
		t.Fatal("the websocket path must keep serving")
	}
}

// A directory with an unreadable capture must leave the built-in profile
// serving: refusing to serve because a file is corrupt would be worse.
func TestUnusableCapturedProfileFallsBackToBuiltin(t *testing.T) {
	// Not parallel: it mutates the package-level profile directory.
	previousDir := CodexProfileDir()
	t.Cleanup(func() {
		if err := SetCodexProfileDir(previousDir); err != nil {
			t.Logf("restore profile dir: %v", err)
		}
	})

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, CodexProfileHTTPFile), []byte("not a client hello"), 0o644); err != nil {
		t.Fatalf("write junk: %v", err)
	}

	// The corrupt file is reported...
	if err := SetCodexProfileDir(dir); err == nil {
		t.Fatal("a corrupt capture should be reported")
	}
	// ...but the built-in profile still serves.
	builtin := builtinCodexOpenSSLClientHelloSpec()
	if got := codexOpenSSLClientHelloSpec(); len(got.CipherSuites) != len(builtin.CipherSuites) {
		t.Fatalf("corrupt capture: HTTP path returned %d cipher suites, want the built-in's %d",
			len(got.CipherSuites), len(builtin.CipherSuites))
	}
	if got := CodexWebSocketClientHelloSpec(); len(got.CipherSuites) == 0 {
		t.Fatal("the websocket path must keep serving")
	}
}
