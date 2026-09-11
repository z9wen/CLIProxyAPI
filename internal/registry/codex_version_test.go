package registry

import (
	"testing"
)

func TestParseCodexReleaseTag(t *testing.T) {
	t.Parallel()

	tests := []struct {
		tag     string
		want    string
		wantErr bool
	}{
		{tag: "rust-v0.154.0", want: "0.154.0"},
		{tag: "rust-v1.2.3", want: "1.2.3"},
		{tag: "rust-v0.155.0-alpha.1", want: "0.155.0-alpha.1"},
		{tag: "v0.154.0", wantErr: true},
		{tag: "0.154.0", wantErr: true},
		{tag: "rust-v0.154", wantErr: true},
		{tag: "", wantErr: true},
	}
	for _, tt := range tests {
		t.Run(tt.tag, func(t *testing.T) {
			t.Parallel()

			got, err := parseCodexReleaseTag(tt.tag)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("parseCodexReleaseTag(%q) = %q, want an error", tt.tag, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("parseCodexReleaseTag(%q) error = %v", tt.tag, err)
			}
			if got != tt.want {
				t.Fatalf("parseCodexReleaseTag(%q) = %q, want %q", tt.tag, got, tt.want)
			}
		})
	}
}

func TestSetCodexClientVersionRejectsUnusableValues(t *testing.T) {
	// Not parallel: it mutates the package-level advertised version.
	previous := CodexClientVersion()
	t.Cleanup(func() { SetCodexClientVersion(previous) })

	for _, bad := range []string{"", "   ", "latest", "rust-v0.154.0", "0.154", "v0.154.0"} {
		SetCodexClientVersion(bad)
		if got := CodexClientVersion(); got != previous {
			t.Fatalf("SetCodexClientVersion(%q) changed the version to %q, want it left at %q", bad, got, previous)
		}
	}
}

func TestSetCodexClientVersionAdvertisesNewerRelease(t *testing.T) {
	// Not parallel: it mutates the package-level advertised version.
	previous := CodexClientVersion()
	t.Cleanup(func() { SetCodexClientVersion(previous) })

	SetCodexClientVersion("0.199.0")
	if got := CodexClientVersion(); got != "0.199.0" {
		t.Fatalf("CodexClientVersion() = %q, want 0.199.0", got)
	}
}

// TestCodexProfileVersionIsValid guards the constant the whole identity is
// written against: a typo here would blank the User-Agent.
func TestCodexProfileVersionIsValid(t *testing.T) {
	t.Parallel()

	if !isCodexVersion(CodexProfileVersion) {
		t.Fatalf("CodexProfileVersion = %q is not a usable version", CodexProfileVersion)
	}
	if CodexClientVersion() == "" {
		t.Fatal("CodexClientVersion() is empty")
	}
}

// The ClientHello profile only moves with the TLS stack, so the Cargo.lock check
// is what decides when a re-capture is due — not the release version.
func TestParseCodexTLSStack(t *testing.T) {
	t.Parallel()

	lock := []byte(`[[package]]
name = "openssl-sys"
version = "0.9.111"
source = "registry+https://github.com/rust-lang/crates.io-index"

[[package]]
name = "reqwest"
version = "0.12.28"

[[package]]
name = "rustls"
version = "0.23.36"
`)

	stack, err := parseCodexTLSStack(lock)
	if err != nil {
		t.Fatalf("parseCodexTLSStack: %v", err)
	}
	if want := "openssl-sys 0.9.111 / rustls 0.23.36"; stack.String() != want {
		t.Fatalf("stack = %q, want %q", stack, want)
	}
	if !BuiltinCodexProfileBaseline().matches(stack) {
		t.Fatal("the shipped pins must match the release this profile was captured from")
	}
}

func TestParseCodexTLSStackDetectsDrift(t *testing.T) {
	t.Parallel()

	// A rustls bump is exactly the event that invalidates the captured profile.
	lock := []byte("[[package]]\nname = \"rustls\"\nversion = \"0.24.0\"\n")
	stack, err := parseCodexTLSStack(lock)
	if err != nil {
		t.Fatalf("parseCodexTLSStack: %v", err)
	}
	if BuiltinCodexProfileBaseline().matches(stack) {
		t.Fatal("a rustls bump must not match the captured profile")
	}
}

// A lock that carries both the old and the new crate during an upgrade must not
// be read as "the pinned version is present, so nothing changed".
func TestParseCodexTLSStackTreatsMultipleVersionsAsDrift(t *testing.T) {
	t.Parallel()

	lock := []byte("[[package]]\nname = \"rustls\"\nversion = \"0.23.36\"\n\n[[package]]\nname = \"rustls\"\nversion = \"0.24.0\"\n")
	stack, err := parseCodexTLSStack(lock)
	if err != nil {
		t.Fatalf("parseCodexTLSStack: %v", err)
	}
	if BuiltinCodexProfileBaseline().matches(stack) {
		t.Fatal("a lock resolving two rustls versions must count as drift")
	}
}

func TestParseCodexTLSStackRejectsUnrelatedDocument(t *testing.T) {
	t.Parallel()

	if _, err := parseCodexTLSStack([]byte("# not a lock file\n")); err == nil {
		t.Fatal("a document with neither dependency must be rejected, not silently matched")
	}
}

// A drifted TLS stack freezes the advertised version, so the User-Agent never
// claims a release whose handshake this proxy does not reproduce.
func TestCodexVersionFreezesWhenProfileDrifts(t *testing.T) {
	// Not parallel: it mutates the package-level profile and version state.
	previousVersion := CodexClientVersion()
	previousCurrent := CodexProfileIsCurrent()
	t.Cleanup(func() {
		codexProfileCurrent.Store(previousCurrent)
		SetCodexClientVersion(previousVersion)
	})

	// Sanity: while the stack matches, the version follows upstream.
	codexProfileCurrent.Store(true)
	SetCodexClientVersion("0.199.0")
	if got := CodexClientVersion(); got != "0.199.0" {
		t.Fatalf("with a current profile the version = %q, want 0.199.0", got)
	}

	// A drifted stack must hold the identity at the captured version.
	codexProfileCurrent.Store(false)
	SetCodexClientVersion("0.200.0")
	if got := CodexClientVersion(); got != CodexProfileVersion {
		t.Fatalf("with a drifted profile the version = %q, want it held at %q", got, CodexProfileVersion)
	}
	if CodexProfileIsCurrent() {
		t.Fatal("CodexProfileIsCurrent must report false once the stack drifted")
	}
}

// withOwnedProfileBaseline runs fn against baseline state the test owns and
// restores the package-level values afterwards. Not parallel: the baseline is
// process-wide.
func withOwnedProfileBaseline(t *testing.T, fn func()) {
	t.Helper()
	previousBaseline := CurrentCodexProfileBaseline()
	previousVersion := CodexClientVersion()
	previousCurrent := CodexProfileIsCurrent()
	previousDir, _ := codexProfileBaselineDir.Load().(string)
	t.Cleanup(func() {
		codexProfileBaseline.Store(previousBaseline)
		codexProfileBaselineDir.Store(previousDir)
		codexProfileCurrent.Store(previousCurrent)
		codexClientVersion.Store(previousVersion)
		codexDriftWarned.Clear()
	})
	fn()
}

// A capture has two halves: writing the profiles, and moving the baseline with
// them. Without the second, the drift check keeps comparing the release just
// captured from against the pins it replaced — it stays frozen, the panel keeps
// reporting a stale profile, and pressing refresh looks like it did nothing.
func TestAdoptCodexProfileBaselineLiftsTheFreeze(t *testing.T) {
	withOwnedProfileBaseline(t, func() {
		codexProfileCurrent.Store(false)
		if got := CodexClientVersion(); got != CodexProfileVersion {
			t.Fatalf("version = %q, want it held at %q while frozen", got, CodexProfileVersion)
		}

		baseline := CodexProfileBaseline{Version: "0.155.0", OpenSSLSys: "0.9.112", Rustls: "0.23.40"}
		if err := AdoptCodexProfileBaseline(baseline); err != nil {
			t.Fatalf("AdoptCodexProfileBaseline: %v", err)
		}

		if !CodexProfileIsCurrent() {
			t.Fatal("adopting the baseline a capture established must clear the freeze")
		}
		if got := CodexClientVersion(); got != "0.155.0" {
			t.Fatalf("version = %q, want the captured release 0.155.0", got)
		}
		captured := codexTLSStack{OpenSSLSys: []string{"0.9.112"}, Rustls: []string{"0.23.40"}}
		if !CurrentCodexProfileBaseline().matches(captured) {
			t.Fatal("the release just captured from must read as matching, not drifted")
		}
		superseded := codexTLSStack{
			OpenSSLSys: []string{codexProfileBuiltinOpenSSLSys},
			Rustls:     []string{codexProfileBuiltinRustls},
		}
		if CurrentCodexProfileBaseline().matches(superseded) {
			t.Fatal("the superseded stack must stop matching once the baseline moved")
		}
	})
}

// The freeze has to survive a restart. An install that captured, then came back
// up on the compiled-in pins, would decide the release it just captured from had
// drifted and hold itself back again until someone pressed refresh a second time.
func TestCodexProfileBaselineSurvivesRestart(t *testing.T) {
	withOwnedProfileBaseline(t, func() {
		dir := t.TempDir()
		if err := SetCodexProfileBaselineDir(dir); err != nil {
			t.Fatalf("SetCodexProfileBaselineDir: %v", err)
		}

		baseline := CodexProfileBaseline{Version: "0.156.0", OpenSSLSys: "0.9.113", Rustls: "0.23.41"}
		if err := AdoptCodexProfileBaseline(baseline); err != nil {
			t.Fatalf("AdoptCodexProfileBaseline: %v", err)
		}

		// Restart: runtime state returns to what init() leaves behind.
		codexProfileBaseline.Store(BuiltinCodexProfileBaseline())
		codexProfileCurrent.Store(false)

		if err := SetCodexProfileBaselineDir(dir); err != nil {
			t.Fatalf("reload after restart: %v", err)
		}
		if got := CurrentCodexProfileBaseline(); got != baseline {
			t.Fatalf("baseline after reload = %+v, want %+v", got, baseline)
		}
		if !CodexProfileIsCurrent() {
			t.Fatal("a reloaded baseline must leave the identity coherent, not frozen")
		}
	})
}

func TestAdoptCodexProfileBaselineRejectsUnusable(t *testing.T) {
	withOwnedProfileBaseline(t, func() {
		before := CurrentCodexProfileBaseline()
		unusable := map[string]CodexProfileBaseline{
			"empty version":   {OpenSSLSys: "0.9.111", Rustls: "0.23.36"},
			"unparsable":      {Version: "not-a-version", OpenSSLSys: "0.9.111", Rustls: "0.23.36"},
			"missing openssl": {Version: "0.155.0", Rustls: "0.23.36"},
			"missing rustls":  {Version: "0.155.0", OpenSSLSys: "0.9.111"},
		}
		for name, baseline := range unusable {
			if err := AdoptCodexProfileBaseline(baseline); err == nil {
				t.Fatalf("%s: expected a rejection", name)
			}
		}
		if got := CurrentCodexProfileBaseline(); got != before {
			t.Fatalf("a rejected baseline must not move the current one: got %+v, want %+v", got, before)
		}
	})
}
