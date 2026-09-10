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
	if !stack.matchesProfile() {
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
	if stack.matchesProfile() {
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
	if stack.matchesProfile() {
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
