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
