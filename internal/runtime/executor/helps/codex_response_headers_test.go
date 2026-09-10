package helps

import (
	"net/http"
	"testing"
)

// The Codex client reads these to decide what to do next, so they are forwarded
// even when passthrough-headers is off; everything else stays behind that switch.
func TestCodexResponseHeadersForClient(t *testing.T) {
	t.Parallel()

	upstream := http.Header{
		"X-Codex-Turn-State":               {"turn-abc"},
		"X-Reasoning-Included":             {"true"},
		"Openai-Model":                     {"gpt-5.5"},
		"X-Codex-Primary-Used-Percent":     {"42"},
		"X-Codex-Primary-Reset-At":         {"1789049425"},
		"X-Codex-Credits-Has-Credits":      {"true"},
		"X-Codex-Promo-Message":            {"promo"},
		"X-Codex-Safety-Buffering-Enabled": {"true"},
		"X-Codex-Active-Limit":             {"codex"},
		// Not forwarded: an invalidation hint for the client's model list, which
		// this proxy serves itself.
		"X-Models-Etag": {"etag-from-upstream"},
		// Not Codex-specific; gated behind passthrough-headers.
		"Cf-Ray":         {"abc123"},
		"Content-Length": {"123"},
	}

	got := CodexResponseHeadersForClient(upstream)

	want := []string{
		"X-Codex-Turn-State",
		"X-Reasoning-Included",
		"Openai-Model",
		"X-Codex-Primary-Used-Percent",
		"X-Codex-Primary-Reset-At",
		"X-Codex-Credits-Has-Credits",
		"X-Codex-Promo-Message",
		"X-Codex-Safety-Buffering-Enabled",
		"X-Codex-Active-Limit",
	}
	for _, name := range want {
		if values := got.Values(name); len(values) == 0 {
			t.Errorf("%s missing, want it forwarded", name)
		}
	}
	for _, name := range []string{"X-Models-Etag", "Cf-Ray", "Content-Length"} {
		if values := got.Values(name); len(values) != 0 {
			t.Errorf("%s = %v, want it left out", name, values)
		}
	}
}

func TestCodexResponseHeadersForClientEmpty(t *testing.T) {
	t.Parallel()

	if got := CodexResponseHeadersForClient(nil); got != nil {
		t.Fatalf("nil headers = %v, want nil", got)
	}
	if got := CodexResponseHeadersForClient(http.Header{"Cf-Ray": {"x"}}); got != nil {
		t.Fatalf("unrelated headers = %v, want nil", got)
	}
}
