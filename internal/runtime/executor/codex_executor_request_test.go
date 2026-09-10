package executor

import (
	"bytes"
	"io"
	"net/http"
	"testing"

	"github.com/klauspost/compress/zstd"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// The real client zstd-compresses /responses bodies on the ChatGPT backend and
// leaves everything else alone, so these tests pin both halves of that gate.

func TestApplyCodexRequestCompressionCompressesResponsesForChatGPTAuth(t *testing.T) {
	t.Parallel()

	body := []byte(`{"model":"gpt-5.5","input":"hello","stream":true}`)
	req := newCodexTestRequest(t, "https://chatgpt.com/backend-api/codex/responses", body)

	compressed := applyCodexRequestCompression(nil, &cliproxyauth.Auth{Provider: "codex"}, req, body)
	if bytes.Equal(compressed, body) {
		t.Fatal("ChatGPT-auth /responses request was not compressed")
	}
	if got := req.Header.Get("Content-Encoding"); got != "zstd" {
		t.Fatalf("Content-Encoding = %q, want zstd", got)
	}
	if req.ContentLength != int64(len(compressed)) {
		t.Fatalf("ContentLength = %d, want %d", req.ContentLength, len(compressed))
	}
	if got := mustReadAll(t, req); !bytes.Equal(got, compressed) {
		t.Fatal("request body does not match the returned compressed body")
	}
	decoder, errDecoder := zstd.NewReader(nil)
	if errDecoder != nil {
		t.Fatalf("build zstd reader: %v", errDecoder)
	}
	defer decoder.Close()
	decoded, errDecode := decoder.DecodeAll(compressed, nil)
	if errDecode != nil {
		t.Fatalf("decode compressed body: %v", errDecode)
	}
	if !bytes.Equal(decoded, body) {
		t.Fatalf("round trip = %s, want %s", decoded, body)
	}
}

func TestApplyCodexRequestCompressionLeavesOtherRequestsAlone(t *testing.T) {
	t.Parallel()

	apiKeyAuth := &cliproxyauth.Auth{Provider: "codex", Attributes: map[string]string{"api_key": "sk-test"}}
	oauthAuth := &cliproxyauth.Auth{Provider: "codex"}

	tests := []struct {
		name string
		auth *cliproxyauth.Auth
		url  string
		cfg  *config.Config
	}{
		{name: "API key auth", auth: apiKeyAuth, url: "https://chatgpt.com/backend-api/codex/responses"},
		{name: "compact endpoint", auth: oauthAuth, url: "https://chatgpt.com/backend-api/codex/responses/compact"},
		{name: "images endpoint", auth: oauthAuth, url: "https://chatgpt.com/backend-api/codex/images/generations"},
		{name: "disabled by config", auth: oauthAuth, url: "https://chatgpt.com/backend-api/codex/responses",
			cfg: &config.Config{Codex: config.CodexConfig{DisableRequestCompression: true}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			body := []byte(`{"model":"gpt-5.5"}`)
			req := newCodexTestRequest(t, tt.url, body)
			if got := applyCodexRequestCompression(tt.cfg, tt.auth, req, body); !bytes.Equal(got, body) {
				t.Fatal("request should not have been compressed")
			}
			if got := req.Header.Get("Content-Encoding"); got != "" {
				t.Fatalf("Content-Encoding = %q, want empty", got)
			}
			if got := mustReadAll(t, req); !bytes.Equal(got, body) {
				t.Fatalf("body = %s, want it untouched", got)
			}
		})
	}
}

func newCodexTestRequest(t *testing.T, url string, body []byte) *http.Request {
	t.Helper()
	req, errRequest := http.NewRequest(http.MethodPost, url, bytes.NewReader(body))
	if errRequest != nil {
		t.Fatalf("build request: %v", errRequest)
	}
	req.ContentLength = int64(len(body))
	req.GetBody = func() (io.ReadCloser, error) {
		return io.NopCloser(bytes.NewReader(body)), nil
	}
	return req
}

func mustReadAll(t *testing.T, req *http.Request) []byte {
	t.Helper()
	if req.Body == nil {
		return nil
	}
	data, errRead := io.ReadAll(req.Body)
	if errRead != nil {
		t.Fatalf("read body: %v", errRead)
	}
	// Restore so callers can read it again.
	req.Body = io.NopCloser(bytes.NewReader(data))
	return data
}

// The real client sends x-codex-routing-hint on the ChatGPT backend only, with a
// value that mirrors the request's own model.
func TestApplyCodexRoutingHint(t *testing.T) {
	t.Parallel()

	oauthAuth := &cliproxyauth.Auth{Provider: "codex"}
	apiKeyAuth := &cliproxyauth.Auth{Provider: "codex", Attributes: map[string]string{"api_key": "sk-test"}}

	tests := []struct {
		name  string
		auth  *cliproxyauth.Auth
		url   string
		model string
		body  string
		want  string
	}{
		{name: "chatgpt responses", auth: oauthAuth, model: "gpt-5.5",
			url: "https://chatgpt.com/backend-api/codex/responses", body: `{}`, want: "model=gpt-5.5"},
		{name: "with service tier", auth: oauthAuth, model: "gpt-5.5",
			url: "https://chatgpt.com/backend-api/codex/responses", body: `{"service_tier":"priority"}`,
			want: "model=gpt-5.5;tier=priority"},
		{name: "api key auth", auth: apiKeyAuth, model: "gpt-5.5",
			url: "https://chatgpt.com/backend-api/codex/responses", body: `{}`, want: ""},
		{name: "compact endpoint", auth: oauthAuth, model: "gpt-5.5",
			url: "https://chatgpt.com/backend-api/codex/responses/compact", body: `{}`, want: ""},
		{name: "no model", auth: oauthAuth, model: "  ",
			url: "https://chatgpt.com/backend-api/codex/responses", body: `{}`, want: ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			req := newCodexTestRequest(t, tt.url, []byte(tt.body))
			applyCodexRoutingHint(req, tt.auth, tt.model, []byte(tt.body))
			if got := req.Header.Get("x-codex-routing-hint"); got != tt.want {
				t.Fatalf("x-codex-routing-hint = %q, want %q", got, tt.want)
			}
		})
	}
}
