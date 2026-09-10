package executor

import (
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/config"
	cliproxyauth "github.com/router-for-me/CLIProxyAPI/v7/sdk/cliproxy/auth"
)

// TestCodexWebsocketDialerOwnsProxyDialing guards a subtle gorilla behaviour:
// when Dialer.Proxy is set, gorilla wraps NetDialTLSContext with a CONNECT
// dialer that calls it with the *proxy's* address and expects a plain TCP
// connection to tunnel through. Our dial function does the TLS handshake, so it
// would handshake with the proxy instead of the upstream, and because the proxy
// address is an IP literal uTLS strips it from SNI — the ClientHello silently
// loses its server_name extension.
func TestCodexWebsocketDialerOwnsProxyDialing(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  *config.Config
		auth *cliproxyauth.Auth
	}{
		{name: "config proxy", cfg: &config.Config{SDKConfig: config.SDKConfig{ProxyURL: "http://127.0.0.1:8899"}}},
		{name: "credential proxy", auth: &cliproxyauth.Auth{ProxyURL: "socks5://127.0.0.1:1080"}},
		{name: "no proxy", cfg: &config.Config{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dialer := newCodexWebsocketDialer(tt.cfg, tt.auth)
			if dialer.Proxy != nil {
				t.Fatal("Proxy must be nil: gorilla would hand NetDialTLSContext the proxy address")
			}
			if dialer.NetDialTLSContext == nil {
				t.Fatal("NetDialTLSContext must be set so the rustls profile is used")
			}
			if !dialer.EnableCompression {
				t.Fatal("EnableCompression must stay on: the real handshake offers permessage-deflate")
			}
		})
	}
}

// TestCodexWebsocketDialerPrefersCredentialProxy pins the precedence the rest of
// the executor uses: an explicit credential proxy wins over the config proxy.
func TestCodexWebsocketProxyURLPrecedence(t *testing.T) {
	t.Parallel()

	cfg := &config.Config{SDKConfig: config.SDKConfig{ProxyURL: "http://config:8080"}}
	auth := &cliproxyauth.Auth{ProxyURL: "http://credential:8080"}
	if got := codexWebsocketProxyURL(cfg, auth); got != "http://credential:8080" {
		t.Fatalf("proxy url = %q, want the credential proxy", got)
	}
	if got := codexWebsocketProxyURL(cfg, &cliproxyauth.Auth{}); got != "http://config:8080" {
		t.Fatalf("proxy url = %q, want the config proxy", got)
	}
	if got := codexWebsocketProxyURL(nil, nil); got != "" {
		t.Fatalf("proxy url = %q, want empty", got)
	}
}
