package helps

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	tls "github.com/refraction-networking/utls"
	internalcache "github.com/router-for-me/CLIProxyAPI/v7/internal/cache"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/httpwire"
	"github.com/router-for-me/CLIProxyAPI/v7/sdk/proxyutil"
	log "github.com/sirupsen/logrus"
	"golang.org/x/net/proxy"
)

// The Codex client ships two independent TLS stacks, and the proxy has to match
// whichever one it is standing in for:
//
//   - The HTTP/SSE path goes through reqwest's default backend, which is
//     native-tls. On Linux that is OpenSSL; the official Linux build vendors
//     OpenSSL 3.6.3, so a single capture covers every distribution and only
//     moves when OpenAI bumps their vendored copy.
//   - The WebSocket path builds a rustls ClientConfig by hand. rustls is
//     platform independent, so this capture applies unchanged on every OS.
//
// Neither stack requests ALPN. reqwest only calls request_alpns under its
// native-tls-alpn feature, which codex-rs never enables, and the hand-built
// rustls config never sets alpn_protocols. Both therefore negotiate HTTP/1.1.
//
// Specs were captured with tools/codexfp and verified by replaying them through
// uTLS and diffing byte for byte against the capture; only the random, session
// id and key share differ. Re-capture whenever the advertised Codex version
// changes and keep these in sync with tools/codexfp/testdata.

// codexOpenSSLClientHelloSpec returns the ClientHello for the HTTP/SSE path: a
// capture from disk when one exists, otherwise the built-in literal.
func codexOpenSSLClientHelloSpec() *tls.ClientHelloSpec {
	if spec := capturedCodexProfile(codexProfileHTTP); spec != nil {
		return spec
	}
	return builtinCodexOpenSSLClientHelloSpec()
}

// builtinCodexOpenSSLClientHelloSpec reproduces the ClientHello emitted by the
// official Linux Codex build (musl, vendored OpenSSL 3.6.3) on its HTTP/SSE path.
func builtinCodexOpenSSLClientHelloSpec() *tls.ClientHelloSpec {
	return &tls.ClientHelloSpec{
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			0x009f, // TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			0xccaa, // TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			0x009e, // TLS_DHE_RSA_WITH_AES_128_GCM_SHA256
			0xc024, // TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384
			0xc028, // TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384
			0x006b, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			0x0067, // TLS_DHE_RSA_WITH_AES_128_CBC_SHA256
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			0x0039, // TLS_DHE_RSA_WITH_AES_256_CBC_SHA
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			0x0033, // TLS_DHE_RSA_WITH_AES_128_CBC_SHA
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			0x003d, // TLS_RSA_WITH_AES_256_CBC_SHA256
			tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		},
		CompressionMethods: []uint8{0},
		Extensions: []tls.TLSExtension{
			&tls.RenegotiationInfoExtension{Renegotiation: tls.RenegotiateOnceAsClient},
			&tls.SNIExtension{},
			&tls.SupportedPointsExtension{SupportedPoints: []byte{0}},
			&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
				tls.X25519MLKEM768,
				tls.X25519,
				tls.CurveP256,
				0x001e, // x448
				tls.CurveP384,
				tls.CurveP521,
				0x0100, // ffdhe2048
				0x0101, // ffdhe3072
			}},
			&tls.SessionTicketExtension{},
			// encrypt_then_mac has no native uTLS type; replay the (empty) body verbatim.
			&tls.GenericExtension{Id: 0x0016},
			&tls.ExtendedMasterSecretExtension{},
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
				0x0905, // mldsa65
				0x0906, // mldsa87
				0x0904, // mldsa44
				tls.ECDSAWithP256AndSHA256,
				tls.ECDSAWithP384AndSHA384,
				tls.ECDSAWithP521AndSHA512,
				tls.Ed25519,
				0x0808, // rsa_pss_pss_sha256
				0x081a, // ecdsa_brainpoolP256r1tls13_sha256
				0x081b, // ecdsa_brainpoolP384r1tls13_sha384
				0x081c, // ecdsa_brainpoolP512r1tls13_sha512
				0x0809, // rsa_pss_pss_sha384
				0x080a, // rsa_pss_pss_sha512
				0x080b, // rsa_pss_pss_sha384 (reserved slot in OpenSSL's list)
				tls.PSSWithSHA256,
				tls.PSSWithSHA384,
				tls.PSSWithSHA512,
				tls.PKCS1WithSHA256,
				tls.PKCS1WithSHA384,
				tls.PKCS1WithSHA512,
				0x0303, // ecdsa_sha224
				0x0301, // rsa_pkcs1_sha224
				0x0302, // dsa_sha224
				0x0402, // dsa_sha256
				0x0502, // dsa_sha384
				0x0602, // dsa_sha512
			}},
			&tls.SupportedVersionsExtension{Versions: []uint16{tls.VersionTLS13, tls.VersionTLS12}},
			&tls.PSKKeyExchangeModesExtension{Modes: []uint8{1}},
			&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
				{Group: tls.X25519MLKEM768},
				{Group: tls.X25519},
			}},
		},
	}
}

// CodexWebSocketClientHelloSpec returns the ClientHello for the WebSocket path: a
// capture from disk when one exists, otherwise the built-in literal.
//
// With several captures it returns a different one on each call, drawn from the
// set the real client produced. That client runs rustls, which reorders its
// extensions on every connection, so replaying any one order would give every
// handshake the same JA3 while a genuine client's changes each time. Every
// capture is an ordering the client actually emitted, so rotating among them
// removes the constant without inventing an order no client would send.
//
// Callers must not cache the result: it is a per-handshake choice.
func CodexWebSocketClientHelloSpec() *tls.ClientHelloSpec {
	if spec := capturedCodexProfile(codexProfileWebSocket); spec != nil {
		return spec
	}
	return builtinCodexWebSocketClientHelloSpec()
}

// builtinCodexWebSocketClientHelloSpec reproduces the ClientHello emitted on the
// Codex WebSocket handshake, which uses rustls with the aws-lc-rs provider.
func builtinCodexWebSocketClientHelloSpec() *tls.ClientHelloSpec {
	return &tls.ClientHelloSpec{
		CipherSuites: []uint16{
			tls.TLS_AES_256_GCM_SHA384,
			tls.TLS_AES_128_GCM_SHA256,
			tls.TLS_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			0x00ff, // TLS_EMPTY_RENEGOTIATION_INFO_SCSV
		},
		CompressionMethods: []uint8{0},
		Extensions: []tls.TLSExtension{
			&tls.SupportedPointsExtension{SupportedPoints: []byte{0}},
			&tls.ExtendedMasterSecretExtension{},
			&tls.SupportedCurvesExtension{Curves: []tls.CurveID{
				tls.X25519MLKEM768,
				tls.X25519,
				tls.CurveP256,
				tls.CurveP384,
			}},
			&tls.SessionTicketExtension{},
			&tls.KeyShareExtension{KeyShares: []tls.KeyShare{
				{Group: tls.X25519MLKEM768},
				{Group: tls.X25519},
			}},
			&tls.SNIExtension{},
			&tls.PSKKeyExchangeModesExtension{Modes: []uint8{1}},
			&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{
				tls.ECDSAWithP384AndSHA384,
				tls.ECDSAWithP256AndSHA256,
				tls.ECDSAWithP521AndSHA512,
				tls.Ed25519,
				tls.PSSWithSHA512,
				tls.PSSWithSHA384,
				tls.PSSWithSHA256,
				tls.PKCS1WithSHA512,
				tls.PKCS1WithSHA384,
				tls.PKCS1WithSHA256,
			}},
			&tls.StatusRequestExtension{},
			&tls.SupportedVersionsExtension{Versions: []uint16{tls.VersionTLS13, tls.VersionTLS12}},
		},
	}
}

// ApplyCodexWebSocketClientHello switches conn to the rustls profile used by the
// Codex WebSocket handshake. Native TLS is not involved, so this is the correct
// profile on every platform.
func ApplyCodexWebSocketClientHello(ctx context.Context, conn net.Conn, host string) (net.Conn, error) {
	if conn == nil {
		return nil, errors.New("codex tls: connection is nil")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	tlsConn := tls.UClient(conn, &tls.Config{ServerName: host}, tls.HelloCustom)
	if err := tlsConn.ApplyPreset(CodexWebSocketClientHelloSpec()); err != nil {
		return nil, fmt.Errorf("codex tls: apply rustls ClientHello: %w", err)
	}
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		return nil, fmt.Errorf("codex tls: handshake: %w", err)
	}
	return tlsConn, nil
}

// CodexWebsocketTLSDialContext returns a dial function for gorilla/websocket's
// NetDialTLSContext. gorilla would otherwise use Go's crypto/tls, a fingerprint
// no version of the Codex client has ever produced; the real WebSocket
// handshake builds a rustls config by hand.
//
// proxyURL is the credential or config proxy. When it is empty the environment
// is consulted, preserving the http.ProxyFromEnvironment behaviour gorilla
// applies by default.
func CodexWebsocketTLSDialContext(proxyURL string) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		dialer := codexDialerFor(proxyURL, addr)
		var (
			conn net.Conn
			err  error
		)
		if contextDialer, ok := dialer.(proxy.ContextDialer); ok {
			conn, err = contextDialer.DialContext(ctx, network, addr)
		} else {
			conn, err = dialer.Dial(network, addr)
		}
		if err != nil {
			return nil, fmt.Errorf("codex tls: dial upstream: %w", err)
		}

		host, _, errSplit := net.SplitHostPort(addr)
		if errSplit != nil {
			if errClose := conn.Close(); errClose != nil {
				log.Debugf("codex tls: close failed connection: %v", errClose)
			}
			return nil, fmt.Errorf("codex tls: split upstream address: %w", errSplit)
		}
		tlsConn, errHandshake := ApplyCodexWebSocketClientHello(ctx, conn, host)
		if errHandshake != nil {
			if errClose := conn.Close(); errClose != nil {
				log.Debugf("codex tls: close connection after handshake failure: %v", errClose)
			}
			return nil, errHandshake
		}
		// gorilla writes the upgrade through this conn, so the wrapper is what
		// puts the handshake headers in the client's order and casing.
		return httpwire.NewOrderedRequestConn(tlsConn, CodexWebsocketHeaderOrder), nil
	}
}

// codexDialerFor resolves a proxy dialer with the same precedence the rest of
// the Codex executor uses: explicit credential or config proxy first, then the
// environment, then a direct dial with the same timeouts as before.
func codexDialerFor(proxyURL string, addr string) proxy.Dialer {
	if dialer, ok := buildCodexProxyDialer(proxyURL); ok {
		return dialer
	}
	// The environment may still name a proxy; gorilla honoured that by default.
	if req, errRequest := http.NewRequest(http.MethodGet, "https://"+addr, nil); errRequest == nil {
		if envURL, errProxy := http.ProxyFromEnvironment(req); errProxy == nil && envURL != nil {
			if dialer, ok := buildCodexProxyDialer(envURL.String()); ok {
				return dialer
			}
		}
	}
	return &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
}

func buildCodexProxyDialer(proxyURL string) (proxy.Dialer, bool) {
	if strings.TrimSpace(proxyURL) == "" {
		return nil, false
	}
	dialer, mode, errBuild := proxyutil.BuildDialer(proxyURL)
	if errBuild != nil {
		log.Errorf("codex tls: failed to configure proxy dialer for %q: %v", proxyutil.Redact(proxyURL), errBuild)
		return nil, false
	}
	if mode == proxyutil.ModeInherit || dialer == nil {
		return nil, false
	}
	return dialer, true
}

const codexRoundTripperCacheCapacity = 64

// codexRoundTripperCache is keyed by proxy URL so a session never crosses proxy
// boundaries, matching the Claude Code transport above.
var codexRoundTripperCache = internalcache.NewBoundedLRU[string, http.RoundTripper](
	codexRoundTripperCacheCapacity,
	func(_ string, roundTripper http.RoundTripper) {
		if transport, ok := roundTripper.(interface{ CloseIdleConnections() }); ok {
			transport.CloseIdleConnections()
		}
	},
)

func cachedCodexRoundTripper(proxyURL string) http.RoundTripper {
	return codexRoundTripperCache.GetOrAdd(proxyURL, func() http.RoundTripper {
		return newCodexRoundTripper(proxyURL)
	})
}

// newCodexRoundTripper builds the transport for the Codex HTTP/SSE path.
//
// It speaks HTTP/1.1 on purpose: the real client sends no ALPN, so the upstream
// serves it HTTP/1.1, and a client that suddenly negotiates h2 while advertising
// an OpenSSL ClientHello is the kind of mismatch this work exists to remove.
//
// DisableCompression is required because Go injects "Accept-Encoding: gzip"
// otherwise, and the real client sends no accept-encoding at all.
func newCodexRoundTripper(proxyURL string) http.RoundTripper {
	var dialer proxy.Dialer = proxy.Direct
	if proxyURL != "" {
		proxyDialer, mode, errBuild := proxyutil.BuildDialer(proxyURL)
		if errBuild != nil {
			log.Errorf("codex tls: failed to configure proxy dialer for %q: %v", proxyutil.Redact(proxyURL), errBuild)
		} else if mode != proxyutil.ModeInherit && proxyDialer != nil {
			dialer = proxyDialer
		}
	}

	return &http.Transport{
		ForceAttemptHTTP2:  false,
		DisableCompression: true,
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			var (
				conn net.Conn
				err  error
			)
			if contextDialer, ok := dialer.(proxy.ContextDialer); ok {
				conn, err = contextDialer.DialContext(ctx, network, addr)
			} else {
				conn, err = dialer.Dial(network, addr)
			}
			if err != nil {
				return nil, fmt.Errorf("codex tls: dial upstream: %w", err)
			}

			host, _, errSplit := net.SplitHostPort(addr)
			if errSplit != nil {
				if errClose := conn.Close(); errClose != nil {
					log.Debugf("codex tls: close failed connection: %v", errClose)
				}
				return nil, fmt.Errorf("codex tls: split upstream address: %w", errSplit)
			}
			tlsConn := tls.UClient(conn, &tls.Config{ServerName: host}, tls.HelloCustom)
			if errPreset := tlsConn.ApplyPreset(codexOpenSSLClientHelloSpec()); errPreset != nil {
				if errClose := tlsConn.Close(); errClose != nil {
					log.Debugf("codex tls: close connection after preset failure: %v", errClose)
				}
				return nil, fmt.Errorf("codex tls: apply OpenSSL ClientHello: %w", errPreset)
			}
			if errHandshake := tlsConn.HandshakeContext(ctx); errHandshake != nil {
				if errClose := tlsConn.Close(); errClose != nil {
					log.Debugf("codex tls: close connection after handshake failure: %v", errClose)
				}
				return nil, fmt.Errorf("codex tls: handshake upstream: %w", errHandshake)
			}
			return httpwire.NewOrderedRequestConn(tlsConn, codexRequestHeaderOrder), nil
		},
	}
}

// CodexWebsocketHeaderOrder lists the WebSocket handshake headers in the order
// the real client sends them, and pins their spelling: tungstenite capitalises
// the headers it writes itself, while codex-rs' own headers reach the wire
// lowercase. httpwire matches case-insensitively and rewrites to the name given
// here, so this list controls both order and casing.
//
// The first six are fixed by tungstenite's handshake writer. The rest come from
// a hash-ordered HeaderMap on the real client, so their order here follows the
// source insertion order rather than a captured one — the header-order capture
// task pins that down.
//
// Sec-WebSocket-Extensions is deliberately left with gorilla's offer rather than
// the real client's. The real offer carries no *_no_context_takeover parameter,
// so the server may enable context takeover, which gorilla cannot decode
// (doc.go: "Currently this package does not support compression with context
// takeover"). Replacing it before that is solvable would trade a minor header
// difference for broken streams.
func CodexWebsocketHeaderOrder(_, _ string) []string {
	return []string{
		"Host",
		"Connection",
		"Upgrade",
		"Sec-WebSocket-Version",
		"Sec-WebSocket-Key",
		"Sec-WebSocket-Extensions",
		"x-codex-beta-features",
		"originator",
		"x-client-request-id",
		"session-id",
		"thread-id",
		"x-codex-window-id",
		"x-codex-turn-metadata",
		"x-codex-parent-thread-id",
		"x-openai-subagent",
		"x-codex-routing-hint",
		"x-oai-attestation",
		"openai-beta",
		"x-responsesapi-include-timing-metrics",
		"user-agent",
		"x-openai-internal-codex-residency",
		"authorization",
		"chatgpt-account-id",
	}
}

// codexRequestHeaderOrder lists the header names in the order the real client
// emits them, and pins their spelling. hyper writes every name lowercase, so
// these are lowercase too, and httpwire rewrites whatever the Go client
// produced to match.
//
// The captured order (tools/codexfp -mode serve, official Linux build) is
//
//	x-codex-beta-features, x-codex-window-id, x-codex-turn-metadata,
//	x-client-request-id, session-id, thread-id, accept, content-type,
//	authorization, originator, user-agent, host, content-length
//
// host and content-length are written by hyper rather than the application, and
// still land last, so they stay last here.
//
// http::HeaderMap iterates in insertion order, so the order is deterministic
// rather than hash-derived. The entries marked inferred are the ones only the
// ChatGPT-auth path sends; that capture ran with a custom provider, so their
// positions follow the source's insertion order instead of a capture.
func codexRequestHeaderOrder(_, _ string) []string {
	return []string{
		"version", // inferred: provider default header
		"x-codex-beta-features",
		"x-codex-turn-state", // inferred
		"x-codex-window-id",
		"x-codex-turn-metadata",
		"x-codex-parent-thread-id",               // inferred
		"x-openai-subagent",                      // inferred
		"x-codex-routing-hint",                   // inferred
		"x-oai-attestation",                      // inferred
		"x-openai-internal-codex-responses-lite", // inferred
		"x-client-request-id",
		"session-id",
		"thread-id",
		"accept",
		"content-encoding", // only present when the body is zstd-compressed
		"content-type",
		"authorization",
		"chatgpt-account-id", // inferred: applied with authorization
		"x-openai-fedramp",   // inferred: applied with authorization
		"originator",
		"user-agent",
		"x-openai-internal-codex-residency", // inferred
		"host",
		"content-length",
	}
}
