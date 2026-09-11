package helps

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	tls "github.com/refraction-networking/utls"
	"github.com/router-for-me/CLIProxyAPI/v7/internal/httpwire"
)

// The reference ClientHellos in testdata were captured from the real Codex
// client with tools/codexfp. These tests pin the proxy's outbound handshake to
// them, so a change to a spec, a uTLS upgrade, or an accidental switch of TLS
// stack fails loudly instead of silently drifting away from the client the
// proxy is standing in for.

const (
	codexHTTPReference      = "testdata/codex-http-clienthello.bin"
	codexWebSocketReference = "testdata/codex-websocket-clienthello.bin"
)

// clientHelloShape is the part of a ClientHello that must match byte for byte.
// The random, session id and key share are regenerated on every handshake, so
// they are compared only for length.
type clientHelloShape struct {
	Length           int
	CipherSuites     []uint16
	ExtensionTypes   []uint16
	ExtensionLengths []int
	// ExtensionBodies is each extension's payload, in wire order. Types and
	// lengths agreeing is not the same as agreeing on content: an extension can
	// carry the right number of bytes and still say something else.
	ExtensionBodies [][]byte
	Groups          []tls.CurveID
	KeyShareGroups  []tls.CurveID
	ALPN            []string
}

// bodyFor returns the payload of the first extension of the given type.
func (s clientHelloShape) bodyFor(extType uint16) ([]byte, bool) {
	for i, got := range s.ExtensionTypes {
		if got == extType && i < len(s.ExtensionBodies) {
			return s.ExtensionBodies[i], true
		}
	}
	return nil, false
}

// differingExtensionBodies reports every extension whose payload differs from
// the reference's, skipping the ones that are per-connection by design: a key
// share carries freshly generated keys, and nothing else here does.
func differingExtensionBodies(got, reference clientHelloShape) []string {
	var problems []string
	for i, extType := range reference.ExtensionTypes {
		if extType == extensionTypeKeyShare || i >= len(reference.ExtensionBodies) {
			continue
		}
		body, ok := got.bodyFor(extType)
		if !ok {
			problems = append(problems, fmt.Sprintf("extension %d is missing", extType))
			continue
		}
		if !bytes.Equal(body, reference.ExtensionBodies[i]) {
			problems = append(problems, fmt.Sprintf("extension %d carries %x, the capture carries %x",
				extType, body, reference.ExtensionBodies[i]))
		}
	}
	return problems
}

// extensionTypeKeyShare is the one extension whose bytes are drawn per
// connection, so only its structure can be compared.
const extensionTypeKeyShare = 51

// The body comparison has to be able to fail, or it would pass on any
// ClientHello at all.
func TestDifferingExtensionBodiesDetectsChange(t *testing.T) {
	t.Parallel()

	reference := clientHelloShape{
		ExtensionTypes:  []uint16{0x0000, 0x000d, extensionTypeKeyShare},
		ExtensionBodies: [][]byte{{0x00, 0x0b}, {0x04, 0x03}, {0xde, 0xad}},
	}
	// Same bodies in a different order, with a key share drawn for this
	// connection: this is what a WebSocket handshake actually looks like.
	same := clientHelloShape{
		ExtensionTypes:  []uint16{extensionTypeKeyShare, 0x000d, 0x0000},
		ExtensionBodies: [][]byte{{0xbe, 0xef}, {0x04, 0x03}, {0x00, 0x0b}},
	}
	if problems := differingExtensionBodies(same, reference); len(problems) != 0 {
		t.Fatalf("a reordered ClientHello carrying the same bodies was reported as different: %v", problems)
	}

	changed := clientHelloShape{
		ExtensionTypes:  []uint16{0x0000, 0x000d, extensionTypeKeyShare},
		ExtensionBodies: [][]byte{{0x00, 0x0b}, {0x04, 0x04}, {0xbe, 0xef}},
	}
	if problems := differingExtensionBodies(changed, reference); len(problems) == 0 {
		t.Fatal("a ClientHello carrying a different signature_algorithms was reported as matching")
	}

	absent := clientHelloShape{
		ExtensionTypes:  []uint16{0x0000, extensionTypeKeyShare},
		ExtensionBodies: [][]byte{{0x00, 0x0b}, {0xbe, 0xef}},
	}
	if problems := differingExtensionBodies(absent, reference); len(problems) == 0 {
		t.Fatal("a ClientHello missing an extension the capture carries was reported as matching")
	}
}

func TestCodexHTTPClientHelloMatchesCapture(t *testing.T) {
	t.Parallel()

	reference := readClientHelloReference(t, codexHTTPReference)
	if reference.ALPN != nil {
		t.Fatalf("reference advertises ALPN %v; the real Codex client sends none", reference.ALPN)
	}

	got := captureClientHelloFromTransport(t)
	if got.Length != reference.Length {
		t.Fatalf("ClientHello length = %d, want %d", got.Length, reference.Length)
	}
	if !reflect.DeepEqual(got.CipherSuites, reference.CipherSuites) {
		t.Fatalf("cipher suites = %v, want %v", got.CipherSuites, reference.CipherSuites)
	}
	if !reflect.DeepEqual(got.ExtensionTypes, reference.ExtensionTypes) {
		t.Fatalf("extension types = %v, want %v", got.ExtensionTypes, reference.ExtensionTypes)
	}
	if !reflect.DeepEqual(got.ExtensionLengths, reference.ExtensionLengths) {
		t.Fatalf("extension lengths = %v, want %v", got.ExtensionLengths, reference.ExtensionLengths)
	}
	if !reflect.DeepEqual(got.Groups, reference.Groups) {
		t.Fatalf("supported groups = %v, want %v", got.Groups, reference.Groups)
	}
	if !reflect.DeepEqual(got.KeyShareGroups, reference.KeyShareGroups) {
		t.Fatalf("key share groups = %v, want %v", got.KeyShareGroups, reference.KeyShareGroups)
	}
	if problems := differingExtensionBodies(got, reference); len(problems) > 0 {
		t.Fatalf("the ClientHello does not carry the capture's extensions: %v", problems)
	}
}

func TestCodexWebSocketClientHelloMatchesCapture(t *testing.T) {
	t.Parallel()

	reference := readClientHelloReference(t, codexWebSocketReference)
	if reference.ALPN != nil {
		t.Fatalf("reference advertises ALPN %v; the real Codex WebSocket handshake sends none", reference.ALPN)
	}
	if reference.Length != 1462 {
		t.Fatalf("reference length = %d, want 1462; the capture file may have changed", reference.Length)
	}

	// ApplyCodexWebSocketClientHello is called directly rather than through
	// CodexWebsocketTLSDialContext so the test never depends on whatever proxy
	// the developer happens to have in the environment. It is the same handshake
	// the dial context performs.
	got := captureClientHelloFromDial(t, func(addr string) {
		conn, errDial := net.DialTimeout("tcp", addr, 5*time.Second)
		if errDial != nil {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, errApply := ApplyCodexWebSocketClientHello(ctx, conn, "chatgpt.com")
		if errApply != nil && !errors.Is(errApply, context.DeadlineExceeded) {
			t.Logf("websocket handshake: %v", errApply)
		}
	})

	if got.Length != reference.Length {
		t.Fatalf("ClientHello length = %d, want %d", got.Length, reference.Length)
	}
	if !reflect.DeepEqual(got.CipherSuites, reference.CipherSuites) {
		t.Fatalf("cipher suites = %v, want %v", got.CipherSuites, reference.CipherSuites)
	}
	// Which capture is drawn decides the order, so what has to match the reference
	// is which extensions were sent and how long each was, not the sequence.
	if !sameExtensionMultiset(got.ExtensionTypes, got.ExtensionLengths, reference.ExtensionTypes, reference.ExtensionLengths) {
		t.Fatalf("extension set = %v, want the capture's %v",
			pairExtensions(got.ExtensionTypes, got.ExtensionLengths),
			pairExtensions(reference.ExtensionTypes, reference.ExtensionLengths))
	}
	if !reflect.DeepEqual(got.KeyShareGroups, reference.KeyShareGroups) {
		t.Fatalf("key share groups = %v, want %v", got.KeyShareGroups, reference.KeyShareGroups)
	}
	// The order is drawn per handshake, so the bodies are compared by type.
	if problems := differingExtensionBodies(got, reference); len(problems) > 0 {
		t.Fatalf("the ClientHello does not carry the capture's extensions: %v", problems)
	}
}

// teeConn passes everything through to a real connection while keeping a copy of
// what the client wrote, so a live handshake can also report which extension
// order it sent. Distinct from recordingConn above, which stands in for a
// connection rather than wrapping one.
type teeConn struct {
	net.Conn
	sent bytes.Buffer
}

func (c *teeConn) Write(p []byte) (int, error) {
	c.sent.Write(p)
	return c.Conn.Write(p)
}

// The ordering moves extensions within the set rustls itself moves, so the
// standard permits it — but "permitted" is not "accepted". The claim that matters
// is that the real server still completes the handshake, and only a real server
// can settle that: the capture tests above read a ClientHello off a local
// listener and never finish a TLS exchange.
//
// Gated on an environment variable because it reaches the network:
//
//	CODEX_TLS_LIVE_HOST=chatgpt.com go test ./internal/runtime/executor/helps \
//	    -run TestLiveCodexWebsocketHandshakeIsAccepted -v
func TestLiveCodexWebsocketHandshakeIsAccepted(t *testing.T) {
	host := strings.TrimSpace(os.Getenv("CODEX_TLS_LIVE_HOST"))
	if host == "" {
		t.Skip("set CODEX_TLS_LIVE_HOST to exercise the handshake against the real server")
	}

	// Load the captures first: without them the built-in literal is a single
	// fixed order, and the run would only be re-checking that constant rather
	// than the record whose order is redrawn per handshake.
	restoreProfileState(t)
	if errProfiles := SetCodexProfileDir("testdata"); errProfiles != nil {
		t.Fatalf("load the captured profiles: %v", errProfiles)
	}

	const attempts = 5
	orders := make(map[string]int, attempts)
	rejected := make([]string, 0, attempts)
	for i := 0; i < attempts; i++ {
		record, errHandshake := liveCodexWebsocketHandshake(t, host)
		order := liveExtensionOrder(t, record)
		if errHandshake != nil {
			// The ClientHello was still sent — the server answered it with a close —
			// so its order is the one that was refused.
			rejected = append(rejected, order)
			t.Logf("attempt %d: REJECTED (%v), extensions %s", i+1, errHandshake, order)
			continue
		}
		orders[order]++
		t.Logf("attempt %d: accepted, extensions %s", i+1, order)
	}
	if len(rejected) > 0 {
		t.Errorf("the server refused %d of %d handshakes; orders: %v", len(rejected), attempts, rejected)
	}
	if len(orders) < 2 {
		t.Fatalf("%d live handshakes all sent the same extension order; the ordering is not being applied", attempts)
	}
	t.Logf("%d live handshakes produced %d distinct extension orders", attempts, len(orders))
}

// liveCodexWebsocketHandshake completes a real TLS handshake at host:443 with the
// profile the WebSocket transport sends, and returns the ClientHello it sent.
func liveCodexWebsocketHandshake(t *testing.T, host string) ([]byte, error) {
	t.Helper()

	conn, errDial := net.DialTimeout("tcp", net.JoinHostPort(host, "443"), 10*time.Second)
	if errDial != nil {
		return nil, fmt.Errorf("dial %s: %w", host, errDial)
	}
	recorder := &teeConn{Conn: conn}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	tlsConn, errApply := ApplyCodexWebSocketClientHello(ctx, recorder, host)
	if errApply != nil {
		if errClose := conn.Close(); errClose != nil {
			t.Logf("close conn: %v", errClose)
		}
		// Returned anyway: a refused handshake still sent a ClientHello, and which
		// order it carried is the whole point of the failure.
		record, _ := extractClientHelloRecord(recorder.sent.Bytes())
		return record, errApply
	}
	if errClose := tlsConn.Close(); errClose != nil {
		t.Logf("close tls conn: %v", errClose)
	}

	record, ok := extractClientHelloRecord(recorder.sent.Bytes())
	if !ok {
		return nil, errors.New("the ClientHello is not in what the transport wrote")
	}
	return record, nil
}

func liveExtensionOrder(t *testing.T, record []byte) string {
	t.Helper()
	shape, errShape := shapeOfClientHello(record)
	if errShape != nil {
		t.Fatalf("parse the ClientHello that was sent: %v", errShape)
	}
	return fmt.Sprint(shape.ExtensionTypes)
}

// TestCodexWebsocketHeaderOrderRewritesGorillaHandshake pins the upgrade
// rewrite. gorilla writes Go's canonical spellings in sorted order; the wrapper
// is what turns that into the client's order and casing.
func TestCodexWebsocketHeaderOrderRewritesGorillaHandshake(t *testing.T) {
	t.Parallel()

	// Sorted and canonically spelled, exactly as gorilla emits it.
	upgrade := "GET /backend-api/codex/responses HTTP/1.1\r\n" +
		"Authorization: Bearer token\r\n" +
		"Chatgpt-Account-Id: acct\r\n" +
		"Connection: Upgrade\r\n" +
		"Host: chatgpt.com\r\n" +
		"Openai-Beta: responses_websockets=2026-02-06\r\n" +
		"Sec-WebSocket-Extensions: permessage-deflate; server_no_context_takeover; client_no_context_takeover\r\n" +
		"Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n" +
		"Sec-WebSocket-Version: 13\r\n" +
		"Session-Id: session-abc\r\n" +
		"Thread-Id: thread-def\r\n" +
		"Upgrade: websocket\r\n" +
		"User-Agent: codex_cli_rs/0.154.0\r\n" +
		"\r\n"

	recorder := &recordingConn{}
	conn := httpwire.NewOrderedRequestConn(recorder, CodexWebsocketHeaderOrder)
	if _, errWrite := conn.Write([]byte(upgrade)); errWrite != nil {
		t.Fatalf("write upgrade: %v", errWrite)
	}

	got := headerNamesInOrder(string(recorder.written()))
	want := []string{
		"Host", "Connection", "Upgrade", "Sec-WebSocket-Version", "Sec-WebSocket-Key",
		"Sec-WebSocket-Extensions",
		"session-id", "thread-id", "openai-beta",
		"user-agent", "authorization", "chatgpt-account-id",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("handshake header order = %v, want %v", got, want)
	}
}

// headerNamesInOrder returns the header names of an HTTP/1.1 request head, in
// the order they appear, preserving their wire casing.
func headerNamesInOrder(head string) []string {
	lines := strings.Split(head, "\r\n")
	names := make([]string, 0, len(lines))
	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		name, _, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		names = append(names, name)
	}
	return names
}

// recordingConn captures everything written to it and discards reads.
type recordingConn struct {
	buf bytes.Buffer
}

func (c *recordingConn) Write(p []byte) (int, error)      { return c.buf.Write(p) }
func (c *recordingConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *recordingConn) written() []byte                  { return c.buf.Bytes() }
func (c *recordingConn) Close() error                     { return nil }
func (c *recordingConn) LocalAddr() net.Addr              { return dummyAddr{} }
func (c *recordingConn) RemoteAddr() net.Addr             { return dummyAddr{} }
func (c *recordingConn) SetDeadline(time.Time) error      { return nil }
func (c *recordingConn) SetReadDeadline(time.Time) error  { return nil }
func (c *recordingConn) SetWriteDeadline(time.Time) error { return nil }

type dummyAddr struct{}

func (dummyAddr) Network() string { return "test" }
func (dummyAddr) String() string  { return "test" }

func readClientHelloReference(t *testing.T, path string) clientHelloShape {
	t.Helper()
	record, errRead := os.ReadFile(filepath.Join(path))
	if errRead != nil {
		t.Fatalf("read reference %s: %v", path, errRead)
	}
	shape, errShape := shapeOfClientHello(record)
	if errShape != nil {
		t.Fatalf("parse reference %s: %v", path, errShape)
	}
	return shape
}

// captureClientHelloFromTransport drives the real transport over a throwaway
// CONNECT proxy and returns the handshake it sent.
//
// Routing through a proxy rather than dialling the listener directly is what
// keeps the SNI realistic: uTLS strips IP literals from SNI per RFC 6066, so a
// request to 127.0.0.1 would arrive with an empty server_name and the handshake
// would not match production. Here the request targets chatgpt.com and the
// listener only ever sees the tunnelled bytes.
//
// The handshake cannot complete — nothing terminates TLS — but the ClientHello
// is on the wire before that matters.
func captureClientHelloFromTransport(t *testing.T) clientHelloShape {
	t.Helper()

	listener, errListen := net.Listen("tcp", "127.0.0.1:0")
	if errListen != nil {
		t.Fatalf("listen: %v", errListen)
	}
	defer func() {
		if errClose := listener.Close(); errClose != nil {
			t.Logf("close listener: %v", errClose)
		}
	}()

	captured := make(chan []byte, 1)
	go func() {
		conn, errAccept := listener.Accept()
		if errAccept != nil {
			captured <- nil
			return
		}
		defer func() {
			if errClose := conn.Close(); errClose != nil {
				t.Logf("close conn: %v", errClose)
			}
		}()
		if errDeadline := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); errDeadline != nil {
			captured <- nil
			return
		}

		// Complete the CONNECT handshake, then read whatever the client tunnels.
		buf := make([]byte, 0, 8192)
		chunk := make([]byte, 4096)
		headersDone := false
		for {
			n, errRead := conn.Read(chunk)
			if n > 0 {
				buf = append(buf, chunk[:n]...)
				if !headersDone && bytes.Contains(buf, []byte("\r\n\r\n")) {
					headersDone = true
					buf = buf[:0]
					if _, errWrite := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); errWrite != nil {
						captured <- nil
						return
					}
					continue
				}
				if headersDone {
					if record, ok := extractClientHelloRecord(buf); ok {
						captured <- record
						return
					}
				}
			}
			if errRead != nil {
				captured <- nil
				return
			}
		}
	}()

	transport, ok := newCodexRoundTripper("http://" + listener.Addr().String()).(*http.Transport)
	if !ok {
		t.Fatal("Codex transport is not an *http.Transport")
	}
	defer transport.CloseIdleConnections()

	if transport.ForceAttemptHTTP2 {
		t.Fatal("Codex transport must not negotiate HTTP/2: the real client sends no ALPN")
	}
	if !transport.DisableCompression {
		t.Fatal("Codex transport must disable auto compression: the real client sends no accept-encoding")
	}

	req, errRequest := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://chatgpt.com/backend-api/codex/responses", strings.NewReader(`{"stream":true}`))
	if errRequest != nil {
		t.Fatalf("build request: %v", errRequest)
	}
	resp, errRoundTrip := transport.RoundTrip(req)
	if resp != nil && resp.Body != nil {
		if errClose := resp.Body.Close(); errClose != nil {
			t.Logf("close response body: %v", errClose)
		}
	}
	if errRoundTrip != nil {
		t.Logf("round trip failed as expected: %v", errRoundTrip)
	}

	select {
	case record := <-captured:
		if record == nil {
			t.Fatal("no ClientHello observed")
		}
		shape, errShape := shapeOfClientHello(record)
		if errShape != nil {
			t.Fatalf("parse captured ClientHello: %v", errShape)
		}
		return shape
	case <-time.After(15 * time.Second):
		t.Fatal("timed out waiting for the ClientHello")
		return clientHelloShape{}
	}
}

func captureClientHelloFromDial(t *testing.T, dial func(addr string)) clientHelloShape {
	t.Helper()

	listener, errListen := net.Listen("tcp", "127.0.0.1:0")
	if errListen != nil {
		t.Fatalf("listen: %v", errListen)
	}
	defer func() {
		if errClose := listener.Close(); errClose != nil {
			t.Logf("close listener: %v", errClose)
		}
	}()

	captured := make(chan []byte, 1)
	go func() {
		conn, errAccept := listener.Accept()
		if errAccept != nil {
			captured <- nil
			return
		}
		defer func() {
			if errClose := conn.Close(); errClose != nil {
				t.Logf("close conn: %v", errClose)
			}
		}()
		if errDeadline := conn.SetReadDeadline(time.Now().Add(10 * time.Second)); errDeadline != nil {
			captured <- nil
			return
		}
		buf := make([]byte, 0, 8192)
		chunk := make([]byte, 4096)
		for {
			n, errRead := conn.Read(chunk)
			if n > 0 {
				buf = append(buf, chunk[:n]...)
				if record, ok := extractClientHelloRecord(buf); ok {
					captured <- record
					return
				}
			}
			if errRead != nil {
				captured <- nil
				return
			}
		}
	}()

	dial(listener.Addr().String())

	select {
	case record := <-captured:
		if record == nil {
			t.Fatal("no ClientHello observed")
		}
		shape, errShape := shapeOfClientHello(record)
		if errShape != nil {
			t.Fatalf("parse captured ClientHello: %v", errShape)
		}
		return shape
	case <-time.After(15 * time.Second):
		t.Fatal("timed out waiting for the ClientHello")
		return clientHelloShape{}
	}
}

// extractClientHelloRecord walks the TLS record layer and returns the complete
// record whose handshake payload is a ClientHello.
func extractClientHelloRecord(buf []byte) ([]byte, bool) {
	off := 0
	for {
		if len(buf)-off < 5 {
			return nil, false
		}
		recType := buf[off]
		recLen := int(buf[off+3])<<8 | int(buf[off+4])
		if recLen == 0 || recLen > 1<<15 {
			return nil, false
		}
		if len(buf)-off-5 < recLen {
			return nil, false
		}
		body := buf[off+5 : off+5+recLen]
		if recType == 22 && len(body) >= 4 && body[0] == 1 {
			return buf[off : off+5+recLen], true
		}
		off += 5 + recLen
	}
}

// shapeOfClientHello reads the record directly rather than re-marshalling a
// uTLS spec: uTLS does not repopulate SNIExtension.ServerName when it parses a
// record, so a length computed from a parsed spec would be wrong for exactly the
// extension whose length matters most.
func shapeOfClientHello(record []byte) (clientHelloShape, error) {
	suites, extTypes, extLengths, errParse := parseClientHelloLayout(record)
	if errParse != nil {
		return clientHelloShape{}, errParse
	}
	shape := clientHelloShape{
		Length:           len(record),
		CipherSuites:     suites,
		ExtensionTypes:   extTypes,
		ExtensionLengths: extLengths,
		ExtensionBodies:  extensionBodies(record),
	}

	// Groups, key shares and ALPN are value-level details; uTLS parses those
	// reliably, and it is the only place we need it.
	spec, errFingerprint := (&tls.Fingerprinter{AllowBluntMimicry: true}).FingerprintClientHello(record)
	if errFingerprint != nil {
		return clientHelloShape{}, errFingerprint
	}
	for _, ext := range spec.Extensions {
		switch typed := ext.(type) {
		case *tls.SupportedCurvesExtension:
			shape.Groups = typed.Curves
		case *tls.KeyShareExtension:
			for _, share := range typed.KeyShares {
				shape.KeyShareGroups = append(shape.KeyShareGroups, share.Group)
			}
		case *tls.ALPNExtension:
			shape.ALPN = typed.AlpnProtocols
		}
	}
	return shape, nil
}

// extensionBodies walks the record and returns each extension's payload, in wire
// order. Nil when the record cannot be walked, which the callers treat as a
// mismatch rather than a pass.
func extensionBodies(record []byte) [][]byte {
	pos := 9 + 2 + 32
	if pos+1 > len(record) {
		return nil
	}
	sessionIDLen := int(record[pos])
	pos += 1 + sessionIDLen
	if pos+2 > len(record) {
		return nil
	}
	pos += 2 + int(binary.BigEndian.Uint16(record[pos:pos+2]))
	if pos+1 > len(record) {
		return nil
	}
	pos += 1 + int(record[pos])
	if pos+2 > len(record) {
		return nil
	}
	end := pos + 2 + int(binary.BigEndian.Uint16(record[pos:pos+2]))
	pos += 2
	if end > len(record) {
		return nil
	}

	var bodies [][]byte
	for pos < end {
		if pos+4 > end {
			return nil
		}
		length := int(binary.BigEndian.Uint16(record[pos+2 : pos+4]))
		if pos+4+length > end {
			return nil
		}
		bodies = append(bodies, record[pos+4:pos+4+length])
		pos += 4 + length
	}
	return bodies
}

// parseClientHelloLayout walks the record far enough to report the cipher suite
// list and each extension's type and body length, in wire order.
func parseClientHelloLayout(record []byte) ([]uint16, []uint16, []int, error) {
	cursor := 9 // record header (5) + handshake header (4)
	need := func(n int) error {
		if cursor+n > len(record) {
			return errors.New("ClientHello truncated")
		}
		return nil
	}

	if err := need(2 + 32); err != nil { // legacy version + random
		return nil, nil, nil, err
	}
	cursor += 2 + 32

	if err := need(1); err != nil {
		return nil, nil, nil, err
	}
	sessionIDLen := int(record[cursor])
	cursor++
	if err := need(sessionIDLen); err != nil {
		return nil, nil, nil, err
	}
	cursor += sessionIDLen

	if err := need(2); err != nil {
		return nil, nil, nil, err
	}
	suiteLen := int(record[cursor])<<8 | int(record[cursor+1])
	cursor += 2
	if err := need(suiteLen); err != nil {
		return nil, nil, nil, err
	}
	var suites []uint16
	for off := cursor; off+1 < cursor+suiteLen; off += 2 {
		suites = append(suites, uint16(record[off])<<8|uint16(record[off+1]))
	}
	cursor += suiteLen

	if err := need(1); err != nil {
		return nil, nil, nil, err
	}
	compressionLen := int(record[cursor])
	cursor++
	if err := need(compressionLen + 2); err != nil {
		return nil, nil, nil, err
	}
	cursor += compressionLen

	extensionsLen := int(record[cursor])<<8 | int(record[cursor+1])
	cursor += 2
	end := cursor + extensionsLen
	if end > len(record) {
		return nil, nil, nil, errors.New("extension list runs past the record")
	}

	var types []uint16
	var lengths []int
	for cursor+4 <= end {
		extType := uint16(record[cursor])<<8 | uint16(record[cursor+1])
		extLen := int(record[cursor+2])<<8 | int(record[cursor+3])
		cursor += 4
		if cursor+extLen > end {
			return nil, nil, nil, errors.New("extension body runs past the list")
		}
		types = append(types, extType)
		lengths = append(lengths, extLen)
		cursor += extLen
	}
	return suites, types, lengths, nil
}
