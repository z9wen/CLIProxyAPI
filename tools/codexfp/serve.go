package main

import (
	stdtls "crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// runServe terminates TLS and records whatever the client speaks next. The
// client is expected to be the real Codex CLI, which may or may not use ALPN:
// its default HTTP stack (native-tls) cannot request ALPN at all, so the
// connection usually arrives as plain HTTP/1.1. Both are handled — the mode is
// chosen from the first bytes on the wire, not from configuration.
func runServe(addr, outDir string) error {
	cert, err := stdtls.LoadX509KeyPair(
		filepath.Join(outDir, "leaf.pem"),
		filepath.Join(outDir, "leaf-key.pem"),
	)
	if err != nil {
		return fmt.Errorf("load leaf certificate (run -mode genca first): %w", err)
	}
	cfg := &stdtls.Config{
		Certificates: []stdtls.Certificate{cert},
		// Offer both, but do not require either: a client that sends no ALPN
		// extension must still complete the handshake so we can see it.
		NextProtos: []string{"h2", "http/1.1"},
	}
	ln, err := stdtls.Listen("tcp", addr, cfg)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	defer func() {
		if errClose := ln.Close(); errClose != nil {
			fmt.Fprintf(os.Stderr, "codexfp: close listener: %v\n", errClose)
		}
	}()
	fmt.Printf("listening on %s (mode=serve)\nwaiting for the client to connect...\n", addr)
	seq := 0
	for {
		conn, errAccept := ln.Accept()
		if errAccept != nil {
			return fmt.Errorf("accept: %w", errAccept)
		}
		seq++
		handleServe(conn, outDir, seq)
	}
}

func handleServe(conn net.Conn, outDir string, seq int) {
	defer func() {
		if errClose := conn.Close(); errClose != nil {
			fmt.Fprintf(os.Stderr, "codexfp: close conn: %v\n", errClose)
		}
	}()
	remote := conn.RemoteAddr().String()

	tlsConn, ok := conn.(*stdtls.Conn)
	if !ok {
		return
	}
	if err := tlsConn.Handshake(); err != nil {
		fmt.Printf("\n[%d] %s: handshake failed: %v\n", seq, remote, err)
		return
	}
	state := tlsConn.ConnectionState()
	fmt.Printf("\n[%d] connection from %s\n", seq, remote)
	fmt.Printf("    TLS version: %s, cipher: %s\n", tlsVersionName(state.Version), stdtls.CipherSuiteName(state.CipherSuite))
	fmt.Printf("    ALPN negotiated: %q  (empty means the client sent no ALPN extension)\n", state.NegotiatedProtocol)

	if err := conn.SetReadDeadline(time.Now().Add(captureReadTimeout)); err != nil {
		fmt.Fprintf(os.Stderr, "codexfp: set deadline: %v\n", err)
		return
	}

	br := newRewindReader(conn)
	peek := make([]byte, len(h2ClientPreface))
	n, errPeek := io.ReadFull(br, peek)
	if errPeek != nil {
		fmt.Fprintf(os.Stderr, "codexfp: read first bytes: %v\n", errPeek)
		return
	}

	if string(peek[:n]) == h2ClientPreface {
		captureHTTP2(br, outDir, seq, remote)
		return
	}
	// Not HTTP/2: put the sniffed bytes back so the request is dumped verbatim.
	br.Unread(peek[:n])
	captureHTTP1(br, outDir, seq, remote)
}

// rewindReader lets us inspect the first bytes without losing them.
type rewindReader struct {
	r      io.Reader
	peeked []byte
}

func newRewindReader(r io.Reader) *rewindReader { return &rewindReader{r: r} }

func (rr *rewindReader) Read(p []byte) (int, error) {
	if len(rr.peeked) > 0 {
		n := copy(p, rr.peeked)
		rr.peeked = rr.peeked[n:]
		return n, nil
	}
	return rr.r.Read(p)
}

func (rr *rewindReader) Unread(b []byte) {
	rr.peeked = append(append([]byte(nil), b...), rr.peeked...)
}

func captureHTTP1(br *rewindReader, outDir string, seq int, remote string) {
	head, err := readUntilHeaderEnd(br)
	if err != nil {
		fmt.Fprintf(os.Stderr, "codexfp: read request head: %v\n", err)
		return
	}

	var out strings.Builder
	fmt.Fprintf(&out, "# HTTP/1.1 client capture\n\n")
	fmt.Fprintf(&out, "peer: %s\n\n", remote)
	fmt.Fprintf(&out, "## Request head, verbatim (%d bytes)\n", len(head))
	fmt.Fprintf(&out, "%s\n", strings.ReplaceAll(strings.TrimRight(string(head), "\r\n"), "\r\n", "\n"))

	lines := strings.Split(strings.TrimRight(string(head), "\r\n"), "\r\n")
	fmt.Fprintf(&out, "## Header name order, as sent\n")
	names := make([]string, 0, len(lines))
	for i, line := range lines {
		if i == 0 {
			fmt.Fprintf(&out, "  request line: %s\n", line)
			continue
		}
		name, value, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		name = strings.TrimSpace(name)
		names = append(names, name)
		fmt.Fprintf(&out, "  %2d. %-34s %s\n", len(names), name, strings.TrimSpace(value))
	}
	fmt.Fprintf(&out, "## Summary\n")
	fmt.Fprintf(&out, "header order: %s\n", strings.Join(names, ", "))
	fmt.Fprintf(&out, "accept-encoding present: %v\n", containsFold(names, "Accept-Encoding"))
	fmt.Fprintf(&out, "content-encoding: %s\n", headerValue(lines, "Content-Encoding"))
	fmt.Fprintf(&out, "originator: %s\n", headerValue(lines, "originator"))
	fmt.Fprintf(&out, "user-agent: %s\n", headerValue(lines, "User-Agent"))
	fmt.Fprintf(&out, "version: %s\n", headerValue(lines, "version"))
	fmt.Fprintf(&out, "session header: %s\n", sessionHeaderName(lines))

	// Body: read Content-Length bytes and report the encoding.
	if cl := headerValue(lines, "Content-Length"); cl != "" {
		if length, errAtoi := strconv.Atoi(strings.TrimSpace(cl)); errAtoi == nil && length > 0 && length < 64<<20 {
			body := make([]byte, length)
			if _, errRead := io.ReadFull(br, body); errRead == nil {
				fmt.Fprintf(&out, "\n## Body (%d bytes)\n", length)
				fmt.Fprintf(&out, "first bytes: %s\n", hex.EncodeToString(body[:min(32, len(body))]))
				if enc := strings.ToLower(headerValue(lines, "Content-Encoding")); enc == "zstd" {
					fmt.Fprintf(&out, "zstd magic present: %v (expected 28b52ffd)\n",
						strings.HasPrefix(hex.EncodeToString(body), "28b52ffd"))
				}
			}
		}
	}

	path := filepath.Join(outDir, fmt.Sprintf("h1.%d.txt", seq))
	if err := os.WriteFile(path, []byte(out.String()), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "codexfp: write %s: %v\n", path, err)
		return
	}
	fmt.Printf("[%d] captured HTTP/1.1 request; wrote %s\n", seq, path)
	fmt.Print(out.String())
}

func readUntilHeaderEnd(r io.Reader) ([]byte, error) {
	buf := make([]byte, 0, 4096)
	chunk := make([]byte, 1)
	for len(buf) < 256<<10 {
		if _, err := r.Read(chunk); err != nil {
			return nil, err
		}
		buf = append(buf, chunk[0])
		if len(buf) >= 4 && string(buf[len(buf)-4:]) == "\r\n\r\n" {
			return buf, nil
		}
	}
	return nil, fmt.Errorf("request head exceeded 256 KiB without terminator")
}

func headerValue(lines []string, name string) string {
	for _, line := range lines[1:] {
		k, v, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		if strings.EqualFold(strings.TrimSpace(k), name) {
			return strings.TrimSpace(v)
		}
	}
	return "(absent)"
}

func sessionHeaderName(lines []string) string {
	for _, line := range lines[1:] {
		k, _, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		k = strings.TrimSpace(k)
		if strings.EqualFold(k, "session-id") || strings.EqualFold(k, "session_id") {
			return k
		}
	}
	return "(absent)"
}

func containsFold(names []string, want string) bool {
	for _, n := range names {
		if strings.EqualFold(n, want) {
			return true
		}
	}
	return false
}

func tlsVersionName(v uint16) string {
	switch v {
	case stdtls.VersionTLS12:
		return "TLS 1.2"
	case stdtls.VersionTLS13:
		return "TLS 1.3"
	case stdtls.VersionTLS11:
		return "TLS 1.1"
	case stdtls.VersionTLS10:
		return "TLS 1.0"
	default:
		return fmt.Sprintf("0x%04x", v)
	}
}
