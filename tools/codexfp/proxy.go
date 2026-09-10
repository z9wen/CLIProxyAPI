package main

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"time"
)

// runProxy is a minimal HTTP CONNECT proxy that exists only to read the
// ClientHello of the tunnelled connection. It never terminates TLS, so it needs
// no trusted certificate and no system changes — point the client at it with
// HTTPS_PROXY and run it.
//
// With forward set, the connection is spliced through to the real destination
// after the ClientHello is captured. Without it the connection is closed right
// after the handshake, which is enough to observe a fingerprint but starves the
// client: anything else it needs to do over the same connection — a token
// refresh, say — fails. Use forward when the client must keep working.
//
// This only captures the ClientHello. Header order and body framing need TLS
// termination (see -mode serve), which does require a trusted local CA.
func runProxy(addr, outDir string, forward bool) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	defer func() {
		if errClose := ln.Close(); errClose != nil {
			fmt.Fprintf(os.Stderr, "codexfp: close listener: %v\n", errClose)
		}
	}()
	fmt.Printf("CONNECT proxy listening on %s out of %s\n", addr, outDir)
	if forward {
		fmt.Printf("forwarding: tunnelled connections are spliced through after capture\n")
	} else {
		fmt.Printf("capture-only: tunnelled connections close after the handshake\n")
	}
	fmt.Printf("run the client with: HTTPS_PROXY=http://%s\n\n", addr)

	seq := 0
	for {
		conn, errAccept := ln.Accept()
		if errAccept != nil {
			return fmt.Errorf("accept: %w", errAccept)
		}
		seq++
		// Each connection gets its own goroutine. Handling them on the accept
		// loop would serialise the proxy: a forwarding tunnel stays open for the
		// whole session, so every later connection would starve.
		go handleProxyConn(conn, outDir, seq, forward)
	}
}

func handleProxyConn(conn net.Conn, outDir string, seq int, forward bool) {
	defer func() {
		if errClose := conn.Close(); errClose != nil {
			fmt.Fprintf(os.Stderr, "codexfp: close conn: %v\n", errClose)
		}
	}()
	remote := conn.RemoteAddr().String()
	if err := conn.SetDeadline(time.Now().Add(captureReadTimeout)); err != nil {
		fmt.Fprintf(os.Stderr, "codexfp: set deadline: %v\n", err)
		return
	}

	// Read the CONNECT request head.
	br := newRewindReader(conn)
	head, err := readUntilHeaderEnd(br)
	if err != nil {
		fmt.Printf("[%d] %s: not a CONNECT request: %v\n", seq, remote, err)
		return
	}
	requestLine := ""
	if lines := strings.Split(strings.TrimRight(string(head), "\r\n"), "\r\n"); len(lines) > 0 {
		requestLine = lines[0]
	}
	target := connectTarget(requestLine)
	if target == "" {
		fmt.Printf("[%d] %s: could not parse CONNECT target from %q\n", seq, remote, requestLine)
		return
	}
	fmt.Printf("[%d] %s -> %s\n", seq, remote, target)

	var upstream net.Conn
	if forward {
		dialed, errDial := net.DialTimeout("tcp", target, 10*time.Second)
		if errDial != nil {
			fmt.Printf("[%d] dial %s: %v\n", seq, target, errDial)
			if _, errWrite := conn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n")); errWrite != nil {
				fmt.Fprintf(os.Stderr, "codexfp: write error response: %v\n", errWrite)
			}
			return
		}
		upstream = dialed
		defer func() {
			if errClose := upstream.Close(); errClose != nil {
				fmt.Fprintf(os.Stderr, "codexfp: close upstream: %v\n", errClose)
			}
		}()
		// A forwarded tunnel outlives the capture window, so drop the deadline
		// the capture-only path relies on.
		if errDeadline := conn.SetDeadline(time.Time{}); errDeadline != nil {
			fmt.Fprintf(os.Stderr, "codexfp: clear deadline: %v\n", errDeadline)
			return
		}
	}

	if _, err := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		fmt.Fprintf(os.Stderr, "codexfp: write CONNECT response: %v\n", err)
		return
	}

	// Everything past this point is the tunnelled TLS handshake, in cleartext.
	buf := make([]byte, 0, 8192)
	chunk := make([]byte, 4096)
	var record []byte
	for {
		n, errRead := br.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
			if upstream != nil {
				if _, errWrite := upstream.Write(chunk[:n]); errWrite != nil {
					fmt.Fprintf(os.Stderr, "codexfp: forward to upstream: %v\n", errWrite)
					return
				}
			}
			if rec, ok := extractClientHelloRecord(buf); ok {
				record = rec
				break
			}
		}
		if errRead != nil {
			if record == nil {
				fmt.Printf("[%d] no ClientHello seen (%d bytes read)\n", seq, len(buf))
			}
			return
		}
	}

	if err := writeHelloArtifacts(outDir, seq, record); err != nil {
		fmt.Fprintf(os.Stderr, "codexfp: %v\n", err)
	}
	if upstream == nil {
		return
	}
	// Splice the rest of the session through so the client keeps working.
	go func() {
		if _, errCopy := io.Copy(upstream, br); errCopy != nil && !errors.Is(errCopy, io.EOF) {
			fmt.Fprintf(os.Stderr, "codexfp: forward client->upstream ended: %v\n", errCopy)
		}
	}()
	if _, errCopy := io.Copy(conn, upstream); errCopy != nil && !errors.Is(errCopy, io.EOF) {
		fmt.Fprintf(os.Stderr, "codexfp: forward upstream->client ended: %v\n", errCopy)
	}
}

// connectTarget pulls "host:port" out of a CONNECT request line.
func connectTarget(requestLine string) string {
	fields := strings.Fields(requestLine)
	if len(fields) < 2 || !strings.EqualFold(fields[0], "CONNECT") {
		return ""
	}
	target := fields[1]
	if _, _, errSplit := net.SplitHostPort(target); errSplit != nil {
		return ""
	}
	return target
}
