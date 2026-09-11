package codexcapture

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	log "github.com/sirupsen/logrus"
)

// captureTimeout bounds how long a tunnelled connection may take to deliver a
// ClientHello.
//
// The client is cut off mid-handshake by design, so a stalled or silent one must
// not hold the capture open: this listener is a capture harness, not a serving
// path, and the deadline is what lets a capture fail fast instead of hanging.
const captureTimeout = 20 * time.Second

// clientHelloListener is a minimal HTTP CONNECT proxy whose only job is to read
// the ClientHello of the connection tunnelled through it.
//
// Nothing terminates TLS, so the handshake arrives in cleartext and no
// certificate has to be trusted. The client is closed out as soon as the
// handshake is read, which is why the caller sees a connection error and falls
// back to its next transport — that fallback is wanted, because it is how both
// the websocket and the HTTP/SSE profiles get captured in one run.
type clientHelloListener struct {
	listener net.Listener
	results  chan capturedHello
	closed   sync.Once
}

type capturedHello struct {
	record []byte
	target string
}

// newClientHelloListener starts listening on a loopback port.
func newClientHelloListener() (*clientHelloListener, error) {
	listener, errListen := net.Listen("tcp", "127.0.0.1:0")
	if errListen != nil {
		return nil, fmt.Errorf("codexcapture: listen: %w", errListen)
	}
	l := &clientHelloListener{
		listener: listener,
		results:  make(chan capturedHello, 16),
	}
	go l.serve()
	return l, nil
}

func (l *clientHelloListener) Addr() string {
	if l == nil || l.listener == nil {
		return ""
	}
	return l.listener.Addr().String()
}

// ProxyURL is the value to hand the client through HTTPS_PROXY.
func (l *clientHelloListener) ProxyURL() string {
	return "http://" + l.Addr()
}

func (l *clientHelloListener) Close() error {
	if l == nil {
		return nil
	}
	var err error
	l.closed.Do(func() {
		err = l.listener.Close()
	})
	return err
}

func (l *clientHelloListener) serve() {
	for {
		conn, errAccept := l.listener.Accept()
		if errAccept != nil {
			return
		}
		go l.handle(conn)
	}
}

func (l *clientHelloListener) handle(conn net.Conn) {
	defer func() {
		if errClose := conn.Close(); errClose != nil {
			log.Debugf("codexcapture: close connection: %v", errClose)
		}
	}()
	deadline := time.Now().Add(captureTimeout)
	if errDeadline := conn.SetDeadline(deadline); errDeadline != nil {
		return
	}

	head, errRead := readUntilHeaderEnd(conn)
	if errRead != nil {
		return
	}
	target := connectTarget(head)

	// A client that reaches the proxy without CONNECT is not something to guess
	// at; let it fail so the caller moves on.
	if target == "" {
		return
	}
	if _, errWrite := conn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); errWrite != nil {
		return
	}

	record, ok := readClientHello(conn)
	if !ok {
		return
	}
	select {
	case l.results <- capturedHello{record: record, target: target}:
	default:
	}
}

// Next returns the next captured ClientHello, or an error when the context ends.
func (l *clientHelloListener) Next(ctx context.Context) (capturedHello, error) {
	select {
	case hello := <-l.results:
		return hello, nil
	case <-ctx.Done():
		return capturedHello{}, ctx.Err()
	}
}

func readUntilHeaderEnd(r io.Reader) ([]byte, error) {
	buf := make([]byte, 0, 4096)
	one := make([]byte, 1)
	for len(buf) < 256<<10 {
		if _, err := r.Read(one); err != nil {
			return nil, err
		}
		buf = append(buf, one[0])
		if len(buf) >= 4 && string(buf[len(buf)-4:]) == "\r\n\r\n" {
			return buf, nil
		}
	}
	return nil, errors.New("codexcapture: request head too large")
}

// connectTarget pulls "host:port" out of a CONNECT request line.
func connectTarget(head []byte) string {
	line, _, _ := strings.Cut(strings.TrimRight(string(head), "\r\n"), "\r\n")
	fields := strings.Fields(line)
	if len(fields) < 2 || !strings.EqualFold(fields[0], "CONNECT") {
		return ""
	}
	if _, _, errSplit := net.SplitHostPort(fields[1]); errSplit != nil {
		return ""
	}
	return fields[1]
}

// readClientHello accumulates until the TLS record holding the ClientHello is
// complete, which may take more than one read.
func readClientHello(r io.Reader) ([]byte, bool) {
	buf := make([]byte, 0, 8192)
	chunk := make([]byte, 4096)
	for {
		n, errRead := r.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
			if record, ok := extractClientHelloRecord(buf); ok {
				return record, true
			}
		}
		if errRead != nil {
			return nil, false
		}
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
