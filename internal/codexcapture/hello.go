package codexcapture

import (
	"errors"
	"fmt"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
)

// profileKind is which of the two Codex transports a captured handshake belongs
// to. The two are stored separately because they are produced by different TLS
// stacks and cannot be interchanged.
type profileKind int

const (
	profileHTTP profileKind = iota
	profileWebSocket
)

func (k profileKind) String() string {
	if k == profileWebSocket {
		return "websocket"
	}
	return "http"
}

// other returns the transport that is not k.
func (k profileKind) other() profileKind {
	if k == profileWebSocket {
		return profileHTTP
	}
	return profileWebSocket
}

// fileName is the name the loader reads this transport's profile under. The two
// live beside each other and are replaced as a pair.
func (k profileKind) fileName() string {
	if k == profileWebSocket {
		return helps.CodexProfileWebSocketFile
	}
	return helps.CodexProfileHTTPFile
}

// Extension IDs that separate the two transports.
const (
	extEncryptThenMAC    = 0x0016
	extRenegotiationInfo = 0xff01
)

// Extension IDs every Codex handshake offers, on either transport. A TLS 1.3
// client advertises supported_versions and a key share, and both captures do.
// Requiring them keeps a degenerate or truncated stream from being filed as a
// profile on the strength of an absence.
const (
	extSupportedVersions = 0x002b
	extKeyShare          = 0x0033
)

var errShortHello = errors.New("codexcapture: truncated ClientHello")

// classify decides which transport produced a ClientHello.
//
// The two paths differ by TLS implementation, not by release: the HTTP/SSE path
// runs on OpenSSL, because native-tls is the client's default backend, and the
// WebSocket path runs on rustls. OpenSSL offers renegotiation_info and
// encrypt_then_mac on every handshake it sends; rustls offers neither. Counting
// cipher suites would separate them today and break on the next OpenSSL release,
// so the marker is the extension set.
//
// A handshake matching neither, or only one of the two, is refused. Filing a
// capture under the wrong transport would replace a working profile with a
// fingerprint no real client sends — worse than not capturing at all, because it
// would be applied silently.
func classify(record []byte) (profileKind, error) {
	extensions, errExtensions := clientHelloExtensionIDs(record)
	if errExtensions != nil {
		return 0, errExtensions
	}

	var renegotiation, encryptThenMAC, supportedVersions, keyShare bool
	for _, id := range extensions {
		switch id {
		case extRenegotiationInfo:
			renegotiation = true
		case extEncryptThenMAC:
			encryptThenMAC = true
		case extSupportedVersions:
			supportedVersions = true
		case extKeyShare:
			keyShare = true
		}
	}
	if !supportedVersions || !keyShare {
		return 0, fmt.Errorf(
			"codexcapture: not a TLS 1.3 client hello (supported_versions=%t, key_share=%t)",
			supportedVersions, keyShare)
	}

	switch {
	case renegotiation && encryptThenMAC:
		return profileHTTP, nil
	case !renegotiation && !encryptThenMAC:
		return profileWebSocket, nil
	default:
		return 0, fmt.Errorf(
			"codexcapture: ClientHello matches neither Codex transport (renegotiation_info=%t, encrypt_then_mac=%t)",
			renegotiation, encryptThenMAC)
	}
}

// clientHelloExtensionIDs returns the extension IDs a captured ClientHello
// record offers, in wire order.
//
// Parsed by hand rather than through uTLS. Only the IDs are wanted, and the
// fingerprinter reports them through a type switch over its own spec types,
// which would have to be mirrored here to read two values out of a handshake.
func clientHelloExtensionIDs(record []byte) ([]uint16, error) {
	body, errBody := clientHelloBody(record)
	if errBody != nil {
		return nil, errBody
	}
	c := &helloCursor{buf: body}

	// legacy_version(2) then random(32).
	if _, errSkip := c.take(2 + 32); errSkip != nil {
		return nil, errSkip
	}
	sessionIDLen, errSession := c.u8()
	if errSession != nil {
		return nil, errSession
	}
	if _, errSkip := c.take(sessionIDLen); errSkip != nil {
		return nil, errSkip
	}
	cipherSuitesLen, errCipher := c.u16()
	if errCipher != nil {
		return nil, errCipher
	}
	if _, errSkip := c.take(cipherSuitesLen); errSkip != nil {
		return nil, errSkip
	}
	compressionLen, errCompression := c.u8()
	if errCompression != nil {
		return nil, errCompression
	}
	if _, errSkip := c.take(compressionLen); errSkip != nil {
		return nil, errSkip
	}
	extensionsLen, errExtensions := c.u16()
	if errExtensions != nil {
		return nil, errExtensions
	}
	extensions, errTake := c.take(extensionsLen)
	if errTake != nil {
		return nil, errTake
	}

	inner := &helloCursor{buf: extensions}
	var ids []uint16
	for inner.remaining() > 0 {
		id, errID := inner.u16()
		if errID != nil {
			return nil, errID
		}
		length, errLength := inner.u16()
		if errLength != nil {
			return nil, errLength
		}
		if _, errSkip := inner.take(length); errSkip != nil {
			return nil, errSkip
		}
		ids = append(ids, uint16(id))
	}
	return ids, nil
}

// clientHelloBody returns the handshake body of a captured TLS record whose
// payload is a ClientHello, as produced by extractClientHelloRecord.
func clientHelloBody(record []byte) ([]byte, error) {
	if len(record) < 5 {
		return nil, errShortHello
	}
	recordLen := int(record[3])<<8 | int(record[4])
	if len(record) < 5+recordLen {
		return nil, errShortHello
	}
	handshake := record[5 : 5+recordLen]
	// handshake_type(1) == client_hello, then a 3-byte length.
	if len(handshake) < 4 || handshake[0] != 1 {
		return nil, errors.New("codexcapture: TLS record does not hold a ClientHello")
	}
	bodyLen := int(handshake[1])<<16 | int(handshake[2])<<8 | int(handshake[3])
	if len(handshake) < 4+bodyLen {
		return nil, errShortHello
	}
	return handshake[4 : 4+bodyLen], nil
}

// helloCursor walks a ClientHello body, refusing to read past the end.
type helloCursor struct {
	buf []byte
	off int
}

func (c *helloCursor) remaining() int {
	return len(c.buf) - c.off
}

func (c *helloCursor) take(n int) ([]byte, error) {
	if n < 0 || c.remaining() < n {
		return nil, errShortHello
	}
	out := c.buf[c.off : c.off+n]
	c.off += n
	return out, nil
}

func (c *helloCursor) u8() (int, error) {
	b, errTake := c.take(1)
	if errTake != nil {
		return 0, errTake
	}
	return int(b[0]), nil
}

func (c *helloCursor) u16() (int, error) {
	b, errTake := c.take(2)
	if errTake != nil {
		return 0, errTake
	}
	return int(b[0])<<8 | int(b[1]), nil
}
