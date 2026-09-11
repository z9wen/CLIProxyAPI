package helps

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sort"
)

// rustls randomizes the order of the ClientHello extensions that carry no
// ordering requirement of their own, once per connection, from a u16 seed drawn
// from the system RNG. The Codex WebSocket transport runs rustls, so a replay
// that always sends the same order is a constant where the real client has a
// spread — and a constant is a signal in its own right.
//
// Ported from rustls 0.23 (src/msgs/handshake.rs):
// order_insensitive_extensions_in_random_order and low_quality_integer_hash.
// The ordering is a stable sort by that hash of (seed<<16)|extension_type, so
// hash collisions keep the base order rather than reordering arbitrarily.

// Extensions the standard requires to come last. rustls removes these from the
// randomized set and appends them afterwards, in this relative order.
const (
	extTypePreSharedKey              = 41
	extTypeEncryptedClientHello      = 65037
	extTypeEncryptedClientHelloOuter = 65038
	// extTypePadding is not pinned by rustls, which never emits it. uTLS does
	// rewrite padding in list order, so anything carrying it keeps it last.
	extTypePadding = 21
)

// lowQualityIntegerHash is rustls's ordering hash. Every step is a u32 wrap.
func lowQualityIntegerHash(x uint32) uint32 {
	x = x + 0x7ed55d16 + (x << 12)
	x = (x ^ 0xc761c23c) ^ (x >> 19)
	x = x + 0x165667b1 + (x << 5)
	x = (x + 0xd3a2646c) ^ (x << 9)
	x = x + 0xfd7046c5 + (x << 3)
	x = (x ^ 0xb55a4f09) ^ (x >> 16)
	return x
}

// isOrderPinned reports whether an extension keeps its captured position.
func isOrderPinned(extType uint16) bool {
	switch extType {
	case extTypePreSharedKey, extTypeEncryptedClientHello,
		extTypeEncryptedClientHelloOuter, extTypePadding:
		return true
	default:
		return false
	}
}

// randomRustlsOrderSeed draws the per-connection ordering seed: rustls uses
// random_u16, so every connection gets an independent order.
func randomRustlsOrderSeed() (uint16, error) {
	var buf [2]byte
	if _, errRead := rand.Read(buf[:]); errRead != nil {
		return 0, errRead
	}
	return binary.BigEndian.Uint16(buf[:]), nil
}

// clientHelloExtensionBlock locates the extensions field inside a raw
// ClientHello record and returns the byte ranges of the fixed prefix, of every
// extension, and of the total record.
type clientHelloExtensionBlock struct {
	extensionsOffset int
	extensionsLength int
	blocks           [][]byte
	types            []uint16
}

// parseClientHelloExtensions walks a raw ClientHello far enough to split its
// extension list into self-delimiting blocks. Each block keeps its own header,
// so permuting them cannot change any length.
func parseClientHelloExtensions(raw []byte) (clientHelloExtensionBlock, error) {
	var out clientHelloExtensionBlock
	// record header, handshake header, legacy version, random, session id,
	// cipher suites and compression methods all precede the extensions.
	if len(raw) < 9 || raw[0] != 0x16 || raw[5] != 0x01 {
		return out, fmt.Errorf("codex tls: not a ClientHello record")
	}
	pos := 9 + 2 + 32
	if len(raw) < pos+1 {
		return out, fmt.Errorf("codex tls: truncated ClientHello header")
	}
	sessionIDLen := int(raw[pos])
	pos += 1 + sessionIDLen
	if len(raw) < pos+2 {
		return out, fmt.Errorf("codex tls: truncated session id")
	}
	pos += 2 + int(binary.BigEndian.Uint16(raw[pos:pos+2]))
	if len(raw) < pos+1 {
		return out, fmt.Errorf("codex tls: truncated cipher suites")
	}
	pos += 1 + int(raw[pos])
	if len(raw) < pos+2 {
		return out, fmt.Errorf("codex tls: truncated compression methods")
	}
	out.extensionsLength = int(binary.BigEndian.Uint16(raw[pos : pos+2]))
	out.extensionsOffset = pos + 2
	end := out.extensionsOffset + out.extensionsLength
	if end > len(raw) {
		return out, fmt.Errorf("codex tls: extensions field runs past the record")
	}

	for p := out.extensionsOffset; p < end; {
		if p+4 > end {
			return out, fmt.Errorf("codex tls: truncated extension header")
		}
		blockLen := 4 + int(binary.BigEndian.Uint16(raw[p+2:p+4]))
		if p+blockLen > end {
			return out, fmt.Errorf("codex tls: extension runs past the list")
		}
		out.types = append(out.types, binary.BigEndian.Uint16(raw[p:p+2]))
		out.blocks = append(out.blocks, raw[p:p+blockLen])
		p += blockLen
	}
	return out, nil
}

// reorderClientHelloExtensions rewrites a raw ClientHello so its extensions are
// in the order rustls would emit for a connection that drew seed.
func reorderClientHelloExtensions(raw []byte, seed uint16) ([]byte, error) {
	parsed, errParse := parseClientHelloExtensions(raw)
	if errParse != nil || len(parsed.blocks) == 0 {
		return nil, errParse
	}

	reorderable := make([]int, 0, len(parsed.blocks))
	pinned := make([]int, 0, len(parsed.blocks))
	for i, extType := range parsed.types {
		if isOrderPinned(extType) {
			pinned = append(pinned, i)
			continue
		}
		reorderable = append(reorderable, i)
	}

	keys := make(map[int]uint32, len(reorderable))
	for _, i := range reorderable {
		keys[i] = lowQualityIntegerHash(uint32(seed)<<16 | uint32(parsed.types[i]))
	}
	sort.SliceStable(reorderable, func(a, b int) bool {
		return keys[reorderable[a]] < keys[reorderable[b]]
	})

	// The blocks are the same bytes as before, so nothing outside the extension
	// list changes and every recorded length stays correct.
	out := make([]byte, len(raw))
	copy(out, raw[:parsed.extensionsOffset])
	pos := parsed.extensionsOffset
	for _, i := range append(reorderable, pinned...) {
		pos += copy(out[pos:], parsed.blocks[i])
	}
	return out, nil
}
