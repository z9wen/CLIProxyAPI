package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/net/http2/hpack"
)

const h2ClientPreface = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"

// HTTP/2 frame types we care about when describing a client's opening behaviour.
const (
	frameHeaders    = 0x1
	framePriority   = 0x2
	frameRSTStream  = 0x3
	frameSettings   = 0x4
	framePush       = 0x5
	framePing       = 0x6
	frameGoAway     = 0x7
	frameWindowUpd  = 0x8
	frameContinuatn = 0x9
)

var h2FrameNames = map[uint8]string{
	frameHeaders: "HEADERS", framePriority: "PRIORITY", frameRSTStream: "RST_STREAM",
	frameSettings: "SETTINGS", framePush: "PUSH_PROMISE", framePing: "PING",
	frameGoAway: "GOAWAY", frameWindowUpd: "WINDOW_UPDATE", frameContinuatn: "CONTINUATION",
}

var h2SettingNames = map[uint16]string{
	0x1: "HEADER_TABLE_SIZE", 0x2: "ENABLE_PUSH", 0x3: "MAX_CONCURRENT_STREAMS",
	0x4: "INITIAL_WINDOW_SIZE", 0x5: "MAX_FRAME_SIZE", 0x6: "MAX_HEADER_LIST_SIZE",
}

// captureHTTP2 records the client's SETTINGS, any WINDOW_UPDATE, and the
// pseudo-header and header order of the first request. The preface has already
// been consumed by the caller.
func captureHTTP2(br *rewindReader, outDir string, seq int, remote string) {
	var out strings.Builder
	fmt.Fprintf(&out, "# HTTP/2 client capture\n\n")
	fmt.Fprintf(&out, "peer: %s\n\n", remote)

	var headerBlock []byte
	headersDone := false
	frameIdx := 0

	for !headersDone && frameIdx < 32 {
		var fh [9]byte
		if _, err := io.ReadFull(br, fh[:]); err != nil {
			fmt.Fprintf(os.Stderr, "codexfp: read frame header: %v\n", err)
			break
		}
		length := int(fh[0])<<16 | int(fh[1])<<8 | int(fh[2])
		ftype := fh[3]
		flags := fh[4]
		streamID := uint32(fh[5])&0x7f<<24 | uint32(fh[6])<<16 | uint32(fh[7])<<8 | uint32(fh[8])
		payload := make([]byte, length)
		if length > 0 {
			if _, err := io.ReadFull(br, payload); err != nil {
				fmt.Fprintf(os.Stderr, "codexfp: read frame payload: %v\n", err)
				break
			}
		}
		frameIdx++
		fmt.Fprintf(&out, "frame %2d: %-12s flags=0x%02x stream=%d len=%d\n",
			frameIdx, h2FrameNames[ftype], flags, streamID, length)

		switch ftype {
		case frameSettings:
			if flags&0x1 != 0 {
				fmt.Fprintf(&out, "           ACK\n")
				break
			}
			for off := 0; off+6 <= len(payload); off += 6 {
				id := uint16(payload[off])<<8 | uint16(payload[off+1])
				val := uint32(payload[off+2])<<24 | uint32(payload[off+3])<<16 |
					uint32(payload[off+4])<<8 | uint32(payload[off+5])
				name := h2SettingNames[id]
				if name == "" {
					name = fmt.Sprintf("UNKNOWN(0x%04x)", id)
				}
				fmt.Fprintf(&out, "           %-24s = %d\n", name, val)
			}
		case frameWindowUpd:
			if len(payload) == 4 {
				inc := uint32(payload[0])&0x7f<<24 | uint32(payload[1])<<16 |
					uint32(payload[2])<<8 | uint32(payload[3])
				fmt.Fprintf(&out, "           increment = %d\n", inc)
			}
		case framePriority:
			if len(payload) == 5 {
				dep := uint32(payload[0])&0x7f<<24 | uint32(payload[1])<<16 |
					uint32(payload[2])<<8 | uint32(payload[3])
				fmt.Fprintf(&out, "           depends on stream %d, exclusive=%v, weight=%d\n",
					dep, payload[0]&0x80 != 0, payload[4]+1)
			}
		case frameHeaders:
			if flags&0x8 != 0 && len(payload) > 0 {
				padLen := int(payload[0])
				payload = payload[1 : len(payload)-padLen]
			}
			if flags&0x20 != 0 && len(payload) >= 5 {
				payload = payload[5:]
			}
			headerBlock = append(headerBlock, payload...)
			if flags&0x4 != 0 {
				headersDone = true
			}
		case frameContinuatn:
			headerBlock = append(headerBlock, payload...)
			if flags&0x4 != 0 {
				headersDone = true
			}
		}
	}

	if len(headerBlock) > 0 {
		decoder := hpack.NewDecoder(4096, nil)
		fields, err := decoder.DecodeFull(headerBlock)
		if err != nil {
			fmt.Fprintf(&out, "\nHPACK decode failed: %v\nraw block: %s\n", err, hex.EncodeToString(headerBlock))
		} else {
			fmt.Fprintf(&out, "\n## Request headers, in wire order (%d)\n", len(fields))
			for i, f := range fields {
				fmt.Fprintf(&out, "  %2d. %-32s %s\n", i, f.Name, f.Value)
			}
			var pseudo, names []string
			for _, f := range fields {
				if strings.HasPrefix(f.Name, ":") {
					pseudo = append(pseudo, f.Name)
				} else {
					names = append(names, f.Name)
				}
			}
			fmt.Fprintf(&out, "\n## Summary\n")
			fmt.Fprintf(&out, "pseudo-header order: %s\n", strings.Join(pseudo, ", "))
			fmt.Fprintf(&out, "header order: %s\n", strings.Join(names, ", "))
			fmt.Fprintf(&out, "accept-encoding present: %v\n", containsFold(names, "accept-encoding"))
		}
	}

	path := filepath.Join(outDir, fmt.Sprintf("h2.%d.txt", seq))
	if err := os.WriteFile(path, []byte(out.String()), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "codexfp: write %s: %v\n", path, err)
		return
	}
	fmt.Printf("[%d] captured %d HTTP/2 frames; wrote %s\n", seq, frameIdx, path)
	fmt.Print(out.String())
}
