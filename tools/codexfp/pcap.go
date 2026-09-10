package main

import (
	"encoding/binary"
	"fmt"
	"os"
	"sort"
)

// pcapLinkType values we can walk to find the IP layer.
const (
	linkTypeNull     = 0   // BSD loopback: 4-byte AF header
	linkTypeEthernet = 1   // 14-byte Ethernet header
	linkTypeRaw      = 101 // raw IP
	linkTypeLinuxSLL = 113 // 16-byte Linux cooked header
)

// pcapPacket is one captured frame with its transport payload located.
type pcapPacket struct {
	index    int
	srcIP    string
	dstIP    string
	srcPort  uint16
	dstPort  uint16
	protocol string
	payload  []byte
}

// readPcap pulls every IPv4/TCP/UDP payload out of a classic libpcap file.
// Only the link types tcpdump emits on macOS are handled; anything else is
// reported rather than silently skipped.
func readPcap(path string) ([]pcapPacket, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", path, err)
	}
	if len(raw) < 24 {
		return nil, fmt.Errorf("%s is too short to be a pcap file", path)
	}

	// The magic is written in the capturing host's byte order, so whichever
	// interpretation yields the canonical value tells us the file's order.
	var order binary.ByteOrder
	switch {
	case binary.LittleEndian.Uint32(raw[0:4]) == 0xa1b2c3d4 ||
		binary.LittleEndian.Uint32(raw[0:4]) == 0xa1b23c4d:
		order = binary.LittleEndian
	case binary.BigEndian.Uint32(raw[0:4]) == 0xa1b2c3d4 ||
		binary.BigEndian.Uint32(raw[0:4]) == 0xa1b23c4d:
		order = binary.BigEndian
	default:
		return nil, fmt.Errorf("%s is not a classic pcap file (first bytes % x); pcapng is not supported",
			path, raw[0:4])
	}
	linkType := order.Uint32(raw[20:24])

	var packets []pcapPacket
	off := 24
	index := 0
	for off+16 <= len(raw) {
		inclLen := int(order.Uint32(raw[off+8 : off+12]))
		off += 16
		if inclLen <= 0 || off+inclLen > len(raw) {
			break
		}
		frame := raw[off : off+inclLen]
		off += inclLen
		index++

		ip, ok := stripLinkLayer(frame, linkType)
		if !ok {
			continue
		}
		pkt, ok := parseIPv4Transport(ip, index)
		if !ok {
			continue
		}
		packets = append(packets, pkt)
	}
	if len(packets) == 0 {
		return nil, fmt.Errorf("no IPv4 TCP/UDP packets decoded from %s (link type %d)", path, linkType)
	}
	return packets, nil
}

func stripLinkLayer(frame []byte, linkType uint32) ([]byte, bool) {
	switch linkType {
	case linkTypeNull:
		if len(frame) < 4 {
			return nil, false
		}
		return frame[4:], true
	case linkTypeEthernet:
		if len(frame) < 14 {
			return nil, false
		}
		etherType := binary.BigEndian.Uint16(frame[12:14])
		// Skip VLAN tags so tagged captures still decode.
		offset := 14
		for etherType == 0x8100 && len(frame) >= offset+4 {
			etherType = binary.BigEndian.Uint16(frame[offset+2 : offset+4])
			offset += 4
		}
		if etherType != 0x0800 {
			return nil, false
		}
		return frame[offset:], true
	case linkTypeRaw:
		return frame, true
	case linkTypeLinuxSLL:
		if len(frame) < 16 || binary.BigEndian.Uint16(frame[14:16]) != 0x0800 {
			return nil, false
		}
		return frame[16:], true
	default:
		return nil, false
	}
}

func parseIPv4Transport(ip []byte, index int) (pcapPacket, bool) {
	if len(ip) < 20 || ip[0]>>4 != 4 {
		return pcapPacket{}, false
	}
	ihl := int(ip[0]&0x0f) * 4
	if ihl < 20 || len(ip) < ihl {
		return pcapPacket{}, false
	}
	proto := ip[9]
	totalLen := int(binary.BigEndian.Uint16(ip[2:4]))
	if totalLen < ihl {
		totalLen = len(ip)
	}
	payload := ip[ihl:]
	if totalLen-ihl < len(payload) && totalLen-ihl >= 0 {
		payload = payload[:totalLen-ihl]
	}

	pkt := pcapPacket{
		index: index,
		srcIP: net_IPv4(ip[12:16]),
		dstIP: net_IPv4(ip[16:20]),
	}
	switch proto {
	case 6:
		pkt.protocol = "TCP"
		if len(payload) < 20 {
			return pcapPacket{}, false
		}
		doff := int(payload[12]>>4) * 4
		if doff < 20 || len(payload) < doff {
			return pcapPacket{}, false
		}
		pkt.srcPort = binary.BigEndian.Uint16(payload[0:2])
		pkt.dstPort = binary.BigEndian.Uint16(payload[2:4])
		pkt.payload = payload[doff:]
	case 17:
		pkt.protocol = "UDP"
		if len(payload) < 8 {
			return pcapPacket{}, false
		}
		pkt.srcPort = binary.BigEndian.Uint16(payload[0:2])
		pkt.dstPort = binary.BigEndian.Uint16(payload[2:4])
		pkt.payload = payload[8:]
	default:
		return pcapPacket{}, false
	}
	return pkt, true
}

func net_IPv4(b []byte) string {
	return fmt.Sprintf("%d.%d.%d.%d", b[0], b[1], b[2], b[3])
}

// flushOrder returns packet indexes in capture order (readPcap already appends
// in order; this exists so callers do not have to reason about it).
func flushOrder(pkts []pcapPacket) []pcapPacket {
	out := append([]pcapPacket(nil), pkts...)
	sort.SliceStable(out, func(i, j int) bool { return out[i].index < out[j].index })
	return out
}
