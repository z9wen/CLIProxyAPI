package main

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	tls "github.com/refraction-networking/utls"
)

// runPcap analyses a tcpdump capture of a real client: it reassembles each TCP
// flow, pulls out the ClientHello, and reports the parts of the profile that
// differ between clients (ALPN, extension order, TLS stack shape). QUIC traffic
// is reported separately, because HTTP/3 would mean there is no TLS record to
// match at all.
func runPcap(inPath, outDir string) error {
	packets, err := readPcap(inPath)
	if err != nil {
		return err
	}

	type flowKey struct {
		srcIP, dstIP string
		srcPort      uint16
		dstPort      uint16
	}
	flows := map[flowKey][]byte{}
	var flowOrder []flowKey
	quicFirstBytes := map[string]int{}

	for _, pkt := range packets {
		if pkt.protocol == "UDP" && (pkt.dstPort == 443 || pkt.srcPort == 443) {
			// QUIC long-header Initial packets start with a byte in 0xC0..0xFF.
			if len(pkt.payload) > 1200 || (len(pkt.payload) > 0 && pkt.payload[0]&0xc0 == 0xc0) {
				key := pkt.srcIP + "->" + pkt.dstIP
				if len(quicFirstBytes) < 4 && len(pkt.payload) > 8 {
					quicFirstBytes[key] = int(pkt.payload[1])<<24 | int(pkt.payload[2])<<16 |
						int(pkt.payload[3])<<8 | int(pkt.payload[4])
				}
			}
			continue
		}
		if pkt.protocol != "TCP" || len(pkt.payload) == 0 {
			continue
		}
		if pkt.dstPort != 443 && pkt.srcPort != 443 {
			continue
		}
		key := flowKey{pkt.srcIP, pkt.dstIP, pkt.srcPort, pkt.dstPort}
		if _, seen := flows[key]; !seen {
			flowOrder = append(flowOrder, key)
		}
		flows[key] = append(flows[key], pkt.payload...)
	}

	var out strings.Builder
	fmt.Fprintf(&out, "# pcap analysis: %s\n\n", inPath)
	fmt.Fprintf(&out, "IPv4 TCP/UDP packets: %d, TCP flows on 443: %d\n", len(packets), len(flowOrder))

	if len(quicFirstBytes) > 0 {
		fmt.Fprintf(&out, "\n## QUIC / HTTP-3 traffic detected\n")
		for k, v := range quicFirstBytes {
			fmt.Fprintf(&out, "  %s  first long-header bytes: %08x\n", k, v)
		}
		fmt.Fprintf(&out, "  NOTE: if the client uses HTTP/3, its handshake is inside QUIC, not TLS records.\n")
	} else {
		fmt.Fprintf(&out, "\n## No QUIC detected — client uses TLS over TCP.\n")
	}

	found := 0
	for i, key := range flowOrder {
		stream := flows[key]
		record, ok := extractClientHelloRecord(stream)
		if !ok {
			continue
		}
		found++
		stem := fmt.Sprintf("pcap-clienthello.%d", i+1)
		binPath := filepath.Join(outDir, stem+".bin")
		if err := os.WriteFile(binPath, record, 0o644); err != nil {
			return fmt.Errorf("write %s: %w", binPath, err)
		}

		fmt.Fprintf(&out, "\n## ClientHello #%d  (%s:%d -> %s:%d, %d bytes on the wire)\n",
			found, key.srcIP, key.srcPort, key.dstIP, key.dstPort, len(record))

		spec, errSpec := (&tls.Fingerprinter{AllowBluntMimicry: true}).FingerprintClientHello(record)
		if errSpec != nil {
			fmt.Fprintf(&out, "  could not fingerprint: %v\n  raw: %s\n", errSpec, hex.EncodeToString(record))
			continue
		}
		report := summariseHello(spec)
		fmt.Fprint(&out, report)
		fmt.Fprintf(&out, "  raw saved: %s\n", binPath)
	}

	if found == 0 {
		fmt.Fprintf(&out, "\nNo ClientHello found. The capture may have missed the handshake, or the\n")
		fmt.Fprintf(&out, "traffic used a connection established before the capture started.\n")
	}

	path := filepath.Join(outDir, "pcap-report.txt")
	if err := os.WriteFile(path, []byte(out.String()), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", path, err)
	}
	fmt.Printf("analysed %d ClientHello(s); wrote %s\n\n", found, path)
	fmt.Print(out.String())
	return nil
}

// summariseHello prints the fields that actually distinguish one client from
// another, so a diff against the reference capture is a glance, not a ceremony.
func summariseHello(spec *tls.ClientHelloSpec) string {
	var b strings.Builder
	var extNames []string
	hasALPN := false
	hasGREASE := false
	var alpn []string

	for i, ext := range spec.Extensions {
		id := extensionID(ext)
		name := extensionName(id)
		extNames = append(extNames, fmt.Sprintf("0x%04x %s", id, name))
		switch e := ext.(type) {
		case *tls.ALPNExtension:
			hasALPN = true
			alpn = e.AlpnProtocols
		case *tls.UtlsGREASEExtension:
			hasGREASE = true
		}
		_ = i
	}

	fmt.Fprintf(&b, "  cipher suites: %d, first three: %s\n", len(spec.CipherSuites), firstN(spec.CipherSuites, 3))
	fmt.Fprintf(&b, "  ALPN: %v", hasALPN)
	if hasALPN {
		fmt.Fprintf(&b, "  protocols=%v  <-- client speaks HTTP/2", alpn)
	} else {
		fmt.Fprintf(&b, "  <-- no ALPN extension, falls back to HTTP/1.1")
	}
	fmt.Fprintf(&b, "\n")
	fmt.Fprintf(&b, "  GREASE present: %v\n", hasGREASE)
	fmt.Fprintf(&b, "  extension order (%d):\n", len(spec.Extensions))
	for i, n := range extNames {
		fmt.Fprintf(&b, "    %2d. %s\n", i, n)
	}
	for _, ext := range spec.Extensions {
		switch e := ext.(type) {
		case *tls.SNIExtension:
			if e.ServerName != "" {
				fmt.Fprintf(&b, "  SNI: %s\n", e.ServerName)
			}
		case *tls.SupportedCurvesExtension:
			fmt.Fprintf(&b, "  groups: %s\n", joinCurves(e.Curves))
		case *tls.KeyShareExtension:
			fmt.Fprintf(&b, "  key shares: %s\n", joinKeyShares(e.KeyShares))
		}
	}
	return b.String()
}

func firstN(v []uint16, n int) string {
	parts := make([]string, 0, n)
	for i, x := range v {
		if i >= n {
			break
		}
		parts = append(parts, fmt.Sprintf("0x%04x", x))
	}
	return strings.Join(parts, ", ")
}
