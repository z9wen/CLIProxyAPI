package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	tls "github.com/refraction-networking/utls"
)

const captureReadTimeout = 20 * time.Second

// runHello accepts TCP connections and dumps the first ClientHello it sees. No
// TLS handshake is completed: the client will report a handshake failure, which
// is expected and harmless. The ClientHello is fully transmitted before any
// server response is read, so closing early loses nothing.
func runHello(addr, outDir string) error {
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("listen %s: %w", addr, err)
	}
	defer func() {
		if errClose := ln.Close(); errClose != nil {
			fmt.Fprintf(os.Stderr, "codexfp: close listener: %v\n", errClose)
		}
	}()
	fmt.Printf("listening on %s (mode=hello)\nwaiting for the client to connect...\n", addr)
	seq := 0
	for {
		conn, errAccept := ln.Accept()
		if errAccept != nil {
			return fmt.Errorf("accept: %w", errAccept)
		}
		seq++
		handleHello(conn, outDir, seq)
	}
}

func handleHello(conn net.Conn, outDir string, seq int) {
	defer func() {
		if errClose := conn.Close(); errClose != nil {
			fmt.Fprintf(os.Stderr, "codexfp: close conn: %v\n", errClose)
		}
	}()
	remote := conn.RemoteAddr().String()
	fmt.Printf("\n[%d] connection from %s\n", seq, remote)

	buf := make([]byte, 0, 8192)
	chunk := make([]byte, 4096)
	deadline := time.Now().Add(captureReadTimeout)
	if err := conn.SetReadDeadline(deadline); err != nil {
		fmt.Fprintf(os.Stderr, "codexfp: set deadline: %v\n", err)
		return
	}
	var record []byte
	for {
		n, errRead := conn.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
			if rec, ok := extractClientHelloRecord(buf); ok {
				record = rec
				break
			}
		}
		if errRead != nil {
			break
		}
	}
	if record == nil {
		fmt.Printf("[%d] no ClientHello captured (%d bytes read)\n", seq, len(buf))
		return
	}

	if err := writeHelloArtifacts(outDir, seq, record); err != nil {
		fmt.Fprintf(os.Stderr, "codexfp: %v\n", err)
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

func writeHelloArtifacts(outDir string, seq int, record []byte) error {
	suffix := ""
	if seq > 1 {
		suffix = fmt.Sprintf(".%d", seq)
	}
	stem := "clienthello" + suffix
	binPath := filepath.Join(outDir, stem+".bin")
	if err := os.WriteFile(binPath, record, 0o644); err != nil {
		return fmt.Errorf("write %s: %w", binPath, err)
	}

	return emitHelloReport(outDir, stem, record)
}

// runAnalyze re-derives the report and Go spec from ClientHello bytes already on
// disk, so a capture never has to be repeated just because the analysis changed.
func runAnalyze(outDir string) error {
	matches, err := filepath.Glob(filepath.Join(outDir, "clienthello*.bin"))
	if err != nil {
		return fmt.Errorf("scan %s: %w", outDir, err)
	}
	if len(matches) == 0 {
		return fmt.Errorf("no clienthello*.bin found in %s", outDir)
	}
	for _, path := range matches {
		record, errRead := os.ReadFile(path)
		if errRead != nil {
			return fmt.Errorf("read %s: %w", path, errRead)
		}
		stem := strings.TrimSuffix(filepath.Base(path), ".bin")
		if err := emitHelloReport(outDir, stem, record); err != nil {
			return err
		}
	}
	return nil
}

func emitHelloReport(outDir, stem string, record []byte) error {
	// AllowBluntMimicry carries extensions uTLS has no native type for (OpenSSL
	// sends encrypt_then_mac, which uTLS does not model) through as opaque bytes.
	// They are static, so replaying them verbatim is faithful.
	spec, err := (&tls.Fingerprinter{AllowBluntMimicry: true}).FingerprintClientHello(record)
	if err != nil {
		return fmt.Errorf("fingerprint ClientHello (%d bytes): %w", len(record), err)
	}

	var report strings.Builder
	fmt.Fprintf(&report, "# ClientHello capture\n\n")
	fmt.Fprintf(&report, "record length: %d bytes\n", len(record))
	fmt.Fprintf(&report, "raw hex: %s\n\n", hex.EncodeToString(record))

	fmt.Fprintf(&report, "## Cipher suites (%d)\n", len(spec.CipherSuites))
	for i, cs := range spec.CipherSuites {
		fmt.Fprintf(&report, "  %2d. 0x%04x  %s\n", i, cs, strings.TrimPrefix(cipherSuiteName(cs), "tls."))
	}
	fmt.Fprintf(&report, "\n## Compression methods\n  %v\n", spec.CompressionMethods)

	fmt.Fprintf(&report, "\n## Extensions, in wire order (%d)\n", len(spec.Extensions))
	for i, ext := range spec.Extensions {
		fmt.Fprintf(&report, "  %2d. 0x%04x %-32s %s\n", i, extensionID(ext), extensionName(extensionID(ext)), describeExtension(ext))
	}

	txtPath := filepath.Join(outDir, stem+".txt")
	if err := os.WriteFile(txtPath, []byte(report.String()), 0o644); err != nil {
		return fmt.Errorf("write %s: %w", txtPath, err)
	}

	goPath := filepath.Join(outDir, stem+".spec.go")
	f, err := os.Create(goPath)
	if err != nil {
		return fmt.Errorf("create %s: %w", goPath, err)
	}
	defer func() {
		if errClose := f.Close(); errClose != nil {
			fmt.Fprintf(os.Stderr, "codexfp: close %s: %v\n", goPath, errClose)
		}
	}()
	fmt.Fprintf(f, "// Generated by codexfp from a live capture of the real client.\n")
	fmt.Fprintf(f, "// Keep in sync with a fresh capture whenever the advertised client version changes.\n\n")
	emitSpec(f, spec, "codexTLSClientHelloSpec")

	fmt.Printf("%s: %d bytes, %d cipher suites, %d extensions\n", stem, len(record), len(spec.CipherSuites), len(spec.Extensions))
	fmt.Printf("     wrote %s\n     wrote %s\n", txtPath, goPath)
	fmt.Print(report.String())
	return nil
}

func describeExtension(ext tls.TLSExtension) string {
	switch e := ext.(type) {
	case *tls.SNIExtension:
		return fmt.Sprintf("server_name=%q", e.ServerName)
	case *tls.SupportedCurvesExtension:
		return "groups=" + joinCurves(e.Curves)
	case *tls.SupportedPointsExtension:
		return fmt.Sprintf("points=%v", e.SupportedPoints)
	case *tls.SignatureAlgorithmsExtension:
		return "sigalgs=" + joinSigSchemes(e.SupportedSignatureAlgorithms)
	case *tls.SignatureAlgorithmsCertExtension:
		return "sigalgs_cert=" + joinSigSchemes(e.SupportedSignatureAlgorithms)
	case *tls.ALPNExtension:
		return fmt.Sprintf("alpn=%v", e.AlpnProtocols)
	case *tls.SupportedVersionsExtension:
		return fmt.Sprintf("versions=%v", e.Versions)
	case *tls.KeyShareExtension:
		return "keyshares=" + joinKeyShares(e.KeyShares)
	case *tls.PSKKeyExchangeModesExtension:
		return fmt.Sprintf("psk_modes=%v", e.Modes)
	case *tls.UtlsPreSharedKeyExtension:
		return "PRE_SHARED_KEY (resumption attempted)"
	case *tls.FakePreSharedKeyExtension:
		return "PRE_SHARED_KEY (fake)"
	case *tls.UtlsPaddingExtension:
		return "padding"
	case *tls.SessionTicketExtension:
		return "session_ticket (empty)"
	case *tls.RenegotiationInfoExtension:
		return fmt.Sprintf("renegotiation=%s", renegotiationName(e.Renegotiation))
	case *tls.UtlsGREASEExtension:
		return fmt.Sprintf("GREASE value=0x%04x body=%v", e.Value, e.Body)
	case *tls.GenericExtension:
		return fmt.Sprintf("unrecognized, %d body bytes: %s", len(e.Data), hex.EncodeToString(e.Data))
	default:
		return fmt.Sprintf("%T", ext)
	}
}
