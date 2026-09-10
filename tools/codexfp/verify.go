package main

import (
	"context"
	"fmt"
	"net"
	"os"
	"reflect"
	"strings"
	"time"

	tls "github.com/refraction-networking/utls"
)

// runVerify replays a captured ClientHello through uTLS and compares what comes
// back out with the original. A profile is only trustworthy once this passes:
// it catches extension reordering, dropped extensions and wrong lengths, which
// a spec dump looks fine but does not prove.
func runVerify(inPath, sni string) error {
	reference, err := os.ReadFile(inPath)
	if err != nil {
		return fmt.Errorf("read reference %s: %w", inPath, err)
	}
	spec, err := (&tls.Fingerprinter{AllowBluntMimicry: true}).FingerprintClientHello(reference)
	if err != nil {
		return fmt.Errorf("fingerprint reference: %w", err)
	}

	got, err := replayClientHello(spec, sni)
	if err != nil {
		return err
	}
	if err := os.WriteFile(inPath+".replay.bin", got, 0o644); err != nil {
		return fmt.Errorf("write replay: %w", err)
	}

	gotSpec, err := (&tls.Fingerprinter{AllowBluntMimicry: true}).FingerprintClientHello(got)
	if err != nil {
		return fmt.Errorf("fingerprint replay: %w", err)
	}

	ok := true
	if len(reference) != len(got) {
		fmt.Printf("record length: reference=%d replay=%d  MISMATCH\n", len(reference), len(got))
		ok = false
	} else {
		fmt.Printf("record length: %d == %d  ok\n", len(reference), len(got))
	}

	ok = compareList("cipher suites", len(spec.CipherSuites), len(gotSpec.CipherSuites),
		uint16Slice(spec.CipherSuites), uint16Slice(gotSpec.CipherSuites)) && ok
	ok = compareList("compression methods", len(spec.CompressionMethods), len(gotSpec.CompressionMethods),
		uint8Slice(spec.CompressionMethods), uint8Slice(gotSpec.CompressionMethods)) && ok

	fmt.Printf("extensions: reference=%d replay=%d\n", len(spec.Extensions), len(gotSpec.Extensions))
	if len(spec.Extensions) != len(gotSpec.Extensions) {
		ok = false
	}
	for i := 0; i < len(spec.Extensions) && i < len(gotSpec.Extensions); i++ {
		wantID := extensionID(spec.Extensions[i])
		gotID := extensionID(gotSpec.Extensions[i])
		status := "ok"
		if wantID != gotID {
			status = "MISMATCH"
			ok = false
		}
		fmt.Printf("  %2d. 0x%04x %-24s -> 0x%04x %s\n", i, wantID, extensionName(wantID), gotID, status)
		if wantID != gotID {
			continue
		}
		want := describeExtension(spec.Extensions[i])
		gotDesc := describeExtension(gotSpec.Extensions[i])
		// Key share contents are freshly generated per handshake by design.
		if strings.HasPrefix(want, "keyshares=") || strings.HasPrefix(want, "server_name=") || strings.HasPrefix(want, "GREASE") {
			fmt.Printf("        (contents vary by design) want=%s got=%s\n", want, gotDesc)
			continue
		}
		if want != gotDesc {
			fmt.Printf("        body MISMATCH\n          want: %s\n          got:  %s\n", want, gotDesc)
			ok = false
		}
	}

	if !ok {
		return fmt.Errorf("replay does NOT reproduce the reference ClientHello")
	}
	fmt.Printf("\nOK: the spec reproduces the captured ClientHello.\n")
	return nil
}

// replayClientHello dials a local listener with the given spec and returns the
// ClientHello bytes uTLS actually put on the wire.
func replayClientHello(spec *tls.ClientHelloSpec, sni string) ([]byte, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("listen: %w", err)
	}
	defer func() {
		if errClose := ln.Close(); errClose != nil {
			fmt.Fprintf(os.Stderr, "codexfp: close listener: %v\n", errClose)
		}
	}()

	captured := make(chan []byte, 1)
	go func() {
		conn, errAccept := ln.Accept()
		if errAccept != nil {
			captured <- nil
			return
		}
		defer func() {
			if errClose := conn.Close(); errClose != nil {
				fmt.Fprintf(os.Stderr, "codexfp: close conn: %v\n", errClose)
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
				if rec, ok := extractClientHelloRecord(buf); ok {
					captured <- rec
					return
				}
			}
			if errRead != nil {
				captured <- nil
				return
			}
		}
	}()

	conn, errDial := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if errDial != nil {
		return nil, fmt.Errorf("dial: %w", errDial)
	}
	sessionCache := tls.NewLRUClientSessionCache(4)
	uconn := tls.UClient(conn, &tls.Config{
		ServerName:                         sni,
		ClientSessionCache:                 sessionCache,
		OmitEmptyPsk:                       true,
		PreferSkipResumptionOnNilExtension: true,
	}, tls.HelloCustom)
	if errPreset := uconn.ApplyPreset(spec); errPreset != nil {
		return nil, fmt.Errorf("apply preset: %w", errPreset)
	}
	// The handshake cannot complete against our bare listener; we only need the
	// ClientHello, which is sent first.
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = uconn.HandshakeContext(ctx)
	}()

	select {
	case out := <-captured:
		if out == nil {
			return nil, fmt.Errorf("no ClientHello observed from replay")
		}
		return out, nil
	case <-time.After(15 * time.Second):
		return nil, fmt.Errorf("timed out waiting for the replayed ClientHello")
	}
}

func compareList(name string, wantLen, gotLen int, want, got []string) bool {
	if reflect.DeepEqual(want, got) {
		fmt.Printf("%s: %d entries, identical\n", name, wantLen)
		return true
	}
	fmt.Printf("%s MISMATCH (want %d, got %d)\n", name, wantLen, gotLen)
	for i := 0; i < len(want) || i < len(got); i++ {
		w, g := "<none>", "<none>"
		if i < len(want) {
			w = want[i]
		}
		if i < len(got) {
			g = got[i]
		}
		if w != g {
			fmt.Printf("  %2d. want=%s got=%s\n", i, w, g)
		}
	}
	return false
}

func uint16Slice(in []uint16) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		out = append(out, fmt.Sprintf("0x%04x", v))
	}
	return out
}

func uint8Slice(in []uint8) []string {
	out := make([]string, 0, len(in))
	for _, v := range in {
		out = append(out, fmt.Sprintf("0x%02x", v))
	}
	return out
}
