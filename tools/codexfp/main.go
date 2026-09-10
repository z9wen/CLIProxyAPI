// Command codexfp captures the OpenAI Codex client's TLS + HTTP/2 wire
// fingerprint on the local machine, without sending anything to OpenAI.
//
// Why this exists: OpenAI's anti-abuse view of us is dominated by how the
// connection looks, not by what we ask for. The authoritative source for that
// is a capture of the real client. Capturing against chatgpt.com is unreliable
// (upstream outages, rate limits, and the client needs a working account), and
// the TLS ClientHello is produced before any response arrives anyway. So we
// point the client at ourselves:
//
//	sudo codexfp -mode genca -out ~/codex-capture
//	# trust ~/codex-capture/ca.pem in the System keychain, then map the host:
//	#   127.0.0.1 chatgpt.com   >> /etc/hosts
//	sudo codexfp -mode h2 -addr :443 -out ~/codex-capture
//	# run one codex turn; it will fail, which is fine and expected
//
// Modes:
//
//	genca  generate a CA plus a chatgpt.com leaf certificate
//	hello  accept TCP, dump the ClientHello, emit a uTLS ClientHelloSpec as Go
//	proxy  CONNECT proxy that dumps the tunnelled ClientHello (no CA needed)
//	serve  terminate TLS and dump whatever follows, HTTP/2 or HTTP/1.1
//
// serve sniffs the first bytes after the handshake, so it works whether the
// client negotiated h2 (SETTINGS, WINDOW_UPDATE, HPACK-decoded header order) or
// arrived as plain HTTP/1.1 (request line, verbatim header order, body framing).
// The real Codex CLI defaults to native-tls, which cannot request ALPN at all,
// so HTTP/1.1 is the expected case.
package main

import (
	"flag"
	"fmt"
	"os"
)

func main() {
	mode := flag.String("mode", "hello", "genca | hello | h2")
	addr := flag.String("addr", ":443", "listen address")
	out := flag.String("out", ".", "output directory")
	host := flag.String("host", "chatgpt.com", "host to mint the leaf certificate for, and the SNI used by -mode verify")
	in := flag.String("in", "", "reference ClientHello for -mode verify")
	forward := flag.Bool("forward", false, "proxy mode: splice the tunnel through to the real destination after capture")
	flag.Parse()

	if err := os.MkdirAll(*out, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "codexfp: create out dir: %v\n", err)
		os.Exit(1)
	}

	var err error
	switch *mode {
	case "genca":
		err = runGenCA(*out, *host)
	case "hello":
		err = runHello(*addr, *out)
	case "analyze":
		err = runAnalyze(*out)
	case "pcap":
		if *in == "" {
			err = fmt.Errorf("-in <capture.pcap> is required for -mode pcap")
			break
		}
		err = runPcap(*in, *out)
	case "verify":
		if *in == "" {
			err = fmt.Errorf("-in <clienthello.bin> is required for -mode verify")
			break
		}
		err = runVerify(*in, *host)
	case "proxy":
		err = runProxy(*addr, *out, *forward)
	case "serve", "h2":
		err = runServe(*addr, *out)
	default:
		err = fmt.Errorf("unknown mode %q", *mode)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "codexfp: %v\n", err)
		os.Exit(1)
	}
}
