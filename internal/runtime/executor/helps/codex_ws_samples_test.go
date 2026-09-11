package helps

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	tls "github.com/refraction-networking/utls"
)

// Real captures of the Codex WebSocket handshake, taken from the same client, in
// the order the extensions appeared on the wire. Each run produced a different
// order from the same extension set — the client runs rustls, which reorders its
// extensions per connection — and that spread is why the WebSocket profile is
// kept as a set of captures rather than one.
//
// (extension ids: 0 server_name, 5 status_request, 10 supported_groups,
// 11 ec_point_formats, 13 signature_algorithms, 23 extended_master_secret,
// 35 session_ticket, 43 supported_versions, 45 psk_key_exchange_modes,
// 51 key_share)
var codexWebSocketCaptureOrders = map[string][]uint16{
	"reference capture": {
		0x000b, 0x0017, 0x000a, 0x0023, 0x0033,
		0x0000, 0x002d, 0x000d, 0x0005, 0x002b,
	},
	"router run 1": {
		0x002b, 0x000b, 0x0023, 0x0033, 0x0000,
		0x0005, 0x000a, 0x0017, 0x000d, 0x002d,
	},
	"router run 2": {
		0x000a, 0x002b, 0x0017, 0x0023, 0x0000,
		0x002d, 0x0033, 0x000d, 0x000b, 0x0005,
	},
}

// The captures must not share an order, or one capture would have been enough
// and the rotation would be reproducing a constant.
func TestRealCapturesDisagreeOnOrder(t *testing.T) {
	t.Parallel()

	seen := make(map[string]string, len(codexWebSocketCaptureOrders))
	for name, order := range codexWebSocketCaptureOrders {
		key := ""
		for _, id := range order {
			key += string(rune(id)) + ","
		}
		if other, clash := seen[key]; clash {
			t.Fatalf("%s and %s share an extension order; the captures do not evidence a spread", name, other)
		}
		seen[key] = name
	}
}

// Every capture has to offer the same extensions, so rotating between them
// changes only the order and never what is sent.
func TestCapturesAgreeOnExtensionSet(t *testing.T) {
	t.Parallel()

	var reference []uint16
	for name, order := range codexWebSocketCaptureOrders {
		sorted := append([]uint16(nil), order...)
		sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })
		if reference == nil {
			reference = sorted
			continue
		}
		if len(sorted) != len(reference) {
			t.Fatalf("%s offers %d extensions, the first capture offered %d", name, len(sorted), len(reference))
		}
		for i := range sorted {
			if sorted[i] != reference[i] {
				t.Fatalf("%s offers extensions %v, the first capture offered %v", name, sorted, reference)
			}
		}
	}
}

// The rotation is the whole point: with several captures the accessor must not
// keep handing back the same one, or the JA3 stays constant and the spread the
// captures were collected for never reaches the wire.
func TestWebSocketProfileRotatesAmongSamples(t *testing.T) {
	restoreProfileState(t)

	base := builtinCodexWebSocketClientHelloSpec()
	installed := []*tls.ClientHelloSpec{
		rotatedExtensions(base, 0),
		rotatedExtensions(base, 1),
		rotatedExtensions(base, 3),
	}
	installWebSocketSamples(t, installed)

	seen := make(map[string]int, len(installed))
	const draws = 60
	for i := 0; i < draws; i++ {
		spec := CodexWebSocketClientHelloSpec()
		key := extensionOrderKeyOf(spec)
		seen[key]++
	}
	if len(seen) < 2 {
		t.Fatalf("%d draws all returned the same capture (%v); the rotation is not reaching the handshake", draws, seen)
	}
	// A draw that returns something outside the installed set would mean the
	// rotation is mixing in the built-in profile.
	for key := range seen {
		found := false
		for _, spec := range installed {
			if extensionOrderKeyOf(spec) == key {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("a draw returned capture %s, which is not one of the installed samples", key)
		}
	}
}

// One capture is the old behaviour and must stay exactly that: the sample is used
// as it is, not reshuffled or mixed with the built-in profile.
func TestSingleWebSocketSampleIsUsedAsIs(t *testing.T) {
	restoreProfileState(t)

	sample := rotatedExtensions(builtinCodexWebSocketClientHelloSpec(), 2)
	installWebSocketSamples(t, []*tls.ClientHelloSpec{sample})

	want := extensionOrderKeyOf(sample)
	for i := 0; i < 5; i++ {
		if got := extensionOrderKeyOf(CodexWebSocketClientHelloSpec()); got != want {
			t.Fatalf("draw %d returned %s, want the single installed capture %s", i, got, want)
		}
	}
}

// The loader has to pick up the extra samples, or a capture that recorded a set
// would still be replayed as one ordering.
func TestProfileLoaderReadsEveryWebSocketSample(t *testing.T) {
	restoreProfileState(t)

	dir := t.TempDir()
	record, errRead := os.ReadFile(filepath.Join("testdata", CodexProfileWebSocketFile))
	if errRead != nil {
		t.Fatalf("read the reference capture: %v", errRead)
	}
	for _, name := range []string{
		CodexProfileWebSocketFile,
		"codex-websocket-clienthello.2.bin",
		"codex-websocket-clienthello.3.bin",
	} {
		if errWrite := os.WriteFile(filepath.Join(dir, name), record, 0o600); errWrite != nil {
			t.Fatalf("write %s: %v", name, errWrite)
		}
	}
	if err := SetCodexProfileDir(dir); err != nil {
		t.Fatalf("SetCodexProfileDir: %v", err)
	}

	codexProfileMu.RLock()
	loaded := len(codexProfileWebSockets)
	codexProfileMu.RUnlock()
	if loaded != 3 {
		t.Fatalf("loaded %d WebSocket samples, want 3", loaded)
	}
}

// restoreProfileState returns the package's profile state to what it was, so a
// test that installs samples cannot affect another.
func restoreProfileState(t *testing.T) {
	t.Helper()
	previousDir := CodexProfileDir()
	codexProfileMu.RLock()
	previousHTTP := codexProfileHTTPSpec
	previousWebSockets := append([]*tls.ClientHelloSpec(nil), codexProfileWebSockets...)
	codexProfileMu.RUnlock()

	t.Cleanup(func() {
		codexProfileMu.Lock()
		codexProfileDir = previousDir
		codexProfileHTTPSpec = previousHTTP
		codexProfileWebSockets = previousWebSockets
		codexProfileMu.Unlock()
	})
	// Not parallel: the installed samples are package state.
	codexProfileMu.Lock()
	codexProfileDir = ""
	codexProfileHTTPSpec = nil
	codexProfileWebSockets = nil
	codexProfileMu.Unlock()
}

func installWebSocketSamples(t *testing.T, specs []*tls.ClientHelloSpec) {
	t.Helper()
	codexProfileMu.Lock()
	codexProfileWebSockets = specs
	codexProfileMu.Unlock()
}

// rotatedExtensions returns a copy of spec with its extension list rotated, which
// is enough to stand in for a capture with a different ordering.
func rotatedExtensions(base *tls.ClientHelloSpec, by int) *tls.ClientHelloSpec {
	extensions := append([]tls.TLSExtension(nil), base.Extensions...)
	if len(extensions) > 0 {
		by = ((by % len(extensions)) + len(extensions)) % len(extensions)
		extensions = append(extensions[by:], extensions[:by]...)
	}
	copied := *base
	copied.Extensions = extensions
	return &copied
}

// extensionOrderKeyOf renders a profile's extension order for comparison.
func extensionOrderKeyOf(spec *tls.ClientHelloSpec) string {
	if spec == nil {
		return "<nil>"
	}
	key := ""
	for _, ext := range spec.Extensions {
		key += string(rune(extensionTypeOf(ext))) + ","
	}
	return key
}

// extensionTypeOf names an extension's wire type for the tests here. It only has
// to distinguish the extensions the Codex profile uses.
func extensionTypeOf(ext tls.TLSExtension) uint16 {
	switch e := ext.(type) {
	case *tls.GenericExtension:
		return e.Id
	case *tls.UtlsGREASEExtension:
		return e.Value
	case *tls.SNIExtension:
		return 0
	case *tls.StatusRequestExtension:
		return 5
	case *tls.SupportedCurvesExtension:
		return 10
	case *tls.SupportedPointsExtension:
		return 11
	case *tls.SignatureAlgorithmsExtension:
		return 13
	case *tls.ExtendedMasterSecretExtension:
		return 23
	case *tls.SessionTicketExtension:
		return 35
	case *tls.SupportedVersionsExtension:
		return 43
	case *tls.PSKKeyExchangeModesExtension:
		return 45
	case *tls.KeyShareExtension:
		return 51
	default:
		return 0xffff
	}
}

// extensionPair is one extension as it appeared on the wire: type and length.
type extensionPair struct {
	id     uint16
	length int
}

// pairExtensions zips the types and lengths a capture helper reports.
func pairExtensions(ids []uint16, lengths []int) []extensionPair {
	pairs := make([]extensionPair, 0, len(ids))
	for i, id := range ids {
		length := 0
		if i < len(lengths) {
			length = lengths[i]
		}
		pairs = append(pairs, extensionPair{id: id, length: length})
	}
	return pairs
}

// sameExtensionMultiset reports whether two handshakes offered the same
// extensions with the same lengths, whatever order they went in.
func sameExtensionMultiset(aIDs []uint16, aLengths []int, bIDs []uint16, bLengths []int) bool {
	a, b := pairExtensions(aIDs, aLengths), pairExtensions(bIDs, bLengths)
	byIDThenLength := func(pairs []extensionPair) func(i, j int) bool {
		return func(i, j int) bool {
			if pairs[i].id != pairs[j].id {
				return pairs[i].id < pairs[j].id
			}
			return pairs[i].length < pairs[j].length
		}
	}
	sort.Slice(a, byIDThenLength(a))
	sort.Slice(b, byIDThenLength(b))
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// The accessor can rotate all it likes; what matters is that the rotation reaches
// the wire. This performs the handshake ApplyCodexWebsocketTLSDialContext does
// and reads the order off the ClientHello that was actually sent.
func TestWebSocketHandshakeUsesTheRotatedCapture(t *testing.T) {
	restoreProfileState(t)

	base := builtinCodexWebSocketClientHelloSpec()
	installWebSocketSamples(t, []*tls.ClientHelloSpec{
		rotatedExtensions(base, 0),
		rotatedExtensions(base, 2),
	})

	const handshakes = 12
	seen := make(map[string]int, 2)
	for i := 0; i < handshakes; i++ {
		got := captureClientHelloFromDial(t, func(addr string) {
			conn, errDial := net.DialTimeout("tcp", addr, 5*time.Second)
			if errDial != nil {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, errApply := ApplyCodexWebSocketClientHello(ctx, conn, "chatgpt.com"); errApply != nil && !errors.Is(errApply, context.DeadlineExceeded) {
				t.Logf("websocket handshake: %v", errApply)
			}
		})
		seen[fmt.Sprint(got.ExtensionTypes)]++
	}
	if len(seen) < 2 {
		t.Fatalf("%d handshakes all sent one extension order (%v); the rotation is not reaching the wire", handshakes, seen)
	}
	t.Logf("%d handshakes produced %d distinct extension orders", handshakes, len(seen))
}

// uTLS does not treat the spec it is given as read-only: ApplyPreset generates a
// key share and writes it back, and skips any share that already has data. A
// captured profile is cached and shared by every connection, so without a copy
// the first handshake primes it and every later one replays that first
// connection's keys — with no post-quantum private key at all, which aborts the
// handshake the moment the server selects that group.
func TestHandshakeDoesNotMutateTheCachedProfile(t *testing.T) {
	restoreProfileState(t)

	record, errRead := os.ReadFile(filepath.Join("testdata", CodexProfileWebSocketFile))
	if errRead != nil {
		t.Fatalf("read the reference capture: %v", errRead)
	}
	spec, errFingerprint := (&tls.Fingerprinter{AllowBluntMimicry: true}).FingerprintClientHello(record)
	if errFingerprint != nil {
		t.Fatalf("fingerprint: %v", errFingerprint)
	}
	installWebSocketSamples(t, []*tls.ClientHelloSpec{spec})

	before := keyShareDataLengths(spec)
	// Two handshakes: the first is what would prime a shared spec.
	for i := 0; i < 2; i++ {
		captureClientHelloFromDial(t, func(addr string) {
			conn, errDial := net.DialTimeout("tcp", addr, 5*time.Second)
			if errDial != nil {
				return
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if _, errApply := ApplyCodexWebSocketClientHello(ctx, conn, "chatgpt.com"); errApply != nil && !errors.Is(errApply, context.DeadlineExceeded) {
				t.Logf("websocket handshake: %v", errApply)
			}
		})
	}

	if after := keyShareDataLengths(spec); !reflect.DeepEqual(before, after) {
		t.Fatalf("the handshake changed the cached profile: key share data lengths %v -> %v;"+
			" every later handshake would replay the first connection's keys", before, after)
	}
}

// keyShareDataLengths reports what each key share carries, which is what uTLS
// fills in and what a reused spec would carry over from an earlier connection.
func keyShareDataLengths(spec *tls.ClientHelloSpec) []int {
	var lengths []int
	for _, ext := range spec.Extensions {
		shares, ok := ext.(*tls.KeyShareExtension)
		if !ok {
			continue
		}
		for _, share := range shares.KeyShares {
			lengths = append(lengths, len(share.Data))
		}
	}
	return lengths
}
