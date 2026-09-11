package helps

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"testing"

	tls "github.com/refraction-networking/utls"
)

// Golden values for rustls's ordering hash, so a silent change to the port shows
// up here rather than as a fingerprint that quietly stops matching. Computed
// from rustls 0.23's low_quality_integer_hash.
func TestOrderHashMatchesRustls(t *testing.T) {
	t.Parallel()

	cases := []struct {
		in   uint32
		want uint32
	}{
		{0x00000000, 0x6b4ed927},
		{0x00000001, 0xb48681b6},
		{0x00000010, 0x195d7784},
		{0x0000ffff, 0x070a6eec},
		{0xe0a70000, 0x295b595f},
		{0xe0a7000b, 0x8619b4c6},
		{0x00010000, 0x8f8defe4},
		{0xdeadbeef, 0x7ff0eada},
	}
	for _, tc := range cases {
		if got := lowQualityIntegerHash(tc.in); got != tc.want {
			t.Errorf("lowQualityIntegerHash(0x%08x) = 0x%08x, want 0x%08x", tc.in, got, tc.want)
		}
	}
}

// The whole reason for porting the algorithm: the client draws a fresh extension
// order per connection, so the orders it really emitted have to be exactly the
// ones this produces. Each known capture must be reachable from the reference
// record by some seed — if the hash or the sort were wrong, no seed would
// reproduce them.
func TestDrawnOrderReproducesRealClientCaptures(t *testing.T) {
	t.Parallel()

	record, errRead := os.ReadFile(filepath.Join("testdata", CodexProfileWebSocketFile))
	if errRead != nil {
		t.Fatalf("read the reference capture: %v", errRead)
	}
	base, errParse := parseClientHelloExtensions(record)
	if errParse != nil {
		t.Fatalf("parse the reference capture: %v", errParse)
	}

	for name, want := range codexWebSocketCaptureOrders {
		if _, found := seedForOrder(base.types, want); !found {
			t.Errorf("%s: no seed reproduces the recorded order %v from the reference capture;"+
				" the ordering algorithm does not match the client that produced it", name, want)
		}
	}
}

// A drawn order must still be a ClientHello: the same extensions, the same
// lengths, only rearranged. Nothing outside the extension list may move, or the
// lengths recorded in the header would describe the wrong bytes.
func TestReorderPreservesEveryByte(t *testing.T) {
	t.Parallel()

	record, errRead := os.ReadFile(filepath.Join("testdata", CodexProfileWebSocketFile))
	if errRead != nil {
		t.Fatalf("read the reference capture: %v", errRead)
	}
	base, errParse := parseClientHelloExtensions(record)
	if errParse != nil {
		t.Fatalf("parse the reference capture: %v", errParse)
	}

	for seed := 0; seed < 512; seed++ {
		reordered, errOrder := reorderClientHelloExtensions(record, uint16(seed))
		if errOrder != nil {
			t.Fatalf("seed %d: %v", seed, errOrder)
		}
		if len(reordered) != len(record) {
			t.Fatalf("seed %d: length changed %d -> %d", seed, len(record), len(reordered))
		}
		if !bytes.Equal(reordered[:base.extensionsOffset], record[:base.extensionsOffset]) {
			t.Fatalf("seed %d: the bytes before the extension list changed", seed)
		}
		got, errReparse := parseClientHelloExtensions(reordered)
		if errReparse != nil {
			t.Fatalf("seed %d: reordered record does not parse: %v", seed, errReparse)
		}
		if len(got.blocks) != len(base.blocks) {
			t.Fatalf("seed %d: %d extensions became %d", seed, len(base.blocks), len(got.blocks))
		}
		if !sameSet(got.types, base.types) {
			t.Fatalf("seed %d: extension set changed %v -> %v", seed, base.types, got.types)
		}
		// Same blocks, so the same bytes: only the order may differ.
		if !sameBlocks(got.blocks, base.blocks) {
			t.Fatalf("seed %d: extension contents changed", seed)
		}
	}
}

// Different seeds have to give different orders, or the whole exercise collapses
// back into the constant it was meant to remove.
func TestDrawnOrderVariesWithTheSeed(t *testing.T) {
	t.Parallel()

	record, errRead := os.ReadFile(filepath.Join("testdata", CodexProfileWebSocketFile))
	if errRead != nil {
		t.Fatalf("read the reference capture: %v", errRead)
	}

	seen := make(map[string]struct{})
	for seed := 0; seed < 64; seed++ {
		reordered, errOrder := reorderClientHelloExtensions(record, uint16(seed))
		if errOrder != nil {
			t.Fatalf("seed %d: %v", seed, errOrder)
		}
		parsed, errParse := parseClientHelloExtensions(reordered)
		if errParse != nil {
			t.Fatalf("seed %d: %v", seed, errParse)
		}
		seen[orderKey(parsed.types)] = struct{}{}
	}
	if len(seen) < 8 {
		t.Fatalf("64 seeds produced only %d distinct orders; the draw is not spreading", len(seen))
	}
}

// An extension the standard pins to the end has to stay there, whatever the
// seed draws.
func TestPinnedExtensionsStayLast(t *testing.T) {
	t.Parallel()

	types := []uint16{10, 51, 13, 41, 0, 43}
	for seed := 0; seed < 256; seed++ {
		got := applyRustlsOrder(types, uint16(seed))
		if got[len(got)-1] != 41 {
			t.Fatalf("seed %d: pre_shared_key is at %d, not last: %v", seed, len(got)-1, got)
		}
	}
}

// seedForOrder brute-forces the u16 seed that turns base into want.
func seedForOrder(base, want []uint16) (uint16, bool) {
	for seed := 0; seed < 1<<16; seed++ {
		if sameTypes(applyRustlsOrder(base, uint16(seed)), want) {
			return uint16(seed), true
		}
	}
	return 0, false
}

// applyRustlsOrder is the test's own reading of the ordering rule: a stable sort
// by the hash, with the pinned extensions appended unchanged.
func applyRustlsOrder(types []uint16, seed uint16) []uint16 {
	reorderable := make([]uint16, 0, len(types))
	var pinned []uint16
	for _, extType := range types {
		if isOrderPinned(extType) {
			pinned = append(pinned, extType)
			continue
		}
		reorderable = append(reorderable, extType)
	}
	sort.SliceStable(reorderable, func(a, b int) bool {
		return lowQualityIntegerHash(uint32(seed)<<16|uint32(reorderable[a])) <
			lowQualityIntegerHash(uint32(seed)<<16|uint32(reorderable[b]))
	})
	return append(reorderable, pinned...)
}

// sameBlocks reports whether two extension lists carry the same blocks,
// whatever order they are in.
func sameBlocks(a, b [][]byte) bool {
	if len(a) != len(b) {
		return false
	}
	x := append([][]byte(nil), a...)
	y := append([][]byte(nil), b...)
	less := func(blocks [][]byte) func(i, j int) bool {
		return func(i, j int) bool { return bytes.Compare(blocks[i], blocks[j]) < 0 }
	}
	sort.Slice(x, less(x))
	sort.Slice(y, less(y))
	for i := range x {
		if !bytes.Equal(x[i], y[i]) {
			return false
		}
	}
	return true
}

func sameTypes(a, b []uint16) bool {
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

func orderKey(types []uint16) string {
	key := make([]byte, 0, len(types)*2)
	for _, t := range types {
		key = append(key, byte(t>>8), byte(t))
	}
	return string(key)
}

// The accessor is what the handshake actually calls. With a raw capture loaded it
// must draw a new order every time, and every draw must still be a ClientHello
// offering exactly the extensions the capture did.
func TestWebSocketProfileDrawsANewOrderPerHandshake(t *testing.T) {
	restoreProfileState(t)

	record, errRead := os.ReadFile(filepath.Join("testdata", CodexProfileWebSocketFile))
	if errRead != nil {
		t.Fatalf("read the reference capture: %v", errRead)
	}
	reference, errParse := parseClientHelloExtensions(record)
	if errParse != nil {
		t.Fatalf("parse the reference capture: %v", errParse)
	}
	installWebSocketCapture(t, record)

	const draws = 80
	seen := make(map[string]struct{}, draws)
	for i := 0; i < draws; i++ {
		spec := CodexWebSocketClientHelloSpec()
		if spec == nil {
			t.Fatalf("draw %d returned no profile", i)
		}
		types := make([]uint16, 0, len(spec.Extensions))
		for _, ext := range spec.Extensions {
			types = append(types, extensionTypeOf(ext))
		}
		if !sameSet(types, reference.types) {
			t.Fatalf("draw %d offered %v, the capture offered %v", i, types, reference.types)
		}
		seen[orderKey(types)] = struct{}{}
	}
	if len(seen) < draws/4 {
		t.Fatalf("%d draws produced only %d distinct orders; the order is not being redrawn per handshake", draws, len(seen))
	}
}

func sameSet(a, b []uint16) bool {
	x := append([]uint16(nil), a...)
	y := append([]uint16(nil), b...)
	sort.Slice(x, func(i, j int) bool { return x[i] < x[j] })
	sort.Slice(y, func(i, j int) bool { return y[i] < y[j] })
	return sameTypes(x, y)
}

func installWebSocketCapture(t *testing.T, record []byte) {
	t.Helper()
	spec, errFingerprint := (&tls.Fingerprinter{AllowBluntMimicry: true}).FingerprintClientHello(record)
	if errFingerprint != nil {
		t.Fatalf("fingerprint the capture: %v", errFingerprint)
	}
	codexProfileMu.Lock()
	codexProfileWebSocketRaw = record
	codexProfileWebSockets = []*tls.ClientHelloSpec{spec}
	codexProfileMu.Unlock()
}
