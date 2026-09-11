package codexcapture

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/runtime/executor/helps"
)

// readCapture loads one of the reference captures the profile loader ships with.
// Classifying the real handshakes matters more than classifying fixtures: telling
// the two transports apart as the client actually emits them is the entire job.
func readCapture(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("..", "runtime", "executor", "helps", "testdata", name)
	record, errRead := os.ReadFile(path)
	if errRead != nil {
		t.Fatalf("read %s: %v", path, errRead)
	}
	return record
}

func TestClassifySeparatesTheTwoTransports(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		want profileKind
	}{
		{helps.CodexProfileHTTPFile, profileHTTP},
		{helps.CodexProfileWebSocketFile, profileWebSocket},
	}
	for _, tc := range cases {
		got, errClassify := classify(readCapture(t, tc.name))
		if errClassify != nil {
			t.Fatalf("classify(%s): %v", tc.name, errClassify)
		}
		if got != tc.want {
			t.Fatalf("classify(%s) = %s, want %s", tc.name, got, tc.want)
		}
	}
}

// The marker the classifier leans on has to be present in exactly one of the two,
// or the rule is not separating anything.
func TestTransportMarkersAreWhereTheClassifierExpectsThem(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		renegotiate bool
		encryptMAC  bool
	}{
		{helps.CodexProfileHTTPFile, true, true},
		{helps.CodexProfileWebSocketFile, false, false},
	}
	for _, tc := range cases {
		ids, errIDs := clientHelloExtensionIDs(readCapture(t, tc.name))
		if errIDs != nil {
			t.Fatalf("clientHelloExtensionIDs(%s): %v", tc.name, errIDs)
		}
		if got := containsExtension(ids, extRenegotiationInfo); got != tc.renegotiate {
			t.Fatalf("%s: renegotiation_info = %t, want %t (%v)", tc.name, got, tc.renegotiate, ids)
		}
		if got := containsExtension(ids, extEncryptThenMAC); got != tc.encryptMAC {
			t.Fatalf("%s: encrypt_then_mac = %t, want %t (%v)", tc.name, got, tc.encryptMAC, ids)
		}
	}
}

// The parser has to agree with what the reference captures actually contain, or
// a rejection below could be the parser failing rather than the rule working.
func TestClientHelloExtensionIDsMatchTheReferenceCaptures(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		want int
	}{
		{helps.CodexProfileHTTPFile, 11},
		{helps.CodexProfileWebSocketFile, 10},
	}
	for _, tc := range cases {
		ids, errIDs := clientHelloExtensionIDs(readCapture(t, tc.name))
		if errIDs != nil {
			t.Fatalf("clientHelloExtensionIDs(%s): %v", tc.name, errIDs)
		}
		if len(ids) != tc.want {
			t.Fatalf("%s: %d extensions, want %d (%v)", tc.name, len(ids), tc.want, ids)
		}
	}
}

// One marker without the other describes no Codex transport. Filing it under
// either would replace a working profile with a fingerprint no client sends.
func TestClassifyRejectsHandshakesThatAreNeitherTransport(t *testing.T) {
	t.Parallel()

	ambivalent := [][]uint16{
		{extSupportedVersions, extKeyShare, extRenegotiationInfo},
		{extSupportedVersions, extKeyShare, extEncryptThenMAC},
	}
	for _, extensions := range ambivalent {
		if kind, errClassify := classify(buildHello(extensions...)); errClassify == nil {
			t.Fatalf("classify(%v) = %s, want a rejection", extensions, kind)
		}
	}
}

// A stream that is not a TLS 1.3 client hello must be refused, not read as rustls
// on the strength of the markers it happens to lack.
func TestClassifyRejectsDegenerateHandshakes(t *testing.T) {
	t.Parallel()

	degenerate := [][]uint16{
		nil,
		{extSupportedVersions},
		{extKeyShare},
	}
	for _, extensions := range degenerate {
		if kind, errClassify := classify(buildHello(extensions...)); errClassify == nil {
			t.Fatalf("classify(%v) = %s, want a rejection", extensions, kind)
		}
	}
}

func TestClassifyRejectsTruncatedAndForeignRecords(t *testing.T) {
	t.Parallel()

	real := readCapture(t, helps.CodexProfileHTTPFile)
	rejected := [][]byte{
		real[:len(real)/2], // a record cut in half
		real[:4],           // shorter than a record header
		[]byte("not a TLS record at all"),
	}
	for i, record := range rejected {
		if kind, errClassify := classify(record); errClassify == nil {
			t.Fatalf("case %d: classify = %s, want a rejection", i, kind)
		}
	}
}

// buildHello assembles a ClientHello record offering exactly the given
// extensions, so the negative cases above do not depend on editing a real
// capture. Bodies are empty: only the IDs reach the classifier.
func buildHello(extensionIDs ...uint16) []byte {
	var extensions []byte
	for _, id := range extensionIDs {
		extensions = append(extensions, byte(id>>8), byte(id), 0, 0)
	}

	var body []byte
	body = append(body, 0x03, 0x03)          // legacy_version
	body = append(body, make([]byte, 32)...) // random
	body = append(body, 0)                   // session_id
	body = append(body, 0, 0)                // cipher_suites
	body = append(body, 1, 0)                // compression methods
	body = append(body, byte(len(extensions)>>8), byte(len(extensions)))
	body = append(body, extensions...)

	handshake := []byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	handshake = append(handshake, body...)

	record := []byte{22, 0x03, 0x01, byte(len(handshake) >> 8), byte(len(handshake))}
	return append(record, handshake...)
}

func containsExtension(ids []uint16, want uint16) bool {
	for _, id := range ids {
		if id == want {
			return true
		}
	}
	return false
}
