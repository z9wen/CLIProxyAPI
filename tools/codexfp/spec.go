package main

import (
	"fmt"
	"io"
	"sort"
	"strings"

	tls "github.com/refraction-networking/utls"
)

// emitSpec writes a *tls.ClientHelloSpec literal that can be pasted straight
// into the proxy's uTLS profile file. Symbolic names are preferred where the
// constant is exported, otherwise the raw number is emitted with a comment.
func emitSpec(w io.Writer, spec *tls.ClientHelloSpec, funcName string) {
	fmt.Fprintf(w, "func %s() *tls.ClientHelloSpec {\n", funcName)
	fmt.Fprintf(w, "\treturn &tls.ClientHelloSpec{\n")
	fmt.Fprintf(w, "\t\tCipherSuites: []uint16{\n")
	for _, cs := range spec.CipherSuites {
		fmt.Fprintf(w, "\t\t\t%s,\n", cipherSuiteName(cs))
	}
	fmt.Fprintf(w, "\t\t},\n")
	fmt.Fprintf(w, "\t\tCompressionMethods: []uint8{%s},\n", joinUint8(spec.CompressionMethods))
	fmt.Fprintf(w, "\t\tExtensions: []tls.TLSExtension{\n")
	for _, ext := range spec.Extensions {
		fmt.Fprintf(w, "\t\t\t%s,\n", extensionLiteral(ext))
	}
	fmt.Fprintf(w, "\t\t},\n")
	fmt.Fprintf(w, "\t}\n}\n")
}

func extensionLiteral(ext tls.TLSExtension) string {
	switch e := ext.(type) {
	case *tls.SNIExtension:
		return fmt.Sprintf("&tls.SNIExtension{ServerName: %q}", e.ServerName)
	case *tls.ExtendedMasterSecretExtension:
		return "&tls.ExtendedMasterSecretExtension{}"
	case *tls.RenegotiationInfoExtension:
		return fmt.Sprintf("&tls.RenegotiationInfoExtension{Renegotiation: %s}", renegotiationName(e.Renegotiation))
	case *tls.SupportedCurvesExtension:
		return fmt.Sprintf("&tls.SupportedCurvesExtension{Curves: []tls.CurveID{%s}}", joinCurves(e.Curves))
	case *tls.SupportedPointsExtension:
		return fmt.Sprintf("&tls.SupportedPointsExtension{SupportedPoints: []byte{%s}}", joinUint8(e.SupportedPoints))
	case *tls.SessionTicketExtension:
		return "&tls.SessionTicketExtension{}"
	case *tls.ALPNExtension:
		return fmt.Sprintf("&tls.ALPNExtension{AlpnProtocols: []string{%s}}", joinQuoted(e.AlpnProtocols))
	case *tls.NPNExtension:
		return fmt.Sprintf("&tls.NPNExtension{NextProtos: []string{%s}}", joinQuoted(e.NextProtos))
	case *tls.StatusRequestExtension:
		return "&tls.StatusRequestExtension{}"
	case *tls.StatusRequestV2Extension:
		return "&tls.StatusRequestV2Extension{}"
	case *tls.SCTExtension:
		return "&tls.SCTExtension{}"
	case *tls.SignatureAlgorithmsExtension:
		return fmt.Sprintf("&tls.SignatureAlgorithmsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{%s}}",
			joinSigSchemes(e.SupportedSignatureAlgorithms))
	case *tls.SignatureAlgorithmsCertExtension:
		return fmt.Sprintf("&tls.SignatureAlgorithmsCertExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{%s}}",
			joinSigSchemes(e.SupportedSignatureAlgorithms))
	case *tls.KeyShareExtension:
		return fmt.Sprintf("&tls.KeyShareExtension{KeyShares: []tls.KeyShare{%s}}", joinKeyShares(e.KeyShares))
	case *tls.PSKKeyExchangeModesExtension:
		return fmt.Sprintf("&tls.PSKKeyExchangeModesExtension{Modes: []uint8{%s}}", joinUint8(e.Modes))
	case *tls.SupportedVersionsExtension:
		return fmt.Sprintf("&tls.SupportedVersionsExtension{Versions: []uint16{%s}}", joinVersions(e.Versions))
	case *tls.UtlsPaddingExtension:
		return "&tls.UtlsPaddingExtension{GetPaddingLen: tls.BoringPaddingStyle}"
	case *tls.UtlsPreSharedKeyExtension:
		return "&tls.UtlsPreSharedKeyExtension{}"
	case *tls.FakePreSharedKeyExtension:
		return "&tls.FakePreSharedKeyExtension{}"
	case *tls.UtlsGREASEExtension:
		return "&tls.UtlsGREASEExtension{}"
	case *tls.UtlsCompressCertExtension:
		return fmt.Sprintf("&tls.UtlsCompressCertExtension{Algorithms: []tls.CertCompressionAlgo{%s}}",
			joinCertCompression(e.Algorithms))
	case *tls.CookieExtension:
		return fmt.Sprintf("&tls.CookieExtension{Cookie: []byte{%s}}", joinUint8(e.Cookie))
	case *tls.ApplicationSettingsExtension:
		return fmt.Sprintf("&tls.ApplicationSettingsExtension{SupportedProtocols: []string{%s}}", joinQuoted(e.SupportedProtocols))
	case *tls.FakeChannelIDExtension:
		return "&tls.FakeChannelIDExtension{}"
	case *tls.FakeRecordSizeLimitExtension:
		return fmt.Sprintf("&tls.FakeRecordSizeLimitExtension{Limit: %d}", e.Limit)
	case *tls.FakeTokenBindingExtension:
		return fmt.Sprintf("&tls.FakeTokenBindingExtension{MajorVersion: %d, MinorVersion: %d, KeyParameters: []uint8{%s}}",
			e.MajorVersion, e.MinorVersion, joinUint8(e.KeyParameters))
	case *tls.FakeDelegatedCredentialsExtension:
		return fmt.Sprintf("&tls.FakeDelegatedCredentialsExtension{SupportedSignatureAlgorithms: []tls.SignatureScheme{%s}}",
			joinSigSchemes(e.SupportedSignatureAlgorithms))
	case *tls.GenericExtension:
		// uTLS has no native type for this extension; carry the body verbatim.
		// A nil literal here would panic the handshake, so always emit a real one.
		return fmt.Sprintf("&tls.GenericExtension{Id: 0x%04x, Data: []byte{%s}}", e.Id, joinUint8(e.Data))
	default:
		return fmt.Sprintf("/* UNSUPPORTED EXTENSION %T: re-encode as a GenericExtension by hand */ &tls.GenericExtension{Id: 0xffff}", ext)
	}
}

func joinKeyShares(ks []tls.KeyShare) string {
	parts := make([]string, 0, len(ks))
	for _, k := range ks {
		parts = append(parts, fmt.Sprintf("{Group: %s}", curveName(k.Group)))
	}
	return strings.Join(parts, ", ")
}

func joinCurves(cs []tls.CurveID) string {
	parts := make([]string, 0, len(cs))
	for _, c := range cs {
		parts = append(parts, curveName(c))
	}
	return strings.Join(parts, ", ")
}

func joinSigSchemes(ss []tls.SignatureScheme) string {
	parts := make([]string, 0, len(ss))
	for _, s := range ss {
		parts = append(parts, sigSchemeName(s))
	}
	return strings.Join(parts, ", ")
}

func joinCertCompression(as []tls.CertCompressionAlgo) string {
	parts := make([]string, 0, len(as))
	for _, a := range as {
		parts = append(parts, fmt.Sprintf("tls.CertCompressionAlgo(%d)", a))
	}
	return strings.Join(parts, ", ")
}

func joinUint8(v []uint8) string {
	parts := make([]string, 0, len(v))
	for _, x := range v {
		parts = append(parts, fmt.Sprint(x))
	}
	return strings.Join(parts, ", ")
}

func joinQuoted(v []string) string {
	parts := make([]string, 0, len(v))
	for _, s := range v {
		parts = append(parts, fmt.Sprintf("%q", s))
	}
	return strings.Join(parts, ", ")
}

func joinVersions(v []uint16) string {
	parts := make([]string, 0, len(v))
	for _, x := range v {
		switch x {
		case tls.VersionTLS10:
			parts = append(parts, "tls.VersionTLS10")
		case tls.VersionTLS11:
			parts = append(parts, "tls.VersionTLS11")
		case tls.VersionTLS12:
			parts = append(parts, "tls.VersionTLS12")
		case tls.VersionTLS13:
			parts = append(parts, "tls.VersionTLS13")
		case tls.GREASE_PLACEHOLDER:
			parts = append(parts, "tls.GREASE_PLACEHOLDER")
		default:
			parts = append(parts, fmt.Sprintf("0x%04x", x))
		}
	}
	return strings.Join(parts, ", ")
}

func curveName(c tls.CurveID) string {
	switch c {
	case tls.X25519:
		return "tls.X25519"
	case tls.X25519MLKEM768:
		return "tls.X25519MLKEM768"
	case tls.CurveP256:
		return "tls.CurveP256"
	case tls.CurveP384:
		return "tls.CurveP384"
	case tls.CurveP521:
		return "tls.CurveP521"
	case tls.X25519Kyber768Draft00:
		return "tls.X25519Kyber768Draft00"
	case tls.GREASE_PLACEHOLDER:
		return "tls.GREASE_PLACEHOLDER"
	default:
		return fmt.Sprintf("tls.CurveID(0x%04x)", uint16(c))
	}
}

func sigSchemeName(s tls.SignatureScheme) string {
	switch s {
	case tls.PKCS1WithSHA256:
		return "tls.PKCS1WithSHA256"
	case tls.PKCS1WithSHA384:
		return "tls.PKCS1WithSHA384"
	case tls.PKCS1WithSHA512:
		return "tls.PKCS1WithSHA512"
	case tls.PKCS1WithSHA1:
		return "tls.PKCS1WithSHA1"
	case tls.PSSWithSHA256:
		return "tls.PSSWithSHA256"
	case tls.PSSWithSHA384:
		return "tls.PSSWithSHA384"
	case tls.PSSWithSHA512:
		return "tls.PSSWithSHA512"
	case tls.ECDSAWithP256AndSHA256:
		return "tls.ECDSAWithP256AndSHA256"
	case tls.ECDSAWithP384AndSHA384:
		return "tls.ECDSAWithP384AndSHA384"
	case tls.ECDSAWithP521AndSHA512:
		return "tls.ECDSAWithP521AndSHA512"
	case tls.ECDSAWithSHA1:
		return "tls.ECDSAWithSHA1"
	case tls.Ed25519:
		return "tls.Ed25519"
	default:
		return fmt.Sprintf("tls.SignatureScheme(0x%04x)", uint16(s))
	}
}

func renegotiationName(r tls.RenegotiationSupport) string {
	switch r {
	case tls.RenegotiateNever:
		return "tls.RenegotiateNever"
	case tls.RenegotiateOnceAsClient:
		return "tls.RenegotiateOnceAsClient"
	case tls.RenegotiateFreelyAsClient:
		return "tls.RenegotiateFreelyAsClient"
	default:
		return fmt.Sprintf("tls.RenegotiationSupport(%d)", r)
	}
}

var cipherSuiteNames = func() map[uint16]string {
	m := map[uint16]string{}
	for _, cs := range tls.CipherSuites() {
		m[cs.ID] = cs.Name
	}
	for _, cs := range tls.InsecureCipherSuites() {
		m[cs.ID] = cs.Name
	}
	return m
}()

func cipherSuiteName(id uint16) string {
	if name, ok := cipherSuiteNames[id]; ok {
		return "tls." + name
	}
	return fmt.Sprintf("0x%04x", id)
}

// extensionName is the IANA name, used only for the human-readable summary.
func extensionName(id uint16) string {
	name, ok := extensionNames[id]
	if !ok {
		return fmt.Sprintf("unknown(0x%04x)", id)
	}
	return name
}

var extensionNames = map[uint16]string{
	0:     "server_name",
	1:     "max_fragment_length",
	5:     "status_request",
	10:    "supported_groups",
	11:    "ec_point_formats",
	13:    "signature_algorithms",
	14:    "use_srtp",
	16:    "application_layer_protocol_negotiation",
	17:    "status_request_v2",
	18:    "signed_certificate_timestamp",
	21:    "padding",
	22:    "encrypt_then_mac",
	23:    "extended_master_secret",
	24:    "token_binding",
	27:    "compress_certificate",
	28:    "record_size_limit",
	35:    "session_ticket",
	41:    "pre_shared_key",
	42:    "early_data",
	43:    "supported_versions",
	44:    "cookie",
	45:    "psk_key_exchange_modes",
	49:    "post_handshake_auth",
	50:    "signature_algorithms_cert",
	51:    "key_share",
	57:    "quic_transport_parameters",
	13172: "next_protocol_negotiation",
	17513: "application_settings",
	30031: "channel_id",
	30032: "channel_id_old",
	65281: "renegotiation_info",
}

func extensionID(ext tls.TLSExtension) uint16 {
	// Every uTLS extension type reports its length; only GenericExtension and
	// UtlsGREASEExtension carry an explicit ID. Derive the rest from the known
	// type set.
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
	case *tls.ALPNExtension:
		return 16
	case *tls.StatusRequestV2Extension:
		return 17
	case *tls.SCTExtension:
		return 18
	case *tls.UtlsPaddingExtension:
		return 21
	case *tls.ExtendedMasterSecretExtension:
		return 23
	case *tls.FakeTokenBindingExtension:
		return 24
	case *tls.UtlsCompressCertExtension:
		return 27
	case *tls.FakeRecordSizeLimitExtension:
		return 28
	case *tls.SessionTicketExtension:
		return 35
	case *tls.UtlsPreSharedKeyExtension, *tls.FakePreSharedKeyExtension:
		return 41
	case *tls.SupportedVersionsExtension:
		return 43
	case *tls.CookieExtension:
		return 44
	case *tls.PSKKeyExchangeModesExtension:
		return 45
	case *tls.SignatureAlgorithmsCertExtension:
		return 50
	case *tls.KeyShareExtension:
		return 51
	case *tls.QUICTransportParametersExtension:
		return 57
	case *tls.NPNExtension:
		return 13172
	case *tls.ApplicationSettingsExtension:
		return 17513
	case *tls.FakeChannelIDExtension:
		return 30031
	case *tls.RenegotiationInfoExtension:
		return 65281
	default:
		return 0
	}
}

// sortedExtIDs is a small helper for deterministic summary output.
func sortedExtIDs(ids []uint16) []uint16 {
	out := append([]uint16(nil), ids...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
