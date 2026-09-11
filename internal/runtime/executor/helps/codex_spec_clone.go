package helps

import (
	tls "github.com/refraction-networking/utls"
)

// cloneClientHelloSpec returns a spec that can be handed to uTLS without the
// caller's copy being changed by it.
//
// ApplyPreset does not treat the spec as read-only: while walking the
// extensions it fills in what it can only know per connection. A key share with
// no data gets one generated and written back into the spec, GREASE placeholders
// are replaced, and padding is recomputed — all into the objects it was given.
//
// For the built-in profiles that costs nothing, because each call builds a fresh
// literal. A captured profile is cached and shared by every connection, so
// without this the first handshake would prime it and the rest would reuse that
// first connection's key material: uTLS skips generating a share whose data is
// already populated, so a replayed share is sent verbatim, and the post-quantum
// half is left with no private key at all — which is a handshake that fails
// outright the moment the server selects that group.
func cloneClientHelloSpec(spec *tls.ClientHelloSpec) *tls.ClientHelloSpec {
	if spec == nil {
		return nil
	}
	cloned := *spec
	cloned.Extensions = make([]tls.TLSExtension, 0, len(spec.Extensions))
	for _, ext := range spec.Extensions {
		cloned.Extensions = append(cloned.Extensions, cloneExtension(ext))
	}
	return &cloned
}

// cloneExtension copies the extension types uTLS writes to during ApplyPreset.
//
// The rest are shared by pointer, which is safe because uTLS only reads them,
// and the sort order the caller sees is preserved either way.
func cloneExtension(ext tls.TLSExtension) tls.TLSExtension {
	switch typed := ext.(type) {
	case *tls.KeyShareExtension:
		// ApplyPreset fills in each share's key material here.
		shares := make([]tls.KeyShare, len(typed.KeyShares))
		copy(shares, typed.KeyShares)
		cloned := *typed
		cloned.KeyShares = shares
		return &cloned

	case *tls.SupportedCurvesExtension:
		// GREASE placeholders are replaced in place.
		curves := make([]tls.CurveID, len(typed.Curves))
		copy(curves, typed.Curves)
		cloned := *typed
		cloned.Curves = curves
		return &cloned

	case *tls.UtlsGREASEExtension:
		cloned := *typed
		return &cloned

	case *tls.UtlsPaddingExtension:
		cloned := *typed
		return &cloned

	default:
		return ext
	}
}
