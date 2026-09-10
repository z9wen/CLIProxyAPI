package helps

import (
	"net/http"
	"strings"
)

// codexClientResponseHeaders names upstream headers beyond the quota family that
// the Codex client reads in order to adjust its own behaviour, not merely to
// display something:
//
//   - x-codex-turn-state carries backend affinity the client replays for the
//     rest of the turn.
//   - x-reasoning-included tells the client whether reasoning is already part of
//     the context it was sent, which feeds its context-window estimate and so
//     when it auto-compacts.
//   - openai-model is the model the backend actually served; the client warns on
//     a mismatch.
//   - the safety-buffering pair drives whether the client may offer a retry.
//
// The quota family (rate limits, credits, active limit, plan type) is covered by
// isCodexQuotaHeaderName and does not need repeating here.
//
// x-models-etag is deliberately absent. It is an invalidation hint for the model
// list: forwarding the upstream's value while this proxy serves its own catalog
// would invite the client to refetch on every turn.
var codexClientResponseHeaders = map[string]struct{}{
	"x-codex-turn-state":                    {},
	"x-reasoning-included":                  {},
	"openai-model":                          {},
	"x-codex-safety-buffering-enabled":      {},
	"x-codex-safety-buffering-faster-model": {},
	"x-codex-promo-message":                 {},
	"x-codex-rate-limit-reached-type":       {},
}

// CodexResponseHeadersForClient extracts the upstream headers a Codex client
// needs to see. It returns nil when there is nothing worth forwarding.
//
// These are forwarded regardless of the passthrough-headers setting. That
// setting decides whether this proxy exposes the upstream verbatim; these
// headers are different in kind, because losing them silently changes what the
// client does — it over-counts its context and compacts early, loses the
// rate-limit reset time, and cannot offer a safety-buffering retry.
func CodexResponseHeadersForClient(headers http.Header) http.Header {
	if len(headers) == 0 {
		return nil
	}
	out := make(http.Header)
	for key, values := range headers {
		lower := strings.ToLower(strings.TrimSpace(key))
		if _, ok := codexClientResponseHeaders[lower]; !ok && !isCodexQuotaHeaderName(lower) {
			continue
		}
		out[http.CanonicalHeaderKey(key)] = append([]string(nil), values...)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
