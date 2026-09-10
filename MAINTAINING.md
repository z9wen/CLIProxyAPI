# Maintaining this tree

This is a maintained fork of [router-for-me/CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI).
Upstream's README is mostly sponsors and feature marketing; this file records what is
different here, why, and how to keep it current. For everything not listed below, read
upstream's docs.

The fork exists to answer one question: **what does the upstream provider see when this
proxy sends a request?** Everything in the "outbound" section below came from reading
what the real client does and making the proxy match it. The inbound section came from
the fact that the proxy is meant to be reachable from the internet.

---

## 1. Outbound: matching the real Codex client

The real client used to be reproduced by guesswork. It no longer is: `tools/codexfp`
captures the actual client's TLS handshake and turns it into a uTLS spec, and
`internal/runtime/executor/helps/codex_tls_test.go` fails the build if the proxy stops
producing the captured bytes.

### What changed

| | Before | Now |
|---|---|---|
| HTTP/SSE TLS | `HelloChrome_Auto` (a browser!) | OpenSSL 3.6.3 profile, captured from the official Linux build |
| HTTP version | HTTP/2 | **HTTP/1.1** — the real client sends no ALPN |
| WebSocket TLS | Go's `crypto/tls` | rustls / aws-lc-rs profile, captured from the real client |
| Header order | Go's map order, i.e. random per request | pinned from a capture; all lowercase |
| `accept-encoding` | injected `gzip` | **not sent** — the real client sends none |
| `Connection` | `Keep-Alive` | **not sent** |
| `originator` | `codex-tui` | `codex_cli_rs` |
| User-Agent | stale hardcoded string | `codex_cli_rs/<version> (Ubuntu 26.4.0; x86_64) xterm-256color (codex-tui; <version>)` |
| `version` header | passed through or absent | always set, matching the User-Agent |
| session headers | `session_id` (underscore) | `session-id` / `thread-id`, hyphenated lowercase |
| `conversation_id` | sent | **not sent** — it is a body field, not a header |
| request body | plain JSON | **zstd level 3** + `content-encoding: zstd` |
| `x-codex-routing-hint` | absent | `model=<model>[;tier=<tier>]` |

Both TLS profiles were verified by replaying them through uTLS and diffing against the
capture: only the random, session id and key share differ.

### Keeping it converged

The advertised version **tracks upstream releases on its own** (`internal/registry/codex_version.go`,
polled daily). A forgotten manual bump therefore cannot leave the identity stale.

What does *not* track automatically is the TLS profile, and it cannot: it is a capture.
When the version advances past `registry.CodexProfileVersion`, the process logs a
one-time warning telling you to re-capture:

```
codex: upstream released 0.155.0 but the TLS profile was captured from 0.154.0;
re-capture with tools/codexfp (see tools/codexfp/README.md) ...
```

That warning is the whole point — it means you cannot forget either.

### Re-capturing after a Codex release

```bash
cd tools/codexfp && go build .
./codexfp -mode genca -out ~/capture          # for the -mode serve path
./codexfp -mode proxy -addr 127.0.0.1:8899 -out ~/capture
HTTPS_PROXY=http://127.0.0.1:8899 <real codex client>
./codexfp -mode analyze -out ~/capture        # emits <name>.spec.go
./codexfp -mode verify -in ~/capture/clienthello.bin -host chatgpt.com
```

`verify` replays the spec through uTLS and compares it with the capture field by field.
It must come back with zero unexplained differences before the spec is worth pasting in.

Then paste the spec into `helps/codex_tls.go`, copy the capture into
`helps/testdata/`, and update `registry.CodexProfileVersion`.

### Deliberately not done

- **WebSocket-first.** The real client uses the upstream WebSocket by default; this tree
  keeps upstream's behaviour of only doing so when the *downstream* request also arrived
  over a WebSocket. Turning WebSocket on is a client-side setting. The gap is benign: a
  real client whose WebSocket fails falls back to HTTP for the whole session anyway.
  Making it the default is not a one-line change — the WS executor's session key is only
  populated by the downstream WebSocket handler, so removing the gate without first
  deriving a session id for the HTTP path would give every request its own upstream
  WebSocket, which is *more* conspicuous, not less.

### Known remaining gaps

- The header **order** for the ChatGPT-auth path is partly inferred. The header **set**
  was confirmed from a live deployment; the order for the few headers only that path
  sends follows the source's insertion order rather than a capture.
- `x-codex-turn-metadata`, `x-codex-window-id`, `x-client-request-id` and friends are
  passed through from the downstream client, not synthesised. A real Codex CLI sends
  them; a plain `curl` does not. Fabricating them would be more suspicious, not less.

---

## 2. Inbound: not attracting scanners

Three things used to announce the software to anything that probed the port.

| | Before | Now |
|---|---|---|
| `GET /` | `{"message":"CLI Proxy API Server", ...}` | endpoint list only, no product name |
| `Access-Control-Expose-Headers` | named `X-CPA-VERSION`, `X-SERVER-VERSION`, … on every response | generic names only |
| Build headers on a 401 | sent *before* the key check | sent only after authentication |
| Control panel | served to anyone who could reach the port | follows `allow-remote-management` |

Plus `remote-management.panel-path`, so the panel does not sit at the path every
scanner's wordlist contains.

### Deployment config

```yaml
host: "0.0.0.0"
port: 8317

remote-management:
  # false: panel and API are loopback-only. true: both reachable remotely, key required.
  allow-remote: true
  secret-key: "<bcrypt hash preferred over plaintext>"
  panel-path: "console-<random>.html"   # default management.html

# Only when a reverse proxy sits in front. IPs or CIDRs.
trusted-proxies:
  - "172.16.0.0/12"     # e.g. the Docker bridge subnet
```

**`trusted-proxies` is not optional decoration.** gin trusts every peer by default, so
without this any client can send `X-Forwarded-For: 127.0.0.1` and be treated as a local
caller — which defeats `allow-remote`, unlocks the local-password path, and makes the
five-attempt ban useless because it is keyed by client IP. Verified on a live
deployment: with the default, a forged header from a remote host is ignored; with the
proxy's CIDR listed, that proxy's header is honoured.

Two rules go with it:

1. **List only the proxy.** Trusting a range you do not control re-opens the hole.
2. **The proxy must be the only route in.** If the proxy's upstream port is also
   published, a client can skip the proxy and forge the header directly, and nothing
   here can tell.

TLS is expected to terminate at the reverse proxy. If you expose this server directly,
set `tls.enable` — otherwise API keys and the management key cross the network in
cleartext.

---

## 3. Verifying a build

```bash
go build ./... && go test ./internal/... ./sdk/...
```

`internal/util`'s `TestInPlaceByteWritesAreReviewed` fails whenever a third-party
checkout (such as `sub2api/` or `codex-src/`) sits in the repository root, because it
walks the whole tree. That failure predates this fork's changes and is not a regression.

The fingerprint tests are worth running on their own after any dependency bump:

```bash
go test ./internal/runtime/executor/helps/ -run TestCodex -v
go test ./internal/config/ -run Panel -v
```

For an end-to-end check against the real upstream, `tools/codexfp -mode proxy -forward`
can be pointed at a test instance via its `proxy-url`, capturing what the proxy actually
puts on the wire while still splicing the connection through. That is how the captures
behind the table above were confirmed.

---

## 4. Rebasing on upstream

The changes are confined to:

- `internal/runtime/executor/helps/codex_tls.go` (new) — TLS profiles, transports
- `internal/runtime/executor/helps/codex_tls_test.go` (new) — the byte-level tests
- `internal/runtime/executor/helps/testdata/` (new) — the captures they compare against
- `internal/registry/codex_version.go` (new) — version tracking
- `internal/runtime/executor/codex_*.go` — identity headers, zstd, WebSocket dialer
- `internal/config/management_panel_path.go` (new), `config.go` — panel path, trusted proxies
- `internal/api/server*.go` — root response, CORS list, panel access, trusted proxies
- `tools/codexfp/` (new, its own Go module) — capture and verification tooling

Nothing under `internal/translator/`. When rebasing, the two files most likely to
conflict are `codex_executor_request.go` (upstream edits the same header code) and
`server_middleware.go`.
