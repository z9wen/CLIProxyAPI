# Maintaining this tree

This is a maintained fork of [router-for-me/CLIProxyAPI](https://github.com/router-for-me/CLIProxyAPI).
Upstream's README is mostly sponsors and feature marketing; this file records what is
different here, why, and how to keep it current. For everything not listed below, read
upstream's docs.

The fork exists to answer one question: **what does the upstream provider see when this
proxy sends a request?** Everything in the "outbound" section below came from reading
what the real client does and making the proxy match it. The inbound section came from
the fact that the proxy is meant to be reachable from the internet.

**Scope: Codex only.** The Codex provider is the one in use, so it is where the
fingerprint work goes. Claude, Gemini, Antigravity, xAI and the rest are kept working
and otherwise left alone: their current behaviour is not a defect and they are not a
target for this kind of work. When changing shared code (`helps`, `registry`), confirm
the other providers' paths are untouched rather than refactoring them along the way.

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
A capture falls due when the client's **TLS stack** moves, not when a release lands —
releases are frequent and the stack moves rarely, so warning on every release would be
noise that gets ignored. The check therefore reads the release's `Cargo.lock` and
compares `openssl-sys` and `rustls` against the ones the live profiles came from
(`registry.CurrentCodexProfileBaseline`).

On a mismatch the proxy **holds the advertised version at the captured one** — claiming
a release whose handshake it does not reproduce is exactly the mismatch this all exists
to remove — and says so once per release:

```
codex: holding the advertised version at 0.154.0; 0.155.0 ships openssl-sys 0.9.112 /
rustls 0.23.40, but the profiles were captured from openssl-sys 0.9.111 / rustls 0.23.36.
Re-capture from the management panel's Codex profile notice, or with tools/codexfp ...
```

The same condition drives the management panel's notice, so it is visible where the
operator already looks rather than only in a log.

The baseline is **runtime state, persisted** as `codex-profile.json` beside the captures
(`internal/registry/codex_profile.go`). It has to persist: an install that captured, then
came back up on the compiled-in pins, would decide the release it just captured from had
drifted and hold itself back again. A successful capture moves the baseline with the
profiles, which is what clears the freeze.

### Re-capturing

**From the panel.** The stale-profile notice carries a *Re-capture now* button. It calls
`POST /v0/management/codex-profile/refresh` (management key, like the rest of that
group), which runs `internal/codexcapture` in the background:

1. resolve the host architecture (`aarch64` / `x86_64` — the releases are Linux only, so
   a capture needs a Linux host)
2. fetch the release's `SHA256SUMS`, download
   `codex-package-<arch>-unknown-linux-musl.tar.gz`, and verify it against them
3. extract `bin/codex`
4. run it against a local CONNECT listener under a throwaway `CODEX_HOME`, so the real
   binary produces the handshake while nothing leaves the machine and no credential is
   used
5. write the profiles, reload them, and record the new baseline

`GET /v0/management/codex-profile` reports the state, including whether a capture is
running and why the last one failed.

Two details worth keeping: the archive lands **beside the profile directory, not in
`/tmp`** — on the routers this runs on `/tmp` is tmpfs, so 112 MB there is 112 MB of
resident memory — and the run is repeated so that one refresh yields several WebSocket
orderings (see below).

**By hand, with `tools/codexfp`.** Still the path when there is no Linux host to hand,
and still what produces the reference captures under `helps/testdata/`:

```bash
cd tools/codexfp && go build .
./codexfp -mode proxy -addr 127.0.0.1:8899 -out ~/capture
HTTPS_PROXY=http://127.0.0.1:8899 <real codex client>
./codexfp -mode analyze -out ~/capture        # emits <name>.spec.go
./codexfp -mode verify -in ~/capture/clienthello.bin -host chatgpt.com
```

`verify` replays the spec through uTLS and compares it with the capture field by field.
It must come back with zero unexplained differences before the spec is worth pasting in.

### WebSocket: the extension order is not stable

The two transports are not symmetric, and the difference is easy to miss.

The HTTP/SSE path runs **OpenSSL**, which orders its extensions deterministically — three
captures of the real client agreed byte for byte — so one capture describes it completely.

The WebSocket path runs **rustls**, which since its "Randomize ClientHello extensions"
change reorders the extensions that carry no ordering requirement on *every connection*,
so the JA3/JA4 a server computes differs each time. Replaying a single fixed order
therefore gives every handshake the same JA3 while a genuine client's changes — a
constant where the real article has a spread, which is its own signal.

This tree keeps **several** real captures (`codex-websocket-clienthello*.bin`) and picks
one at random per handshake, so every order sent is one the client actually emitted and
nothing is synthesised. A single capture is still honoured as the old behaviour.

Reproducing rustls's ordering algorithm instead was tried and abandoned: it means
carrying a copy of rustls's hash into this tree, it only pays off if the server goes as
far as checking that a permutation is one rustls could emit, and uTLS applies extension
side effects in list order — so arbitrary permutations are not free to apply.

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

One test reaches the real server and is therefore opt-in. It is the only one that shows a
changed ClientHello is still *accepted*: the capture tests read a handshake off a local
listener and never finish a TLS exchange.

```bash
CODEX_TLS_LIVE_HOST=chatgpt.com go test ./internal/runtime/executor/helps/ \
    -run TestLiveCodexWebsocketHandshakeIsAccepted -v
```

The server closes a small share of handshakes (~1 in 40) **with the profile unchanged**,
measured on both the shipped profile and a reordered one, so treat an occasional refusal
as the environment rather than as a regression.

For an end-to-end check against the real upstream, `tools/codexfp -mode proxy -forward`
can be pointed at a test instance via its `proxy-url`, capturing what the proxy actually
puts on the wire while still splicing the connection through. That is how the captures
behind the table above were confirmed.

---

## 4. Rebasing on upstream

The changes are confined to:

- `internal/runtime/executor/helps/codex_tls.go` (new) — TLS profiles, transports
- `internal/runtime/executor/helps/codex_tls_test.go` (new) — the byte-level tests
- `internal/runtime/executor/helps/codex_profile_store.go` (new) — loads captures from
  disk, and picks one WebSocket ordering per handshake
- `internal/runtime/executor/helps/codex_ws_samples_test.go` (new) — the ordering tests
- `internal/runtime/executor/helps/testdata/` (new) — the captures they compare against
- `internal/registry/codex_version.go` (new) — version tracking, TLS-stack drift check
- `internal/registry/codex_profile.go` (new) — the profile baseline and its persistence
- `internal/codexcapture/` (new) — in-process capture: download, verify, run, collect
- `internal/api/handlers/management/codex_profile.go` (new) — the refresh endpoints
- `internal/runtime/executor/codex_*.go` — identity headers, zstd, WebSocket dialer
- `internal/config/management_panel_path.go` (new), `config.go` — panel path, trusted proxies
- `internal/api/server*.go` — root response, CORS list, panel access, trusted proxies,
  and the stale-profile notice plus its re-capture button
- `cmd/server/main.go` — points the loader at the profile directory at startup
- `tools/codexfp/` (new, its own Go module) — capture and verification tooling

Nothing under `internal/translator/`. When rebasing, the two files most likely to
conflict are `codex_executor_request.go` (upstream edits the same header code) and
`server_middleware.go`.
