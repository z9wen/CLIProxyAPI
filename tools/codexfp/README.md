# codexfp

Captures the real Codex client's TLS fingerprint and turns it into a uTLS
`ClientHelloSpec`, so the proxy's upstream connections can be made to match the
client they are standing in for.

This is a development tool. It lives in its own Go module and is not part of the
server build.

## Why it works offline

The ClientHello is transmitted before any response arrives, so capturing it does
not require a working upstream account — or a reachable upstream at all. The
client is pointed at a local listener instead, and only the handshake is read.

The two reference captures in `testdata/` were taken this way:

| File | Target | Stack |
|---|---|---|
| `codex-linux-http.bin` | Official Linux musl build, run in a container | OpenSSL 3.6.3 (native-tls) |
| `codex-rustls-websocket.bin` | WebSocket handshake | rustls + aws-lc-rs |

The Linux build vendors its own OpenSSL, so one capture covers every Linux
distribution. rustls does not depend on the operating system at all, so the
WebSocket profile is the same on every platform.

## Modes

| Mode | Purpose |
|---|---|
| `proxy` | HTTP CONNECT proxy that dumps the tunnelled ClientHello. No CA, no sudo, no system changes. |
| `serve` | Terminates TLS and dumps the request that follows: HTTP/1.1 headers in wire order (with body framing), or HTTP/2 frames decoded from HPACK. Needs a trusted local CA. |
| `hello` | Reads a ClientHello from a bare TCP connection and emits the Go spec. |
| `analyze` | Re-derives reports and specs from ClientHello bytes already on disk. |
| `pcap` | Analyses a tcpdump capture of a real client; also reports QUIC. |
| `verify` | Replays a spec through uTLS and diffs the result against the reference. |
| `genca` | Generates a CA and a leaf certificate for `serve`. |

## Capturing a new reference

`-mode proxy` needs nothing installed. Point the client's `HTTPS_PROXY` at it:

```bash
go run . -mode proxy -addr 127.0.0.1:8899 -out ~/capture
HTTPS_PROXY=http://127.0.0.1:8899 <client command>
```

To capture the official Linux binary without a Linux host:

```bash
curl -sSLO https://github.com/openai/codex/releases/latest/download/codex-<arch>-unknown-linux-musl.tar.gz
docker run --rm -v "$PWD:/w" -w /w alpine:3.20 sh -c '
  mkdir -p /w/cap
  ./codexfp-linux -mode proxy -addr 127.0.0.1:8899 -out /w/cap &
  HTTPS_PROXY=http://127.0.0.1:8899 ./codex-<arch>-unknown-linux-musl exec "hi"
'
```

Set the provider's `base_url` to `https://chatgpt.com/backend-api/codex` in a
throwaway config so the SNI matches production. The request itself never leaves
the machine.

## Verifying a profile

A spec only proves itself when it reproduces the reference on the wire:

```bash
go run . -mode verify -in testdata/codex-linux-http.bin -host chatgpt.com
```

It replays the spec through uTLS against a local listener, then compares the
result with the reference field by field. The random, session id and key share
differ by design; everything else must match exactly.

`verify` compares structure, not raw bytes. For a byte-exact check, look at the
differing offsets between `X.bin` and `X.bin.replay.bin` and confirm every one
falls inside those three regions.

## Regenerating after a client upgrade

1. Re-capture with `-mode proxy`.
2. `go run . -mode analyze -out <dir>` to regenerate `<name>.spec.go`.
3. Paste the spec into the executor's profile file.
4. `-mode verify` against the new reference.

Read `originator`, `version` and the user agent out of the capture too — those
are emitted by the client and must stay consistent with the TLS profile.
