#!/usr/bin/env bash
#
# Re-capture the Codex TLS profiles from a host that cannot run the capture
# itself — a Mac, say.
#
# internal/codexcapture reproduces the handshake by downloading and running the
# official Codex *Linux* build, so the in-process capture behind the management
# panel's refresh button refuses on anything but Linux. This does the same
# capture inside a throwaway Linux container: cross-compile the server, mount
# the profile directory, drive the endpoint, then remove the container.
#
# The profiles land directly in the mounted directory, so the running server
# picks them up on its next start. The script does not restart it: how the
# server is launched is the deployment's business, not this tool's.
#
#   tools/capture-codex-profile.sh [--profile-dir DIR] [--port PORT]
#
# --profile-dir defaults to $CODEX_PROFILE_PATH, then to ./codex-profile. The
# directory must already exist and hold captures; the script will not create
# one, so a typo cannot quietly write profiles where the server never reads.
#
# --port is the loopback port the container publishes on. It defaults to 18318
# because 18317 is commonly taken by a CPA manager process.

set -Eeuo pipefail

usage() {
  sed -n '2,20p' "$0" | sed 's/^# \{0,1\}//'
}

profile_dir=""
port=18318

while [ $# -gt 0 ]; do
  case "$1" in
    --profile-dir) profile_dir="${2:-}"; shift 2 ;;
    --port)        port="${2:-}"; shift 2 ;;
    -h|--help)     usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

repo_root="$(cd "$(dirname "$0")/.." && pwd)"
container="cpa-codex-capture"

for tool in docker go curl openssl; do
  command -v "$tool" >/dev/null 2>&1 || { echo "error: $tool is not on PATH" >&2; exit 1; }
done

if [ -z "$profile_dir" ]; then
  profile_dir="${CODEX_PROFILE_PATH:-./codex-profile}"
fi
profile_dir="$(cd "$profile_dir" 2>/dev/null && pwd)" || {
  echo "error: no such profile directory: ${CODEX_PROFILE_PATH:-./codex-profile}" >&2
  exit 1
}
if ! ls "$profile_dir"/codex-*.bin >/dev/null 2>&1; then
  echo "error: $profile_dir holds no codex-*.bin captures." >&2
  echo "       Point --profile-dir at the directory the server reads." >&2
  exit 1
fi

case "$(uname -m)" in
  arm64|aarch64) goarch=arm64 ;;
  x86_64|amd64)  goarch=amd64 ;;
  *) echo "error: unsupported host architecture: $(uname -m)" >&2; exit 1 ;;
esac

docker info >/dev/null 2>&1 || {
  echo "error: the Docker daemon is not reachable. Start Docker Desktop and retry." >&2
  exit 1
}

# The bundle mounted into the container as its trust store. macOS keeps it at
# /etc/ssl/cert.pem; the others are there for a non-Linux host that is not a Mac.
ca_bundle=""
for candidate in /etc/ssl/cert.pem /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/certs/ca-certificates.crt; do
  if [ -f "$candidate" ]; then ca_bundle="$candidate"; break; fi
done
if [ -z "$ca_bundle" ]; then
  echo "error: found no CA bundle to mount into the container" >&2
  exit 1
fi

tmp="$(mktemp -d "${TMPDIR:-/tmp}/cpa-capture.XXXXXX")"
api_key="$(openssl rand -hex 24)"

logs_pid=""
cleanup() {
  if [ -n "$logs_pid" ]; then kill "$logs_pid" >/dev/null 2>&1 || true; fi
  docker rm -f "$container" >/dev/null 2>&1 || true
  rm -rf "$tmp"
}
trap cleanup EXIT INT TERM

echo "profile directory: $profile_dir"
echo "building the server for linux/$goarch ..."
(
  cd "$repo_root"
  CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -o "$tmp/cli-proxy-api" ./cmd/server
)

# Throwaway, and kept out of the user's configuration entirely: the container
# exists to run one capture and is removed with it.
cat > "$tmp/config.yaml" <<EOF
host: "0.0.0.0"
port: 8317
remote-management:
  allow-remote: true
  secret-key: "$api_key"
  disable-control-panel: true
  disable-auto-update-panel: true
auth-dir: /capture/auths
debug: false
logging-to-file: false
plugins:
  enabled: false
EOF
mkdir -p "$tmp/auths"

docker rm -f "$container" >/dev/null 2>&1 || true
docker run -d --name "$container" \
  -p "127.0.0.1:$port:8317" \
  -v "$tmp:/capture" \
  -v "$profile_dir:/capture/codex-profile" \
  -v "$tmp/cli-proxy-api:/CLIProxyAPI/CLIProxyAPI" \
  -v "$ca_bundle:/certs/ca.pem:ro" \
  -e SSL_CERT_FILE=/certs/ca.pem \
  -e CODEX_PROFILE_PATH=/capture/codex-profile \
  -w /CLIProxyAPI \
  debian:bookworm \
  /CLIProxyAPI/CLIProxyAPI --config /capture/config.yaml >/dev/null

# The image carries no CA bundle, and installing one would mean reaching a
# distribution mirror this may not be able to reach. The host's bundle is
# mounted instead and Go reads it through SSL_CERT_FILE.
docker logs -f "$container" > "$tmp/container.log" 2>&1 &
logs_pid=$!
printed=0

show_progress() {
  local total
  total="$(wc -l < "$tmp/container.log" | tr -d ' ')"
  if [ "$total" -gt "$printed" ]; then
    tail -n "+$((printed + 1))" "$tmp/container.log" \
      | grep -E 'codexcapture:|codex profile capture:' || true
    printed="$total"
  fi
}

status_url="http://127.0.0.1:$port/v0/management/codex-profile"
status_get() { curl -fsS -m 10 -H "Authorization: Bearer $api_key" "$status_url"; }

echo "waiting for the container to serve ..."
ready=0
for _ in $(seq 1 60); do
  if status_get >/dev/null 2>&1; then ready=1; break; fi
  if ! docker inspect -f '{{.State.Running}}' "$container" 2>/dev/null | grep -q true; then
    echo "error: the container exited before it served" >&2
    cat "$tmp/container.log" >&2
    exit 1
  fi
  sleep 1
done
if [ "$ready" != 1 ]; then
  echo "error: the container never answered on $status_url" >&2
  cat "$tmp/container.log" >&2
  exit 1
fi

# The error field is read by parsing, not by matching. The text it carries holds a
# signed URL with quotes and escapes in it, and a "[^"]*" match stops at the first
# escaped quote — which is how an earlier version reported a truncated reason for a
# capture whose own status said it had failed, and then went on to report success.
capture_error() {
  local out=""
  if command -v python3 >/dev/null 2>&1; then
    out="$(printf '%s' "$1" \
      | python3 -c 'import json,sys; print(json.load(sys.stdin).get("capture",{}).get("error",""))' 2>/dev/null)" || out=""
  fi
  if [ -z "$out" ]; then
    out="$(printf '%s' "$1" | grep -o '"error":"[^"]*"')" || out=""
  fi
  printf '%s' "$out"
}

marker="$tmp/marker"
touch "$marker"

# The release assets come from a CDN that drops the connection often enough to be
# worth retrying, and a failure lands within seconds of the start.
attempt=1
max_attempts=3
capture_err=""
while : ; do
  echo "starting the capture (attempt $attempt of $max_attempts; it downloads the Codex release and runs it) ..."
  curl -fsS -m 15 -X POST -H "Authorization: Bearer $api_key" "$status_url/refresh" >/dev/null

  # A capture downloads ~112 MB and starts the client once per WebSocket sample, so
  # it runs for minutes; the bound is only here so a wedged container cannot leave
  # this waiting forever.
  status=""
  for _ in $(seq 1 240); do
    show_progress
    status="$(status_get || true)"
    case "$status" in
      *'"running":false'*) break ;;
    esac
    sleep 5
  done
  show_progress

  case "$status" in
    "") echo "error: the capture never reported a state" >&2; exit 1 ;;
    *'"running":true'*) echo "error: the capture is still running after 20 minutes" >&2; exit 1 ;;
  esac

  capture_err="$(capture_error "$status")"
  if [ -z "$capture_err" ]; then break; fi
  if [ "$attempt" -ge "$max_attempts" ]; then
    echo "capture failed after $attempt attempts: $capture_err" >&2
    exit 1
  fi
  echo "attempt $attempt failed: $capture_err" >&2
  echo "retrying ..." >&2
  attempt=$((attempt + 1))
  sleep 5
done

# A run that reports success but wrote nothing means the profile directory never
# reached the container: a bind mount that silently did not apply would otherwise
# look exactly like a good capture.
if [ ! "$profile_dir/codex-http-clienthello.bin" -nt "$marker" ]; then
  echo "error: the capture reported success but nothing in $profile_dir was written" >&2
  exit 1
fi

echo
echo "captured into $profile_dir:"
printf '%s' "$status" | grep -o '"profiles":\[[^]]*\]' || true
echo
echo "$status"
echo
echo "Restart the server so it loads the new captures."
