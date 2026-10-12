#!/usr/bin/env bash
# Exercise adaptive Shroud 3 packet flow through real Linux TUN devices in
# nested isolated network namespaces. No host routes, DNS, or firewall change.
set -euo pipefail

SCRIPT_PATH="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [[ "${1:-}" != "--inside" ]]; then
  if [[ "$(uname -s)" != "Linux" ]]; then
    printf 'SKIP,shroud3_tun_namespace,requires Linux\n'
    exit 0
  fi
  for tool in unshare ip mount python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
      printf 'SKIP,shroud3_tun_namespace,requires %s\n' "$tool"
      exit 0
    fi
  done
  if [[ ! -e /dev/net/tun ]]; then
    printf 'SKIP,shroud3_tun_namespace,/dev/net/tun is unavailable\n'
    exit 0
  fi
  if ! unshare --user --map-root-user --net --mount --propagation private -- \
      sh -c 'mount --make-rprivate / && mount -t tmpfs tmpfs /run && mkdir -p /run/netns && ip netns add shph-preflight && ip netns del shph-preflight' \
      >/dev/null 2>&1; then
    printf 'SKIP,shroud3_tun_namespace,host denied isolated namespace or nested network namespace capability\n'
    exit 0
  fi
  exec unshare --user --map-root-user --net --mount --propagation private -- "$SCRIPT_PATH" --inside
fi

cd "$ROOT"
if [[ -f "$HOME/.cargo/env" ]]; then
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
fi

if [[ ! -e /dev/net/tun ]] || ! command -v ip >/dev/null 2>&1 || ! command -v mount >/dev/null 2>&1; then
  printf 'SKIP,shroud3_tun_namespace,TUN device or namespace tools unavailable inside namespace\n'
  exit 0
fi
mount --make-rprivate /
mount -t tmpfs tmpfs /run
mkdir -p /run/netns
ip netns add shph-srv
ip netns add shph-cli
ip link add shph-vs type veth peer name shph-vc
ip link set shph-vs netns shph-srv
ip link set shph-vc netns shph-cli
ip -n shph-srv link set dev lo up
ip -n shph-cli link set dev lo up
ip -n shph-srv address add 192.0.2.1/30 dev shph-vs
ip -n shph-cli address add 192.0.2.2/30 dev shph-vc
ip -n shph-srv link set dev shph-vs up
ip -n shph-cli link set dev shph-vc up

if ! cargo build -p shph-cli --release --locked --offline >/dev/null; then
  printf 'FAIL,shroud3_tun_namespace,locked offline SHPH release build failed\n' >&2
  exit 1
fi

BIN="$ROOT/target/release/shph"
if [[ ! -x "$BIN" ]]; then
  printf 'FAIL,shroud3_tun_namespace,release binary missing: %s\n' "$BIN" >&2
  exit 1
fi

TMP_DIR="$(mktemp -d)"
SERVER_PID=""
CLIENT_PID=""
ECHO_PID=""
cleanup() {
  local exit_status=$?
  set +e
  if [[ "$exit_status" -ne 0 ]]; then
    printf 'FAIL,shroud3_tun_namespace,probe exited with status %s\n' "$exit_status" >&2
    for log_path in "$TMP_DIR/server.log" "$TMP_DIR/client.log" "$TMP_DIR/echo.log"; do
      if [[ -f "$log_path" ]]; then
        printf '%s\n' "--- $log_path ---" >&2
        cat "$log_path" >&2
      fi
    done
  fi
  for pid in "$CLIENT_PID" "$SERVER_PID" "$ECHO_PID"; do
    if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
      kill -TERM "$pid" 2>/dev/null
    fi
  done
  for pid in "$CLIENT_PID" "$SERVER_PID" "$ECHO_PID"; do
    if [[ -n "$pid" ]]; then
      wait "$pid" 2>/dev/null
    fi
  done
  ip netns del shph-cli 2>/dev/null
  ip netns del shph-srv 2>/dev/null
  rm -rf "$TMP_DIR"
}
trap cleanup EXIT INT TERM

SERVER_DIR="$TMP_DIR/server"
CLIENT_DIR="$TMP_DIR/client"
mkdir -p "$SERVER_DIR" "$CLIENT_DIR"
SERVER_CONFIG="$SERVER_DIR/config.toml"
CLIENT_CONFIG="$CLIENT_DIR/config.toml"
CERT="$SERVER_DIR/server.der"
KEY="$SERVER_DIR/server.key"

"$BIN" --config "$SERVER_CONFIG" init --new >/dev/null
"$BIN" --config "$CLIENT_CONFIG" init --new >/dev/null
sed -i 's/^interface_name = .*/interface_name = "s3srv0"/' "$SERVER_CONFIG"
sed -i 's/^interface_name = .*/interface_name = "s3cli0"/' "$CLIENT_CONFIG"

PORT="$(python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
SERVER_ID="$("$BIN" --config "$SERVER_CONFIG" show-public-key)"
SERVER_SIGN_ID="$("$BIN" --config "$SERVER_CONFIG" show-signing-public-key)"
CLIENT_ID="$("$BIN" --config "$CLIENT_CONFIG" show-public-key)"
CLIENT_SIGN_ID="$("$BIN" --config "$CLIENT_CONFIG" show-signing-public-key)"
"$BIN" --config "$SERVER_CONFIG" add-peer client 192.0.2.1 "$PORT" "$CLIENT_ID" --sign-pubkey "$CLIENT_SIGN_ID" >/dev/null
"$BIN" --config "$CLIENT_CONFIG" add-peer server 192.0.2.1 "$PORT" "$SERVER_ID" --sign-pubkey "$SERVER_SIGN_ID" >/dev/null

cat >>"$SERVER_CONFIG" <<TOML

[session]
role = "listen"
bind = "192.0.2.1:$PORT"
timeout_secs = 5
shroud3_adaptive = true
quic_cert = "$CERT"
quic_key = "$KEY"

[control_plane]
apply_interface_address = true
interface_cidr = "10.88.0.1/32"
apply_routes = true
route_cidrs = ["10.88.0.2/32"]
dry_run = false
TOML

cat >>"$CLIENT_CONFIG" <<TOML

[session]
role = "connect"
peer = "192.0.2.1:$PORT"
transport_peer = "192.0.2.1:$PORT"
timeout_secs = 5
shroud3_adaptive = true
quic_cert = "$CERT"

[control_plane]
apply_interface_address = true
interface_cidr = "10.88.0.2/32"
apply_routes = true
route_cidrs = ["10.88.0.1/32"]
dry_run = false
TOML

ip netns exec shph-srv env SHPH_TUN_NATIVE=1 "$BIN" --config "$SERVER_CONFIG" up --transport quic-standard --shroud3-adaptive --quic-cert "$CERT" --quic-key "$KEY" >"$TMP_DIR/server.log" 2>&1 &
SERVER_PID=$!

wait_for_server() {
  for ((attempt = 0; attempt < 200; attempt++)); do
    if [[ -e "$CERT" ]] && ip -n shph-srv link show dev s3srv0 >/dev/null 2>&1; then
      return 0
    fi
    if ! kill -0 "$SERVER_PID" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
  cat "$TMP_DIR/server.log" >&2
  return 1
}

wait_for_log() {
  local log_path="$1"
  local pattern="$2"
  local pid="$3"
  for ((attempt = 0; attempt < 200; attempt++)); do
    if grep -Fq "$pattern" "$log_path"; then
      return 0
    fi
    if ! kill -0 "$pid" 2>/dev/null; then
      break
    fi
    sleep 0.1
  done
  cat "$log_path" >&2
  return 1
}

wait_for_server
ip netns exec shph-cli env SHPH_TUN_NATIVE=1 "$BIN" --config "$CLIENT_CONFIG" up --transport quic-standard --shroud3-adaptive --quic-cert "$CERT" >"$TMP_DIR/client.log" 2>&1 &
CLIENT_PID=$!
wait_for_log "$TMP_DIR/client.log" "SHPH handshake connect-loop ok" "$CLIENT_PID"
wait_for_log "$TMP_DIR/server.log" "SHPH handshake listen-loop ok" "$SERVER_PID"

ip -n shph-srv -4 addr show dev s3srv0 | grep -Fq '10.88.0.1/32'
ip -n shph-cli -4 addr show dev s3cli0 | grep -Fq '10.88.0.2/32'
ip -n shph-cli route get 10.88.0.1 | grep -Fq 'dev s3cli0'

UDP_PORT="$(ip netns exec shph-srv python3 -c 'import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.bind(("10.88.0.1", 0)); print(s.getsockname()[1]); s.close()')"
ip netns exec shph-srv python3 -u - "$UDP_PORT" >"$TMP_DIR/echo.log" 2>&1 <<'PY' &
import socket
import sys

port = int(sys.argv[1])
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind(("10.88.0.1", port))
sock.settimeout(10)
print("LISTEN", flush=True)
data, address = sock.recvfrom(4096)
if data != b"shroud3-tun-roundtrip-v1":
    raise SystemExit("unexpected payload")
sock.sendto(data, address)
print("ECHO PASS", flush=True)
PY
ECHO_PID=$!

for ((attempt = 0; attempt < 100; attempt++)); do
  if grep -Fq LISTEN "$TMP_DIR/echo.log"; then
    break
  fi
  if ! kill -0 "$ECHO_PID" 2>/dev/null; then
    cat "$TMP_DIR/echo.log" >&2
    exit 1
  fi
  sleep 0.05
done
grep -Fq LISTEN "$TMP_DIR/echo.log"

ip netns exec shph-cli python3 - "10.88.0.2" "10.88.0.1" "$UDP_PORT" <<'PY'
import socket
import sys

source, destination, port = sys.argv[1], sys.argv[2], int(sys.argv[3])
payload = b"shroud3-tun-roundtrip-v1"
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((source, 0))
sock.settimeout(8)
sock.sendto(payload, (destination, port))
response, address = sock.recvfrom(4096)
if response != payload or address[0] != destination:
    raise SystemExit("Shroud 3 TUN payload round trip mismatch")
print("PASS,shroud3_tun_namespace,authenticated adaptive Shroud 3 TUN UDP round trip")
PY

wait "$ECHO_PID"
grep -Fq 'ECHO PASS' "$TMP_DIR/echo.log"

stop_cleanly() {
  local pid="$1"
  local log_path="$2"
  kill -TERM "$pid"
  if ! wait "$pid"; then
    cat "$log_path" >&2
    printf 'FAIL,shroud3_tun_namespace,session process did not shut down cleanly\n' >&2
    return 1
  fi
}

stop_cleanly "$CLIENT_PID" "$TMP_DIR/client.log"
CLIENT_PID=""
stop_cleanly "$SERVER_PID" "$TMP_DIR/server.log"
SERVER_PID=""
ECHO_PID=""

if ip -n shph-srv link show dev s3srv0 >/dev/null 2>&1 || ip -n shph-cli link show dev s3cli0 >/dev/null 2>&1; then
  printf 'FAIL,shroud3_tun_namespace,TUN interface remained after clean shutdown\n' >&2
  exit 1
fi
if [[ -e "$SERVER_DIR/config.control-plane.json" || -e "$CLIENT_DIR/config.control-plane.json" ]]; then
  printf 'FAIL,shroud3_tun_namespace,control-plane state remained after clean shutdown\n' >&2
  exit 1
fi
ip netns del shph-cli
ip netns del shph-srv
if ip netns list | grep -Eq '^shph-(cli|srv)( |$)'; then
  printf 'FAIL,shroud3_tun_namespace,temporary network namespace remained after cleanup\n' >&2
  exit 1
fi

REPORT_DIR="$ROOT/benchmark-runs"
mkdir -p "$REPORT_DIR"
REPORT_PATH="$REPORT_DIR/shroud3-tun-namespace-$(date -u +%Y%m%dT%H%M%SZ).md"
REVISION="$(git rev-parse HEAD 2>/dev/null || printf 'unknown')"
if [[ -n "$(git status --porcelain 2>/dev/null)" ]]; then
  PROVENANCE="dirty"
else
  PROVENANCE="clean"
fi
KERNEL="$(uname -r)"
if grep -qi microsoft /proc/sys/kernel/osrelease 2>/dev/null; then
  PLATFORM="WSL2 isolated client/server network namespaces with veth underlay"
else
  PLATFORM="Linux isolated client/server network namespaces with veth underlay"
fi
cat >"$REPORT_PATH" <<REPORT
# Adaptive Shroud 3 TUN namespace packet-flow probe

- Result: PASS
- Date: $(date -u +%Y-%m-%dT%H:%M:%SZ)
- Platform: $PLATFORM
- Kernel: $KERNEL
- Git revision: $REVISION
- Worktree provenance: $PROVENANCE
- Probe: two local SHPH processes in separate nested network namespaces established a pinned, authenticated standards-QUIC session with adaptive Shroud 3 selected on both sides; a UDP payload traversed the client TUN, veth underlay, SHPH session, server TUN, local echo service, and return path.
- Cleanup: both processes exited on SIGTERM; both TUN interfaces, control-plane state files, and temporary nested namespaces were removed. Addresses and routes remained within the temporary namespaces. No DNS or firewall rules were changed.
- Limits: this is one-kernel namespace evidence. It is not native two-host interoperability, a representative Linux host campaign, Windows evidence, killswitch validation, a full-session benchmark, or evidence for anonymity, censorship resistance, or DPI evasion.
REPORT
printf 'REPORT,%s\n' "$REPORT_PATH"
