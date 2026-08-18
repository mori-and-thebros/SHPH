#!/usr/bin/env bash
# Run an authenticated SHPH TCP payload exchange across two Linux network
# namespaces connected by a private veth pair. This does not change the host
# routing table or install a host firewall policy.

set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
  printf 'SKIP,isolated_e2e,requires Linux\n'
  exit 0
fi

if [[ "${EUID}" -ne 0 ]]; then
  echo "[!] Run as root: sudo $0" >&2
  exit 2
fi

for required in cargo ip ping; do
  command -v "$required" >/dev/null 2>&1 || {
    printf 'SKIP,isolated_e2e,missing command: %s\n' "$required" >&2
    exit 0
  }
done

ip netns help >/dev/null 2>&1 || {
  printf 'SKIP,isolated_e2e,iproute2 network namespaces are unavailable\n' >&2
  exit 0
}

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

SERVER_NS="shph-srv-$$"
CLIENT_NS="shph-cli-$$"
VETH_SRV="shs$$"
VETH_CLI="shc$$"
SRV_IP="10.99.0.1"
CLI_IP="10.99.0.2"
PORT="4433"
MESSAGE="SHPH_ISOLATED_TEST_PASS"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/shph-e2e.XXXXXX")"
SERVER_CONFIG="$WORK_DIR/server.toml"
CLIENT_CONFIG="$WORK_DIR/client.toml"
SERVER_LOG="$WORK_DIR/server.log"
CLIENT_LOG="$WORK_DIR/client.log"
SERVER_PID=""
SERVER_NS_CREATED=0
CLIENT_NS_CREATED=0

create_namespace() {
  local name="$1"
  local error
  if error="$(ip netns add "$name" 2>&1)"; then
    return 0
  fi
  if grep -Eqi 'operation not permitted|permission denied|not supported' <<<"$error"; then
    printf 'SKIP,isolated_e2e,host denied network namespace capability\n' >&2
    return 2
  fi
  printf 'ERROR,isolated_e2e,could not create namespace %s: %s\n' "$name" "$error" >&2
  return 1
}

cleanup() {
  set +e
  if [[ -n "$SERVER_PID" ]]; then
    kill -TERM "$SERVER_PID" 2>/dev/null || true
    wait "$SERVER_PID" 2>/dev/null || true
  fi
  if [[ "$SERVER_NS_CREATED" -eq 1 ]]; then
    ip netns del "$SERVER_NS" 2>/dev/null || true
  fi
  if [[ "$CLIENT_NS_CREATED" -eq 1 ]]; then
    ip netns del "$CLIENT_NS" 2>/dev/null || true
  fi
  ip link del "$VETH_SRV" 2>/dev/null || true
  rm -rf "$WORK_DIR"
}
trap cleanup EXIT
trap 'exit 130' INT TERM

echo "[1/7] Building SHPH CLI..."
cargo build -p shph-cli --release --locked --quiet
SHPH_BIN="$ROOT/target/release/shph"
if [[ ! -x "$SHPH_BIN" ]]; then
  echo "[!] Missing executable: $SHPH_BIN" >&2
  exit 1
fi

echo "[2/7] Creating isolated network namespaces..."
if create_namespace "$SERVER_NS"; then
  :
else
  status=$?
  if [[ "$status" -eq 2 ]]; then
    exit 0
  fi
  exit "$status"
fi
SERVER_NS_CREATED=1
if create_namespace "$CLIENT_NS"; then
  :
else
  status=$?
  if [[ "$status" -eq 2 ]]; then
    exit 0
  fi
  exit "$status"
fi
CLIENT_NS_CREATED=1

echo "[3/7] Wiring private veth link ($SRV_IP <-> $CLI_IP)..."
ip link add "$VETH_SRV" type veth peer name "$VETH_CLI"
ip link set "$VETH_SRV" netns "$SERVER_NS"
ip link set "$VETH_CLI" netns "$CLIENT_NS"
ip -n "$SERVER_NS" addr add "$SRV_IP/24" dev "$VETH_SRV"
ip -n "$SERVER_NS" link set "$VETH_SRV" up
ip -n "$SERVER_NS" link set lo up
ip -n "$CLIENT_NS" addr add "$CLI_IP/24" dev "$VETH_CLI"
ip -n "$CLIENT_NS" link set "$VETH_CLI" up
ip -n "$CLIENT_NS" link set lo up

echo "[4/7] Verifying the private link..."
ip netns exec "$CLIENT_NS" ping -c 2 -W 1 "$SRV_IP" >/dev/null

echo "[5/7] Creating identities and mutually pinned peer policies..."
"$SHPH_BIN" --config "$SERVER_CONFIG" init >/dev/null
"$SHPH_BIN" --config "$CLIENT_CONFIG" init >/dev/null

SERVER_PUB="$("$SHPH_BIN" --config "$SERVER_CONFIG" show-public-key)"
SERVER_SIGN_PUB="$("$SHPH_BIN" --config "$SERVER_CONFIG" show-signing-public-key)"
CLIENT_PUB="$("$SHPH_BIN" --config "$CLIENT_CONFIG" show-public-key)"
CLIENT_SIGN_PUB="$("$SHPH_BIN" --config "$CLIENT_CONFIG" show-signing-public-key)"

"$SHPH_BIN" --config "$SERVER_CONFIG" add-peer \
  client "$CLI_IP" "$PORT" "$CLIENT_PUB" --sign-pubkey "$CLIENT_SIGN_PUB" >/dev/null
"$SHPH_BIN" --config "$CLIENT_CONFIG" add-peer \
  server "$SRV_IP" "$PORT" "$SERVER_PUB" --sign-pubkey "$SERVER_SIGN_PUB" >/dev/null

echo "[6/7] Running authenticated receive/send exchange..."
ip netns exec "$SERVER_NS" "$SHPH_BIN" \
  --config "$SERVER_CONFIG" recv-once \
  --bind "$SRV_IP:$PORT" --timeout-secs 20 >"$SERVER_LOG" 2>&1 &
SERVER_PID=$!
sleep 1

CLIENT_STATUS=0
ip netns exec "$CLIENT_NS" "$SHPH_BIN" \
  --config "$CLIENT_CONFIG" send-once \
  --peer "$SRV_IP:$PORT" --text "$MESSAGE" --timeout-secs 20 \
  >"$CLIENT_LOG" 2>&1 || CLIENT_STATUS=$?

SERVER_STATUS=0
wait "$SERVER_PID" || SERVER_STATUS=$?
SERVER_PID=""

if [[ "$CLIENT_STATUS" -ne 0 || "$SERVER_STATUS" -ne 0 ]]; then
  echo "[!] Authenticated exchange failed." >&2
  echo "--- client log ---" >&2
  cat "$CLIENT_LOG" >&2
  echo "--- server log ---" >&2
  cat "$SERVER_LOG" >&2
  exit 1
fi

grep -Fq "Payload: $MESSAGE" "$SERVER_LOG" || {
  echo "[!] Receiver did not verify the expected payload." >&2
  cat "$SERVER_LOG" >&2
  exit 1
}

echo "[7/7] Isolated authenticated exchange passed."
printf 'PASS,isolated_e2e,tcp-handshake-and-payload\n'
