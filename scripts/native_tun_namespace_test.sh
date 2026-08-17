#!/usr/bin/env bash
# Validate the Linux AsyncFd native-TUN probe inside an isolated user/network
# namespace. This never mutates the host routing table.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

if [[ "$(uname -s)" != "Linux" ]]; then
  printf 'SKIP,native_tun_namespace,requires Linux\n'
  exit 0
fi

if ! command -v unshare >/dev/null 2>&1; then
  printf 'SKIP,native_tun_namespace,requires unshare\n'
  exit 0
fi

if [[ ! -e /dev/net/tun ]]; then
  printf 'SKIP,native_tun_namespace,/dev/net/tun is unavailable\n'
  exit 0
fi

if [[ -f "$HOME/.cargo/env" ]]; then
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
fi

HOLD_MS="${SHPH_TUN_NAMESPACE_HOLD_MS:-50}"
if [[ ! "$HOLD_MS" =~ ^[0-9]+$ ]]; then
  printf 'ERROR,native_tun_namespace,hold-ms must be a non-negative integer\n' >&2
  exit 2
fi

if ! cargo build -p shph-tun --example native_tun_probe --offline >/dev/null; then
  printf 'ERROR,native_tun_namespace,probe build failed\n' >&2
  exit 1
fi

PROBE="$ROOT/target/debug/examples/native_tun_probe"
if [[ ! -x "$PROBE" ]]; then
  printf 'ERROR,native_tun_namespace,probe binary missing: %s\n' "$PROBE" >&2
  exit 1
fi

TMP_OUTPUT="$(mktemp)"
cleanup() {
  rm -f "$TMP_OUTPUT"
}
trap cleanup EXIT

set +e
unshare --user --map-root-user --net -- "$PROBE" --hold-ms "$HOLD_MS" \
  >"$TMP_OUTPUT" 2>&1
STATUS=$?
set -e

if [[ "$STATUS" -eq 0 ]]; then
  cat "$TMP_OUTPUT"
  printf 'PASS,native_tun_namespace,isolated AsyncFd TUN open/hold/close\n'
  exit 0
fi

if grep -Eqi 'operation not permitted|permission denied|cap_net_admin|tunsetiff|unshare failed' "$TMP_OUTPUT"; then
  printf 'SKIP,native_tun_namespace,host denied isolated user/network namespace capability\n'
  sed -n '1,12p' "$TMP_OUTPUT" >&2
  exit 0
fi

cat "$TMP_OUTPUT" >&2
printf 'FAIL,native_tun_namespace,probe failed with status %s\n' "$STATUS" >&2
exit "$STATUS"
