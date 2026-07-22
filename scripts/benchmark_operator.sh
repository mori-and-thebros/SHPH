#!/usr/bin/env bash
# Run SHPH benchmark layers that require real processes, host tools, or two hosts.
#
# This script deliberately does not synthesize TUN, route/DNS, reconnect, or
# network results. Missing capabilities are reported as SKIP with the exact
# prerequisite needed.
#
# Usage:
#   scripts/benchmark_operator.sh --mode local
#   scripts/benchmark_operator.sh --mode lifecycle --config /path/config.toml
#   scripts/benchmark_operator.sh --mode control-plane --config /path/config.toml
#   scripts/benchmark_operator.sh --mode reconnect --config /path/config.toml
#   scripts/benchmark_operator.sh --mode tun --config /path/config.toml
#   scripts/benchmark_operator.sh --mode all --config /path/config.toml
#
# For two-host work, run the same prepared configuration on both machines and
# use an external traffic generator (iperf3 or an equivalent controlled tool).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
if [[ -f "$HOME/.cargo/env" ]]; then
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
fi

MODE="local"
CONFIG=""
OUTPUT=""
FRAMES="${SHPH_BENCH_FRAMES:-100000}"
ITERATIONS="${SHPH_BENCH_ITERATIONS:-1000}"
TRANSPORT="${SHPH_BENCH_TRANSPORT:-tcp}"
TUN_NATIVE="${SHPH_TUN_NATIVE:-0}"

usage() {
  sed -n '1,28p' "$0"
  cat <<'USAGE'

Options:
  --mode MODE             local|lifecycle|control-plane|reconnect|tun|all
  --config PATH           Existing operator configuration for non-local modes
  --output PATH           Append measurements to this file
  --frames N              Sustained frame count for local benchmark
  --iterations N          Latency sample count for local benchmark
  --transport MODE        tcp|quic
  --tun-native 0|1        Set SHPH_TUN_NATIVE for the child process
  --help                  Show this help
USAGE
}

while (($#)); do
  case "$1" in
    --mode) MODE="${2:?missing value for --mode}"; shift 2 ;;
    --config) CONFIG="${2:?missing value for --config}"; shift 2 ;;
    --output) OUTPUT="${2:?missing value for --output}"; shift 2 ;;
    --frames) FRAMES="${2:?missing value for --frames}"; shift 2 ;;
    --iterations) ITERATIONS="${2:?missing value for --iterations}"; shift 2 ;;
    --transport) TRANSPORT="${2:?missing value for --transport}"; shift 2 ;;
    --tun-native) TUN_NATIVE="${2:?missing value for --tun-native}"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

BIN="${SHPH_BIN:-$ROOT/target/release/shph}"
BENCH="${SHPH_BENCH_BIN:-$ROOT/benchmarks/target/release/shph-benchmarks}"

log() {
  if [[ -n "$OUTPUT" ]]; then
    printf '%s\n' "$*" | tee -a "$OUTPUT"
  else
    printf '%s\n' "$*"
  fi
}

skip() {
  log "SKIP,$1,$2"
}

require_binary() {
  if [[ ! -x "$1" ]]; then
    log "BUILD,$1"
    cargo build --release -p shph-cli --manifest-path "$ROOT/Cargo.toml"
  fi
}

require_benchmark_binary() {
  if [[ ! -x "$BENCH" ]]; then
    log "BUILD,$BENCH"
    cargo build --release --manifest-path "$ROOT/benchmarks/Cargo.toml"
  fi
}

measure_command() {
  local name="$1"
  shift
  local start end elapsed rc
  start="$(date +%s%N)"
  set +e
  "$@"
  rc=$?
  set -e
  end="$(date +%s%N)"
  elapsed="$(( (end - start) / 1000000 ))"
  log "timing,$name,$elapsed,$rc"
  return "$rc"
}

metadata() {
  log "# commit=$(git rev-parse HEAD)"
  log "# platform=$(uname -srm)"
  log "# rustc=$(rustc --version)"
  log "# transport=$TRANSPORT"
  log "# tun_native=$TUN_NATIVE"
}

run_local() {
  require_benchmark_binary
  metadata
  SHPH_TUN_NATIVE="$TUN_NATIVE" "$BENCH" \
    --suite all --iterations "$ITERATIONS" --frames "$FRAMES"
}

run_lifecycle() {
  if [[ -z "$CONFIG" ]]; then
    skip lifecycle "requires --config pointing at a prepared peer session"
    return 0
  fi
  if [[ ! -f "$CONFIG" ]]; then
    skip lifecycle "config does not exist: $CONFIG"
    return 0
  fi
  require_binary "$BIN"
  metadata
  measure_command startup_status env SHPH_TUN_NATIVE="$TUN_NATIVE" \
    "$BIN" --config "$CONFIG" status
  log "# cold-start requires a prepared peer and is measured with 'shph up';"
  log "# run this mode on the listener and connector separately to capture handshake time"
  measure_command graceful_shutdown env SHPH_TUN_NATIVE="$TUN_NATIVE" \
    timeout --signal=INT --kill-after=5s 5s \
    "$BIN" --config "$CONFIG" up
}

run_control_plane() {
  if [[ -z "$CONFIG" ]]; then
    skip control_plane "requires --config with dry_run=true or an isolated privileged host"
    return 0
  fi
  if [[ ! -f "$CONFIG" ]]; then
    skip control_plane "config does not exist: $CONFIG"
    return 0
  fi
  require_binary "$BIN"
  metadata
  measure_command control_apply "$BIN" --config "$CONFIG" apply
  measure_command control_reconcile "$BIN" --config "$CONFIG" reconcile
  measure_command control_undo "$BIN" --config "$CONFIG" undo
}

run_reconnect() {
  if [[ -z "$CONFIG" ]]; then
    skip reconnect "requires --config with [session.reconnect] and an isolated peer"
    return 0
  fi
  if [[ ! -f "$CONFIG" ]]; then
    skip reconnect "config does not exist: $CONFIG"
    return 0
  fi
  require_binary "$BIN"
  metadata
  log "# reconnect recovery is measured by interrupting the peer after session establishment"
  log "# this command records bounded retry/backoff behavior; it does not inject a fake recovery"
  measure_command reconnect_backoff env SHPH_TUN_NATIVE="$TUN_NATIVE" \
    timeout --signal=INT --kill-after=5s 8s \
    "$BIN" --config "$CONFIG" up
}

run_tun() {
  if [[ "$TUN_NATIVE" != "1" ]]; then
    skip tun "set --tun-native 1 on native Linux with /dev/net/tun and CAP_NET_ADMIN"
    return 0
  fi
  if [[ "$(uname -s)" != "Linux" ]]; then
    skip tun "native TUN benchmark is Linux-only; Windows requires provisioned signed Wintun"
    return 0
  fi
  if [[ ! -e /dev/net/tun ]]; then
    skip tun "/dev/net/tun is unavailable"
    return 0
  fi
  if [[ -z "$CONFIG" ]]; then
    skip tun "requires --config with a prepared session"
    return 0
  fi
  if [[ ! -f "$CONFIG" ]]; then
    skip tun "config does not exist: $CONFIG"
    return 0
  fi
  require_binary "$BIN"
  metadata
  log "# TUN throughput/goodput and CPU require traffic through the live interface."
  log "# Use iperf3/ping from a second host or namespace; this step only validates startup."
  measure_command tun_startup env SHPH_TUN_NATIVE=1 \
    timeout --signal=INT --kill-after=5s 5s \
    "$BIN" --config "$CONFIG" up
}

case "$MODE" in
  local) run_local ;;
  lifecycle) run_lifecycle ;;
  control-plane|control_plane) run_control_plane ;;
  reconnect) run_reconnect ;;
  tun) run_tun ;;
  all)
    run_local
    run_lifecycle
    run_control_plane
    run_reconnect
    run_tun
    ;;
  *) echo "invalid mode: $MODE" >&2; usage >&2; exit 2 ;;
esac
