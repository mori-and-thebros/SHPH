#!/usr/bin/env bash
# Measure isolated native-TUN open/hold/close lifecycle cost.
#
# This is intentionally not a throughput benchmark: the probe does not inject
# packets and cannot prove two-host routing, goodput, RTT, jitter, or CPU
# saturation. Those measurements require a privileged native Linux host.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

ITERATIONS="${SHPH_TUN_BENCH_ITERATIONS:-20}"
HOLD_MS="${SHPH_TUN_BENCH_HOLD_MS:-0}"
OUTPUT=""

usage() {
  sed -n '1,12p' "$0"
  cat <<'USAGE'

Options:
  --iterations N  Number of isolated lifecycle samples (default: 20)
  --hold-ms N     AsyncFd probe hold duration per sample (default: 0)
  --output PATH   Append CSV output to PATH
USAGE
}

while (($#)); do
  case "$1" in
    --iterations) ITERATIONS="${2:?missing value for --iterations}"; shift 2 ;;
    --hold-ms) HOLD_MS="${2:?missing value for --hold-ms}"; shift 2 ;;
    --output) OUTPUT="${2:?missing value for --output}"; shift 2 ;;
    --help|-h) usage; exit 0 ;;
    *) printf 'unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ ! "$ITERATIONS" =~ ^[1-9][0-9]*$ ]]; then
  printf 'ERROR,benchmark_native_tun,iterations must be a positive integer\n' >&2
  exit 2
fi
if [[ ! "$HOLD_MS" =~ ^[0-9]+$ ]]; then
  printf 'ERROR,benchmark_native_tun,hold-ms must be a non-negative integer\n' >&2
  exit 2
fi

emit() {
  if [[ -n "$OUTPUT" ]]; then
    printf '%s\n' "$*" | tee -a "$OUTPUT"
  else
    printf '%s\n' "$*"
  fi
}

if [[ "$(uname -s)" != "Linux" ]]; then
  emit "SKIP,native_tun_lifecycle,requires Linux"
  exit 0
fi
if ! command -v unshare >/dev/null 2>&1; then
  emit "SKIP,native_tun_lifecycle,requires unshare"
  exit 0
fi
if [[ ! -e /dev/net/tun ]]; then
  emit "SKIP,native_tun_lifecycle,/dev/net/tun is unavailable"
  exit 0
fi

if [[ -f "$HOME/.cargo/env" ]]; then
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
fi

cargo build -p shph-tun --example native_tun_probe --offline >/dev/null
PROBE="$ROOT/target/debug/examples/native_tun_probe"
if [[ ! -x "$PROBE" ]]; then
  emit "ERROR,native_tun_lifecycle,probe binary missing: $PROBE" >&2
  exit 1
fi

metadata() {
  emit "# benchmark=native_tun_lifecycle"
  emit "# commit=$(git rev-parse HEAD)"
  emit "# platform=$(uname -srm)"
  emit "# rustc=$(rustc --version)"
  emit "# iterations=$ITERATIONS"
  emit "# hold_ms=$HOLD_MS"
  emit "benchmark,sample,elapsed_ns,status"
}

TMP_OUTPUT="$(mktemp)"
cleanup() {
  rm -f "$TMP_OUTPUT"
}
trap cleanup EXIT

metadata
samples=()
for ((sample = 1; sample <= ITERATIONS; sample++)); do
  start="$(date +%s%N)"
  set +e
  unshare --user --map-root-user --net -- "$PROBE" --hold-ms "$HOLD_MS" \
    >"$TMP_OUTPUT" 2>&1
  status=$?
  set -e
  end="$(date +%s%N)"
  elapsed="$((end - start))"

  if [[ "$status" -ne 0 ]]; then
    if grep -Eqi 'operation not permitted|permission denied|cap_net_admin|tunsetiff|unshare failed' "$TMP_OUTPUT"; then
      emit "SKIP,native_tun_lifecycle,host denied isolated user/network namespace capability"
      sed -n '1,12p' "$TMP_OUTPUT" >&2
      exit 0
    fi
    cat "$TMP_OUTPUT" >&2
    emit "FAIL,native_tun_lifecycle,sample $sample exited $status"
    exit "$status"
  fi

  samples+=("$elapsed")
  emit "native_tun_lifecycle,$sample,$elapsed,pass"
done

sorted="$(printf '%s\n' "${samples[@]}" | sort -n)"
count="${#samples[@]}"
min="$(printf '%s\n' "$sorted" | head -n1)"
max="$(printf '%s\n' "$sorted" | tail -n1)"
p50_index=$(( (count + 1) / 2 ))
p95_index=$(( (count * 95 + 99) / 100 ))
p95_index=$(( p95_index < 1 ? 1 : p95_index ))
p95_index=$(( p95_index > count ? count : p95_index ))
p50="$(printf '%s\n' "$sorted" | sed -n "${p50_index}p")"
p95="$(printf '%s\n' "$sorted" | sed -n "${p95_index}p")"
emit "summary,native_tun_lifecycle,min_ns=$min;p50_ns=$p50;p95_ns=$p95;max_ns=$max"
