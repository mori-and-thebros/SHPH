#!/usr/bin/env bash
set -euo pipefail
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-never}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT="${1:-$ROOT/benchmark-runs/criterion-linux}"
TOOLCHAIN="${SHPH_RUST_TOOLCHAIN:-1.96.0}"
FILTER="${2:-}"

mkdir -p "$OUTPUT"
{
  printf 'commit=%s\n' "$(git -C "$ROOT" rev-parse HEAD)"
  printf 'platform=%s\n' "$(uname -srm)"
  printf 'rustc=%s\n' "$(rustc "+$TOOLCHAIN" --version)"
  printf 'toolchain=%s\n' "$TOOLCHAIN"
  printf 'harness=criterion\n'
  printf 'scope=local-microbenchmark;GitHub-hosted-run\n'
  printf 'determinism=inputs-and-seeds-fixed;OS-randomized-padding-may-vary\n'
} > "$OUTPUT/metadata.txt"

args=(
  "+$TOOLCHAIN"
  bench
  --manifest-path "$ROOT/benchmarks/Cargo.toml"
  --bench criterion
  --locked
  --
  --noplot
)
if [[ -n "$FILTER" ]]; then
  args+=("$FILTER")
fi

set +e
cargo "${args[@]}" 2>&1 | tee "$OUTPUT/criterion.log"
status=${PIPESTATUS[0]}
set -e
if [[ "$status" -ne 0 ]]; then
  exit "$status"
fi

if [[ ! -d "$ROOT/benchmarks/target/criterion" ]]; then
  echo "Criterion did not produce its report directory" >&2
  exit 1
fi
cp -a "$ROOT/benchmarks/target/criterion" "$OUTPUT/criterion-report"
printf 'Criterion capture complete: %s\n' "$OUTPUT"
