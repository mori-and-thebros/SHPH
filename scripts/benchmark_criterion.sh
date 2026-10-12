#!/usr/bin/env bash
set -euo pipefail
export CARGO_TERM_COLOR="${CARGO_TERM_COLOR:-never}"

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUTPUT="${1:-$ROOT/benchmark-runs/criterion-linux}"
TOOLCHAIN="${SHPH_RUST_TOOLCHAIN:-1.96.0}"
FILTER="${2:-}"

if [[ "$OUTPUT" != /* ]]; then
  OUTPUT="$ROOT/$OUTPUT"
fi
if [[ -e "$OUTPUT" ]]; then
  echo "Benchmark output already exists; choose a new output directory: $OUTPUT" >&2
  exit 2
fi
TREE_STATE=clean
if [[ -n "$(git -C "$ROOT" status --porcelain=v1 --untracked-files=all)" ]]; then
  TREE_STATE=dirty
fi
TRACKED_DIFF_SHA256="$(git -C "$ROOT" diff --binary HEAD -- . | sha256sum | awk '{print $1}')"
UNTRACKED_SHA256="$(git -C "$ROOT" ls-files --others --exclude-standard -z | while IFS= read -r -d '' path; do printf '%s\0' "$path"; sha256sum -- "$ROOT/$path"; done | sha256sum | awk '{print $1}')"
mkdir -p "$(dirname "$OUTPUT")"
mkdir "$OUTPUT"
{
  printf 'commit=%s\n' "$(git -C "$ROOT" rev-parse HEAD)"
  printf 'tree_state=%s\n' "$TREE_STATE"
  printf 'tracked_diff_sha256=%s\n' "$TRACKED_DIFF_SHA256"
  printf 'untracked_inventory_sha256=%s\n' "$UNTRACKED_SHA256"
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

export CARGO_TARGET_DIR="$OUTPUT/.cargo-target"
set +e
cargo "${args[@]}" 2>&1 | tee "$OUTPUT/criterion.log"
status=${PIPESTATUS[0]}
set -e
if [[ "$status" -ne 0 ]]; then
  exit "$status"
fi

if [[ ! -d "$CARGO_TARGET_DIR/criterion" ]]; then
  echo "Criterion did not produce its report directory" >&2
  exit 1
fi
cp -a "$CARGO_TARGET_DIR/criterion" "$OUTPUT/criterion-report"
rm -rf "$CARGO_TARGET_DIR"
printf 'Criterion capture complete: %s\n' "$OUTPUT"
