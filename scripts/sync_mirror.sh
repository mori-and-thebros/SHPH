#!/usr/bin/env bash
# scripts/sync_mirror.sh — keep two configured platform checkouts synchronized.
#
# Configure the two checkout paths with SHPH_SYNC_LINUX_DIR and
# SHPH_SYNC_WINDOWS_DIR before running the script.
#
# Both trees are git repositories; .git/ is mirrored so tag/history/HEAD
# are identical on both sides (a true mirror).
#
# Usage:
#   scripts/sync_mirror.sh                 # auto-detect side, mirror source<->dest
#   scripts/sync_mirror.sh --to-windows    # force: Linux checkout -> Windows checkout
#   scripts/sync_mirror.sh --to-linux      # force: Windows checkout -> Linux checkout
#   scripts/sync_mirror.sh --verify        # checksum-only: report differences, change nothing
#   scripts/sync_mirror.sh --dry-run       # show what would change, write nothing
#
# Excluded from mirroring (local/build artifacts): see EXCLUDES below.
# Exit codes: 0 success, 1 usage/mount error, 2 rsync failure, 3 verify found diffs.

set -euo pipefail

LINUX_DIR="${SHPH_SYNC_LINUX_DIR:-}"
WINDOWS_MIRROR="${SHPH_SYNC_WINDOWS_DIR:-}"

# Paths never mirrored: build output, generated benchmark/fuzz data, the root
# application lockfile, and local-only dirs. The standalone benchmark/fuzz
# lockfiles are mirrored. .git/ is mirrored so both trees share tag/history/HEAD.
EXCLUDES=(
  --exclude='target/'
  --exclude='benchmark-runs/'
  --exclude='fuzz/corpus/'
  --exclude='fuzz/artifacts/'
  --exclude='/Cargo.lock'
  --exclude='/wintun.dll'
  --exclude='/wintun.h'
  --exclude='THE WORKING ONE/'
  --exclude='.agents/'
  --exclude='.codex/'
  --exclude='.gapcode/'
)

MODE="auto"
DRY_RUN=0

if [ -z "$LINUX_DIR" ] || [ -z "$WINDOWS_MIRROR" ]; then
  echo "ERROR: set SHPH_SYNC_LINUX_DIR and SHPH_SYNC_WINDOWS_DIR first." >&2
  echo "Example: SHPH_SYNC_LINUX_DIR=/path/to/linux SHPH_SYNC_WINDOWS_DIR=/path/to/windows" >&2
  exit 1
fi

usage() {
  sed -n '2,22p' "$0" | sed 's/^# \{0,1\}//'
  exit 1
}

for arg in "$@"; do
  case "$arg" in
    --to-windows) MODE="to-windows" ;;
    --to-linux)   MODE="to-linux" ;;
    --verify)     MODE="verify" ;;
    --dry-run)    DRY_RUN=1 ;;
    -h|--help)    usage ;;
    *) echo "unknown argument: $arg" >&2; usage ;;
  esac
done

# Resolve which side we are running from (by which path exists as our CWD ancestor).
self_dir="$(cd "$(dirname "$0")/.." && pwd)"
if [ "$self_dir" = "$LINUX_DIR" ]; then
  HERE="linux"
else
  # If running from the configured Windows checkout, confirm the side.
  case "$self_dir" in
    "$WINDOWS_MIRROR") HERE="windows" ;;
    *) HERE="linux" ;;  # default assumption
  esac
fi

if [ ! -d "$LINUX_DIR" ]; then
  echo "ERROR: configured Linux checkout not found: $LINUX_DIR" >&2; exit 1
fi
if [ ! -d "$WINDOWS_MIRROR" ]; then
  echo "ERROR: configured Windows checkout not found: $WINDOWS_MIRROR" >&2
  exit 1
fi

run_rsync() {
  # $1 = source (with trailing /), $2 = dest (with trailing /)
  local src="$1" dst="$2"
  local flags=(-a --delete "${EXCLUDES[@]}")
  if [ "$DRY_RUN" -eq 1 ]; then
    flags+=(--dry-run --itemize-changes)
    echo ">> DRY RUN: $src -> $dst"
  else
    echo ">> SYNC: $src -> $dst"
  fi
  if ! rsync "${flags[@]}" "$src" "$dst"; then
    echo "ERROR: rsync failed ($src -> $dst)" >&2
    exit 2
  fi
}

verify() {
  # $1,$2 = the two trees (no trailing slash)
  local a="$1" b="$2"
  echo ">> VERIFY: comparing checksums of $a <-> $b"
  local tmpa tmpb
  tmpa="$(mktemp)"; tmpb="$(mktemp)"
  # shellcheck disable=SC2164
  ( cd "$a" && find . -type f \
      -not -path '*/target/*' -not -path './.git/*' \
      -not -path './benchmark-runs/*' \
      -not -path './fuzz/corpus/*' -not -path './fuzz/artifacts/*' \
      -not -path './wintun.dll' -not -path './wintun.h' \
      -not -path './THE WORKING ONE/*' -not -path './.agents/*' \
      -not -path './.codex/*' -not -path './.gapcode/*' \
      -not -path './Cargo.lock' -exec md5sum {} \; ) | sort -k2 > "$tmpa"
  ( cd "$b" && find . -type f \
      -not -path '*/target/*' -not -path './.git/*' \
      -not -path './benchmark-runs/*' \
      -not -path './fuzz/corpus/*' -not -path './fuzz/artifacts/*' \
      -not -path './wintun.dll' -not -path './wintun.h' \
      -not -path './THE WORKING ONE/*' -not -path './.agents/*' \
      -not -path './.codex/*' -not -path './.gapcode/*' \
      -not -path './Cargo.lock' -exec md5sum {} \; ) | sort -k2 > "$tmpb"
  if diff -u "$tmpa" "$tmpb"; then
    echo ">> PARITY OK: trees are identical"
    rm -f "$tmpa" "$tmpb"
    return 0
  else
    rm -f "$tmpa" "$tmpb"
    echo ">> DIFFERENCES FOUND (see above)" >&2
    return 3
  fi
}

case "$MODE" in
  verify)
    verify "$LINUX_DIR" "$WINDOWS_MIRROR" && exit 0 || exit 3
    ;;
  to-windows)
    run_rsync "$LINUX_DIR/" "$WINDOWS_MIRROR/"
    ;;
  to-linux)
    run_rsync "$WINDOWS_MIRROR/" "$LINUX_DIR/"
    ;;
  auto)
    # Default direction: the configured Linux checkout is the source.
    echo ">> auto mode (running from: $HERE); defaulting to Linux -> Windows"
    run_rsync "$LINUX_DIR/" "$WINDOWS_MIRROR/"
    ;;
esac

# After a real (non-dry) sync, verify parity automatically.
if [ "$DRY_RUN" -eq 1 ]; then
  echo ">> dry run complete; no changes written"
else
  if verify "$LINUX_DIR" "$WINDOWS_MIRROR"; then
    echo ">> DONE: mirrored and verified."
  else
    exit 3
  fi
fi
