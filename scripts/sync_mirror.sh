#!/usr/bin/env bash
# scripts/sync_mirror.sh — keep the SHPH working copy and the Windows mirror in sync.
#
# The project has two trees:
#   - Linux working copy: /home/mori/SHPH_working_copy   (this WSL home)
#   - Windows mirror:     D:\FUNDING NEEDED\snap-shroud-rs  (mounted at /mnt/d)
#
# Neither is a git repo yet, so this uses rsync to produce a true mirror.
#
# Usage:
#   scripts/sync_mirror.sh                 # auto-detect side, mirror source<->dest
#   scripts/sync_mirror.sh --to-windows    # force: working copy  ->  Windows mirror
#   scripts/sync_mirror.sh --to-linux      # force: Windows mirror ->  working copy
#   scripts/sync_mirror.sh --verify        # checksum-only: report differences, change nothing
#   scripts/sync_mirror.sh --dry-run       # show what would change, write nothing
#
# Excluded from mirroring (local/build artifacts): see EXCLUDES below.
# Exit codes: 0 success, 1 usage/mount error, 2 rsync failure, 3 verify found diffs.

set -euo pipefail

LINUX_DIR="/home/mori/SHPH_working_copy"
WINDOWS_MIRROR="/mnt/d/FUNDING NEEDED/snap-shroud-rs"

# Paths never mirrored: build output, lockfile (platform-specific), local-only dirs.
EXCLUDES=(
  --exclude='target/'
  --exclude='.git/'
  --exclude='Cargo.lock'
  --exclude='THE WORKING ONE/'
  --exclude='.agents/'
  --exclude='.codex/'
  --exclude='.gapcode/'
)

MODE="auto"
DRY_RUN=0

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
  # Could be running from the Windows mirror mount; confirm.
  case "$self_dir" in
    "$WINDOWS_MIRROR") HERE="windows" ;;
    *) HERE="linux" ;;  # default assumption
  esac
fi

if [ ! -d "$LINUX_DIR" ]; then
  echo "ERROR: Linux working copy not found: $LINUX_DIR" >&2; exit 1
fi
if [ ! -d "$WINDOWS_MIRROR" ]; then
  echo "ERROR: Windows mirror not found: $WINDOWS_MIRROR" >&2
  echo "Is the D: drive mounted in WSL? (it normally appears at /mnt/d)" >&2
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
      -not -path './target/*' -not -path './.git/*' \
      -not -path './THE WORKING ONE/*' -not -path './.agents/*' \
      -not -path './.codex/*' -not -path './.gapcode/*' \
      -not -name 'Cargo.lock' -exec md5sum {} \; ) | sort -k2 > "$tmpa"
  ( cd "$b" && find . -type f \
      -not -path './target/*' -not -path './.git/*' \
      -not -path './THE WORKING ONE/*' -not -path './.agents/*' \
      -not -path './.codex/*' -not -path './.gapcode/*' \
      -not -name 'Cargo.lock' -exec md5sum {} \; ) | sort -k2 > "$tmpb"
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
    # Default direction: working copy is canonical, mirror to Windows.
    # (Change HERE-based logic if you want Windows to be canonical.)
    echo ">> auto mode (running from: $HERE); defaulting to working copy -> Windows mirror"
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
