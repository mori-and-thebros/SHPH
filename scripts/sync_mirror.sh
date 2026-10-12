#!/usr/bin/env bash
# scripts/sync_mirror.sh — keep two configured platform checkouts synchronized.
#
# Configure the two checkout paths with SHPH_SYNC_LINUX_DIR and
# SHPH_SYNC_WINDOWS_DIR before running the script.
#
# Both trees are git repositories. The script preserves each checkout's Git
# metadata and requires matching HEAD/branch/tag state before syncing files.
#
# Usage:
#   scripts/sync_mirror.sh                 # default: Linux checkout -> Windows
#   scripts/sync_mirror.sh --to-windows    # force: Linux checkout -> Windows checkout
#   scripts/sync_mirror.sh --to-linux      # force: Windows checkout -> Linux checkout
#   scripts/sync_mirror.sh --verify        # checksum-only: report differences, change nothing
#   scripts/sync_mirror.sh --dry-run       # show what would change, write nothing
#   scripts/sync_mirror.sh --accept-dirty-destination  # acknowledge reviewed destination edits
#   scripts/sync_mirror.sh --prune-destination-only    # explicitly delete destination-only files
#
# Excluded from mirroring (local/build artifacts and confidential material):
# see EXCLUDES below.
# Exit codes: 0 success, 1 usage/mount error, 2 rsync failure, 3 verify found diffs.

set -euo pipefail

LINUX_DIR="${SHPH_SYNC_LINUX_DIR:-}"
WINDOWS_DIR="${SHPH_SYNC_WINDOWS_DIR:-}"

# Paths never mirrored: build output, generated benchmark/fuzz data, local
# tooling state, and confidential/local-only material. The standalone
# benchmark/fuzz lockfiles are mirrored. Git metadata is checked but never
# rsynced, preserving destination indexes, stashes, reflogs, and local objects.
EXCLUDES=(
  --exclude='target/'
  --exclude='.git'
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
  --exclude='__pycache__/'
  --exclude='.git/*.lock'
  --exclude='.git/**/*.lock'
  --exclude='/.two-host-validation/'
  --exclude='/tmp/'
  --exclude='/dist/'
  --exclude='/OTF_PRIVATE/'
  --exclude='/docs/CRYPTO_FUNDING_BOOTSTRAP.md'
  --exclude='/docs/FUNDING_SPRINT_BOARD.md'
  --exclude='/docs/IDENTITY_DISCOVERY_BENCHMARKS_2026-08-14.md'
  --exclude='/docs/IDENTITY_DISCOVERY_DESIGN.md'
)

MODE="auto"
DRY_RUN=0
ACCEPT_DIRTY_DESTINATION=0
PRUNE_DESTINATION_ONLY=0

if [ -z "$LINUX_DIR" ] || [ -z "$WINDOWS_DIR" ]; then
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
    --accept-dirty-destination) ACCEPT_DIRTY_DESTINATION=1 ;;
    --prune-destination-only) PRUNE_DESTINATION_ONLY=1 ;;
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
    "$WINDOWS_DIR") HERE="windows" ;;
    *) HERE="linux" ;;  # default assumption
  esac
fi

if [ ! -d "$LINUX_DIR" ]; then
  echo "ERROR: configured Linux checkout not found: $LINUX_DIR" >&2; exit 1
fi
if [ ! -d "$WINDOWS_DIR" ]; then
  echo "ERROR: configured Windows checkout not found: $WINDOWS_DIR" >&2
  exit 1
fi

LINUX_REAL_DIR="$(cd "$LINUX_DIR" && pwd -P)"
WINDOWS_REAL_DIR="$(cd "$WINDOWS_DIR" && pwd -P)"
case "$LINUX_REAL_DIR/" in
  "$WINDOWS_REAL_DIR/"|"$WINDOWS_REAL_DIR"/*)
    echo "ERROR: configured checkouts overlap: $LINUX_REAL_DIR and $WINDOWS_REAL_DIR" >&2
    exit 1
    ;;
esac

IGNORED_EXCLUDES="$(mktemp)"
cleanup() {
  rm -f "$IGNORED_EXCLUDES"
}
trap cleanup EXIT

collect_ignored_excludes() {
  local repository="$1" ignored_list ignored escaped character index
  ignored_list="$(mktemp)"
  if ! git -C "$repository" ls-files --others --ignored --exclude-standard --directory -z > "$ignored_list"; then
    rm -f "$ignored_list"
    echo "ERROR: unable to enumerate ignored files in $repository" >&2
    return 1
  fi
  while IFS= read -r -d '' ignored; do
    if [[ "$ignored" == *$'\n'* ]]; then
      rm -f "$ignored_list"
      echo "ERROR: ignored path contains a newline and cannot be safely mirrored: $ignored" >&2
      return 1
    fi
    escaped=""
    for ((index = 0; index < ${#ignored}; index++)); do
      character="${ignored:index:1}"
      case "$character" in
        \\|\*|\?|\[|\]) escaped+="\\$character" ;;
        *) escaped+="$character" ;;
      esac
    done
    printf '/%s\n' "$escaped" >> "$IGNORED_EXCLUDES"
  done < "$ignored_list"
  rm -f "$ignored_list"
}

collect_ignored_excludes "$LINUX_DIR"
collect_ignored_excludes "$WINDOWS_DIR"
LC_ALL=C sort -u "$IGNORED_EXCLUDES" -o "$IGNORED_EXCLUDES"
case "$WINDOWS_REAL_DIR/" in
  "$LINUX_REAL_DIR/"|"$LINUX_REAL_DIR"/*)
    echo "ERROR: configured checkouts overlap: $LINUX_REAL_DIR and $WINDOWS_REAL_DIR" >&2
    exit 1
    ;;
esac

run_rsync() {
  # $1 = source (with trailing /), $2 = dest (with trailing /)
  local src="$1" dst="$2"
  local flags=(-a --checksum "${EXCLUDES[@]}" --exclude-from="$IGNORED_EXCLUDES")
  if [ "$PRUNE_DESTINATION_ONLY" -eq 1 ]; then
    flags+=(--delete)
  fi
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

preflight_git_metadata() {
  local source_head destination_head source_branch destination_branch source_refs destination_refs
  source_head="$(git -C "$LINUX_DIR" rev-parse HEAD)"
  destination_head="$(git -C "$WINDOWS_DIR" rev-parse HEAD)"
  if [ "$source_head" != "$destination_head" ]; then
    echo "ERROR: checkout HEADs differ; reconcile Git history before mirroring files." >&2
    echo "  Linux:   $source_head" >&2
    echo "  Windows: $destination_head" >&2
    return 1
  fi
  source_branch="$(git -C "$LINUX_DIR" symbolic-ref --quiet --short HEAD || printf '%s' '(detached)')"
  destination_branch="$(git -C "$WINDOWS_DIR" symbolic-ref --quiet --short HEAD || printf '%s' '(detached)')"
  if [ "$source_branch" != "$destination_branch" ]; then
    echo "ERROR: active branches differ; reconcile checkout state before mirroring." >&2
    echo "  Linux:   $source_branch" >&2
    echo "  Windows: $destination_branch" >&2
    return 1
  fi
  source_refs="$(git -C "$LINUX_DIR" for-each-ref --format='%(refname) %(objectname)' refs/heads refs/tags | LC_ALL=C sort)"
  destination_refs="$(git -C "$WINDOWS_DIR" for-each-ref --format='%(refname) %(objectname)' refs/heads refs/tags | LC_ALL=C sort)"
  if [ "$source_refs" != "$destination_refs" ]; then
    echo "ERROR: branch or tag refs differ; reconcile Git history before mirroring files." >&2
    return 1
  fi
}

preflight_destination_worktree() {
  if [ "$ACCEPT_DIRTY_DESTINATION" -eq 1 ]; then
    return 0
  fi
  local destination="$1" destination_status
  destination_status="$(git -C "$destination" status --porcelain --untracked-files=all)"
  if [ -n "$destination_status" ]; then
    echo "ERROR: destination $destination has local work; review it, then pass --accept-dirty-destination to overwrite matching paths." >&2
    printf '%s\n' "$destination_status" >&2
    return 1
  fi
}

verify() {
  # $1,$2 = the two trees (no trailing slash)
  local a="$1" b="$2"
  echo ">> VERIFY: comparing checksums of $a <-> $b"
  local differences
  if ! differences="$(rsync --recursive --links --checksum --dry-run --delete \
      --itemize-changes --out-format='%i %n%L' --no-perms --no-owner --no-group \
      --no-times "${EXCLUDES[@]}" --exclude-from="$IGNORED_EXCLUDES" \
      "$a/" "$b/")"; then
    echo ">> ERROR: unable to compare mirror trees" >&2
    return 2
  fi
  if [ -z "$differences" ]; then
    echo ">> PARITY OK: trees are identical"
    return 0
  else
    printf '%s\n' "$differences"
    echo ">> DIFFERENCES FOUND (see above)" >&2
    return 3
  fi
}

case "$MODE" in
  verify)
    preflight_git_metadata
    if verify "$LINUX_DIR" "$WINDOWS_DIR"; then
      exit 0
    else
      status=$?
      exit "$status"
    fi
    ;;
  to-windows)
    preflight_git_metadata
    preflight_destination_worktree "$WINDOWS_DIR"
    run_rsync "$LINUX_DIR/" "$WINDOWS_DIR/"
    ;;
  to-linux)
    preflight_git_metadata
    preflight_destination_worktree "$LINUX_DIR"
    run_rsync "$WINDOWS_DIR/" "$LINUX_DIR/"
    ;;
  auto)
    # Default direction: the configured Linux checkout is the source.
    preflight_git_metadata
    preflight_destination_worktree "$WINDOWS_DIR"
    echo ">> auto mode (running from: $HERE); defaulting to Linux -> Windows"
    run_rsync "$LINUX_DIR/" "$WINDOWS_DIR/"
    ;;
esac

# After a real (non-dry) sync, verify parity automatically.
if [ "$DRY_RUN" -eq 1 ]; then
  echo ">> dry run complete; no changes written"
else
  if verify "$LINUX_DIR" "$WINDOWS_DIR"; then
    echo ">> DONE: mirrored and verified."
  else
    status=$?
    exit "$status"
  fi
fi
