# Mirror Sync

SHPH can keep separate Linux and Windows working trees in sync. Configure the
absolute paths for your environment before using the helper:

```bash
export SHPH_LINUX_DIR=/absolute/path/to/linux/checkout
export SHPH_WINDOWS_MIRROR=/absolute/path/to/windows/mirror
```

## The sync script

`scripts/sync_mirror.sh` mirrors the trees with `rsync` and **verifies parity
by checksum** after every real sync. Run it from either side:

```bash
# Default: working copy -> Windows mirror, then verify.
./scripts/sync_mirror.sh

# Force a direction.
./scripts/sync_mirror.sh --to-windows   # working copy  ->  Windows mirror
./scripts/sync_mirror.sh --to-linux     # Windows mirror ->  working copy

# Checksum-only comparison, change nothing (exit 3 if diffs found).
./scripts/sync_mirror.sh --verify

# Preview what would change without writing.
./scripts/sync_mirror.sh --dry-run --to-windows
```

## What is never mirrored

These are local/build artifacts and are excluded on both sides:

- `target/` — cargo build output
- `benchmark-runs/` — generated benchmark captures
- `fuzz/corpus/` and `fuzz/artifacts/` — generated fuzz data
- root `Cargo.lock` — regenerated per platform; do not mirror
- `THE WORKING ONE/`, `.agents/`, `.codex/`, `.gapcode/` — local-only

The script does mirror `.git/` so the two repositories share history, tags, and
`HEAD`. The standalone `benchmarks/Cargo.lock` and `fuzz/Cargo.lock` files are
mirrored; only the root application lockfile is intentionally excluded.

## Notes

- The Linux working copy is treated as **canonical**: `--to-windows` (and the
  default) make the Windows mirror match it. Use `--to-linux` only when you've
  edited files on the Windows side and want to pull them back.
- drvfs permission bits differ between the two trees, so a `--dry-run` may list
  files as "changed" due to permission (`p`) flags even when content is
  identical. The post-sync checksum `--verify` is the source of truth for
  content parity.
- Source and documentation files are mirrored; never commit or mirror build,
  generated benchmark, or generated fuzz artifacts.

## Alternative: git (if adopted later)

If the project moves to git, the canonical sync becomes a normal
`git push` / `git pull` against a shared remote, and this script can be retired
or kept as a local convenience.
