# Checkout Synchronization

The optional synchronization helper keeps two platform-specific checkouts in
sync. It does not assume a particular filesystem layout.

Set `SHPH_SYNC_LINUX_DIR` and `SHPH_SYNC_WINDOWS_DIR` to the two checkout
directories before running the helper.

## The sync script

`scripts/sync_mirror.sh` mirrors the trees with `rsync` and **verifies parity
by checksum** after every real sync. Run it from either side:

```bash
# Configure the checkout paths for the current machine.
export SHPH_SYNC_LINUX_DIR=/path/to/linux-checkout
export SHPH_SYNC_WINDOWS_DIR=/path/to/windows-checkout

# Default: Linux checkout -> Windows checkout, then verify.
./scripts/sync_mirror.sh

# Force a direction.
./scripts/sync_mirror.sh --to-windows
./scripts/sync_mirror.sh --to-linux

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
- local tool and placeholder directories — local-only

The script mirrors `.git/` so the two repositories share history and tags. The
standalone `benchmarks/Cargo.lock` and `fuzz/Cargo.lock` files are mirrored;
only the root application lockfile is intentionally excluded.

## Notes

- The configured Linux checkout is the default source: `--to-windows` and the
  default mode make the Windows checkout match it. Use `--to-linux` to reverse
  the direction.
- Filesystem permission metadata may differ between platforms. The post-sync
  checksum `--verify` is the source of truth for content parity.
- Source and documentation files are mirrored; never commit or mirror build,
  generated benchmark, or generated fuzz artifacts.

## Alternative: git (if adopted later)

If the project moves to git, the canonical sync becomes a normal
`git push` / `git pull` against a shared remote, and this script can be retired
or kept as a local convenience.
# Root Lockfile Refresh After a Version Change

The root `Cargo.lock` is intentionally excluded from Linux/Windows mirroring
because the application workspace can resolve platform-specific dependency
metadata. The standalone `benchmarks/Cargo.lock` and `fuzz/Cargo.lock` are
mirrored.

When the workspace version or root dependency graph changes, refresh the root
lockfile natively in each supported checkout before running a locked build:

```bash
cargo check --workspace
cargo check --workspace --locked
```

On Windows, run the same commands in a native Windows terminal. Do not replace
the Windows root lockfile with a WSL-generated file merely to make mirror
checks pass.
