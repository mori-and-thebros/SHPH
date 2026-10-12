# Checkout Synchronization

The optional synchronization helper keeps two platform-specific checkouts in
sync. It does not assume a particular filesystem layout.

Set `SHPH_SYNC_LINUX_DIR` and `SHPH_SYNC_WINDOWS_DIR` to the two checkout
directories before running the helper.

## The sync script

`scripts/sync_mirror.sh` copies workspace files with `rsync` and **verifies
content parity by checksum** after every real sync, and uses checksums during
transfer so matching sizes or timestamps cannot hide changed bytes. It checks
that both Git
checkouts have the same `HEAD`, branches, and tags, but preserves each
checkout's `.git/` directory. Run it from either side:

```bash
# Configure the checkout paths for the current machine.
export SHPH_SYNC_LINUX_DIR=/path/to/linux-checkout
export SHPH_SYNC_WINDOWS_DIR=/path/to/windows-checkout

# Default: Linux checkout -> Windows checkout, then verify.
./scripts/sync_mirror.sh

# Force a direction.
./scripts/sync_mirror.sh --to-windows
./scripts/sync_mirror.sh --to-linux

# Compare Git state and content, change nothing (exit 3 if content differs).
./scripts/sync_mirror.sh --verify

# Preview after reviewing the dirty Windows worktree.
./scripts/sync_mirror.sh --dry-run --accept-dirty-destination --to-windows

# Explicitly allow removal of destination-only, non-excluded files.
./scripts/sync_mirror.sh --accept-dirty-destination \
  --prune-destination-only --to-windows
```

Normal syncs refuse a dirty destination unless `--accept-dirty-destination`
is supplied after reviewing its changes. Destination-only files are retained
by default. `--prune-destination-only` opts in to their removal; excluded
files remain protected. A mismatched `HEAD`, branch, or tag set blocks the
file sync so Git history can be reconciled separately rather than overwritten.

## What is never mirrored

These are local/build artifacts or confidential/local-only material and are
excluded on both sides:

- `target/` — cargo build output
- `benchmark-runs/` — generated benchmark captures
- `fuzz/corpus/` and `fuzz/artifacts/` — generated fuzz data
- root `Cargo.lock` — regenerated per platform; do not mirror
- `dist/` — generated release packages
- `THE WORKING ONE/`, `.agents/`, `.codex/`, `.gapcode/`, `.two-host-validation/`,
  and `tmp/` — local working and tooling state
- `OTF_PRIVATE/` and the confidential funding/identity design documents — local
  evidence and internal material

The script does not copy `.git/`, which protects destination indexes, stashes,
reflogs, and local objects. The standalone `benchmarks/Cargo.lock` and
`fuzz/Cargo.lock` files are mirrored; only the root application lockfile is
intentionally excluded.
`.gitattributes` normalizes repository text to LF and keeps PowerShell scripts
at CRLF so edits from either checkout do not create line-ending-only diffs.

## Notes

- The configured Linux checkout is the default source: `--to-windows` and the
  default mode copy it to the Windows checkout. Use `--to-linux` to reverse
  the direction.
- Filesystem permission metadata may differ between platforms. The post-sync
  checksum `--verify` is the source of truth for content parity.
- Source and documentation files are mirrored; never commit or mirror build,
  generated benchmark, or generated fuzz artifacts.

## Shared remote option

The checkouts already use git locally. If a shared remote is adopted, normal
`git push` / `git pull` can replace local tree mirroring; keep generated and
confidential exclusions in the remote workflow as well.
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
the Windows root lockfile with a WSL-generated file merely to make parity
checks pass.
