# SHPH Supply-Chain Scan & Advisory Triage

This document records the scanner, reproduction command, current CI policy,
and the disposition of historical advisories.

## 1. Scanner

- **Tool:** `cargo-audit` (RustSec advisory database).
- **Command:** `cargo audit --deny warnings`.
- **Captured output:** `docs/evidence/CARGO_AUDIT.txt`.

## 2. How to reproduce

```bash
cargo install cargo-audit --version 0.22.2 --locked
for lockfile in Cargo.lock benchmarks/Cargo.lock fuzz/Cargo.lock shph-edge/Cargo.lock; do
  cargo audit --deny warnings --file "$lockfile"
  cargo audit --deny yanked --file "$lockfile"
done
```

Run this from the repository root after every lockfile change. The CI workflow
uses the same blocking policy and does not ignore advisory IDs.

## 3. Current policy (2026-09-28)

The root, benchmark, fuzz, and standalone edge lockfiles were scanned with
`cargo-audit 0.22.2` using both `cargo audit --deny warnings --no-fetch
--file <lockfile>` and `cargo audit --deny yanked --no-fetch --file
<lockfile>`. All eight scans exited successfully without advisory or
yanked-crate warnings. They covered 299, 269, 183, and 178 locked dependencies,
respectively. The local advisory database HEAD
`ef03605143a913024f864d2edf476adad5720c93` matched upstream HEAD in a
`git ls-remote` check at `2026-09-28T21:17:17Z`; `--no-fetch` was used after
that match was verified. Exact results are recorded in
[`evidence/CARGO_AUDIT.txt`](evidence/CARGO_AUDIT.txt).

The pinned 0.22.2 scanner was built into an ignored project-local tools
directory and is not part of the release package.

### Historical advisories

| Advisory | Historical crate | Historical disposition |
| -------- | ---------------- | ---------------------- |
| RUSTSEC-2024-0436 | `paste 1.0.15` | Previously transitive through the optional TUI; absent from the current lockfile. |
| RUSTSEC-2026-0002 | `lru 0.12.5` | Previously transitive through the optional TUI; current lockfile uses `lru 0.18.2`. |

## 4. Follow-ups

1. Repeat all four lockfile scans after dependency changes and before release.
2. Keep the CI advisory job blocking; no advisory IDs are ignored.
3. Consider `cargo-deny` for license and ban-list enforcement at a later phase.
