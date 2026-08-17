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
cargo audit --deny warnings 2>&1 | tee docs/evidence/CARGO_AUDIT.txt
```

Run this from the repository root after every lockfile change. The CI workflow
uses the same blocking policy and does not ignore advisory IDs.

## 3. Current policy (2026-08-15)

The previous 2026-08-05 report is historical. The current root lockfile
resolves `ratatui 0.30.2` and `lru 0.18.2`; it contains neither the previously
reported `paste` package nor `lru 0.12.5`.

The captured evidence must be regenerated after the next successful
`cargo-audit` installation on a host with a working linker. Until then, this
file describes the policy and current lockfile state, not a newly reproduced
advisory result.

### Historical advisories

| Advisory | Historical crate | Historical disposition |
| -------- | ---------------- | ---------------------- |
| RUSTSEC-2024-0436 | `paste 1.0.15` | Previously transitive through the optional TUI; absent from the current lockfile. |
| RUSTSEC-2026-0002 | `lru 0.12.5` | Previously transitive through the optional TUI; current lockfile uses `lru 0.18.2`. |

## 4. Follow-ups

1. Regenerate `docs/evidence/CARGO_AUDIT.txt` after dependency changes.
2. Keep the CI advisory job blocking; no advisory IDs are ignored.
3. Consider `cargo-deny` for license and ban-list enforcement at a later phase.
