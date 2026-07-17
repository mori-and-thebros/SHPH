# SHPH Supply-Chain Scan & Advisory Triage

This is the Phase B.2 "resolve high-impact/low-effort CVE-risk issues
identified by scanners" deliverable. It records the scanner used, the captured
output, and the triage of every advisory found.

## 1. Scanner

- **Tool:** `cargo-audit` (RustSec advisory database).
- **Command:** `cargo audit` (run from the workspace root against `Cargo.lock`).
- **Captured output:** `docs/evidence/CARGO_AUDIT.txt` (regenerate after any
  dependency change; do not hand-edit).

## 2. How to reproduce

```bash
source "$HOME/.cargo/env"   # if cargo is not on PATH
cargo audit 2>&1 | tee docs/evidence/CARGO_AUDIT.txt
```

`cargo-audit` is a one-time `cargo install cargo-audit --locked` (not bundled,
to avoid adding a build-time dependency).

## 3. Triage (as of checkpoint-phaseB-1.0.0)

Scanned **200 crate dependencies**. Result: **0 vulnerabilities**, 2
advisory **warnings**, both transitive and isolated to the optional TUI.

| Advisory | Crate | Severity | Path | Disposition |
| -------- | ----- | -------- | ---- | ----------- |
| RUSTSEC-2024-0436 | `paste 1.0.15` | unmaintained | `ratatui` → `shph-tui` (optional) | Accepted: build-time proc-macro, optional-TUI only, no runtime impact. |
| RUSTSEC-2026-0002 | `lru 0.12.5` | unsound `IterMut` | `ratatui` → `shph-tui` (optional) | Accepted: unsound API (`IterMut`) not used by the TUI; optional component. |

### Resolved this phase

| Advisory | Crate | Action |
| -------- | ----- | ------ |
| RUSTSEC-2026-0190 | `anyhow` unsound `downcast_mut` | **Fixed:** bumped `anyhow 1.0.102 → 1.0.103`; re-audit clean. Direct workspace dependency; `downcast_mut` was never called by SHPH. |

## 4. Why the two remaining warnings are accepted

Both arrive **only** through `ratatui`, which is a dependency of `shph-tui` — an
**optional** terminal UI that is not part of the core transport, CLI, or
crypto path. They do not reach `shph-core`, `shph-transport`, `shph-cli`, or
`shph-config`. `paste` is a compile-time macro (no runtime code shipped); `lru`'s
unsoundness requires `IterMut`, which the TUI does not invoke. Removing them
requires a `ratatui` release that drops them; this is tracked as a follow-up
rather than a funding blocker.

## 5. Follow-ups (tracked, non-blocking)

1. Watch for a `ratatui` release that drops `paste` / `lru`; bump when available.
2. Keep the CI advisory job blocking. It explicitly ignores only the two
   accepted TUI advisories above; new warnings or vulnerabilities fail CI.
3. Consider `cargo-deny` for license + ban-list enforcement at a later phase.
