# SHPH Milestone Scorecard & Roadmap Burn-down

Measurable, verifiable progress against the funding roadmap. Each row ties a
milestone to its acceptance evidence and a command you can run to reproduce it.
This is the single source of truth for "how far along is SHPH?"

## Phase A — Production Foundations

| Phase | Title | Status | Evidence (run to verify) |
| ----- | ----- | ------ | ------------------------ |
| A.1 | Delivery-Critical Networking | **Complete** | `cargo test -p shph-cli --test cli_up_session_mode`; graceful-shutdown log in `docs/TESTING.md` |
| A.2 | Control-Plane Reliability | **Complete** | `cargo test -p shph-cli --test cli_control_plane`; preflight rejection in `docs/TESTING.md` |
| A.3 | Security Baseline for Deployment | **Complete** | `cargo test -p shph-core crypto::tests::replayed_frame_is_rejected_fail_closed` (replay, EOF, malformed-frame suite) |
| A.4 | Ops, Packaging, and Trust | **Complete** | `SECURITY.md`, `CONTRIBUTING.md`, `.github/workflows/ci.yml`, `docs/REPRODUCIBILITY.md`, `LICENSE-*` present |
| A.5 | Documentation for Funders | **Complete** | This doc + `docs/FUNDERS.md`, `docs/RISK_MATRIX.md`, `docs/SUPPORT_AND_MAINTENANCE.md` |

**Phase A burn-down: 5 / 5 complete (100%).**

## Phase B — Funding Validation & Audit Preparation (complete)

| Phase | Title | Status | Evidence (run to verify) |
| ----- | ----- | ------ | ------------------------ |
| B.1 | External Review Readiness | **Complete** | `docs/FUNDERS.md`, reproducible demo scripts, `docs/REPRODUCIBILITY.md` |
| B.2 | API Stability & Supply-Chain Scan | **Complete** | `docs/API_STABILITY.md`, `docs/SECURITY_REPORTING.md`, `docs/SUPPLY_CHAIN_SCAN.md`; `cargo audit` clean (0 vulns, 2 accepted advisories) |

**Phase B burn-down: 2 / 2 complete (100%).** Tagged at `checkpoint-phaseB-1.0.0`.

## Measurable quality signals (reproducible)

These numbers regenerate from a clean checkout. Run the command to verify.

| Signal | Value | Reproduce |
| ------ | ----- | --------- |
| Workspace tests passing | **83 passed, 0 failed** | `cargo test --workspace` |
| Core security/crypto tests | 48 (39 unit + 9 integration) | `cargo test -p shph-core` |
| Transport tests | 5 | `cargo test -p shph-transport` |
| CLI unit + integration tests | 27 (19 unit + 8 integration) | `cargo test -p shph-cli` |
| Lint cleanliness | 0 warnings (warnings = errors) | `cargo clippy --workspace --all-targets -- -D warnings` |
| Format cleanliness | clean | `cargo fmt --all -- --check` |
| Reproducible build | yes (locked) | `cargo build --workspace --locked` |
| CI matrix | Linux + Windows | `.github/workflows/ci.yml` |

> Test counts grow as features land; update this table when you update the
> scorecard. The "0 failed" invariant is the binding claim.

## Definition of "complete" (binding)

A phase is complete only when **all** of these hold:

1. Every task in `ROADMAP_OSS_AND_DELIVERY.md` for that phase is done.
2. Every acceptance/exit criterion is met.
3. Evidence (test command + result) is recorded in `docs/FUNDING_SPRINT_BOARD.md`
   and `docs/TESTING.md`.
4. The change is mirrored and parity-verified across both trees
   (`./scripts/sync_mirror.sh --verify`).
5. `cargo fmt`, `cargo clippy -D warnings`, and `cargo test --workspace` are
   green.

No phase is ever marked complete by estimate or intention — only by evidence.
