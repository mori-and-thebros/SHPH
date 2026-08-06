# SHPH Milestone Scorecard & Roadmap Burn-down

The active post-baseline delivery sequence is now **Phase C: Shroud lab
completion**, **Phase D: hardening and optimization**, **Phase D-A:
pre-completion audit**, **Phase E: big move/release readiness**, and
**Phase F: Windows TUN delivery**. These are sequential gates; local WSL2
benchmark evidence does not satisfy native-TUN or two-host acceptance criteria.

The 2026-08-05 checkpoint adds paired local evidence from WSL2/Linux and
native Windows for workspace version `0.5.0-dev.0`. It verifies the local
build, test, benchmark, and profile-comparison paths; it does not promote
local in-memory or lifecycle measurements into live TUN/VPN claims.

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

## Phase C — Shroud Lab Completion (complete for controlled lab scope)

| Sub-gate | Status | Evidence |
| --- | --- | --- |
| Core cell invariants and frame-type validation | **Complete** | `shph-core/src/framing.rs`; current core test totals from `cargo test -p shph-core` |
| Profile-wide data/chaff round trips | **Complete** | `cargo test -p shph-core framing::tests::every_profile_round_trips_data_and_chaff` |
| User payload versus encrypted-cell capacity separation | **Complete** | `encode_data_cell` versus `encode_cell`; transport Shroud round trips pass |
| Malformed, truncation, oversize, replay, and mismatch matrix | **Complete** | `cargo test -p shph-transport quic_shroud`; 6 focused tests pass |
| Shroud overhead/tail benchmark evidence | **Complete** | Separate `shroud_framing`, `shroud_aead`, and morphology rows recorded in `docs/SHROUD2_BENCHMARK_RESULTS_2026-08-04.md`; historical WSL2 baseline remains in `docs/BENCHMARK_RESULTS_2026-07-28.md` |
| Profile selection and non-claims documentation | **Complete** | Explicit env-only activation, resolver tests, and lab/non-claims text in `docs/LAB_PROTOTYPES.md` |

**Phase C burn-down: 6 / 6 sub-gates complete (100%).**

## Phase D — Hardening and Optimization (in progress)

| Work item | Status | Evidence |
| --- | --- | --- |
| Fuzz targets and malformed-input regression pass | **Complete for lab evidence** | `fuzz/README.md`, `docs/PHASE_D_HARDENING_2026-07-28.md`; four 20-second no-crash campaigns |
| QUIC-shim tail repeatability check | **Complete for lab evidence** | Two 5,000-sample runs recorded in `docs/PHASE_D_HARDENING_2026-07-28.md` |
| Secure-default versus classical-lab benchmark separation | **Complete for lab evidence** | Profile comparison recorded in `docs/PHASE_D_HARDENING_2026-07-28.md` |
| Static and dependency review | **Complete for current checkout** | Strict fmt/Clippy/tests/build, fuzz manifest check, `cargo audit --no-fetch`; two accepted optional-TUI advisories remain |
| Allocation/RSS optimization pass | **Complete for confirmed lab hotspots** | Borrowed Shroud decode plus stack-backed handshake transcript/HKDF; measured in `docs/PHASE_D_HARDENING_2026-07-28.md` |
| Native Linux TUN lifecycle implementation | **Hardened; async CLI bridge integrated; capability-gated** | `TunDevice::open_native`, `AsyncTunDevice`, bounded async CLI bridge, 15 `shph-tun` tests, complete-write/zeroizing-buffer hardening, one device remains open through `up` setup/reconnect |
| Native Linux namespace smoke and lifecycle automation | **Implemented; isolated WSL2 smoke passed** | `scripts/native_tun_namespace_test.sh`; `scripts/benchmark_native_tun.sh`; 20/20 lifecycle samples passed (`min=59.1ms`, `p50=189.0ms`, `p95=348.9ms`, `max=349.6ms`) |
| Standards-QUIC Linux native-TUN bridge | **Implemented; live forwarding evidence pending** | RFC 9221 DATAGRAM bridge in `shph-transport/src/standards_tun.rs`; Linux `up --transport quic-standard`; malformed/IPv4/IPv6 boundary checks |
| Windows Wintun backend | **Wired; host integration pending** | Signed application-local loader, elevation check, bounded ring, packet release/commit wrappers, bounded event waits, shared-session cloning, public `TunDevice` integration, and RAII teardown |
| Paired WSL2/native-Windows benchmark campaign | **Complete for local lab scope** | `docs/BENCHMARK_RESULTS_2026-08-05.md`; raw captures under `benchmark-runs/2026-08-05-wsl2-final/` and `benchmark-runs/2026-08-05-windows-final/` |
| Native TUN/two-host operator evidence | **Pending operator host** | `scripts/benchmark_operator.sh` emits explicit prerequisite `SKIP` records |

**Phase D status:** local implementation and validation are complete for the
controlled scope, but the phase is not delivery-complete until native Linux
two-host forwarding and privileged Windows Wintun packet evidence exist.

## Phase D-A — Pre-Completion Audit (remediation complete)

| Gate | Status | Evidence |
| --- | --- | --- |
| Audit input snapshot and scope | **Complete** | public review findings tracked through the security and hardening documentation |
| Finding register and severity dispositions | **Complete** | remediation status summarized in `docs/HARDENING.md` |
| Remediation and focused regressions | **Complete** | High/Medium/Low fixes plus handshake, malformed-peer, standards-QUIC, JA4, and TUN regressions |
| Full post-remediation validation and parity | **Complete** | `docs/evidence/GATE_EVIDENCE.md`, Windows GNU cross-target evidence, and configured mirror verification |
| Audit disposition publication | **Complete** | This disposition document; native Windows execution remains an explicit release gate |

## Phase E — Big Move / Release Readiness (not complete)

| Gate | Status | Evidence |
| --- | --- | --- |
| Paired benchmark/evidence bundle | **Complete for `0.5.0-dev.0`** | `docs/BENCHMARK_RESULTS_2026-08-05.md` and `docs/evidence/WINDOWS_NATIVE_VALIDATION_2026-08-05.md` |
| Claims, limitations, and profile labels | **Complete for current lab scope** | `ROADMAP_OSS_AND_DELIVERY.md`, `docs/RISK_MATRIX.md`, benchmark report |
| Final release snapshot and SemVer tag | **Pending** | Requires completion of the remaining host-gated TUN evidence and final release checklist |
| Release-candidate reproducibility review | **Pending** | Run after the final claims/version/commit freeze |

## Phase F — Windows TUN Delivery (host-gated)

| Gate | Status | Evidence |
| --- | --- | --- |
| Wintun backend implementation | **Wired; not runtime-validated** | `docs/NATIVE_TUN_STATUS_2026-08-04.md`; `shph-tun/src/windows.rs` |
| Privileged adapter lifecycle and packet I/O | **Pending** | Requires approved signed `wintun.dll` and elevated Windows host |
| Windows route/DNS, reconnect, and teardown matrix | **Pending** | Must be exercised on the live adapter |
| Two-node Windows tunnel and performance evidence | **Pending** | Must remain separate from local benchmark and WSL2 results |

## Measurable quality signals (reproducible)

These numbers regenerate from a clean checkout. Run the command to verify.

| Signal | Value | Reproduce |
| ------ | ----- | --------- |
| Workspace tests passing | **WSL2/Linux: 191; native Windows: 176** | `cargo test --workspace --locked` |
| Core security/crypto tests | Current totals in evidence | `cargo test -p shph-core` |
| Transport tests | Current totals in evidence | `cargo test -p shph-transport` |
| CLI unit + integration tests | current totals in evidence | `cargo test -p shph-cli` |
| Lint cleanliness | 0 warnings (warnings = errors) | `cargo clippy --workspace --all-targets -- -D warnings` |
| Format cleanliness | clean | `cargo fmt --all -- --check` |
| Reproducible build | Linux and native Windows release builds pass | `cargo build --workspace --release --locked` |
| CI matrix | Linux + Windows | `.github/workflows/ci.yml` |
| Paired benchmark report | **Complete for local lab scope** | `docs/BENCHMARK_RESULTS_2026-08-05.md` |

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
Phase D cannot be marked complete until Phase D-A is closed.
