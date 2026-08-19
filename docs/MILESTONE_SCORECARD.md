# SHPH Milestone Scorecard & Roadmap Burn-down

The active post-baseline delivery sequence is now **Phase C: Shroud lab
completion**, **Phase D: hardening and optimization**, **Phase D-A:
pre-completion audit**, **Phase E: big move/release readiness**, and
**Phase F: Windows TUN delivery**. These are sequential gates; local WSL2
benchmark evidence does not satisfy native-TUN or two-host acceptance criteria.

The August 8-9, 2026 validation refresh adds native Windows workspace,
Windows-only test, benchmark, and post-loader adapter/session smoke evidence
from the prior `0.6.0-dev.0` line. The current `0.6.3-dev.3` prerelease carries
subsequent hardening, while the scorecard still does not promote local
in-memory measurements, a single-host smoke, or a failed two-node campaign
into live TUN/VPN claims.

Measurable, verifiable progress against the funding roadmap. Each row ties a
milestone to its acceptance evidence and a command you can run to reproduce it.
This is the single source of truth for "how far along is SHPH?"

The product boundary is defined by `docs/SUPPORT_MATRIX.md`. The release gate
and its PASS/FAIL/SKIP semantics are defined by
`docs/RELEASE_READINESS.md`; security evidence is mapped in
`docs/SECURITY_EVIDENCE.md`. Experimental transports do not silently count as
release-profile support.

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
| B.2 | API Stability & Supply-Chain Scan | **Policy complete; evidence refresh pending** | `docs/API_STABILITY.md`, `docs/SECURITY_REPORTING.md`, `docs/SUPPLY_CHAIN_SCAN.md`; CI uses blocking `cargo audit --deny warnings` |

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
| Static and dependency review | **Remediation complete; current gate rerun pending** | Strict fmt/Clippy/tests/build, standalone fuzz/benchmark checks, and blocking `cargo audit --deny warnings` |
| Allocation/RSS optimization pass | **Complete for confirmed lab hotspots** | Borrowed Shroud decode plus stack-backed handshake transcript/HKDF; measured in `docs/PHASE_D_HARDENING_2026-07-28.md` |
| Native Linux TUN lifecycle implementation | **Hardened; async CLI bridge integrated; capability-gated** | `TunDevice::open_native`, `AsyncTunDevice`, bounded async CLI bridge, 15 `shph-tun` tests, complete-write/zeroizing-buffer hardening, one device remains open through `up` setup/reconnect |
| Opt-in host leak containment and MTU/MSS hardening | **Implemented; privileged execution and crash-leak evidence pending** | `shph up --killswitch`, `--killswitch-dry-run`, `--mss-clamp`; `shph-tun` firewall planners and Windows WFP backend; focused CLI/TUN tests |
| Native Linux namespace smoke and lifecycle automation | **Implemented; isolated WSL2 smoke passed** | `scripts/native_tun_namespace_test.sh`; `scripts/benchmark_native_tun.sh`; 20/20 lifecycle samples passed (`min=59.1ms`, `p50=189.0ms`, `p95=348.9ms`, `max=349.6ms`) |
| Standards-QUIC Linux native-TUN bridge | **Implemented; live forwarding evidence pending** | RFC 9221 DATAGRAM bridge in `shph-transport/src/standards_tun.rs`; Linux `up --transport quic-standard`; malformed/IPv4/IPv6 boundary checks |
| Windows Wintun backend | **Wired; adapter/session smoke passed; packet and two-host evidence pending** | Application-local SHA-256-pinned loader, elevation check, bounded ring, packet release/commit wrappers, bounded event waits, shared-session cloning, public `TunDevice` integration, RAII teardown, and `docs/evidence/WINDOWS_NATIVE_VALIDATION_2026-08-09_POST_LOADER.md`. The Windows validator separately requires valid Authenticode before staging the DLL. |
| Windows-local `0.6.1-dev` benchmark baseline | **Complete for local lab scope** | `docs/BENCHMARK_RESULTS_2026-08-14.md`; both profiles, full suite, 5,000 samples, 100,000 frames; native TUN disabled |
| Paired WSL2/native-Windows benchmark campaign | **Complete for local lab scope** | `docs/BENCHMARK_RESULTS_2026-08-05.md` plus the latest native Windows gate record `docs/evidence/WINDOWS_NATIVE_VALIDATION_2026-08-09_POST_LOADER.md`; raw captures remain under ignored `benchmark-runs/` paths |
| Native TUN/two-host operator evidence | **Pending operator host** | `scripts/benchmark_operator.sh` emits explicit prerequisite `SKIP` records |

**Phase D status:** local implementation and validation are complete for the
controlled scope, but the phase is not delivery-complete until native Linux
two-host forwarding and privileged Windows Wintun packet evidence exist.

## Phase D-A — Pre-Completion Audit (remediation complete)

| Gate | Status | Evidence |
| --- | --- | --- |
| Public assessment scope and risk register | **Complete** | `SECURITY.md`, `docs/RISK_MATRIX.md`, and `docs/VALIDATION_FOLLOWUP_2026-08-05.md`; private review material is kept outside the public checkout |
| Finding remediation and regression evidence | **Complete for documented scope** | `docs/VALIDATION_FOLLOWUP_2026-08-05.md`, `docs/evidence/GATE_EVIDENCE.md`, and focused workspace tests |
| Remediation and focused regressions | **Complete** | High/Medium/Low fixes plus handshake, malformed-peer, standards-QUIC, JA4, and TUN regressions |
| Full post-remediation validation and parity | **Pending dedicated validation-lane rerun** | Re-run the root, standalone, advisory, and native-host gates after the current fixes |
| Public limitations and follow-up publication | **Complete** | `SECURITY.md`, `docs/RISK_MATRIX.md`, and `docs/VALIDATION_FOLLOWUP_2026-08-05.md`; native Windows execution remains an explicit release gate |

## Phase E — Big Move / Release Readiness (not complete)

| Gate | Status | Evidence |
| --- | --- | --- |
| Authoritative release profile and support matrix | **Complete for current scope** | `docs/SUPPORT_MATRIX.md` |
| Reproducible release-readiness collector | **Implemented; dedicated validation-lane refresh pending** | `scripts/release_readiness.ps1`, `docs/RELEASE_READINESS.md` |
| Security evidence and publication-redaction pack | **Implemented; dedicated validation-lane refresh pending** | `scripts/security_evidence.ps1`, `docs/SECURITY_EVIDENCE.md` |
| Paired benchmark/evidence bundle | **Complete for the `0.6.0-dev.0` development line** | `docs/BENCHMARK_RESULTS_2026-08-05.md` and `docs/evidence/WINDOWS_NATIVE_VALIDATION_2026-08-09_POST_LOADER.md` |
| Windows-local `0.6.1-dev` benchmark baseline | **Complete for local lab scope** | `docs/BENCHMARK_RESULTS_2026-08-14.md`; Wintun/TUN and two-host claims remain out of scope |
| Claims, limitations, and profile labels | **Complete for current lab scope** | `ROADMAP_OSS_AND_DELIVERY.md`, `docs/RISK_MATRIX.md`, benchmark report |
| Final release snapshot and SemVer tag | **Pending** | Requires completion of the remaining host-gated TUN evidence and final release checklist |
| Release-candidate reproducibility review | **Pending** | Run after the final claims/version/commit freeze |

## Phase F — Windows TUN Delivery (host-gated)

| Gate | Status | Evidence |
| --- | --- | --- |
| Wintun backend implementation | **Wired; Windows unit-tested; adapter/session smoke passed** | `docs/evidence/WINDOWS_NATIVE_VALIDATION_2026-08-09_POST_LOADER.md`; `shph-tun/src/windows.rs` |
| Privileged adapter lifecycle and packet I/O | **Pending** | Adapter/session open and teardown passed; packet send/receive and two-node forwarding still require an elevated Windows host campaign |
| Windows route/DNS, reconnect, and teardown matrix | **Pending** | Must be exercised on the live adapter |
| Two-node Windows tunnel and performance evidence | **Pending** | Must remain separate from local benchmark and WSL2 results |

## Measurable quality signals (reproducible)

These numbers regenerate from a clean checkout. Run the command to verify.

| Signal | Value | Reproduce |
| ------ | ----- | --------- |
| Workspace tests passing | **WSL2/Linux: 191; native Windows: 180** | `cargo test --workspace --locked` |
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
3. Evidence (test command + result) is recorded in the reviewed evidence
   artifacts under `docs/evidence/` and `docs/TESTING.md`.
4. The change is mirrored and parity-verified across both trees
   (`./scripts/sync_mirror.sh --verify`).
5. `cargo fmt`, `cargo clippy -D warnings`, and `cargo test --workspace` are
   green.
6. The support matrix, README, risk matrix, and release-readiness report agree
   on what is supported and what remains host-gated.

No phase is ever marked complete by estimate or intention — only by evidence.
Phase D cannot be marked complete until Phase D-A is closed.
