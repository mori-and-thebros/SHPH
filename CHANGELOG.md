# Changelog

All notable changes to SHPH are documented here. This project follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) principles, adapted to
the phase-gated funding roadmap in `ROADMAP_OSS_AND_DELIVERY.md`.

Gates referenced below: `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace` (0 failed), `cargo build --workspace --locked`.

## [Phase B.1] — External Review Readiness (in progress, 2026-06-29)

### Added
- `scripts/demo.sh` — reproducible demo + failure-mode walk-through (happy,
  bad-cidr, unreachable) running entirely on loopback.
- `scripts/capture_evidence.sh` — regenerates `docs/evidence/GATE_EVIDENCE.md`
  by running every mandatory gate and summing passed/failed/ignored totals.
- `docs/evidence/GATE_EVIDENCE.md` — captured acceptance-gate evidence log.
- `docs/RELEASE_PROCEDURE.md` — funding-checkpoint tagging procedure + manifest.
- `docs/LEGAL_COMPLIANCE.md` — OSS artifact handling legal/compliance checklist.

### Fixed
- `scripts/capture_evidence.sh` totals: replaced the broken nested-quoted `awk`
  totals line with a shell-summed parser (`PASSED=` / `FAILED=` / `IGNORED=`).
- Evidence script no longer aborts on a single failing gate; all gates are now
  reported before the script returns.

## [Phase A.5] — Documentation for Funders (2026-06-29)

### Added
- `docs/FUNDERS.md` — what SHPH is / is-not for grant reviewers.
- `docs/RISK_MATRIX.md` — severity-rated current limits + explicit exclusions.
- `docs/MILESTONE_SCORECARD.md` — phase scorecard + reproducible quality signals.
- `docs/SUPPORT_AND_MAINTENANCE.md` — support tiers, SLA, maintenance cadence.

## [Phase A.4] — Ops, Packaging, and Trust (2026-06-25)

### Added
- `LICENSE-MIT`, `LICENSE-APACHE` (match `Cargo.toml` `MIT OR Apache-2.0`).
- `SECURITY.md` — disclosure process, threat model, non-claims matrix.
- `CONTRIBUTING.md` — build/test, style, phase-gating, release checklist.
- `.github/workflows/ci.yml` — Linux + Windows fmt/clippy/build/test matrix.
- `docs/REPRODUCIBILITY.md` — lockfile / `--locked` / `cargo audit` discipline.
- `scripts/sync_mirror.sh` + `docs/SYNC.md` — rsync mirror tooling with parity checks.

## [Phase A.3] — Security Baseline for Deployment (2026-06-24)

### Added
- Anti-replay in `ReceiveCipher` (`shph-core/src/crypto.rs`, monotonic `last_nonce`).
- Bounded accept loop `TCP_HANDSHAKE_ATTEMPTS = 5` (`shph-transport`).
- Security regression tests for replay, EOF, and malformed frames.

### Fixed
- Removed remaining production `.unwrap()`/`.expect()` (kept only in `#[cfg(test)]`).
- `shph-core/src/net.rs` panic on invalid endpoint removed; fail-closed.

## [Phase A.2] — Control-Plane Reliability (2026-06-24)

### Added
- `build_control_plane_plan` atomic preflight (validate all CIDRs/DNS before mutation).
- Error-preserving `restore_dns` and robust multi-error `ControlPlaneGuard::cleanup`.

## [Phase A.1] — Delivery-Critical Networking (2026-06-24)

### Added
- Graceful SIGINT/SIGTERM shutdown (`shph-cli/src/shutdown.rs`).
- Poll-driven stdin so the connect loop observes shutdown within ~200ms.
- Session lifecycle trail (`Session id`/`start`/`end`/`Final metrics`) on all `up` paths.
- `MetricsCollector` (bytes/packets/errors sent+recv) wired into one-shot and loop paths.

### Notes
- Windows graceful shutdown via `SetConsoleCtrlHandler` tracked as a follow-up
  (needs `windows-sys` + the Windows toolchain to verify).
