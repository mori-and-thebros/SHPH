# AI Handoff Notes for SHPH

This repository is an active prototype-to-production hardening effort with strict phase-gating.

## Working directories
- Primary: `/home/mori/SHPH_working_copy`
- Mirror: `D:\FUNDING NEEDED\snap-shroud-rs`

## Primary conventions
- Do **not** mark phase completion unless every phase task and evidence criterion is complete.
- Prefer minimal, conservative edits; fix root causes only.
- Keep docs/tests aligned with code changes and mirror updates.

## Useful quick commands
- `cargo fmt --all`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`

## Environment limitation to watch
- Loopback TCP binds can fail in some containers with `Operation not permitted`.
- Transport integration tests were updated to skip on explicit bind-permission-denied errors.

## Current status
- Phase A.1 (Delivery-Critical Networking): **Complete**.
- Phase A.2 (Control-Plane Reliability): **Complete**.
- Phase A.3 (Security Baseline for Deployment): **Complete**.
- Phase A.4 (Ops, Packaging, and Trust): **Complete**.
- Phase A.5 (Documentation for Funders): **Complete**.
- **Phase A is COMPLETE (5/5).**
- Phase B.1 (External Review Readiness): **Complete**. Added `scripts/demo.sh`,
  `scripts/capture_evidence.sh` (writes `docs/evidence/GATE_EVIDENCE.md`),
  `docs/RELEASE_PROCEDURE.md`, `docs/LEGAL_COMPLIANCE.md`, `CHANGELOG.md`.
  The tree is now a git repository; the first checkpoint tag
  `checkpoint-phaseA-1.0.0` closes Phase A + Phase B.1.
- Phase B.2 (Stability Before Feature Expansion): **Complete**. Added
  `docs/API_STABILITY.md`, `docs/SECURITY_REPORTING.md`, `docs/SUPPLY_CHAIN_SCAN.md`;
  fixed the direct `anyhow` scanner finding (1.0.102->1.0.103), bumped
  `ratatui` 0.27->0.28.1, wired `cargo audit` into CI. **Phase B is COMPLETE.**
- Completed improvements are present in both trees; do not revert test skip guards unless host policy is confirmed and safe.

## Next engineer starting points
1. Sync the changed files to the Windows mirror `D:\\FUNDING NEEDED\\snap-shroud-rs`
   via `./scripts/sync_mirror.sh --to-windows` and run `cargo fmt --all`,
   `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`
   there to confirm parity.
2. Re-run `./scripts/capture_evidence.sh` after any change so
   `docs/evidence/GATE_EVIDENCE.md` stays current.
3. The first checkpoint `checkpoint-phaseA-1.0.0` (commit `e0a5949`) is cut.
   Future checkpoints: refresh evidence + changelog, then
   `git tag -a checkpoint-phaseX-Y.Y.Z` per `docs/RELEASE_PROCEDURE.md`.
4. Wire Windows graceful shutdown (`SetConsoleCtrlHandler` via `windows-sys`) - the
   tracked A.2 follow-up; needs the Windows toolchain to verify.
5. Next roadmap phase is **B.2 (Stability Before Feature Expansion)** — still locked
   pending sign-off. Re-check `docs/FUNDING_SPRINT_BOARD.md`.
