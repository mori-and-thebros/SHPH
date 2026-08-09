# Maintainer Notes

This document records public project status and release-validation guidance.
It is kept concise so it can be reviewed alongside the source and tests.

## Project conventions

- Do **not** mark phase completion unless every phase task and evidence criterion is complete.
- Prefer minimal, conservative edits; fix root causes only.
- Keep documentation and tests aligned with code changes.

## Useful quick commands
- `cargo fmt --all`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`

## Environment notes

- Loopback TCP binds can fail in restricted containers with `Operation not permitted`.
- Transport integration tests skip only on explicit bind-permission-denied errors.

## Current status (2026-08-09)
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
- Phase C (Shroud lab completion): **Complete for controlled lab scope**.
- Phase D (hardening and optimization): **Implementation complete for the
  current non-TUN lab scope**; the roadmap gate remains open for native
  TUN/two-host operator evidence.
- Phase D-A (pre-completion audit): **Remediation complete**; post-remediation
  validation and parity evidence must stay aligned with the current tree.
- Phase E (big move/release readiness): **Not started**.
- Phase F (Windows TUN delivery): **Deferred final phase**.
- Current workspace version: `0.6.0-dev.0`. Latest Shroud report:
  `docs/SHROUD2_BENCHMARK_RESULTS_2026-08-04.md`.
- Latest native Windows validation:
  `docs/evidence/WINDOWS_NATIVE_VALIDATION_2026-08-09_POST_LOADER.md` (180
  workspace tests passed; elevated Wintun adapter/session lifecycle reached
  teardown with no residue; route-rollback fix awaits a clean elevated rerun).
- Do not revert test skip guards unless the host policy is confirmed and safe.

## Validation checklist
1. Run the Linux validation gates and refresh generated evidence after changes.
2. Run `validate_windows_tun.ps1` from an elevated PowerShell session with
   a current-compatible signed `wintun.dll` beside the application.
3. If maintaining a second checkout, synchronize source and documentation with
   `scripts/sync_mirror.sh`, then run its verification mode.
4. Keep the root `Cargo.lock` as the intentional platform-specific difference;
   benchmark and fuzz lockfiles are mirrored.
5. Verify Windows graceful shutdown and Wintun integration with the native
   Windows toolchain; cross-compilation does not replace native execution.
6. Before a release, re-check `docs/MILESTONE_SCORECARD.md`,
   `docs/RELEASE_PROCEDURE.md`, and the current audit disposition.
