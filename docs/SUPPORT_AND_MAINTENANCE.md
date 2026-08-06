# SHPH Support Model & Maintenance Plan

How SHPH is supported and maintained, for funders and adopters evaluating
long-term viability.

## Support tiers

| Tier | Audience | Channel | SLA / expectation |
| ---- | -------- | ------- | ----------------- |
| Community | anyone | GitHub issues (non-security), discussions | Best-effort, volunteer response |
| Security | anyone reporting a vuln | private advisory / maintainer email (see `SECURITY.md`) | 5-business-day ack, coordinated ≤90-day disclosure |
| Maintainer | core `SHPH Team` | internal | owns merges, releases, policy |

SHPH is currently a **community-supported, best-effort** project. There is no
paid 24/7 support or uptime guarantee. Funders evaluating support should treat
the `SECURITY.md` disclosure SLA as the firmest commitment.

## What is supported

- Building and testing from `main` on Linux and Windows stable Rust.
- The TCP transport path (stable).
- Config-driven `up`/`listen`/`connect`/`send-once`/`recv-once` workflows.
- The documented control-plane dry-run and safe-apply modes.

## What is explicitly unsupported (today)

- The experimental transports (QUIC shim, offline-mesh, data-mule) beyond
  "builds and basic tests pass".
- Production deployment in hostile networks (see `docs/RISK_MATRIX.md`).
- Any platform other than Linux and Windows desktop/toolchain targets.

## Maintenance plan

### Cadence

- **Continuous:** `main` must stay green — `cargo fmt`, `cargo clippy -D warnings`,
  and `cargo test --workspace` pass after every merge (enforced by
  `.github/workflows/ci.yml`).
- **Per-release:** follow `CONTRIBUTING.md`'s release checklist; bump version in
  workspace `Cargo.toml`, update `Cargo.lock`, run `cargo audit`, mirror to the
  Windows tree, and verify parity (`./scripts/sync_mirror.sh --verify`).
- **Dependency hygiene:** run `cargo audit` before each release and on any
  `Cargo.lock` change; review `cargo tree` diffs. (Automating `cargo audit` in
  CI is a tracked next step — see `docs/REPRODUCIBILITY.md`.)

### Roles & governance

- **Maintainers (`SHPH Team`)** approve merges/releases, own security disclosure,
  and update this plan. Decision style: transparent, minimal-scope, honest
  capability claims (see `CONTRIBUTING.md`).
- **Contributors** follow the PR flow in `CONTRIBUTING.md` and the phase-gating
  discipline in `docs/FUNDING_SPRINT_BOARD.md`.

### Phase-gating (governs what "done" means)

Progress is phase-gated; a phase advances only when its acceptance criteria and
evidence are satisfied and mirrored. See `docs/MILESTONE_SCORECARD.md` for the
binding definition of "complete" and the current burn-down.

### Backwards compatibility

SHPH is pre-1.0 (`0.1.0`). Breaking changes are allowed but must be documented
in release notes. Config/command surfaces should change conservatively.

### Sustainability signals for funders

- All claims are test-backed and reproducible (`docs/MILESTONE_SCORECARD.md`).
- Public disclosure + maintenance process exists (`SECURITY.md`, this doc).
- Reproducible, locked builds (`docs/REPRODUCIBILITY.md`).
- Two-tree mirror with parity verification (`docs/SYNC.md`).
