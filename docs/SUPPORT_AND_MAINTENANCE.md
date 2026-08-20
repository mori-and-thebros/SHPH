# SHPH Support Model & Maintenance Plan

How SHPH is supported and maintained for adopters and contributors evaluating
long-term viability.

## Support tiers

| Tier | Audience | Channel | SLA / expectation |
| ---- | -------- | ------- | ----------------- |
| Community | anyone | GitHub issues (non-security), discussions | Best-effort, volunteer response |
| Security | anyone reporting a vuln | private advisory / maintainer email (see `SECURITY.md`) | 5-business-day ack, coordinated ≤90-day disclosure |
| Maintainer | core `SHPH Team` | maintainer coordination | owns merges, releases, policy |

SHPH is currently a **community-supported, best-effort** project. There is no
paid 24/7 support or uptime guarantee. Operators should treat the `SECURITY.md`
disclosure SLA as the firmest commitment.

The product support boundary is maintained in `docs/SUPPORT_MATRIX.md`.
Experimental transports are intentionally excluded from the release profile,
and a host-gated result is not treated as a supported deployment.

## What is supported

- Building and testing from `main` on Linux and Windows stable Rust.
- The TCP transport path (stable).
- Config-driven `up`/`listen`/`connect`/`send-once`/`recv-once` workflows.
- The documented control-plane dry-run and safe-apply modes.
- The release-profile TCP lane and its separately documented host-gated TUN
  acceptance procedures.

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
- **Dependency hygiene:** run `cargo audit --deny warnings` before each
  release and on any `Cargo.lock` change; review `cargo tree` diffs. The
  blocking advisory job is enforced in `.github/workflows/ci.yml`; see
  `docs/REPRODUCIBILITY.md`.

### Roles & governance

- **Maintainers (`SHPH Team`)** approve merges/releases, own security disclosure,
  and update this plan. Decision style: transparent, minimal-scope, honest
  capability claims (see `CONTRIBUTING.md`).
- **Contributors** follow the PR flow in `CONTRIBUTING.md` and the validation
  discipline in `docs/RELEASE_READINESS.md`.

### Validation (governs what "done" means)

Work is considered complete only when the relevant acceptance criteria and
evidence are satisfied. See `docs/RELEASE_READINESS.md` for the engineering
definition of release readiness.

### Backwards compatibility

SHPH is pre-1.0 (`0.1.0`). Breaking changes are allowed but must be documented
in release notes. Config/command surfaces should change conservatively.

### Sustainability signals

- All claims are test-backed and reproducible (`docs/RELEASE_READINESS.md`).
- Public disclosure + maintenance process exists (`SECURITY.md`, this doc).
- Reproducible, locked builds (`docs/REPRODUCIBILITY.md`).
- Two-tree mirror with parity verification (`docs/SYNC.md`).
