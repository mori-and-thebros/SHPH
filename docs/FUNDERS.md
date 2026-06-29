# SHPH for Funders

This page is the entry point for grant reviewers (e.g. OTF) and enterprise
pre-reviewers. It states plainly **what SHPH is, what it is not**, how to verify
every claim, and where to find the risk, milestone, and support details.

> SHPH (Shroud-Phantom) is an open-source, VPN-first secure-transport project in
> active, phase-gated hardening. It is **funding-ready as a transparent,
> testable engineering effort**, and **not** a production censorship-resistant
> product.

## What SHPH is

- A Rust workspace VPN-first project: identity, authenticated handshake,
  encrypted data plane, TUN integration, CLI, and (experimental) alternate
  transports.
- **Lab-grade functional today**: a two-node encrypted tunnel transfers data
  end-to-end on Linux; the toolchain builds cleanly on Windows.
- **Transparent and auditable**: every claim below is backed by a test or a doc
  you can run/read yourself (see "How to verify").
- **Phase-gated**: progress is tracked in `docs/FUNDING_SPRINT_BOARD.md` and a
  phase is only marked complete when its acceptance criteria and evidence are
  met and mirrored.

## What SHPH is NOT (do not claim otherwise)

This list is binding for any funder-facing or marketing material:

- **Not** production-hardened or censorship-resistant transport.
- **Not** a DPI/TLS/QUIC fingerprint-parity or anti-observation tool (planned,
  not shipped).
- **Not** a full QUIC stack (the QUIC path is an experimental UDP shim).
- **Not** a key-management/HSM/TPM/YubiKey/PQC/Shamir solution (planned, not
  defaults).
- **Not** audited for constant-time or side-channel resistance beyond what its
  dependency crates provide.
- **Not** Windows-feature-complete for graceful teardown (Unix-only today).

See `docs/RISK_MATRIX.md` for the severity-rated version of this list.

## Current capability snapshot (verifiable)

| Capability | Status | How to verify |
| ---------- | ------ | ------------- |
| Workspace builds, lints, tests clean | done | `cargo build --locked`, `cargo clippy -- -D warnings`, `cargo test --workspace` |
| Authenticated TCP handshake (transcript-bound keys) | done | `cargo test -p shph-core --test handshake_flow` |
| Encrypted framed data plane (ChaCha20-Poly1305) | done | `cargo test -p shph-cli --test cli_tcp_data_plane` |
| Anti-replay on the data plane (fail-closed) | done | `cargo test -p shph-core crypto::tests::replayed_frame_is_rejected_fail_closed` |
| Graceful SIGINT/SIGTERM shutdown (Unix) | done | `docs/TESTING.md` (Phase A.1 evidence) |
| Atomic control-plane apply + rollback | done | `cargo test -p shph-cli --test cli_control_plane` |
| CI template (Linux + Windows) | done | `.github/workflows/ci.yml` |
| Reproducible, locked builds | done | `cargo build --locked` + `docs/REPRODUCIBILITY.md` |
| DPI/fingerprint evasion | not done | `docs/RISK_MATRIX.md` |
| Production anti-observation posture | not done | `docs/RISK_MATRIX.md` |

Test totals (as of last validation): **52 passed, 0 failed** across the
workspace. Re-run `cargo test --workspace` to reproduce.

## How funders verify claims

1. Clone and build from docs only: see `CONTRIBUTING.md`.
2. Run the gates: `cargo fmt --all -- --check`,
   `cargo clippy --workspace --all-targets -- -D warnings`,
   `cargo test --workspace`.
3. Inspect the evidence trail: `docs/FUNDING_SPRINT_BOARD.md` (phase-by-phase
   completion + evidence), `docs/TESTING.md` (command logs + per-test intent).
4. Read the security posture honestly: `SECURITY.md`
   (threat model + non-claims matrix).
5. Check reproducibility: `docs/REPRODUCIBILITY.md` (`--locked`, `cargo audit`).

## Related funder documents

- `docs/RISK_MATRIX.md` — current limits and explicit exclusions (severity-rated).
- `docs/MILESTONE_SCORECARD.md` — measurable phase scorecard + roadmap burn-down.
- `docs/SUPPORT_AND_MAINTENANCE.md` — support model and maintenance plan.
- `ROADMAP_OSS_AND_DELIVERY.md` — full delivery roadmap.
- `SECURITY.md` — disclosure process and threat model.
