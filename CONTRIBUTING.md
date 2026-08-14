# Contributing to SHPH

Thanks for helping harden SHPH. This guide tells you how to build, test, and
land changes, plus the project's release and governance process.

## Prerequisites

- Rust `1.96.0` (the pinned toolchain in `rust-toolchain.toml`). Install via
  <https://rustup.rs>.
- A C compiler for `ring`'s build script (any platform toolchain works).
- Optional (Linux native TUN testing): `CAP_NET_ADMIN` / root and `/dev/net/tun`.

## Build & Test (clone-to-tested from docs)

```bash
git clone https://github.com/mori-and-thebros/shph.git
cd shph

# Format check
cargo fmt --all -- --check

# Lint (warnings are errors in CI)
cargo clippy --workspace --all-targets --locked -- -D warnings

# Build
cargo build --workspace --locked

# Test
cargo test --workspace --locked
```

All four commands must pass before a change can merge. See `docs/TESTING.md`
for focused test runs and platform notes.

> Note: some integration tests bind loopback TCP. In sandboxes that deny
> loopback sockets they self-skip on `PermissionDenied`; on an unrestricted host
> they run for real.

## Project Layout

```
shph-core/        crypto, handshake, framing, net, metrics, stealth, roadmap
shph-config/      TOML config schema + IO
shph-tun/         TUN device abstraction (Linux native behind SHPH_TUN_NATIVE=1)
shph-transport/   transport modes: TCP (stable), QUIC/offline-mesh/data-mule (experimental)
shph-obfuscation/ profile surface (early)
shph-cli/         `shph` binary + integration tests
shph-tui/         optional terminal UI
docs/             testing, control-plane, sprint board, reproducibility
```

## Code Style

- `cargo fmt --all` is authoritative; do not hand-format.
- No warnings: `cargo clippy --workspace --all-targets --locked -- -D warnings` is clean.
- Prefer minimal, conservative edits; fix root causes over surface patches.
- Fail closed: protocol/transport/IO errors should terminate the relevant
  session, never corrupt state or `unwrap` on untrusted input.
- Keep docs and tests aligned with code changes.
- Do not add inline comments unless requested; do not add copyright/license
  headers to source files (licensing lives in `LICENSE-MIT` / `LICENSE-APACHE`).

## Phase-Gating Discipline

SHPH uses strict phase-gating (see `docs/FUNDING_SPRINT_BOARD.md`). Do **not**
mark a phase complete unless every task and evidence criterion is satisfied
and recorded in the repository.

## Pull Requests

1. Branch from `main`.
2. Ensure `fmt`, `clippy`, and `test` all pass.
3. Update the relevant documentation and evidence when behavior or validation
   changes.
4. Describe behavior changes, test coverage, and any follow-ups.
5. Do not include private keys, keystores, raw two-host logs, credentials, or
   generated benchmark data in a pull request.

## Release Checklist

Before tagging a release:

- [ ] `cargo fmt --all -- --check` clean
- [ ] `cargo clippy --workspace --all-targets --locked -- -D warnings` clean
- [ ] `cargo test --workspace --locked` passes on Linux **and** Windows
- [ ] `CHANGELOG`/release notes updated
- [ ] `Cargo.lock` committed and reproducible (see `docs/REPRODUCIBILITY.md`)
- [ ] Version bumped consistently in workspace `Cargo.toml`
- [ ] Security posture in `SECURITY.md` still accurate (no over-claims)
- [ ] Monitored private security-reporting channel is enabled in the hosted repository
- [ ] Native two-host evidence is captured or explicitly marked pending
- [ ] Any supported checkout used for release validation is in sync
- [ ] No private keystores, runtime DLLs, benchmark working directories, or
      unreviewed evidence logs are staged for publication
- [ ] Native Linux two-host and Windows Wintun reports retain their platform
      boundaries; do not represent WSL or local benchmarks as native tunnel data

## Governance

- **Maintainers** (`SHPH Team`) approve merges and releases.
- Decisions favor transparency, minimal scope, and honest capability claims.
- Security issues follow `SECURITY.md` coordinated disclosure, **not** public
  issues.
- Governance changes are documented in this file and version-controlled.

## Code of Conduct

Be respectful and constructive. Harassment or discrimination is not tolerated.
