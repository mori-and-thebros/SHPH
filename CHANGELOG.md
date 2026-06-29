# Changelog

All notable changes to SHPH are documented here. This project follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) principles, adapted to
the phase-gated funding roadmap in `ROADMAP_OSS_AND_DELIVERY.md`.

## [Phase B.2] — Stability Before Feature Expansion (2026-06-29)

### Added
- `docs/API_STABILITY.md` — public-API tiers (CLI / config / library), SemVer
  posture, and validation-window freeze rules.
- `docs/SECURITY_REPORTING.md` — bug-bounty-safe redactable report template +
  severity-based triage SLA (complements `SECURITY.md`).
- `docs/SUPPLY_CHAIN_SCAN.md` — `cargo-audit` scanner procedure + advisory triage.
- `docs/evidence/CARGO_AUDIT.txt` — captured advisory-scan output.
- `cargo audit` job in `.github/workflows/ci.yml` (non-blocking, periodic).

### Changed
- `anyhow` bumped `1.0.102 -> 1.0.103` (RUSTSEC-2026-0190, direct dep).
- `ratatui` bumped `0.27 -> 0.28.1` in `shph-tui` (transitive advisory hygiene).

### Fixed
- `shph-tui/src/main.rs`: deprecated `frame.size()` -> `frame.area()` (ratatui 0.28).

### Security
- Resolved the one direct scanner finding (`anyhow` unsound `downcast_mut`,
  never invoked by SHPH). 2 transitive warnings (`paste`, `lru`) accepted and
  documented; both isolated to the optional TUI.

## [Hardening] — Crypto data-plane hardening (2026-06-30)

Concrete security hardening of `shph-core/src/crypto.rs`, each with a
regression test. This is the first increment of the post-funding hardening
track (Optional/Research), not a funding-gate phase.

### Security
- **Anti-replay window correctness:** `ReplayWindow` was a `HashSet` that
  cleared the whole set when it filled, dropping protection across the clear
  boundary (a previously-seen nonce became acceptable again). Replaced with a
  proper sliding bitmap window over the 64-bit counter space; the previous
  highest nonce is recorded as seen on every advance, so it cannot be replayed.
- **Nonce-reuse prevention:** `SendCipher` now fails closed at `AEAD_NONCE_LIMIT`
  (`2^32 - 1`) instead of letting the 64-bit counter wrap and reuse nonce 0
  (which would catastrophically break ChaCha20-Poly1305). The session must
  rekey rather than overflow.
- **Timing-safe verification:** handshake signature comparison now uses a
  constant-time equality check (`constant_time_eq`) instead of `!=`, removing a
  timing oracle on how much of the signature digest matched.

### Tests
- 8 new regression tests in `shph-core` (replay-window boundary, replay after
  many advances, nonce-limit fail-closed, constant-time eq semantics/prefix).
- `shph-core` unit tests: 19 -> 27.

## [Hardening] — Keystore secret hygiene (2026-06-30)

Hardening of `shph-core/src/keystore.rs` (private identity-key storage). Second
increment of the Optional/Research hardening track.

### Security
- **Private-key file permissions:** the keystore (holding the X25519 private
  key) is now written with mode `0600` on Unix (owner-only) instead of the
  process-umask default (often world-readable `0644`).
- **Leaky-file refusal:** `load` now rejects a keystore that is group/other
  accessible, failing closed rather than silently using a leaked key.
- **Bounded load:** keystore load is capped at 1 MiB (`MAX_KEYSTORE_BYTES`) and
  enforces UTF-8, so a hostile/giant file cannot force a large allocation.
- **Atomic save:** the keystore is written to a temp file beside the target,
  fsynced, then renamed into place — a crash mid-write can no longer leave a
  truncated/corrupt key file.

### Tests
- 5 new keystore regression tests (roundtrip, 0600 perms, leaky-file refusal,
  oversized-file rejection, no leftover temp files). `shph-core` 27 -> 32.

## [Hardening] — Transport DoS hardening + dead-code cleanup (2026-06-30)

Third increment of the Optional/Research hardening track (`shph-transport`).

### Security
- **Per-peer connection-rate limiting:** the TCP accept entry path now enforces
  a per-source-IP cap (`MAX_CONNECTS_PER_PEER_PER_WINDOW` = 8 per 10s) before
  any handshake work. This complements the per-loop `TCP_HANDSHAKE_ATTEMPTS`
  bound (which only covers a single accept loop) so one host cannot flood the
  entry path across repeated sessions.
- **Anti-slowloris hello read:** `read_tcp_hello` now reads in 1 KiB chunks into
  a single bounded buffer instead of one syscall per byte, with the same
  `MAX_HELLO_BYTES` cap. A dribbling peer can no longer amplify per-byte cost or
  hold the connection open beyond the cap.

### Changed
- Removed the orphaned, never-compiled root `src/crypto.rs` and `src/error.rs`
  (not part of any workspace crate; the live code is `shph-core/src/`).

### Tests
- 3 new `PeerRateLimiter` regression tests (under-cap allow, per-IP-not-port
  keying, distinct-IP isolation). `shph-transport` 1 -> 4 unit tests.

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
