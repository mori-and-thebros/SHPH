# Changelog

## [0.6.1-dev] — prerelease hardening follow-up (2026-08-14)

### Security and protocol hardening

- Added a rotating, stateless HMAC-SHA256 TCP cookie challenge after the
  existing per-source pressure threshold. Cookie validation occurs before
  responder ML-KEM key generation and ciphertext decapsulation.
- Added a complementary deterministic peer-ID role decision for
  simultaneous-open orchestration while preserving the connected socket's
  initiator/responder key direction.
- Added explicit empirical-CDF size sampling to the opt-in Shroud 2.0 lab
  morphology engine while retaining negotiated path-MTU and envelope bounds.
- Configured native TUN interfaces to a validated 1360-byte MTU before route,
  DNS, and session setup, with Linux and Windows command builders covered by
  tests.
- Added opt-in host leak containment: Linux installs a dedicated nftables
  killswitch before native TUN setup, while Windows installs persistent WFP
  outbound authorization filters. Both require literal peer IP/port
  allowlists, and `down` removes stale SHPH-owned policy. The
  `--killswitch-dry-run` preview does not require native TUN, elevation, or
  firewall mutation.
- Added opt-in Linux TCP SYN MSS clamping in a separate nftables table.
  Windows reports an explicit unsupported error because this build does not
  perform unsafe host-wide TCP-option rewriting.
- Replaced ambiguous handshake transcript concatenation with canonical,
  length-prefixed field framing that binds the negotiated profile, peer
  ordering, initiator identity, hybrid public values, and optional KEM
  ciphertext.
- Made native `up` capture session failures before cleanup so control-plane,
  MSS-clamp, and killswitch rollback remains consistent on early exits.
- Captured a fresh Windows-local full benchmark suite for `0.6.1-dev` across
  `secure-default` and `classical-lab` with 5,000 latency samples and 100,000
  sustained frames; native TUN and two-host behavior remain outside the run.

These changes do not claim production traffic morphology, DPI resistance,
privileged firewall execution on every host, or native two-host VPN evidence.

## [0.6.0-dev.0] — release-polish and native-platform hardening (2026-08-09)

This is a development release. It is not a production-ready transport, an
independent security audit, or evidence that the remaining native two-host TUN
release gates have been completed.

### Windows native TUN validation refresh

- Recorded a fresh native Windows validation run: locked workspace checks,
  strict Clippy, release builds, 180 passing workspace tests, Windows-only
  Wintun and ACL regressions, and both local benchmark profiles.
- Removed the host-incompatible strict signed-target DLL flag while retaining
  application-local loading, elevation checks, SHA-256 pinning, and validator
  Authenticode verification.
- Captured a post-loader native Wintun adapter/session smoke and documented the
  remaining packet-I/O, route/DNS rollback confirmation, reconnect, shutdown,
  and two-node evidence gates.
- Fixed Windows route rollback to include the adapter interface in the
  generated `netsh delete route` command.

### Security-assessment remediation

- Made responder-side ML-KEM decapsulation policy-aware: the peer hello
  signature and configured identity/signing-key pin are verified before PQ
  decapsulation in every transport, including file adapters and standards
  QUIC.
- Added collision-safe peer-limiter eviction and corrected its distributed
  source regression assertion.
- Added mandatory application-local Wintun SHA-256 pinning through
  `SHPH_WINTUN_SHA256`; missing, malformed, oversized, or mismatched runtimes
  fail closed before DLL loading.
- Zeroized keystore serialization staging and password-bearing configuration
  holders on drop, while retaining explicit documentation for unavoidable
  API/string copies.
- Added the `shroud2_datagram` target to the CI fuzz smoke loop.
- Made native Linux and Windows bridge disconnects retryable unless shutdown
  was requested locally, so reconnect policy is exercised after a remote close.
- Made public TCP send/receive helpers retain caller-owned AEAD cipher state,
  preventing accidental per-frame nonce-counter resets.
- Added the native Linux two-host validation harness, including host/container
  exclusion, private external state, interval CPU/RSS capture, `iperf3`
  readiness checks, routed ping/goodput measurements, and reconnect evidence.
- Added GitHub issue/PR templates plus a publication checklist that requires
  monitored private vulnerability reporting and sanitized evidence review.
- Made a remotely closed standards-QUIC native-TUN bridge fail explicitly
  instead of completing successfully, and reject standards-QUIC reconnect
  configuration until certificate continuity is implemented.

### Standards/TUN hardening and documentation

- Disabled TLS 1.3 early data (0-RTT) in both explicit standards-QUIC TLS
  builders, preventing replayable application input before the SHPH handshake.
- Bounded opt-in JA4 SNI recording to 255 UTF-8 bytes and preserved the
  partial-observation/non-spoofing contract.
- Rejected oversized standards-QUIC TUN datagrams before copying them into
  zeroizing packet buffers and capped the malformed-datagram close budget.
- Retried interrupted native-TUN syscalls, reported native EOF consistently,
  and wiped rejected packets from caller-provided read buffers.
- Reconciled README, security, testing, funder, and standards-QUIC docs with
  the implemented Linux native-TUN bridge and its remaining host-evidence
  gates.

### Transport, configuration, and fuzzing hardening

- Added a standalone `cargo-fuzz` workspace with bounded fuzz targets for
  Shroud-cell decoding, configuration parsing, audit-record deserialization,
  and replay-window state transitions.
- Added a public configuration parser entry point so fuzzing exercises the same
  TOML deserialization path used by file loading.
- Fixed Data-Mule responder handshakes leaving the consumed peer hello in the
  inbox, which could cause the same hello to be selected again.
- Fixed offline/Data-Mule queue polling so malformed payload candidates are
  quarantined and do not block later valid envelopes.
- Hardened file-adapter reads against final-component symlink traversal and
  made envelope temp-file creation exclusive.
- Bounded TCP connect setup with the configured timeout instead of relying on
  platform-specific blocking connect behavior.
- Fixed Unix stdin session mode dropping additional lines when one read
  contained multiple newline-delimited messages; oversized lines now fail
  closed at 64 KiB.
- Hardened config persistence with unique exclusive temp files, cleanup on
  failure, and parent-directory sync after replacement.
- Hardened CLI peer authentication by pinning the Ed25519 handshake-signing
  public key alongside the X25519 identity key.
- Added bounded TCP address fallback, Unix keystore symlink refusal, and
  encrypted-keystore KDF parameter bounds.
- Bounded TCP/QUIC handshake retries to one overall timeout and added a hard
  stdin line cap on non-Unix builds.
- Hardened ratchet-audit journal reads/appends against final-component
  symlink replacement.
- Bounded configuration loading to 1 MiB, rejected non-UTF-8 input, and
  refused final-component symlinks on Unix.
- Made malformed file-adapter quarantine collision-safe so rejected evidence is
  not overwritten.
- Added a Linux-first benchmarking roadmap with explicit security/performance
  profile rules; no protocol mode behavior changed.
- Implemented explicit `secure-default` and `classical-lab` handshake profiles.
  Profiles are signed and transcript-bound, profile mismatches fail closed, and
  the CLI/config expose classical benchmarking only as an explicit opt-in.
- Bumped the unreleased handshake protocol identity to `shph/5`; `shph/4`
  peers are intentionally incompatible with the profile-aware wire format.
- Added a standalone native-Linux benchmark runner under `benchmarks/` for
  handshake, framing, AEAD, and replay measurements with environment metadata.

### Earlier development-line remediation

- Made CLI peer identity pinning mandatory; sessions now fail closed when no
  expected peer is configured.
- Added `show-public-key` to make safe `add-peer` registration straightforward.
- Added Windows console-control shutdown handling via `SetConsoleCtrlHandler`.
- Added idempotent `apply`, `reconcile`, and `undo` control-plane commands with
  persisted applied-state tracking.
- Preserved multiple configured DNS servers during control-plane application:
  Linux uses one `resolvectl` update and Windows emits primary/secondary
  `netsh` commands by address family.
- Added a hard aggregate 60-second TCP accept/handshake deadline.
- Made `SHPH_TUN_NATIVE=1` fail explicitly on Windows until signed Wintun
  runtime integration exists; it no longer silently selects the stub backend.
- Added regression coverage for multi-server DNS command generation and
  cross-platform TUN-name validation.
- Refreshed audit, evidence, and mirror verification artifacts.

### Secret-material zeroization

- **Session AEAD keys are now zeroized on drop.** `SendCipher` and
  `ReceiveCipher` implement `Drop` to wipe the 32-byte ChaCha20-Poly1305 session
  key, so live traffic keys no longer persist in heap memory after a session
  ends. This mitigates core-dump, swap, and memory-disclosure recovery of
  session keys.
- **`SessionKeys` derives `ZeroizeOnDrop`** — `send_key` / `recv_key` are wiped
  on drop (nonces are non-secret and skipped).
- **Ed25519 signing-seed hygiene** — `IdentityKeyPair.sign_seed` is now wiped in
  both `Zeroize` and `Drop` (the X25519 `StaticSecret` already self-zeroizes).
- **HKDF intermediates zeroized** — the raw 32-byte HKDF outputs in
  `verify_and_derive` are wrapped in `Zeroizing<Vec<u8>>` and wiped once copied
  into the session keys.

- No wire-format, protocol-tag, or public-API change. The `zeroize` crate was
  already a direct dependency of `shph-core`; no new dependency added.

- 4 new regression tests for zeroize-on-drop (`SendCipher`, `ReceiveCipher`,
  `SessionKeys`, `IdentityKeyPair`). Workspace tests 79 -> 83 (0 failed).

## [0.4.0] — Hybrid post-quantum key exchange + QUIC shim hardening (BREAKING, 2026-07-02)

### Security (hybrid PQECDH)
- **Hybrid post-quantum key exchange (ML-KEM-768) is now layered on X25519.**
  Each handshake performs a full ML-KEM-768 encapsulation/decapsulation in
  addition to the classical X25519 ECDH. The session key is derived from
  **both** the ECDH shared secret **and** the ML-KEM shared secret via HKDF, so
  recorded traffic remains confidential even against a future quantum adversary
  that breaks ECDH ("harvest now, decrypt later").
- **Downgrade resistance.** `verify_and_derive` fails closed if the PQ shared
  secret is absent: a peer that strips the PQ ciphertext can never silently
  negotiate a classical-only key. The PQ public key is bound into the signed
  handshake transcript, so it cannot be swapped by a MITM.
- New `shph-core/src/pqc.rs` module (`PqcKeypair`, `encapsulate_against`,
  `decapsulate`) wrapping RustCrypto `ml-kem` (FIPS-203).

### Breaking changes
- Protocol tag bumped `shph/3` -> `shph/4`; `Hello` gains `pqc_pub_b64` and
  `pqc_ct_b64` fields. Old and new peers are not wire-compatible.
- The handshake now exchanges a small follow-up ML-KEM ciphertext message after
  the hello round-trip (one extra bounded frame/datagram/payload per handshake).
- `HandshakeMaterial` gained a `pq_shared` field and is no longer `Clone`
  (ML-KEM decapsulation keys are not cloneable).

### Hardening (QUIC/UDP shim)
- **Post-handshake source-address binding.** QUIC data-frame datagrams are now
  rejected unless they arrive from the address authenticated during the
  handshake, closing an off-path injection/amplification surface.
- **Per-IP rate limiting on the QUIC accept path** (parity with TCP), so a single
  host cannot exhaust the handshake budget by flooding UDP hellos.
- **Datagram truncation guard:** a hello that fills the receive buffer is
  rejected instead of being parsed as a truncated message.
- PQ ciphertext frames are length-prefixed and size-bounded to exactly
  `ML_KEM_768_CIPHERTEXT_BYTES`; oversized or short reads fail closed.

### Tests
- Hybrid roundtrip, downgrade-blocked, corrupted-ciphertext-breaks-agreement,
  and classical-only-cannot-derive regression tests in `handshake_flow.rs`.
- QUIC foreign-source rejection regression test in `shph-transport`.

### Out of scope (documented, not implemented)
HSM/TPM/YubiKey key binding, browser/DPI/TLS fingerprint shaping, and offline
mesh adversarial posture remain explicitly out of scope — they require hardware
or substantial design work and are tracked in `docs/RISK_MATRIX.md`.

## [0.3.0] — Real Ed25519 handshake authentication (BREAKING, 2026-06-30)

### Security (critical fix)
- **The handshake "signature" was not a real signature.** `sign_handshake`
  computed `SHA256(public-key || transcript)` and verify compared that hash — a
  digest of purely public data with no private-key operation. Anyone could forge
  a valid `sig`, so the handshake had **no authentication / no MITM resistance**.
- Replaced with a **real Ed25519 detached signature** via `ring`. Each identity
  now carries an independent Ed25519 keypair (in addition to the X25519 DH key).
  The signature binds the X25519 identity key, the Ed25519 signing key, the
  ephemeral key, the nonce, and the timestamp, so the keys cannot be swapped by
  a MITM. Only the holder of the peer's Ed25519 private key can complete the
  handshake.

### Breaking changes
- Protocol tag bumped `shph/2` -> `shph/3`; `Hello` gains a `sign_pub_b64`
  field. Old and new peers are not wire-compatible.
- Keystore gains a persisted Ed25519 signing seed (`sign_seed_b64`); pre-0.3
  keystores load with a fallback signing key and should be re-`init`ed.

### Changed
- Workspace version `0.2.0` -> `0.3.0`.
- `SECURITY.md` corrected: the "Ed25519-style handshake signatures" claim is now
  genuinely true (previously aspirational), and the MITM threat row reflects the
  real public-key signature.

### Tests
- +4 handshake authentication regression tests: real sig verifies; forged
  impersonation rejected; tampered signature bytes rejected; swapped signing key
  rejected. `handshake_flow` 2 -> 6.

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
- Windows graceful shutdown via `SetConsoleCtrlHandler` is now wired through
  `windows-sys`; native Windows verification remains an operator action.
