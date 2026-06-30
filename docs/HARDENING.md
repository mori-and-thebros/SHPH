# SHPH Hardening Summary

This document consolidates the security-hardening work done *after* the
funding-readiness track (Phases A + B). It is the Optional/Research hardening
track from `ROADMAP_OSS_AND_DELIVERY.md`: concrete, tested, verifiable
defenses rather than research-grade features.

Every change here:
- fixes a real weakness found by audit (not theoretical),
- ships with regression tests,
- keeps all gates green (`fmt` / `clippy -D warnings` / `test 0 failed` /
  `--locked` build),
- is captured in `CHANGELOG.md` and tagged (`hardening-N`).

## Increment 1 — Crypto data-plane (`hardening-1`)

File: `shph-core/src/crypto.rs`.

- **Anti-replay window correctness.** `ReplayWindow` was a `HashSet` that
  cleared the entire set when it filled, so after every `size` packets a
  previously-seen nonce became acceptable again. Replaced with a sliding bitmap
  window over the 64-bit counter space; on every advance the previous-highest
  nonce is recorded as seen so it cannot be replayed.
- **Nonce-reuse prevention.** `SendCipher` now fails closed at
  `AEAD_NONCE_LIMIT` (`2^32 - 1`) instead of letting the 64-bit counter wrap to
  0 and reuse a nonce (a catastrophic ChaCha20-Poly1305 break). The session
  must rekey.
- **Timing-safe verification.** Handshake signature compare now uses a
  constant-time equality check instead of `!=`, removing a timing oracle on how
  much of the digest matched.

Tests: 8 new (replay-window boundary, replay-after-many-advances, nonce-limit
fail-closed, constant-time semantics). `shph-core` 19 -> 27.

## Increment 2 — Keystore secret hygiene (`hardening-2`)

File: `shph-core/src/keystore.rs`.

- **Owner-only file perms.** The keystore (holding the X25519 private key) is
  now written mode `0600` on Unix instead of the umask default (often
  world-readable `0644`).
- **Leaky-file refusal.** `load` rejects a group/other-accessible keystore,
  failing closed rather than silently using a leaked key.
- **Bounded load.** Capped at 1 MiB (`MAX_KEYSTORE_BYTES`) + UTF-8 enforced, so
  a hostile/giant file cannot force a large allocation.
- **Atomic save.** Write to temp + fsync + rename — a crash mid-write can no
  longer leave a truncated/corrupt key file.

Tests: 5 new (roundtrip, 0600, leaky-file refusal, oversized rejection, no
leftover temp files). `shph-core` 27 -> 32.

## Increment 3 — Transport DoS + cleanup (`hardening-3`)

File: `shph-transport/src/lib.rs`.

- **Per-peer connection-rate limiting.** The TCP accept entry path enforces a
  per-source-IP cap (8 connects per 10s) before any handshake work. Complements
  the per-loop `TCP_HANDSHAKE_ATTEMPTS=5` bound (which only covers a single
  accept loop) so one host cannot flood the entry path across sessions.
- **Anti-slowloris hello read.** `read_tcp_hello` reads 1 KiB chunks into a
  bounded buffer instead of one syscall per byte; same `MAX_HELLO_BYTES` cap.

Cleanup: removed the orphaned, never-compiled root `src/crypto.rs` +
`src/error.rs`.

Tests: 3 new `PeerRateLimiter` tests (under-cap allow, per-IP-not-port keying,
distinct-IP isolation). `shph-transport` 1 -> 4.

## Threat-table impact

| Threat | Before hardening | After hardening |
| ------ | ---------------- | --------------- |
| Replay across window-clear boundary | Vulnerable (set cleared) | Sliding window (fixed) |
| AEAD nonce reuse via counter wrap | Possible (catastrophic) | Fail-closed at limit |
| Signature-verify timing oracle | `!=` compare | Constant-time |
| Private key world-readable at rest | umask default (~0644) | Owner-only (0600) |
| Handshake-flood from one host | Per-loop bound only | + per-IP rate limit |
| Slowloris per-byte hello cost | 1 syscall/byte | Chunked bounded read |

## What this is NOT

These are hardening of the existing design, not new anti-observation
capabilities. Per `SECURITY.md`, SHPH still does **not** claim: browser/TLS/QUIC
fingerprint parity, DPI evasion, constant-time guarantees beyond the crypto
crates, or hostile-network adversarial posture. Those remain research-track
items (`ROADMAP_OSS_AND_DELIVERY.md`).
