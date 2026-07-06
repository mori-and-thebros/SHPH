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

## Increment 4 — Hybrid post-quantum exchange + QUIC shim hardening (v0.4.0)

Files: `shph-core/src/pqc.rs` (new), `shph-core/src/handshake.rs`,
`shph-transport/src/lib.rs`.

- **Hybrid PQECDH (ML-KEM-768).** The handshake now performs a full ML-KEM-768
  encapsulation/decapsulation alongside X25519 ECDH; the session key is HKDF-
  derived from both shared secrets, so a future quantum adversary that breaks
  ECDH cannot decrypt recorded sessions ("harvest now, decrypt later").
- **Downgrade resistance.** `HandshakeMaterial.pq_shared` is `None` until the
  PQ round-trip completes; `verify_and_derive` fails closed on `None`, so a peer
  that strips the PQ ciphertext can never silently negotiate classical-only.
- **PQ key binding.** The ML-KEM public key is included in the Ed25519-signed
  transcript, so a MITM cannot swap it.
- **Bounded PQ transport.** The ML-KEM ciphertext is exchanged as a size-bounded
  follow-up frame (TCP: length-prefixed exactly `ML_KEM_768_CIPHERTEXT_BYTES`;
  UDP: a single fixed-size datagram; offline/data-mule: a bounded payload).
- **QUIC source-address binding.** Post-handshake data-frame datagrams are
  rejected unless they arrive from the authenticated peer address, closing an
  off-path injection/amplification surface.
- **QUIC per-IP rate limiting** (parity with TCP accept path).
- **QUIC datagram truncation guard** — a hello filling the receive buffer is
  rejected rather than parsed as a truncated message.

Tests: 4 new PQ regression tests (hybrid roundtrip, downgrade-blocked, corrupted
ciphertext breaks agreement, classical-only cannot derive) + 1 QUIC
foreign-source rejection test.

## Threat-table impact (increment 4)

| Threat | Before | After |
| ------ | ------ | ----- |
| Harvest-now-decrypt-later (future quantum breaks ECDH) | Vulnerable | Hybrid ML-KEM-768 mitigates |
| Silent classical downgrade (PQ stripped) | N/A | Fails closed |
| Off-path QUIC frame injection | Accepted from any source | Source-address bound |
| QUIC handshake flood from one host | No per-IP limit | Per-IP rate limited |
| Truncated UDP hello parsing | Possible | Rejected |

## Increment 5 — Secret-material zeroization on drop (`hardening-5`)

Files: `shph-core/src/crypto.rs`, `shph-core/src/handshake.rs`.

- **Session AEAD keys wiped on drop.** `SendCipher` and `ReceiveCipher` hold the
  32-byte ChaCha20-Poly1305 session key in plain heap memory. Previously it
  survived until the allocator reused the page; now both implement `Drop` to
  `zeroize` the key the instant the cipher is discarded. This closes core-dump,
  swap, and memory-disclosure exposure of *live traffic keys* after a session
  ends.
- **`SessionKeys` derived from `ZeroizeOnDrop`.** The `send_key` / `recv_key`
  arrays are now zeroized on drop via the `zeroize` derive (nonces are skipped —
  they are not secret).
- **Identity signing-seed hygiene.** `IdentityKeyPair.sign_seed` (the raw 32-byte
  Ed25519 seed) is now wiped in both `Zeroize` and `Drop`. The X25519
  `StaticSecret` already self-zeroizes; the raw Ed25519 seed previously did not.
- **HKDF intermediate zeroization.** The raw 32-byte HKDF outputs in
  `verify_and_derive` are wrapped in `Zeroizing<Vec<u8>>` so the key material is
  wiped once it has been copied into the session keys, rather than lingering in
  a freed heap buffer.

This is a defense-in-depth / secret-hygiene hardening: it does not change any
wire format or public API, so it is non-breaking. The `zeroize` crate (with the
`derive` feature) was already a direct `shph-core` dependency, so no new
dependency was introduced.

Tests: 4 new regression tests proving the key bytes are wiped after drop
(`send_cipher_zeroizes_key_on_drop`, `receive_cipher_zeroizes_key_on_drop`,
`session_keys_zeroizes_on_drop`, `identity_keypair_zeroizes_sign_seed_on_drop`).
`shph-core` unit tests 35 -> 39.

## Threat-table impact (increment 5)

| Threat | Before | After |
| ------ | ------ | ----- |
| Session AEAD key recoverable from freed memory / core dump | Yes (plain bytes) | Zeroized on drop |
| `SessionKeys` retained after session end | Yes | Zeroized on drop |
| Ed25519 signing seed retained after identity drop | Yes (raw array) | Zeroized on drop |
| HKDF raw output retained in heap | Yes | `Zeroizing` wiped after copy |

## What this is NOT

These are hardening of the existing design, not new anti-observation
capabilities. Per `SECURITY.md`, SHPH still does **not** claim: browser/TLS/QUIC
fingerprint parity, DPI evasion, constant-time guarantees beyond the crypto
crates, or hostile-network adversarial posture. Those remain research-track
items (`ROADMAP_OSS_AND_DELIVERY.md`).
