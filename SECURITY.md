# SHPH Security Policy

SHPH (Shroud-Phantom) is a VPN-first research/prototype project in active
hardening. This document states what is supported, what is **not** claimed, how
to report issues, and the current threat model.

## Supported Versions

Only the latest `main` / tagged release receives security attention.

| Version | Supported |
| ------- | --------- |
| latest `main` / most recent tag | yes |
| older commits | no |

## Reporting a Vulnerability

- **Do not open a public GitHub issue for security bugs.**
- Email the maintainers privately (see repository `SECURITY.md` contact or the
  governance section of `CONTRIBUTING.md`). If no email is listed yet, open a
  private advisory via GitHub's "Security" → "Advisories" → "Report a
  vulnerability".
- Include: affected version/commit, reproduction steps, impact assessment, and
  any suggested fix.
- You will receive an acknowledgement within 5 business days. Coordinated
  disclosure timing is decided together; please allow up to 90 days for a fix
  before public disclosure.
- Please **do not** test exploits against systems you do not own or operate.

## Current Security Posture (honest)

SHPH is **not** production-hardened or censorship-resistant transport. It is
suitable for **controlled lab environments, staged engineering, and transparent
OSS validation only.**

### What works today

- X25519 identity keys for DH **plus** a separate Ed25519 key that produces a
  real detached signature over the handshake transcript (identity + signing key
  + ephemeral + nonce + timestamp), transcript-bound HKDF session-key derivation.
- **Hybrid post-quantum key exchange (ML-KEM-768, FIPS-203)** layered on X25519:
  every handshake additionally performs an ML-KEM encapsulation/decapsulation
  and the session key is derived from **both** the ECDH and the ML-KEM shared
  secrets, so recorded traffic stays confidential against a future quantum
  adversary that breaks ECDH ("harvest now, decrypt later"). The PQ public key
  is bound into the signed transcript and derivation fails closed if the PQ
  shared secret is absent, blocking a silent classical downgrade.
- ChaCha20-Poly1305 AEAD framing on the TCP data plane.
- AEAD nonce anti-replay: the receiver rejects replayed or out-of-order counter
  nonces via a sliding bitmap window (fail-closed); the send counter also stops
  at the AEAD nonce limit to make nonce reuse impossible.
- Bounded handshake attempts on the TCP accept path (drops malformed/early-
  closing/wrong-key peers, fails closed).
- Fail-closed IO: EOF/broken-pipe/timeout/errors terminate the session rather
  than corrupting state.
- Secret-at-rest hygiene: the keystore (private identity key) is written
  owner-only (mode 0600 on Unix) via an atomic temp+rename, and loading refuses
  a group/other-accessible key file rather than silently using a leaked key.
- Atomic control-plane apply with preflight validation and best-effort rollback.
- Graceful SIGINT/SIGTERM shutdown on Unix.

### Explicitly NOT done / out of scope today

This is the **non-claims matrix** — SHPH must **not** be marketed as providing
these until the corresponding roadmap phase ships and is independently reviewed:

- Browser/TLS/QUIC fingerprint parity or DPI evasion.
- Full production QUIC: the QUIC path is an experimental UDP shim. It now has
  post-handshake source-address binding, per-IP rate limiting, and truncation
  guards (v0.4.0), but it is **not** a conformant or congestion-controlled QUIC
  implementation and remains opt-in/experimental; TCP is the stable default.
- Hostile-network / adversarial anti-observation posture.
- Constant-time guarantees beyond what the underlying crates provide.
- Production key management (HSM/PKCS#11/YubiKey/TPM), Shamir quorum, and
  ratchet audit (planned, not defaults). Hybrid PQ key exchange **is** shipped
  (v0.4.0); hardware-backed key storage is still out of scope.
- Side-channel resistance audits of the full stack.
- Windows graceful Ctrl+C teardown (tracked follow-up; Unix-only today).

## Threat Model (current scope)

| Threat | Status |
| ------ | ------ |
| Passive eavesdropper on the wire | Mitigated: AEAD-encrypted data plane. |
| Replay of a captured data frame | Mitigated: receiver-side sliding-window nonce anti-replay (fail-closed); send-side nonce-limit guard prevents nonce reuse. |
| Tampered/truncated frames | Mitigated: AEAD authentication + length bounds + fail-closed decode. |
| Unauthenticated handshake flood (resource exhaustion) | Mitigated: bounded accept loop + handshake timeouts + per-source-IP connection rate limiting; not a full DoS defense against a distributed flood. |
| Active MITM | Mitigated by Ed25519 transcript signature verification + peer fingerprint pinning (only the holder of the peer's Ed25519 private key can complete the handshake). |
| Harvest-now-decrypt-later (recorded traffic broken by a future quantum adversary) | Mitigated (v0.4.0): hybrid ML-KEM-768 + X25519 key derivation means breaking ECDH alone is insufficient to recover the session key. Note: this protects confidentiality of recorded sessions, not against an active quantum adversary that also defeats the classical authentication. |
| Endpoint compromise / key theft | Out of scope: no HSM/TPM binding yet. |
| Traffic-analysis / DPI | Out of scope: no fingerprint parity yet. |
| Host privilege escalation via control-plane apply | Mitigated by dry-run default, preflight validation, and OS privilege requirements. |

## Cryptographic Dependencies

SHPH composes vetted primitives from existing crates rather than rolling its
own cryptography: `ring`, `x25519-dalek`, `chacha20poly1305`, `hkdf`, `sha2`,
`zeroize`. See `Cargo.lock` for exact versions and `docs/REPRODUCIBILITY.md`
for the supply-chain posture.
