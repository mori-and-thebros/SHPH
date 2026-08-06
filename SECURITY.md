# SHPH Security Policy

SHPH (Shroud-Phantom) is a VPN-first research/prototype project in active
hardening. This document states what is supported, what is **not** claimed, how
to report issues, and the current threat model.

## Supported Versions

Only the latest `main` or `master` / tagged release receives security attention
until the hosted default branch is finalized.

| Version | Supported |
| ------- | --------- |
| latest `main` / most recent tag | yes |
| older commits | no |

## Reporting a Vulnerability

- **Do not open a public GitHub issue for security bugs.**
- Before publishing the repository, the maintainer **must enable and monitor**
  GitHub private vulnerability reporting. Until that hosted private channel is
  confirmed, SHPH is not ready for public security issue intake.
- Do not put sensitive details in a public issue. Use the hosted repository's
  private advisory channel ("Security" → "Advisories" → "Report a
  vulnerability") after it is enabled, or contact the project owner through
  the hosting account's private mechanism before disclosure.
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
  + PQ public key + ephemeral + nonce + timestamp), followed by transcript-bound
  HKDF session-key derivation.
- **Hybrid post-quantum key exchange (ML-KEM-768, FIPS-203)** layered on X25519:
  every handshake additionally performs an ML-KEM encapsulation/decapsulation
  and the session key is derived from **both** the ECDH and the ML-KEM shared
  secrets, so recorded traffic stays confidential against a future quantum
  adversary that breaks ECDH ("harvest now, decrypt later"). The PQ public key
  is bound into the signed transcript and derivation fails closed if the PQ
  shared secret is absent, blocking a silent classical downgrade.
- ChaCha20-Poly1305 AEAD framing on the TCP data plane.
- AEAD nonce anti-replay: TCP uses strict monotonic counters, while the
  experimental UDP/QUIC receiver uses a bounded sliding bitmap window to accept
  authenticated reordering and reject duplicates (fail-closed).
- Deadline-bounded handshake work on the TCP/UDP accept paths: malformed,
  early-closing, and wrong-key peers are dropped without terminating the
  listener before its operator deadline.
- Configured peer identities are mandatory and pinned at the CLI session boundary; an
  authenticated but unexpected identity is rejected before data-plane use.
- Fail-closed IO: EOF/broken-pipe/timeout/errors terminate the session rather
  than corrupting state.
- Secret-at-rest hygiene: the keystore (private identity key) is written
  owner-only (mode 0600 on Unix) via an atomic temp+rename, and loading refuses
  a group/other-accessible key file rather than silently using a leaked key.
- In-memory secret hygiene: session AEAD keys (`SendCipher` / `ReceiveCipher`),
  derived `SessionKeys`, the Ed25519 signing seed, and HKDF intermediates are
  `zeroize`d on drop so live key material does not linger in freed heap memory
  after a session ends (`hardening-5`).
- Atomic control-plane apply with preflight validation and best-effort rollback.
- Graceful SIGINT/SIGTERM shutdown on Unix and console-control shutdown on Windows.

### Explicitly NOT done / out of scope today

This is the **non-claims matrix** — SHPH must **not** be marketed as providing
these until the corresponding roadmap phase ships and is independently reviewed:

- Browser/TLS/QUIC fingerprint parity or DPI evasion.
- Full production QUIC: the QUIC path is an experimental UDP shim. It now has
  post-handshake source-address binding, per-IP rate limiting, and truncation
  guards (v0.4.0), but it is **not** a conformant or congestion-controlled QUIC
  implementation and remains opt-in/experimental; TCP is the stable default.
  An opt-in standards QUIC module now uses Quinn for the actual QUIC/TLS
  transport and RFC 9221 datagrams, including a Linux native-TUN bridge; its
  production certificate/trust workflow and host evidence are not complete.
- Offline-mesh and data-mule are filesystem-backed lab adapters. Their
  hardening bounds reads/scans and defers file removal until authenticated
  consumption, but does not provide wireless discovery, delivery guarantees,
  multi-writer coordination, or hostile-filesystem protection.
- Lab Shroud cells: `SHPH_SHROUD_PROFILE` applies fixed-size authenticated cells
  to the experimental UDP shim. This changes framing and padding in lab tests;
  it does not provide browser fingerprint parity or censorship resistance.
- Optional passive JA4-compatible observability records bounded public
  ClientHello metadata on the standards-QUIC server path. It is disabled by
  default, does not rewrite handshakes, and does not provide fingerprint
  evasion or traffic-analysis resistance.
- Standards QUIC disables TLS 1.3 early data (0-RTT) on both endpoints, so
  SHPH application messages are not accepted through a replayable
  pre-authentication data path.
- The hybrid handshake has no explicit post-KEM key-confirmation message yet.
  Tampering with the ML-KEM ciphertext causes the peers to derive different
  session keys and then fail closed when data-plane authentication begins; it
  must not be represented as an immediately detected handshake failure.
- Hostile-network / adversarial anti-observation posture.
- Constant-time guarantees beyond what the underlying crates provide.
- Production key management (HSM/PKCS#11/YubiKey/TPM), Shamir quorum, and
  ratchet audit (planned, not defaults). Hybrid PQ key exchange **is** shipped
  (v0.4.0); hardware-backed key storage is still out of scope.
- Side-channel resistance audits of the full stack.
- Full service-manager integration beyond the Windows console-control handler.
- Password-encrypted keystores are available when `SHPH_KEYSTORE_PASSWORD` is
  set; filesystem permissions remain required, and legacy plaintext keystores
  remain supported for migration.

## Threat Model (current scope)

| Threat | Status |
| ------ | ------ |
| Passive eavesdropper on the wire | Mitigated: AEAD-encrypted data plane. |
| Replay of a captured data frame | Mitigated: TCP strict monotonic anti-replay and experimental UDP/QUIC sliding-window anti-replay (fail-closed); send-side nonce-limit guard prevents nonce reuse. |
| Tampered/truncated frames | Mitigated: AEAD authentication + length bounds + fail-closed decode. |
| Unauthenticated handshake flood (resource exhaustion) | Mitigated: deadline-bounded accept loops + handshake timeouts + pre-authentication signature checks + per-source-IP connection rate limiting; not a full DoS defense against a distributed flood. |
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
