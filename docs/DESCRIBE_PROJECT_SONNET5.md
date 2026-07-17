# Describe the Project — Sonnet 5

**Author:** Claude Sonnet 5 (external, independent read of the codebase)
**Date (UTC):** 2026-07-06
**Scope:** `D:\FUNDING NEEDED\snap-shroud-rs` at commit `7de572e` (workspace
version `0.4.0` + unreleased `hardening-5`), cross-checked against the
canonical Linux checkout `/home/mori/SHPH_working_copy`.

This document is a from-scratch description of what SHPH is, how it is built,
and what its threat model actually is, derived by reading the code and
running it — not by summarizing the project's own marketing docs. Where this
assessment agrees with `SECURITY.md` / `docs/RISK_MATRIX.md`, that is
independent corroboration, not a copy; disagreements, if any, are called out
explicitly.

## 1. What SHPH is

SHPH ("Shroud-Phantom") is a Rust workspace implementing a **point-to-point
authenticated, encrypted transport** — the core of a VPN-like tool, not yet a
full VPN product. Two parties (`listen`/`connect`, or a CLI's `recv-once`/
`send-once`) run a mutually authenticated key exchange over TCP (stable) or a
UDP "QUIC-like" shim (experimental), then exchange AEAD-encrypted, replay-
protected frames. Optional pieces (native Linux TUN packet forwarding,
control-plane route/DNS apply, session reconnect/backoff, offline mesh,
"data-mule" store-and-forward) sit on top of that authenticated channel.

It is explicitly **not** claiming to be a censorship-resistant or DPI-evading
transport today — that positioning is enforced by its own `docs/RISK_MATRIX.md`
"non-claims" policy, and this review confirms the claim is currently accurate:
there is a `stealth.rs`/`shph-obfuscation` profile *surface* (cell sizing,
padding intervals) but no evidence in the transport layer of it actually being
wired into the wire format yet — framing is plain length-prefixed AEAD frames,
not fixed-size shaped cells.

### 1.1 Workspace shape

| Crate | Role |
| ----- | ---- |
| `shph-core` | Crypto primitives, handshake protocol, keystore, framing, PQC, "stealth" profile data, roadmap/config-adjacent types |
| `shph-config` | TOML config schema + IO |
| `shph-transport` | TCP transport, experimental QUIC-like UDP shim, offline-mesh/data-mule glue |
| `shph-tun` | Linux TUN device abstraction (stub by default, native behind `SHPH_TUN_NATIVE=1`) |
| `shph-obfuscation` | Thin composition of `shph-core` profiles; not yet load-bearing on the wire |
| `shph-cli` | `shph` binary: `init`, `add-peer`, `listen`/`connect`, `send-once`/`recv-once`, `up` session mode |
| `shph-tui` | Optional terminal UI |

### 1.2 Protocol version and cryptographic construction

Current wire protocol tag: **`shph/4`** (`shph-core/src/handshake.rs`).

The handshake (`Hello` message) binds together, per side:

- An X25519 identity public key (`identity_pub_b64`) — classical DH.
- A **separate** Ed25519 signing public key (`sign_pub_b64`) — used only for
  authenticating the transcript, not for DH. This separation (fixed in
  `v0.3.0`) matters: the earlier "signature" was `SHA256(public-data)`, i.e. no
  private-key operation at all, so anyone could forge a valid `sig`. The
  current design uses a real Ed25519 detached signature via `ring`.
- An ML-KEM-768 (FIPS-203) encapsulation public key and ciphertext
  (`pqc_pub_b64`, `pqc_ct_b64`) — post-quantum KEM layered on top of the
  classical exchange (`v0.4.0`).
- An ephemeral X25519 public key, a 32-byte nonce, and a timestamp.
- `sig`: the Ed25519 signature over the serialized transcript (all of the
  above fields), so a MITM cannot swap in its own signing key, PQ key, or
  ephemeral without invalidating the signature.

Session key derivation (`verify_and_derive`) combines **both** the X25519 ECDH
shared secret and the ML-KEM-768 shared secret via HKDF-SHA256, and **fails
closed** if the PQ shared secret is missing — a peer cannot silently downgrade
the pair to classical-only key agreement. HKDF intermediates are wrapped in
`Zeroizing<Vec<u8>>` and wiped after being copied into the final session keys
(`hardening-5`).

The confirmed data plane uses ChaCha20-Poly1305 AEAD framing
(`shph-core/src/framing.rs`, `SendCipher`/`ReceiveCipher`) with:

- A monotonic send-side nonce counter that refuses to exceed the AEAD's safe
  nonce limit (hard stop rather than nonce reuse).
- A receiver-side sliding-window bitmap that rejects replayed or excessively
  out-of-order nonces, fail-closed.
- `Drop`/`ZeroizeOnDrop` on `SendCipher`, `ReceiveCipher`, `SessionKeys`, and
  the Ed25519 signing seed inside `IdentityKeyPair`, so the 32-byte session
  keys and signing seed are wiped from heap memory when the objects are
  dropped (`hardening-5`, verified live in this session: 4 passing
  `zeroize`-on-drop regression tests).

### 1.3 Identity and key storage

`shph-core/src/keystore.rs` persists the long-term identity (X25519 + Ed25519
seed material) to disk. On Unix it is written with an atomic temp-file +
rename and owner-only permissions (`0600`); loading **refuses** a
group/other-readable key file rather than silently trusting a leaked key
(verified: `save_creates_owner_only_file`, `load_refuses_world_readable_key_file`
tests pass). There is no HSM/TPM/YubiKey binding — the private key material
lives in an on-disk file protected only by filesystem permissions, and in
process memory protected only by the zeroize-on-drop hygiene above (not by
memory locking / `mlock`).

### 1.4 Transport-layer hardening

`shph-transport/src/lib.rs`:

- TCP accept path bounds the number of malformed/early-closing/wrong-key
  handshake attempts it will tolerate from a single connection sequence
  (`TCP_HANDSHAKE_ATTEMPTS = 5`) and enforces `MAX_HELLO_BYTES` /
  `MAX_FRAME_BYTES` size caps before parsing, so an unauthenticated peer has a
  bounded ability to consume server effort or memory.
- A per-source-IP rate limiter (`PeerRateLimiter`) gates both TCP and the QUIC
  shim's accept paths — keyed by IP, not IP:port, so a single flooding host
  cannot rotate source ports to bypass the limit (verified by
  `peer_rate_limiter_keys_by_ip_not_port`).
- The QUIC-like UDP shim additionally verifies the source address of
  post-handshake data-frame datagrams against the address that completed the
  handshake, rejecting off-path/foreign-source injection
  (`quic_frame_rejects_foreign_source` test), and rejects datagrams that fill
  the receive buffer outright rather than parsing a possibly-truncated
  message.

This is meaningfully more than a toy demo, but it is still a **shim**: it does
not implement QUIC's actual wire format, congestion control, or connection
migration — it borrows the "hello + per-datagram AEAD frame" shape over UDP and
layers the above guards on it. Treating it as "QUIC" for interoperability
purposes would be inaccurate; treating it as "a rate-limited, source-bound,
authenticated UDP transport option" is accurate.

### 1.5 Control plane and TUN

`shph-tun` provides a stub backend by default; native `/dev/net/tun` packet
I/O on Linux is opt-in via `SHPH_TUN_NATIVE=1` and validates interface names,
packet bounds, IP headers, device mode, and permissions before opening
(requires `CAP_NET_ADMIN`/root by design — this is an OS requirement, not a
gap in SHPH). On Windows, `SHPH_TUN_NATIVE=1` fails explicitly until a signed
Wintun runtime is provisioned, avoiding a silent stub fallback. The control-plane
route/DNS apply path defaults to `dry_run=true`, does preflight validation,
and attempts rollback on shutdown/error when live apply is enabled — this
matters because a route/DNS apply is one of the few places SHPH asks for
elevated host privileges, and a bad apply could disrupt a host's networking
entirely if unvalidated.

## 2. Threat model

This section states, independently, who SHPH defends against today, who it
does not, and why — organized by adversary capability rather than by feature.

### 2.1 Assets being protected

- **Confidentiality and integrity of the data-plane payload** (whatever
  application data is tunneled once a session is established).
- **Authenticity of the peer's identity** (that you are talking to the holder
  of a specific Ed25519 private key, not an impersonator).
- **The long-term identity/signing key material at rest and in memory.**
- **Availability of the handshake accept path** against trivial flooding.

It does **not** currently claim to protect:

- The fact that a SHPH session is happening at all (traffic-analysis /
  metadata resistance).
- The host running SHPH, if that host is already compromised.
- Anything about DNS/route state beyond validate-then-apply-then-rollback
  correctness (not a security boundary, an operational-safety one).

### 2.2 Adversary: passive network observer (can read, not write, packets)

**Covered.** All data-plane payload bytes after the handshake are
ChaCha20-Poly1305 AEAD-encrypted; the handshake transcript itself carries
public keys, a nonce, a timestamp, and a signature — no static application
secret is exposed on the wire. A passive observer today gets: packet sizes,
timing, the fact that a `shph/4` handshake occurred, and (for TCP) the
underlying TCP metadata (source/destination IP:port, TCP header fields). No
padding/shaping is currently applied on the wire (see §1 — `shph-obfuscation`
is not wired in yet), so **traffic-analysis resistance is not covered**, even
though confidentiality of payload contents is.

### 2.3 Adversary: active on-path attacker (can read, drop, delay, inject, modify packets)

**Mostly covered for integrity/authenticity, partially for availability.**

- **Modification/injection of data-plane frames:** rejected by AEAD
  authentication (any bit-flip fails to decrypt/verify) and the receiver's
  fail-closed decode path.
- **Replay of a previously captured frame:** rejected by the sliding-window
  nonce anti-replay check.
- **MITM during the handshake (attempting to substitute its own keys):**
  blocked, because the Ed25519 signature covers the full transcript including
  the identity, signing, PQ, and ephemeral public keys — an attacker without
  the legitimate peer's Ed25519 private key cannot produce a valid signature
  over a substituted transcript. This is the fix that shipped in `v0.3.0` and
  is the single most important security-relevant commit in the project's
  history (the pre-fix "signature" gave zero MITM resistance).
- **Selective packet dropping / connection reset:** not specifically
  defended — this is a standard on-path DoS capability that essentially no
  transport fully defends against; SHPH's `[session.reconnect]` backoff logic
  is a resilience feature, not a security defense, against this.
- **QUIC-shim datagram spoofing from an off-path attacker who can guess/see
  the session:** the source-address binding check mitigates the specific case
  of a foreign-address datagram injection into an established QUIC-shim
  session, but this is address-based, not cryptographically bound to a
  handshake-derived value beyond what the AEAD frame auth already provides —
  it is a defense-in-depth layer, not the primary integrity mechanism (AEAD
  auth is).

### 2.4 Adversary: unauthenticated flooder (handshake-spam / connect-spam, no valid keys)

**Partially covered.** Per-source-IP rate limiting and bounded handshake
attempt counts (TCP: 5 attempts; size-capped hello/frame parsing) bound the
cost a single misbehaving or flooding IP can impose. This is **not** a defense
against a distributed flood from many source IPs, nor against an attacker who
can spoof source IPs on UDP (the QUIC shim's rate limiter and source-binding
check both key on IP, which is spoofable at the network layer without
additional out-of-band verification). `docs/RISK_MATRIX.md` already classifies
this correctly as "Partial" / "not a full DoS defense."

### 2.5 Adversary with a future large-scale quantum computer (harvest-now-decrypt-later)

**Confidentiality covered for recorded sessions; authentication is not.** The
hybrid ML-KEM-768 + X25519 derivation means an adversary who records encrypted
traffic today and later breaks X25519 with a quantum computer still cannot
recover the session key, because the HKDF input also requires the ML-KEM
shared secret, and the design fails closed rather than permitting a classical-
only fallback. This is a real, verifiable property (see `pqc.rs` and the
`missing_pq_shared_secret_blocks_downgrade` / `hybrid_session_keys_match_across_sides`
regression tests). It does **not** cover the handshake **authentication**
itself: the Ed25519 signature is classical and would be forgeable by an
adversary with a large quantum computer capable of breaking EdDSA — so a
future quantum-capable *active* attacker could still MITM a live handshake
even though a passive quantum-capable *recorder* could not decrypt past
sessions. This distinction is worth stating explicitly for funders/auditors:
SHPH's PQ story today is "confidentiality-only harvest-now-decrypt-later
protection," not "full post-quantum authentication."

### 2.6 Adversary: endpoint/host compromise

**Out of scope, correctly so.** If the machine running SHPH is compromised
(malware, root access, physical access), the attacker gets the identity key
from the keystore file (protected only by filesystem permissions, not
hardware) and can read live session keys before they are dropped/zeroized.
Zeroize-on-drop reduces the *forensic* window (e.g., core dumps, swapped
memory, freed-heap scraping after the session ends) but is not a defense
against an attacker with live process access during the session. No
HSM/TPM/YubiKey binding exists yet, matching the project's own stated
exclusions.

### 2.7 Adversary: censor / DPI operator trying to detect or block SHPH itself

**Not covered, and the project does not claim otherwise.** The wire format is
a recognizable custom framing (length-prefixed hello + AEAD frames over raw
TCP, or a UDP shim), with no TLS/QUIC fingerprint mimicry and no padding/
shaping actually applied at the transport layer despite the `stealth.rs`
profile *data* existing in `shph-core`. A moderately capable DPI system could
likely fingerprint the `shph/4` hello structure. This matches the project's
own non-claims but is worth stating plainly: **the "Shroud" traffic-shaping
half of the project's name is currently aspirational at the wire level**, not
yet implemented for the shipped transports.

### 2.8 Adversary: supply-chain (malicious/vulnerable dependency)

**Actively monitored, low residual risk.** `cargo audit` (run live in this
review) reports only two pre-accepted, transitive advisories: `paste`
(unmaintained, no CVE) and `lru` (`RUSTSEC-2026-0002`, unsound `IterMut`, not
exercised by SHPH's own dependency use as far as this review determined from
the dependency graph shape). No direct dependency currently has an open
advisory. Cryptography is composed from vetted crates (`ring`, `x25519-dalek`,
`ml-kem`/RustCrypto, `chacha20poly1305`, `hkdf`, `sha2`, `zeroize`) rather than
hand-rolled, which is the correct default posture for a project at this
maturity stage.

## 3. Threat coverage summary

| Adversary / threat | Coverage | Primary mechanism | Residual gap |
| ------------------- | -------- | ------------------ | ------------- |
| Passive eavesdropper | Covered (payload) | AEAD data-plane encryption | No traffic-analysis/shape resistance |
| Active MITM during handshake | Covered | Ed25519 transcript signature over full hello | None identified beyond classical EdDSA's own limits |
| Frame replay | Covered | Sliding-window nonce anti-replay, fail-closed | None identified |
| Frame tamper/truncation | Covered | AEAD auth + length bounds + fail-closed decode | None identified |
| Handshake flood, single source | Partially covered | Per-IP rate limit + bounded attempts + size caps | No distributed-flood or IP-spoofing defense |
| Harvest-now-decrypt-later (confidentiality) | Covered | Hybrid ML-KEM-768 + X25519 HKDF, fail-closed | N/A |
| Quantum-capable active MITM (authentication) | Not covered | — | Ed25519 signature is classical only |
| Endpoint/host compromise | Not covered | — | No HSM/TPM/YubiKey; keys readable by anyone with host access |
| DPI/censorship detection or blocking | Not covered | — | No fingerprint parity; `stealth.rs` profiles not wired to wire format |
| Malicious/vulnerable dependency | Low residual risk | `cargo audit` in CI, vetted crypto crates | 2 accepted transitive advisories, unmaintained-but-unexploited `paste` |

## 4. Notable observations for funders / auditors

- The `v0.3.0` fix (real Ed25519 signatures replacing a public-data digest) is
  the single highest-impact security commit in the project's history — before
  it, the handshake had literally zero authentication despite superficially
  looking authenticated. This should be foregrounded in any external audit or
  funding narrative as the project's own most important self-caught bug, not
  buried in a changelog entry.
- The PQ story is real but partial: confidentiality-only, not authentication.
  Funding/marketing language should say "post-quantum confidentiality" rather
  than an unqualified "post-quantum secure," to stay accurate.
- "Shroud" traffic-shaping/obfuscation is currently a data-structure surface
  (`shph-obfuscation`, `stealth.rs`) with no wire-format integration in the
  shipped transports. This is consistent with the project's own roadmap
  framing but is easy to overstate in a one-line description; a reader of the
  project name alone would reasonably expect more shaping than currently
  exists.
  Recommend the README/CHANGELOG keep the current caveat language rather than
  softening it.
- The QUIC transport is a UDP shim with meaningful DoS hardening
  (source-binding, per-IP rate limiting, truncation guards), but is not
  protocol-conformant QUIC. This is already disclosed accurately in
  `SECURITY.md` / `docs/RISK_MATRIX.md`; this review's independent read
  agrees with that characterization.
