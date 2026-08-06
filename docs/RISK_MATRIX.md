# SHPH Risk Matrix

Severity-rated statement of **current limits** and **explicit exclusions**.
This is the canonical reference for what SHPH does and does not protect against
today. It must stay consistent with `SECURITY.md` and the project's non-claims.

Severity legend:

- **Critical** — absence undermines the core secure-transport promise; must be
  addressed before any "secure VPN" framing.
- **High** — meaningful gap for real-world use; tracked for near-term hardening.
- **Medium** — known scope limit, documented and accepted for this stage.
- **Low** — minor/operational; nice-to-have.

## Current limits (things that exist but are incomplete)

| Risk / Limit | Severity | Status | Mitigation today | Plan |
| ------------ | -------- | ------ | ---------------- | ---- |
| Legacy `quic` path is an experimental UDP shim, not production QUIC | High | Partially hardened (v0.4.0) | TCP is the stable default; the shim is opt-in with source binding, bounded peer state, malformed-datagram budgets, strict frame lengths, and capped idle timeout | Loss recovery, congestion control, stream multiplexing, and conformant QUIC remain separate work |
| Standards-QUIC native-TUN deployment lacks production host evidence | High | Implemented; controlled-lab/host-gated | Quinn/rustls supplies RFC 9000 transport and RFC 9221 datagrams; Linux has a bounded native-TUN bridge, 0-RTT is disabled, and peer trust is out of band | Native Linux two-host evidence, production certificate/PKI operations, and Windows Wintun validation |
| Native TUN accepts malformed or oversized IP packets | High | Hardened in working tree | 65,535-byte cap, MTU+1 truncation detection, IPv4/IPv6 length validation, complete-write enforcement, and zeroizing bridge buffers | Privilege separation and broader packet-policy controls in ops phase |
| Native TUN requires `CAP_NET_ADMIN`/root or elevated Windows runtime | Medium | By design | Linux native backend is opt-in; Windows native backend fails closed when signed Wintun, elevation, adapter, or session setup is unavailable | Privilege-separation, signed-runtime provenance, and native-host validation |
| Dependency advisory automation | Low | **Present and blocking** | `cargo audit` runs in `.github/workflows/ci.yml`; only two documented TUI advisories are ignored | Revisit the allowlist when `ratatui` drops the affected transitive crates |
| Live control-plane apply needs host privileges/tools | Medium | By design | `dry_run=true` default; preflight validation; rollback guard | Ops hardening phase |

## Shipped security capabilities (v0.4.0)

- **Hybrid post-quantum key exchange (ML-KEM-768 + X25519)** — the session key
  is derived from both the classical ECDH and the ML-KEM shared secret, with
  downgrade resistance (derivation fails closed without the PQ shared secret).
- **Ed25519 transcript signatures** for handshake authentication (v0.3.0).
- **Bounded, rate-limited, fail-closed** handshake entry paths on TCP and the
  QUIC shim; the standards-QUIC path uses Quinn/rustls with explicit
  replay-safe TLS defaults.
- **Optional passive JA4-compatible observability** on standards QUIC. It
  records bounded public rustls ClientHello metadata for lab analysis; it does
  not spoof fingerprints or change traffic behavior.

## Explicit exclusions (things SHPH does NOT provide)

These are **out of scope** until the corresponding roadmap phase ships and is
independently reviewed. Marketing or implying any of these is a policy violation.

| Excluded capability | Severity of claiming it falsely | Why excluded | Roadmap home |
| ------------------- | ------------------------------- | ------------ | ------------ |
| Censorship-resistant / anti-observation transport | Critical | No fingerprint parity or adversarial posture | Later phases |
| DPI / TLS / QUIC fingerprint evasion | Critical | Not implemented | Later phases |
| Production key management (HSM/PKCS#11/YubiKey/TPM) | High | Not implemented; providers fail closed | Roadmap (optional) |
| Shamir quorum key sharing | Medium | Safe bounded CLI/library primitive, not a production KMS | Split input is capped at 128 KiB in the core API (CLI: 64 KiB); decoded share payloads and aggregate recovery work are bounded; no hardware custody |
| Constant-time / side-channel audit of the full stack | High | Relies on dependency crates' guarantees | Security audit phase |
| Anti-DoS / resource-exhaustion guarantees | High | Deadline-bounded handshakes, per-source limits, bounded file/config/audit inputs, and bounded Shamir split/recovery; distributed flood remains out of scope | Hardening phase |
| Mobile/embedded platform support | Low | Not targeted | Not planned |

## Threat coverage today (from SECURITY.md)

| Threat | Covered? | Mechanism |
| ------ | -------- | --------- |
| Passive wire eavesdropping | Yes | AEAD-encrypted data plane |
| Frame replay | Yes | TCP strict monotonic anti-replay; experimental UDP/QUIC sliding-window anti-replay (fail-closed) + send-side nonce-limit guard |
| Tampered/truncated frames | Yes | AEAD auth + length bounds + fail-closed decode |
| Active MITM | Yes | Identity-key signature + mandatory CLI-enforced configured peer fingerprint pinning |
| Handshake flood | Partial | Deadline-bounded accept loop + per-source limits + pre-auth checks (not full DoS defense) |
| Endpoint/key compromise | No | No HSM/TPM binding yet |
| Traffic analysis / DPI | No | Passive JA4 observability is diagnostic only; no fingerprint parity, evasion, or stealth is claimed |

## Policy

- Any funder, marketing, or README claim must be traceable to a green test or a
  "done" row in this matrix or `docs/MILESTONE_SCORECARD.md`.
- When a gap is closed, move it from "Current limits"/"Exclusions" into the
  capability snapshot in `docs/FUNDERS.md` with a verification command.
