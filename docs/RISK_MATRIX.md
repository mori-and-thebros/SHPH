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
| QUIC path is an experimental UDP shim, not production QUIC | High | Partially hardened (v0.4.0) | TCP is the stable default; QUIC is opt-in with source binding, bounded peer state, malformed-datagram budgets, strict frame lengths, and capped idle timeout | Loss recovery, congestion control, stream multiplexing, and conformant QUIC in later phase |
| Native TUN accepts malformed or oversized IP packets | High | Hardened in working tree | 65,535-byte cap plus IPv4/IPv6 length validation at both TUN directions | Privilege separation and broader packet-policy controls in ops phase |
| Native TUN requires `CAP_NET_ADMIN`/root | Medium | By design | Linux native backend is opt-in; Windows native mode refuses unsafe stub fallback until Wintun integration is provisioned | Privilege-separation and signed Wintun runtime integration |
| Dependency advisory automation | Low | **Present and blocking** | `cargo audit` runs in `.github/workflows/ci.yml`; only two documented TUI advisories are ignored | Revisit the allowlist when `ratatui` drops the affected transitive crates |
| Live control-plane apply needs host privileges/tools | Medium | By design | `dry_run=true` default; preflight validation; rollback guard | Ops hardening phase |

## Shipped security capabilities (v0.4.0)

- **Hybrid post-quantum key exchange (ML-KEM-768 + X25519)** — the session key
  is derived from both the classical ECDH and the ML-KEM shared secret, with
  downgrade resistance (derivation fails closed without the PQ shared secret).
- **Ed25519 transcript signatures** for handshake authentication (v0.3.0).
- **Bounded, rate-limited, fail-closed** handshake entry paths on both TCP and
  the QUIC shim.

## Explicit exclusions (things SHPH does NOT provide)

These are **out of scope** until the corresponding roadmap phase ships and is
independently reviewed. Marketing or implying any of these is a policy violation.

| Excluded capability | Severity of claiming it falsely | Why excluded | Roadmap home |
| ------------------- | ------------------------------- | ------------ | ------------ |
| Censorship-resistant / anti-observation transport | Critical | No fingerprint parity or adversarial posture | Later phases |
| DPI / TLS / QUIC fingerprint evasion | Critical | Not implemented | Later phases |
| Production key management (HSM/PKCS#11/YubiKey/TPM) | High | Not implemented; providers fail closed | Roadmap (optional) |
| Shamir quorum key sharing | Medium | Safe CLI primitive, not a production KMS | Split/recover validates bounded shares; no hardware custody |
| Constant-time / side-channel audit of the full stack | High | Relies on dependency crates' guarantees | Security audit phase |
| Anti-DoS / resource-exhaustion guarantees | High | Only bounded handshake attempts + timeouts | Hardening phase |
| Mobile/embedded platform support | Low | Not targeted | Not planned |

## Threat coverage today (from SECURITY.md)

| Threat | Covered? | Mechanism |
| ------ | -------- | --------- |
| Passive wire eavesdropping | Yes | AEAD-encrypted data plane |
| Frame replay | Yes | TCP strict monotonic anti-replay; experimental UDP/QUIC sliding-window anti-replay (fail-closed) + send-side nonce-limit guard |
| Tampered/truncated frames | Yes | AEAD auth + length bounds + fail-closed decode |
| Active MITM | Yes | Identity-key signature + mandatory CLI-enforced configured peer fingerprint pinning |
| Handshake flood | Partial | Bounded accept loop + handshake timeouts (not full DoS defense) |
| Endpoint/key compromise | No | No HSM/TPM binding yet |
| Traffic analysis / DPI | No | No fingerprint parity yet |

## Policy

- Any funder, marketing, or README claim must be traceable to a green test or a
  "done" row in this matrix or `docs/MILESTONE_SCORECARD.md`.
- When a gap is closed, move it from "Current limits"/"Exclusions" into the
  capability snapshot in `docs/FUNDERS.md` with a verification command.
