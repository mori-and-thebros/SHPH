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
| Windows graceful Ctrl+C teardown not signal-driven | Medium | Tracked | Default termination; stdin loop still checks shutdown flag | `windows-sys` `SetConsoleCtrlHandler` (A.2 follow-up) |
| QUIC path is an experimental UDP shim, not hardened | High | Known | TCP is the stable default; QUIC is opt-in/experimental | Full QUIC hardening in later phase |
| Native TUN requires `CAP_NET_ADMIN`/root | Medium | By design | Stub backend for dev flow; native behind `SHPH_TUN_NATIVE=1` | Privilege-separation in ops phase |
| No dependency advisory automation in CI yet | Low | Tracked | Manual `cargo audit` before release (see REPRODUCIBILITY.md) | Add `cargo audit` step once release cadence exists |
| Live control-plane apply needs host privileges/tools | Medium | By design | `dry_run=true` default; preflight validation; rollback guard | Ops hardening phase |

## Explicit exclusions (things SHPH does NOT provide)

These are **out of scope** until the corresponding roadmap phase ships and is
independently reviewed. Marketing or implying any of these is a policy violation.

| Excluded capability | Severity of claiming it falsely | Why excluded | Roadmap home |
| ------------------- | ------------------------------- | ------------ | ------------ |
| Censorship-resistant / anti-observation transport | Critical | No fingerprint parity or adversarial posture | Later phases |
| DPI / TLS / QUIC fingerprint evasion | Critical | Not implemented | Later phases |
| Production key management (HSM/PKCS#11/YubiKey/TPM) | High | Planned, not a default | Roadmap (optional) |
| Post-quantum cryptography (PQC) | Medium | Planned, not a default | Roadmap (optional) |
| Shamir quorum key sharing | Medium | Planned, not a default | Roadmap (optional) |
| Constant-time / side-channel audit of the full stack | High | Relies on dependency crates' guarantees | Security audit phase |
| Anti-DoS / resource-exhaustion guarantees | High | Only bounded handshake attempts + timeouts | Hardening phase |
| Mobile/embedded platform support | Low | Not targeted | Not planned |

## Threat coverage today (from SECURITY.md)

| Threat | Covered? | Mechanism |
| ------ | -------- | --------- |
| Passive wire eavesdropping | Yes | AEAD-encrypted data plane |
| Frame replay | Yes | Receiver sliding-window nonce anti-replay (fail-closed) + send-side nonce-limit guard |
| Tampered/truncated frames | Yes | AEAD auth + length bounds + fail-closed decode |
| Active MITM | Yes | Identity-key signature + peer fingerprint pinning |
| Handshake flood | Partial | Bounded accept loop + handshake timeouts (not full DoS defense) |
| Endpoint/key compromise | No | No HSM/TPM binding yet |
| Traffic analysis / DPI | No | No fingerprint parity yet |

## Policy

- Any funder, marketing, or README claim must be traceable to a green test or a
  "done" row in this matrix or `docs/MILESTONE_SCORECARD.md`.
- When a gap is closed, move it from "Current limits"/"Exclusions" into the
  capability snapshot in `docs/FUNDERS.md` with a verification command.
