# SHPH Security Reporting: Bug-Bounty-Safe Template & Triage SLA

This is the Phase B.2 "bug bounty-safe report template and triage SLA"
deliverable. It complements `SECURITY.md` (which states the disclosure SLA and
threat model) with a **structured, redactable report template** safe to share
with bounty programs and a **severity-based triage SLA**.

## 1. Where to report

- **Privately**, never as a public issue. See `SECURITY.md` → "Reporting a
  Vulnerability": email the maintainers, or use GitHub
  *Security → Advisories → Report a vulnerability*.
- Coordinated disclosure: acknowledgement within **5 business days**, fix window
  up to **90 days** (decided together with the reporter).

## 2. Bug-bounty-safe report template

Fill in every field. Fields marked **[REDACTABLE]** can be blanked before
sharing the report with a third-party bounty platform — they are not required
for triage.

```markdown
### SHPH Security Report

**Report ID:** [REDACTABLE] (assign on intake; do not put personal data here)
**Date (UTC):** YYYY-MM-DD
**Reporter handle:** [REDACTABLE]
**Affected version / commit:** e.g. checkpoint-phaseA-1.0.0 / commit <short hash>

#### 1. Summary
One-paragraph description of the issue.

#### 2. Affected component
Pick one: handshake | crypto/AEAD | framing | control-plane | transport (tcp/quic)
| TUN | CLI/config | TUI | dependency (name the crate).

#### 3. Impact
What an attacker can achieve, against whom, under what preconditions.
Be concrete: "remote unauthenticated X can Y".

#### 4. Preconditions / threat model fit
Network position required? Credentials required? Does it require a compromised
endpoint (currently out of scope per SECURITY.md)?

#### 5. Reproduction
Minimal steps on loopback (the project ships `scripts/demo.sh`). No exploits
against systems you do not own.

#### 6. Suggested fix [optional]
Patch or approach.

#### 7. Disclosure preference
Coordinated (default) | immediate (active exploitation).
```

**Safe-sharing rule:** before posting to a bounty platform, remove the
`Reporter handle`, `Report ID`, and any identifying reproduction host details.
The technical fields (component, impact, repro) are the triage signal.

## 3. Triage severity rubric

| Severity | Definition (example) | Target ack | Target fix |
| -------- | -------------------- | ---------- | ---------- |
| **Critical** | Remote unauth break of confidentiality/integrity of the data plane (e.g. AEAD forgery, key recovery). | 1 business day | emergency checkpoint, < 30 days |
| **High** | Authenticated break, or remote crash/DoS of the handshake path bypassing the bounded-accept mitigation. | 3 business days | next checkpoint, < 60 days |
| **Medium** | Local privilege/footprint issue, or unsoundness reachable only via a non-default path. | 5 business days | next checkpoint, < 90 days |
| **Low** | Defense-in-depth, hardening, or theoretical issues with no shown path. | 5 business days | best-effort, tracked |

## 4. Triage SLA (operational)

1. **Intake:** maintainer acknowledges privately within the severity's ack
   target and assigns a `Report ID`.
2. **Classification:** maintainer assigns a severity using the rubric above and
   confirms/refutes the threat-model fit (many "endpoint compromise" reports
   are out of scope per `SECURITY.md` and are closed as such with explanation).
3. **Fix:** work proceeds on a private branch; the reporter is kept informed.
4. **Disclosure:** coordinated per `SECURITY.md`; credit given unless declined.
5. **Record:** fixed issues are noted in `CHANGELOG.md` (without exploit
   detail) and, where relevant, the `docs/RISK_MATRIX.md` threat table.

## 5. Out-of-scope fast-close

The following are **out of scope** (per `SECURITY.md` non-claims matrix) and are
closed promptly with an explanation rather than triaged as vulnerabilities:

- Traffic-analysis / DPI evasion (no fingerprint parity claimed).
- Endpoint compromise / key theft (no HSM/TPM binding yet).
- Issues requiring the QUIC experimental shim to be production-grade.
- Reports from testing against systems the reporter does not own.
