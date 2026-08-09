# SHPH Crypto Funding Bootstrap

This document is a campaign draft for a small, crypto-only public-goods
fundraising effort. It is not a promise of anonymity, tax treatment, legal
status, or custodial safety. Wallet control and local compliance remain the
operator's responsibility.

## Campaign snapshot

| Field | Draft value |
| ----- | ----------- |
| Campaign name | SHPH Security Hardening Bootstrap |
| Initial target | USD 7,500 equivalent |
| Stretch target | USD 15,000 equivalent |
| Duration | 6–8 weeks |
| Funding type | Direct BTC, ETH, and GRAM donations only |
| Custody | Operator-controlled multisig preferred |
| Public deliverable | Reproducible code, tests, evidence, and release notes |
| Explicit non-claim | This does not fund a production VPN, censorship resistance, or a full security audit |

The USD amounts are budgeting units only. The initial accepted assets are:

| Asset | Network | Donation address |
| ----- | ------- | ---------------- |
| BTC | Bitcoin mainnet | `ADDRESS_TO_BE_PROVIDED` |
| ETH | Ethereum mainnet | `ADDRESS_TO_BE_PROVIDED` |
| GRAM (formerly TON Coin) | TON mainnet | `ADDRESS_TO_BE_PROVIDED` |

The published campaign should show the asset, network, wallet address, and
exchange-rate timestamp for each donation. The addresses are intentionally
placeholders until the operator supplies and independently verifies them.
Check the network carefully before publishing; an address for one network must
not be presented as an address for another.

## Milestones

### M1 — Release and evidence cleanup — $1,000

Acceptance:

- Working tree is reviewed and the intended release scope is explicitly listed.
- `cargo fmt --all -- --check` passes.
- `cargo clippy --workspace --all-targets -- -D warnings` passes.
- `cargo test --workspace` passes with zero failures.
- `cargo build --workspace --locked` passes.
- `scripts/capture_evidence.sh` is refreshed.
- Linux/Windows checkout parity is verified.
- A signed or otherwise independently verifiable release artifact is published.

### M2 — Automated security testing — $2,000

Acceptance:

- Framing, handshake parsing, keystore loading, config loading, and transport
  boundaries have focused fuzz or property-test harnesses.
- Every confirmed defect gets a regression test and a changelog entry.
- Test commands, corpus seeds, limits, and remaining findings are documented.
- No claim of formal verification or complete security coverage is made.

### M3 — Windows readiness — $2,000

Acceptance:

- A real Windows host validates the documented build and CLI smoke tests.
- Native TUN behavior is either validated with an operator-approved Wintun
  runtime (hash-pinned by the loader and Authenticode-checked by the validator)
  or remains explicitly fail-closed with an operator-facing explanation.
- Windows route/DNS behavior is tested in dry-run mode and, where privileged
  access is available, in a controlled apply/rollback test.
- Platform limitations are recorded in the evidence log.

The operator must provide the privileged Windows host and perform any action
that requires local administrator access, driver installation, or code signing.

### M4 — Independent focused review — $1,500

Acceptance:

- A security researcher or qualified reviewer receives a pinned source snapshot.
- The review scope, limitations, findings, and remediation status are public.
- Any unresolved high-severity issue blocks a production-sounding claim.

This budget is for a focused review, not a full professional audit or
certification.

### M5 — Public maintenance package — $1,000

Acceptance:

- Reproducible demo and contributor instructions are refreshed.
- Threat model, risk matrix, and non-claims remain synchronized with code.
- Release notes and a final funding report are published.
- A public issue list identifies the next unfunded work.

## Spending and reporting

- Keep donation custody separate from code-maintainer signing keys.
- Prefer a multisig wallet with at least three independent signers.
- Record each received asset, network, amount, timestamp, and conversion basis.
- Do not mix personal funds and campaign funds.
- Publish milestone reports before requesting the next discretionary payout.
- Never publish private keys, seed phrases, recovery shares, or unredacted
  transaction metadata that could compromise a signer.
- Crypto addresses are often pseudonymous, not automatically anonymous.

## Donation-page copy

> SHPH is an open-source Rust secure-transport project for controlled lab
> environments. We are raising the first USD 7,500 equivalent in crypto to
> improve reproducible releases, automated security testing, Windows readiness,
> and an independent focused review. We accept BTC, ETH, and GRAM (formerly TON
> Coin). SHPH is not currently a production VPN, full QUIC
> implementation, or censorship-resistant transport. Every milestone will
> publish code, tests, evidence, and limitations.

## What the operator must provide

Before publishing a campaign, the operator must decide and document:

1. The public name shown on the campaign. This can simply be `SHPH Team`; it
   does not mean publishing a private legal identity.
2. A verified donation address for BTC, ETH, and GRAM.
3. The multisig signers and recovery plan, kept private where appropriate.
4. The exchange-rate source and reporting currency.
5. The payout authority and milestone approval process.
6. The public location for reports and release artifacts.

The coding assistant can prepare the repository, campaign text, acceptance
tests, evidence scripts, and reports. It cannot control wallets, verify
ownership of addresses, sign transactions, perform privileged Windows driver
work, or act as a legal/tax adviser.

## First-week execution order

1. Freeze the campaign scope; `SHPH Team` is the current placeholder public name.
2. Review the current working tree and decide which changes belong in the first
   public checkpoint.
3. Create the BTC, ETH, and GRAM donation wallet or multisig outside the
   repository.
4. Verify every donation address and network on a separate trusted device.
5. Publish this campaign draft with placeholders replaced.
6. Complete M1 before requesting or spending beyond the initial setup budget.
