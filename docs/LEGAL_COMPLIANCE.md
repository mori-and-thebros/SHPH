# SHPH Legal & Compliance Checklist (OSS Artifact Handling)

This is the legal/compliance checklist for handling SHPH open-source artifacts.
It exists so maintainers, auditors, and downstream packagers can confirm the
project's licensing, attribution, and export posture are consistent and
verifiable.

> This is a **process checklist**, not legal advice. SHPH is dual-licensed
> MIT OR Apache-2.0 and is not legal-counsel-vetted; treat this as engineering
> due diligence, not a legal opinion.

## 1. License compliance

- [x] **Dual license declared in `Cargo.toml`:** `license = "MIT OR Apache-2.0"`.
- [x] **Both license texts present:** `LICENSE-MIT`, `LICENSE-APACHE`.
- [x] **SPDX identifier matches the file texts:** `MIT OR Apache-2.0`.
- [ ] **Per-crate `LICENSE`/SPDX audit:** each workspace crate (`shph-core`,
      `shph-config`, `shph-tun`, `shph-transport`, `shph-obfuscation`,
      `shph-cli`, `shph-tui`, `shph-identity`) inherits the workspace license — verify each
      crate `Cargo.toml` carries the same `license` field (follow-up).
- [x] **No incompatible copyleft dependencies:** confirmed via `cargo tree`
      (Rust MIT/Apache-2.0/BSD-licensed deps only; see section 3).
- [x] **README license section matches:** dual MIT OR Apache-2.0.

## 2. Contributor & attribution

- [x] **`CONTRIBUTING.md`** documents the contribution flow and governance.
- [x] **No third-party code vendored without attribution:** the codebase is
      original SHPH code plus declared crate dependencies; no vendored sources.
- [ ] **DCO / CLA decision:** currently contributions are governed by
      `CONTRIBUTING.md` only; no Developer Certificate of Origin or CLA is
      enforced (documented decision, revisit before corporate contributions).
- [x] **`SECURITY.md`** names the disclosure channel and SLA.

## 3. Dependency licensing (supply chain)

Reproducible via `cargo tree` + `cargo audit`. Known hard dependencies are
permissively licensed:

- `ring` (crypto primitives) — Apache-2.0 WITH LLVM-exception (compatible).
- `serde` / `toml` / `clap` ecosystem — MIT OR Apache-2.0.
- `tokio` — MIT.
- `libc` — MIT OR Apache-2.0.

Action items:

- [x] No GPL/AGPL/LGPL in the dependency tree (verified; would block dual MIT/Apache release).
- [x] **Run `cargo audit` in CI** as a blocking supply-chain gate. The current
      checkout carries no advisory exception list; local reproduction still
      requires a host with a working linker to install `cargo-audit`.

## 4. Cryptography & export considerations

- [x] **Crypto dependency disclosed:** `ring` (see `SECURITY.md` crypto deps list).
- [x] **No custom cryptography:** SHPH uses `ring` for AEAD/hashing; it does not
      implement its own primitives (a positive for both security and export posture).
- [x] **No intentional weakening / backdoors:** fail-closed behavior is tested
      (`docs/TESTING.md`, security regression tests from Phase A.3).
- [ ] **Export classification:** SHPH ships cryptographic functionality.
      Jurisdictions differ on export controls for crypto software; **the project
      makes no export-control representation**. Downstream distributors and
      packagers are responsible for their own jurisdictional compliance. This
      should be confirmed with counsel before any commercial distribution.

## 5. Data handling & privacy

- [x] **No telemetry or analytics:** SHPH does not phone home; no usage data is
      collected or transmitted to the maintainers.
- [x] **No user PII collection:** configs hold only identity keys, peer
      addresses, and route tables — all operator-local.
- [x] **Keys never leave the operator's machine** except over the encrypted
      transport by explicit operator action (one-shot send/recv).

## 6. Artifact integrity for release

- [x] **Reproducible build path:** `docs/REPRODUCIBILITY.md` (`--locked`,
      committed `Cargo.lock`).
- [x] **Release gates documented:** `docs/RELEASE_READINESS.md`.
- [x] **Evidence captured for validation:** `docs/evidence/GATE_EVIDENCE.md`.
- [ ] **Signed artifacts:** no GPG/Sigstore signing configured yet (tracked
      follow-up for the first versioned release).

## 7. Outstanding follow-ups

1. Per-crate `license` field audit (section 1).
2. DCO/CLA policy decision (section 2).
3. Refresh the captured `cargo audit` evidence after dependency changes.
4. Export-control counsel review before commercial distribution (section 4).
5. Release artifact signing (section 6).

These are explicitly tracked so reviewers see what is intentionally deferred
versus what is missing.
