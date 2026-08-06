# GitHub Publication Checklist

Use this checklist immediately before making SHPH public. It prevents release
claims or local evidence from being published by accident.

## Repository Setup

- [ ] Create the hosted repository and replace `<owner>` in `CONTRIBUTING.md`.
- [ ] Replace `<owner>` in `.github/ISSUE_TEMPLATE/config.yml` with the hosted
  repository owner so the private vulnerability-reporting link is valid.
- [ ] Set the default branch and protect it with the CI checks in
  `.github/workflows/ci.yml`.
- [ ] Enable and monitor GitHub private vulnerability reporting; verify the
  security contact flow before opening public issues.
- [ ] Add repository description, topics, license metadata, and a `0.5.0-dev.0`
  prerelease or clear development status as appropriate.
- [ ] Confirm `LICENSE-MIT` and `LICENSE-APACHE` are displayed by GitHub.

## Sensitive Material

- [ ] Inspect the staged tree for keystores, private keys, passwords, tokens,
  and generated credentials.
- [ ] Do not publish `${XDG_STATE_HOME:-$HOME/.local/state}/shph/` or raw
  logs from `scripts/validate_linux_two_host.sh`; those runs store private
  keystores outside the repository by default.
- [ ] Keep the legacy repo-local `/.two-host-validation/` path ignored.
- [ ] Review `benchmark-runs/` and `docs/evidence/` individually; publish only
  sanitized, reproducible evidence that does not identify peers or hosts.

## Evidence And Claims

- [ ] Run the Rust validation gates described in `docs/RELEASE_PROCEDURE.md`.
- [ ] Run `scripts/sync_mirror.sh --verify`; the intentional root `Cargo.lock`
  mirror difference is documented in `docs/SYNC.md`.
- [ ] Capture native Linux two-host evidence with
  `scripts/validate_linux_two_host.sh`, or leave every related claim marked
  pending.
- [ ] Confirm Windows-native evidence is accurate for the exact signed Wintun
  runtime and host used.
- [ ] Read `README.md` and `SECURITY.md` for unsupported production, QUIC, and
  anti-censorship claims before publishing.

## First Release

- [ ] Update `CHANGELOG.md`, version metadata, and release notes.
- [ ] Create an annotated SemVer tag only after the evidence above is complete.
- [ ] Attach checksums and build-host details to published binaries.
