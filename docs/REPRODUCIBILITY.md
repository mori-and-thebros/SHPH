# Dependency & Artifact Reproducibility

SHPH aims for transparent, reproducible builds so funders and reviewers can
verify exactly what shipped.

## Lockfile discipline

- `Cargo.lock` is committed at the repository root and covers the whole
  workspace.
- Dependency versions are pinned in `Cargo.lock`; do not regenerate it blindly
  during a release. Review the diff before committing lock changes.
- Workspace deps are centralized in the root `[workspace.dependencies]` table and
  referenced via `{ workspace = true }` from each crate, so version drift is
  visible in one place.

## Building reproducibly

```bash
git checkout <tag-or-commit>
cargo build --workspace --locked
cargo test --workspace --locked
```

`--locked` refuses to build if `Cargo.lock` does not match `Cargo.toml`, which
prevents silent dependency upgrades.

## Supply-chain posture

- SHPH composes vetted cryptography from established crates rather than
  implementing its own primitives: `ring`, `x25519-dalek`, `chacha20poly1305`,
  `hkdf`, `sha2`, `zeroize`.
- Inspect the full dependency graph and exact versions with:
  ```bash
  cargo tree --workspace
  ```
- For a vulnerability audit of the locked dependency set, use the pinned CI
  version where possible:
  ```bash
  cargo install cargo-audit --version 0.22.2 --locked
  cargo audit --no-fetch
  ```
  Run this before tagging a release and record the result.

## Verification of a release artifact

1. Note the release commit/tag and its `Cargo.lock`.
2. `cargo build --release --locked` on a clean checkout.
3. Confirm `cargo fmt --all -- --check`,
   `cargo clippy --workspace --all-targets -- -D warnings`, and
   `cargo test --workspace` pass on both Linux and Windows.
4. Compare the produced binary checksum against the published checksum.

## Known reproducibility caveats

- `ring` includes pre-generated assembly/C and its build detection can vary by
  platform toolchain; build on the same OS/arch you intend to ship.
- Windows builds require the MSVC or GNU toolchain; cross-compiling from Linux
  needs the matching cross toolchain (e.g. `x86_64-w64-mingw32-gcc`) and is not
  validated in every environment.
- Build paths and timestamps may be embedded in debug info; use `--release` for
  distribution artifacts and document the build host if byte-identical binaries
  are required.

## Cargo audit integration

The CI workflow already runs `cargo audit` and explicitly ignores only the two
accepted optional-TUI advisories documented in `docs/SUPPLY_CHAIN_SCAN.md`.
New warnings or vulnerabilities fail the advisory job.
