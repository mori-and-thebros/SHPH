# Dependency & Artifact Reproducibility

SHPH aims for transparent, reproducible builds so operators and reviewers can
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

The benchmark harness is intentionally a standalone manifest so its measurement
dependencies do not enter the shipped workspace binaries. Validate it
separately:

```bash
cargo fmt --manifest-path benchmarks/Cargo.toml -- --check
cargo check --manifest-path benchmarks/Cargo.toml --all-targets --locked
cargo build --manifest-path benchmarks/Cargo.toml --release --locked
```

For identity/plugin-provider coverage, run the explicit suite and preserve the
environment metadata and CSV output with the reviewed evidence:

```bash
cargo run --manifest-path benchmarks/Cargo.toml --release -- \
  --suite identity --iterations 1000 --frames 1000
```

The identity suite includes local filesystem, in-memory, and failure-model
providers. It is not a substitute for a native two-host or remote-plugin
availability test.

For wire and packet-overhead coverage:

```bash
cargo run --manifest-path benchmarks/Cargo.toml --release -- \
  --suite wire --iterations 1000 --frames 10000
```

The wire suite reports encrypted/enveloped bytes, overhead, packet rate,
in-memory roundtrip behavior, and authenticated UDP loopback. It excludes
IP/UDP/Ethernet headers and is not a substitute for native TUN or two-host
throughput evidence.

On Windows, use the MSVC target when Visual Studio C++ build tools are
available:

```powershell
cargo +1.96.0 build --release --manifest-path benchmarks/Cargo.toml `
  --target x86_64-pc-windows-msvc --locked
```

If MSVC is unavailable, use a complete, supported LLVM-MinGW installation
configured as the Rust GNU target linker. Do not force
`-C link-self-contained=yes` as a substitute for a complete runtime; it can
produce binaries that fail in the MinGW CRT relocation/startup path before
`main`. Record the exact linker and CRT versions with any GNU-target benchmark
evidence.

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
  cargo audit --deny warnings
  ```
  Run this before tagging a release and record the result.

## Verification of a release artifact

1. Note the release commit/tag and its `Cargo.lock`.
2. `cargo build --release --locked` on a clean checkout.
3. Confirm `cargo fmt --all -- --check`,
   `cargo clippy --workspace --all-targets -- -D warnings`, and
   `cargo test --workspace` pass on both Linux and Windows.
4. Compare the produced binary checksum against the published checksum.

For a small distribution directory containing only reviewed public material,
use the repository packager after building the target binary:

```bash
python scripts/package_release.py \
  --binary target/release/shph \
  --output dist/shph-package
python scripts/verify_release.py \
  --package dist/shph-package \
  --version 0.6.7-dev
```

Use `target/release/shph.exe` for a Windows build. The packager records the
source revision, dirty-tree state, lockfile checksums, payload checksums, and
platform metadata in `manifest.json`, and writes a `SHA256SUMS` file. It uses
an explicit public-document allowlist and refuses symlinks, oversized files,
and common private-key or token markers. `--allow-dirty` is available for
engineering snapshots, but a release package must be made from a clean tree.
`verify_release.py` rechecks the clean-tree marker, allowlisted payload,
manifest metadata, and every checksum before publication. The tag-triggered
GitHub release workflow also creates a signed artifact attestation for each
published archive. These controls are packaging/provenance evidence; they are
not byte-for-byte reproducibility or an independent security review.

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

The CI workflow runs `cargo audit --deny warnings` without ignored advisory
IDs. The historical optional-TUI advisories and their old allowlist are
documented only as historical context in `docs/SUPPLY_CHAIN_SCAN.md`.
New warnings or vulnerabilities fail the advisory job.
