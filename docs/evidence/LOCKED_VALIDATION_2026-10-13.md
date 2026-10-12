# Locked Validation - 2026-10-13

This record summarizes the local Windows release-readiness run for source
commit `aeb71d1` (`Add SNAP and transport hardening features`). The collector
observed a clean worktree at that commit. The follow-up commit that adds this
record and corrects maintainer status documents changes no implementation
source.

## Dependency archive

The `quinn-proto 0.11.19` archive was obtained from the official
`static.crates.io` endpoint after the configured rsproxy mirror failed. Its
SHA-256 was verified against the lockfile checksum:

```text
0e750cca55fe4f0439a15d0bb529da9651e79993e8e72c61a899a36d462befbe
```

The four repository lockfiles were not changed during this validation:

| Lockfile | SHA-256 |
| --- | --- |
| `Cargo.lock` | `DCAF3743733DB4EF38925FFA8542486B1CCC85E7A98BD092BB7721559C6067D0` |
| `benchmarks/Cargo.lock` | `1BE973D8109EE618BDEE9044D2F274749D9669615E8D06867AEB3E23C1269DC0` |
| `fuzz/Cargo.lock` | `4A9C8DE97E52FFE3296DF2B684DB0A89EBE4880BD0ED856572D4DC783F1750F8` |
| `shph-edge/Cargo.lock` | `1968948D8EAF5633772E085E7CD0EF5A96BC7A6208A48288F2C2579C4B47B66` |

## Results

The full collector completed with **46 PASS, 0 FAIL, and 4 SKIP**. Its local
report is kept in the ignored `benchmark-runs/` directory:
`release-readiness-20261013-clean/release-readiness-20261013T120050Z.md`.
That report is not committed because it contains machine-specific command and
path details.

Passing gates included:

- Root workspace format, locked metadata, all-target check, Clippy with
  warnings denied, all-target tests, SNAP profile/adapter/paired CLI tests, and
  release build.
- Windows MSVC all-target build and release build.
- Windows package creation from the clean source tree. This is an engineering
  package for workspace version `0.6.7-dev`, not an approved `0.6.8-dev`
  release artifact.
- Benchmark workspace format, check, Clippy, tests, release build, smoke runs,
  and Windows MSVC release build.
- Fuzz workspace format, check, Clippy, and all seven bounded fuzz smoke
  targets.
- Standalone `shph-edge` format, default and HTTP/3 checks/tests/Clippy, and
  default release build.
- Four `cargo audit --deny warnings --no-fetch` scans using the cached RustSec
  database. The scans passed, but the database was not freshly fetched during
  this collector run.

The collector marked these required host/service lanes `SKIP`:

- `native-tun-two-host`
- `snap-linux-adapter-acceptance`
- `snap-windows-adapter-acceptance`
- `snap-external-service-acceptance`

The operator asked to defer those campaigns. They remain open release gates;
their `SKIP` status does not count as a pass. The collector therefore reports
`release_eligible=false`. No anonymity, censorship-resistance, DPI-evasion,
production-VPN, or independently audited security claim follows from these
local results. The current support boundaries remain in
[`SUPPORT_MATRIX.md`](../SUPPORT_MATRIX.md), and the binding gates are in
[`RELEASE_READINESS.md`](../RELEASE_READINESS.md).

## Reproduction

The full local collector was run from the repository root:

```powershell
.\scripts\release_readiness.ps1 -OutputDirectory benchmark-runs\release-readiness-20261013-clean
```

The root locked commands also passed independently:

```powershell
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo build --workspace --release --locked
```

This is engineering validation for commit `aeb71d1`, not candidate approval.
The workspace remains `0.6.7-dev`; `0.6.8-dev` is tentative. Re-run the gates
on the final versioned candidate, refresh the advisory database, and close all
required host/service evidence before considering release eligibility.
