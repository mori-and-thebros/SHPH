# Native Windows Validation — 2026-08-08

## Scope

This record covers a fresh native Windows run for workspace version
`0.5.0-dev.0`. It validates the Windows MSVC build, tests, Windows-only unit
paths, fail-closed native-TUN selection, and the local benchmark runner. It
does not claim live Wintun packet forwarding or two-host VPN performance.

The working tree was already dirty before this run. No source files were
changed by the validation commands.

## Host and Toolchain

- OS: Windows `10.0.26200.0`
- PowerShell: `5.1.26100.8875`
- Rust: `rustc 1.96.0 (ac68faa20 2026-05-25)`
- Cargo: `cargo 1.96.0 (30a34c682 2026-05-25)`
- Target: `x86_64-pc-windows-msvc`
- Git base: `3fd2e44a81536fd4b90f7ca2881fcffbba5dca56`
- Workspace version: `0.5.0-dev.0`

## Standard Gates

| Command | Result |
| --- | --- |
| `cargo fmt --all -- --check` | Pass |
| `cargo check --workspace --locked` | Pass |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Pass |
| `cargo test --workspace --locked` | **180 passed, 0 failed** |
| `cargo build --workspace --release --locked` | Pass |
| `cargo build --release --manifest-path benchmarks/Cargo.toml --locked` | Pass |

The full workspace test run included the Windows-only backend tests. Focused
Windows groups also passed:

```powershell
cargo test -p shph-tun --locked windows::tests -- --nocapture
# 6 passed, 0 failed

cargo test -p shph-core --locked `
  keystore::tests::windows_acl_protected_keystore_roundtrips -- --nocapture
# 1 passed, 0 failed
```

## Benchmark Capture

The native Windows runner completed both required profiles:

```powershell
.\scripts\benchmark_windows.ps1 `
  -Suite all -Iterations 5000 -Frames 100000 `
  -OutputDirectory .\benchmark-runs\windows-validation-2026-08-08
```

- `secure-default.csv`: emitted and non-empty
- `classical-lab.csv`: emitted and non-empty
- Native TUN flag: `0`
- Scope: local authenticated operation and morphology measurements only

Raw captures are ignored local artifacts under
`benchmark-runs/windows-validation-2026-08-08/`.

## Wintun Provenance and Fail-Closed Check

An application-local `target/release/wintun.dll` was present for inspection:

- Size: `427552` bytes
- PowerShell Authenticode status: `Valid`
- Reported signer: WireGuard LLC
- SHA-256:
  `E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE`

This observation is not operator approval of a deployment artifact. The
release gate still requires the approved signed runtime to be supplied beside
the application and checked by `validate_windows_tun.ps1`.

The non-elevated native-TUN smoke path was exercised with
`SHPH_TUN_NATIVE=1` and the matching hash. It exited nonzero with:

```text
PermissionDenied("Administrator elevation is required before loading Wintun")
```

This confirms that native Windows selection fails closed rather than falling
back to the stub backend.

## Host-Gated Result

`validate_windows_tun.ps1` was attempted from the directory containing the
signed runtime, but the current PowerShell session was not elevated. Its
`#Requires -RunAsAdministrator` guard stopped execution before adapter
creation or any route/DNS mutation.

The following remain unvalidated by this run:

1. Elevated Wintun adapter and session creation.
2. Live packet receive/send, wait-event behavior, and teardown.
3. Route/DNS apply, rollback, shutdown, and reconnect on a live adapter.
4. A two-node authenticated Windows tunnel and performance measurements.

These results do not close the native Linux two-host TUN gate, controlled
standards-QUIC network-impairment testing, or the final release-readiness
snapshot/tag gate.
