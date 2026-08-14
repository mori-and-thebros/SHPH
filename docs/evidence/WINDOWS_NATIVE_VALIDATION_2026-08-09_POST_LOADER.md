# Windows Native Validation — Post-Loader — 2026-08-09

## Scope

This follow-up records the first native Windows run after removing the
host-incompatible `LOAD_LIBRARY_REQUIRE_SIGNED_TARGET` flag. The loader still
restricts the DLL to the application-local filename and verifies the pinned
`SHPH_WINTUN_SHA256`; the validator separately requires a valid Authenticode
signature.

The run proves application-local Wintun loading, adapter/session creation,
control-plane apply, and teardown on one elevated Windows host. It does not
prove packet forwarding, reconnect behavior, Ctrl+C handling during a live
session, or two-node performance.

## Host and Toolchain

- Date: August 9, 2026
- OS: Windows `10.0.26200.0`
- PowerShell: `5.1.26100.8875`
- Rust/Cargo: `1.96.0`
- Target: `x86_64-pc-windows-msvc`
- Administrator elevation: confirmed for the successful post-loader run
- Secure Boot: enabled
- Workspace version: `0.5.0-dev.0`
- Wintun runtime: official `0.14.1` AMD64 DLL
- Wintun SHA-256:
  `E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE`

## Gates

| Gate | Result |
| --- | --- |
| `cargo fmt --all -- --check` | Pass |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Pass |
| `cargo test --workspace --locked` | **180 passed, 0 failed** |
| `cargo build --workspace --release --locked` | Pass |
| Standalone benchmark build | Pass |
| Windows benchmark profiles | Pass |
| Native Wintun DLL load | Pass |
| Native adapter/session creation | Pass |
| Reserved route and DNS apply | Pass |
| Adapter/session teardown | Pass |
| Post-run residue check | Clear |

The standalone benchmark capture is under the ignored directory
`benchmark-runs/windows-native-post-loader-2026-08-09/`. The validator's
native-enabled profiles are under
`benchmark-runs/windows-native-post-loader-native-2026-08-09/`; both
`secure-default.csv` and `classical-lab.csv` were emitted.

## Native Smoke Result

The elevated validator completed with exit code `0` and reported:

```text
Windows native TUN validation completed successfully.
SHPH_TUN_NATIVE=1
SHPH_WINTUN_SHA256=E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE
```

The smoke created a real Wintun adapter/session, applied the reserved
`198.18.0.0/15` route and temporary `1.1.1.1` DNS setting, then tore them down.
The follow-up host check found no `shph-*` adapter, reserved route, SHPH DNS
entry, `shph` process, or `shph-phase-f-*` temporary directory.

## Cleanup Follow-Up

The first post-loader run exposed a malformed Windows route-delete command in
its console output even though `netsh` returned success and the host was left
clean. The rollback path now carries the adapter interface name into
`netsh interface <family> delete route`, and a Windows-specific regression
assertion covers the generated `interface=...` argument.

A final rerun of `validate_windows_tun.ps1` after that source fix remains
required from an Administrator PowerShell session. The current non-elevated
shell could not execute the script's `#Requires -RunAsAdministrator` gate.

## Remaining Host Gates

1. Rerun the validator from an Administrator PowerShell session after the
   route-rollback fix.
2. Exercise Wintun packet receive/send and wait-event behavior.
3. Validate reconnect and Ctrl+C shutdown during a live native session.
4. Run a separate authenticated two-node Windows tunnel and performance test.

Native Linux two-host forwarding, standards-QUIC impairment testing, and the
final Phase E release snapshot/tag remain separate gates.
