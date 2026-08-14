# Native Windows Validation - 2026-08-09

## Scope

This record captures the elevated native Windows retry for workspace version
`0.5.0-dev.0`. It confirms that the release builds and local benchmark
capture still pass, and that the validator reaches the real signed-target
Wintun load. The run used the platform-matching
`<downloads>\wintun-0.14.1\wintun\bin\amd64\wintun.dll` from the
package README's side-by-side deployment layout. The live adapter lifecycle
did not start because Windows rejected the staged runtime with Win32 error
`577`.

This is not live packet-forwarding, route/DNS, reconnect, shutdown, or
two-node VPN evidence. The August 8 record remains the baseline for the
native Windows workspace test totals and focused Windows regressions.

## Host and Toolchain

- Date: August 9, 2026
- OS: Windows `10.0.26200.0`
- PowerShell: `5.1.26100.8875`
- Rust: `rustc 1.96.0 (ac68faa20 2026-05-25)`
- Cargo: `cargo 1.96.0 (30a34c682 2026-05-25)`
- Target: `x86_64-pc-windows-msvc`
- Administrator elevation: confirmed
- Secure Boot: enabled
- Workspace version: `0.5.0-dev.0`

## Elevated Validator

The validator was run from the directory containing the staged `wintun.dll`:

```powershell
Push-Location .\.wintun-validation-runtime
..\validate_windows_tun.ps1
Pop-Location
```

The staged runtime was copied from the official package layout:

```text
<downloads>\wintun-0.14.1\wintun\bin\amd64\wintun.dll
```

| Gate | Result |
| --- | --- |
| `cargo build --workspace --release --locked` | Pass |
| `cargo build --release --manifest-path benchmarks/Cargo.toml --locked` | Pass |
| Windows benchmark capture, both profiles | Pass |
| Native Wintun load and adapter creation | Blocked before adapter creation |
| Validator exit | Fail closed with Win32 error `577` |

The benchmark validator emitted non-empty `secure-default.csv` and
`classical-lab.csv` files under the ignored archived directory
`benchmark-runs/windows-native-pre-loader-2026-08-09/`. These are local
authenticated operation measurements, not TUN packet throughput.

The live smoke command failed with:

```text
unable to load signed Wintun runtime: Win32 error 577
```

The validator then ran its best-effort `down` cleanup and reported no applied
control-plane state.

## Runtime Provenance

The staged runtime was inspected before loading:

- File version: `0.14.1`
- Size: `427552` bytes
- PowerShell Authenticode status: `Valid`
- Reported signer: WireGuard LLC
- SHA-256:
  `E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE`
- Signer certificate expiry: December 14, 2021
- `certutil -dump` chain result: `CERT_E_EXPIRED` against the current clock

The exact hash passed SHPH's provenance pinning. The failure is therefore not
a missing, malformed, or mismatched hash. Windows error `577` means the
signed-target load was rejected by the current Windows image-signature policy.
The package's `amd64` DLL has the same file version, hash, and signing
certificate as the previously inspected copy; selecting the README-recommended
platform directory does not change the result.

## Loader Isolation Probe

An independent `LoadLibraryExW` probe against the same application-local DLL
isolated the rejection to `LOAD_LIBRARY_REQUIRE_SIGNED_TARGET`:

| Flags | Result | Last error |
| --- | --- | --- |
| `0x0` | Loaded | `0` |
| `0xA00` (`SEARCH_APPLICATION_DIR` + `SEARCH_SYSTEM32`) | Loaded | `0` |
| `0xA80` plus `REQUIRE_SIGNED_TARGET` | Rejected | `577` |

This was the pre-loader recommendation. The current implementation retains
`SHPH_WINTUN_SHA256` and the restricted application-local search flags while
omitting `LOAD_LIBRARY_REQUIRE_SIGNED_TARGET` because this host rejected the
official runtime at that boundary. See the post-loader follow-up below.

## Cleanup Verification

After the failed smoke:

- No `shph-*` or Wintun adapter was present.
- No `198.18.0.0/15` route was present.
- No SHPH/Wintun DNS entry was present.
- No `shph-phase-f-*` temporary smoke directory remained.
- No `shph` process remained running.

## Remaining Host Gates

The following remain pending:

1. Supply and independently verify an operator-approved current signed x64
   `wintun.dll`.
2. Rerun `validate_windows_tun.ps1` until adapter/session creation succeeds.
3. Validate packet receive/send, wait-event behavior, route/DNS apply and
   rollback, reconnect, Ctrl+C shutdown, and teardown.
4. Run a separate two-node authenticated Windows tunnel and performance test.

Native Linux two-host forwarding, standards-QUIC impairment testing, and the
final Phase E release snapshot/tag remain separate gates.

## Superseding follow-up

This record captures the pre-loader-change failure and remains historical.
The post-loader adapter/session smoke and current validation disposition are
recorded in
`docs/evidence/WINDOWS_NATIVE_VALIDATION_2026-08-09_POST_LOADER.md`.
