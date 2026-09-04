# Elevated Windows forced-termination and WFP cleanup validation

## Result

| Field | Value |
| --- | --- |
| Validation date | 2026-09-01 |
| Status | PASS |
| Host scope | One elevated Windows host |
| Evidence class | Engineering evidence; not a clean release snapshot |
| Procedure | `scripts/validate_windows_wfp_crash.ps1` |
| Wintun Authenticode | `Valid` |
| Wintun SHA-256 | `E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE` |
| Session | Native Wintun client with `up --killswitch` and a local no-TUN TCP listener |
| Pre-existing SHPH WFP filters | `0` |
| SHPH WFP filters while active | `7` |
| SHPH WFP filters after `Stop-Process -Force` | `7` |
| SHPH WFP filters after explicit `shph down` | `0` |
| Post-cleanup residue | No SHPH process, generated adapter, matching route/DNS state, control-plane state, or test directory |

## Procedure

The elevated script created two fresh local identities, pinned both identity
keys, started a local no-TUN TCP listener, and started a native Wintun client
with `--killswitch`. It captured the WFP filter state, hard-terminated the
client with `Stop-Process -Force`, captured WFP again, then invoked
`shph down` explicitly and verified WFP and host-state cleanup.

Reproduce from an elevated Windows PowerShell prompt after building the release
binary and placing the Authenticode-verified runtime at `.\wintun.dll`:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\validate_windows_wfp_crash.ps1 `
  -Binary .\target\release\shph.exe `
  -Wintun .\wintun.dll
```

The raw run directory is intentionally machine-local and is not a publication
artifact. The public record above omits usernames, absolute paths, process IDs,
random adapter names, temporary identities, and command output containing
identity material.

## Interpretation and boundary

This PASS establishes a narrow single-host sequence: SHPH-owned WFP policy was
observable while the native client was active, remained observable after hard
termination, and was removed by an explicit `shph down`. It also records clean
adapter, route/DNS, process, control-plane, and temporary-directory teardown.

Because a forced process termination does not run normal application cleanup,
this is not evidence that Windows automatically removes WFP policy at crash
time. The run did not assert packet blocking or packet-leak prevention after
the kill. It also does not establish Windows-to-Windows or Linux-to-Linux
forwarding, real Internet DNS/IPv6/UDP/QUIC reachability, or long-duration
path-soak behavior.
