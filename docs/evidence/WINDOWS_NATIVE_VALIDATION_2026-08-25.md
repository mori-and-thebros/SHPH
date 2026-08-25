# Windows Native TUN and WFP Lifecycle Evidence — 2026-08-25

This is an engineering snapshot from an elevated Windows host. It records
native Wintun adapter/session lifecycle, route/DNS rollback, and the opt-in
Windows Filtering Platform killswitch smoke. Packet forwarding was validated
separately in the cross-platform report
`CROSS_PLATFORM_NATIVE_TUN_VALIDATION_2026-08-25.md`. This record alone does
not claim two-host throughput, reconnect reliability, crash-time containment,
or production VPN readiness.

## Provenance

| Field | Value |
| --- | --- |
| Validation base | `v0.6.5-dev`, `HEAD=e44483897574d39a550b2c145d47fc480ffa4e5b` |
| Publication ref | `v0.6.5-dev.1` follow-up |
| Date | August 25, 2026 |
| Host | Windows 11 workstation |
| Target | `x86_64-pc-windows-msvc` |
| Rust | `rustc 1.96.0 (ac68faa20 2026-05-25)` |
| Wintun | Application-local AMD64 runtime |
| Authenticode | Valid; signer reported as WireGuard LLC |
| Wintun SHA-256 | `E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE` |
| Capture timing | Pre-publication engineering run; sanitized and published with the follow-up |

The validation base identifies the source revision used for the run; the
sanitized report is published with the `v0.6.5-dev.1` follow-up.

## Gate results

| Gate | Result |
| --- | --- |
| Native Windows TUN validator | PASS |
| Signed and SHA-256-pinned Wintun load | PASS |
| Native adapter/session creation | PASS |
| Temporary route apply and rollback | PASS |
| Temporary DNS apply and rollback | PASS |
| Elevated WFP killswitch install | PASS |
| WFP policy teardown | PASS |
| Post-run residue audit | PASS |
| Workspace tests, final pre-doc pass | PASS — 316 tests, 0 failures |
| Workspace strict Clippy | PASS |
| Release CLI build | PASS |

## Native TUN validator

The elevated validator completed with exit code `0`. It loaded the
application-local signed Wintun DLL, created a real adapter/session, applied a
reserved `198.18.0.0/15` route and temporary `1.1.1.1` DNS setting, then
removed them during teardown.

The post-run audit found:

- no SHPH/Wintun adapter;
- no `198.18.0.0/15` route;
- no SHPH process;
- no temporary `1.1.1.1` DNS entry; and
- no temporary SHPH phase directory.

This validates lifecycle and control-plane rollback. The validator itself did
not inject packets through a peer; forwarding, throughput, reconnect, and
impairment results are recorded separately in the cross-platform report.

## Windows WFP smoke

An elevated loopback-only configuration exercised `up --killswitch` and
`down`. The fresh capture returned:

```text
up=0
down=0
hash=E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE
```

The run installed the persistent SHPH WFP policy, initialized native TUN, and
cleanly removed the policy and session. The final elevated filter audit found
no SHPH-owned WFP records.

The WFP implementation required two corrections during this pass:

1. `FwpmEngineOpen0` now uses the supported Windows RPC authentication service.
2. ALE connect filters use the generic remote-address condition with the
   correct IPv4/IPv6 value-mask type.

The smoke used a loopback peer configuration only. It is not evidence of
Internet connectivity, packet forwarding, crash-time leak behavior, or
two-node killswitch effectiveness.

## Remaining host gates

Still open beyond the separately recorded cross-platform direct-TCP lane:

1. a Windows-to-Windows native Wintun forwarding campaign;
2. reconnect and Ctrl+C behavior during a live native session;
3. authenticated two-node throughput and packet-loss measurements;
4. crash/forced-termination leak behavior under the persistent WFP policy; and
5. native Linux-to-Linux forwarding and standards-QUIC host evidence.
