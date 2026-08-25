# Windows Native TUN and WFP Lifecycle Evidence — 2026-08-25

This is an engineering snapshot from an elevated Windows host. It records
native Wintun adapter/session lifecycle, route/DNS rollback, and the opt-in
Windows Filtering Platform killswitch smoke. It does not claim packet
forwarding, two-host throughput, reconnect reliability, or production VPN
readiness.

## Provenance

| Field | Value |
| --- | --- |
| Workspace base | `v0.6.4-dev.4`, `HEAD=ade2c8355d34312cd528b4c0fa8578df9dd9de2d` |
| Date | August 25, 2026 |
| Host | Windows 11 workstation |
| Target | `x86_64-pc-windows-msvc` |
| Rust | `rustc 1.96.0 (ac68faa20 2026-05-25)` |
| Wintun | Application-local AMD64 runtime |
| Authenticode | Valid; signer reported as WireGuard LLC |
| Wintun SHA-256 | `E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE` |
| Working tree | Dirty engineering tree; this record is not a release snapshot |

The benchmark commit field identifies `HEAD`; it does not imply that the
working-tree changes were committed or published.

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
| Workspace tests, final pre-doc pass | PASS — 315 tests, 0 failures |
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

This validates lifecycle and control-plane rollback. The validator did not
inject packets through a peer or measure forwarding throughput.

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

Still open for a broader native Windows claim:

1. real Wintun packet send/receive through a configured peer;
2. reconnect and Ctrl+C behavior during a live native session;
3. authenticated two-node Windows forwarding and throughput;
4. crash/forced-termination leak behavior under the persistent WFP policy; and
5. native Linux two-host forwarding.
