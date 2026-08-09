# Native TUN Status — 2026-08-04

## Scope

This note records the Linux native-TUN work in workspace version
`0.5.0-dev.0` against `research stuff/NATIVE_TUN_IMPLANTATION_SPEC.md`.
It is implementation evidence, not a claim that SHPH is a production VPN or
that Windows Wintun delivery is complete.

## Implemented

- Linux opens `/dev/net/tun` with `O_NONBLOCK`.
- Linux opens `/dev/net/tun` with `O_CLOEXEC | O_NOFOLLOW` and requests
  `IFF_TUN_EXCL`, preventing descriptor inheritance and refusing accidental
  attachment to a pre-existing interface owned by another process. The opened
  descriptor is type-checked after open, avoiding a path-metadata TOCTOU.
- `TUNSETIFF` uses `IFF_TUN | IFF_NO_PI | IFF_TUN_EXCL`, so the data plane
  receives raw layer-3 IPv4/IPv6 packets without a packet-information header
  and does not silently attach to an existing interface.
- Interface names are validated before the ioctl and are bounded to the Linux
  15-byte name limit.
- The read buffer is exactly `65,536` bytes (`65,535` maximum packet bytes plus
  one truncation-detection byte).
- IPv4 and IPv6 version, header, and declared-length fields are validated at
  both ingress and egress boundaries. IPv6 jumbo-payload encoding is rejected
  explicitly.
- Native capability and ioctl errors map to actionable fail-closed errors.
- `up` keeps one validated native device alive through control-plane setup,
  session startup, and reconnect attempts; it does not probe, drop, and
  recreate the interface.
- Native file descriptors are cloned only for the two directional data-plane
  workers.
- Short native writes are rejected instead of being retried as a second
  partial packet.
- Native bridge packet buffers are zeroized on drop.
- Linux exposes `AsyncTunDevice`, a Tokio `AsyncFd` wrapper with the same
  packet validation and complete-write rules. Linux native `up` now uses this
  async bridge with bounded packet queues and blocking transport workers.
  `native_tun_probe` exercises its open/hold/close lifecycle.
- Linux standards-QUIC `up` now connects two cloned `AsyncTunDevice` handles
  to the RFC 9221 QUIC DATAGRAM data plane. Received datagrams are validated
  as IPv4/IPv6 packets before TUN injection; oversized packets and malformed
  authenticated datagrams are bounded and counted rather than injected.
- Windows has a wired Wintun backend with hash-pinned application-local DLL loading,
  mandatory `SHPH_WINTUN_SHA256` provenance pinning, administrator checks,
  ring-capacity bounds, receive/release and allocate/send packet wrappers, IP
  validation, bounded read-event waits, shared-session cloning, explicit
  wait-status classification, UTF-16/control-character adapter-name
  validation, receive-buffer wiping on errors, and RAII teardown.
  Runtime execution remains host-gated until a real elevated Windows host
  validates the signed DLL, adapter lifecycle, and packet path.

### Wintun provisioning

Place the operator-approved, signed `wintun.dll` beside the application
executable. Compute its deployment-specific SHA-256 and set the exact
64-character hexadecimal digest before starting native TUN:

```powershell
$env:SHPH_WINTUN_SHA256 = (Get-FileHash .\wintun.dll -Algorithm SHA256).Hash
```

The loader rejects a missing or malformed variable and refuses to load a file
whose digest differs. The digest is intentionally supplied by deployment
configuration rather than hard-coded here, because the approved Wintun release
is an operator/release artifact. Native Windows verification must still confirm
the signer, ACLs, adapter creation, packet I/O, and shutdown behavior.

## Validation

Passing Linux checks:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo build --workspace --locked
cargo check --manifest-path benchmarks/Cargo.toml --locked
cargo check --manifest-path fuzz/Cargo.toml --locked
```

Focused `shph-tun` result on August 4, 2026:

```text
15 passed; 0 failed
```

The focused regression set covers interface-name validation, the Linux
`ifreq` ABI size and native open flags, native-open fail-closed behavior,
async-open capability gating, valid async packet delivery, malformed-packet
rejection, EOF handling, stub conversion refusal, IP length validation, and
the complete-write requirement.

The host exposes `/dev/net/tun`, but the outer WSL2 process has no effective
`CAP_NET_ADMIN`; direct SHPH native startup therefore fails closed at
`TUNSETIFF` with `PermissionDenied`. The isolated namespace smoke command is
available through `scripts/native_tun_namespace_test.sh` and
`scripts/benchmark_native_tun.sh`. The outer process lacks effective
`CAP_NET_ADMIN`, but this host permits an isolated user/network namespace:
the smoke test opened and closed a real TUN device successfully.

The documented 20-sample lifecycle smoke run completed with:

```text
min_ns=58672713
p50_ns=199054823
p95_ns=458718205
max_ns=468719396
```

These values include isolated namespace/process startup and are not packet
throughput or steady-state data-plane latency. The 20 samples all returned
`pass`.

## Post-integration rerun

After the Linux async bridge and Windows public-backend wiring changes, the
Linux validation rerun completed successfully:

- `shph-cli`: 29 unit tests plus all CLI integration suites passed.
- `shph-core`: 66 unit tests and 13 handshake-flow tests passed.
- `shph-transport`: 47 tests passed.
- `shph-tun`: 15 tests passed.
- Workspace fmt, Clippy, tests, locked build, benchmark-manifest check,
  fuzz-manifest check, and `git diff --check` passed.
- Isolated namespace smoke passed.

The fresh 20-sample isolated lifecycle run on WSL2 reported:

```text
min_ns=59305434
p50_ns=269811993
p95_ns=376458440
max_ns=418330327
```

These are probe open/hold/close values, not packet throughput, live tunnel
latency, or two-host VPN performance.

The fresh 20-sample lifecycle run from the final validation pass reported:

```text
min_ns=109151183
p50_ns=268705223
p95_ns=388429286
max_ns=479208194
```

All 20 samples returned `pass`. The values include isolated namespace and
process startup overhead and are not data-plane throughput or steady-state
latency.

## Pre-audit rerun

After the pre-audit hardening increment, a fresh five-sample WSL2 lifecycle
run completed with:

```text
min_ns=89096056
p50_ns=208642428
p95_ns=309358567
max_ns=309358567
```

All five samples returned `pass`. This remains lifecycle smoke evidence only;
it does not establish native Linux two-host forwarding, throughput, goodput,
latency-under-load, or Windows Wintun runtime behavior.

## Still host-gated

- Windows signed-runtime provenance, adapter installation, event-loop mapping,
  and packet-I/O evidence on a supported elevated Windows host.
- Native Linux two-host packet forwarding, route/DNS acceptance, throughput,
  goodput, RTT, jitter, CPU, RSS, and reconnect benchmarks.
- Windows signed-runtime provenance, elevated-host packet I/O, and
  two-machine Windows tunnel evidence.

These remain explicit roadmap gates rather than hidden placeholders. The
namespace script is an isolated lifecycle check, not a throughput result.
