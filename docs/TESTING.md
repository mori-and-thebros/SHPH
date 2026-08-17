# SHPH Testing Guide

This project uses workspace-wide validation and crate-level tests.

## Fast Local Commands

```bash
cargo fmt --all -- --check
cargo check --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
```

For quick local diagnosis:

```bash
shph doctor
shph doctor --strict --json
shph status --json
shph list-peers --json
```

For the binding release and security collectors on Windows or PowerShell
Core:

```powershell
pwsh -File .\scripts\release_readiness.ps1 -AllowDirty
pwsh -File .\scripts\security_evidence.ps1 -AllowDirty
```

These commands write timestamped, machine-readable and Markdown snapshots
under `benchmark-runs/`. `-AllowDirty` is for engineering evidence only; a
dirty-tree result is never release-eligible. Both collectors preserve
`FAIL`/`SKIP` statuses instead of turning unavailable host capabilities into
passes. See `docs/RELEASE_READINESS.md` and `docs/SECURITY_EVIDENCE.md`.

## Host prerequisites and evidence provenance

The workspace must be validated with a complete native toolchain. On Windows,
the MSVC Rust target requires Visual C++ Build Tools (including `link.exe`).
The GNU target is not a substitute unless its complete LLVM-MinGW/libgcc
runtime is installed. Linux-only scripts and fuzz campaigns require a native
Linux environment; WSL is not assumed.

Native Windows validation is maintained as a separate, date-stamped host
campaign and is recorded in
`docs/evidence/WINDOWS_NATIVE_VALIDATION_2026-08-09_POST_LOADER.md`. That record
should be used for platform-status review. Local workstation availability is
intentionally not treated as release evidence.

Remaining product gates are still explicit: native TUN packet I/O, route/DNS
rollback, reconnect, teardown, and two-host forwarding require the dedicated
host campaigns described in `docs/SUPPORT_MATRIX.md` and
`docs/RELEASE_READINESS.md`.

## Focused Test Runs

### CLI integration tests

```bash
cargo test -p shph-cli --test cli_basic
cargo test -p shph-cli --test cli_tcp_handshake
cargo test -p shph-cli --test cli_tcp_data_plane
cargo test -p shph-cli --test cli_up_session_mode
cargo test -p shph-cli --test cli_control_plane
cargo test -p shph-cli --lib --locked
```

### Core handshake tests

```bash
cargo test -p shph-core --lib --locked
cargo test -p shph-core --test handshake_flow --locked
cargo test -p shph-identity --locked
cargo test -p shph-transport --lib --locked
```

The focused hardening tests include bounded replay-window and HKDF construction
(including output-size limits),
peer-policy pin limits, canonical nonce parsing, TCP cookie/line framing,
pipelined follow-up bytes, outbound TCP and unshrouded-QUIC frame limits,
local handshake-material binding, inline-PQ metadata rejection, anchored
identity-record continuity,
collision-resistant file-adapter paths, pre-encryption adapter payload bounds,
bounds that include AEAD/base64/envelope overhead, deadline-aware hostname
resolution, and interface-scoped route rollback. Privileged command-builder
coverage also exercises the shared
strict TUN interface-name validator.
The special-file and X25519 checks are source-level fail-closed guards and
should be exercised by the complete platform test matrix.

### Native TUN checks

The default TUN tests are capability-gated and fail closed when the host
cannot configure `/dev/net/tun`. The Linux async API and packet boundary
regressions are covered by:

```bash
cargo test -p shph-tun --offline
cargo clippy -p shph-tun --all-targets --offline -- -D warnings
./scripts/native_tun_namespace_test.sh
./scripts/benchmark_native_tun.sh --iterations 20 --hold-ms 0
```

The namespace and lifecycle scripts isolate the probe with
`unshare --user --map-root-user --net`. They print `PASS` only when the
isolated AsyncFd probe opens and closes a real TUN device, and print `SKIP`
when the host denies the namespace or network capability. They do not measure
packet throughput, routing, RTT, jitter, or two-node behavior.

### Firewall and MSS hardening checks

The default test suite does not mutate host firewall state. The bounded plan
builders and CLI peer-selection rules can be checked without elevation:

```bash
cargo test -p shph-tun firewall --locked
cargo test -p shph-cli killswitch --locked
```

For a non-mutating operator preview, provide a configuration containing at
least one literal peer IP/port and run:

```bash
shph up --config <path> --killswitch --killswitch-dry-run
```

Dry-run mode does not require native TUN, administrator/root privileges, or
`nft`/WFP mutation. Live `--killswitch` and Linux `--mss-clamp` require
`SHPH_TUN_NATIVE=1`, native host privileges, and platform-specific validation.
Windows WFP execution, Linux crash-leak behavior, and two-host forwarding are
not established by these deterministic tests.

### Fuzzing

The standalone `fuzz/` workspace contains `cargo-fuzz` targets for framing,
configuration parsing, audit-record parsing, replay-window state, and the
Shroud 2 datagram envelope. See `fuzz/README.md` for setup and bounded run
commands. Fuzzing is an additional security gate, not a substitute for the
deterministic test suite.

### 30-minute fuzz campaign (Linux, 2026-07-21)

All four targets ran concurrently under nightly `rustc 1.99.0-nightly` for
`-max_total_time=1800`. Every target exited with code 0 and produced no crash,
leak, OOM, or timeout artifacts:

- `frame_decode`: 654,172,020 executions; coverage 69; corpus 13 files.
- `config_parse`: 35,979,131 executions; coverage 3,932; corpus 2,915 files.
- `audit_record`: 330,407,632 executions; coverage 1,344; corpus 1,946 files.
- `replay_window`: 1,101,717,299 executions; coverage 49; corpus 53 files.

This is campaign evidence for the current harnesses, not a proof of absence of
security defects.

## Pre-completion audit workflow

Before Phase D is marked complete, freeze the audit input tree and record the
workspace version, commit, toolchain, lockfiles, and validation commands. The
auditor's findings must be tracked with severity, affected path, disposition,
and a regression-test requirement. After remediation, rerun the focused tests
for each finding and the full workspace validation set before publishing the
audit disposition.

### Phase D fuzz campaign (Linux/WSL2, 2026-07-28)

All four targets ran under nightly Rust with `cargo-fuzz 0.13.2`,
`--sanitizer none`, and `-max_total_time=20` per target. Every target exited
with code 0 and produced no crash artifacts:

- `frame_decode`: 26,183,071 executions; coverage 58; peak RSS 47 MiB.
- `config_parse`: 2,455,022 executions; coverage 1,572; peak RSS 46 MiB.
- `audit_record`: 9,823,297 executions; coverage 818; peak RSS 47 MiB.
- `replay_window`: 30,734,181 executions; coverage 33; peak RSS 47 MiB.

`frame_decode` used `fuzz/shroud.dict` and selected all five current Shroud
profiles. This is repeatable lab evidence, not a proof of absence of defects.

The campaign corpora were replayed afterward with `-runs=0`:
`frame_decode` (49 inputs), `config_parse` (4,824), `audit_record` (3,760),
`replay_window` (62). All replays completed without crash artifacts. The
`shroud2_datagram` target was added after this historical campaign.

The supported replay command is run from the fuzz workspace:

```bash
cd fuzz
cargo +nightly fuzz run frame_decode corpus/frame_decode \
  --sanitizer none -- -runs=0
```

Repeat it for the other target names listed above.

### Pinned fuzz smoke follow-up (Linux/WSL2, 2026-08-05)

The CI-pinned nightly was installed and used for a bounded smoke run:

```text
rustc 1.99.0-nightly (d0babd8b6 2026-07-15)
cargo-fuzz 0.13.2
```

With `--sanitizer none` and `-runs=1`, all five current targets passed:
`frame_decode`, `config_parse`, `audit_record`, `replay_window`, and
`shroud2_datagram`. A second bounded run using the default sanitizer path with
`LSAN_OPTIONS=detect_leaks=0 ASAN_OPTIONS=detect_leaks=0` also passed for all
five targets. Leak reporting is disabled only because the local WSL wrapper
causes LeakSanitizer to fail under ptrace; these smoke runs do not replace the
sanitizer-enabled CI job or a longer fuzz campaign. Full details are in
`docs/VALIDATION_FOLLOWUP_2026-08-05.md`.

## Historical platform-targeted test runs (2026-07-15)

- Linux validation was run from a native Linux checkout.
- Windows validation was run from a native Windows checkout.

Commands executed:
- `cargo fmt --all`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`

## Historical Result (2026-07-15)

- Status: **PASS**
- Workspace totals: **regenerated by `cargo test --workspace`; see the latest
  evidence artifact for exact totals**
- CLI tests:
  - `cli_basic`: 1 passed
  - `cli_tcp_handshake`: 1 passed
  - `cli_tcp_data_plane`: 1 passed
  - `cli_up_session_mode`: 2 passed
  - `cli_control_plane`: 6 passed
- Core tests:
  - `shph-core` unit tests: 54 passed
  - `shph_core` `handshake_flow`: 9 passed
- Transport crate tests:
  - `shph-transport` unit tests: 13 passed
- Other crates: `shph-config` 2 passed; `shph-tun` 6 passed
- Validation command set: `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`
- Observability note: when host loopback sockets are denied by policy (`Operation not permitted`), transport integration tests return early via capability guard to avoid false negatives in restricted test sandboxes.
- The trailing `0 passed` lines are empty doctest suites; they are not skipped
  unit/integration tests or failures.

### Follow-up hardening pass (Linux/WSL2, 2026-08-04)

The shared Shamir API resource-bound regression set passed:

```bash
cargo fmt --all -- --check
cargo test -p shph-core roadmap
cargo clippy -p shph-core --all-targets -- -D warnings
```

Coverage includes oversized split secrets, excessive recovery share counts,
and decoded share payloads above the canonical 256 KiB raw limit. The core API
caps split input at 128 KiB; the CLI remains capped at 64 KiB and recovery
inputs remain bounded by file-count, per-file, aggregate, and decoded-share
limits.
- Phase A.1 closeout (2026-06-24): `shph-cli` unit tests now 13 passed
  (adds `request_and_reset_shutdown_roundtrip`). `cli_up_session_mode`
  assertions extended to verify the `Session id`/`Session start`/`Session end`/
  `Final metrics` trail on one-shot and loop `up` paths.

### Phase A.1 Live Evidence (Linux, 2026-06-24)

Session lifecycle trail captured from a live `up` one-shot run (loopback TCP):

- Connector (`send-once`): `Session id: send-once-...`, `Session start`,
  `handshake send-once ok`, `Sent bytes: 19`, `Session end`,
  `Final metrics: MetricsSnapshot { bytes_sent: 19, packets_sent: 1, ... }`.
- Listener (`recv-once`): `Session id: recv-once-...`, `Session start`,
  `handshake recv-once ok`, `Payload: a1-evidence-payload`, `Session end`,
  `Final metrics: MetricsSnapshot { bytes_recv: 19, packets_recv: 1, ... }`.

Graceful teardown evidence (SIGINT on a running connect-loop session):

- SIGINT delivered -> within ~200ms the connect loop printed
  `Transport loop: closed`, `Session end`, `Final metrics`, then exited with
  code 0 (not killed).
- The peer (listener) closed cleanly on `ConnectionClosed`: same
  `Transport loop: closed` / `Session end` / `Final metrics` trail, exit 0.

### Windows Verification (operator action required)

- Native Windows validation was rerun from an elevated session on August 9,
  2026. Release workspace and benchmark builds passed, and the validator
  emitted both local benchmark profiles.
- The native Windows workspace test run reported **180 passed and 0 failed**.
  The focused Windows Wintun unit group reported 6 passed, and the Windows
  ACL keystore regression reported 1 passed.
- The latest post-loader evidence is
  `docs/evidence/WINDOWS_NATIVE_VALIDATION_2026-08-09_POST_LOADER.md`.
- The elevated post-loader validator accepted the same
  `wintun-0.14.1\wintun\bin\amd64\wintun.dll`, created a real adapter/session,
  applied the reserved route and DNS settings, and completed teardown without
  residue.
- The loader uses restricted application/system search flags plus
  application-local filename, elevation, and SHA-256 checks. The validator
  separately requires a valid Authenticode signature. A route rollback
  interface-argument fix is covered by unit tests but still needs a clean
  elevated rerun before final release evidence.
- Windows console-control handling is wired through `windows-sys`; verify it by
  sending Ctrl+C to a running `up` session.
- Native Wintun adapter, packet-I/O, route/DNS, reconnect, Ctrl+C, and
  two-machine evidence remain separate host-gated release work.

Linux cross-target validation now passes with a user-space MinGW toolchain
extracted outside the repository:

- `cargo check --workspace --target x86_64-pc-windows-gnu --locked --offline`
- `cargo clippy --workspace --all-targets --target x86_64-pc-windows-gnu --locked --offline -- -D warnings`
- `cargo build --workspace --target x86_64-pc-windows-gnu --locked --offline`

The cross-target gates validate compilation and linting only. They do not
replace native Windows execution, Wintun provisioning, administrator checks,
adapter lifecycle, packet I/O, or two-machine evidence.

### Phase A.2 Evidence (Linux, 2026-06-24)

Control-plane atomicity (live `up`, `dry_run=false`):

- Config with one good route (`10.99.0.0/16`) + one bad route (`10.88.0.0/40`)
  was rejected up front: `Error: Config("CIDR prefix out of range: 10.88.0.0/40")`,
  and no route was applied (no `route add` output).

Validation suite (all passing):

- `cargo fmt --all` (clean)
- `cargo clippy --workspace --all-targets -- -D warnings` (clean)
- `cargo test --workspace`: 36 passed, 0 failed
- `shph-cli` unit tests: 19 passed (was 13 after A.1; +6 control-plane plan tests)
- `cli_control_plane`: 3 passed

New control-plane unit tests cover preflight atomicity, plan normalization
(IPv4+IPv6 CIDRs, multiple DNS), interface-name requirement, empty-DNS skipping,
the `dry_run` guard flag, and default-plan emptiness.

### Phase A.3 Evidence (Linux, 2026-06-24)

Security baseline validation (all passing):

- `cargo fmt --all` (clean)
- `cargo clippy --workspace --all-targets -- -D warnings` (clean)
- `cargo test --workspace`: 52 passed, 0 failed
- `shph-core` unit tests: 19 passed (was 3; +16 security/crypto/framing/net tests)

Security regression coverage:

- Anti-replay: replayed AEAD nonce rejected fail-closed
  (`replayed_frame_is_rejected_fail_closed`); out-of-order nonce rejected
  (`out_of_order_nonce_is_rejected`).
- EOF/truncated frames: `< 12-byte` ciphertext rejected
  (`truncated_ciphertext_is_rejected_fail_closed`); TCP read/write loops map
  EOF/reset to `ConnectionClosed` (fail-closed).
- Malformed/oversized frames: oversize payload, corrupt header, oversize
  length field, and unsupported frame type all rejected (framing tests).
- Input validation: `Endpoint` no longer panics on bad hosts; new
  `to_socket_addr_result` returns errors instead of `.unwrap()`.
- Peer-policy tests require both the pinned X25519 identity and Ed25519
  handshake-signing public key.
- Keystore tests cover final-component symlink refusal and bounded encrypted
  PBKDF2 parameters.
- Ratchet-audit tests cover final-component symlink refusal.
- Wrong-key AEAD authentication fails closed (`wrong_key_authentication_fails`).

Bounded handshake: `tcp_accept_and_handshake` drops malformed/closing peers and
continues accepting until the operator timeout. The regression
`tcp_listener_survives_malformed_peer_flood` proves a later valid peer can still
connect after six malformed peers.

## Test Intent Snapshot

- `cli_basic`: command surface sanity.
- `cli_tcp_handshake`: one-shot authenticated handshake path.
- `cli_tcp_data_plane`: one-shot encrypted frame transfer.
- `cli_up_session_mode`: session-driven `up` behavior for one-shot and loop modes.
- `cli_control_plane`: dry-run logging, invalid CIDR rejection, reconnect logging.
- `handshake_flow`: transcript and protocol validation logic.

## Notes

- Control-plane live apply paths (`dry_run=false`) depend on host tools and privileges.
- CI and local default tests intentionally focus on deterministic behavior without requiring privileged network mutation.
- Linux native TUN lifecycle checks:
  - `SHPH_TUN_NATIVE=1` enables `/dev/net/tun` path.
  - The `up` path keeps one validated native device open through control-plane
    setup, session startup, and reconnect attempts; it does not drop and
    recreate the interface between those stages.
  - Native writes require one complete kernel write; short writes fail closed.
  - Interrupted native reads/writes are retried, native EOF is reported as
    connection closure, and rejected packet bytes are wiped from read buffers.
  - Native receive errors wipe the complete caller-provided buffer, preventing
    stale packet bytes from surviving EOF, malformed-packet, or I/O failures.
  - Native bridge packet buffers are zeroized on drop.
  - `AsyncTunDevice` uses Tokio `AsyncFd` readiness on Linux, and Linux native
    `up` uses the async TUN bridge with bounded queues and blocking transport
    workers. Standards-QUIC `up` uses its separate bounded RFC 9221 bridge.
  - Interface name constraints are validated before ioctl.
  - Permission and ioctl failures return explicit actionable errors.
  - IP version/header/length validation rejects malformed packets at the TUN
    boundary; IPv6 jumbo packets are currently rejected by policy.
  - The Windows backend validates hash-pinned application-local Wintun loading,
    administrator elevation, bounded rings, packet release/commit, bounded
    event waits, shared-session cloning, and RAII teardown in source; real
    Windows host evidence is still required.
  - On Windows, `SHPH_TUN_NATIVE=1` fails closed if the signed runtime,
    elevation, adapter, or session setup is unavailable; it does not silently
    run a stub tunnel.
  - Native Windows also requires `SHPH_WINTUN_SHA256` to match the
    application-local `wintun.dll`; see `docs/NATIVE_TUN_STATUS_2026-08-04.md`
    for provisioning.
  - UDP-shim tests cover source-table exhaustion and strict frame-length
    validation. The standards-QUIC loopback test covers real QUIC/TLS,
    application handshake, control streams, and RFC 9221 datagrams. A host
    that blocks local UDP sockets may still return `EPERM`.

### Native Linux TUN evidence (2026-08-04)

The focused native-TUN suite passed with 15 tests and 0 failures. The full
workspace gates also passed:

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`
- `cargo build --workspace --locked`
- `cargo check --manifest-path benchmarks/Cargo.toml --locked`
- `cargo check --manifest-path fuzz/Cargo.toml --locked`

The outer WSL2 process exposes `/dev/net/tun` but lacks effective
`CAP_NET_ADMIN`, so direct `TUNSETIFF` startup fails closed with an explicit
permission error. The isolated namespace smoke and lifecycle scripts pass on
this host; they validate only AsyncFd open/hold/close behavior and do not
establish SHPH two-host packet forwarding or throughput evidence. The complete
scope is in `docs/NATIVE_TUN_STATUS_2026-08-04.md`.

The earlier 20-sample lifecycle run reported `min=58,672,713 ns`,
`p50=199,054,823 ns`, `p95=458,718,205 ns`, and `max=468,719,396 ns`; all
samples passed. The later rerun and current workspace totals are recorded in
`docs/NATIVE_TUN_STATUS_2026-08-04.md` and
`docs/evidence/GATE_EVIDENCE.md`.

The pre-audit five-sample WSL2 lifecycle rerun also passed:
`min=89,096,056 ns`, `p50=208,642,428 ns`,
`p95=309,358,567 ns`, and `max=309,358,567 ns`.

### Test Evidence Notes

- Keep command output logs in your local shell history for exact failure/debug triage.
- Any failure should be recorded with:
  - failing test name
  - command used
  - environment (`linux` or `windows`)
  - remediation action
