# SHPH Testing Guide

This project uses workspace-wide validation and crate-level tests.

## Fast Local Commands

```bash
cargo fmt --all
cargo check --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

## Focused Test Runs

### CLI integration tests

```bash
cargo test -p shph-cli --test cli_basic
cargo test -p shph-cli --test cli_tcp_handshake
cargo test -p shph-cli --test cli_tcp_data_plane
cargo test -p shph-cli --test cli_up_session_mode
cargo test -p shph-cli --test cli_control_plane
```

### Core handshake tests

```bash
cargo test -p shph-core --test handshake_flow
```

## Platform-targeted test runs executed for this sync

- Linux workspace root: `/home/mori/SHPH_working_copy`
- Windows funding mirror: `/mnt/d/FUNDING NEEDED/snap-shroud-rs`

Commands executed:
- `cargo fmt --all`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo test --workspace`

## Last Recorded Result (2026-06-24)

- Status: **PASS**
- CLI tests:
  - `cli_basic`: 1 passed
  - `cli_tcp_handshake`: 1 passed
  - `cli_tcp_data_plane`: 1 passed
  - `cli_up_session_mode`: 2 passed
  - `cli_control_plane`: 3 passed
- Core tests:
  - `shph-core` unit tests: 3 passed
  - `shph_core` `handshake_flow`: 2 passed
- Transport crate tests:
  - `shph-transport` unit tests: 1 passed
- Other crates: no unit failures
- Validation command set: `cargo fmt --all`, `cargo clippy --workspace --all-targets -- -D warnings`, `cargo test --workspace`
- Observability note: when host loopback sockets are denied by policy (`Operation not permitted`), transport integration tests return early via capability guard to avoid false negatives in restricted test sandboxes.
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

- Run `cargo fmt --all`, `cargo check --workspace`,
  `cargo clippy --workspace --all-targets -- -D warnings`,
  `cargo test --workspace` on `D:\FUNDING NEEDED\snap-shroud-rs`.
- Note: SIGINT/SIGTERM signal handling is unix-only. Windows graceful shutdown
  via `SetConsoleCtrlHandler` is a tracked A.2 follow-up (needs `windows-sys`,
  verifiable only on the Windows toolchain).
- Record Windows command logs here once run.

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
- Wrong-key AEAD authentication fails closed (`wrong_key_authentication_fails`).

Bounded handshake: `tcp_accept_and_handshake` tolerates up to
`TCP_HANDSHAKE_ATTEMPTS` (5) malformed/closing peers, then fails closed.

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
  - Interface name constraints are validated before ioctl.
  - Permission and ioctl failures return explicit actionable errors.

### Test Evidence Notes

- Keep command output logs in your local shell history for exact failure/debug triage.
- Any failure should be recorded with:
  - failing test name
  - command used
  - environment (`linux` or `windows mirror`)
  - remediation action
