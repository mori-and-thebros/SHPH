# SHPH Project Context Summary

## Date
2026-08-09

## Current milestone state
- **Phase A.1 (Delivery-Critical Networking): COMPLETE**
- **Phase A.2 (Control-Plane Reliability): COMPLETE**
- **Phase A.3 (Security Baseline for Deployment): COMPLETE**
- **Phase A.4 (Ops, Packaging, and Trust): COMPLETE**
- **Phase A.5 (Documentation for Funders): COMPLETE**
- **Phase A is COMPLETE (5/5).**
- **Phase B is COMPLETE (2/2).**
- **Phase C is COMPLETE (6/6) for the controlled Shroud lab scope.**
- **Phase D local implementation and validation are complete, but the delivery
  gate remains open** for native Linux two-host TUN evidence and privileged
  Windows Wintun packet-path evidence.
- **Phase D-A audit remediation is COMPLETE** for the documented non-native-TUN
  audit scope.
- **Phase E is not complete:** the paired benchmark/evidence bundle exists,
  but final release claims, snapshot, and tag remain gated on host-level TUN
  evidence.
- **Phase F is host-gated:** the Windows Wintun backend is wired and the
  post-loader elevated validator reached adapter/session teardown; packet I/O,
  two-host evidence, and a clean rerun after the route-rollback fix remain.
- Workspace version: `0.6.0-dev.0`.
- Paired benchmark report: `docs/BENCHMARK_RESULTS_2026-08-05.md`.
- Latest Windows validation evidence:
  `docs/evidence/WINDOWS_NATIVE_VALIDATION_2026-08-09_POST_LOADER.md`.

## Phase A.3 completion — Security Baseline

1. Anti-replay (crypto)
- `ReceiveCipher` (`shph-core/src/crypto.rs`) now tracks the highest accepted
  AEAD counter nonce (`last_nonce: Option<u64>`) and rejects any nonce <= the
  last accepted one before AEAD decryption (fail-closed).
- Added `nonce_counter()` helper (big-endian counter from nonce bytes 4..12).

2. Connection/handshake limits on unauthenticated entry
- `tcp_accept_and_handshake` (`shph-transport/src/lib.rs`) now runs a bounded
  loop (`TCP_HANDSHAKE_ATTEMPTS = 5`): drops malformed/early-closing/wrong-key
  peers and keeps listening for a legitimate one; fails closed when exhausted.
  Genuine listener failures/timeouts propagate immediately.

3. Read/write/handshake loop hardening
- Verified fail-closed: `map_io_error` maps EOF/broken-pipe/abort/reset ->
  `ConnectionClosed`, timeouts -> `Timeout`; CLI loops (A.1) break cleanly.
- No avoidable `.unwrap()`/`.expect()` on unauthenticated/protocol paths
  (remaining ones are all inside `#[cfg(test)]`).

4. Strict input validation at parser/command boundaries
- Removed panicking `.unwrap()` in `Endpoint -> SocketAddr` (`shph-core/src/net.rs`).
- Added `Endpoint::to_socket_addr_result()` (fallible); `From` now degrades
  safely instead of panicking on untrusted input.
- Frame parsing already bounds cell size, header, payload length, frame type.

5. Security regression tests (all passing)
- crypto: replay rejection, out-of-order rejection, truncated ciphertext,
  wrong-key auth failure, nonce extraction.
- framing: oversize payload, corrupt header, oversize length, unsupported type,
  invalid cell size.
- net: endpoint parse, socket-addr validation, no-panic `From`.

## Prior phases (A.1, A.2)
- A.1: graceful SIGINT/SIGTERM shutdown, poll-driven stdin, session lifecycle
  trail on all `up` paths, metrics wiring.
- A.2: atomic control-plane preflight, error-preserving rollback, robust cleanup.

## Historical validation done (all passing)
- `cargo fmt --all` (clean)
- `cargo clippy --workspace --all-targets -- -D warnings` (clean)
- `cargo test --workspace` (52 passed, 0 failed)

## Current known caveats / follow-ups
- Windows graceful shutdown via `SetConsoleCtrlHandler` is wired through
  `windows-sys`; native Windows workspace and benchmark execution now pass
  (**180 tests, 0 failures**). The post-loader elevated attempt reached the
  real Wintun adapter/session and left no residue; a clean elevated rerun after
  the route-rollback fix remains pending.
- The paired benchmark data is local authenticated operation evidence:
  in-memory goodput is not TUN/VPN throughput, and the UDP lab shim is not
  standards-compliant QUIC performance evidence.
- The WSL2 native-TUN namespace result is a 20/20 open/hold/close lifecycle
  smoke test; it does not establish packet forwarding, two-host RTT/jitter,
  CPU/RSS saturation, or reconnect performance.
- Native Linux two-host TUN forwarding and privileged Windows Wintun packet
  I/O remain the next release-blocking validation gates.

## Current validation evidence (2026-08-09)
- WSL2/Linux: the `0.6.0-dev.0` release-polish pass completed format, strict
  Clippy, workspace tests (**196 passed**), locked release builds, benchmark
  build, demo, dependency audit, and bounded fuzz smoke runs. This is
  intermediate dirty-tree development evidence, not a tagged release snapshot.
  The earlier native-TUN lifecycle probe (**20/20**) remains separate,
  capability-gated evidence.
- Native Windows: format, workspace check, strict Clippy, workspace tests
  (**180 passed**), release build, Windows-only focused tests, signed-runtime
  inspection, benchmark capture, and the post-loader native-TUN attempt pass
  through adapter/session teardown. The route rollback command was corrected
  afterward; rerun the elevated validator before treating the updated cleanup
  path as final evidence.
- Pinned fuzz smoke: five targets completed bounded runs without crash
  artifacts; this does not replace longer sanitizer-enabled campaigns.
- Dependency audit: `cargo audit --no-fetch` exits cleanly with two accepted
  optional-TUI advisories documented in `docs/evidence/CARGO_AUDIT.txt`.
- Full benchmark tables, commands, environment metadata, and remaining
  host-level work are in `docs/BENCHMARK_RESULTS_2026-08-05.md`; the latest
  Windows gate record is
  `docs/evidence/WINDOWS_NATIVE_VALIDATION_2026-08-09_POST_LOADER.md`.

## Phase B.2 completion (2026-06-29) — Stability Before Feature Expansion
- `docs/API_STABILITY.md`: API tiers + validation-window freeze rules.
- `docs/SECURITY_REPORTING.md`: bug-bounty-safe report template + triage SLA.
- `docs/SUPPLY_CHAIN_SCAN.md` + `docs/evidence/CARGO_AUDIT.txt`: cargo-audit
  scan of 178 deps -> 0 vulnerabilities; direct `anyhow` finding fixed
  (1.0.102->1.0.103), 2 transitive warnings (`paste`,`lru`) accepted (optional TUI).
- `ratatui` 0.27->0.28.1; `frame.size()`->`frame.area()`; `cargo audit` in CI.

## Next
- Run native Linux two-host TUN forwarding and performance measurements on a
  host with the required privileges and traffic tools.
- Run privileged native Windows Wintun adapter, packet-I/O, route/DNS,
  reconnect, Ctrl+C teardown, and two-node validation.
- After those gates, freeze the release claims/version/commit and complete
  Phase E without converting lab-only measurements into production claims.

## Phase B.1 completion (2026-06-29) — External Review Readiness
- `scripts/demo.sh`: reproducible loopback demos (happy / bad-cidr / unreachable).
- `scripts/capture_evidence.sh`: runs every gate, writes
  `docs/evidence/GATE_EVIDENCE.md` with summed totals (fmt clean, clippy 0
  warnings, test 0 failed, `--locked` build OK).
- `docs/RELEASE_PROCEDURE.md`: funding-checkpoint tagging procedure + manifest
  Tree is now a git repository; checkpoint tag `checkpoint-phaseA-1.0.0`
  (commit `e0a5949`) is cut.
- `docs/LEGAL_COMPLIANCE.md`: OSS artifact legal/compliance checklist.
- `CHANGELOG.md`: phase-anchored changelog.
- README documentation index and maintainer notes updated.

## Phase A.4 completion — Ops, Packaging, and Trust
- Added `LICENSE-MIT`, `LICENSE-APACHE` (match `license = "MIT OR Apache-2.0"`).
- `SECURITY.md`: disclosure process, threat model, non-claims matrix, crypto deps.
- `CONTRIBUTING.md`: build/test, style, phase-gating, release checklist, governance.
- `.github/workflows/ci.yml`: Linux + Windows fmt/clippy/build/test matrix +
  optional Linux native-TUN job.
- `docs/REPRODUCIBILITY.md`: lockfile/`--locked` discipline, `cargo audit`,
  release artifact verification, caveats.
- README links updated.

## Key files / anchors
- Anti-replay: `shph-core/src/crypto.rs` (`ReceiveCipher`, `nonce_counter`).
- Bounded accept: `shph-transport/src/lib.rs` (`tcp_accept_and_handshake`,
  `TCP_HANDSHAKE_ATTEMPTS`).
- Input validation: `shph-core/src/net.rs` (`Endpoint::to_socket_addr_result`).
- Graceful shutdown: `shph-cli/src/shutdown.rs`.
- Control plane: `shph-cli/src/main.rs` (`apply_control_plane`,
  `build_control_plane_plan`, `ControlPlaneGuard`).
- Sprint board: `docs/FUNDING_SPRINT_BOARD.md`; control-plane: `docs/CONTROL_PLANE.md`.
- Source/documentation synchronization excludes build and generated artifacts.
- Current benchmark evidence: `docs/BENCHMARK_RESULTS_2026-08-05.md`;
  Windows runner: `scripts/benchmark_windows.ps1`; latest gate record:
  `docs/evidence/WINDOWS_NATIVE_VALIDATION_2026-08-09_POST_LOADER.md`.
- Current native-TUN evidence: `docs/NATIVE_TUN_STATUS_2026-08-04.md` and
  `docs/evidence/WINDOWS_NATIVE_VALIDATION_2026-08-09_POST_LOADER.md`.
