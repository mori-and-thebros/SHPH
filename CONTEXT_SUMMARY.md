# SHPH Context Summary (for next AI handoff)

## Date
2026-06-24

## Scope completed so far
- **Phase A.1 (Delivery-Critical Networking): COMPLETE**
- **Phase A.2 (Control-Plane Reliability): COMPLETE**
- **Phase A.3 (Security Baseline for Deployment): COMPLETE**
- **Phase A.4 (Ops, Packaging, and Trust): COMPLETE**
- **Phase A.5 (Documentation for Funders): COMPLETE**
- **Phase A is COMPLETE (5/5).**
- Main branch used: `/home/mori/SHPH_working_copy`
- Funded mirror: `D:\FUNDING NEEDED\snap-shroud-rs` (synced via `/mnt/d`).

## Phase A.3 completion (this session) — Security Baseline

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

## Prior phases (A.1, A.2) — see git/file history in this doc's prior versions.
- A.1: graceful SIGINT/SIGTERM shutdown, poll-driven stdin, session lifecycle
  trail on all `up` paths, metrics wiring.
- A.2: atomic control-plane preflight, error-preserving rollback, robust cleanup.

## Validation done (all passing)
- `cargo fmt --all` (clean)
- `cargo clippy --workspace --all-targets -- -D warnings` (clean)
- `cargo test --workspace` (52 passed, 0 failed)

## Known caveats / follow-ups
- Windows graceful shutdown via `SetConsoleCtrlHandler` (needs `windows-sys`,
  verifiable on Windows only) — tracked from A.2.
- `ring` cross-compile to Windows needs `x86_64-w64-mingw32-gcc` (not present
  here); Windows target not `cargo check`-able in this sandbox.
- This sandbox sometimes denies loopback; transport tests have skip-guards.

## Phase B.2 completion (2026-06-29) — Stability Before Feature Expansion
- `docs/API_STABILITY.md`: API tiers + validation-window freeze rules.
- `docs/SECURITY_REPORTING.md`: bug-bounty-safe report template + triage SLA.
- `docs/SUPPLY_CHAIN_SCAN.md` + `docs/evidence/CARGO_AUDIT.txt`: cargo-audit
  scan of 178 deps -> 0 vulnerabilities; direct `anyhow` finding fixed
  (1.0.102->1.0.103), 2 transitive warnings (`paste`,`lru`) accepted (optional TUI).
- `ratatui` 0.27->0.28.1; `frame.size()`->`frame.area()`; `cargo audit` in CI.

## Next
- **Phase B is COMPLETE (B.1 + B.2).** Next roadmap item is the Optional /
  Research Track (transport fingerprint shaping, QUIC hardening) — explicitly
  NOT part of mandatory funding readiness.

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
- README doc index, `docs/FUNDING_SPRINT_BOARD.md`, `agents.md` updated.

## Phase A.4 completion (this session) — Ops, Packaging, and Trust
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
- Mirror sync: source/doc files only, never `target/`.
