# SHPH Funding Sprint Board (Current Phase Only)

**Policy:** only edit this board when a phase is fully completed and acceptance criteria are met.

## Current Active Phase

### Phase A.1 — Delivery-Critical Networking (Complete)

**Status:** Complete (2026-06-24)

#### Tasks (all must pass before phase completion)

1. Finalize stable `up` data-plane behavior on Linux + Windows.
2. Verify TUN lifecycle reliability for start/stop/restart and clean teardown.
3. Add session startup/shutdown and reconnect determinism evidence.
4. Add minimal performance/error observability for encrypted tunnel flow.

#### Completion Evidence (2026-06-24)

1. `up` data-plane (Linux): verified live on loopback TCP. One-shot
   `startup_payload` exchange (`up` listen/connect) transfers an encrypted
   payload end-to-end; loop mode streams stdin lines as encrypted frames.
   Windows workspace and adapter/session evidence is recorded in the dated
   native Windows validation report; packet forwarding and two-host live runs
   remain operator validation gates.
2. TUN lifecycle / clean teardown: added graceful SIGINT/SIGTERM handling
   (`shph-cli/src/shutdown.rs`) plus poll-driven stdin reads so the connect loop
   observes a shutdown request within ~200ms. Live test: SIGINT to a running
   connect-loop session emitted `Transport loop: closed`, `Session end`, and
   `Final metrics`, then exited code 0. The peer closed cleanly on
   `ConnectionClosed`. Native TUN threads honor the same process-wide flag.
3. Session startup/shutdown + reconnect determinism: every `up` path (one-shot
   send/recv and listen/connect loops) now emits `Session id` / `Session start`
   / `Initial metrics` / `Session end` / `Final metrics`. Reconnect retries with
   exponential backoff and stops on non-retryable errors
   (`reconnect_retries_then_succeeds`, `reconnect_stops_on_non_retryable_error`).
4. Observability: `MetricsCollector` (bytes/packets/errors sent+recv) is wired
   into both one-shot and loop paths and printed in every session trail. Live
   one-shot run showed `bytes_sent: 19, packets_sent: 1` on the connector and
   `bytes_recv: 19, packets_recv: 1` on the listener.

Validation commands executed and passing in this environment:

- `cargo fmt --all` (clean)
- `cargo clippy --workspace --all-targets -- -D warnings` (clean)
- `cargo test --workspace` (all green; loopback integration tests ran, not skipped)

#### Evidence Required

- Linux + Windows validation command logs in `docs/TESTING.md`.
- Session startup/shutdown log trail from `up` (`Session id`, `Session start`, `Session end`, `Final metrics`).
- No regression in existing `cargo fmt`, `clippy`, `test` gates.

#### Definition of Done

Phase A.1 is complete only when **all four tasks and all evidence items** are fully satisfied and test logs are mirrored across supported checkouts.

> All four tasks and evidence items are satisfied in the repository checkout.
> Run the supported synchronization and verification commands below after each
> change.

#### Sync Notes

- Set `SHPH_SYNC_LINUX_DIR` and `SHPH_SYNC_WINDOWS_DIR` before using the
  optional synchronization helper.
- Run `./scripts/sync_mirror.sh --to-windows` followed by
  `./scripts/sync_mirror.sh --verify`.

## Later Phases

### Phase A.2 — Control-Plane Reliability (Complete)

**Status:** Complete, with persistent lifecycle commands and multi-DNS
hardening (2026-07-15)

#### Tasks

1. Atomic control-plane apply: validate all routes + DNS before any host mutation.
2. Preserve real root-cause errors during rollback instead of generic strings.
3. Make rollback robust to partial state (collect all errors, roll back as much as possible).
4. Windows graceful-shutdown parity.

#### Completion Evidence (2026-06-24)

1. Preflight validation (`build_control_plane_plan`): every route CIDR and DNS
   IP is validated up front. A live `up` with one good + one bad route
   (`10.99.0.0/16`, `10.88.0.0/40`) is rejected with
   `CIDR prefix out of range` and applies nothing (atomic).
2. `restore_dns` now returns the real command error with the family/interface
   context (`dns {family} restore failed for {interface}: {err}`) instead of a
   generic `Internal` message.
3. `ControlPlaneGuard::cleanup` rolls back DNS then routes, collecting all
   errors rather than aborting on the first, maximizing partial rollback.
4. Windows graceful-shutdown via `SetConsoleCtrlHandler` is wired through
   `windows-sys`; native Windows parity remains part of the dedicated
   validation campaigns. Unix SIGINT/SIGTERM parity from A.1 remains in place.
5. Persistent `apply`, `reconcile`, `undo`, and `down` lifecycle commands now
   record exact live-applied state beside the config and are covered by
   `cli_control_plane`.
6. Multi-server DNS application preserves all configured servers: Linux emits
   one `resolvectl dns` command, while Windows emits primary and secondary
   `netsh` commands per address family. Partial application retains rollback
   state before command execution.

Validation commands executed and passing in this environment:
- `cargo fmt --all` (clean)
- `cargo clippy --workspace --all-targets -- -D warnings` (clean)
- `cargo test --workspace` (exact totals recorded in `docs/evidence/GATE_EVIDENCE.md`)

New/changed unit tests: `control_plane_plan_preflight_validates_all_before_apply`,
`control_plane_plan_normalizes_dns_and_routes`, `control_plane_plan_requires_interface_name`,
`control_plane_plan_skips_dns_when_no_servers`,
`apply_control_plane_records_dry_run_flag`, `control_plane_plan_default_is_empty`.

See `docs/CONTROL_PLANE.md` for updated behavior.

### Phase A.3 — Security Baseline for Deployment

**Status:** Complete (2026-06-24)

#### Tasks

1. Add anti-replay in PSK/token style flows used for auth and bootstrap.
2. Add transport rate and connection limits on unauthenticated entry paths.
3. Harden read/write/handshake loops for EOF, timeout, and partial-shutdown behavior.
4. Add strict input validation at all parser and command boundaries.

#### Completion Evidence (2026-06-24)

1. Anti-replay: `ReceiveCipher` now tracks the highest accepted AEAD counter
   nonce and rejects any replayed or stale/out-of-order nonce (fail-closed)
   before AEAD decryption. `crypto::tests::replayed_frame_is_rejected_fail_closed`
   and `out_of_order_nonce_is_rejected` prove it.
2. Connection/handshake limits: `tcp_accept_and_handshake` now runs a
   deadline-bounded handshake loop that drops malformed/early-closing/wrong-key
   peers and keeps listening for a legitimate one until the operator timeout.
   Genuine listener failures propagate immediately.
3. Read/write loop hardening: `map_io_error` already maps EOF/broken-pipe/
   abort/reset to `ConnectionClosed` and timeouts to `Timeout`; CLI loops
   (A.1) break cleanly on both. Verified fail-closed; no avoidable unwrap on
   unauthenticated/protocol paths.
4. Strict input validation: removed the panicking `.unwrap()` in
   `Endpoint -> SocketAddr`; added `Endpoint::to_socket_addr_result` and a
   non-panicking `From` that degrades safely. Frame parsing already bounds
   cell size, header, payload length, and frame type (new framing tests).

Security regression tests added (all passing):
- `replayed_frame_is_rejected_fail_closed`, `out_of_order_nonce_is_rejected`,
  `truncated_ciphertext_is_rejected_fail_closed`,
  `wrong_key_authentication_fails`, `nonce_counter_*`
  (crypto), plus framing tests (oversize payload/header/length/type,
  invalid cell size) and endpoint validation tests (net).

Validation commands executed and passing in this environment:
- `cargo fmt --all` (clean)
- `cargo clippy --workspace --all-targets -- -D warnings` (clean)
- `cargo test --workspace` (52 passed, 0 failed)

#### Exit Criteria Check

- No avoidable unwrap on unauthenticated/invalid protocol paths: confirmed
  (only remaining `.unwrap`/`.expect` are inside `#[cfg(test)]` blocks).
- Security regression tests added for replay, EOF, and malformed frames: yes.
- Failure semantics are fail-closed and explicitly tested: yes.

### Phase A.4 — Ops, Packaging, and Trust

**Status:** Complete (2026-06-25)

#### Tasks

1. Add `SECURITY.md`, threat model, and non-claims matrix.
2. Add `CONTRIBUTING.md`, release checklist, and project governance policy.
3. Add GitHub-style CI template for Linux + Windows lint/test/build matrix.
4. Add dependency and artifact reproducibility notes.

#### Completion Evidence (2026-06-25)

1. `SECURITY.md`: vulnerability reporting/disclosure process (private advisory,
   5-day ack, 90-day window), honest current posture, explicit **non-claims
   matrix**, threat-model table, and cryptographic dependency listing.
2. `CONTRIBUTING.md`: clone-to-tested build/test instructions, project layout,
   code style (fmt/clippy/fail-closed), phase-gating discipline, PR flow,
   release checklist, and governance.
3. `.github/workflows/ci.yml`: Linux + Windows matrix running `fmt`,
   `clippy --all-targets -D warnings`, `build`, and `test`; plus a Linux
   native-TUN job that reports host capability skips explicitly.
4. `docs/REPRODUCIBILITY.md`: committed `Cargo.lock` discipline, `--locked`
   builds, `cargo tree`/`cargo audit` supply-chain steps, release artifact
   verification, and known caveats (`ring`, Windows toolchain).

Also added: `LICENSE-MIT` and `LICENSE-APACHE` (matching `Cargo.toml`'s
`license = "MIT OR Apache-2.0"` declaration), and README links to the new docs.

Checkout synchronization (replaces ad-hoc rsync):
- `scripts/sync_mirror.sh`: mirrors two configured checkouts via rsync,
  auto-verifies checksum parity after every real sync, and supports
  `--to-windows`, `--to-linux`, `--verify`, and `--dry-run`.
- `docs/SYNC.md`: documents the two-checkout layout, exclusions, and
  synchronization direction.

#### Exit Criteria Check

- New contributor can clone/build/test from docs only: yes
  (`CONTRIBUTING.md` + `docs/REPRODUCIBILITY.md` + `docs/TESTING.md`).
- Public process for disclosure and maintenance is in place: yes
  (`SECURITY.md` + `CONTRIBUTING.md` governance).

Validation commands executed and passing in the recorded run:
- `cargo fmt --all` (clean)
- `cargo clippy --workspace --all-targets -- -D warnings` (clean)
- `cargo test --workspace` (52 passed, 0 failed) — A.4 is docs/CI-only; no code
  changed, so the test count is unchanged from A.3.

### Phase A.5 — Documentation for Funders

**Status:** Complete (2026-06-29)

#### Tasks

1. Publish "what SHPH is / is not" page.
2. Publish risk matrix (current limits, explicit exclusions).
3. Publish measurable milestone scorecard and roadmap burn-down.
4. Publish support model and maintenance plan.

#### Completion Evidence (2026-06-29)

1. `docs/FUNDERS.md`: funder/reviewer entry point — what SHPH is, what it is NOT
   (binding non-claims), a verifiable capability snapshot, and pointers to
   reproduce every claim.
2. `docs/RISK_MATRIX.md`: severity-rated current limits and explicit exclusions,
   threat-coverage table, and the "every claim must trace to a green test" policy.
3. `docs/MILESTONE_SCORECARD.md`: phase scorecard (A.1-A.5 complete = Phase A
   5/5, 100%), reproducible quality signals (52 passed/0 failed, 0 warnings,
   locked build), and the binding definition of "complete".
4. `docs/SUPPORT_AND_MAINTENANCE.md`: support tiers (community/security/
   maintainer), the `SECURITY.md` disclosure SLA as the firmest commitment,
   maintenance cadence, governance, and sustainability signals.

README's doc index updated to link all four pages.

#### Exit Criteria Check

- Public docs support an OTF/enterprise pre-review: yes (FUNDERS hub + risk
  matrix + scorecard + support/maintenance + SECURITY + CONTRIBUTING).
- Funders can verify claims against tests and changelog: yes (every capability
  row carries a reproduce command; scorecard lists test totals + gates).

Historical validation commands executed and passing at that checkpoint:
- `cargo fmt --all` (clean)
- `cargo clippy --workspace --all-targets -- -D warnings` (clean)
- `cargo test --workspace` (52 passed, 0 failed) — A.5 is docs-only; no code
  changed.

---

## Phase A — COMPLETE (5/5)

All Phase A foundations (A.1-A.5) are complete and mirrored. Phase A is the
production-foundation track; the next track is Phase B (Funding Validation &
Audit Preparation), which remains locked pending sign-off.

### Phase B.1 — External Review Readiness (Complete)

**Status:** Complete (2026-06-29)

#### Tasks

1. Add reproducible demo scripts and failure-mode walk-throughs.
2. Add test artifacts / CI logs for each mandatory acceptance gate.
3. Add release tagging for "funding checkpoint" artifacts.
4. Add legal/compliance checklist for open-source artifact handling.

#### Completion Evidence (2026-06-29)

1. **Reproducible demos:** `scripts/demo.sh` runs three loopback demos —
   `happy` (encrypted one-shot tunnel), `bad-cidr` (invalid CIDR rejected
   fail-closed by the atomic preflight), `unreachable` (peer reconnect/backoff).
   All produce their expected output; no privileges or real TUN needed.
2. **Gate evidence:** `scripts/capture_evidence.sh` runs every mandatory gate
   (fmt / clippy / test / `--locked` build) and writes
   `docs/evidence/GATE_EVIDENCE.md` with summed totals. Current capture:
   fmt clean, clippy 0 warnings, test **0 failed**, `--locked` build OK.
3. **Release tagging:** `docs/RELEASE_PROCEDURE.md` defines checkpoint
   qualification, the `checkpoint-phaseX-Y.Y.Z` tag scheme, the cut procedure,
   a reviewer reproduction path, and a funding-checkpoint manifest. Caveat
   noted: the tree is not yet a git repository, so the manifest stands in for a
   git tag until the tree is under git.
4. **Legal/compliance:** `docs/LEGAL_COMPLIANCE.md` covers dual-license
   compliance, contributor attribution, supply-chain dependency licensing,
   cryptography/export considerations, data/privacy handling, and artifact
   integrity, with explicitly tracked non-blocking follow-ups.

Also added: `CHANGELOG.md` (phase-anchored changelog).

#### Exit Criteria Check

- Reproducible demo scripts + failure-mode walk-throughs: yes (`scripts/demo.sh`).
- Test artifacts / CI logs for each acceptance gate: yes
  (`docs/evidence/GATE_EVIDENCE.md`, regenerable on demand).
- Release tagging for funding-checkpoint artifacts: yes (procedure + manifest in
  `docs/RELEASE_PROCEDURE.md`; git tag pending git init).
- Legal/compliance checklist for OSS artifact handling: yes
  (`docs/LEGAL_COMPLIANCE.md`).

Validation commands executed and passing in this environment:
- `cargo fmt --all -- --check` (clean)
- `cargo clippy --workspace --all-targets -- -D warnings` (clean)
- `cargo test --workspace` (0 failed) — B.1 is scripts/docs-only; no Rust code
  changed, so behavior is unchanged from A.5.

---

## Phase B.1 — COMPLETE

All four B.1 tasks and evidence items are satisfied in the repository checkout.

### Phase B.2 — Stability Before Feature Expansion (Complete)

**Status:** Complete (2026-06-29)

#### Tasks

1. Freeze API changes during validation window.
2. Add bug bounty-safe report template and triage SLA.
3. Resolve high-impact/low-effort CVE-risk issues identified by scanners.

#### Completion Evidence (2026-06-29)

1. **API freeze:** `docs/API_STABILITY.md` defines the three public-API tiers
   (CLI, config schema, library crates), SemVer `0.x` posture, and the rules
   that hold during a validation window — no breaking CLI/config changes,
   library breaks only with CHANGELOG rationale, security fixes override.
2. **Bug-bounty template + triage SLA:** `docs/SECURITY_REPORTING.md` ships a
   structured redactable report template (with safe-sharing rule) and a
   severity-based triage rubric (Critical/High/Medium/Low) with ack/fix SLAs,
   complementing `SECURITY.md`'s 5-day/90-day disclosure window.
3. **Scanner-driven fixes:** `cargo-audit` run against 178 dependencies.
   - Fixed the one direct finding: `anyhow 1.0.102 -> 1.0.103`
     (RUSTSEC-2026-0190 unsound `downcast_mut`, never called by SHPH).
   - Historical checkpoint: accepted 2 transitive warnings (`paste`, `lru`)
     isolated to the optional TUI via `ratatui`; the current lockfile and
     policy are documented in `docs/SUPPLY_CHAIN_SCAN.md`.
   - Bumped `ratatui 0.27 -> 0.28.1`; fixed the deprecated `frame.size()` ->
     `frame.area()` it introduced.
   - `cargo audit --deny warnings` is wired into CI as a blocking gate;
     the non-blocking configuration was historical.
   - Historical captured output in `docs/evidence/CARGO_AUDIT.txt`.

#### Exit Criteria Check

- API changes frozen during validation window (policy documented): yes.
- Bug bounty-safe report template + triage SLA: yes.
- High-impact/low-effort scanner issues resolved: yes (direct dep fixed;
  transitive findings triaged + documented; result 0 vulnerabilities).

Validation commands executed and passing in this environment:
- `cargo fmt --all -- --check` (clean)
- `cargo clippy --workspace --all-targets -- -D warnings` (clean)
- `cargo test --workspace` (0 failed)
- Historical `cargo audit` snapshot (0 vulnerabilities; 2 accepted transitive warnings)
- `cargo build --workspace --locked` (OK)

---

## Phase B.2 — COMPLETE

All three B.2 tasks and evidence items are satisfied. With B.1 and B.2 done,
**Phase B (Funding Validation & Audit Preparation) is COMPLETE.**
