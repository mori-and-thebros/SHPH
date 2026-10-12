# Phantom Shroud Audit and Roadmap Evidence — 2026-09-27

Status: local engineering evidence from a dirty development tree. This record
does not establish a release, independent audit, external-host result, or
roadmap package as `VALIDATED`.

This is the 2026-09-27 run only. The separate 2026-09-28 active-probe and
synthetic-evaluation evidence is recorded in
[`PHANTOM_SHROUD_AUDIT_2026-09-28.md`](PHANTOM_SHROUD_AUDIT_2026-09-28.md).

## Security changes

- Capability replay entries now use an expiry min-heap; a live duplicate is
  rejected before pruning, and a full cache continues to fail closed without
  evicting live nonces. Regression tests exercise out-of-order expiry and
  repeated replay at capacity.
- The edge applies a global fixed one-second capability-verification limit
  (default 256 per second, configurable from 1 to 100,000). It verifies
  signatures before awaiting a Tokio replay-cache mutex and holds that mutex
  only for the nonce commit. Cancellation can abandon a queued commit; live
  duplicate nonces and full-cache insertions still fail closed. The limit is
  not per-client fairness.
- Release-package verification rejects non-POSIX traversal, symlink/reparse
  components and entries, non-regular package entries, and non-portable
  Windows path components. Tests cover traversal, links, and a normal nested
  package.
- Windows interface-alias conversion rejects empty, NUL-containing, and
  control-character names before calling the Windows API. The Windows-only
  regression test was not executed: the attempted Windows-target check could
  not run `x86_64-w64-mingw32-gcc` because execution was denied in this
  environment.

## Validation

- Workspace formatting, Clippy with warnings denied, all-target tests, and the
  locked build pass after the replay-lock refinement. The standalone edge
  default and HTTP/3-feature suites each pass 45 tests, and standalone edge
  Clippy passes. Benchmark tests pass (7); the fuzz workspace locked check
  passes; the Python suite passes 32 tests.
- Cached RustSec vulnerability scans with `--no-fetch --no-yanked --deny
  warnings` report no advisories for the root, benchmark, fuzz, and edge
  lockfiles. The online command's crates.io index requests timed out while
  checking yanked status; this remains unverified.
- The release `shroud` microbenchmark ran 25 iterations and 10,000 frames on
  WSL2, AMD Ryzen 7 7700X, with Rust 1.96.0. For the balanced 991-byte decode
  case, the borrowed view measured 20 ns p50 and 15 allocation calls (8,160
  bytes across samples), versus 40 ns p50 and 40 calls (32,929 bytes) for the
  owned-copy path. These are local microbenchmark observations, not network
  throughput or P5 complete-session evidence. Raw output is kept locally at
  `target/d4-local/shroud-audit-20260927.csv` and is excluded from the mirror.

## Probe and simulation

- The post-refactor active-probe campaign targeted a temporary self-signed
  TLS edge on loopback, pinned as `edge.local`; it did not contact an external
  host. Nine HTTP/2 cases returned the expected 404/405/401 responses,
  including invalid signature and expired capability. The valid first-use
  probe returned 200; reuse returned 401. Backend instrumentation counted
  exactly one connection, from that acknowledged first use. A partial TLS
  handshake closed with zero response bytes, and both requested TCP churn
  connections succeeded. This single local sample is not a response
  distribution or indistinguishability result.
- A focused edge concurrency test confirms invalid signatures are rejected
  without waiting on replay state, distinct valid capabilities survive cache
  contention, and concurrent uses of one capability produce exactly one
  accepted decision. Separate regressions cover cancellation and the full
  not-before/expiry skew window.
- The offline blocking simulation was rerun with seed 7 using 36 synthetic
  groups, 3,456 packet rows, and 288 sessions. The report was `partial` with
  sample limitations; its held-out flow decisions changed no packets or
  routes. Synthetic output is smoke-test data, not capture evidence or a
  detectability claim.

## Roadmap boundary

D2 now has local active-probe, authorization, replay, and backend-observation
evidence, but remains `IMPLEMENTING` until paired baseline/candidate response
distributions and operator-profile review are recorded. P5 still requires
authorized complete-session captures and observation points. D1, D3, D4, O1a,
and O1b retain their host, representative-data, integration, cancellation, or
independent-protocol-review gates documented in
[`PHANTOM_SHROUD_SCOPE.md`](../PHANTOM_SHROUD_SCOPE.md). No package is marked
`VALIDATED` by this record.
