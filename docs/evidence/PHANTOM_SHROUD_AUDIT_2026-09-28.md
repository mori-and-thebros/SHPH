# Phantom Shroud Audit and Roadmap Evidence — 2026-09-28

Status: local engineering evidence from a dirty development tree. It does not
establish a release, independent audit, external-host result, or any roadmap
package as `VALIDATED`. The benchmark artifact records base commit
`0ff80522c37f39afa0f8b03b2df24ef1e1adc55f` with uncommitted changes.

## Validation

- The workspace passed formatting, metadata, check, Clippy with warnings
  denied, tests, and the locked release build. Benchmark and fuzz workspace
  checks passed. The standalone edge default and HTTP/3 feature suites passed
  54 and 55 tests, respectively; the Python suite passed 75 tests.
- A bounded AddressSanitizer `cargo-fuzz` campaign for
  `phantom_one_envelope` ran 604,624 executions in 61 seconds without a crash.
  libFuzzer ended at `cov=812`, `ft=1114`, and 110 corpus entries. Its build,
  corpus, and artifacts are local-only under
  `target/fuzz-phantom-one-20260928/`; this finite run is not a proof of safety.
- A Windows/MSVC release-collector rerun on 2026-09-28 passed its source,
  workspace, benchmark, fuzz-smoke, packaging, and standalone edge gates. The
  collector report is local-only under
  `benchmark-runs/release-readiness/release-readiness-20260928T191318Z.md`.
  It remains ineligible because the worktree is dirty and the native TUN
  two-host campaign is `SKIP`. The generated package records
  `source_dirty: true`; `verify_release.py` correctly rejects it as a release
  package.
- The Windows security-evidence collector passed its redacted secret scan,
  focused core/transport/TUN tests, cached advisory scan, and six fuzz smokes.
  Its only non-pass was the expected dirty-tree `WARN`; the local report is at
  `benchmark-runs/security-evidence/security-evidence-20260928T192011Z.md`.
- The root `Cargo.lock` was updated from `rustls 0.23.43` to `0.23.45` after
  the audit found RUSTSEC-2026-0285. Cached advisory scans for all four
  lockfiles passed against the local database; online yanked-status checks
  timed out and remain `SKIP`. See `CARGO_AUDIT.txt` for exact scope.
- A low-severity Data-Mule starvation issue was fixed by scanning only the
  local recipient spool while retaining scan caps. All 14 focused Data-Mule
  tests passed. Flat-root inbox files are not read; in-tree writers use
  recipient subdirectories.
- Windows MSVC all-target and release builds passed on 2026-09-28 with Rust
  1.96.0. This closes compile/link validation only; no native Windows TUN,
  firewall, crash-cleanup, or packet-forwarding campaign is claimed here.

## Code-review scope

Focused manual spot checks covered handshake transcript signatures and peer
pinning, post-quantum downgrade rejection, atomic owner-restricted keystore
writes, bounded SOCKS setup, and Phantom One length validation. These checks did
not establish a full-source security audit. The independent Rust security
review did not complete, so this report makes no claim that the entire codebase
is free of vulnerabilities; separate protocol and native-Windows reviews remain
open.

## Performance

Criterion ran on WSL2 Linux x86_64 with Rust 1.96.0. It measured Phantom One
selection and encoding microbenchmarks only; this is not complete-session,
network, or P5 performance evidence. The working tree was dirty at capture.

| Criterion case | Estimate | Criterion interval |
| --- | ---: | ---: |
| First-fit target selection, 1-byte payload, 256-byte path | 4.4728 ns | 4.4188–4.5486 ns |
| Weighted 25/75 target selection, same limits | 22.631 ns | 22.584–22.681 ns |
| Weighted encode, same limits | 95.493 ns | 94.946–96.155 ns |

Raw local artifacts are in the ignored directory
`benchmark-runs/criterion-2026-09-28-p1/`. The recorded metadata includes the
dirty-tree hashes, host, and toolchain.

A focused rerun on the current dirty tree used `cargo +1.96.0 bench` with an
isolated ignored target directory. Criterion's 100-sample estimates were:

| Criterion case | Estimate | Criterion interval |
| --- | ---: | ---: |
| First-fit target selection, 1-byte payload, 256-byte path | 6.1902 ns | 6.0772–6.3142 ns |
| Weighted 25/75 target selection, same limits | 27.839 ns | 27.216–28.589 ns |
| Weighted encode, same limits | 118.58 ns | 117.03–120.20 ns |
| Authenticated envelope encode/decode | 214.65 ns | 211.80–217.77 ns |
| Reusable-buffer encode/decode | 91.473 ns | 90.349–92.567 ns |
| Reject malformed magic | 20.078 ns | 19.665–20.551 ns |

This focused microbenchmark is not a full-session or P5 measurement. Its
machine-local build and reports are under
`target/criterion-rerun-20260928/` and are not publication artifacts.

## Active probing

The 2026-09-28 probe targeted a temporary TLS + HTTP/2 edge on loopback
(`127.0.0.1`), not an external host. Nine unauthenticated probe classes were
repeated three times each: missing, malformed, duplicate, expired, and
invalid-signature capabilities; root and unmatched paths; query-on-relay; and
an unsupported method. They returned the expected 401, 404, or 405 statuses.
An authorized first use returned 200, replay returned 401, and backend
instrumentation counted one accepted request. A partial TLS handshake closed
with zero response bytes; all 8 requested churn connections succeeded.

These finite loopback observations are not paired baseline/candidate response
distributions and do not establish indistinguishability. The machine-specific
report and logs remain under the ignored `target/d4-local/` directory.

## Offline blocking simulation

The seed-7 synthetic evaluation used 180 groups, 17,280 packet rows, and 1,440
sessions, split by group into train, calibration, and held-out test sets. The
pipeline emitted separate synthetic baseline and variant results, including
a variant held-out ROC-AUC of about 0.421; this is a synthetic smoke test, not
a result about real traffic or censorship. Its simulated blocking decisions
changed no packets or routes. No authorized representative PCAP was supplied.

Generated CSV and JSON files are local-only artifacts under
`target/d4-local/roadmap-20260928/` and
`target/d4-local/blocking-180-20260928.json`.

## Roadmap boundary

The package-by-package status and remaining acceptance gates are tracked in
[`PHANTOM_SHROUD_SCOPE.md`](../PHANTOM_SHROUD_SCOPE.md). Microbenchmarks do not
pass P5; loopback probes do not pass the paired-distribution portion of D2;
synthetic traces do not pass D4. External authorized-host campaigns, native
Windows/WFP validation, representative capture data, and independent O1b
protocol review remain separate gates.

The one-shot CLI now exposes authenticated envelope-policy negotiation for TCP
and standards QUIC. Loopback process tests cover baseline and negotiated
send/receive with receipt acknowledgement; persistent TUN sessions remain
unsupported and fail closed. Native-TUN morphology remains blocked until its
distinct framing is covered by authenticated negotiation. The bounded
`scripts/benchmark_one_shot_loopback.py` runner records real local CLI session
wall time and payload verification only. It does not collect packet captures,
wire overhead, resource use, or representative workloads and does not satisfy
P5 acceptance.

Follow-up loopback session observations on 2026-09-28 used ten baseline and ten
negotiated one-shot sessions per transport with 256-byte payloads. The TCP
process-wall-time medians and maxima were 180.294/182.374 ms baseline and
181.253/183.661 ms negotiated. Standards-QUIC medians and maxima were
182.385/532.697 ms baseline and 248.944/550.823 ms negotiated. These include
process startup and orchestration; the QUIC sample spread includes a large
local outlier. This dirty-tree loopback sample is not carrier-only performance
evidence. Machine-local manifests are under
`target/loopback-session-20260928/`; they are not publication artifacts.
