# SHPH Roadmap (OSS + Delivery + Funding Readiness)

## Objective

Make SHPH a **funding-ready, open-source VPN** with:

- Reliable encrypted networking on Linux + Windows
- Measurable security posture (with explicit non-claims)
- Clean operational and contributor experience
- Transparent, testable milestones suitable for grant review

Non-goals in this roadmap section: stealth/fingerprinting, anti-censorship claims, and optional experimental transports.

## Current State (as of 2026-08-17)

### What is already built

- Rust workspace compiles and is locally testable.
- Authenticated handshake (TCP) with transcript-bound keys.
- Encrypted framed transport over TCP.
- `up` session mode with one-shot and continuous transfer.
- Linux native TUN flow behind `SHPH_TUN_NATIVE=1`.
- Reconnect policy with runtime backoff for session mode.
- Config schema and peer/config workflows.
- Control-plane routes/DNS apply, reconcile, undo, and persistent rollback state.
- Opt-in native host leak containment: Linux nftables killswitch planning and
  application, Windows WFP outbound authorization filters, literal peer
  allowlists, stale-policy cleanup, and Linux MSS-clamp support.
- Canonical length-prefixed hybrid handshake transcript framing and
  exception-safe rollback across control-plane, firewall, and session setup.
- CLI and docs baseline in place.
- Roadmap validation, Shamir split/recovery, and ratchet-audit export primitives
  are available behind explicit CLI commands.
- Paired local benchmark evidence is available for WSL2/Linux and native
  Windows, including secure-default/classical-lab handshake, authenticated
  goodput, morphology, allocation, replay, and lab-shim measurements. See
  `docs/BENCHMARK_RESULTS_2026-08-05.md`.
- A fresh Windows-local `0.6.1-dev` full-suite capture for both benchmark
  profiles is recorded in `docs/BENCHMARK_RESULTS_2026-08-14.md`; it remains
  separate from native-TUN and two-host evidence.
- Native Windows workspace validation was refreshed on August 8, 2026:
  locked build/check, strict Clippy, 180 tests, Windows-only Wintun and ACL
  regressions, release build, and both local benchmark profiles pass. See
  `docs/evidence/WINDOWS_NATIVE_VALIDATION_2026-08-08.md`.

### Mandatory-track status

The mandatory funding track is complete for the documented controlled-lab scope:
Linux gates, the mirrored source tree, control-plane lifecycle tests, security
regressions, release/process documents, and evidence artifacts are maintained.
This does not make SHPH a production VPN or establish hostile-network,
anti-censorship, or conformant-QUIC claims.

The next delivery sequence is now explicit:

1. **Shroud lab phase** — make the cell/framing path useful, measurable, and
   honest about its limits.
2. **Hardening and optimization phase** — find and fix defects, reduce
   allocations and tail latency, and repeat the benchmark gates.
3. **Big move / release-readiness gate** — freeze claims, publish evidence,
   and prepare the Linux/Windows operator release.
4. **Windows TUN phase** — integrate and validate an operator-approved Wintun runtime as
   the final platform-delivery step.

These phases are sequential. The later phase must not be marked complete based
on placeholder implementations or local-only scores.

Remaining work is explicitly phase-gated or deployment-specific:

- Native Windows route/DNS execution still requires operator validation on a
  privileged Windows host. The hash-pinned Wintun loader/session/packet backend is
  wired into `TunDevice`, and native Windows unit/build/benchmark gates now
  pass, but live adapter creation, packet I/O, rollback, reconnect, and
  two-node forwarding remain host-gated.
- Native Linux two-host forwarding and live TUN performance remain
  host-gated. The current 20/20 namespace/lifecycle result measures
  open/hold/close behavior only, not packet forwarding or VPN throughput.
- Production QUIC, effective anti-observation shaping, and hardware-backed
  identity providers remain unimplemented.
- A lab-grade password-encrypted keystore path now exists; production key
  management remains unimplemented.
- Firewall containment remains opt-in and host-gated: privileged Linux/WFP
  mutation, process-crash leak tests, Windows packet-policy coverage, and
  two-host forwarding are not yet published as release evidence.

### Phase-gate rule

The latest Windows-local benchmark capture is
`docs/BENCHMARK_RESULTS_2026-08-14.md`. The paired WSL2/native-Windows report
remains `docs/BENCHMARK_RESULTS_2026-08-05.md`; historical baseline results
remain in `docs/BENCHMARK_RESULTS_2026-07-28.md` and the Shroud morphology
report in `docs/SHROUD2_BENCHMARK_RESULTS_2026-08-04.md`. These reports are
useful for regression tracking, but they are not native-TUN, two-host, or
production-VPN evidence. Each phase below must preserve that distinction.

---

## Mandatory Funding Track (must be done for VPN credibility)

## Phase Update Discipline

- Do not update phase status outside section-specific completion gates.
- A new phase may be marked started only after the previous phase is fully completed and validated.
- "Completed" status is set only after all acceptance criteria for that phase are met.

## Phase A — Production Foundations (Weeks 1–3)

### A.1 Delivery-Critical Networking

- Finalize stable transport behavior on Linux + Windows for `up` data-plane.
- Ensure TUN lifecycle is robust across start/stop and process exit/restart.
- Add packet capture-safe observability for basic throughput and error rates.
- Add deterministic session startup/shutdown guarantees.

**Exit criteria**
- Two-node encrypted tunnel test passes on Linux and Windows.
- `up` session can recover cleanly from transient transport disconnects.
- TUN lifecycle and reconnection behavior documented and tested.

### A.2 Control-Plane Reliability (Mandatory)

- Complete route/DNS apply/rollback behavior for Windows and Linux.
- Add idempotent `apply`, `reconcile`, and `undo` command flow.
- Add guardrails for bad config, malformed routes, and privilege failures.
- Add CLI-visible operator status output for all control-plane actions.

**Exit criteria**
- Controlled test matrix passes for dry-run and safe apply mode.
- Rollback works for at least 5 common route/DNS mutation scenarios.
- Operator receives explicit remediation text on permission/config failures.

### A.3 Security Baseline for Deployment (Mandatory)

- Add anti-replay in PSK/token style flows used for auth and bootstrap.
- Add transport rate and connection limits on unauthenticated entry paths.
- Harden read/write/handshake loops for EOF, timeout, and partial-shutdown behavior.
- Add strict input validation at all parser and command boundaries.

**Exit criteria**
- No avoidable unwrap on unauthenticated/invalid protocol paths.
- Security regression tests added for replay, EOF, and malformed frames.
- Failure semantics are fail-closed and explicitly tested.

### A.4 Ops, Packaging, and Trust

- Add `SECURITY.md`, threat model, and non-claims matrix.
- Add `CONTRIBUTING.md`, release checklist, and project governance policy.
- Add GitHub-style CI template for Linux + Windows lint/test/build matrix.
- Add dependency and artifact reproducibility notes.

**Exit criteria**
- New contributor can clone/build/test from docs only.
- Public process for disclosure and maintenance is in place.

### A.5 Documentation for Funders

- Publish “what SHPH is / is not” page.
- Publish risk matrix (current limits, explicit exclusions).
- Publish measurable milestone scorecard and roadmap burn-down.
- Publish support model and maintenance plan.

**Exit criteria**
- Public docs support an OTF/enterprise pre-review.
- Funders can verify claims against tests and changelog.

## Phase B — Funding Validation & Audit Preparation (Weeks 4–6)

### B.1 External Review Readiness

- Add reproducible demo scripts and failure-mode walk-throughs.
- Add test artifacts and CI logs for each mandatory acceptance gate.
- Add release tagging for “funding checkpoint” artifacts.
- Add legal/compliance checklist for open-source artifact handling.

### B.2 Stability Before Feature Expansion

- Freeze API changes during validation window.
- Add bug bounty-safe report template and triage SLA.
- Resolve high-impact/low-effort CVE-risk issues identified by scanners.

---

## Next Delivery Sequence

The following sequence supersedes the earlier “optional / research” framing for
the explicitly approved Shroud-to-Windows-TUN work. It does not turn the
experimental transports into stealth, anti-censorship, or standards-compliant
QUIC claims.

### Phase C — Shroud Lab Completion

**Objective:** turn the current Shroud-cell lab path into a useful,
instrumented, testable framing experiment without presenting it as stealth.

**Work items**

- Define and document cell framing invariants, size limits, padding behavior,
  profile semantics, and authenticated failure behavior.
- Add coverage for balanced, low-latency, bulk, randomized-lab, and
  extreme-lab profiles,
  including malformed cells, truncation, oversize input, replay, and
  profile-mismatch cases.
- Separate framing overhead from cryptographic cost in benchmark output.
- Add deterministic fixtures and reviewed examples for each profile.
- Document that the current UDP adapter remains a lab shim and is not QUIC.

**Exit criteria**

- Every lab profile has round-trip, negative, and regression tests.
- Shroud benchmark rows include payload size, cell size, overhead, and tail
  latency.
- No profile is selected implicitly by a production configuration.
- Docs state the exact non-claims: no stealth guarantee, fingerprint
  resistance, censorship bypass, or QUIC interoperability.

**Current status:** complete for the controlled lab scope. Core cell
invariants, explicit frame types, profile-wide round trips, the raw-cell
versus user-payload capacity boundary, canonical padding, the authenticated
malformed-input matrix, separated framing/AEAD benchmark rows, and explicit
profile-selection/non-claims documentation are covered by tests and evidence.
Native/live benchmark evidence remains outside this Phase C completion claim.

### Phase D — Hardening and Optimization

**Objective:** complete another bug-finding pass and improve the measured
implementation before the release-readiness move.

**Work items**

- Re-run static review, dependency review, fuzz targets, malformed-input
  tests, replay/nonce boundary tests, and lifecycle tests.
- Investigate the QUIC-shim handshake tail outlier and add a repeatability
  threshold before accepting any optimization.
- Reduce avoidable allocations in handshake, frame processing, and
  long-session paths; measure allocation rate and RSS over sustained runs.
- Benchmark secure-default and classical-lab separately without treating them
  as equivalent security profiles.
- Add native Linux TUN and two-host test plans, with explicit `SKIP` evidence
  when privileges or tools are unavailable.
- Fix only confirmed defects or measurable regressions; preserve fail-closed
  behavior.

**Exit criteria**

- `cargo fmt --all -- --check`, strict Clippy, workspace tests, locked build,
  and benchmark checks pass.
- Fuzzing and regression suites have documented commands and non-placeholder
  coverage.
- Benchmark changes are reproduced on two runs and recorded with environment
  metadata.
- No known high-severity correctness or security issue remains open.

### Phase D-A — Pre-Completion Audit Gate

**Objective:** subject the hardened, non-TUN implementation to an external
audit before declaring Phase D complete.

This is a mandatory gate between implementation work and Phase D completion.
It does not begin Windows TUN work and does not require native TUN evidence.

**Work items**

- Freeze the audit input tree and record the exact workspace version, commit,
  lockfiles, platform, and validation commands.
- Provide the auditor with the production workspace, fuzz harnesses,
  benchmark/evidence docs, threat model, non-claims, and known accepted risks.
- Record every audit finding with severity, affected path, reproducibility,
  disposition, and regression-test requirement.
- Fix confirmed correctness, security, reliability, and documentation issues;
  reject only demonstrably false positives with written rationale.
- Re-run focused regressions for every fix, then repeat the complete Phase D
  validation gate and mirror verification.
- Publish an audit disposition note before advancing to Phase E.

**Exit criteria**

- Audit scope and exact input snapshot are recorded.
- Every finding is fixed, accepted with documented rationale, or explicitly
  deferred outside the release scope.
- High-severity findings are zero; any medium-severity residual risk has an
  owner, rationale, and mitigation.
- Focused regression tests cover every accepted fix.
- Full fmt, Clippy, workspace test/build, fuzz-manifest, audit, diff, and
  mirror-parity checks pass after remediation.
- The audit disposition is linked from the Phase D scorecard and release
  evidence.

**Current status (2026-08-08):** local implementation, hardening,
fuzz-smoke, regression, and paired WSL2/native-Windows benchmark work is
complete for the controlled lab scope. Phase D remains open as a delivery gate
until native Linux two-host TUN evidence and privileged Windows Wintun packet
evidence are recorded.

### Phase E — Big Move / Release Readiness

**Objective:** convert the hardened lab state into a reviewable release
candidate without overstating platform or network evidence.

**Work items**

- Freeze the protocol/profile and public-API claims for the release candidate.
- Publish benchmark results, limitations, threat model, dependency scan, and
  reproducibility evidence together.
- Reconcile configured Linux and Windows checkouts, then verify checksums.
- Run the complete release checklist and create a SemVer release tag only when
  the documented criteria are met.
- Keep production claims limited to the validated platform and transport scope.

**Exit criteria**

- Release manifest, changelog, audit evidence, and benchmark report agree on
  the same version and commit.
- Mirror parity is verified.
- All unsupported capabilities remain explicitly labeled as unavailable,
  lab-only, or operator-dependent.
- A reviewer can reproduce the claimed results from the documentation.

**Current status (2026-08-17):** preparation is in progress, but Phase E is
not complete. The benchmark/evidence bundle was captured on the prior
`0.6.0-dev.0` and `0.6.1-dev` lines; the current `0.6.2-dev` development
snapshot carries follow-up hardening and public-surface cleanup. The final
claims freeze, mirror-parity check, final release checklist, and production
release sign-off remain gated on the outstanding native TUN evidence.

### Phase F — Windows TUN Delivery

**Objective:** integrate and validate the final Windows data-plane backend.

**Work items**

- Provision a signed, version-pinned Wintun runtime and define its packaging
  and verification procedure.
- Validate the wired Windows TUN backend on an approved elevated host; never
  silently fall back to a stub.
- Validate interface lifecycle, packet I/O, route/DNS apply/rollback,
  shutdown, reconnect, and privilege/error reporting on supported Windows
  versions.
- Add Windows-specific integration evidence and keep it separate from WSL2
  and native-Linux benchmark results.

**Exit criteria**

- A two-node authenticated Windows tunnel transfers packets through Wintun.
- Start, stop, reconnect, rollback, and failure paths are tested on a
  privileged Windows host.
- Signed-runtime provenance and supported-version documentation are complete.
- Windows TUN claims are not marked complete until the above evidence exists.

**Current status (2026-08-08):** the backend, Windows-only unit coverage,
signed-runtime inspection, and non-elevated fail-closed path are complete.
The live elevated adapter, packet, control-plane, reconnect, shutdown, and
two-node gates remain open.

## Optional / Research Track (does not replace the delivery sequence)

Keep these as explicit optional features, not part of mandatory funding readiness.

### Transport Research
- Browser-like TLS/QUIC fingerprint shaping
- Exact wire-level JA4 capture through a lower-level TLS/QUIC observation hook
- QUIC production hardening beyond the current standards-QUIC lab path
- Adaptive timing/cell-size morphology

### Extreme Transport Modes
- Offline mesh (Bluetooth/Wi-Fi Direct/DTN)
- Data-Mule file-courier transport

### Advanced Trust & Crypto
- HSM/PKCS#11 offload
- YubiKey / PIV binding
- TPM key sealing
- ~~Hybrid PQC session upgrade (ML-KEM/Kyber-style)~~ — **shipped in v0.4.0** (ML-KEM-768 + X25519); see `docs/HARDENING.md` increment 4.
- Shamir M-of-N unwrapping workflows
- Ratchet audit export for compliance

### Optional-track implementation status

- Configuration validation and safe CLI primitives exist for offline-mesh,
  data-mule, Shamir, and ratchet-audit workflows.
- Offline-mesh and data-mule prototypes now have bounded scans, quarantine,
  deferred acknowledgement, and documented copy/replication workflows for
  controlled labs.
- Hardware identity provider entries fail closed with an explicit unavailable
  backend error.
- These primitives are not represented as production hardware integrations,
  production QUIC, or effective anti-observation traffic shaping. The
  Shroud-cell path is lab-only and opt-in.
- The reviewed Shroud 2.0 subset now has an opt-in standards-QUIC morphology
  API for bounded size classes, authenticated padding, and bounded delay.
- Standards QUIC also has an opt-in passive JA4-compatible observability
  plugin. It records bounded public rustls ClientHello metadata for lab
  diagnostics; live observations are explicitly partial and do not spoof or
  reshape the handshake.
  Browser fingerprint forgery and active-probe decoy routing remain
  deliberately out of scope; see `docs/SHROUD_2_IMPLEMENTATION.md`.

### Standards QUIC progress

- The explicit standards path now uses Quinn/rustls RFC QUIC with bounded
  control streams and RFC 9221 DATAGRAM support.
- CLI support is available for `listen`, `connect`, `send-once`, and
  `recv-once` through `--transport quic-standard --quic-cert PATH`.
- The legacy `--transport quic` UDP shim is unchanged.
- Continuous Linux native-TUN `up` mode now uses the asynchronous
  `AsyncTunDevice` bridge with bounded queues and blocking transport workers.
  Linux standards-QUIC `up` also has a bounded RFC 9221 DATAGRAM-to-TUN bridge.
  The Windows Wintun backend remains pending native-host validation, while
  production certificate/PKI operations and live two-host evidence remain
  future work and are not claimed complete.

## Benchmarking and Performance Profiles

Benchmarking will use a **native Linux host as the default environment**.
Windows benchmarking is a secondary platform-validation track, not the source
of the primary performance baseline. WSL results must be labeled separately
from native Linux results because virtualization, filesystem mounts, and
scheduler behavior can distort measurements.

### Benchmark phases

1. **Methodology freeze** — record OS release, kernel, CPU model, governor,
   Rust toolchain, compiler flags, dependency lockfile, and benchmark revision.
2. **Microbenchmarks** — measure AEAD, X25519, ML-KEM-768, HKDF, framing,
   Shroud-cell processing, replay-window operations, config parsing, and audit
   record parsing, reporting min/p50/p95/p99/max/mean latency.
3. **Handshake benchmarks** — measure complete authenticated handshakes,
   separating secure-default and classical-lab results, with p50/p95/p99
   latency and explicit security-profile labels.
4. **Data-plane benchmarks** — measure throughput and latency across payload
   sizes, batching choices, and controlled concurrency.
5. **Adapter benchmarks** — measure TCP, the QUIC-like lab shim, offline-mesh,
   and data-mule behavior independently; do not present the lab shim as
   standards-compliant QUIC.
6. **Regression tracking** — publish median/p95/p99 latency, throughput,
   memory/allocation observations, variance, and the exact command used.

### Implemented security/performance profiles

Profiles must be explicit, visible in logs/metrics, and selected by both peers.
They must never create an implicit downgrade path.

- **`secure-default`** — production profile; authenticated Ed25519 handshake,
  X25519, mandatory ML-KEM-768 hybrid derivation, AEAD, replay protection, and
  normal framing protections. This remains the default.
- **`classical-lab`** — benchmark-only profile for measuring X25519 without
  ML-KEM overhead. It must use a distinct protocol/profile identifier, require
  explicit opt-in on both peers, and be rejected by production-default peers.
- **`framing-lab`** — benchmark-only profile for comparing cell/padding costs
  while retaining authentication, AEAD, and replay protection. It must not be
  described as traffic-analysis resistance.
- **`transport-lab`** — benchmark-only adapter selection profile for isolating
  TCP, the QUIC-like shim, offline-mesh, or data-mule costs without changing
  the cryptographic security contract.

`secure-default` and `classical-lab` are now implemented as distinct signed
handshake identities. The profile is carried in every hello, bound to the
signature and transcript, and included in HKDF context. Existing APIs retain
the secure-default behavior. `classical-lab` has no ML-KEM material, requires
explicit selection on both peers, and fails closed against profile mismatch.
The CLI accepts `--handshake-profile`, and `[session].handshake_profile` is
available for long-running sessions.

Disabling ML-KEM is therefore a **separate, visibly non-production protocol
profile**, not a runtime switch that silently weakens `secure-default`.
Benchmark results from different profiles are not directly comparable unless
the report states which security properties were removed.

### Benchmark obstacles

- CPU frequency scaling, turbo behavior, thermal throttling, background load,
  and VM scheduling can overwhelm small crypto differences.
- ML-KEM cost varies significantly by CPU and compiler; one Linux result is not
  a universal performance claim.
- Loopback measures host-stack behavior, not real link loss, MTU, jitter,
  congestion, or cross-machine scheduling.
- Concurrent fuzzing, CI runners, containers, and WSL mounts contaminate
  filesystem and scheduler measurements.
- Classical-only and hybrid handshakes have different security properties, so
  comparisons must be labeled rather than marketed as equivalent.
- Benchmark harnesses can accidentally measure allocations, logging, key
  generation, or setup work instead of the intended steady-state operation.
- Windows native TUN, route/DNS privileges, and the current QUIC-like shim
  require separate capability and platform notes.

### Exit criteria for this roadmap item

- Native Linux baseline is reproducible from documented commands.
- Every result includes environment metadata and security profile.
- Production defaults remain hybrid and fail closed on profile mismatch.
- A benchmark regression is reproduced twice before being treated as a bug.

Current implementation status:

- Core/transport profile behavior: complete.
- Focused profile and config regression tests: complete.
- Dependency-light native Linux runner: complete.
- Latency distribution output, p99.9 reporting, payload-size matrix, CPU/RSS,
  allocation counters, Shroud profile rows, QUIC-shim loopback rows, and
  million-frame replay/nonce coverage: complete.
- Operator wrapper for lifecycle, control-plane, reconnect, and native-TUN
  prerequisite/timing checks is complete; isolated namespace smoke and
  open/hold/close lifecycle benchmark scripts are also available.
- Paired WSL2/Linux and native Windows local benchmark capture is complete for
  the `0.6.0-dev.0` development line; the full score tables, commands, raw-capture
  paths, and interpretation limits are recorded in
  `docs/BENCHMARK_RESULTS_2026-08-05.md`. The latest native Windows gate
  record is `docs/evidence/WINDOWS_NATIVE_VALIDATION_2026-08-08.md`.
- Native Linux TUN lifecycle, packet-boundary validation, complete-write
  enforcement, and zeroizing bridge buffers: complete for capability-gated
  local evidence; see `docs/NATIVE_TUN_STATUS_2026-08-04.md`.
- Real native Linux TUN saturation, two-machine RTT/jitter, injected
  standards-QUIC impairment runs, Windows process CPU/RSS instrumentation,
  Criterion reports, and reviewed native-TUN evidence publication: remaining
  because they require operator hosts, privileges, or external traffic tools.

---

## Funding-Critical KPI (Monthly)

- Pass rate: 100% on local lint/test/build gates.
- Session uptime for one-shot and loop `up` flows.
- Windows parity on route/DNS apply + rollback.
- Mean time to recover from transient disconnects.
- Number of unresolved critical security findings in tracker.

---

## Practical Positioning

For now, position SHPH as:

- **Open-source VPN-first infrastructure**
- **Transparent security posture with explicit trust boundaries**
- **Reliable transport + sane operations before anti-observation claims**

This is the fastest route to serious funding credibility and long-term engineering trust.
