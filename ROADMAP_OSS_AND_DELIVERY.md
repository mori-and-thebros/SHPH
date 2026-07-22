# SHPH Roadmap (OSS + Delivery + Funding Readiness)

## Objective

Make SHPH a **funding-ready, open-source VPN** with:

- Reliable encrypted networking on Linux + Windows
- Measurable security posture (with explicit non-claims)
- Clean operational and contributor experience
- Transparent, testable milestones suitable for grant review

Non-goals in this roadmap section: stealth/fingerprinting, anti-censorship claims, and optional experimental transports.

## Current State (as of 2026-07-10)

### What is already built

- Rust workspace compiles and is locally testable.
- Authenticated handshake (TCP) with transcript-bound keys.
- Encrypted framed transport over TCP.
- `up` session mode with one-shot and continuous transfer.
- Linux native TUN flow behind `SHPH_TUN_NATIVE=1`.
- Reconnect policy with runtime backoff for session mode.
- Config schema and peer/config workflows.
- Control-plane routes/DNS apply, reconcile, undo, and persistent rollback state.
- CLI and docs baseline in place.
- Roadmap validation, Shamir split/recovery, and ratchet-audit export primitives
  are available behind explicit CLI commands.

### Mandatory-track status

The mandatory funding track is complete for the documented controlled-lab scope:
Linux gates, the mirrored source tree, control-plane lifecycle tests, security
regressions, release/process documents, and evidence artifacts are maintained.
This does not make SHPH a production VPN or establish hostile-network,
anti-censorship, or conformant-QUIC claims.

Remaining work is explicitly optional or deployment-specific:

- Native Windows route/DNS execution still requires operator validation on a
  privileged Windows host; native Windows TUN now fails explicitly until a
  signed Wintun runtime is provisioned and integrated.
- Production QUIC, effective anti-observation shaping, and hardware-backed
  identity providers remain unimplemented.
- A lab-grade password-encrypted keystore path now exists; production key
  management remains unimplemented.

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

## Optional / Research Track (do not block funding milestone)

Keep these as explicit optional features, not part of mandatory funding readiness.

### Transport Research
- Browser-like TLS/QUIC fingerprint shaping
- QUIC production hardening
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

## Benchmarking and Performance Profiles (Planned)

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
  prerequisite/timing checks: complete.
- Real native Linux TUN saturation, two-machine RTT/jitter, injected QUIC-shim
  impairment runs, Criterion reports, and reviewed evidence publication: remaining
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
