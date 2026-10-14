# Phantom One, Shroud 2, and Optional Onion Routing: Implementation Scope

Status: implementation checkpoint 2026-09-28. This document consolidates the
five morphology improvements, four traffic-analysis/probing workstreams, and
optional onion routing requested for the next development program. The
checkpoint below records partial implementation and test evidence; no package
is marked validated.

The existing TCP/native-TUN release profile and lifecycle gates remain binding.
This experimental program may proceed alongside that work, but does not broaden
the release claims in [SUPPORT_MATRIX.md](SUPPORT_MATRIX.md).

## Outcomes and boundaries

- Improve control of envelope sizes, latency, overhead, and adaptation under
  interactive, bursty, and sustained workloads.
- Measure whether the complete carried session is less distinguishable under
  explicitly documented passive-classification and active-probing experiments.
- Provide optional onion routing while retaining SHPH peer authentication and
  end-to-end payload encryption.
- Keep morphology, carrier choice, and routing independently selectable. Onion
  routing must not imply a particular padding policy or a DPI-resistance claim.
- Preserve explicit opt-in, bounded memory/queues/timers, secret-safe diagnostics,
  cancellation, and fail-closed parsing. No silent direct-network fallback when
  a selected carrier or onion route fails.
- Run live experiments on owned or explicitly authorized infrastructure. Record
  capabilities that cannot be exercised as `SKIP`, not successful validation.

## Work packages

The ten top-level work packages below are tracked separately from their
acceptance evidence. Existing code is a starting point, not evidence that a
package's acceptance criteria have been met.

### P1. Phantom One weighted size selection and padding budgets

Deliver configurable integer weights over eligible canonical size classes,
with per-frame and session-level padding budgets. Keep the current selection
policy available for baseline comparisons. Define behavior when the remaining
budget cannot accommodate a canonical target: bounded waiting or an explicit
error, never a silent noncanonical frame. Account for fixed envelope bytes and
random padding separately.

Acceptance: seeded reproducibility; valid weight/configuration bounds; measured
selection frequencies within predeclared statistical tolerances; maximum size
and padding-budget enforcement; no state advancement on invalid input; tests at
class, payload, and carrier-budget boundaries. Compare latency and overhead
against the current selector using P5.

Primary code: `shph-transport/src/phantom_one.rs`, `shph-obfuscation/src/lib.rs`.

### P2. Authenticated envelope-policy negotiation

Add a bounded, versioned policy exchange over the authenticated session before
application data. Cover envelope version, supported profiles, selection policy,
padding bounds, and directional frame budgets. Bind agreement to that session
and require explicit acknowledgement. Specify compatibility with legacy
explicitly configured peers; reject incompatible settings with actionable
errors and without implicit downgrade. Treat wire-format changes explicitly.

Acceptance: disagreement, truncation, replay from another session, unknown
versions, excessive lists, timeout, and downgrade tests; no application delivery
before agreement; both TCP and standards-QUIC coverage. A shrinking carrier
limit remains authoritative after negotiation.

Primary code: `shph-transport/src/lib.rs`, `shph-transport/src/standards_quic.rs`,
`shph-config/src/lib.rs`, `shph-cli/src/ticket.rs`.

### P3. Shroud 2 adaptation using workload and queue observations

Extend the explicit adaptive API with bounded caller-supplied observations of
arrival intervals, burst length, and queue age. Preserve payload-size EWMA as a
baseline. Add hysteresis and minimum profile dwell time; use a monotonic clock
or injected timestamps. Avoid application identity inference and payload
inspection. Expose profile transitions and their reasons as aggregate metrics.

Acceptance: synthetic interactive/bulk transitions; burst/idle sequences;
nonmonotonic observation rejection; bounded counters; no rapid oscillation;
invalid input does not mutate state. Use ablation experiments to determine
whether each additional signal improves the latency/overhead tradeoff.

Primary code: `shph-transport/src/shroud2/mod.rs`.

### P4. Deadline-aware pacing and explicit backpressure

Introduce an explicit pacing policy with caller deadlines, bounded queue size,
cancellation, and documented overflow behavior. Include time already spent
queued when computing a shaping delay. Define whether expired datagrams are
dropped or returned as errors and distinguish this from reliable-stream
behavior. Recheck current carrier size limits before transmission. Keep the
existing non-pacing option for comparisons.

Acceptance: deterministic clock tests for deadline accounting and cancellation;
no busy loop; bounded memory under a blocked sender; size-limit shrink and
congestion cases; metrics for queue age, shaping delay, deadline expiration,
and locally dropped datagrams. Measure actual scheduler overshoot separately
from requested delay. Do not promise hard real-time delivery.

Primary code: `shph-transport/src/standards_quic.rs`,
`shph-transport/src/standards_tun.rs`, `shph-transport/src/shroud2/mod.rs`.

### P5. Complete-session performance and carrier measurements

Build a repeatable workload runner for interactive exchanges, bursts, idle
intervals, sustained transfer, and mixed bidirectional traffic. Compare shaping
off, existing profiles, and proposed policies over direct TCP, standards QUIC,
and the owned HTTP/2 carrier. Include HTTP/3 when its feature and hosts are
available. Add loss, delay, reordering, bandwidth constraints, and reconnect
campaigns where the test environment supports them.

Acceptance: machine-readable run manifests with revision, configuration,
workload, seeds, hosts, duration, and carrier; delivered goodput, p50/p95/p99
latency, CPU/memory, envelope overhead, carrier wire overhead, and loss reported
separately. Repeat runs and report variability. Capture both directions at
defined observation points; in-memory envelope sizes must not be labeled as
observed network packet sizes. Store raw captures outside public artifacts and
publish reviewed aggregate evidence.

Primary code: `benchmarks/`, `scripts/operator_campaigns.py`, `shph-edge/`.

### D1. First-hop carrier and connection-opening behavior

Integrate and evaluate the owned-domain HTTP/TLS edge path as an explicit
carrier for SHPH. Inventory what an observer can see during setup, steady
state, idle periods, and shutdown. Verify where the SHPH handshake becomes
protected by the carrier. Establish HTTP/2 first; exercise feature-gated HTTP/3
separately. Preserve destination peer pinning through the relay.

Acceptance: authenticated payload delivery through the carrier, invalid TLS and
peer-pin rejection, bounded pooling and reconnect, no direct fallback, and P5
captures of complete sessions. Record visible TLS/HTTP characteristics and
classify them through D4; standards compliance alone is not browser parity.

Primary code: `shph-edge/src/carrier.rs`, `shph-edge/src/relay.rs`,
`shph-transport/src/lib.rs`.

### D2. Active-probing resistance

Create an owned-endpoint probe harness covering missing/invalid/expired/replayed
capabilities, malformed requests, unsupported methods, partial handshakes, and
connection churn. Compare observable response content, lengths, timing, and
closure behavior. Design unauthenticated behavior around an operator-owned
service with bounded resource use and no backend access before authorization.
Evaluate an established secret-authenticated transport adapter as a separately
measured option before inventing a new handshake.

Acceptance: no authorization bypass or replay-cache capacity bypass; bounded
preauthentication work; no secret-bearing output; reproducible baseline and
candidate probe results. Report observed distinguishability, not a claim that
finite testing proves indistinguishability. Any adapter has separate setup,
dependency, interoperability, and shutdown coverage.

Primary code: `shph-edge/src/frontdoor.rs`, `shph-edge/src/capability.rs`,
`shph-edge/src/carrier.rs`, new local probe harness under `scripts/`.

### D3. Sequence shaping and optional cover traffic

Extend shaping experiments from individual lengths to bursts, gaps, direction
changes, and session transitions. Add a negotiated, explicitly opt-in cover
policy with absolute byte/rate caps, an overhead budget, idle timeout, and
bounded scheduling. Cover frames must be authenticated and unambiguously
discarded without delivery as application or TUN payloads. Payload traffic
takes priority; congestion and shutdown suppress cover generation.

Acceptance: disabled mode generates no cover; idle and busy sessions obey
budgets; cover cannot keep a cancelled session alive; frame negotiation and
replay behavior remain correct. P5 records latency/bandwidth costs and D4
evaluates joint size/timing sequences. Use P2 and P4 rather than introducing a
second negotiation or pacing mechanism.

### D4. Offline detectability evaluation

Build a bounded offline feature-extraction and classification pipeline for
authorized captures. Evaluate opening behavior and complete bidirectional
length/timing sequences against representative background traffic. Separate
this analysis from the live transport process. Split datasets by capture
session and, where possible, host/site/day; never randomly split packets from
the same session across training and evaluation.

Acceptance: dataset provenance and preprocessing recorded; held-out results;
detection rate at predeclared false-positive targets, ROC/PR curves, sample
counts, uncertainty, and performance cost. Include baseline, each individual
change, and combined-policy comparisons. Flag datasets too small to estimate
the requested false-positive rate. Freeze evaluation thresholds and resource
budgets before comparing candidates; report negative results and distribution
shift. Entropy or histogram similarity alone cannot pass this package.

Dependencies: P5 provides captures; D1-D3 provide candidate behaviors. A lab
classifier result cannot establish universal censorship resistance.

### O1. Optional multihop onion routing

Deliver in two stages under one explicit routing boundary.

**O1a: Tor underlay integration.** Reuse an operator-managed Tor SOCKS endpoint
for SHPH TCP. Add explicit routing configuration, proxy-side name resolution,
SOCKS authentication support for stream-isolation credentials where configured,
bounded setup, cancellation, and no direct fallback. Retain end-to-end SHPH
authentication. Exercise ordinary peer endpoints and optionally onion-service
peer endpoints. Direct QUIC-over-Tor is not part of this TCP/SOCKS integration.

Acceptance: mock-proxy tests for destination-name forwarding, isolation,
timeouts, and failure closure; a separately recorded live Tor campaign when
available; no local destination DNS lookup or direct peer connection in onion
mode. Test native-TUN routing/containment separately before claiming full VPN
operation through Tor. O1a does not complete native onion routing.

**O1b: Native SHPH onion-circuit prototype.** Produce a protocol design and then
an opt-in prototype for client -> entry -> middle -> destination SHPH peer.
Start with explicitly configured, pinned relays and no public relay discovery
or arbitrary public exit service. Specify independent ephemeral per-hop keys,
authenticated circuit construction, layered payload protection, directional
sequence/replay state, rekey/expiry, flow control, quotas, and teardown. Preserve
the inner client-to-destination SHPH channel. Merely chaining proxies does not
satisfy this deliverable.

Acceptance: document what each hop learns and the effects of shared relay
ownership, collusion, and observation of both ends; review the key schedule and
wire protocol before production integration. Exercise at least three relay
processes in isolation, layer tampering/replay, failed extension, malicious or
stalled middle hop, cancellation, circuit exhaustion, and reconnect without
direct fallback. Bound per-circuit state and traffic amplification. Capture P5
performance and D4 first-hop observations separately. An independent protocol
review and new evidence are required before broadening security claims.

Routing remains off by default. Additional hops are not evidence of anonymity
or improved DPI resistance. Relay distribution and entry-selection policy must
be part of the design, rather than assuming random rotation is beneficial.

## Delivery order and completion tracking

| Stage | Packages | Exit criterion |
| --- | --- | --- |
| A: Baselines | P5 baseline, D4 dataset/evaluation design | Reproducible workloads and frozen evaluation methodology |
| B: Envelope policy | P1, P2 | Bounded selection and authenticated agreement pass tests |
| C: Adaptation and scheduling | P3, P4 | Deterministic transition/deadline tests and comparative performance results |
| D: Carrier and observation resistance | D1, D2, D3; expanded P5/D4 | Full-session and probe results with costs and limitations |
| E: Established onion underlay | O1a | Isolation, name-resolution, failure, and available live campaign evidence |
| F: Native onion prototype | O1b | Reviewed design, bounded prototype, multihop failure tests and measured results |

Track each package as `SCOPED`, `IMPLEMENTING`, `IMPLEMENTED`, or `VALIDATED`.
Record validation outcomes separately as `PASS`, `FAIL`, `SKIP`, or `BLOCKED`.
At program kickoff, all packages were `SCOPED`. A mock, simulation, or local
test cannot substitute for a missing carrier, native-host, or independent-review
gate.

### Checkpoint: 2026-09-28

`LOCAL NEXT` identifies work that can proceed in this repository. `BLOCKED`
identifies acceptance evidence that depends on external data, hosts, carriers,
or independent review; it does not mean all local implementation work is done.

| Package | Work status | Validation evidence and remaining gates |
| --- | --- | --- |
| P1 | `IMPLEMENTING` | `PASS`: seeded weighted-frequency and padding/class-boundary tests; focused release Criterion rows are recorded in the 2026-09-28 evidence. `LOCAL NEXT`: compare complete-session latency and overhead across workloads. Loopback microbenchmarks do not satisfy P5. |
| P2 | `IMPLEMENTING` | `PASS`: bounded codec, session binding, TCP and standards-QUIC exchange, directional limits/budgets, explicit one-shot CLI/config wiring before payload I/O, and loopback process tests for baseline and negotiated TCP/standards-QUIC send/receive with receipt acknowledgement; unsupported transports and persistent TUN sessions fail closed. `LOCAL NEXT`: negative timeout/replay/downgrade matrix and a design decision for persistent-session integration. `BLOCKED`: independent peer interoperability evidence. |
| P3 | `IMPLEMENTING` | `PASS`: deterministic workload, queue-age, burst, dwell, reason-counter tests, and a paced QUIC send API. `LOCAL NEXT`: CLI/TUN session integration and P5 ablation measurements. |
| P4 | `IMPLEMENTING` | `PASS`: deadline, cancellation, queue-bound, expiry, carrier-limit helpers, and QUIC morphology send-path pacing. `LOCAL NEXT`: native-TUN bridge scheduling, deterministic timer/shrink coverage, and scheduler-overshoot measurements. |
| P5 | `IMPLEMENTING` | `PASS`: bounded [`benchmark_one_shot_loopback.py`](../scripts/benchmark_one_shot_loopback.py) runner exercises real one-shot CLI sessions and verifies payloads. `LOCAL NEXT`: add resource, goodput, packet, and workload-class measurements. `BLOCKED`: representative authorized multi-carrier captures; loopback process time is not P5 acceptance. |
| D1 | `IMPLEMENTING` | `LOCAL NEXT`: exercise TLS pinning and reconnect behavior against an owned local endpoint. `BLOCKED`: authorized multi-carrier observation and complete-session capture evidence. |
| D2 | `IMPLEMENTING` | `PASS`: `ring`-pinned edge; bounded verification and expiry-indexed replay regressions; signature-before-replay-commit, contention, cancellation, clock-skew, and duplicate tests; repeated loopback HTTP/2 probes for malformed, invalid-signature, expired, valid-first-use/replay, partial TLS, and connection churn; backend accepted exactly one authorized first use; idle H2 connections expire under a tested application-activity deadline. `LOCAL NEXT`: paired baseline/candidate loopback response distributions and operator-profile review. `BLOCKED`: representative owned-host campaign evidence. |
| D3 | `IMPLEMENTED` | `PASS`: negotiated TCP and QUIC cover frames; sender suppression and absolute/relative budgets; receiver regressions reject cover before data and cumulative overhead excess. `LOCAL NEXT`: sequence experiments and combined P5/D4 analysis. |
| D4 | `IMPLEMENTING` | `PASS`: bounded opening-order/timeline features, grouped held-out flow-blocking decisions, deterministic synthetic smoke data, bounded classic-Ethernet-PCAP-to-summary conversion with provenance, multi-CSV evaluation, and parser-to-evaluator tests. `LOCAL NEXT`: extend synthetic smoke analysis only where it tests a specific acceptance condition. `BLOCKED`: authorized representative PCAP data and held-out results. |
| O1a | `IMPLEMENTING` | `PASS`: local SOCKS mocks for fresh credentials, `.onion` name forwarding, timeout, failure closure, pre-cancellation, and cancellation during a stalled exchange; CLI shutdown is wired through one-shot TCP setup. `LOCAL NEXT`: make proxy TCP connect and the SHPH handshake promptly cancellable. `BLOCKED`: live Tor and native-TUN routing/containment campaign. |
| O1b | `SCOPED` | Design proposal exists in [`ONION_CIRCUIT_DESIGN.md`](ONION_CIRCUIT_DESIGN.md). `LOCAL NEXT`: bounded opt-in prototype and three-relay failure tests. `BLOCKED`: independent protocol review and production-facing measured results. |

### Engineering update: 2026-10-14

The historical checkpoint above remains unchanged. Current implementation
progress for the requested Shroud 3 and edge-probe work is:

| Package | Work status | Current local evidence and remaining gates |
| --- | --- | --- |
| P3 / adaptive Shroud 3 surface | `IMPLEMENTING` | `PASS`: independent `S3` v1 engine with its own bounded observation window, workload modes, joint size/delay profiles, OS-seeded production randomness, padding, and metrics; strict S2/S3 separation; deterministic sampling, state-transition, invalid-observation, MTU, padding, and frame-wipe tests; Linux `host`/`join`/`up` opt-in and config plumbing; authenticated loopback bridge framing; a previously recorded WSL2 isolated two-network-namespace UDP echo through both real TUN devices (dirty provenance); and synthetic in-memory Shroud 2/Shroud 3 workload comparisons. Linux link activation now precedes route setup and restores a previously-down state on cleanup. `LOCAL NEXT`: authorized two-host interoperability and carrier-visible measurements. `BLOCKED`: representative authorized captures, capture-fitted profiles, and held-out passive-classifier evaluation; native-TUN host evidence remains separate. |
| P4 / Shroud 3 pacing integration | `IMPLEMENTING` | `PASS`: bounded pacing API and paced send wired into the opt-in Linux native-TUN bridge; bridge helper framing/pacing is exercised over authenticated loopback QUIC, and the WSL2 namespace packet round trip exercised that bridge. The benchmark-only cover-policy arm uses existing Phantom One keepalive framing and does not add a production Shroud 3 cover path. `LOCAL NEXT`: deterministic timer/shrinking-carrier coverage in the bridge and scheduler-overshoot measurements. |
| D2 / `shph-edge` active-probe evaluation | `IMPLEMENTING` | `PASS`: loopback HTTP/2 tests compare exact denial status, content type, and body for missing, invalid, expired, and replayed capabilities; verify connection reuse; and confirm exactly one backend accept for the authorized first use. A TLS loopback test bounds an incomplete ClientHello, enforces `max_connections`, survives eight connect/close attempts, and returns to serving requests. Malformed and partial HTTP/2 frames close with bounded output and no backend connection. The Python probe helpers are exercised against loopback TCP/TLS listeners; the report summarizes response status, body size/hash, timing, malformed-frame outcomes, and churn. Its suite ran 18 tests (17 passed, one POSIX-only test skipped on Windows). `LOCAL NEXT`: run the updated operator probe against the actual `shph-edge` TLS server and review response/closure distributions. `BLOCKED`: no operator-probe distributions have been collected from the actual edge server. External or host-mutating campaigns remain `SKIP` without authorized infrastructure. |
| O1b / native onion prototype | `IMPLEMENTING` | `PASS`: nested TLS 1.3 with per-hop pinned certificates and tokens, literal allowlists, bounded setup/lifetime/bytes/concurrency, two/three-hop loopback path, reconnect, wrong-pin/token and forbidden-target rejection, three separate relay processes carrying an authenticated SHPH payload, and local stalled-setup shutdown, circuit-exhaustion, malformed-setup, and stalled-destination lifetime tests. `LOCAL NEXT`: P5 measurements and reviewed teardown/route behavior. `BLOCKED`: independent protocol/code review, authorized external relay evidence, and native-TUN containment. |

These results are implementation and local regression evidence. Neither
surface is `VALIDATED`, included in the release profile, or evidence for
anonymity, censorship resistance, DPI evasion, production VPN operation, or
full-session performance.

No package is `VALIDATED`. Local test passes above establish only the named
code paths. The D4 flow-blocking output is an offline classifier decision
simulation; it does not drop packets, emulate an on-path censor, or establish
traffic indistinguishability. Synthetic traces are test fixtures, not captures
or evidence. Real D4 results require authorized representative data and remain
blocked until that data is available.

Each implementation change must update relevant operator/configuration docs,
add meaningful boundary tests, run affected locked test and Clippy targets,
and record wire compatibility. Changes to parsers extend the existing fuzz
targets. Standalone edge checks use its own manifest; workspace success does
not validate it. Run format and diff checks before delivery.

The complete program requires all ten top-level packages, including both O1
stages, to meet their stated acceptance criteria. Partial implementation and
negative experimental outcomes must remain visible rather than being called
completion.
