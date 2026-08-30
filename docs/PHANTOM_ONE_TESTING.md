# Phantom One Testing and Evidence Boundaries

Status: prototype testing plan, 2026-08-29. This document scopes authorized
testing for Phantom One and defines what current and future evidence may
and may not claim. It complements `docs/PHANTOM_ONE_DESIGN.md` and follows the
evidence discipline of `docs/SECURITY_EVIDENCE.md`, `docs/TESTING.md`, and
`docs/REPRODUCIBILITY.md`.

## Authorized testing scope

All Phantom One testing is **lab-only and authorized-only**:

- Run tests against infrastructure you own or are explicitly authorized to
  use: loopback, private namespaces, and operator-controlled edge domains.
- Do not point the edge relay or Phantom One carriers at third-party networks,
  services, or domains you do not control. The edge is an owned-domain
  component; using it to front, probe, or imitate others' infrastructure is
  out of scope and out of policy.
- Do not run Phantom One experiments as censorship-circumvention or DPI-evasion
  exercises against real network middleboxes you do not operate. No such
  result would be admissible evidence under this taxonomy anyway.
- Phantom One artifacts are not release artifacts. Test outputs are engineering
  evidence, never release-eligible claims.

## Current evidence state

| Component | State | Evidence class |
| --- | --- | --- |
| Phantom One envelope (`shph_transport::phantom_one`) | Exported opt-in lab module; unit tests cover round-trip, bounds, malformed/truncated/non-canonical rejection, replay-window behavior, and sequence exhaustion | S0 (source boundary) + S1 (focused unit tests) |
| Edge relay (`shph-edge/`) | Standalone prototype, **not a workspace member**; unit tests cover capability signature/expiry/audience/replay rejection, replay-cache bounds, front-door fallback decisions, configurable-path validation, bounded token bundles, log redaction, config validation, and bounded no-reparse file inputs | S0 + S1 within its own manifest; Linux and Windows format, Clippy, compile/test gates |
| HTTP/2 carrier | TLS-required loopback-capable prototype with bounded connection/stream pooling; no recorded live-TLS multiplexing or two-host run | S0 + S1 for validation and lifecycle boundaries |
| HTTP/3 carrier | Feature-gated opt-in Quinn/rustls + h3/h3-quinn relay path with bounded requests, capability checks, replay protection, and shutdown handling | S0 + S1 compile/unit evidence; no live two-host HTTP/3 evidence |
| Fuzz target (`fuzz/fuzz_targets/phantom_one_envelope.rs`) | Registered in `fuzz/Cargo.toml`; exercises the **real** `shph_transport::phantom_one` decode, encoder, and stateful-decoder paths with arbitrary bytes and bounded path MTU | S2-eligible once a bounded run is recorded; see below |

There is currently **no S3 or S4 evidence** for any Phantom One component: no
two-host run, no hostile-network or impairment campaign, no independent
review, no production telemetry. All current evidence is source-level and
deterministic-test-level.

The benchmark runner additionally records `phantom_one` allocating and reusable
buffer encode/decode rows plus one profile-bound row for each of the six
assigned profile IDs,
adaptive Shroud2 rows, and an in-memory `edge_opaque_relay` row. These are
implementation and allocation regression signals only; they do not upgrade
the Phantom One or edge components to host, network, or censorship-resistance
evidence.

## Test layers and commands

### S1 — deterministic unit tests

Envelope tests (workspace):

```bash
cargo test -p shph-transport phantom_one --lib
```

Edge prototype tests (separate manifest, not the workspace):

```bash
cargo test --manifest-path shph-edge/Cargo.toml
```

The CI workflow also runs the edge manifest's format, Clippy, and test gates on
a Windows runner so the platform-specific no-reparse file-open path is compiled
and exercised. This remains code-path evidence, not hostile-filesystem or
production deployment evidence.

Coverage intent for the S1 layer:

- Envelope round-trip preserves generation, frame type, sequence, payload,
  and target length.
- Explicit-target and path-MTU bounds are enforced; the path limit is the
  only accepted size authority.
- Caller-owned encode buffers are reusable and are cleared on rejected
  requests; successful encode/decode reuse wipes bytes retired by resizing or
  envelope removal.
- Malformed magic, version, generation, frame type, reserved bytes, declared
  lengths, and empty/oversized payloads all fail closed.
- Replay window rejects duplicates and stale sequences, accepts in-window
  reordering, accepts authenticated forward jumps beyond the bitmap window,
  and pins the generation; skipped and older values become stale.
- Sequence-space exhaustion returns an explicit error and never wraps.
- Capability verification rejects tampering, expiry, not-yet-valid,
  audience mismatch, excessive lifetime, and nonce replay.
- Front door returns fixed fallback responses without leaking which check
  failed.
- Relay paths are exact and bounded; token bundles are line-oriented and
  bounded, and each supplied token remains independently one-use.
- The HTTP/2 pool is bounded and its acquisition path observes shutdown; live
  TLS multiplexing remains an unrecorded capability-gated campaign.
- The HTTP/3 edge path is feature-gated, requires paired operator-owned TLS
  material, uses bounded QUIC/H3 settings and per-request limits, and consumes
  one capability token per local SOCKS session. Live H3 interoperability and
  long-run behavior remain unrecorded.
- Edge configuration rejects non-loopback SOCKS listeners, and the CLI serve
  path and library serve entry point require paired TLS certificate/key files.
- Edge SOCKS5 parsing rejects empty domains promptly; repeated short relay
  sessions complete under a bounded timeout.
- Edge log events contain only redacted metadata fields.
- Edge token, public-key, certificate, and private-key inputs are bounded,
  regular files and reject symlink/reparse traversal.

### S2 — fuzz and dependency evidence

The `phantom_one_envelope` fuzz target is registered in `fuzz/Cargo.toml` and
exercises the real `shph_transport::phantom_one` decode, encoder, and stateful
decoder with arbitrary bytes and bounded path MTU, covering malformed,
truncated, non-canonical, oversized, replay, and sequence-exhaustion inputs.
The CI fuzz-smoke job runs one iteration per target including
`phantom_one_envelope`; the pinned Windows campaign wrapper includes all six
registered targets as well.

Bounded local run:

```bash
cd fuzz
cargo fuzz run phantom_one_envelope -- -max_total_time=60
```

As with all SHPH fuzzing: a clean smoke run demonstrates only that the
exercised harness did not crash during that run — it is not a proof of
protocol correctness. A dated campaign record under `docs/evidence/` is
required before any run is cited as S2 evidence.

Dependency evidence for `shph-edge` (hyper, rustls, ring, tokio) is the
standard locked-manifest plus `cargo audit` discipline; because the crate is
outside the workspace, its lockfile and audit must be run and recorded
separately, and must not be conflated with workspace `cargo audit` results.

### S3 — host and multi-node evidence (not yet held)

No S3 evidence exists for Phantom One. Before any such claim is made, a recorded
campaign must capture, at minimum:

- exact commit, workspace version, toolchain, platform, and native-vs-WSL2
  status (per `docs/REPRODUCIBILITY.md`);
- edge serve + SOCKS5 connect round-trip over real TLS on owned loopback or
  an owned two-host setup, with a valid short-lived capability;
- the same round-trip through the feature-gated HTTP/3 carrier, including
  QUIC address validation and a multi-session token bundle;
- negative cases on the same rig: expired capability, replayed nonce, wrong
  audience, wrong path/method, missing capability, oversized stream;
- byte-count accounting from redacted edge logs matching observed transfers.

### S4 — independent review

None exists and none is claimed.

## Evidence taxonomy for Phantom One claims

Phantom One reuses the SHPH tier model (`docs/SECURITY_EVIDENCE.md`):

| Tier | Phantom One meaning | Admissible artifacts |
| --- | --- | --- |
| S0 | Source boundary: bounds, fail-closed branches, redaction-by-construction | Code review against the invariants in `docs/PHANTOM_ONE_DESIGN.md` |
| S1 | Focused deterministic tests | Unit/integration test output with command, commit, toolchain |
| S2 | Fuzz or dependency evidence | Registered `phantom_one_envelope` runs against the **real** module; per-crate `cargo audit` records |
| S3 | Host/multi-node evidence | Dated, reproducible campaign records under `docs/evidence/` |
| S4 | Independent review | External review with stated scope and findings |

Claim rules:

- A capability-rejection test (S1) supports "verification fails closed"; it
  does not support any statement about real-world attack resistance.
- A loopback HTTP/2 relay run supports "bytes were forwarded under a valid
  capability"; it does not support throughput, latency, censorship, or
  fingerprint claims on any real network.
- A clean `phantom_one_envelope` fuzz run supports only "the exercised harness
  did not crash during that run"; it does not support claims about envelope
  robustness beyond the recorded inputs, duration, and commit.
- Every evidence artifact records command, commit, toolchain, platform, and
  date; unlabeled results are not evidence.

## Explicit non-claims for test results

Regardless of test outcomes, Phantom One testing must not be used to assert:

- DPI evasion, censorship resistance, or classifier defeat;
- anonymity or unlinkability of any kind;
- browser/client fingerprint parity or indistinguishability from any real
  application traffic;
- active-probe deflection or decoy behavior;
- production readiness, Internet-scale performance, or multi-host robustness.

A passing Phantom One test establishes only the specific bounded behavior it
exercised, on the recorded host, at the recorded commit. Anything broader
requires the corresponding higher tier of evidence and an updated, dated
record — and several of the non-claims above are design-level: no test
result can convert them into claims.
