# Shroud 2.0 Lab Implementation

## Scope

The `SHROUD2.0_RESEARCH_SPEC.txt` research document was reviewed against the current
SHPH transport architecture on August 4, 2026. SHPH implements the safe,
measurable subset as an opt-in lab API under
`shph-transport/src/shroud2/`.

This work does not modify `shph-core/src/crypto.rs`,
`shph-core/src/keystore.rs`, or the cryptographic handshake. The separate
Linux standards-QUIC integration connects the authenticated QUIC DATAGRAM path
to native TUN, but does not turn morphology into a stealth or fallback router.

## Implemented

- Explicit morphology profiles for low-latency, web-browsing, video-streaming,
  and bulk lab comparisons.
- Seeded morphology selection for deterministic tests and reproducible
  benchmarks.
- Negotiated QUIC DATAGRAM limit enforcement.
- Bounded target-size selection that never shrinks below the payload.
- Versioned envelope with declared total length and payload length.
- Random authenticated-transport padding after the payload.
- Bounded inter-datagram delay; the delay is not an unbounded sleep or retry
  loop.
- Offline empirical-histogram construction, normalized sampling, and exact
  one-dimensional Wasserstein-1 measurement primitives for reviewed lab data.
- Standards-QUIC send/receive helpers using Quinn RFC 9221 DATAGRAM support.
- Unit, loopback, negative, and fuzz-manifest coverage.

The envelope is expected to be carried inside the authenticated QUIC
connection. It is not an authentication mechanism and must not be treated as
one.

## Technical Hardening Deep Dive

### Invariants enforced at the morphology boundary

- The negotiated QUIC DATAGRAM limit is the authoritative path bound; local
  Ethernet or interface MTU guesses are not accepted as substitutes.
- The fixed envelope header is seven bytes. Its declared total size must equal
  the received datagram length, and its payload length must leave enough bytes
  inside that datagram.
- Empty payloads, zero-sized or oversized path limits, target sizes below the
  payload plus header, and payloads that cannot fit the two-byte length field
  fail closed.
- Padding is generated with `OsRng::try_fill_bytes`; randomness failure returns
  an error instead of panicking or silently emitting predictable padding.
- Every profile has bounded size classes and bounded delay ranges. The engine
  has no retry loop, unbounded allocation policy, or unbounded sleep.

### QUIC lifecycle and resource bounds

- Reliable control messages are length-prefixed and capped before allocation.
- Handshake reads use the same bounded framing path as application control
  messages, including the ML-KEM ciphertext size limit.
- QUIC DATAGRAM sends validate the negotiated peer maximum before copying the
  payload into a `Bytes` buffer.
- Datagram and stream concurrency, receive/send buffers, incoming connections,
  and idle timeout are bounded by `StandardsQuicConfig` and Quinn limits.
- The standards path uses QUIC/TLS authentication for transport integrity; the
  morphology header is not trusted until it has crossed that authenticated
  boundary.

### Review findings addressed in this pass

- Rejected zero and sub-second idle timeouts, matching the documented
  one-second lower bound and preventing accidental ultra-short session churn.
- Added regression tests for inconsistent declared envelope sizes and
  impossible payload lengths.
- Kept padding randomness failure fallible and covered path-MTU rejection
  behavior.
- Kept empirical distribution tooling offline and bounded: it accepts only
  finite, ordered bins with non-negative weights and never parses untrusted
  PCAP data inside the transport path.

### Residual risks and measurement limits

- QUIC DATAGRAM loss is expected. Applications that require delivery must use
  the reliable control stream or implement an explicit authenticated
  application-level recovery protocol.
- The morphology profile is not cryptographic padding negotiation. Both peers
  must agree out of band on how to interpret the envelope, and the receiver
  currently validates the envelope rather than enforcing a profile identifier.
- Loopback and in-memory benchmark values do not represent Internet RTT,
  congestion-control behavior, packet loss recovery, CPU saturation on two
  hosts, TUN throughput, or traffic-analysis resistance.
- A successful fuzz smoke run demonstrates only that the exercised harness did
  not crash during that run; it is not a proof of protocol correctness or
  stealth.

## Deliberately Not Implemented

### Browser or JA4 fingerprint forgery

SHPH does not add `craftls`, hard-coded browser fingerprints, ClientHello
extension-order forgery, or OS/TCP fingerprint claims. Quinn/rustls remains the
standards implementation. A static browser fingerprint would age badly and
could create cross-layer inconsistencies rather than provide a reliable
security property.

An optional passive JA4-compatible observability plugin exists for the
standards-QUIC server path. It records bounded metadata from the real
ClientHello for diagnostics and lab analysis; it does not spoof the client,
change the handshake, or provide a stealth property. Because the public rustls
resolver hook does not expose every extension and its wire order, live records
are explicitly partial rather than exact JA4. See
`docs/JA4_OBSERVABILITY.md`.

### Active-probe decoy routing

SHPH does not add a transparent reverse proxy, SNI-triggered decoy routing, or
unauthenticated fallback to a local HTTP/3 service. Those features would
change the threat model, expose an additional forwarding surface, and could
turn invalid protocol input into unexpected local service access. Invalid SHPH
application handshakes remain fail-closed.

### Statistical mimicry claims

The profiles are controlled morphology experiments, not browser or multimedia
traffic replicas. Real fidelity requires reviewed PCAP datasets, a declared
distance metric, and repeatable capture methodology. No Wasserstein threshold
or anti-DPI guarantee is claimed by the implementation.

## Verification

Focused commands:

```text
cargo test -p shph-transport shroud2 --lib
cargo test -p shph-transport standards_quic::tests
cargo check --manifest-path fuzz/Cargo.toml --offline
```

Benchmark command:

```text
cargo run --manifest-path benchmarks/Cargo.toml --release --offline -- \
  --profile secure-default --suite shroud --iterations 5000 --frames 100000
```

The benchmark emits `shroud2_morphology` rows for all four morphology
profiles. Each row includes p50/p95/p99/p99.9 latency, allocation/RSS
observations, and the observed target-size range under a 1,450-byte datagram
budget. The current workspace version is `0.5.0-dev.0`; benchmark reports must
also record the exact commit, platform, toolchain, and whether the run is
native Linux or WSL2.

The captured WSL2 results are recorded in
`docs/SHROUD2_BENCHMARK_RESULTS_2026-08-04.md`.

The fuzz target is:

```text
cd fuzz
cargo fuzz run shroud2_datagram -- -max_total_time=60
```

Long fuzz campaigns and PCAP fidelity experiments are separate lab work. A
successful smoke run does not establish production safety or stealth.
