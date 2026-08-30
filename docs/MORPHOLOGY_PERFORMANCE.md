# Morphology Performance and Tuning

Status: prototype engineering note, 2026-08-27.

This document describes the performance work around the Shroud 2 and
Phantom One morphology APIs. It is a tuning and measurement guide, not a
claim of browser fingerprint parity, DPI evasion, censorship resistance,
anonymity, or production readiness.

## Design goals

The implementation has two goals that must be evaluated together:

1. keep morphology bounded and reproducible enough to measure; and
2. avoid turning every application frame into a fresh allocation or an
   unbounded delay.

The stable SHPH security boundary remains the authenticated, hybrid
X25519 + ML-KEM-768 session. Morphology runs inside that boundary and does not
replace encryption, peer pinning, replay protection, or nonce management.

## Current performance paths

The transport-side hot paths now provide:

- `MorphologyEngine::encode_datagram_into`, which clears and reuses a
  caller-owned `Vec<u8>`;
- `PhantomOneEncoder::encode_into` and `encode_with_target_into`, which reuse an
  authenticated TCP inner-envelope buffer;
- `shph_obfuscation::apply_profile_into`, which lets stateless profile
  callers reuse the same bounded buffer as stateful padders;
- pre-sized Shroud 2.0 batch payload construction after a checked length pass;
- a TCP receive path that decrypts directly from the retained frame buffer
  instead of first allocating a temporary ciphertext copy; and
- best-effort `TCP_NODELAY` on SHPH TCP sockets and the owned edge relay. A
  socket-option failure is not treated as a security downgrade; the session
  remains standards TCP and the failure is recorded at debug level.

The reusable-buffer APIs are preferred for steady-state loops. The allocating
APIs remain available for one-shot callers and compatibility. On the receive
side, `decode_datagram_in_place` validates the complete envelope before moving
the payload to the front of an owned vector, then wipes the retired header and
padding bytes before truncation.

Reusable profile and TCP/QUIC transport buffers are also cleared on rejected
operations and scoped for zeroization after use, including the TCP sender's
validation, AEAD, write, and flush error paths. This is memory-lifetime
hygiene; it does not guarantee that no plaintext or ciphertext copies existed
in allocator, runtime, kernel, or cryptographic-library memory.

## Bounded adaptive morphology

`AdaptiveMorphologyEngine` is an explicit lab API over the existing tuned
profiles. It uses a session-local integer EWMA of payload length and
hysteresis:

| Transition | Default threshold |
| --- | ---: |
| tuned-low → tuned-web | 192-byte EWMA |
| tuned-web → tuned-low | 128-byte EWMA |
| tuned-web → tuned-video | 900-byte EWMA |
| tuned-video → tuned-web | 640-byte EWMA |
| tuned-video → tuned-bulk | 1,350-byte EWMA |
| tuned-bulk → tuned-video | 1,100-byte EWMA |

The EWMA uses a divisor of four. Profile changes are synchronous with the
next encode call, and the engine performs no background classification, timer,
retry loop, or hidden sleep. A caller may provide a different set of ordered
thresholds through `AdaptiveMorphologyConfig::new`; invalid hysteresis
ordering is rejected.

The engine keeps one session-scoped random generator for size-class selection
and tail padding. It does not reset randomness per frame and it does not
claim to model a browser, video codec, or particular network middlebox.

Adaptive morphology is not enabled by default in the CLI or release profile.
It is intended for controlled experiments where both sides agree on the
envelope and the operator records the selected thresholds.

## Instrumentation semantics

`MorphologyMetrics` reports when explicitly enabled with
`MorphologyEngine::enable_metrics()` or `with_metrics()`:

- encoded frame count;
- aggregate plaintext payload bytes;
- aggregate morphology-envelope wire bytes;
- aggregate `padding_bytes`, which includes the fixed seven-byte Shroud 2.0
  envelope header plus the random tail; and
- minimum and maximum observed wire lengths.

Counters are disabled by default so the normal transport path does not pay
for measurement bookkeeping. Calling `set_metrics_enabled(true)` enables
collection for subsequent frames; `reset_metrics()` clears the collected
values without changing the engine's profile or random stream.

`overhead_pct()` is therefore total morphology-envelope overhead relative to
the supplied plaintext payload. It is a local accounting value, not a
classifier score or an estimate of Internet traffic-analysis protection.

The standalone benchmark runner also records seeded distribution-stability
rows for the Shroud 2.0 profiles. Each row reports wire-size quantiles,
distinct-size count, entropy, and a first-half versus second-half comparison
including mean-size delta and a Wasserstein-style distance over the measured
wire-size samples. These values are intended to catch accidental per-frame
randomness resets, distribution drift, or unexpectedly large tails. They are
local encode/decode measurements and do not establish stability against a
network observer or any DPI classifier.

## Owned edge relay

The standalone `shph-edge` prototype remains separate from the application
workspace. Its relay fast path forwards opaque bytes with bounded buffers,
per-stream byte caps, idle timeouts, cancellation, connection limits, and
short-lived signed capabilities. The HTTP/2 and feature-gated HTTP/3 carriers
are TLS-required and owned-domain-only. HTTP/3 uses Quinn/rustls plus the
opt-in `h3`/`h3-quinn` stack; it remains experimental and has no live
two-host evidence in this report.

The benchmark runner includes an `edge_opaque_relay` row in the `all` and
`extended` suites. It measures only the in-memory opaque pipe over bounded
Tokio duplex streams. It does not include TLS, HTTP/2 framing, socket
congestion, TUN I/O, or a real network path.

## Measurement commands

From the repository root:

```text
cargo run --manifest-path benchmarks/Cargo.toml --release --locked -- \
  --suite shroud --iterations 1000 --frames 10000

cargo run --manifest-path benchmarks/Cargo.toml --release --locked -- \
  --suite extended --iterations 100 --frames 10000

cargo test --manifest-path shph-edge/Cargo.toml --locked
```

For Criterion:

```text
cargo bench --manifest-path benchmarks/Cargo.toml \
  --bench criterion --locked -- --noplot
```

Every capture must record the exact revision, date, host OS, target triple,
toolchain, lockfile, workload, path-MTU budget, morphology profile or
thresholds, sample count, and whether it is local, CI-hosted, native-host, or
two-host evidence.

## Tuning guidance

- Use `encode_datagram_into` or the Phantom One reusable-buffer API in long-lived
  loops.
- Prefer `decode_datagram_in_place` when a receive loop owns a mutable
  datagram buffer; malformed input is rejected before the buffer is modified.
- Keep `path_mtu` equal to the negotiated logical transport budget; do not
  infer it from an Ethernet or interface MTU.
- Use the tuned web/video profiles only for the payload distributions they
  were designed to measure. Near-MTU video results must not be generalized to
  small control packets.
- Do not batch independent native-TUN IP packets. A lost unreliable datagram
  would lose every message in that batch.
- Keep adaptive thresholds and profile changes in the evidence record.
- Compare distributions, overhead, allocations, and p50/p95 latency across
  repeated captures. Do not select only favorable samples.

## Explicit non-claims

These optimizations do not establish:

- outer TLS or QUIC fingerprint parity;
- resistance to active probing or a particular DPI implementation;
- censorship bypass, anonymity, or an anonymity set;
- production VPN throughput, Internet RTT, or long-duration uptime; or
- security assurance beyond the exercised code paths and recorded evidence.
