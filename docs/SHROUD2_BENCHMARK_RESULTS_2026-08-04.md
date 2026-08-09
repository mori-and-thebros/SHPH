# Shroud 2.0 Morphology Benchmark Results

## Build identity

| Field | Value |
| --- | --- |
| Workspace version | `0.5.0-dev.0` |
| Commit | `3fd2e44a81536fd4b90f7ca2881fcffbba5dca56` |
| Platform | WSL2 (`platform=wsl2`) |
| Rust | `rustc 1.96.0 (ac68faa20 2026-05-25)` |
| CPU | AMD Ryzen 7 7700X 8-Core Processor |
| Path budget | 1,450 bytes |
| Payload | 1,024 bytes |
| Samples | 5,000 |
| Build | `release` |
| Native TUN | Disabled |

Command:

```bash
cargo run --manifest-path benchmarks/Cargo.toml --release --offline -- \
  --profile secure-default --suite shroud --iterations 5000 --frames 100000
```

## Morphology results

The measured operation includes seeded target-size selection, randomized
padding, envelope encoding, and decoding. It does not include QUIC socket
transmission, congestion, network scheduling, or the profile's optional delay
sleep.

| Profile | p50 | p95 | p99 | p99.9 | Mean | Target range | Alloc calls |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `low-latency` | 90 ns | 131 ns | 150 ns | 161 ns | 89 ns | 1,031–1,031 B | 10,015 |
| `web-browsing-lab` | 91 ns | 1,337 ns | 1,387 ns | 2,080 ns | 495 ns | 1,031–1,450 B | 10,015 |
| `video-streaming-lab` | 1,336 ns | 1,377 ns | 1,447 ns | 7,948 ns | 1,032 ns | 1,031–1,450 B | 10,015 |
| `bulk-lab` | 1,337 ns | 1,396 ns | 1,487 ns | 2,783 ns | 1,282 ns | 1,280–1,450 B | 10,015 |

The low-latency profile remains at the minimum required size for this payload,
while the larger profiles exercise multiple size classes before the 1,450-byte
budget clamps them. This is expected behavior, not evidence of browser-traffic
similarity.

## Delay distribution

These rows sample `MorphologyEngine::next_delay()` without sleeping. They
validate the configured distribution bounds, not scheduler or network timing.

| Profile | p50 | p95 | p99.9 | Mean | Observed range |
| --- | ---: | ---: | ---: | ---: | ---: |
| `low-latency` | 245.957 µs | 475.574 µs | 499.663 µs | 248.073 µs | 78 ns–499.838 µs |
| `web-browsing-lab` | 3.987 ms | 7.609 ms | 7.993 ms | 4.015 ms | 101.236 µs–7.997 ms |
| `video-streaming-lab` | 1.507 ms | 2.849 ms | 2.998 ms | 1.516 ms | 52.102 µs–2.999 ms |
| `bulk-lab` | 370.318 µs | 711.407 µs | 749.179 µs | 371.706 µs | 117 ns–749.707 µs |

## Long-session morphology

The 100,000-frame local encode/decode run used the `web-browsing-lab` profile
with a 1,024-byte payload:

| Goodput | Wire rate | Allocations | Allocated bytes | RSS | Peak RSS |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 2,313.754 Mbps | 2,631.435 Mbps | 200,014 | 218,867,747 B | 3,344 KiB | 3,452 KiB |

The run preserved every local frame and accumulated approximately 404.1 seconds
of *intended* delay without sleeping. This is an allocation/RSS and payload
preservation test, not a wall-clock session-duration result.

## Deterministic impairment stress

The local emulator used an eight-entry queue, intentionally injected loss every
17th frame, and drained in bursts. For 100,000 generated frames it recorded:

| Injected loss | Queue drops | Reordered | Delivered | Decode failures |
| ---: | ---: | ---: | ---: | ---: |
| 5,883 | 94,109 | 1 | 8 | 0 |

This confirms bounded queue behavior and fail-closed decoding under pressure.
It does **not** measure QUIC congestion control, retransmission, Internet loss
recovery, or packet scheduling. Those require a real QUIC connection under a
network emulator such as `tc netem`.

## Interpretation

- The envelope is inexpensive in this local run: p50 is below 1.4 microseconds
  for all profiles.
- Larger morphology profiles cost more CPU and allocation bandwidth because
  they write and validate more padding.
- The results validate bounds, payload preservation, and profile separation.
- They do not establish network throughput, RTT, jitter, packet-loss behavior,
  QUIC interoperability, or anti-DPI effectiveness.

## Remaining benchmark work

The highest-value follow-ups are:

1. Native Linux two-host standards-QUIC measurements.
2. Datagram loss/reordering and congestion measurements over a controlled
   network emulator.
3. End-to-end send timing with the delay path enabled.
4. Native TUN throughput and latency after the deferred TUN phase.

Keep WSL2, native Linux, Windows, and two-host results in separate tables.

## Post-hardening validation rerun

On August 4, 2026, the Shroud suite was rerun after the transport-boundary
hardening changes. This shorter release-mode run used 2,000 latency samples
and 20,000 sustained frames, so it is a validation rerun rather than a
replacement for the 5,000/100,000 evidence above.

| Profile | Morphology p50 | Morphology p99 | Target range |
| --- | ---: | ---: | ---: |
| `low-latency` | 70 ns | 140 ns | 1,031–1,031 B |
| `web-browsing-lab` | 80 ns | 1,172 ns | 1,031–1,450 B |
| `video-streaming-lab` | 1,112 ns | 1,452 ns | 1,031–1,450 B |
| `bulk-lab` | 1,131 ns | 1,431 ns | 1,280–1,450 B |

The `web-browsing-lab` long-session row measured 2,262.204 Mbps goodput and
2,570.407 Mbps wire rate in the local encode/decode path, with 2,912 KiB RSS
and peak RSS. The deterministic impairment row recorded 1,177 injected
losses, 18,815 queue drops, one reorder, eight delivered frames, and zero
decode failures. These values remain local emulator evidence, not network
performance claims.
