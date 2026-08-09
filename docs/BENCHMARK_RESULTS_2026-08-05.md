# SHPH Benchmark Results — 2026-08-05

## Executive Summary

This report records the first paired **WSL2/Linux and native Windows** release
benchmark campaign for workspace version `0.5.0-dev.0`.

- `secure-default` uses authenticated hybrid X25519 + ML-KEM-768.
- `classical-lab` is an explicit benchmark-only X25519 profile and is not a
  production fallback.
- Each profile used 5,000 latency samples and 100,000 sustained frames.
- The benchmark executable was built in release mode with Rust `1.96.0`.
- The raw captures are retained under:
  - `benchmark-runs/2026-08-05-wsl2-final/`
  - `benchmark-runs/2026-08-05-windows-final/`

These are local authenticated operation measurements. The data-plane rows are
in-memory AEAD goodput, not live VPN throughput through a TUN adapter. The QUIC
rows exercise the project’s UDP lab shim and are explicitly not standards-
compliant QUIC performance evidence.

## Build Identity

| Field | Value |
| --- | --- |
| Workspace version | `0.5.0-dev.0` |
| Git `HEAD` | `3fd2e44a81536fd4b90f7ca2881fcffbba5dca56` |
| Build profile | `release` |
| Rust | `rustc 1.96.0 (ac68faa20 2026-05-25)` |
| Latency samples | `5,000` |
| Sustained frames | `100,000` |
| Native TUN flag | `0` |
| Linux host | WSL2, Linux `5.15.167.4-microsoft-standard-WSL2` |
| Linux CPU | AMD Ryzen 7 7700X, 8 cores |
| Windows host | Windows `10.0.26200.0`, PowerShell `5.1.26100.8875` |
| Windows CPU metadata | AMD64 Family 25 Model 97 Stepping 2 |

The working tree was intentionally dirty during this engineering capture.
The commit above identifies the checked-out base; the raw files include the
benchmark metadata emitted by the executable.

## Validation Gates

### Linux / WSL2

- `cargo fmt --all -- --check`: pass
- `cargo clippy --workspace --all-targets --locked --offline -- -D warnings`:
  pass
- `cargo test --workspace --locked --offline`: 191 passed, 0 failed
- `git diff --check`: pass
- Native-TUN lifecycle probe: 20/20 pass

The WSL2 TUN lifecycle probe reported a minimum of `78.254 ms`, p50
`188.589 ms`, p95 `378.399 ms`, and maximum `418.121 ms`. It measures isolated
open/hold/close process cost only; it does not measure forwarding, RTT,
goodput, jitter, CPU saturation, or two-host behavior.

### Native Windows

- `cargo fmt --all -- --check`: pass
- `cargo check --workspace --locked`: pass
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: pass
- `cargo test --workspace --locked`: 176 passed, 0 failed
- `cargo build --workspace --release --locked`: pass
- Native benchmark executable build: pass
- PowerShell benchmark capture: pass

The root `Cargo.lock` is intentionally excluded from mirror synchronization.
The Windows-local lockfile was refreshed on the Windows host before the
locked gate run; this does not change the canonical Linux lockfile.

## Handshake and Local Latency

All values below are p50 unless another percentile is named.

| Platform | Profile | Full handshake | 1 KiB authenticated RTT p50 | RTT p99.9 |
| --- | --- | ---: | ---: | ---: |
| WSL2 | `secure-default` | 499.281 µs | 5.920 µs | 17.370 µs |
| WSL2 | `classical-lab` | 313.241 µs | 6.360 µs | 16.955 µs |
| Windows | `secure-default` | 613.500 µs | 6.100 µs | 10.200 µs |
| Windows | `classical-lab` | 394.400 µs | 6.100 µs | 10.700 µs |

The hybrid profile’s extra handshake cost is the ML-KEM exchange and
validation. It does not remove authentication: both profiles retain the
authenticated signing and key-derivation path.

## Data-Plane Goodput

Goodput is bidirectional in-memory AEAD payload rate. Wire rate includes the
local framing/AEAD overhead reported by the runner. Values are Mbps.

### WSL2

| Payload | `secure-default` goodput / wire | `classical-lab` goodput / wire |
| ---: | ---: | ---: |
| 1 KiB | 342.496 / 351.861 | 316.315 / 324.964 |
| 4 KiB | 725.696 / 730.657 | 659.062 / 663.567 |
| 1,400 B | 364.912 / 372.210 | 367.214 / 374.558 |
| 1,500 B | 397.668 / 405.091 | 351.614 / 358.178 |
| 64 KiB | 871.088 / 871.460 | 850.236 / 850.600 |

### Native Windows

| Payload | `secure-default` goodput / wire | `classical-lab` goodput / wire |
| ---: | ---: | ---: |
| 1 KiB | 332.813 / 341.914 | 331.296 / 340.355 |
| 4 KiB | 718.433 / 723.344 | 695.700 / 700.456 |
| 1,400 B | 387.620 / 395.373 | 386.051 / 393.772 |
| 1,500 B | 387.754 / 394.992 | 387.293 / 394.523 |
| 64 KiB | 746.211 / 746.530 | 753.445 / 753.767 |

These results are useful for regression comparison between profiles and
platforms. They must not be presented as TUN or Internet throughput.

## Shroud 2.0 Morphology

Rows measure target selection, padding, envelope encoding, and decoding for a
1,024-byte payload under a 1,450-byte path budget. Values are p50 / p95 /
p99 / p99.9 in nanoseconds.

### `secure-default`

| Morphology profile | WSL2 | Windows |
| --- | --- | --- |
| `low-latency` | 75 / 128 / 149 / 171 | 100 / 200 / 200 / 300 |
| `web-browsing-lab` | 86 / 1,231 / 1,273 / 1,702 | 200 / 400 / 400 / 700 |
| `video-streaming-lab` | 1,199 / 1,231 / 1,295 / 2,419 | 300 / 400 / 400 / 700 |
| `bulk-lab` | 1,209 / 1,252 / 1,455 / 2,440 | 300 / 400 / 400 / 600 |

### `classical-lab`

| Morphology profile | WSL2 | Windows |
| --- | --- | --- |
| `low-latency` | 70 / 110 / 130 / 140 | 100 / 200 / 200 / 300 |
| `web-browsing-lab` | 80 / 1,140 / 1,190 / 2,280 | 100 / 400 / 400 / 600 |
| `video-streaming-lab` | 1,140 / 1,170 / 1,400 / 2,310 | 300 / 400 / 400 / 700 |
| `bulk-lab` | 1,140 / 1,180 / 1,400 / 2,390 | 300 / 400 / 400 / 600 |

The Windows sub-microsecond rows are quantized by the platform timer and
should be interpreted as bounded-cost buckets, not exact zero-nanosecond
operations.

## Long Sessions and Allocation Pressure

The long-session row performs 100,000 local Shroud 2.0 encode/decode frames.
It preserves the payload and records allocator counters. RSS is available from
`/proc` on WSL2; the current standalone Windows runner leaves RSS and CPU
fields unavailable rather than fabricating values.

| Platform | Profile | Goodput Mbps | Wire Mbps | Alloc calls | Allocated bytes | RSS / peak RSS |
| --- | --- | ---: | ---: | ---: | ---: | --- |
| WSL2 | `secure-default` | 2,164.767 | 2,461.992 | 200,014 | 218,867,747 | 3,428 / 6,016 KiB |
| WSL2 | `classical-lab` | 2,302.583 | 2,618.730 | 200,014 | 218,867,747 | 3,492 / 6,080 KiB |
| Windows | `secure-default` | 5,284.643 | 6,010.230 | 200,004 | 218,859,787 | unavailable |
| Windows | `classical-lab` | 5,186.412 | 5,898.511 | 200,004 | 218,859,787 | unavailable |

The intended morphology delay accumulated by the local model is not slept in
this benchmark. These are processing and allocation results, not elapsed
wall-clock session duration.

## QUIC-Shim and Replay Measurements

The UDP loopback handshake uses the authenticated project lab shim. It is not
an RFC 9000 interoperability test.

| Platform | Profile | Shim handshake p50 | Reorder p50 / p99 | Loss-tolerance p50 / p99 |
| --- | --- | ---: | ---: | ---: |
| WSL2 | `secure-default` | 835.756 µs | 1.896 / 2.112 µs | 954 / 1.062 µs |
| WSL2 | `classical-lab` | 543.537 µs | 1.753 / 1.944 µs | 887 / 967 ns |
| Windows | `secure-default` | 911.300 µs | 2.000 / 2.100 µs | 1.000 / 1.100 µs |
| Windows | `classical-lab` | 660.700 µs | 2.000 / 2.500 µs | 1.000 / 1.300 µs |

The deterministic per-IP limiter probe accepted `8` attempts and rejected
`4,993` excess attempts in each profile. The local replay-window insertion
path remained bounded; Windows reports sub-microsecond samples in coarse
100-nanosecond timer buckets.

## Interpretation

- Native Windows local execution is now verified for the benchmark executable
  and the full workspace gates.
- The hybrid profile costs more during handshake, as expected, while steady
  state remains in the same broad local-goodput range as the classical lab
  profile.
- Shroud 2.0 morphology overhead is bounded and profile-dependent; larger
  profiles spend more time writing and validating padding.
- The Windows and WSL2 results are not directly interchangeable because their
  schedulers, timers, allocators, and host environments differ.
- No result here proves native Linux two-host throughput, Windows Wintun packet
  I/O, route/DNS mutation, reconnect recovery over a real network, Internet
  jitter, or QUIC interoperability.

## Remaining Host-Level Work

1. Native Linux two-host TUN throughput, goodput, RTT, jitter, CPU, and RSS.
2. Native Windows elevated Wintun adapter creation, packet I/O, teardown,
   route/DNS behavior, and two-host throughput.
3. Controlled `tc netem` or equivalent loss/reordering/congestion tests for
   standards-QUIC.
4. Windows process CPU/RSS instrumentation in the standalone benchmark runner.

The raw CSVs are the source for numerical review; this report is the
human-readable summary.
