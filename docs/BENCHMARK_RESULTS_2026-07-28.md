# SHPH Benchmark Results

This report records reproducible benchmark evidence captured on **July 28,
2026**. It complements `docs/BENCHMARKING.md`, which defines the methodology
and the native-Linux and two-host follow-up work.

## Build Identity

| Field | Value |
| --- | --- |
| Workspace version | `0.5.0-dev.0` |
| Benchmark package | `shph-benchmarks 0.5.0-dev.0` |
| Git commit | `6a6104b7b7fb688579ff67c76df38ca341a81eeb` |
| Git state | Dirty checkout; research capture, not a release-tag measurement |
| Profile | `secure-default` |
| Build profile | `release` |
| Platform | WSL2 (`platform=wsl2`) |
| Kernel | `Linux 5.15.167.4-microsoft-standard-WSL2 #1 SMP Tue Nov 5 00:21:55 UTC 2024 x86_64` |
| CPU | AMD Ryzen 7 7700X 8-Core Processor |
| Rust | `rustc 1.96.0 (ac68faa20 2026-05-25)` |
| Clock | `std::time::Instant` |
| Latency samples | `5,000` |
| Sustained/load frames | `1,000,000` |
| Native TUN | Disabled (`SHPH_TUN_NATIVE=0`) |

The benchmark binary was rebuilt with `--locked`. The raw CSV capture remains
local and can be regenerated with the command in the reproduction section.

## Validation Gates

The checkout passed the validation sequence before this run:

| Gate | Result |
| --- | --- |
| `cargo fmt --all -- --check` | Pass |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | Pass |
| `cargo test --workspace --locked` | Pass; 146 reported test cases, 0 failures |
| `cargo build --workspace --locked` | Pass |
| Benchmark `cargo check` | Pass |
| Benchmark clippy | Pass |

The 146 figure includes test targets that report zero tests; all reported
failures were zero.

## Score Summary

### Core latency

| Measurement | Scenario | Payload | p50 | p95 | p99 | p99.9 | Mean | Notes |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Full handshake | `full_handshake` | - | 369,606 ns | 507,328 ns | 557,428 ns | 649,440 ns | 382,494 ns | In-memory authenticated setup |
| RTT under load | `rtt_under_load_1k` | 1 KiB | 6,298 ns | 6,828 ns | 7,868 ns | 18,142 ns | 6,406 ns | In-memory bidirectional echo |
| Replay insertion | `replay_window_long_session` | - | 32 ns | 32 ns | 32 ns | 64 ns | 31 ns | Million-frame nonce-window transition |

### Data-plane goodput

These are in-memory AEAD measurements, not socket, TUN, or Internet VPN
throughput. `wire_mbps` includes measured framing overhead.

| Payload | Goodput | Wire rate | CPU | Elapsed | Notes |
| ---: | ---: | ---: | ---: | ---: | --- |
| 1 KiB | 317.737 Mbps | 326.425 Mbps | 94.29% | 6,445 ms | Bidirectional in-memory AEAD |
| 4 KiB | 691.307 Mbps | 696.033 Mbps | 96.82% | 11,850 ms | Bidirectional in-memory AEAD |
| 1,400 B | 365.973 Mbps | 373.292 Mbps | 93.81% | 7,650 ms | MTU-oriented payload |
| 1,500 B | 375.217 Mbps | 382.221 Mbps | 95.82% | 7,995 ms | MTU-oriented payload |
| 64 KiB | 870.061 Mbps | 870.433 Mbps | 95.79% | 150,646 ms | Bidirectional in-memory AEAD |

### Resource and allocation observations

| Measurement | CPU | Allocations | Allocated bytes | RSS | Peak RSS | Notes |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Resource idle | 0.00% | 15 | 8,129 B | 3,120 KiB | 34,124 KiB | Process-level snapshot |
| Full handshake | 99.12% | 460,014 | 207,353,128 B | 2,600 KiB | 2,604 KiB | Hybrid setup and key derivation |
| RTT under load | 94.32% | 6,000,014 | 6,264,008,128 B | 18,496 KiB | 18,496 KiB | Million-frame load loop |

These are regression signals from process-level RSS and allocator counters,
not a complete long-lived daemon memory profile.

### Shroud cell profiles

The runner separates raw framing, fixed-cell AEAD, and the combined in-memory
cell path. The combined path is diagnostic and does not represent live-network
throughput.

| Profile | Framing p50 | Framing p99.9 | AEAD p50 | AEAD p99.9 | Combined p50 | Combined p99.9 | Cell | Overhead |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `balanced` | 359 ns | 1,167 ns | 3,319 ns | 12,082 ns | 70 ns | 100 ns | 1,024 B | 300% |
| `low-latency` | 139 ns | 309 ns | 2,871 ns | 11,604 ns | 60 ns | 80 ns | 512 B | 100% |
| `bulk` | 1,526 ns | 9,341 ns | 6,659 ns | 17,237 ns | 877 ns | 1,755 ns | 4,096 B | 1,500% |
| `randomized-lab` | 339 ns | 698 ns | 3,300 ns | 11,943 ns | 70 ns | 129 ns | 1,024 B | 300% |
| `extreme-lab` | 3,081 ns | 13,598 ns | 10,876 ns | 26,628 ns | 1,705 ns | 9,690 ns | 8,192 B | 3,100% |

Large-cell profiles intentionally trade bandwidth and CPU cost for lab
framing experiments. `extreme-lab` is not a production recommendation.

### QUIC-like lab shim

The UDP adapter is a local lab shim and is **not standards-compliant QUIC**.
These measurements do not claim congestion control, Internet loss recovery,
or production QUIC interoperability.

| Measurement | Scenario | p50 | p95 | p99 | p99.9 | Mean | Notes |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| Shim handshake | `quic_shim_loopback_handshake` | 470,972 ns | 626,859 ns | 746,439 ns | 1,069,200 ns | 1,330,571 ns | UDP loopback; no loss injection |
| Reordering | `quic_shim_reordering` | 1,928 ns | 1,961 ns | 2,383 ns | 10,693 ns | 1,971 ns | Authenticated in-memory reordering |
| Loss tolerance | `quic_shim_loss_tolerance` | 975 ns | 997 ns | 1,246 ns | 8,927 ns | 1,002 ns | One missing frame; later nonce accepted |
| Rate limiting | `quic_shim_rate_limit` | - | - | - | - | - | 8 accepted, 4,993 rejected; per-IP probe |

The shim-handshake p99.9 is sensitive to local scheduling and is not an
Internet latency claim.

### Long-session scalability

| Scenario | Frames | Payload | Goodput | CPU | Allocations | Allocated bytes | Notes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `long_session` | 1,000,000 | 64 B | 26.139 Mbps | 92.29% | 3,000,014 | 252,008,128 B | Single-key nonce and replay path |

This exercises the million-frame nonce/replay path but remains an in-memory
measurement and does not prove live-session reliability.

## Not Yet Scored

The following still require operator-controlled processes, privileges, a second
host, or native Linux:

- Native Linux TUN versus non-TUN throughput and goodput.
- Two-machine tunnel throughput, real RTT, jitter, and p99.9.
- CPU and RSS during live tunnel saturation.
- Reconnect recovery time and reconnect backoff overhead.
- Route/DNS apply and reconcile timing on an isolated control-plane setup.
- Real datagram loss, reordering, and rate-limiter network behavior.
- Full startup timing including keystore load and live handshake.
- Graceful shutdown timing for a live session.
- `classical-lab` comparative scores.

Use `scripts/benchmark_operator.sh` for lifecycle, control-plane, reconnect,
and native-TUN prerequisite/timing checks. Keep native Linux, WSL2, Windows,
containers, VMs, and two-host results in separate evidence tables.

## Reproduction

From the Linux checkout:

```bash
source "$HOME/.cargo/env"
cargo build --release --manifest-path benchmarks/Cargo.toml --locked
./benchmarks/target/release/shph-benchmarks \
  --profile secure-default --suite all --iterations 5000 --frames 1000000
```

Never present these WSL2 local results as native-Linux or real VPN
throughput. See `docs/BENCHMARKING.md` for the full methodology and
environment-control requirements.
