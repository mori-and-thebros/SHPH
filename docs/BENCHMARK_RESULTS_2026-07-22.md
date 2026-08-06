# SHPH Benchmark Results

This report records the reproducible benchmark evidence available for SHPH on
**July 22, 2026**. It complements `docs/BENCHMARKING.md`, which defines the
methodology and the required native-Linux and two-host follow-up work.

## Build Identity

| Field | Value |
| --- | --- |
| Workspace version | `0.5.0-dev.0` |
| Benchmark package | `shph-benchmarks 0.5.0-dev.0` |
| Git commit | `6a6104b7b7fb688579ff67c76df38ca341a81eeb` |
| Git state | Dirty checkout; benchmark capture did not include unrelated working-tree changes |
| Profile | `secure-default` |
| Build profile | `release` |
| Platform | WSL2 (`platform=wsl2`) |
| Kernel | `Linux 5.15.167.4-microsoft-standard-WSL2 #1 SMP Tue Nov 5 00:21:55 UTC 2024 x86_64` |
| CPU | AMD Ryzen 7 7700X 8-Core Processor |
| Rust | `rustc 1.96.0 (ac68faa20 2026-05-25)` |
| Clock | `std::time::Instant` |
| Latency samples | `1,000` |
| Sustained/load frames | `10,000` |
| Native TUN | Disabled (`SHPH_TUN_NATIVE=0`) |

The raw runner capture was generated locally for this report. Build artifacts
and benchmark captures are intentionally not part of the source-tracked
mirror; rerun the command in the reproduction section to regenerate them.

## Score Summary

### Core latency

| Measurement | Scenario | Payload | p50 | p95 | p99 | p99.9 | Mean | Notes |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Full handshake | `full_handshake` | - | 372,193 ns | 432,672 ns | 585,159 ns | 648,888 ns | 381,776 ns | In-memory authenticated setup |
| RTT under load | `rtt_under_load_1k` | 1 KiB | 5,850 ns | 5,910 ns | 6,510 ns | 25,689 ns | 5,974 ns | In-memory bidirectional echo; p99.9 is jitter tail |
| Replay insertion | `replay_window_long_session` | - | 30 ns | 30 ns | 30 ns | 30 ns | 27 ns | Nonce-window state transition |

### Data-plane goodput

These are in-memory AEAD measurements, not socket, TUN, or Internet VPN
throughput. `wire_mbps` includes the measured framing overhead.

| Payload | Goodput | Wire rate | CPU | Elapsed | Notes |
| ---: | ---: | ---: | ---: | ---: | --- |
| 1 KiB | 341.864 Mbps | 351.211 Mbps | 99.96% | 59 ms | Bidirectional in-memory AEAD |
| 4 KiB | 717.614 Mbps | 722.520 Mbps | 99.98% | 114 ms | Bidirectional in-memory AEAD |
| 1,400 B | 395.728 Mbps | 403.642 Mbps | 99.94% | 70 ms | MTU-oriented payload |
| 1,500 B | 399.772 Mbps | 407.234 Mbps | 99.96% | 75 ms | MTU-oriented payload |
| 64 KiB | 899.054 Mbps | 899.438 Mbps | 99.59% | 1,457 ms | Bidirectional in-memory AEAD |

### Resource and allocation observations

| Measurement | Elapsed | CPU | Allocations | Allocated bytes | RSS | Peak RSS | Notes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| Resource idle | 0 ms | 2.72% | 15 | 8,129 B | 3,024 KiB | 3,180 KiB | Process-level snapshot; not sustained saturation |
| Full handshake | 382 ms | 99.99% | 92,014 | 41,477,128 B | 2,508 KiB | 2,512 KiB | Includes hybrid setup and key derivation |
| RTT under load | 60 ms | 99.93% | 60,014 | 62,648,128 B | 3,064 KiB | 3,064 KiB | Includes the load-loop allocations |

The runner reports process-level RSS and allocator counts. These values are
useful for regression comparisons, but are not a complete long-lived daemon
memory profile.

### Shroud cell profiles

| Profile | Payload | p50 | p95 | p99 | p99.9 | Mean | Cell capacity | Reported padding overhead |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `balanced` | 256 B | 60 ns | 71 ns | 81 ns | 101 ns | 63 ns | 1,024 B | 300% |
| `low-latency` | 256 B | 61 ns | 90 ns | 101 ns | 302 ns | 78 ns | 512 B | 100% |
| `bulk` | 256 B | 101 ns | 131 ns | 131 ns | 141 ns | 106 ns | 4,096 B | 1,500% |
| `randomized-lab` | 256 B | 61 ns | 90 ns | 100 ns | 101 ns | 67 ns | 1,024 B | 300% |

`randomized-lab` is an explicitly labeled lab experiment. The runner notes
that randomized padding itself is not modeled in this measurement.

#### Phase C follow-up

After the Phase C framing-boundary and canonical-padding fixes, a dedicated
5,000-sample WSL2 run produced:

| Profile | Payload | p50 | p95 | p99 | p99.9 | Mean | Cell capacity | Reported padding overhead |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `balanced` | 256 B | 200 ns | 210 ns | 210 ns | 400 ns | 202 ns | 1,024 B | 300% |
| `low-latency` | 256 B | 130 ns | 170 ns | 180 ns | 220 ns | 130 ns | 512 B | 100% |
| `bulk` | 256 B | 830 ns | 840 ns | 1,420 ns | 14,610 ns | 855 ns | 4,096 B | 1,500% |
| `randomized-lab` | 256 B | 210 ns | 220 ns | 220 ns | 400 ns | 213 ns | 1,024 B | 300% |

This follow-up measures core encode/decode only, not authenticated UDP
transport, and should be compared only with runs using the same runner and
environment.

#### Final intensity-aware rerun

After adding the explicit `off`/`low`/`medium`/`high`/`extreme-lab` selection
aliases and the `extreme-lab` profile, the final 5,000-sample WSL2 Shroud
capture produced the following diagnostic layers:

| Profile | Framing p50 | Framing p99.9 | AEAD p50 | AEAD p99.9 | Combined p50 | Combined p99.9 | Cell | Overhead |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| `balanced` | 330 ns | 600 ns | 3,280 ns | 13,150 ns | 70 ns | 130 ns | 1,024 B | 300% |
| `low-latency` | 140 ns | 280 ns | 2,850 ns | 11,731 ns | 60 ns | 70 ns | 512 B | 100% |
| `bulk` | 1,530 ns | 8,950 ns | 6,850 ns | 19,081 ns | 910 ns | 2,580 ns | 4,096 B | 1,500% |
| `randomized-lab` | 320 ns | 1,160 ns | 3,290 ns | 12,900 ns | 70 ns | 140 ns | 1,024 B | 300% |
| `extreme-lab` | 3,070 ns | 12,360 ns | 10,831 ns | 27,871 ns | 1,740 ns | 9,571 ns | 8,192 B | 3,100% |

`shroud_framing` measures raw cell encode/decode, `shroud_aead` measures
fixed-cell AEAD encrypt/decrypt, and `shroud_profile` measures the combined
raw-cell path. The `extreme-lab` row is intentionally expensive and remains a
lab experiment, not a production recommendation.

### QUIC-like lab shim

The UDP adapter below is a local lab shim and is **not standards-compliant
QUIC**. These measurements do not claim congestion control, Internet loss
recovery, or production QUIC interoperability.

| Measurement | Scenario | p50 | p95 | p99 | p99.9 | Mean | Notes |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| Shim handshake | `quic_shim_loopback_handshake` | 469,365 ns | 594,206 ns | 753,797 ns | 1,061,349,554 ns | 2,626,460 ns | UDP loopback; no loss injection |
| Reordering | `quic_shim_reordering` | 1,748 ns | 1,909 ns | 2,019 ns | 3,506 ns | 1,794 ns | Authenticated in-memory reordering |
| Loss tolerance | `quic_shim_loss_tolerance` | 894 ns | 974 ns | 1,015 ns | 1,547 ns | 902 ns | One missing frame; later nonce accepted |
| Rate limiting | `quic_shim_rate_limit` | - | - | - | - | - | 8 accepted, 993 rejected; per-IP probe |

The unusually large shim-handshake p99.9 is retained exactly as emitted. It is
an outlier-sensitive local measurement and should be rerun before drawing a
performance conclusion.

### Long-session scalability

| Scenario | Frames | Payload | Goodput | CPU | Allocations | Allocated bytes | Notes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| `long_session` | 10,000 | 64 B | 28.648 Mbps | 98.89% | 30,014 | 2,528,128 B | Single-key nonce and replay path |

The runner itself recommends `--frames 1000000` for million-frame evidence;
that larger run is not included in this report.

## Final Full-Suite Rerun

The final full-suite WSL2 run used `secure-default`, 1,000 latency samples,
and 10,000 load frames. Key rows were:

| Measurement | p50 | p95 | p99 | p99.9 | Mean | Result |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Full handshake | 366,537 ns | 397,967 ns | 437,548 ns | 522,400 ns | 370,928 ns | Pass |
| RTT under load, 1 KiB | 5,870 ns | 6,100 ns | 6,440 ns | 15,861 ns | 5,938 ns | Pass |
| Replay insertion | 30 ns | 30 ns | 40 ns | 110 ns | 28 ns | Pass |
| In-memory goodput, 1 KiB | - | - | - | - | - | 339.867 Mbps |
| In-memory goodput, 4 KiB | - | - | - | - | - | 727.105 Mbps |
| In-memory goodput, 64 KiB | - | - | - | - | - | 881.442 Mbps |
| QUIC-shim reordering | 1,751 ns | 1,771 ns | 1,791 ns | 14,657 ns | 1,788 ns | Pass |
| QUIC-shim loss tolerance | 890 ns | 900 ns | 910 ns | 14,297 ns | 926 ns | Pass |
| QUIC-shim rate limiter | - | - | - | - | - | 8 accepted, 993 rejected |

The full run also included the complete intensity-aware Shroud matrix above.
As before, these are WSL2 local measurements and not native-TUN or two-host
VPN scores.

## Previously Recorded Smoke Baseline

The benchmark plan also contains an earlier July 22, 2026 WSL2 smoke capture:

| Measurement | Samples | p50 | p99 | Result |
| --- | ---: | ---: | ---: | --- |
| `quic_shim_reordering` | 32 | 1,749 ns | 1,779 ns | Pass |
| `quic_shim_loss_tolerance` | 32 | 880 ns | 910 ns | Pass |
| `quic_shim_rate_limit` | 33 probes | - | - | 8 accepted, 25 rejected |

The newer 1,000-sample results above supersede this smoke run for trend
comparisons, while the smoke values remain useful as historical evidence.

## Not Yet Scored

The following require operator-controlled processes, privileges, a second
host, or a native Linux environment and therefore have no honest numeric score
in this report:

- Native Linux TUN versus non-TUN throughput and goodput.
- Two-machine tunnel throughput, real RTT, jitter, and p99.9.
- CPU and RSS during live tunnel saturation.
- Reconnect recovery time and reconnect backoff overhead.
- Route/DNS apply and reconcile timing on an isolated control-plane setup.
- Real datagram loss, reordering, and rate-limiter network behavior.
- Full startup timing including keystore load and live handshake.
- Graceful shutdown timing for a live session.
- Million-frame replay-window and nonce-counter evidence.
- `classical-lab` comparative scores.

Use `scripts/benchmark_operator.sh` for the lifecycle, control-plane,
reconnect, and native-TUN prerequisites. Keep native Linux, WSL2, Windows,
containers, VMs, and two-host results in separate tables.

## Reproduction

From the Linux checkout:

```bash
source "$HOME/.cargo/env"
cargo run --manifest-path benchmarks/Cargo.toml --release -- \
  --profile secure-default --suite all --iterations 1000 --frames 10000
```

For a higher-confidence local run:

```bash
cargo run --manifest-path benchmarks/Cargo.toml --release -- \
  --profile secure-default --suite all --iterations 10000 --frames 100000
```

For a million-frame scalability run:

```bash
cargo run --manifest-path benchmarks/Cargo.toml --release -- \
  --profile secure-default --suite scalability --iterations 1000 --frames 1000000
```

Never present these WSL2 local results as native-Linux or real VPN
throughput. See `docs/BENCHMARKING.md` for the full methodology and
environment-control requirements.
