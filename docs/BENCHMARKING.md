# SHPH Benchmarking Plan

This document defines the Linux-first benchmark method and the explicit
handshake profiles used by the benchmark harness. Native operation remains
`secure-default`; benchmark-only classical operation requires an explicit
profile on both peers.

## Default Environment

The primary baseline is a **native Linux host**. Record:

- Distribution and kernel version
- CPU model, core count, and governor
- Rust toolchain and compiler version
- Repository commit and lockfile
- Build profile and relevant environment variables
- Whether the run is native Linux, WSL, containerized, or virtualized

Windows is a secondary validation platform. WSL measurements must not be mixed
with native Linux results.

## Measurements

1. Handshake latency: complete authenticated setup for each handshake profile.
2. Framing latency: encode/decode by payload size.
3. AEAD latency: encryption by payload size.
4. Replay latency: nonce-window insertion cost.
5. Adapter latency: TCP, QUIC-like lab shim, offline-mesh, and data-mule
   measured separately in later phases.
6. Throughput and resource behavior: allocations, memory growth, CPU
   saturation, variance, and sustained data-plane performance.

## Profiles and dimensions

| Profile | Intended use | Security status |
| --- | --- | --- |
| `secure-default` | Normal operation and production baseline | Default; hybrid X25519 + ML-KEM-768 |
| `classical-lab` | Measure X25519 without ML-KEM overhead | Explicit benchmark-only profile |
| `framing-lab` | Measurement dimension for cell/padding cost | Authentication and AEAD retained |
| `transport-lab` | Measurement dimension for adapter cost | No cryptographic downgrade implied |

`classical-lab` must not be implemented as an unnoticed fallback. Both peers
must explicitly select it, its protocol identity must be distinct, and
`secure-default` peers must reject it.

The profile implementation lives in `shph-core/src/handshake.rs` and
`shph-transport/src/lib.rs`. The standalone runner is outside the production
workspace under `benchmarks/`, so benchmark dependencies and output do not
alter the shipped binary workspace.

`secure-default` and `classical-lab` are protocol profiles. `framing-lab` and
`transport-lab` are benchmark dimensions and do not create additional
cryptographic negotiation modes.

## Output interpretation

The runner emits CSV rows with:

| Column | Meaning |
| --- | --- |
| `benchmark` | Operation being measured |
| `profile` | Handshake profile used for the run |
| `payload_bytes` | Payload size; `0` means not payload-sized |
| `iterations` | Number of timed samples |
| `min_ns` | Fastest observed sample |
| `p50_ns` | Median sample |
| `p95_ns` | 95th-percentile sample |
| `p99_ns` | 99th-percentile sample |
| `max_ns` | Slowest observed sample |
| `mean_ns` | Arithmetic mean |

The handshake row measures the full in-memory setup, including hello
construction, signatures, X25519, ML-KEM when enabled, and key derivation.
It does not measure socket transfer or network round-trip time. Framing and
AEAD rows cover payload sizes of 64, 256, 1024, and 4096 bytes; framing is
capped by the selected cell capacity.

For latency work, report at least p50 and p95, keep p99 when the sample count
supports it, and do not treat a single short smoke run as a stable estimate.
Use separate runs for each profile and payload size.

## Obstacles and Controls

- Stabilize CPU frequency, background load, and process affinity where
  possible.
- Run enough iterations to report variance, not only a single best result.
- Separate setup/key-generation costs from steady-state throughput.
- Use controlled loopback tests first, then multi-host network tests.
- Keep Linux, WSL, Windows, CI, and virtual-machine results in separate groups.
- Never compare classical-only and hybrid results without stating the security
  difference.
- Treat the QUIC-like adapter as a lab shim, not standards-compliant QUIC.

## Commands

Run from native Linux:

```bash
cargo run --manifest-path benchmarks/Cargo.toml --release -- --profile secure-default --iterations 100
cargo run --manifest-path benchmarks/Cargo.toml --release -- --profile classical-lab --iterations 100
```

The runner prints environment metadata followed by CSV rows for complete
handshakes, framing, AEAD, and replay-window operations. It records the
release build profile, timing clock, and an explicit note that these are local
operation latencies rather than network RTTs. Results should be copied into
reviewed evidence, not committed as raw build artifacts.

`classical-lab` is a classical X25519 measurement only. It is not a production
fallback and must never be presented as equivalent to the hybrid profile.
When run under WSL2, the runner labels the output `platform=wsl2`; those
results must remain separate from native-Linux evidence.

Recommended evidence table:

| Environment | Profile | Payload | Iterations | p50 | p95 | p99 | Notes |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| native Linux | secure-default | 1024 | 10000 | ... | ... | ... | clean host |
| native Linux | classical-lab | 1024 | 10000 | ... | ... | ... | benchmark-only |

Do not claim that `classical-lab` is “faster SHPH” without stating that it
removes ML-KEM and therefore provides a different security contract.

## Expanded benchmark coverage

The standalone runner now supports `--suite all|core|dataplane|resource|shroud|quic|scalability`, reports p50/p95/p99/p99.9 latency, bidirectional in-memory goodput/wire rate for 1 KiB, 4 KiB, 1400-byte, 1500-byte, and 64 KiB payloads, CPU, RSS/peak RSS, allocation pressure, Shroud profiles, QUIC-shim loopback handshake timing, and long-session replay/nonce behavior.

These are local measurements, not proof of live VPN throughput, TUN performance, network RTT, reconnect recovery, or control-plane cost. Use `scripts/benchmark_operator.sh` for real-process lifecycle, reconnect, control-plane, and native-TUN prerequisite/timing checks. It emits explicit `SKIP` records when a host, privilege, peer, or tool is unavailable.

Recommended commands:

```bash
cargo run --manifest-path benchmarks/Cargo.toml --release -- --suite all --iterations 10000 --frames 100000
scripts/benchmark_operator.sh --mode lifecycle --config /path/to/config.toml
scripts/benchmark_operator.sh --mode control-plane --config /path/to/config.toml
scripts/benchmark_operator.sh --mode reconnect --config /path/to/config.toml
SHPH_TUN_NATIVE=1 scripts/benchmark_operator.sh --mode tun --tun-native 1 --config /path/to/config.toml
```

For native Linux two-host evidence, run authenticated listener/connector configs with `SHPH_TUN_NATIVE=1`, generate traffic through the tunnel with `iperf3`/`ping`, capture CPU and RSS during saturation, record packet size/MTU, then repeat after a controlled disconnect. Keep native Linux, WSL2, Windows, containers, VMs, and two-host results in separate evidence tables. `randomized-lab` and the QUIC-like UDP shim remain lab experiments, not stealth or standards-compliant QUIC claims.

### Local QUIC impairment evidence

The `quic` suite also exercises deterministic local behavior:

- authenticated frame reordering within the replay window;
- one missing frame followed by a valid later frame; and
- the per-IP handshake rate-limit cap.

Example WSL2 smoke evidence from July 22, 2026:

```text
profile=secure-default platform=wsl2 iterations=32
quic_shim_reordering p50=1749ns p99=1779ns
quic_shim_loss_tolerance p50=880ns p99=910ns
quic_shim_rate_limit accepted=8 rejected=25
```

This is local crypto/replay and limiter evidence only. It does not represent
packet loss recovery over a real network, congestion behavior, or native TUN
throughput. The existing transport tests separately cover source binding and
authenticated reordering.
