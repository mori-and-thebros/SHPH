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

## Planned Measurements

1. Crypto primitives: AEAD, X25519, ML-KEM-768, HKDF, and key generation.
2. Handshake phases: serialization, classical exchange, PQ exchange, and full
   authenticated setup.
3. Data plane: throughput and p50/p95/p99 latency by payload size.
4. Framing: Shroud-cell encode/decode, padding, and replay-window operations.
5. Adapters: TCP, QUIC-like lab shim, offline-mesh, and data-mule separately.
6. Resource behavior: allocations, memory growth, CPU saturation, and variance.

## Planned Profiles

| Profile | Intended use | Security status |
| --- | --- | --- |
| `secure-default` | Normal operation and production baseline | Default; hybrid X25519 + ML-KEM-768 |
| `classical-lab` | Measure X25519 without ML-KEM overhead | Explicit benchmark-only profile |
| `framing-lab` | Measure cell/padding overhead | Authentication and AEAD retained |
| `transport-lab` | Isolate adapter costs | No cryptographic downgrade implied |

`classical-lab` must not be implemented as an unnoticed fallback. Both peers
must explicitly select it, its protocol identity must be distinct, and
`secure-default` peers must reject it.

The profile implementation lives in `shph-core/src/handshake.rs` and
`shph-transport/src/lib.rs`. The standalone runner is outside the production
workspace under `benchmarks/`, so benchmark dependencies and output do not
alter the shipped binary workspace.

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
handshakes, framing, AEAD, and replay-window operations. Results should be
copied into reviewed evidence, not committed as raw build artifacts.

`classical-lab` is a classical X25519 measurement only. It is not a production
fallback and must never be presented as equivalent to the hybrid profile.
