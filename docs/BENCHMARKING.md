# SHPH Benchmarking Plan

This is a planning document. It does not enable new protocol modes or change
the current secure-default handshake.

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

## Planned Commands

The exact Criterion harness and command set will be added after this
methodology is reviewed. Results should be generated from a clean checkout and
stored as reviewed evidence, not raw build artifacts.
