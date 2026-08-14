# SHPH Benchmark Results — 2026-08-14

## Executive Summary

This report records a fresh Windows-local full-suite benchmark capture for
workspace version `0.6.1-dev`, commit
`ec66212129bdec5d0812777774a6c3b9398e053f`.

- Profiles: `secure-default` and explicit benchmark-only `classical-lab`.
- Latency samples: `5,000` per timed row.
- Sustained/load frames: `100,000`.
- Build: release profile, Rust `1.96.0`, target `x86_64-pc-windows-gnu`.
- Raw captures: ignored local files under
  `benchmark-runs/windows-2026-08-14-0.6.1-dev/`.

These are local authenticated-operation measurements. Native TUN was disabled,
so the data-plane rows are in-memory AEAD measurements rather than Wintun,
socket, route/DNS, or two-host VPN throughput. The QUIC rows exercise SHPH's
UDP lab shim and are not standards-compliant QUIC interoperability evidence.

## Build Identity

| Field | Value |
| --- | --- |
| Workspace version | `0.6.1-dev` |
| Git commit | `ec66212129bdec5d0812777774a6c3b9398e053f` |
| Host | Windows `10.0.26200.0` |
| PowerShell | `5.1.26100.7462` |
| Processor metadata | `AMD64 Family 23 Model 24 Stepping 1, AuthenticAMD` |
| Target | `x86_64-pc-windows-gnu` |
| Rust | `rustc 1.96.0 (ac68faa20 2026-05-25)` |
| Build profile | `release` |
| Suite | `all` |
| Latency samples | `5,000` |
| Sustained frames | `100,000` |
| Native TUN flag | `0` |
| Runner CPU/RSS fields | unavailable in this Windows runner |

## Validation Gates

- `cargo fmt --all -- --check`: pass.
- `cargo test --workspace --locked --target x86_64-pc-windows-gnu`: pass,
  zero failed.
- `cargo check --manifest-path benchmarks/Cargo.toml --locked
  --target x86_64-pc-windows-gnu`: pass.
- Release benchmark build and both profile captures: pass.

The pinned GNU toolchain does not have `cargo-clippy`, so this report does not
claim a Clippy run.

## Handshake and Local Latency

Values are p50, p95, and p99.9 from the complete in-memory authenticated setup.

| Profile | p50 | p95 | p99.9 | Allocation calls | Allocated bytes |
| --- | ---: | ---: | ---: | ---: | ---: |
| `secure-default` | 988.9 µs | 1.440 ms | 2.454 ms | 440,004 | 173,645,168 |
| `classical-lab` | 569.8 µs | 835.7 µs | 1.626 ms | 240,004 | 11,270,168 |

The higher hybrid cost is expected because `secure-default` includes the
ML-KEM exchange and validation. `classical-lab` is not a production fallback
and must not be presented as an equivalent security profile.

## In-Memory Data-Plane Goodput

Goodput and wire rate are bidirectional in-memory AEAD measurements in Mbps.

| Payload | `secure-default` goodput / wire | `classical-lab` goodput / wire |
| ---: | ---: | ---: |
| 1 KiB | 214.534 / 220.401 | 212.132 / 217.932 |
| 4 KiB | 342.215 / 344.555 | 344.665 / 347.021 |
| 1,400 B | 227.121 / 231.663 | 235.640 / 240.353 |
| 1,500 B | 232.528 / 236.869 | 233.048 / 237.399 |
| 64 KiB | 376.299 / 376.460 | 328.487 / 328.627 |

These values do not measure TUN forwarding, network throughput, or VPN
performance.

## Long Sessions and Allocation Pressure

The long-session row performs 100,000 local Shroud 2.0 encode/decode frames.

| Profile | Goodput Mbps | Wire Mbps | Allocation calls | Allocated bytes | RSS |
| --- | ---: | ---: | ---: | ---: | --- |
| `secure-default` | 2,077.770 | 2,363.050 | 200,004 | 218,859,787 | unavailable |
| `classical-lab` | 2,414.622 | 2,746.152 | 200,004 | 218,859,787 | unavailable |

The intended morphology delay is modeled but not slept in this benchmark.
These are processing and allocation results, not elapsed wall-clock session
duration.

## Shroud 2.0 Morphology

Rows report p50 / p95 / p99.9 in nanoseconds for the local authenticated
encode/decode path with a 1,450-byte path budget.

| Morphology profile | `secure-default` | `classical-lab` |
| --- | ---: | ---: |
| `low-latency` | 200 / 300 / 400 | 200 / 300 / 400 |
| `web-browsing-lab` | 200 / 600 / 1,000 | 200 / 600 / 1,400 |
| `video-streaming-lab` | 600 / 700 / 800 | 500 / 600 / 900 |
| `bulk-lab` | 600 / 700 / 2,800 | 800 / 900 / 1,500 |

The full raw capture also includes fixed-cell framing, AEAD, owned versus
borrowed decode, sampled delay, long-session, and impairment rows.

## QUIC-Shim and Replay Measurements

The UDP loopback handshake uses the authenticated SHPH lab shim, not RFC 9000
QUIC.

| Profile | Shim handshake p50 | p95 | p99.9 |
| --- | ---: | ---: | ---: |
| `secure-default` | 1.692 ms | 2.731 ms | 4.241 ms |
| `classical-lab` | 1.253 ms | 2.030 ms | 6.469 ms |

Both profiles reported the bounded local limiter probe as `accepted=8` and
`rejected=4993`; replay, reordering, and one-frame-loss rows completed without
failure.

## Interpretation and Limits

- This is a Windows-local prerelease regression capture, not a release claim
  for live VPN performance.
- Native TUN/Wintun packet I/O, route/DNS mutation, reconnect over a real
  network, two-host forwarding, RTT, jitter, and Internet loss behavior remain
  unmeasured here.
- CPU and RSS fields are unavailable from the current Windows benchmark
  runner; no values were fabricated.
- The paired WSL2/native-Windows report from August 5, 2026 remains separate
  historical evidence and is not overwritten by this Windows-only capture.
