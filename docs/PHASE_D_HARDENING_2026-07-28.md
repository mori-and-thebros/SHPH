# Phase D Hardening Evidence

Captured on **July 28, 2026** for workspace version `0.5.0-dev.0`.
This is controlled WSL2/lab evidence, not native-TUN or two-host VPN
evidence.

## Fuzzing

Toolchain: `cargo-fuzz 0.13.2`, nightly Rust, `--sanitizer none`,
20 seconds per target.

| Target | Executions | Coverage | Peak RSS | Result |
| --- | ---: | ---: | ---: | --- |
| `frame_decode` | 26,183,071 | 58 counters | 47 MiB | No crash |
| `config_parse` | 2,455,022 | 1,572 counters | 46 MiB | No crash |
| `audit_record` | 9,823,297 | 818 counters | 47 MiB | No crash |
| `replay_window` | 30,734,181 | 33 counters | 47 MiB | No crash |

The framing harness now covers all five Shroud profiles and uses
`fuzz/shroud.dict`. Fuzzing reports are smoke/campaign evidence only; they do
not prove absence of defects.

## QUIC-Shim Repeatability

Two `secure-default` runs used the release benchmark binary, the `quic` suite,
5,000 latency samples, and 1,000 load frames.

| Run | Handshake p50 | Handshake p99.9 | Handshake max | Reordering p50 | Loss p50 |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 | 511,781 ns | 1,144,745 ns | 1,122,134,823 ns | 1,849 ns | 930 ns |
| 2 | 503,112 ns | 1,048,843,099 ns | 1,088,176,354 ns | 1,929 ns | 975 ns |

The handshake tail is scheduler-sensitive and remains an outlier-controlled
lab metric. No optimization is accepted based on a single tail sample.

## Profile Comparison

The benchmark runner keeps `secure-default` and `classical-lab` separate.
`classical-lab` removes ML-KEM and is not an equivalent security profile.

The following controlled `core` runs used the release benchmark binary,
2,000 handshake samples, and 10,000 load frames:

| Profile | Handshake p50 | Handshake p99.9 | RTT p50 | RTT p99.9 | Replay p50 |
| --- | ---: | ---: | ---: | ---: | ---: |
| `secure-default` | 395,684 ns | 594,684 ns | 6,381 ns | 17,507 ns | 32 ns |
| `classical-lab` | 248,185 ns | 366,455 ns | 6,370 ns | 17,095 ns | 32 ns |

Native/live network measurements remain operator-dependent.

## Fresh Validation Repeat

A second release-binary repeat used 2,000 handshake samples, 10,000 load
frames, and 1,000 QUIC samples on the same WSL2 host. It reproduced the
expected profile separation:

| Profile | Handshake p50 | Handshake p99.9 | RTT p50 | RTT p99.9 | Replay p50 |
| --- | ---: | ---: | ---: | ---: | ---: |
| `secure-default` | 377,316 ns | 519,909 ns | 6,410 ns | 8,210 ns | 30 ns |
| `classical-lab` | 230,914 ns | 300,785 ns | 5,900 ns | 6,731 ns | 30 ns |

The QUIC-shim repeat reported handshake p50 `464,418 ns`, p99.9
`1,030,204,798 ns`, reordering p50 `1,740 ns`, and loss-tolerance p50
`880 ns`. The billion-nanosecond tail remains scheduler-sensitive rather
than a basis for an optimization claim.

All four fuzz corpora were replayed with `-runs=0` after the campaign:
`frame_decode` 49 inputs, `config_parse` 4,824, `audit_record` 3,760, and
`replay_window` 62. Every corpus replay completed without a crash artifact.

## Remaining Phase D Work

- Continue profiling handshake and sustained data paths for additional safe
  wins; the Shroud receive-copy hotspot is now fixed and measured.
- Run native Linux TUN and two-host plans where the required privileges/tools
  are available; otherwise record explicit `SKIP` evidence.
- Complete the release-readiness checklist after the allocation and
  operator-dependent evidence gates are resolved.

## Allocation Optimization

The Shroud receive path now exposes a borrowed decoder for callers that only
need to authenticate and inspect the payload before copying the final user
payload. The QUIC decoder uses this path, removing the intermediate cell
payload allocation. The owned decoder remains available for callers that need
an independent `Vec<u8>`.

A focused release benchmark used 2,000 samples per profile:

| Profile | Owned calls/bytes | Borrowed calls/bytes | Owned p50 | Borrowed p50 |
| --- | ---: | ---: | ---: | ---: |
| `balanced` | 2,015 / 1,990,154 | 15 / 8,160 | 65 ns | 22 ns |
| `low-latency` | 2,015 / 966,154 | 15 / 8,160 | 43 ns | 22 ns |
| `bulk` | 2,015 / 8,134,154 | 15 / 8,160 | 921 ns | 22 ns |
| `randomized-lab` | 2,016 / 1,990,206 | 15 / 8,160 | 54 ns | 22 ns |
| `extreme-lab` | 2,015 / 16,326,154 | 15 / 8,160 | 1,765 ns | 22 ns |

These rows isolate framing decode, not the full encrypted receive path. They
show roughly 99% fewer allocation calls and roughly 99.6% fewer allocated
bytes; they are not live-network throughput claims.

The handshake benchmark was then repeated with 2,000 samples per profile:

| Profile | Previous calls/bytes | Current calls/bytes | Current p50 |
| --- | ---: | ---: | ---: |
| `secure-default` | 184,014 / 82,946,128 | 100,014 / 48,402,128 | 397,752 ns |
| `classical-lab` | 136,014 / 8,736,128 | 60,014 / 3,072,128 | 268,877 ns |

The current handshake path uses bounded stack transcript assembly, a fixed
hybrid-secret buffer, and in-place HKDF output. The latency change is
scheduler-sensitive; the allocation reduction is the accepted optimization
signal.
