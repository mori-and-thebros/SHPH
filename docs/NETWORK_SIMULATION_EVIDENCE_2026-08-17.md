# Network Simulation Evidence Addendum — 2026-08-17

## Disposition

The three supplied “live system simulation” tables are not reproducible from
the repository as submitted. Their packet traces, loss model, RTT model,
random seeds, PMTU behavior, and chaff scheduler are not provided. This
addendum records what the current SHPH implementation can actually support and
the closest reproducible local measurements.

The evidence below is engineering evidence from a dirty development tree. It
is not a native two-host network test, an independent audit, or proof of
Internet behavior.

## 1. MTU and PMTU blackhole claims

### Implemented behavior

- `shph-tun` validates the conservative native TUN MTU of 1,360 bytes.
- Linux has an opt-in MSS-clamp planner that installs a separate
  `inet shph_mss_clamp` nftables table and rewrites TCP SYN MSS in both
  directions using the route MTU.
- The live CLI explicitly reports MSS clamping as unsupported on Windows
  because WFP packet rewriting is not implemented.
- No synthetic ICMP “Packet Too Big” generator or PMTU feedback module exists
  in the current codebase.

### Evidence status

| Supplied strategy | Status |
| --- | --- |
| Naive 1,500-byte path with 35.24% blackholing | Not reproduced; no packet trace or two-host PMTU emulator |
| MSS clamp with 3.19% UDP loss | Not reproduced; current MSS control covers TCP SYN only |
| MSS clamp plus synthetic ICMP with 0% loss | Unsupported; synthetic ICMP PTB is not implemented |

The focused `shph-tun` suite passed all 18 tests, including MTU validation,
MSS-clamp command bounds, packet-length validation, and Windows fail-closed
behavior. These tests validate planners and boundaries; they do not measure
packet delivery.

The 35.24%, 3.19%, and 100% delivery figures must therefore remain
**unverified**, and “flawless” must not be used in release or public
materials.

## 2. Post-quantum handshake latency

The standalone runner measured 20,000 complete in-memory handshakes for each
profile on the Windows GNU compatibility target. There was no RTT, packet
loss, retransmission, scheduler delay, or WAN emulator.

| Profile | p50 | p95 | p99.9 | Initial canonical Hello | Completed |
| --- | ---: | ---: | ---: | ---: | ---: |
| `classical-lab` | 837.8 µs | 1.0352 ms | 1.5920 ms | 474 bytes | 20,000 |
| `secure-default` | 1.5653 ms | 1.8545 ms | 2.7554 ms | 2,054 bytes | 20,000 |

The measured local p50 difference was approximately 727.5 µs. It is a
cryptographic-operation difference, not a global network-latency difference.
`classical-lab` is benchmark-only and removes ML-KEM; it is not a production
fallback.

The secure initial JSON Hello is already larger than a 1,360-byte packet
before the queued 0–64-byte transport whitespace padding and line delimiter.
It is sent through the stream-oriented handshake framing; the repository does
not support the supplied claim that the complete PQ handshake fits in one
1,360-byte TUN frame.

The supplied 8–280 ms RTT table and 99.9–100% WAN success rates are therefore
**not measured by SHPH**. They require a controlled network emulator or
native two-host capture with explicit PMTU, loss, retry, and retransmission
inputs.

## 3. Poisson chaffing and mobile-data claims

The current implementation does not contain a Poisson chaff scheduler,
`lambda = 25s` parameter, or one-hour idle-session accounting. The current
Shroud2 delay engine samples a bounded uniform integer range:

- `low-latency`: 0–500 µs;
- `web-browsing-lab`: 100 µs–8 ms;
- `video-streaming-lab`: 50 µs–3 ms; and
- `bulk-lab`: 0–750 µs.

A 20,000-sample local run reported:

| Profile | p50 sampled delay | Minimum | Maximum |
| --- | ---: | ---: | ---: |
| `low-latency` | 249.546 µs | 7 ns | 499.987 µs |
| `web-browsing-lab` | 4.058906 ms | 100.119 µs | 7.999784 ms |
| `video-streaming-lab` | 1.518770 ms | 50.044 µs | 2.999920 ms |
| `bulk-lab` | 374.715 µs | 11 ns | 749.980 µs |

The run samples delay without sleeping and therefore reports no mobile-data
burn. It does not establish inter-arrival entropy, traffic flattening, DPI
classifier performance, or hourly overhead.

The supplied `694.2 KB/hour`, `5.73 bits`, and “defeats timing classifiers”
claims are **not evidenced** by the current code. They would require a
versioned Poisson scheduler, a defined chaff emission policy, a fixed session
trace, and an explicitly defined entropy estimator.

## Reproduction and raw captures

The relevant commands were:

```powershell
cargo +1.96.0-x86_64-pc-windows-gnu build --release `
  --manifest-path benchmarks/Cargo.toml `
  --target x86_64-pc-windows-gnu --locked --offline

.\benchmarks\target\x86_64-pc-windows-gnu\release\shph-benchmarks.exe `
  --profile secure-default --suite core --iterations 20000 --frames 1

.\benchmarks\target\x86_64-pc-windows-gnu\release\shph-benchmarks.exe `
  --profile classical-lab --suite core --iterations 20000 --frames 1

.\benchmarks\target\x86_64-pc-windows-gnu\release\shph-benchmarks.exe `
  --profile secure-default --suite shroud --iterations 20000 --frames 1

cargo +1.96.0-x86_64-pc-windows-gnu test -p shph-tun --lib `
  --target x86_64-pc-windows-gnu --locked --offline --no-fail-fast
```

Ignored raw-capture hashes:

| Capture | SHA-256 |
| --- | --- |
| Secure-default core | `EE015BB643F7342DE2A9CE2F16956E35686052D0E196529B0B20B25C411AFD05` |
| Classical-lab core | `22012E3ADEC3E245105D373B3723AC7BF0CC94A72A96071A7A64F7F33AB558AE` |
| Shroud delay/morphology | `EF954F9D80C2056564E8A71FA209BE19B02F568D70A4AF4AAB891656A606AEF1` |
| TUN/MTU/MSS focused tests | `FC206C7313C5D7B3E7807142485073692DEBA6C1D6ABA8D5E17F9B3C9590F2EA` |

The captures are local files under ignored `benchmark-runs/`; they are not
publication artifacts.

## Bottom line

The current evidence supports: bounded 1,360-byte TUN configuration, Linux
TCP MSS-clamp planning, local hybrid-handshake cost, and bounded Shroud2 delay
sampling. It does not support synthetic ICMP PTB, WAN delivery percentages,
single-frame PQ handshakes, Poisson chaffing, hourly mobile-data cost, or
timing-classifier defeat.
