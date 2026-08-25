# SHPH Defensive Rejection Benchmark — 2026-08-25

This report records the new `defensive` benchmark suite added after the
`v0.6.4-dev.4` tag. It measures local rejection-path latency in the
standalone benchmark binary. It is not a network, packet-forwarding, DDoS,
PMTU, censorship, or DPI result.

## Provenance

| Field | Value |
| --- | --- |
| Host | Windows |
| Target | `x86_64-pc-windows-msvc` release benchmark binary |
| Rust | `rustc 1.96.0 (ac68faa20 2026-05-25)` |
| Base `HEAD` | `ade2c8355d34312cd528b4c0fa8578df9dd9de2d` |
| Suite | `defensive` |
| Samples per scenario | 2,000 |
| Native TUN | Disabled for this benchmark |
| Capture | `benchmark-runs/defensive-20260825/secure-default.csv` |
| Tree status | Dirty engineering tree; `HEAD` is recorded separately from working-tree changes |

## Results

All scenarios rejected the intentionally malformed or policy-disallowed input
on every sample.

| Scenario | Payload bytes | p50 (ns) | p95 (ns) | p99 (ns) | Mean (ns) | Scope |
| --- | ---: | ---: | ---: | ---: | ---: | --- |
| Truncated Shroud cell | 1,023 | 100 | 100 | 100 | 97 | bounded cell-length rejection |
| Non-canonical cell padding | 1,024 | 500 | 600 | 600 | 540 | canonical-padding rejection |
| Invalid cell header | 1,024 | 100 | 100 | 100 | 96 | header validation |
| Oversized Shroud2 datagram | 1,473 | 100 | 100 | 100 | 90 | path-MTU bound |
| Malformed cookie length | 3 | 0 | 100 | 100 | 42 | pre-auth length rejection |
| Forged cookie tag | 32 | 1,400 | 1,500 | 1,800 | 1,400 | HMAC verification failure |
| Cookie/source mismatch | 32 | 1,400 | 1,400 | 1,400 | 1,383 | source-address binding |
| Duplicate replay nonce | 0 | 0 | 100 | 100 | 39 | 128-bit replay-window rejection |
| Per-source rate-limit rejection | 0 | 800 | 800 | 1,000 | 779 | eight-per-window cap |

## Interpretation

The malformed-input rows are cheap because they fail before cryptographic
work. Forged cookies and source mismatches exercise the authenticated
pre-authentication path. The replay and rate-limit rows measure state-machine
rejection, not the amount of traffic a server can withstand.

The suite is useful for detecting accidental regressions such as parsing
allocations, unbounded work before rejection, or changes to the fail-closed
boundary. It does not establish a packets-per-second guarantee on a listener,
distributed flood resistance, network throughput, or behavior under a real
attacker.

## Reproduce

```powershell
cargo +1.96.0 build --release `
  --manifest-path benchmarks/Cargo.toml `
  --target x86_64-pc-windows-msvc --locked

.\benchmarks\target\x86_64-pc-windows-msvc\release\shph-benchmarks.exe `
  --profile secure-default `
  --suite defensive `
  --iterations 2000 `
  --frames 1
```

The same suite is included in `--suite all`, the Windows benchmark smoke job,
and the Criterion `defensive/rejections` group.
