# SHPH Quality, Tests, and Benchmark Evidence

This document summarizes the validation available for `v0.6.4-dev.2`.
It combines the release validation run on the tagged code with the latest
dated benchmark reports. Measurements are labeled carefully: local benchmark
results are not Internet throughput, and code-path tests are not independent
security audits.

## Release provenance

| Field | Value |
| --- | --- |
| Release tag | `v0.6.4-dev.2` |
| Release commit | `109d0a8` |
| Validation date | 2026-08-20 |
| Primary host | Windows |
| Rust toolchain | `rustc 1.96.0 (ac68faa20 2026-05-25)` |
| Main target | `x86_64-pc-windows-msvc` |
| Additional target | `i686-pc-windows-msvc` |
| Build mode | locked release/debug validation |

## Release validation results

The following gates passed on the release tree:

| Gate | Result |
| --- | --- |
| `cargo fmt --all -- --check` | PASS |
| `cargo check --workspace --locked` | PASS |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | PASS |
| `cargo test --workspace --locked -- --test-threads=1` | PASS |
| Workspace release/all-target build | PASS |
| `shph-cli` release build for 32-bit MSVC | PASS |
| Standalone benchmark format/check gates | PASS |
| Standalone fuzz-manifest format/check gates | PASS |
| Windows benchmark identity smoke | PASS |
| Windows benchmark wire smoke | PASS |
| `cargo audit --deny warnings` | PASS |

The workspace test run executed **297 tests with 0 failures** across the CLI,
configuration, core cryptography/handshake, identity, obfuscation, transport,
and TUN crates. The audit scanned 299 locked crate dependencies.

The transport regression coverage includes a test for a length-prefixed TCP
frame split across polling timeouts. The receiver now preserves partial
prefix/ciphertext state instead of attempting to parse the next read as a new
frame.

## Local benchmark results

The following values come from the dated hardened benchmark campaign in
[`docs/BENCHMARK_RESULTS_2026-08-17.md`](BENCHMARK_RESULTS_2026-08-17.md).
They measure the current Shroud2 implementation in memory on a Windows
workstation; IP, UDP, Ethernet, socket, TUN, and Internet overhead are
excluded unless stated.

### Shroud2 wire overhead

| Traffic profile | Extra wire overhead |
| --- | ---: |
| Bulk | 24.965% |
| Video | 21.093% |
| Web | 90.340% |
| VoIP | 191.303% |
| SSH-sized interactive payloads | 422.775% |

The overhead is relative to plaintext payload bytes. Small interactive
payloads remain expensive because the smallest low-latency wire class is much
larger than a keystroke-sized payload. These figures do not prove traffic
indistinguishability, browser similarity, or DPI classifier failure.

### Pre-authentication and replay measurements

| Measurement | Result |
| --- | ---: |
| Direct ML-KEM-768 decapsulation | 14,425 operations/sec |
| Stateless cookie path | 575,619 operations/sec |
| Per-source limiter path | 1,518,455 operations/sec |
| 128-bit replay-window validation | 17,490,222 validations/sec |

These are single-process or in-memory measurements. They are not network
flood capacity, DDoS protection, line-rate throughput, or a guarantee for a
different CPU or compiler.

### Local scaling and MTU/loss modeling

The extended campaign in
[`docs/BENCHMARK_EXTENDED_RESULTS_2026-08-18.md`](BENCHMARK_EXTENDED_RESULTS_2026-08-18.md)
reported the following in-memory concurrent Shroud2 results:

| Workers | Goodput | Wire rate | Packets/sec |
| ---: | ---: | ---: | ---: |
| 1 | 52.451 Mbps | 590.366 Mbps | 858,649 |
| 2 | 98.168 Mbps | 1,102.398 Mbps | 1,602,487 |
| 4 | 163.014 Mbps | 1,836.431 Mbps | 2,665,387 |
| 8 | 216.828 Mbps | 2,448.797 Mbps | 3,548,553 |

The same campaign generated valid local Shroud2 datagrams across path-MTU
values from 1,200 to 1,472 bytes. With deterministic packet drops injected,
delivery was approximately 89–90% at 10% loss and approximately 95% at 5%
loss; all non-dropped datagrams decoded successfully. This is a local model,
not PMTU discovery or real-network loss recovery.

## What the evidence does prove

- The released workspace compiles with locked dependencies on the tested
  Windows MSVC targets.
- The exercised cryptographic, identity, framing, replay, transport, CLI,
  configuration, and TUN unit/integration paths pass the recorded tests.
- The TCP receiver handles partial frame delivery across polling timeouts.
- The benchmark harness can reproduce bounded local morphology, crypto,
  replay, scaling, and MTU/loss measurements.
- The dependency advisory scan passed for the committed lockfile.

## What the evidence does not prove

This document does not establish:

- production VPN readiness or an uptime/SLA guarantee;
- live Internet throughput, two-host forwarding, or 10/40-Gbps saturation;
- DPI evasion, censorship resistance, browser/TLS fingerprint parity, or
  traffic indistinguishability;
- DDoS capacity from local cryptographic operation rates;
- native Linux TUN or elevated Windows Wintun packet-path completion;
- route/DNS/killswitch crash-leak behavior on every supported host; or
- independent cryptographic or security-audit certification.

Linux namespace tests and nightly cargo-fuzz smoke runs were not executed on
the Windows release workstation because Bash, Linux namespaces, nightly Rust,
and cargo-fuzz were unavailable. They remain separate release gates in
[`docs/RELEASE_READINESS.md`](RELEASE_READINESS.md).

## Reproduce the core checks

From the repository root:

```powershell
cargo fmt --all -- --check
cargo check --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked -- --test-threads=1
cargo build --release --workspace --all-targets --locked
cargo build --release --target i686-pc-windows-msvc -p shph-cli --locked
cargo audit --deny warnings
```

For the standalone benchmark harness:

```powershell
cargo check --manifest-path benchmarks/Cargo.toml --all-targets --locked
cargo run --manifest-path benchmarks/Cargo.toml --release -- `
  --profile secure-default --suite evidence --iterations 1 --frames 1
```

Run new measurements on a clean tree and record the commit, target, compiler,
profile, iteration count, and host capability skips alongside the results.
