# SHPH Local Evidence Update — 2026-08-22

This report records the reproducible Windows-local engineering evidence
captured during the current development pass. It is not an independent audit,
live Internet measurement, or proof of censorship resistance.

## Provenance

| Field | Value |
| --- | --- |
| Base commit | `b0913e0e425535d49d419a7f92ed878c3cfd2e6b` |
| Workspace version | `0.6.4-dev.3` |
| Host | Windows, `x86_64-pc-windows-msvc` |
| Rust | `rustc 1.96.0 (ac68faa20 2026-05-25)` |
| Build | release, locked |
| Native TUN | not enabled for local benchmark rows |
| Tree state | dirty engineering tree |

The source and benchmark changes for this report were captured before the
follow-up publication commit. The raw captures record this base commit and
remain local, ignored artifacts; they are not a substitute for the GitHub tag
or hosted CI artifacts.

## Validation gates

The following checks passed during this pass:

- `cargo fmt --all -- --check`
- `cargo check --workspace --locked`
- `cargo clippy --workspace --all-targets --locked -- -D warnings`
- `cargo test --workspace --locked -- --test-threads=1` — 297 tests, 0 failures
- focused Shroud2 tests — 21 passed
- focused malformed-peer flood test — 1 passed
- benchmark crate tests — 7 passed
- `cargo audit --deny warnings`
- release workspace build
- 32-bit MSVC CLI release build

The standalone benchmark crate then completed both `all` and `extended` suites
for `secure-default` and explicit benchmark-only `classical-lab` profiles
(100 latency iterations and 10,000 frames). The Criterion harness completed
62 result sets across six groups. These are local microbenchmark and synthetic
model results; they do not establish Internet throughput, two-host forwarding,
native TUN behavior, censorship resistance, or production readiness.

The Criterion report contained one comparison warning for the histogram
Wasserstein-distance microbenchmark. That warning is retained as a regression
signal and did not indicate a failing test or invalid result.

The security collector also passed the core (80), transport (75), and TUN
(19) test groups, plus formatting, metadata, and the secret-material scan.
Its overall process was marked incomplete because the tree was intentionally
dirty and audit/fuzz were invoked separately.

## Shroud2 overhead matrix

The measured wire value is the Shroud2 envelope and padding. Plaintext payload
is the baseline; IP, UDP, and Ethernet headers are excluded. Each row uses
5,000 deterministic packets and a 1,472-byte path budget.

| Workload | Profile | Overhead | Wire-size entropy | Scope |
| --- | --- | ---: | ---: | --- |
| Bulk | `BulkLab` | 24.965% | 1.196919 bits | bulk lab distribution |
| Mixed video | `VideoStreamingLab` | 21.093% | 1.469244 bits | mixed 800–1,400-byte payloads |
| Near-MTU video | `VideoStreamingLargePayloadLab` | 1.427% | 1.694293 bits | aggregated 1,408–1,465-byte payloads |
| Near-MTU balanced video | `VideoStreamingBalancedPayloadLab` | **1.360%** | **1.956248 bits** | aggregated 1,408–1,465-byte payloads |
| Web | `WebBrowsingLab` | 90.340% | 2.095707 bits | small-message-heavy lab distribution |
| VoIP-sized | `LowLatency` | 191.303% | 1.301565 bits | 24–119-byte payloads |
| SSH-sized | `LowLatency` | 422.775% | 1.312508 bits | 1–80-byte payloads |

The balanced video profile uses target classes
`1415|1430|1445|1460|1472` with weights `35|30|20|12|3`. It reaches the
stated under-4.6% overhead and above-1.88-bit entropy targets only for the
declared near-MTU, already-aggregated workload. The mixed-video result remains
21.093%; the scoped result must not be generalized to arbitrary video,
control, VoIP, SSH, or browser traffic.

Wire-size entropy is a descriptive statistic of this synthetic distribution.
It is not an anonymity score, DPI-classifier result, browser-similarity score,
or universal privacy guarantee.

## Local latency and defensive-path measurements

The core benchmark recorded:

| Measurement | p99 | Interpretation |
| --- | ---: | --- |
| Full authenticated hybrid setup | 2.2654 ms | in-memory operation latency |
| 1 KiB bidirectional echo | 0.0148 ms | in-memory echo latency |
| 128-bit replay validation | 18,092,801.598 packets/sec | single-threaded nonce validation |

The anti-DoS comparison is also local CPU evidence only. The latest run
reported a cookie/direct ML-KEM rate factor of `42.993x`; it was not a socket
flood, spoofed-source, distributed-load, or DDoS-capacity test.

## Fuzz campaign status

The pinned campaign has five targets at 20,000,000 executions each. The
`frame_decode` target completed cleanly:

- 20,000,000 executions
- no crash, OOM, or timeout artifact
- elapsed libFuzzer time: 509 seconds

The remaining four targets were resumed after the pause and are still in
progress. Until all five target logs report their exact completion markers,
the project must not claim 100,000,000 completed fuzz executions.

## Claims still requiring separate infrastructure

This Windows workstation does not establish:

- 0.00% startup packet leakage under elevated native-TUN/socket-flood tests;
- two-host forwarding, live Internet RTT, packet loss recovery, or throughput;
- DPI evasion, CDN indistinguishability, or censorship bypass;
- universal memory-leak absence or independent security-audit certification;
- production multi-hop routing or adaptive Smart Shroud behavior.

Those claims require an elevated native-TUN host, a second controlled endpoint,
external packet capture, and independently reviewable inputs. The evidence
package records these as open gates rather than substituting Python projections
or synthetic local numbers.
