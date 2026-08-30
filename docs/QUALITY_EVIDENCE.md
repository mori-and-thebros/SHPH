# SHPH Quality, Tests, and Benchmark Evidence

This document summarizes the validation available for the `v0.6.6-dev`
development line. The detailed collector capture below includes historical
pre-publication evidence from the preceding development snapshot, while the
current branch verification is recorded separately. Local and GitHub-hosted
benchmark results are not Internet throughput, and code-path tests are not an
independent security audit.

## Provenance

| Field | Value |
| --- | --- |
| Development line | `v0.6.6-dev` |
| Source revision | `v0.6.6-dev` (publication tag) |
| Publication ref | `v0.6.6-dev` |
| Validation date | 2026-08-30 |
| Primary host | Windows 11 |
| Rust toolchain | `rustc 1.96.0 (ac68faa20 2026-05-25)` |
| Main target | `x86_64-pc-windows-msvc` |
| Additional target | `i686-pc-windows-msvc` |
| Final candidate tree | Clean before publication |

## Current branch verification

The Windows local verification pass for the publication snapshot completed
with the following results:

| Check | Result |
| --- | --- |
| Workspace tests | PASS: 379 passed, 0 failed |
| Repeated fresh-process CLI reliability | PASS: 8 authenticated loopback sessions |
| Standalone edge tests | PASS: 38 passed, 0 failed |
| Standalone edge HTTP/3 tests | PASS: 38 passed, 0 failed |
| Full benchmark smoke | PASS: `--suite all --iterations 3 --frames 512` |
| Sanitized package verification | PASS: 11 allowlisted payload files plus manifest/checksums |
| Native host toolchain | PASS: MSVC linker detected |
| Native-TUN/two-host campaign | SKIP: requires a dedicated privileged host pair |

These results are local engineering evidence. They do not close the native
TUN, two-host, Internet, uptime, hostile-network, censorship-resistance, or
independent-audit boundaries.

## Automated gate capture

The strict release-readiness collector was run with dirty-tree evidence
allowed during the pre-publication engineering capture. The final candidate
was separately rerun through the locked code gates from a clean tree. The
privileged native-host gate remains host-gated in the collector because its
dedicated operator evidence is captured separately.

| Gate | Result |
| --- | --- |
| `cargo fmt --all -- --check` | PASS |
| `cargo metadata --format-version 1 --no-deps --locked` | PASS |
| `cargo check --workspace --all-targets --locked` | PASS |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | PASS |
| `cargo test --workspace --all-targets --locked` | PASS |
| Workspace release build | PASS |
| Benchmark manifest check | PASS |
| Fuzz manifest check | PASS |
| `cargo audit --deny warnings` | PASS |
| Clean-tree gate | PASS on the final candidate; the historical collector capture was WARN because it preceded publication |
| Dedicated native host toolchain gate | SKIP in collector; covered by operator evidence |
| Dedicated native TUN two-host gate | SKIP in collector; covered by operator evidence |
| Collector release eligibility | Host-gated; direct two-host evidence is recorded separately |

The current workspace test run executed **379 tests with 0 failures** across
the CLI, configuration, core cryptography and handshake, identity,
obfuscation, transport, and TUN crates. The advisory scan covered 299 locked
crate dependencies. The historical collector capture referenced by the
original gate table recorded an earlier 316-test snapshot.

## Fuzz smoke

The six checked-in fuzz targets completed 1,000 executions each, for 6,000
requested executions total, using the installed MSVC sanitizer runtime:

| Target | Runs | Result |
| --- | ---: | --- |
| `frame_decode` | 1,000 | PASS |
| `config_parse` | 1,000 | PASS |
| `audit_record` | 1,000 | PASS |
| `replay_window` | 1,000 | PASS |
| `shroud2_datagram` | 1,000 | PASS |
| `phantom_one_envelope` | 1,000 | PASS |

This is smoke evidence. It is not a 20-million or 100-million iteration
campaign and does not replace an independent audit.

## Criterion capture

The Windows Criterion harness generated 536 report files covering crypto,
defensive paths, handshakes, framing, Shroud2, identity records, adapters,
and tuned session-padding groups.

The capture completed successfully, but stored-baseline comparisons reported
performance follow-up signals:

- identity record verification: approximately +5-10%;
- JSON parse and verification: approximately +3-9%;
- JSON serialization: approximately +21-33%; and
- Shroud2 batch push/flush: approximately +6-12%.

These are microbenchmark comparison signals, not correctness failures. They
should be investigated before calling the prototype performance-optimized.

## Local Shroud and defensive measurements

The following values are local in-memory measurements from the existing
benchmark campaign. IP, UDP, Ethernet, socket, TUN, and Internet overhead are
excluded unless explicitly stated.

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
larger than a keystroke-sized payload. These values do not prove traffic
indistinguishability, browser similarity, or DPI classifier failure.

### Pre-authentication and replay measurements

| Measurement | Result |
| --- | ---: |
| Direct ML-KEM-768 decapsulation | 14,425 operations/sec |
| Stateless cookie path | 575,619 operations/sec |
| Per-source limiter path | 1,518,455 operations/sec |
| 128-bit replay-window validation | 17,490,222 validations/sec |

These are single-process or in-memory measurements. They are not network
flood capacity, DDoS protection, line-rate throughput, or a guarantee for
another CPU or compiler.

## Privileged host evidence

The elevated Windows validator passed signed/hash-pinned Wintun lifecycle,
temporary route and DNS rollback, loopback WFP install/teardown, and residue
checks. See
[`evidence/WINDOWS_NATIVE_VALIDATION_2026-08-25.md`](evidence/WINDOWS_NATIVE_VALIDATION_2026-08-25.md).

A separate Windows-to-Linux native-TUN campaign passed:

- authenticated direct-TCP handshake;
- native adapter and Linux TUN setup;
- default-route forwarding and Linux-host egress;
- 10/10 initial pings and 5/5 post-reconnect pings;
- a controlled 64 MiB transfer at approximately 1.27 MB/s;
- a 90-second six-sample soak;
- bounded impairment, DF/MTU-boundary, and teardown checks.

The complete scope and limitations are in
[`evidence/CROSS_PLATFORM_NATIVE_TUN_VALIDATION_2026-08-25.md`](evidence/CROSS_PLATFORM_NATIVE_TUN_VALIDATION_2026-08-25.md).

The optional local SOCKS5/Xray-compatible underlay also completed an
authorized no-TUN SHPH preflight and one-shot payload test. It is not part of
the direct-TCP release profile; see
[`evidence/OPTIONAL_XRAY_UNDERLAY_VALIDATION_2026-08-25.md`](evidence/OPTIONAL_XRAY_UNDERLAY_VALIDATION_2026-08-25.md).

## What the evidence proves

- The workspace builds and passes the locked automated gates on the tested
  Windows MSVC environment.
- The exercised cryptographic, identity, framing, replay, transport, CLI,
  configuration, and TUN paths pass the recorded tests.
- Established TCP sessions no longer inherit handshake read/write deadlines.
- One controlled Windows-to-Linux direct-TCP native-TUN IPv4 lane carried
  external traffic and completed reconnect and teardown checks.
- One authorized no-TUN payload crossed the optional SOCKS5/Xray underlay.

## What the evidence does not prove

This document does not establish:

- production VPN readiness, an uptime/SLA guarantee, or a stable Quick Tunnel;
- anonymity or an anonymity set;
- DPI evasion, censorship resistance, browser/TLS fingerprint parity, or
  traffic indistinguishability;
- DDoS capacity from local cryptographic operation rates;
- generalized Linux/Linux or Windows/Windows native-TUN operation;
- IPv6, DNS, UDP, standards-QUIC, crash-time killswitch containment, or
  full-route/long-duration Xray behavior; or
- independent cryptographic or security-audit certification.

## Remaining release gates

Before a release claim, SHPH still needs a clean-tree capture with complete
provenance, dedicated Linux/Linux and Windows/Windows campaigns, forced
termination and WFP crash-leak evidence, explicit DNS/IPv6/UDP and
standards-QUIC validation, and follow-up on the Criterion regressions.

The binding gate definitions are in
[`RELEASE_READINESS.md`](RELEASE_READINESS.md), with the support boundary in
[`SUPPORT_MATRIX.md`](SUPPORT_MATRIX.md).
