# Hardened Benchmark Campaign - 2026-08-18

## Executive summary

This campaign adds bounded local coverage for batching, path-MTU/loss
behavior, concurrent in-memory sessions, session churn, repeatability, and
the hardened batch-parser limits. It exercised the current Shroud2 encoder,
decoder, and authenticated application-message batch API on the Windows
laptop using the repository's LLVM-MinGW compatibility linker.

The results are engineering evidence for local code paths. They are not
evidence of live VPN throughput, PMTU discovery, ICMP behavior, TUN forwarding,
Internet loss recovery, reconnect recovery, DDoS capacity, or DPI evasion.

## Provenance

| Field | Value |
| --- | --- |
| Date | 2026-08-18 |
| Repository commit | `2a744832502e2b7c7a5b06481d0be856d60d3e39` |
| Workspace version | `0.6.3-dev` release candidate |
| Host platform | Windows |
| Rust | `rustc 1.96.0 (ac68faa20 2026-05-25)` |
| Target | `x86_64-pc-windows-gnu` |
| Linker | repository-local LLVM-MinGW compatibility linker |
| Build | release, locked, offline |
| Profile | `secure-default` |
| Native TUN | disabled |
| Tree state | dirty engineering tree |

The tree was intentionally not cleaned or committed for this campaign. A
release record should be regenerated from a reviewed commit.

Raw captures are ignored local artifacts. The capture files are tied to the
dirty engineering tree and are not release artifacts:

| Capture | Parameters | SHA-256 |
| --- | --- | --- |
| `benchmark-runs/2026-08-18/all-hardening-2026-08-18.txt` | `--suite all --iterations 100 --frames 5000` | `206EADA66E1F3B7DE7F28D61ABEC16E574DA48C1BE8024AB1E326464624E40CC` |
| `benchmark-runs/2026-08-18/extended-hardening-2026-08-18.txt` | `--suite extended --iterations 10 --frames 5000` | `CD75ED0C26ECCE77CCD732567F825CC8C8618208EDA407D15C5903752DDF6AF1` |
| `benchmark-runs/2026-08-18/evidence-hardening-2026-08-18.txt` | `--suite evidence --iterations 1 --frames 1` | `0292CFB0E789D38508CB465012B1DB3A679DDA8A2CFA55E9C27B251BA3F3108A` |
| `benchmark-runs/2026-08-18/repeatability-hardening/summary.csv` | 5 repeated extended runs, 1,000 iterations, 2,000 frames | `CC6B1798FD239DC6065FC4AF9B1D663E90ACE72F1667C8009064D10111C5A3D3` |
| `benchmark-runs/2026-08-18/windows-wrapper-hardening/secure-default.csv` | PowerShell wrapper, all, 100 iterations, 5,000 frames | `0D83CDEE1375F54151E8061EBBA35AB784ED9EFFC61A919AADFDB3490179F022` |
| `benchmark-runs/2026-08-18/windows-wrapper-hardening/classical-lab.csv` | PowerShell wrapper, classical comparison profile | `89461A6333BD8E729FC5E6E1263AD80D82E56523B9E551B56A19BD94194C266C` |
| `benchmark-runs/2026-08-18/operator-capability-skips.txt` | Windows prerequisite audit and explicit SKIPs | local raw skip record |

## Hardened controls exercised

The batch API now rejects invalid policy sizes and caller deadlines above one
second, bounds decoded batch payloads to the global Shroud2 envelope limit
(65,528 bytes), and returns a protocol error if internal batch state becomes
inconsistent instead of panicking. The caller remains responsible for calling
the deadline-aware flush path; no hidden scheduler task is created.

The production `MorphologyBatcher::for_profile` and
`flush_morphology_batch_if_due` paths were exercised by the adaptive benchmark
and the standards-QUIC loopback test. Malformed and oversized batch payload
cases are covered by the transport unit tests.

## 1. Authenticated batch API

The benchmark now uses the bounded `encode_batched_datagram` and
`decode_batched_datagram` API from `shph-transport`, which prefixes each
application message with a two-byte length and sends one authenticated
Shroud2 datagram for the batch. The API is opt-in and application-message
only; it must not coalesce independent native-TUN IP packets because one lost
QUIC DATAGRAM would lose every message in that batch. Overhead is relative to
application payload bytes.

| Profile | Batch size 1 | Batch size 2 | Batch size 4 | Batch size 8 |
| --- | ---: | ---: | ---: | ---: |
| SSH | 429.072% | 186.225% | 115.432% | 86.110% |
| VoIP | 198.664% | 123.082% | 96.835% | 68.039% |
| Web | 1,029.264% | 464.171% | 188.309% | not run; capped at 4 |
| Video | 695.550% | 298.292% | 99.911% | not run; capped at 4 |

The API reduces per-message envelope cost for small messages, especially at
batch sizes 4 and 8. It also changes latency and loss amplification, so callers
must flush according to their latency budget and must not use it for
independent IP packets.

### Adaptive policy capture

The production `MorphologyBatcher::for_profile` policy was exercised over 5,000
synthetic application messages. The deadline is caller-driven; this local
benchmark lets the real clock trigger the policy and therefore records the
observed batch count rather than claiming deterministic timing.

| Profile | Max messages | Max wait | Observed batches | Overhead |
| --- | ---: | ---: | ---: | ---: |
| SSH | 4 | 2 ms | 1,250 | 116.259% |
| VoIP | 4 | 2 ms | 1,250 | 95.040% |
| Web | 8 | 10 ms | 625 | 88.525% |
| Video | 8 | 20 ms | 627 | 15.452% |

These are still in-memory Shroud2 measurements. They do not measure scheduler
latency, QUIC congestion, or loss amplification on a live path.

## 2. Path-MTU and deterministic-loss matrix

The test used WebBrowsingLab payloads, generated a valid Shroud2 datagram for
each negotiated path MTU, and deterministically dropped packets at the
requested percentage before local decode. All rows had zero decode failures;
delivery loss is the injected local impairment.

| Path MTU | 0% loss | 1% loss | 5% loss | 10% loss |
| ---: | ---: | ---: | ---: | ---: |
| 1,200 | 100.0% | 98.9% | 94.9% | 89.8% |
| 1,280 | 100.0% | 99.2% | 95.2% | 89.6% |
| 1,360 | 100.0% | 99.0% | 95.5% | 90.1% |
| 1,400 | 100.0% | 99.0% | 95.0% | 90.1% |
| 1,472 | 100.0% | 98.8% | 94.9% | 89.3% |

The matrix confirms that the local envelope remains within the supplied path
MTU and decodes correctly when a datagram is not dropped. It does not prove
that a real path accepts the MTU, that a host emits ICMP Packet Too Big, or
that TCP/UDP/QUIC PMTU blackholes are repaired.

## 3. Concurrent in-memory sessions

Each worker created an independent WebBrowsingLab morphology engine and
processed 5,000 Shroud2 encode/decode frames. Thread creation and joining were
included in elapsed time.

| Workers | Goodput (Mbps) | Wire rate (Mbps) | Packets/sec |
| ---: | ---: | ---: | ---: |
| 1 | 57.885 | 651.523 | 947,597.839 |
| 2 | 100.066 | 1,123.719 | 1,633,479.802 |
| 4 | 178.777 | 2,014.008 | 2,923,121.894 |
| 8 | 251.265 | 2,837.717 | 4,112,138.003 |

This is useful for spotting local scaling regressions. It is not socket or
TUN throughput and is not a line-rate claim.

## 4. Session-churn model

The requested 5,000 frames were divided across sequential models that created
a fresh morphology engine per session.

| Session models | Goodput (Mbps) | Wire rate (Mbps) | Packets/sec |
| ---: | ---: | ---: | ---: |
| 1 | 69.621 | 796.127 | 1,139,731.023 |
| 4 | 68.339 | 770.956 | 1,115,822.361 |
| 16 | 68.259 | 781.217 | 1,127,039.942 |

This shows no large local regression from repeatedly constructing the
benchmark morphology state. It does not include a handshake, socket close,
peer failure, retry timer, route change, or actual reconnect.

## 5. Repeatability

Five extended captures completed with exit code zero. Their hashes differed,
as expected, because `encode_datagram` fills padding using OS randomness. The
repeatability script records each capture hash and byte count; it does not
pretend that cryptographic padding is byte-for-byte deterministic.

| Run | Capture bytes |
| ---: | ---: |
| 1 | 15,794 |
| 2 | 15,795 |
| 3 | 15,785 |
| 4 | 15,806 |
| 5 | 15,803 |

Individual capture hashes are recorded in
`benchmark-runs/2026-08-18/repeatability-hardening/summary.csv`. They differ,
as expected, because Shroud2 padding uses OS randomness; the stable structural
fields and pass/fail status are the repeatability signal.

## 6. Existing evidence suite from the hardened campaign

The full suite also completed successfully. The current Shroud2 overhead
rows were:

| Profile | Overhead |
| --- | ---: |
| Bulk | 24.965% |
| Video | 21.093% |
| Web | 90.340% |
| VoIP | 191.303% |
| SSH | 422.775% |

Additional local-only rows from the full capture:

| Measurement | Result |
| --- | ---: |
| Direct ML-KEM decapsulation | 15,949.331 operations/sec |
| Stateless cookie gate | 617,116.339 operations/sec |
| Per-source limiter | 1,464,008.807 operations/sec |
| 128-bit replay window | 16,457,275.268 validations/sec |

These figures supersede no network claim. They remain process-local crypto and
nonce-validation measurements, as described in
`docs/BENCHMARK_RESULTS_2026-08-17.md`.

The hardened full-suite capture also recorded the authenticated setup,
bidirectional in-memory echo, identity-provider idempotence, AEAD loopback,
Shroud2 morphology, QUIC-shim impairment, and resource-path scenarios. The
PowerShell wrapper reproduced the same suite under both `secure-default` and
`classical-lab` profiles; it did not enable native TUN.

## 7. Capability audit and explicit skips

The current laptop could not run the operator-only layers:

- MSVC `link.exe` is unavailable. The GNU target was built with the existing
  repository-local compatibility linker; this is not native MSVC evidence.
- WSL is not installed.
- Native PowerShell has no `bash`, `sh`, `iperf3`, `docker`, `unshare`, or
  `ip`. `sudo.exe` alone does not provide Linux namespaces or `/dev/net/tun`.
- No prepared peer configuration was present.

Therefore these were recorded as unavailable rather than simulated:

- native Linux TUN lifecycle and isolated namespace E2E;
- two-host throughput, RTT, jitter, PMTU, and packet-loss measurements;
- real-process lifecycle, control-plane apply/reconcile/undo, and reconnect;
- Wintun/TUN forwarding and route/DNS behavior.

The real two-host gate is prepared in
`scripts/validate_linux_two_host.sh`. It must be run on two separate native
Linux hosts or VMs with root/CAP_NET_ADMIN, `/dev/net/tun`, `iperf3`, and an
operator-provisioned peer configuration. This Windows run intentionally did
not substitute a loopback or synthetic result for that gate.

## Validation gates

- `cargo fmt --all -- --check`: pass.
- `git diff --check`: pass, with only the repository's existing line-ending
  conversion warnings.
- Standalone benchmark tests: 6 passed, 0 failed.
- Standalone benchmark Clippy with `-D warnings`: pass.
- Standards-QUIC transport library Clippy with `-D warnings`: pass.
- Full workspace Clippy with `--all-targets -D warnings`: pass.
- Full workspace release build: pass with the recorded LLVM-MinGW
  compatibility linker.
- Full workspace test build: all workspace test targets compiled, but direct
  execution was blocked when the local GNU runner could not materialize
  `shph-31cb3fe3b3357cb7.exe` (`os error 2`). This is an environment runner
  limitation, not a claimed passing test run.
- Standards-QUIC transport test binary: compiled with `--no-run`; direct
  execution remains blocked by the local Windows GNU test-runner artifact,
  which did not materialize the reported executable path.
- Release benchmark build: pass with the recorded LLVM-MinGW compatibility
  linker.
- Release benchmark extended smoke run (`--iterations 1 --frames 100`): pass.
- Full suite capture: pass.
- Evidence-only capture: pass.
- Extended suite capture: pass.
- Adaptive-policy extended capture: pass.
- Five-run repeatability capture: pass.
- Windows wrapper capture: both `secure-default` and `classical-lab` pass.
