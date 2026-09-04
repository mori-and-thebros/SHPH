# SHPH Security Evidence Pack

This document defines how SHPH turns security code and tests into reviewable
evidence. It does not claim an independent audit, constant-time behavior for
the full stack, or production security.

## Evidence tiers

| Tier | Meaning | Examples |
| --- | --- | --- |
| S0 | Source boundary | length limits, fail-closed branches, regular-file checks |
| S1 | Focused automated test | replay, handshake, malformed frame, TUN boundary, rollback tests |
| S2 | Fuzz or dependency evidence | cargo-fuzz smoke, `cargo audit`, locked dependency graph |
| S3 | Host or two-node evidence | native TUN, packet path, route/DNS rollback, killswitch crash test |
| S4 | Independent review | external code or security review with scope and findings |

Most current SHPH evidence is S0-S2. One S3 cross-platform native-TUN campaign
and one S3 single-host WFP forced-termination record are now recorded, but
broader S3 host gates remain open. There is no S4 claim in this repository.

## Threat-to-evidence map

| Threat | Current control | Evidence | Remaining boundary |
| --- | --- | --- | --- |
| Passive wire capture | Hybrid X25519 + ML-KEM-768 handshake and AEAD data plane | `cargo test -p shph-core --lib --locked`; handshake flow tests | No endpoint-compromise protection |
| Replay or nonce reuse | Sliding replay window and sender nonce limit | `cargo test -p shph-core crypto --locked`; transport replay tests | Experimental UDP paths remain lab-only |
| Active MITM | Transcript-bound Ed25519 signatures and pinned peer policy | `cargo test -p shph-core --test handshake_flow --locked`; CLI peer-policy tests | Key custody is local filesystem based |
| Malformed or oversized input | Bounded frames, payloads, files, and IP packets; fail-closed parsing | `cargo test -p shph-transport --lib --locked`; `cargo test -p shph-tun --lib --locked`; fuzz targets, including `phantom_one_envelope` | Distributed DoS is not solved |
| Slowloris or handshake flood | Aggregate deadlines, bounded hello reads, per-source limits | transport tests and source review | No distributed flood guarantee |
| Local secret disclosure | Owner-only keystore, atomic writes, zeroizing key material | core keystore/crypto tests; secret-material scan | Host compromise and memory forensics remain out of scope |
| File adapter traversal or aliasing | Bounded sanitized components, no-reparse regular-file opens, restart-safe replay identity, and Windows extended-length path handling | roadmap/transport adapter tests, authenticated spool sessions, distinct-root replication test, and standalone edge file-input tests | Directory-handle-relative TOCTOU under hostile concurrent filesystem mutation remains out of scope |
| Configuration/resource exhaustion | Central validation boundary, bounded lists and text fields, cross-field checks, duplicate peer detection, and bounded hostname resolution | `cargo test -p shph-config --lib --locked`; CLI validation tests; transport hostname-resolution tests | Host-wide resource exhaustion and maliciously large valid workloads still require soak testing |
| Route/DNS residue | Preflight and rollback state machine | CLI control-plane tests; elevated Windows lifecycle record; `docs/evidence/WINDOWS_WFP_CRASH_VALIDATION_2026-09-01.md` | Broader host coverage and failure-interruption testing remain S3 work |
| Crash-time plaintext egress | Opt-in Linux nftables or Windows WFP policy | Planner/unit tests; elevated Windows loopback WFP smoke; elevated forced-termination policy-persistence/explicit-cleanup record | Automatic crash-time cleanup, packet-leak prevention, failure-interruption, and broader host evidence remain open |
| Native TUN packet forwarding | IP header/length validation, packet bounds, complete writes, zeroized buffers | `docs/evidence/CROSS_PLATFORM_NATIVE_TUN_VALIDATION_2026-08-25.md` | One direct-TCP Windows-to-Linux IPv4 lane passed, including bounded throughput, reconnect, impairment, MTU-boundary, and soak checks; Linux/Linux, Windows/Windows, IPv6, DNS, UDP, crash containment, and production performance remain open |
| Optional SOCKS5/Xray underlay | Authenticated SHPH framing remains end-to-end through a local SOCKS5 relay | `docs/evidence/OPTIONAL_XRAY_UNDERLAY_VALIDATION_2026-08-25.md` | One authorized no-TUN preflight and payload path passed; full-route, long-duration, provider, and hostile-network behavior remain open |
| Established-session timeout inheritance | Clear transport deadlines after successful handshake | focused transport regression plus cross-platform session hold | Longer reconnect and underlay coverage remain open |
| Phantom One edge misuse | Loopback-only unauthenticated SOCKS adapter, paired TLS requirement, bounded capability replay cache, fixed fallback responses, opaque forwarding, and bounded no-reparse file inputs | `cargo test --manifest-path shph-edge/Cargo.toml --all-targets --locked`; standalone Linux/Windows checks and clippy | Edge is a prototype; no public-proxy, active-probe, or censorship-resistance guarantee |
| Release-material leakage | Explicit public-document allowlist, regular-file checks, bounded package sizes, source/lockfile provenance, checksums, and common secret-marker scan | `python scripts/package_release.py`; CI package manifest/checksum verification | This does not replace human redaction review, artifact signing, or an independent supply-chain audit |
| Dependency compromise or known advisory | Locked manifests and blocking advisory job | `cargo audit --deny warnings`; CI workflow | Advisory database freshness depends on the audit run |

## Required automated checks

The security collector records these checks and their exact status:

```text
git diff --check
cargo fmt --all -- --check
cargo metadata --format-version 1 --no-deps --locked
cargo test -p shph-core --lib --locked
cargo test -p shph-transport --lib --locked
cargo test -p shph-tun --lib --locked
cargo test -p shph-cli --test cli_reliability --locked -- --test-threads=1
cargo test --manifest-path shph-edge/Cargo.toml --all-targets --locked
cargo clippy --manifest-path shph-edge/Cargo.toml --all-targets --locked -- -D warnings
cargo audit --deny warnings
python scripts/package_release.py --binary target/release/shph --output dist/shph-package
```

Fuzz smoke is additive evidence, not a replacement for deterministic tests:

```text
cd fuzz
cargo +nightly-2026-07-16 fuzz run frame_decode -- -runs=1
cargo +nightly-2026-07-16 fuzz run config_parse -- -runs=1
cargo +nightly-2026-07-16 fuzz run audit_record -- -runs=1
cargo +nightly-2026-07-16 fuzz run replay_window -- -runs=1
cargo +nightly-2026-07-16 fuzz run shroud2_datagram -- -runs=1
cargo +nightly-2026-07-16 fuzz run phantom_one_envelope -- -runs=1
```

If a toolchain, advisory database, or host capability is unavailable, record
`SKIP` with the exact reason. Never convert it into a pass.

## Secret and privacy review

Before publishing any evidence artifact, check for:

- private keys, key seeds, keystores, certificates, or token values;
- peer IP addresses, hostnames, usernames, absolute home paths, and local
  adapter names;
- packet captures or logs containing plaintext payloads;
- shell history, environment dumps, or credentials;
- temporary files left by failed tests;
- generated benchmark output that contains machine-specific identifiers.

The automated collector scans for common private-key and token markers. That
scan is a guardrail, not proof that an artifact is safe to publish. A human
must review every generated file.

## Reviewer sign-off

```text
commit/tag:
tree status:
toolchain:
platform:
automated gates:
fuzz evidence:
dependency audit:
native host evidence:
open findings:
redaction reviewed by:
release decision: GO / NO-GO
```

Open host-gated items are tracked in `docs/SUPPORT_MATRIX.md`,
`docs/RISK_MATRIX.md`, and `docs/RELEASE_READINESS.md`.
