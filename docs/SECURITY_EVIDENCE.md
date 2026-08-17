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

Most current SHPH evidence is S0-S2. Native host work is a separate S3 gate.
There is no S4 claim in this repository.

## Threat-to-evidence map

| Threat | Current control | Evidence | Remaining boundary |
| --- | --- | --- | --- |
| Passive wire capture | Hybrid X25519 + ML-KEM-768 handshake and AEAD data plane | `cargo test -p shph-core --lib --locked`; handshake flow tests | No endpoint-compromise protection |
| Replay or nonce reuse | Sliding replay window and sender nonce limit | `cargo test -p shph-core crypto --locked`; transport replay tests | Experimental UDP paths remain lab-only |
| Active MITM | Transcript-bound Ed25519 signatures and pinned peer policy | `cargo test -p shph-core --test handshake_flow --locked`; CLI peer-policy tests | Key custody is local filesystem based |
| Malformed or oversized input | Bounded frames, payloads, files, and IP packets; fail-closed parsing | `cargo test -p shph-transport --lib --locked`; `cargo test -p shph-tun --lib --locked`; fuzz targets | Distributed DoS is not solved |
| Slowloris or handshake flood | Aggregate deadlines, bounded hello reads, per-source limits | transport tests and source review | No distributed flood guarantee |
| Local secret disclosure | Owner-only keystore, atomic writes, zeroizing key material | core keystore/crypto tests; secret-material scan | Host compromise and memory forensics remain out of scope |
| File adapter traversal or aliasing | Bounded sanitized components and regular-file checks | roadmap adapter tests | Hostile filesystem TOCTOU remains out of scope |
| Route/DNS residue | Preflight and rollback state machine | CLI control-plane tests | Live privileged rollback still needs S3 evidence |
| Crash-time plaintext egress | Opt-in Linux nftables or Windows WFP policy | planner/unit tests | Privileged crash-leak and two-host evidence remain open |
| Native TUN packet corruption | IP header/length validation, packet bounds, complete writes, zeroized buffers | TUN unit tests | Native packet forwarding is host-gated |
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
cargo audit --deny warnings
```

Fuzz smoke is additive evidence, not a replacement for deterministic tests:

```text
cd fuzz
cargo +nightly-2026-07-16 fuzz run frame_decode -- -runs=1
cargo +nightly-2026-07-16 fuzz run config_parse -- -runs=1
cargo +nightly-2026-07-16 fuzz run audit_record -- -runs=1
cargo +nightly-2026-07-16 fuzz run replay_window -- -runs=1
cargo +nightly-2026-07-16 fuzz run shroud2_datagram -- -runs=1
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
