# Validation Follow-up — 2026-08-05

This note records the remaining validation work performed after the security
remediation. It covers reproducible commands and platform-specific evidence;
release claims must still be based on a clean tagged revision.

This is a historical snapshot from August 5, 2026. The current dependency
policy and advisory command are maintained in `docs/SUPPLY_CHAIN_SCAN.md`;
the captured output below is not a current scan result.

## Dependency Audit

Historical command:

```text
cargo audit --no-fetch
```

Result: exit `0`, with no vulnerability findings. The current lockfile scan
contains 237 crate dependencies and reports two accepted warnings:

- `RUSTSEC-2024-0436`: unmaintained `paste 1.0.15`, transitive through the
  optional TUI dependency graph.
- `RUSTSEC-2026-0002`: unsound `lru 0.12.5` `IterMut`, transitive through the
  optional TUI dependency graph; the affected API is not used by SHPH.

The captured command output is in `docs/evidence/CARGO_AUDIT.txt`.

## Pinned Fuzz Smoke

The CI-pinned toolchain was installed and verified:

```text
rustc 1.99.0-nightly (d0babd8b6 2026-07-15)
cargo-fuzz 0.13.2
```

Each current target completed a bounded smoke run with the installed pinned
nightly:

```text
cargo +nightly-2026-07-16 fuzz run --sanitizer none <target> -- -runs=1
```

Targets:

- `frame_decode`
- `config_parse`
- `audit_record`
- `replay_window`
- `shroud2_datagram`

All five targets exited successfully without a crash artifact. A second run
used the default cargo-fuzz sanitizer path with
`LSAN_OPTIONS=detect_leaks=0 ASAN_OPTIONS=detect_leaks=0`; all five targets
again passed. Leak reporting is disabled only because the restricted WSL
execution wrapper causes LeakSanitizer to report a false failure under ptrace.
These bounded smoke runs do not replace the sanitizer-enabled CI job or a
longer fuzz campaign.

## Workspace Gates

The refreshed acceptance evidence records:

- `cargo fmt --all -- --check`: pass
- `cargo clippy --workspace --all-targets --locked -- -D warnings`: pass
- `cargo test --workspace --locked`: **191 passed, 0 failed**
- `cargo build --workspace --locked`: pass
- `scripts/demo.sh all`: pass
- `git diff --check`: pass

See `docs/evidence/GATE_EVIDENCE.md` for the generated provenance and command
output.

## Native Linux TUN Capability-Gated Rerun

The isolated namespace probe and lifecycle benchmark were rerun after the
cross-target fixes:

```text
./scripts/native_tun_namespace_test.sh: PASS
20/20 lifecycle samples: PASS
min_ns=59095134
p50_ns=188985283
p95_ns=348877885
max_ns=349571569
```

These values include isolated namespace and process startup overhead. They are
not steady-state packet throughput, goodput, RTT, jitter, CPU, RSS, or
two-machine tunnel results.

## Windows GNU Cross-Target Validation

The `x86_64-pc-windows-gnu` target is installed. A user-space MinGW toolchain
was used for this validation run; it is not part of the repository.

The first target check exposed two real `windows-sys 0.61.2` import mistakes in
`shph-tun/src/windows.rs` (`GUID` and `FreeLibrary`). Those imports were
corrected. Strict target validation then passed:

```text
cargo check --workspace --target x86_64-pc-windows-gnu --locked --offline: PASS
cargo clippy --workspace --all-targets --target x86_64-pc-windows-gnu --locked --offline -- -D warnings: PASS
cargo build --workspace --target x86_64-pc-windows-gnu --locked --offline: PASS
```

The target Clippy pass also found and fixed one Windows-only test import and
one Windows keystore error-construction lint. The remaining native-Windows
release gates are:

- Executing the Windows workspace tests on a supported Windows host.
- Wintun DLL signer/hash provenance, administrator elevation, adapter
  creation, event handling, packet I/O, and teardown.
- Windows reparse-point and concurrent file-adapter behavior on NTFS.
- Two-machine Windows tunnel and performance evidence.

Linux native TUN source-level tests and capability-gated lifecycle evidence
remain documented in `docs/NATIVE_TUN_STATUS_2026-08-04.md`.
