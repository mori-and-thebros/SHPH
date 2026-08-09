# Internal Security Assessment Disposition

Assessment source: `docs/evidence/INTERNAL_SECURITY_ASSESSMENT_2026-08-04.md`
Assessment date: August 4, 2026
Remediation date: August 5, 2026
Workspace version: `0.5.0-dev.0`
Scope: current Linux checkout and synchronized Windows source tree

## Summary

All source-remediable findings in the security review are addressed in the
working tree. The public session constructors and responder PQ path now require
peer policy, configuration and display handling fail closed for secret
material, file adapters have bounded scans and poison-file quarantine, and the
CI fuzz loop covers the current target set.

Native Windows execution remains a host-gated release requirement. Source-level
Wintun provenance is now mandatory through `SHPH_WINTUN_SHA256`, but this Linux
environment cannot validate Authenticode behavior, Windows ACLs, adapter
creation, or packet I/O.

## Finding Register

| Finding | Disposition | Evidence |
| --- | --- | --- |
| `LUNA-HIGH-01` public APIs lacked expected-peer pinning | Fixed | `PeerPolicy` is mandatory across handshake/session APIs; responder PQ decapsulation verifies the signed hello and policy before ML-KEM work; handshake and transport regressions pass |
| `LUNA-MED-01` permissive Unix config permissions | Fixed | `Config::load` rejects group/other-readable files; tests cover `0644`, `0640`, and `0600` |
| `LUNA-MED-02` default config output exposed PINs | Fixed | Recursive redacting serializer covers `pin`, password, token, secret, and private-key naming families; CLI regression covers Shadowsocks and YubiKey PIV fields |
| `LUNA-MED-03` distributed limiter saturation rejected new sources | Fixed | Full table evicts the oldest source; regression proves a new source is admitted and the table remains bounded |
| `LUNA-MED-04` poison envelopes blocked later messages | Fixed | Claimed files with failed AEAD authentication are quarantined; malformed/base64 candidates are quarantined and later valid candidates are selected |
| `LUNA-MED-05` file scans retained excessive candidate state | Fixed | Aggregate scan bytes and candidate metadata memory are bounded; full ciphertext is not retained for every candidate |
| `LUNA-MED-06` Windows file adapters lacked safe replacement/reparse checks | Fixed in source | Reparse checks cover adapter paths; Windows replacement uses `ReplaceFileW`/write-through semantics; native Windows concurrency/reparse tests remain host-gated |
| `LUNA-MED-07` Wintun provenance was not pinned | Fixed in source | Application-local `wintun.dll` requires exact `SHPH_WINTUN_SHA256` before loading and rejects malformed/mismatched hashes |
| `LUNA-MED-08` responder file adapters decapsulated before final policy | Fixed | Responder PQ API itself verifies the peer signature and policy before decapsulation; explicit regression covers rejection before malformed PQ input |
| `LUNA-LOW-01` CI omitted `shroud2_datagram` | Fixed | CI fuzz loop enumerates `frame_decode`, `config_parse`, `audit_record`, `replay_window`, and `shroud2_datagram` |
| `LUNA-INFO-01` secret-bearing staging copies | Hardened/documented | Keystore staging structs and password holders zeroize on drop; bounded serialization/API copies remain documented as unavoidable |

## Validation

The remediation run uses these gates:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --workspace --locked
cargo check --manifest-path benchmarks/Cargo.toml --locked
cargo check --manifest-path fuzz/Cargo.toml --locked
cargo audit --no-fetch
git diff --check
scripts/sync_mirror.sh --verify
```

The sandbox denies local socket creation with `Operation not permitted`, so
socket-based TCP/QUIC tests require an approved host or escalated execution.
No network test result is reported as passing from the restricted sandbox.

## Follow-up Validation — August 5, 2026

The remaining locally feasible checks were completed after this disposition
was first written:

- `cargo audit --no-fetch` exits `0` with the same two accepted optional-TUI
  warnings; current scan size is 237 crate dependencies.
- The pinned CI nightly, `rustc 1.99.0-nightly (d0babd8b6 2026-07-15)`, is now
  installed. All five fuzz targets, including `shroud2_datagram`, pass a
  bounded `-runs=1` smoke run with sanitizers disabled, and also pass the
  default sanitizer path when LeakSanitizer reporting is disabled for the
  restricted WSL environment.
- Refreshed workspace evidence records `191 passed, 0 failed`, plus passing
  formatting, Clippy, locked build, demo, and diff checks.
- The Windows GNU target is installed, but cross-compilation remains blocked
  in this environment by the missing usable `x86_64-w64-mingw32-gcc` compiler;
  native Windows validation remains required.

The detailed command record is in
`docs/VALIDATION_FOLLOWUP_2026-08-05.md`.
