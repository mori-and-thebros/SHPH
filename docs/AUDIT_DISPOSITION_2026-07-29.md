# Internal Security Assessment Disposition

Assessment source: `docs/evidence/INTERNAL_SECURITY_ASSESSMENT_2026-07-29.md`
Assessment date: July 29, 2026
Remediation tree: `0.5.0-dev.0`
Scope: non-native-TUN workspace implementation

Follow-up hardening pass: August 4, 2026. The original CLI-focused Shamir
finding was already fixed; this follow-up extends the same bounds to the
public core API.

## Summary

Both High findings are fixed. The four Medium findings and four actionable Low
findings are fixed with focused code changes and regression coverage. Native
Windows execution remains deferred because this Linux environment cannot run
the Windows ACL/runtime tests. The stable private security contact remains an
operator-owned release task; no unverified address was invented.

## Finding Register

| Finding | Disposition | Evidence |
| --- | --- | --- |
| `SOL-HIGH-01` Windows self-relative ACL dereference | Fixed | `GetSecurityDescriptorDacl` now extracts the ACL safely; descriptor memory is freed on all paths; Windows keystore round-trip regression added in `shph-core/src/keystore.rs` |
| `SOL-HIGH-02` malformed traffic terminates listener | Fixed | TCP listener is deadline-bounded and continues after malformed peers; UDP invalid hello datagrams are dropped until deadline; `tcp_listener_survives_malformed_peer_flood` covers six malformed peers followed by a valid peer |
| `SOL-MED-01` ML-KEM before signature verification | Fixed | `verify_hello_signature` is required by `finalize_initiator_pq` before encapsulation and by responder transport paths before decapsulation |
| `SOL-MED-02` biased Shamir coefficients | Fixed | Rejection sampling covers all field values `0..=256`; payload/domain bounds remain enforced; round-trip and invalid-domain tests remain green |
| `SOL-MED-03` Windows config secret persistence | Fixed in code | Config load/save now rejects reparse points, applies owner-only Windows ACLs, uses `ReplaceFileW`/`MoveFileExW` write-through replacement, and redacts Shadowsocks passwords in `show-config` unless `--show-secrets` is supplied |
| `SOL-MED-04` mutable CI supply chain | Fixed in workflow | Checkout is pinned to a full commit SHA; Rust stable/nightly versions and `cargo-audit`/`cargo-fuzz` versions are pinned; workflow permissions are read-only |
| `SOL-LOW-01` offline scan counts accepted candidates | Fixed | Offline scanning counts every directory entry before filtering |
| `SOL-LOW-02` unbounded audit journal reads | Fixed | File, line, and entry limits are enforced; pruning keeps a bounded tail with `VecDeque` |
| `SOL-LOW-03` unbounded Shamir recovery input | Fixed and strengthened | File count, per-file bytes, total bytes, decoded share count, and share payload limits are enforced in the CLI; `shph-core` now also bounds public split input, decoded payload bytes, aggregate recovery material, and policy share count |
| `SOL-LOW-04` fixed low PBKDF2 work factor | Fixed | New encrypted keystores use 600,000 iterations; legacy values from 100,000 through the maximum remain decryptable |
| `SOL-LOW-05` no stable private security contact | Operator-dependent | No contact address is available to verify or publish safely; `SECURITY.md` keeps the private-advisory guidance and requires the project owner to replace it with a monitored channel before public release |
| `SOL-INFO-01` native privileged paths unvalidated | Deferred | Native Windows ACL/runtime and native-TUN execution require the operator's native hosts; native TUN remains outside this phase |
| `SOL-INFO-02` fuzz coverage gaps | Partially addressed / backlog | Existing fuzz targets remain green; broader hello, keystore, envelope, and Shamir targets are future hardening work |
| `SOL-INFO-03` privilege separation absent | Accepted design backlog | Documented in the risk matrix; requires architectural work beyond this remediation pass |

## Validation

Required post-remediation commands:

```text
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --workspace --locked
cargo check --manifest-path fuzz/Cargo.toml --locked
cargo audit --no-fetch
git diff --check
scripts/sync_mirror.sh --verify
```

Native Windows ACL execution is a required follow-up release gate, not a claim
made by this Linux validation run.
