# SHPH Internal Security and Engineering Assessment

**Review type:** Internal security and engineering assessment; not an
independent audit
**Audit date:** 2026-07-29
**Audited commit:** `6a6104b7b7fb688579ff67c76df38ca341a81eeb`
**Audited description:** development hardening tree
**Workspace version:** `0.5.0-dev.0`
**Latest shipped SemVer tag observed:** `v0.4.0`

> This internal assessment covers the source state available at the reviewed
> commit and the associated development changes present at review time. It is
> not an independent audit or certification.

## 1. Findings Summary

| Severity | Count |
| --- | ---: |
| Critical | 0 |
| High | 2 |
| Medium | 4 |
| Low | 5 |
| Informational | 3 |
| **Total** | **14** |

| Area | Result |
| --- | --- |
| Known vulnerable dependencies | 0 vulnerabilities; 2 accepted warnings |
| Exposed credentials in current tracked files | 0 high-confidence secrets found |
| Exposed credentials in Git patch history | 0 high-confidence secrets found |
| Stable Rust validation | PASS |
| Reproducible demo | PASS |
| Bounded ASan fuzz campaigns | PASS; no crashes or saved artifacts |
| Native Windows runtime validation | Not available in this environment |

## 2. Executive Assessment

SHPH has a substantially stronger security core than a typical research VPN
prototype. The current handshake uses real Ed25519 transcript signatures,
mandatory identity and signing-key pinning at the CLI boundary, ephemeral X25519,
hybrid ML-KEM-768 key establishment, downgrade failure, ChaCha20-Poly1305,
bounded parsers, strict or windowed replay rejection, and zeroization of major
secret-bearing objects. The stable Linux gate suite is fully green, the
loopback demo is reproducible, and four fuzz targets completed millions of
ASan-instrumented executions without a crash.

The audit nevertheless found two High-severity issues:

1. the native Windows keystore ACL routine incorrectly interprets a
   self-relative Windows security descriptor as an absolute descriptor, creating
   an unsafe out-of-bounds pointer read and an invalid DACL pointer;
2. unauthenticated malformed traffic can consume a listener's lifetime
   handshake-attempt budget and make the process exit, so the bounded-accept
   mitigation doubles as a remotely triggerable availability kill switch.

The project should remain described as a controlled research/hardening project,
not a production VPN, until the High findings are fixed and native Windows
behavior is exercised on a real Windows runner.

**No remediation patches were applied.** This report is the only file added by
the audit.

## 3. Scope and Method

The review covered:

- all seven workspace crates;
- approximately 13,690 Rust lines in workspace crates, benchmarks, and fuzz
  harnesses;
- identity, handshake, PQ exchange, KDF, AEAD, nonce, replay, framing, and
  zeroization logic;
- TCP, experimental UDP/QUIC-like, offline-mesh, and data-mule transports;
- keystore and configuration persistence on Unix and Windows;
- TUN validation and unsafe OS boundaries;
- route/DNS control-plane construction, preflight, rollback, and shutdown paths;
- CLI trust policy, secret input/output, and audit-journal operations;
- CI, release/evidence scripts, dependency posture, and disclosure documents;
- current tracked files and Git patch history for common secret patterns;
- all stable validation gates, the full demo, and all four fuzz targets.

Threat models used:

- remote unauthenticated network attacker;
- local unprivileged or same-user hostile process;
- operator-controlled but corrupt files;
- compromised CI dependency/action;
- experimental filesystem-adapter users where the shared spool is writable by
  another process.

The review intentionally distinguishes stable TCP behavior from experimental
UDP/QUIC, offline-mesh, data-mule, Shroud, and Shamir paths, but genuine defects
in experimental code are still reported.

## 4. Validation Evidence

### 4.1 Stable gates

Toolchain:

```text
rustc 1.96.0 (ac68faa20 2026-05-25)
cargo 1.96.0 (30a34c682 2026-05-25)
cargo-audit 0.22.2
cargo-fuzz 0.13.2
host: x86_64-unknown-linux-gnu
```

| Command | Result |
| --- | --- |
| `cargo fmt --all -- --check` | PASS |
| `cargo clippy --workspace --all-targets --locked -- -D warnings` | PASS |
| `cargo test --workspace --all-targets --locked` | PASS: 147 passed, 0 failed, 0 ignored |
| `cargo build --workspace --all-targets --locked` | PASS |
| `cargo audit` | PASS with two allowed warnings |
| `git diff --check` | PASS |
| `./scripts/demo.sh all` | PASS |

The demo verified:

- authenticated encrypted loopback transfer of `demo-payload`;
- invalid CIDR rejection before control-plane mutation;
- bounded reconnect/backoff against an unreachable peer.

### 4.2 Dependency audit

`cargo audit` scanned 200 locked dependencies and found no known
vulnerabilities. It reported two warnings already documented and allowlisted in
CI:

| Advisory | Crate | Disposition |
| --- | --- | --- |
| `RUSTSEC-2024-0436` | `paste 1.0.15` | Unmaintained; transitive through optional TUI |
| `RUSTSEC-2026-0002` | `lru 0.12.5` | Unsound `IterMut`; transitive through optional TUI and affected API not used |

This disposition is reasonable for the present prototype, but the allowlist
should remain temporary and reviewed whenever `ratatui` changes.

### 4.3 Fuzzing

All fuzzing used nightly Rust, libFuzzer, ASan, temporary corpus/artifact
directories, a 10-second run budget per target after build, a three-second
per-input timeout, and no tracked-file writes.

| Target | Result | Final executions | Final coverage |
| --- | --- | ---: | --- |
| `frame_decode` | PASS | 5,238,776 | `cov: 77`, `ft: 93` |
| `config_parse` | PASS | 781,956 | `cov: 2780`, `ft: 9761` |
| `audit_record` | PASS | 3,253,191 | `cov: 1258`, `ft: 3656` |
| `replay_window` | PASS | 7,681,053 | `cov: 50`, `ft: 173` |

No crashes, sanitizer findings, timeout artifacts, or other saved artifacts were
produced.

These are useful parser/state-machine smoke campaigns, not proof of memory
safety or protocol correctness. Important coverage gaps are listed in
`SOL-INFO-02`.

## 5. High Findings

### SOL-HIGH-01 — Self-relative Windows security descriptor is dereferenced as an absolute descriptor

**Confidence:** High
**Category:** Unsafe FFI / native Windows memory safety / secret-file ACL
**Location:** `shph-core/src/keystore.rs:452`
**Primary unsafe read:** `shph-core/src/keystore.rs:485`

`ConvertStringSecurityDescriptorToSecurityDescriptorW` returns an allocated,
self-relative security descriptor. In a self-relative descriptor, the owner,
group, SACL, and DACL fields are 32-bit offsets from the beginning of the
descriptor. The code casts that buffer to the larger absolute
`SECURITY_DESCRIPTOR` representation and dereferences its pointer-valued `Dacl`
field:

```rust
(*(descriptor as *const windows_sys::Win32::Security::SECURITY_DESCRIPTOR)).Dacl
```

The Windows bindings themselves define the incompatible layouts:

```text
SECURITY_DESCRIPTOR:
  Owner, Group, Sacl, Dacl are pointers

SECURITY_DESCRIPTOR_RELATIVE:
  Owner, Group, Sacl, Dacl are u32 offsets
```

On a 64-bit process, the absolute `Dacl` field is located beyond the end of the
small relative header. The dereference can therefore read beyond the allocated
descriptor and construct a meaningless ACL pointer, which is then passed to
`SetNamedSecurityInfoW`.

**Reachability**

- called for every native Windows keystore temp file before secret bytes are
  written (`shph-core/src/keystore.rs:314-316`);
- called again on every native Windows keystore load
  (`shph-core/src/keystore.rs:499-503`);
- executes in safe public `KeyStore::save` / `KeyStore::load` call paths.

**Risk**

- native Windows process crash or access violation;
- invalid ACL application and failure to initialize or load a keystore;
- possible secret-file availability loss;
- reliance on undefined/invalid memory reads at a security boundary.

The routine generally fails closed if the API returns an error, so this is not
reported as a direct remote key-disclosure primitive. It is still High because
unsafe memory access occurs on the primary Windows identity-key path.

**Recommended remediation**

Use `GetSecurityDescriptorDacl` to retrieve the ACL pointer from either an
absolute or self-relative descriptor, then pass that returned pointer to
`SetNamedSecurityInfoW`. Alternatively, apply the complete descriptor using a
Windows API designed to consume the self-relative form.

Also:

- check `dacl_present`;
- reject a null DACL;
- free the allocated descriptor on every exit path;
- add a native Windows test that saves and reloads a keystore, inspects the DACL,
  verifies only the intended owner has access, and runs under a memory checker
  where practical.

### SOL-HIGH-02 — Malformed unauthenticated traffic can terminate the listener

**Confidence:** High
**Category:** Remote unauthenticated denial of service
**TCP locations:** `shph-transport/src/lib.rs:38`, `shph-transport/src/lib.rs:1232`
**UDP locations:** `shph-transport/src/lib.rs:31`, `shph-transport/src/lib.rs:1636`

The TCP listener binds once, accepts at most five failed handshakes, then returns
an error:

```rust
const TCP_HANDSHAKE_ATTEMPTS: usize = 5;
...
for _ in 0..TCP_HANDSHAKE_ATTEMPTS {
    ...
}
Err(last_err.unwrap_or(...))
```

The per-source limit allows eight connections per ten seconds. A single source
can therefore submit five malformed or early-closing connections—without
exceeding its rate limit—and consume the complete listener lifetime budget.
The CLI propagates the error and exits.

The experimental UDP server similarly exits after 64 invalid handshake
datagrams. Its per-IP limit makes a single-source attack harder, but a
distributed or source-spoofed datagram flood can still consume the global
lifetime counter.

**Risk**

- a remote unauthenticated attacker can stop a waiting TCP service reliably;
- a legitimate peer arriving after the fifth malformed TCP connection is never
  accepted;
- supervisors may repeatedly restart the service, enabling restart loops and
  resource churn;
- the code and documentation describe these counters as DoS mitigation, but the
  counters convert hostile input into process termination.

This matches the project's own High-severity rubric: remote crash/DoS of the
handshake path that defeats the intended bounded-accept mitigation.

**Recommended remediation**

Separate per-connection work bounds from listener lifetime:

- keep the listener alive until the operator deadline or shutdown signal;
- drop malformed connections without decrementing a global lifetime budget;
- enforce per-IP token buckets before parsing;
- enforce a bounded number of concurrent handshakes;
- cap per-handshake bytes, time, and cryptographic work;
- use a global overload mode that temporarily sheds traffic rather than exits;
- expose counters/metrics for rejected, rate-limited, timed-out, and
  authentication-failed handshakes;
- add integration tests proving that more than five malformed TCP clients cannot
  prevent a later valid pinned peer from connecting.

For UDP, track invalid budgets per source/prefix with expiry and avoid a global
invalid-datagram counter that terminates the socket.

## 6. Medium Findings

### SOL-MED-01 — ML-KEM work occurs before peer signature verification

**Confidence:** High
**Category:** Pre-authentication CPU exhaustion
**Locations:** `shph-transport/src/lib.rs:1282`, `shph-transport/src/lib.rs:1595`,
`shph-transport/src/lib.rs:1697`, `shph-core/src/handshake.rs:266`

On the TCP responder, attacker-controlled ML-KEM ciphertext is decapsulated
before `verify_and_derive` verifies the peer's Ed25519 signature. On the client
and experimental UDP initiator path, encapsulation is performed against an
attacker-supplied PQ public key before signature verification.

The existing size bounds, timeouts, per-source limits, and attempt budgets reduce
the total work, but they do not authenticate the source before the comparatively
expensive PQ operation. The High listener-exhaustion issue makes this easier to
turn into an availability attack.

**Recommendation**

Split hello validation into two phases:

1. validate protocol/profile, timestamp, encodings, signed fields, signature, and
   configured identity/signing-key policy;
2. only then perform ML-KEM encapsulation or decapsulation.

Where the transport choreography requires the PQ round trip first, add a cheap
stateless cookie or proof-of-reachability stage and stricter per-source work
accounting.

### SOL-MED-02 — Shamir coefficients are biased and exclude valid field elements

**Confidence:** High
**Category:** Cryptographic correctness
**Location:** `shph-core/src/roadmap.rs:519`

Shamir coefficients are generated as:

```rust
(rng.next_u64() % (prime - 2)) + 1
```

For the field of order 257 this samples only `1..=255`, excluding `0` and `256`,
and modulo reduction introduces additional bias because the source range is not
an exact multiple of 255. Shamir coefficients should be uniformly sampled from
the full field. A non-uniform coefficient distribution makes individual shares
non-uniform and weakens the information-theoretic property expected from the
scheme.

The impact is limited because the feature is documented as a lab primitive, not
a production KMS.

**Recommendation**

Use rejection sampling to produce a uniform integer in `0..257`, retain zero for
non-leading coefficients, and decide explicitly whether the highest polynomial
coefficient must be non-zero to enforce the advertised threshold degree. Add
property tests for reconstruction, share-domain validation, and statistical
coverage of all 257 coefficient values.

### SOL-MED-03 — Windows configuration persistence does not protect stored credentials

**Confidence:** High
**Category:** Local secret disclosure / crash consistency
**Locations:** `shph-config/src/lib.rs:60`, `shph-config/src/lib.rs:251`,
`shph-config/src/lib.rs:279`, `shph-cli/src/main.rs:912`

The configuration model can contain a plaintext Shadowsocks password. Unix saves
set mode `0600`, but the non-Unix permission routine is a no-op. The non-Unix
replacement path removes the existing file before renaming the replacement,
creating a crash window in which the configuration is absent. Windows reads also
lack the keystore's explicit symlink/reparse-point rejection.

Additionally, `show-config` serializes the complete structure and prints it to
standard output, including the Shadowsocks password.

**Risk**

- another local Windows account may read the credential depending on inherited
  directory ACLs;
- terminal capture, shell logging, support bundles, or redirected output can
  disclose the password;
- interrupted replacement can destroy the previous valid configuration.

**Recommendation**

- implement owner-only Windows ACL handling using the corrected keystore helper;
- use `ReplaceFileW`/`MoveFileExW` with write-through semantics;
- reject reparse points for the default config and temp path;
- redact secret fields in `show-config` by default and require an explicit
  `--show-secrets` confirmation for full output;
- preferably move passwords to an OS credential store or separate protected
  secret file.

### SOL-MED-04 — CI executes mutable third-party actions and unversioned tool installs

**Confidence:** High
**Category:** CI/CD supply-chain integrity
**Locations:** `.github/workflows/ci.yml:19`, `.github/workflows/ci.yml:20`,
`.github/workflows/ci.yml:38`, `.github/workflows/ci.yml:81`,
`.github/workflows/ci.yml:113`

CI uses mutable action tags such as `actions/checkout@v4`,
`dtolnay/rust-toolchain@stable`, and `Swatinem/rust-cache@v2`. It also installs
the newest available `cargo-fuzz` and `cargo-audit` releases at run time.

If an action tag, installer source, registry account, or newly released tool is
compromised, CI can execute attacker-controlled code with repository and runner
permissions. The moving Rust `stable`/`nightly` toolchains also reduce
reproducibility.

**Recommendation**

- pin actions to reviewed full commit SHAs;
- pin Rust toolchains in `rust-toolchain.toml`;
- install exact audited versions of `cargo-audit` and `cargo-fuzz`;
- use minimal `permissions:` at workflow/job level;
- enable dependency update automation for deliberate pin refreshes;
- consider artifact attestations and a `cargo-deny` license/source policy.

## 7. Low Findings

### SOL-LOW-01 — Offline-mesh scan limit counts accepted candidates, not directory entries

**Confidence:** High
**Category:** Local filesystem denial of service
**Location:** `shph-transport/src/lib.rs:2301`

The offline-mesh scanner checks `candidates.len()` against 4,096. Files that are
not regular JSON files, are malformed and quarantined, have the wrong session,
or are already seen do not increase that counter. A writable spool directory can
therefore contain an effectively unlimited number of irrelevant entries that
are statted and inspected on every poll.

The data-mule scanner correctly maintains a separate `scanned` counter at
`shph-transport/src/lib.rs:2671`; offline-mesh should use the same pattern.

**Recommendation:** count every directory entry before filtering, fail or
paginate after the cap, and use a bounded work queue rather than rescanning the
entire directory every poll.

### SOL-LOW-02 — Audit-journal export and pruning read unbounded files and lines

**Confidence:** High
**Category:** Local resource exhaustion
**Locations:** `shph-core/src/roadmap.rs:491`, `shph-core/src/roadmap.rs:635`

Both export and prune iterate over `BufRead::lines()` and accumulate every parsed
record before applying retention. A large file or a single extremely long line
can allocate excessive memory. `max_entries` is a post-read retention target,
not an input bound.

Normal owner-only operation limits exposure, but a corrupt file or another
same-user process can trigger the path.

**Recommendation:** cap file size and line size, stream only the last
`max_entries`, reject oversized records, and rotate before the journal becomes
large.

### SOL-LOW-03 — Shamir recovery reads share files without size or count bounds

**Confidence:** High
**Category:** Local resource exhaustion
**Location:** `shph-cli/src/main.rs:1000`

Secret input is capped at 64 KiB, but recovery uses `fs::read` for every
user-supplied share path and permits arbitrary arrays of shares in each file.
Oversized files or a very large path list can consume excessive memory before
validation.

**Recommendation:** bound total files, bytes per file, total decoded shares, and
decoded payload length before allocation.

### SOL-LOW-04 — Keystore PBKDF2 work factor is a fixed 100,000 iterations

**Confidence:** High
**Category:** Password-hardening / offline guessing resistance
**Location:** `shph-core/src/keystore.rs:24`

The optional encrypted keystore uses PBKDF2-HMAC-SHA256 with 100,000 iterations.
This is functional and authenticated with ChaCha20-Poly1305, but it is a fixed,
relatively inexpensive CPU-only KDF for protecting long-lived identity seeds.
Weak operator passwords remain practical offline-guessing targets if the file is
copied.

**Recommendation:** benchmark and raise the PBKDF2 work factor, or introduce a
versioned memory-hard KDF such as Argon2id with stored parameters. Preserve
backward-compatible decryption and upgrade the format on the next successful
save.

### SOL-LOW-05 — No verified direct private security contact is published

**Confidence:** High
**Category:** Vulnerability disclosure operations
**Location:** `SECURITY.md:17`

The policy explicitly states that no direct security email is published and
relies on the hosted repository's private advisory channel “when available” or
an unspecified private hosting-account mechanism.

This can delay confidential intake when the repository is mirrored, detached
from hosting, or the advisory feature is disabled.

**Recommendation:** publish a monitored security address or other stable private
contact, optionally with a PGP/age key, and test the intake process against the
documented acknowledgement SLA.

## 8. Informational Observations

### SOL-INFO-01 — Native privileged paths lack runtime verification in this audit

**Confidence:** High

The Linux gates exercised the stub/non-privileged TUN path and loopback
transports. This environment could not execute:

- native Windows keystore ACL and replacement behavior;
- Windows console-control handling;
- Windows route/DNS mutation;
- Wintun provisioning and packet flow;
- native Linux TUN operation with `CAP_NET_ADMIN`;
- destructive live route/DNS rollback scenarios.

These should be release-gated on isolated native runners.

### SOL-INFO-02 — Fuzz coverage omits the highest-risk protocol and FFI boundaries

**Confidence:** High

Existing targets cover cell decoding, TOML parsing, audit-record JSON parsing,
and the replay window. They do not directly fuzz:

- TCP/UDP hello framing and length-prefix readers;
- `Hello` decoding plus signature/profile/timestamp validation;
- ML-KEM ciphertext/public-key parsing and handshake state choreography;
- encrypted TCP/UDP frame decoders with replay state;
- keystore encrypted/plaintext parsing and iteration bounds;
- offline-mesh/data-mule directory and envelope processing;
- Shamir share decoding/reconstruction;
- control-plane CIDR, route, and DNS command generation;
- native Windows descriptor/ACL helpers.

The CI fuzz job runs only one iteration per target, which proves buildability but
not meaningful ongoing fuzzing.

### SOL-INFO-03 — Privilege separation remains absent by design

**Confidence:** High
**Locations:** `docs/RISK_MATRIX.md:20`, `docs/RISK_MATRIX.md:21`

The same CLI process can hold identity/session keys, parse network data, operate
the TUN interface, and invoke privileged control-plane changes. A memory-safety
or logic defect in any privileged path therefore has a broad blast radius.

The project already documents this as a roadmap limit. A production design
should separate a minimal privileged network/configuration helper from the
unprivileged protocol and UI processes.

## 9. Confirmed Security Strengths

The audit verified the following positive controls:

- real Ed25519 signatures bind protocol/profile, X25519 identity, Ed25519 signing
  key, ML-KEM public key, ephemeral key, nonce, and timestamp;
- configured X25519 identity and Ed25519 signing-key pinning is mandatory before
  application data is used;
- the secure-default profile combines X25519 and ML-KEM-768 shared secrets and
  fails if PQ material is absent;
- ChaCha20-Poly1305 keys and nonces are directionally separated;
- send-side nonce exhaustion fails closed before reuse;
- TCP uses strict monotonic replay rejection and UDP uses a bounded replay
  window that accepts authenticated reordering once;
- hello, frame, config, keystore, data-mule, and major packet inputs have
  explicit size bounds;
- UDP post-handshake frames are bound to the authenticated source address;
- Unix secret files use exclusive temp creation, no-follow reads, restrictive
  permissions, fsync, and atomic rename;
- Windows keystore replacement uses `ReplaceFileW`/`MoveFileExW` with
  write-through semantics, independent of the ACL extraction bug;
- session keys, cipher keys, signing seed, and major handshake intermediates are
  zeroized;
- TUN packets are capped and validated against IPv4/IPv6 declared lengths;
- control-plane inputs are preflighted before mutation and rollback is attempted;
- CI covers Linux and Windows builds/tests, demo execution, fuzz-target build
  smoke, and a blocking advisory policy;
- release documentation correctly distinguishes shipped `v0.4.0` from the
  unreleased `0.5.0-dev.0` tree;
- the evidence-capture script now records provenance, refuses dirty release
  evidence by default, and writes through a temporary file;
- no high-confidence API keys, private keys, tokens, or committed secret files
  were found in current tracked content or the inspected Git patch history.

## 10. Patch Proposals for High Findings

> **Review each patch before applying. Nothing has been changed yet.**

### Proposal A — Safely extract the Windows DACL

Replace direct descriptor casting with the platform accessor:

```rust
use windows_sys::Win32::Security::{
    GetSecurityDescriptorDacl, ACL, DACL_SECURITY_INFORMATION,
    PROTECTED_DACL_SECURITY_INFORMATION, PSECURITY_DESCRIPTOR,
};

let mut dacl_present = 0;
let mut dacl_defaulted = 0;
let mut dacl: *mut ACL = std::ptr::null_mut();
let extracted = unsafe {
    GetSecurityDescriptorDacl(
        descriptor,
        &mut dacl_present,
        &mut dacl,
        &mut dacl_defaulted,
    )
};
if extracted == 0 || dacl_present == 0 || dacl.is_null() {
    unsafe { LocalFree(descriptor as _) };
    return Err(windows_error("GetSecurityDescriptorDacl"));
}

let result = unsafe {
    SetNamedSecurityInfoW(
        path.as_ptr(),
        SE_FILE_OBJECT,
        DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
        std::ptr::null_mut(),
        std::ptr::null_mut(),
        dacl,
        std::ptr::null(),
    )
};
unsafe { LocalFree(descriptor as _) };
```

A small RAII guard for `LocalFree` is preferable so future early returns cannot
leak the descriptor.

### Proposal B — Keep listeners alive while bounding hostile work

Restructure TCP acceptance around the overall deadline instead of a fixed number
of hostile clients:

```rust
while Instant::now() < deadline {
    let (mut stream, peer_addr) = accept_until_deadline(&listener, deadline)?;

    if rate_limiter.check_and_record(peer_addr).is_err() {
        continue;
    }

    match perform_bounded_authenticated_handshake(
        &mut stream,
        peer_addr,
        local_identity,
        profile,
        deadline,
    ) {
        Ok(state) => return Ok((stream, state)),
        Err(err) if is_peer_input_error(&err) => {
            metrics.rejected_handshakes += 1;
            continue;
        }
        Err(err) => return Err(err),
    }
}
Err(ShphError::Timeout)
```

Apply equivalent logic to UDP:

- per-source expiring invalid counters;
- no global invalid count that returns from the server;
- bounded concurrent/authentication work;
- temporary load shedding at global capacity;
- valid-peer-after-flood regression tests.

## 11. Prioritized Remediation Plan

### Before native Windows distribution

1. Fix `SOL-HIGH-01`.
2. Add native Windows ACL, reparse-point, replacement, and load/save tests.
3. Apply equivalent ACL/atomic handling to configuration and Shamir secret files.

### Before the next security/funding checkpoint

1. Fix `SOL-HIGH-02`.
2. Move authentication or a stateless cookie ahead of ML-KEM work.
3. Correct Shamir coefficient sampling.
4. Pin CI actions/toolchains/tools and set minimal workflow permissions.
5. Add focused handshake and encrypted-frame fuzz targets.

### Defense-in-depth backlog

1. Bound audit journal and Shamir recovery inputs.
2. Fix the offline-mesh scan counter.
3. Upgrade the encrypted-keystore KDF policy.
4. Publish and test a stable private vulnerability contact.
5. Continue privilege-separation design work.

## 12. Limitations

This was a source review plus local Linux execution, not:

- a formal cryptographic proof;
- an independent audit of `ring`, RustCrypto, `x25519-dalek`, or the ML-KEM
  implementation;
- a side-channel or constant-time laboratory assessment;
- a native Windows penetration test;
- a privileged TUN/control-plane test on disposable hosts;
- a long-duration, coverage-measured fuzzing campaign;
- a distributed denial-of-service simulation;
- a full Git hosting, branch-protection, token-permission, or organization
  configuration review;
- a wireless/offline delivery-system review.

Absence of a reported issue does not prove absence of vulnerabilities.

## 13. Final Opinion

The current tree is technically credible as a transparent secure-transport
research project. Its stable Linux tests, demo, parser bounds, authentication,
hybrid key establishment, replay handling, and secret zeroization are meaningful
strengths.

It is not ready for production-native Windows use until the security-descriptor
bug is corrected and tested. It is also not robust against even a small
unauthenticated TCP nuisance flood because the listener's safety budget can be
used to terminate it.

After the two High findings are fixed, the Medium items should be addressed
before expanding operational claims. The current documentation's conservative
non-claims are appropriate and should remain in force.
