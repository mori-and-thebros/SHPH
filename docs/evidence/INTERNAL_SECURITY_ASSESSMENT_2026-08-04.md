# SHPH Internal Security and Engineering Assessment

**Review type:** Internal security and engineering assessment; not an
independent audit
**Audit date:** August 4, 2026
**Audited branch:** `master`
**Audited `HEAD`:** `3fd2e44a81536fd4b90f7ca2881fcffbba5dca56`
**Workspace version:** `0.5.0-dev.0`
**Latest shipped SemVer tag observed:** `v0.4.0`

> This internal assessment covers the development source state available at the
> reviewed revision. Platform-specific lockfile differences are documented
> separately. It is not an independent audit or certification.

## 1. Findings Summary

| Severity | Count |
| --- | ---: |
| Critical | 0 |
| High | 1 |
| Medium | 8 |
| Low | 1 |
| Informational | 1 |
| **Total** | **11** |

The two Windows-specific findings are classified as conditional Medium findings:
they require native Windows execution and either filesystem/application-directory
control. The stable CLI remains materially safer than the low-level library
surface because it applies configured peer pinning before using a session.

| Area | Result |
| --- | --- |
| Known dependency vulnerabilities | 0; 2 accepted advisory warnings |
| High-confidence committed production secrets | None found |
| Stable Rust validation | PASS |
| Standards-QUIC tests | 6 passed |
| Fuzz workspace check | PASS |
| Demo and mirror parity | PASS |
| Native Windows runtime validation | Not available in this environment |

## 2. Executive Assessment

SHPH is a serious research and hardening project with a substantially improved
cryptographic core. The current implementation uses separate X25519 and Ed25519
keys, real Ed25519 transcript signatures, hybrid X25519/ML-KEM-768 key
establishment, ChaCha20-Poly1305 framing, replay protection, explicit input
bounds, atomic secret-file writes, and zeroization of major key-bearing
objects. The previous Windows ACL descriptor bug and listener-kill issue from
the earlier security review are fixed in the current tree.

The primary current concern is **trust-policy separation**: the public
handshake/transport library APIs authenticate whichever identity and signing key
the remote endpoint advertises, but do not require callers to provide the
expected peer identity. The CLI adds that missing authorization check, while
library and future embedding callers can accidentally treat self-authentication
as peer authentication.

The remaining findings are mostly defense-in-depth and availability issues in
optional configuration, filesystem-backed lab adapters, and native Windows
integration. The tree is suitable for controlled research and staged
engineering, but should not be marketed as a production VPN or production
filesystem-messaging system until the trust boundary is made mandatory and the
native Windows paths are tested on Windows.

**No source remediation was applied. This file is the only audit artifact added
by this run.**

## 3. Scope and Method

The review covered:

- all workspace crates, benchmarks, fuzz targets, scripts, CI, and security
  documentation;
- identity, handshake, signing, X25519, ML-KEM-768, KDF, AEAD, nonce, replay,
  framing, and zeroization logic;
- TCP, experimental UDP/QUIC-like, standards-QUIC, offline-mesh, and data-mule
  transports;
- configuration and keystore persistence, permissions, atomic replacement, and
  secret display;
- CLI peer policy, control-plane, route/DNS validation, shutdown, and Shamir
  operations;
- native Windows Wintun loading and Windows-specific filesystem branches;
- dependency advisories, CI supply-chain posture, secret-like content, Git
  state, and mirror parity;
- stable formatting, linting, tests, locked build, standards-QUIC tests, fuzz
  workspace checking, audit, demo, and parity commands.

Threat models considered:

- remote unauthenticated network attacker;
- distributed source/IP flood against a listener;
- local unprivileged or same-user hostile process;
- another process that can write an optional filesystem adapter directory;
- malformed or oversized operator-controlled files;
- compromised or substituted native Windows runtime files;
- CI dependency/action compromise;
- library or embedded callers that bypass the CLI trust-policy layer.

This was a source and local-execution audit, not a formal cryptographic proof,
side-channel audit, production penetration test, or native Windows execution
campaign.

## 4. Validation Evidence

| Command or check | Result |
| --- | --- |
| `cargo fmt --all -- --check` | PASS |
| Offline workspace clippy with warnings denied | PASS |
| Offline `cargo test --workspace` | PASS: 188 passed, 0 failed |
| `cargo build --workspace --locked` | PASS |
| Standards-QUIC test set | PASS: 6 passed |
| Fuzz workspace check | PASS |
| `cargo audit --no-fetch` | PASS: 0 vulnerabilities |
| `scripts/demo.sh all` | PASS |
| `scripts/sync_mirror.sh --verify` | PASS |
| `git diff --check` | PASS |

`cargo audit --no-fetch` reported two accepted warnings:

| Advisory | Dependency | Disposition |
| --- | --- | --- |
| `RUSTSEC-2024-0436` | `paste 1.0.15` | Unmaintained; transitive through optional TUI |
| `RUSTSEC-2026-0002` | `lru 0.12.5` | Unsound `IterMut`; transitive through optional TUI and affected API not observed in use |

These warnings should remain explicitly tracked and re-evaluated when the
optional TUI dependency graph changes.

## 5. High Finding

### LUNA-HIGH-01 — Public handshake APIs do not require expected-peer pinning

**Confidence:** High
**Category:** Authentication policy / trust-boundary failure
**Locations:**

- `shph-core/src/handshake.rs:196-202`
- `shph-core/src/handshake.rs:205-268`
- `shph-transport/src/lib.rs:1091-1175`
- `shph-transport/src/standards_quic.rs:249-354`
- `shph-cli/src/main.rs:1955-2015`

`verify_hello_signature` validates a signature using the `sign_pub_b64` key
advertised inside the peer's own `Hello`. `verify_and_derive` then returns a
usable `HandshakeState` containing the advertised peer identity and signing
key. Neither function accepts an expected peer identity or an expected signing
public key.

The low-level transport APIs consequently authenticate **key possession**, but
do not authenticate that the peer is the operator-configured peer. A remote
endpoint can generate its own valid X25519 and Ed25519 key pair, sign a valid
hello, and complete the library handshake with a caller that does not perform a
second policy check.

The CLI does perform the missing authorization step in
`enforce_peer_policy`: it matches both the X25519 fingerprint and the pinned
Ed25519 signing key before session use. This substantially protects the shipped
CLI, but it does not make the public library APIs safe-by-default for embedders,
future daemons, standards-QUIC callers, or alternate frontends.

**Impact**

- A library consumer can connect to an attacker-controlled endpoint and treat
  the resulting authenticated session as the intended peer session.
- The attacker does not need to forge Ed25519 or break X25519; it only needs to
  supply a different self-generated identity.
- The issue is an identity authorization failure, not a failure of the current
  Ed25519 primitive.
- The risk is highest for callers that use `tcp_connect_and_handshake`,
  UDP/QUIC-like APIs, standards-QUIC APIs, or filesystem adapters directly and
  then use the returned session without applying CLI-equivalent policy.

**Recommended remediation**

1. Introduce a first-class `PeerPin` or `PeerPolicy` type containing the
   expected X25519 identity public key and Ed25519 signing public key.
2. Require that policy in every API that returns a data-plane session or
   `HandshakeState`.
3. Compare the expected keys immediately after decoding and verifying the hello,
   before ML-KEM encapsulation/decapsulation and before returning a session.
4. For listeners, accept an explicit allowlist or policy callback rather than a
   single optional key.
5. Rename any intentionally low-level unauthenticated API to make its status
   explicit, such as `*_unverified`, and document that it must not carry
   application data.
6. Add tests proving that a correctly signed but unexpected identity is rejected
   before PQ work and before any data-plane handle is exposed.

## 6. Medium Findings

### LUNA-MED-01 — Unix configuration loading accepts leaky file permissions

**Confidence:** High
**Category:** Local secret disclosure
**Locations:** `shph-config/src/lib.rs:131-157`, `shph-config/src/lib.rs:203-210`

On Unix, `open_config_readonly` uses `O_NOFOLLOW` but does not inspect file
permission bits. `Config::load` therefore accepts a configuration readable by
group or other users. The configuration model can contain a plaintext
Shadowsocks password and roadmap identity-provider fields such as a PIV PIN.

The save path creates new files with mode `0600`, but an operator, deployment
tool, or local attacker can change the mode afterward. The read boundary should
fail closed rather than trusting the previous save behavior.

**Reproduction:** during the audit, a valid configuration changed to mode
`0644` was accepted by `show-config` and the command exited successfully.

**Remediation:** call the existing owner-only permission enforcement helper on
Unix during config load, reject any `mode & 0o077 != 0`, and add a regression
test for `0644`, `0640`, and `0600` cases. Apply equivalent directory checks
where the deployment threat model requires them.

### LUNA-MED-02 — Default `show-config` output exposes roadmap PIN fields

**Confidence:** High
**Category:** Local secret disclosure / operator-output handling
**Locations:** `shph-cli/src/main.rs:1041-1052`, `shph-core/src/roadmap.rs:212-217`

`handle_show_config` redacts only the Shadowsocks password. It serializes the
entire remaining configuration, including `roadmap.identity.pin` for a
`yubikey_piv` configuration. The default output path therefore exposes a
credential-like field to terminals, shell logs, CI artifacts, support bundles,
and redirected files.

The audit reproduced this behavior with a non-production fixture containing
`pin = "123456"`; the value appeared in normal `show-config` output without an
explicit secret-display flag.

**Remediation**

- Redact all credential-like fields, including roadmap PIV PINs, by default.
- Prefer a custom redacting serializer over field-by-field mutation so new
  secret fields do not silently become printable.
- Keep `--show-secrets` opt-in, emit a warning, and avoid exposing secrets in
  logs or error messages.
- Do not store hardware PINs in the general configuration if an OS credential
  or hardware-provider prompt can be used.

### LUNA-MED-03 — Peer rate-limit table rejects new sources after 1,024 entries

**Confidence:** High
**Category:** Distributed availability exhaustion
**Locations:** `shph-transport/src/lib.rs:39`, `:1178-1255`

`PeerRateLimiter` stores one entry per source IP in an unbounded-by-policy
`HashMap` capped at `MAX_QUIC_TRACKED_PEERS = 1024`. Once the table contains
1,024 active source IPs, a new source receives `ResourceExhausted` before its
connection is processed. The same limiter is used by both the TCP and
experimental UDP/QUIC-like entry paths.

An attacker able to distribute traffic across enough source addresses can fill
the table with one connection per source and cause legitimate new peers to be
rejected until entries age out of the ten-second window. The existing per-source
limit protects against a single noisy address but does not prevent this
distributed admission failure.

**Remediation**

- Use an expiring bounded LRU or prefix-aware admission structure with explicit
  overload behavior.
- Avoid making table saturation equivalent to rejecting every new source.
- Aggregate IPv6 sources by a documented prefix where appropriate.
- Reserve capacity or use a stateless cookie/proof-of-reachability path for
  legitimate new peers.
- Add a distributed-source test that fills the table and proves service
  recovery without process restart.

### LUNA-MED-04 — Auth-invalid filesystem envelopes remain queued and can block later messages

**Confidence:** High
**Category:** Optional-adapter availability / poison-message denial of service
**Locations:**

- `shph-transport/src/lib.rs:2170-2178`
- `shph-transport/src/lib.rs:2214-2224`
- `shph-transport/src/lib.rs:2487-2492`
- `shph-transport/src/lib.rs:2332-2397`
- `shph-transport/src/lib.rs:2605-2667`

Offline-mesh and data-mule polling identify a syntactically valid envelope and
return its decoded ciphertext. The receiver attempts AEAD decryption and only
then commits the sequence/envelope and removes the file. If authentication
fails, the decrypt error is returned before the file is quarantined or removed.

Because candidates are sorted and the oldest or lowest-identity candidate is
retried, a malformed-but-parseable or wrong-key envelope can remain at the head
of the queue and prevent later valid messages from being delivered. This
requires another process to write the shared spool/inbox and is within the
documented lab-adapter threat boundary, but it remains a real availability
failure.

**Remediation**

- Quarantine an envelope after an authenticated-decrypt failure rather than
  retrying it forever.
- Use bounded retry metadata if transient corruption must be retried.
- Atomically claim files before processing to prevent multi-reader races.
- Ensure poison files cannot block later candidates.
- Add tests with an invalid first envelope followed by a valid envelope for
  both adapters.

### LUNA-MED-05 — File adapters can retain roughly 1 GiB of parsed envelopes

**Confidence:** High
**Category:** Local resource exhaustion
**Locations:** `shph-transport/src/lib.rs:114-116`, `:2332-2381`,
`:2605-2624`, `:2688-2743`

Each file is limited to `256 KiB` and each scan is limited to `4,096` entries,
but the adapters retain parsed envelopes in a `Vec` before selecting a frame.
An attacker-controlled queue containing 4,096 valid-looking files can therefore
cause the process to retain close to:

```text
4,096 * 256 KiB ~= 1 GiB
```

The actual allocation varies with JSON and base64 overhead, but the important
property is that the per-file and per-entry limits do not impose an aggregate
memory limit. The data-mule walker also recursively collects candidates across
directories.

**Remediation**

- Add an aggregate scan-byte and aggregate-candidate-memory budget.
- Process entries in bounded batches or stream only the best candidate.
- Avoid retaining full ciphertext strings for every candidate.
- Stop scanning before the aggregate budget is exhausted and report a bounded
  resource error.
- Add a regression test for many maximum-sized envelopes.

### LUNA-MED-06 — Windows file adapters lack reparse-safe reads and atomic replacement

**Confidence:** Medium
**Category:** Conditional Windows filesystem integrity
**Locations:** `shph-transport/src/lib.rs:137-181`, `:202-215`,
`:2345-2358`, `:2711-2719`

The transport file adapter's non-Unix `open_readonly_nofollow` implementation
falls back to ordinary `File::open`, which does not provide Unix-style
`O_NOFOLLOW` semantics. The directory scanners check ordinary symlink metadata,
but Windows reparse points require explicit handling and are not equivalent to a
portable symlink check.

The Windows write path also falls back from `rename` to deleting the target and
then renaming the temporary file. This creates a crash window in which the
original envelope is gone and leaves a time-of-check/time-of-use opportunity
for a hostile directory owner.

**Remediation**

- Reuse a Windows reparse-point-safe open/validation helper for every read.
- Reject reparse points on the file, parent directory, and adapter root where
  required by the threat model.
- Replace delete-then-rename with `ReplaceFileW` or a write-through equivalent.
- Apply explicit directory ownership/ACL requirements to optional inbox/spool
  roots.
- Add native Windows tests for reparse points, replacement interruption, and
  concurrent readers.

### LUNA-MED-07 — Wintun loading requires a signature but does not pin provenance

**Confidence:** Medium
**Category:** Conditional Windows native-code supply chain
**Locations:** `shph-tun/src/windows.rs:65-100`, `:369-379`

This is a historical pre-remediation observation. The current implementation
pins the application-local runtime by SHA-256, while the Windows validator
requires a valid Authenticode signature before deployment. The strict
signed-target loader flag described below was removed after the official
Wintun runtime was rejected by this host with Win32 error `577`.

The loader restricts the runtime path to an application-local `wintun.dll` and
uses `LOAD_LIBRARY_REQUIRE_SIGNED_TARGET`. This is a meaningful control, but it
accepts any DLL that Windows considers signed and does not verify the expected
Wintun publisher, certificate chain, release version, or hash. A different
validly signed DLL with the required exports could be loaded if an attacker can
write the application directory or influence deployment.

**Remediation**

- Verify Authenticode signer identity against an operator-maintained allowlist.
- Pin a vendor release/version and expected hash in a signed deployment manifest.
- Ensure the application directory is owner/admin controlled.
- Fail closed on missing, stale, or unexpected runtime provenance.
- Add a native Windows test that rejects a correctly exported but wrong-signer
  or wrong-hash DLL.

### LUNA-MED-08 — File-adapter responders decapsulate PQ ciphertext before final signature verification

**Confidence:** High
**Category:** Optional-adapter pre-authentication CPU exhaustion
**Locations:** `shph-transport/src/lib.rs:453-475`, `:539-562`,
`:628-658`, `:727-758`

The offline-mesh and data-mule responder paths receive a peer `Hello`, send the
local hello, read the peer's ML-KEM ciphertext, and call
`absorb_responder_pq` before calling `verify_and_derive`. The latter performs
the Ed25519 signature verification. In contrast, the TCP, UDP/QUIC-like, and
standards-QUIC paths verify the peer hello before performing the expensive PQ
operation.

An attacker who can write to the shared lab spool/inbox can therefore submit
syntactically valid responder ciphertexts that trigger ML-KEM decapsulation
before the peer's signature is checked. File size and timeout bounds limit each
attempt, but repeated poison envelopes can consume CPU and keep the responder
busy. This is limited to the documented filesystem-backed lab adapters and is
not a cryptographic forgery.

**Remediation**

- Verify the peer hello and configured peer policy before accepting or
  decapsulating the follow-up ciphertext.
- Carry the expected peer identity/signing-key policy into the file-adapter
  handshake API rather than relying on a later CLI check.
- Quarantine or consume invalid follow-up ciphertexts so they cannot be retried
  indefinitely.
- Add tests proving that an invalid signature causes no PQ decapsulation and
  that a poisoned first envelope cannot block a later valid handshake.

## 7. Low Finding

### LUNA-LOW-01 — CI fuzz loop omits the `shroud2_datagram` target

**Confidence:** High
**Category:** Assurance and regression coverage
**Location:** `.github/workflows/ci.yml:83-88`

The repository contains the `shroud2_datagram` fuzz target, but the CI loop runs
only:

```text
frame_decode config_parse audit_record replay_window
```

The omitted target can compile locally and still fail to build or execute in CI.
This is not a direct production vulnerability, but it leaves the newer
authenticated Shroud framing path outside the advertised fuzz smoke gate.

**Remediation:** enumerate all fuzz targets from the workspace or add
`shroud2_datagram` explicitly, and retain a meaningful bounded smoke run rather
than treating one iteration as coverage evidence.

## 8. Informational Observation

### LUNA-INFO-01 — Secret-bearing APIs still create ordinary copies

**Confidence:** High
**Category:** Secret lifetime and memory hygiene
**Locations:**

- `shph-core/src/crypto.rs:23-29`, `:65-109`
- `shph-core/src/keystore.rs:44-80`, `:114-133`
- `shph-cli/src/main.rs:1121-1127`, `:1153-1189`

The project zeroizes several important objects, but secret material can still be
copied into ordinary arrays and `String` values through public APIs such as
`private_key_bytes`, `private_key_b64`, `signing_seed`, cloning of
`IdentityKeyPair`/`KeyStore`, and serialization staging in `KeyStore::save`.
Some temporary buffers are wrapped in `Zeroizing`, but not every public copy or
serialized representation has equivalent lifetime guarantees.

This is defense-in-depth rather than a demonstrated remote disclosure.

**Remediation:** reduce or isolate raw secret-returning APIs, avoid deriving
`Clone` for secret holders where practical, use `Zeroizing<Vec<u8>>` for
temporary secret buffers, and document which serialization paths necessarily
create plaintext copies.

## 9. Dependency and Secrets Review

### Dependency posture

- `cargo audit --no-fetch` found no known vulnerabilities in the locked set.
- `paste` is an unmaintained optional-TUI transitive dependency.
- `lru` carries the accepted `IterMut` unsoundness advisory through the optional
  TUI dependency chain; the affected API was not observed in use.
- CI checkout, Rust toolchains, and audit/fuzz tool versions are pinned in the
  current workflow.

### Secret scan

The audit scanned current tracked content, relevant untracked source/configuration
files, CI/scripts, documentation, and inspected Git patch history for common
private-key, API-key, token, password, and cloud-credential patterns.

- No high-confidence production API keys, private keys, access tokens, or
  committed credential files were found.
- `SHPH_KEYSTORE_PASSWORD` is an expected runtime environment variable, not a
  committed credential.
- Test/example values are not treated as production secrets.
- The roadmap PIN and config permission findings are **handling** problems:
  configured operator secrets can be exposed even though no real credential was
  found in the repository.

## 10. Confirmed Security Strengths

The current tree contains the following meaningful controls:

- separate X25519 and Ed25519 key roles with real detached Ed25519 handshake
  signatures;
- signature coverage for protocol/profile, identity, signing key, PQ material,
  ephemeral key, nonce, and timestamp;
- TCP, UDP/QUIC-like, standards-QUIC, and initiator file-adapter paths verify
  the peer signature before the ML-KEM operation;
- hybrid X25519 plus ML-KEM-768 derivation fails closed when PQ material is
  missing;
- directional ChaCha20-Poly1305 session keys and nonce exhaustion protection;
- TCP strict replay rejection and experimental UDP replay-window handling;
- bounded hello, frame, config, keystore, envelope, Shamir, and TUN inputs;
- CLI enforcement of both configured X25519 identity and Ed25519 signing-key
  pins before application data use;
- Unix keystore owner-only permissions, no-follow reads, fsync, and atomic
  replacement;
- Windows keystore/config ACL and replacement fixes from the previous audit;
- listener deadline bounds that no longer terminate the service after a fixed
  number of malformed peers;
- malformed file quarantine and bounded directory traversal for many file-path
  cases;
- Shamir input and recovery bounds;
- control-plane preflight validation and best-effort rollback;
- standards-QUIC loopback coverage with 6 passing tests;
- green formatting, clippy, tests, locked build, demo, audit, and mirror gates.

The main caveat is that CLI policy enforcement must not be mistaken for a
mandatory property of the public library APIs.

## 11. Historical Findings Not Repeated

The following earlier findings were checked against the current tree and are not
re-reported as open findings:

- the Windows self-relative security-descriptor/DACL extraction bug is replaced
  by `GetSecurityDescriptorDacl` with descriptor cleanup;
- the malformed-peer listener lifetime-kill behavior is replaced by a
  deadline-bounded accept loop that continues after bad peers;
- ML-KEM work is gated by hello signature verification in the network and
  initiator file-adapter paths; the responder file-adapter ordering gap is
  reported as `LUNA-MED-08`;
- biased Shamir coefficient generation and earlier unbounded Shamir inputs have
  received follow-up hardening;
- mutable CI checkout/tooling concerns have been addressed in the current
  workflow;
- the earlier CLI Shamir secret-in-argument/output issue is no longer present.

Native Windows execution is still required to validate the fixes in practice.

## 12. High Finding Patch Proposal

> Review this proposal before applying. Nothing has been changed in source code.

### Proposed API shape

Add an explicit peer pin type in `shph-core`:

```rust
pub struct PeerPin {
    pub identity_public: [u8; 32],
    pub signing_public: [u8; 32],
}
```

Add a policy-aware verification function:

```rust
pub fn verify_hello_signature_pinned(
    local_identity: &IdentityKeyPair,
    material: &HandshakeMaterial,
    peer_hello: &Hello,
    expected: &PeerPin,
) -> Result<()> {
    verify_hello_signature(local_identity, material, peer_hello)?;

    let peer_identity = decode_32(&peer_hello.identity_pub_b64, "peer identity")?;
    let peer_signing = decode_32(&peer_hello.sign_pub_b64, "peer signing key")?;
    if peer_identity != expected.identity_public || peer_signing != expected.signing_public {
        return Err(ShphError::Auth("peer is not pinned".into()));
    }
    Ok(())
}
```

Use this function immediately after reading a peer hello, before
`finalize_initiator_pq` or `absorb_responder_pq`. Then require the same policy in
the public TCP, UDP/QUIC-like, standards-QUIC, offline-mesh, and data-mule
session constructors. Listener APIs should accept an allowlist or policy
callback.

The CLI should load its `Contact` pin into `PeerPin` and pass it through the
transport call instead of performing policy only after the library returns a
complete handshake. Keep a deliberately named low-level escape hatch only for
test/protocol tooling, never for application-data session constructors.

Required regression coverage:

1. a valid signature from an unexpected identity is rejected;
2. a valid identity with an unexpected signing key is rejected;
3. rejection happens before PQ encapsulation/decapsulation;
4. no data-plane handle is returned after policy failure;
5. CLI and standards-QUIC paths continue to accept correctly pinned peers.

## 13. Release Recommendation

Do not cut a new production-facing or funding-facing release from this dirty
tree without:

1. making peer pinning mandatory at the library/session boundary;
2. fixing config permission checks and secret-field redaction;
3. adding aggregate file-adapter resource limits and poison-file handling;
4. validating the Windows file adapters and Wintun provenance on a native
   Windows runner;
5. adding `shroud2_datagram` to the CI fuzz gate;
6. refreshing evidence against a clean, immutable, tagged source tree.

Until then, describe SHPH as a controlled research/hardening project with a
secure CLI profile, not as a production VPN or hostile-filesystem transport.
