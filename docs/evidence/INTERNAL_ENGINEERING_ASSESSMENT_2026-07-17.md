# SHPH Internal Engineering and Security Assessment

**Review type:** Internal engineering and security assessment; not an
independent audit
**Audit date:** 2026-07-17
**Scope:** SHPH source tree at the review commit
**Review state:** development tree, including changes present at review time
**Latest SemVer tag observed:** `v0.4.0`

## 1. Executive Summary

SHPH is a serious, unusually transparent secure-transport prototype with meaningful
security engineering already present. The cryptographic design has improved
substantially: the current implementation uses real Ed25519 handshake signatures,
X25519 ephemeral key agreement, hybrid ML-KEM-768 key establishment,
ChaCha20-Poly1305 data protection, peer-key pinning, bounded parsing, timeout
budgets, replay rejection, secret-file protections on Unix, and broad regression
coverage.

I did not find evidence of the old critical unauthenticated-handshake defect in the
current code. The live Linux/WSL validation gates passed:

- formatting passed;
- clippy passed with warnings denied;
- 116 tests passed, 0 failed, 0 ignored;
- the locked workspace build passed;
- parity between the configured Linux and Windows checkouts passed;
- `cargo audit` reported 0 known vulnerabilities and 2 accepted warnings.

However, I do **not** consider the current working tree release-ready or suitable
for a new funding checkpoint yet. The most important problems are release
assurance and operational integrity:

1. the mandatory reproducible demo is broken;
2. CI watches `main`, while the repository is actually on `master`;
3. evidence files are not tied to a clean commit or exact source-tree identity;
4. thousands of lines of unreleased changes still identify themselves as version
   `0.4.0`;
5. native Windows secret-file guarantees are materially weaker than Unix;
6. a Shamir command exposes secrets through process arguments and standard output.

**Overall opinion:** technically promising and fundable as a controlled
research/hardening project, but not ready to be represented as a production VPN.
The code quality is stronger than the release process around it. Fixing the first
four findings would sharply improve external-review credibility.

## 2. Scope and Method

The assessment covered:

- workspace and dependency configuration;
- Git tags, branch state, dirty-tree state, and release documentation;
- CI and evidence-generation scripts;
- cryptographic identity, handshake, KDF, AEAD, nonce, replay, and keystore code;
- TCP and experimental UDP/“QUIC-like” transport paths;
- offline-mesh and data-mule adapter boundaries;
- TUN packet validation;
- CLI peer policy, shutdown, control-plane, and secret-handling paths;
- documentation consistency and funding-readiness claims;
- test, build, lint, audit, demo, and mirror-parity execution.

This was a source and local-execution audit, not a formal cryptographic proof,
penetration test, fuzzing campaign, side-channel assessment, or independent
review of the `ring`, RustCrypto, or ML-KEM implementations.

Native Windows execution was not available from this environment. The Windows
path was inspected through WSL/DrvFS. Windows console handling, Windows ACLs,
native route/DNS mutation, and Wintun behavior therefore remain operator
verification items.

## 3. Validation Results

| Check | Result | Notes |
| --- | --- | --- |
| `cargo fmt --all -- --check` | PASS | No formatting differences |
| `cargo clippy --workspace --all-targets -- -D warnings` | PASS | No clippy warnings |
| `cargo test --workspace` | PASS | 116 passed, 0 failed, 0 ignored |
| `cargo build --workspace --locked` | PASS | Lockfile-respecting build succeeded |
| `git diff --check` | PASS | No whitespace-error findings |
| `cargo audit` | PASS WITH WARNINGS | 0 vulnerabilities; `paste` unmaintained and `lru` unsound warning |
| `scripts/sync_mirror.sh --verify` | PASS | Configured Linux and Windows checkouts matched, excluding documented exclusions |
| `scripts/demo.sh bad-cidr` | PASS | Invalid CIDR failed closed |
| `scripts/demo.sh unreachable` | PASS | Bounded reconnect behavior reproduced |
| `scripts/demo.sh all` | **FAIL** | Happy-path demo stops at `add-peer` argument validation |

The two `cargo audit` warnings are transitive through the optional TUI:

- `RUSTSEC-2024-0436`: `paste 1.0.15` is unmaintained;
- `RUSTSEC-2026-0002`: `lru 0.12.5` has an unsound `IterMut` API.

The present disposition is reasonable for a prototype because these dependencies
are isolated to `shph-tui`, and SHPH does not appear to call the affected
`lru::IterMut` API. They should still remain tracked.

## 4. Prioritized Findings

### REV-01 — Mandatory release demo is broken

**Severity:** Critical release blocker
**Type:** Release integrity / regression
**Evidence:** `scripts/demo.sh:35`, `scripts/demo.sh:38`,
`scripts/demo.sh:39`, `shph-cli/src/main.rs:103`,
`shph-cli/src/main.rs:109`, `docs/RELEASE_PROCEDURE.md:20`

The CLI now requires an Ed25519 signing public key when adding a peer, but the
happy-path demo reads only the X25519 public keys and calls `add-peer` without
`--sign-pubkey`.

Live result:

```text
error: the following required arguments were not provided:
  --sign-pubkey <SIGN_PUBKEY>
```

The release procedure explicitly says `scripts/demo.sh all` must pass before a
checkpoint is releasable. Therefore the current tree fails its own binding
release definition even though the Rust tests pass.

**Impact:** reviewers cannot reproduce the main encrypted-transfer demonstration;
the funding/release gate is red; recorded “external review readiness” is stale for
the current CLI.

**Recommendation:**

1. read both signing public keys with `show-signing-public-key`;
2. pass them to both `add-peer` calls;
3. make the demo assert expected output instead of using permissive `|| true` and
   `grep ... || true`;
4. add a CI job that runs `scripts/demo.sh all`.

### REV-02 — CI targets a branch that does not exist in this repository

**Severity:** High
**Type:** Continuous-integration coverage
**Evidence:** `.github/workflows/ci.yml:4`, `.github/workflows/ci.yml:6`,
`.github/workflows/ci.yml:8`

The workflow triggers only for pushes and pull requests to `main`. The inspected
repository is on `master`, has no local `main` branch, and has no configured
remote in this checkout.

**Impact:** if this exact repository is pushed with `master` as the default branch,
the advertised Linux/Windows CI matrix will not run for normal pushes or pull
requests. A funder may see a CI file and assume protection that is not active.

**Recommendation:** choose one canonical branch and align Git, CI,
`SECURITY.md`, `CONTRIBUTING.md`, support documents, and hosting configuration.
For immediate safety, trigger on both `main` and `master` until migration is
complete.

### REV-03 — Acceptance evidence is not attributable to an immutable source tree

**Severity:** High
**Type:** Reproducibility / audit evidence
**Evidence:** `scripts/capture_evidence.sh:8`,
`scripts/capture_evidence.sh:97`, `scripts/capture_evidence.sh:113`,
`docs/evidence/GATE_EVIDENCE.md:3`

The evidence script records a timestamp and command output, but it does not
record:

- `git rev-parse HEAD`;
- the current tag;
- whether the tree is dirty;
- hashes of tracked differences;
- hashes of untracked source files;
- Rust/Cargo versions;
- operating system and target triple.

The current audit began with 49 pre-existing modified or untracked paths and
roughly 3,800 added lines relative to `v0.4.0`. The evidence file can show green
gates, but it cannot prove exactly which source tree produced them.

The script also overwrites the canonical evidence file while gates are running.
If interrupted, reviewers may receive partial evidence.

**Impact:** the primary evidence artifact is unsuitable as a strong provenance
record for a grant checkpoint, tagged release, or third-party rebuild.

**Recommendation:**

1. refuse release evidence capture from a dirty tree, unless an explicit
   `--allow-dirty` research mode is used;
2. record commit, tag, branch, dirty status, toolchain, target, OS, and lockfile
   hash;
3. write to a temporary evidence file and atomically rename only after all
   commands finish;
4. attach a SHA-256 hash of the evidence file to the annotated release tag or
   checkpoint manifest;
5. include demo, audit, and mirror-parity results in the same evidence bundle.

### REV-04 — Large unreleased behavior changes still identify as `0.4.0`

**Severity:** High
**Type:** Version and artifact identity
**Evidence:** `Cargo.toml:14`, `CHANGELOG.md:3`, `CHANGELOG.md:27`,
`CHANGELOG.md:45`

The workspace version remains `0.4.0`, while the working tree contains extensive
post-`v0.4.0` changes: mandatory peer-policy changes, Windows shutdown handling,
new control-plane commands, encrypted keystores, lab transports, Shamir
operations, TUN hardening, and major CLI/transport modifications.

This is acceptable during development only if artifacts are clearly marked as
unreleased. At present, Cargo metadata and built binaries still describe the
tree as `0.4.0`, which is also the existing release tag.

The CLI also does not expose a normal `--version` flag, making runtime artifact
identification harder.

**Impact:** two materially different source trees can produce packages that both
claim to be `0.4.0`; bug reports and audit evidence may be attributed to the wrong
code; a funder cannot reliably distinguish the released tag from the development
tree.

**Recommendation:** before distributing binaries, bump to the next development
version or embed `0.4.0+<commit>`/dirty build metadata. Add a CLI version command
that prints package version, commit, and dirty marker. Do not cut a new checkpoint
until the tree is committed, tagged, and evidence-bound.

### REV-05 — Native Windows keystore persistence lacks Unix-equivalent guarantees

**Severity:** High for native Windows deployment; Medium for the current lab scope
**Type:** Secret-at-rest / crash consistency
**Evidence:** `shph-core/src/keystore.rs:363`,
`shph-core/src/keystore.rs:370`, `shph-core/src/keystore.rs:379`,
`shph-core/src/keystore.rs:387`, `shph-core/src/keystore.rs:394`,
`shph-core/src/keystore.rs:407`

On Unix, the keystore uses restrictive permissions and rename-based replacement.
On non-Unix platforms:

- permission restriction is a no-op;
- leaky-permission validation is a no-op;
- replacement removes the old keystore, copies the temporary file, and then
  removes the temporary file.

That Windows sequence is not atomic and creates failure windows where the old
keystore is gone but the new copy is incomplete or absent. The resulting file
inherits filesystem ACL behavior rather than enforcing a user-only DACL.

**Impact:** native Windows users may have weaker confidentiality and crash
recovery for identity keys than Unix users. This is especially important because
the audited repository is also maintained in a Windows checkout.

**Recommendation:** implement a Windows-specific secure replacement using Windows
file APIs, set an explicit current-user-only DACL, flush the file, and use an
atomic replace primitive where supported. Add native Windows tests for ACLs,
replacement failure, interruption, and preservation of the previous valid
keystore.

### REV-06 — Shamir secrets are exposed through command arguments and stdout

**Severity:** High if used for real secrets; Medium under the documented lab-only scope
**Type:** Secret handling
**Evidence:** `shph-cli/src/main.rs:116`, `shph-cli/src/main.rs:119`,
`shph-cli/src/main.rs:841`, `shph-cli/src/main.rs:852`,
`shph-cli/src/main.rs:879`, `shph-cli/src/main.rs:882`

`shamir-split --secret <value>` places the full secret in the process argument
list and commonly in shell history. The split operation prints all shares to one
stdout stream, and recovery prints the reconstructed secret to stdout.

**Impact:** secrets can leak through shell history, process inspection, terminal
scrollback, logs, CI output, screen recording, or redirected command output. A
single captured output stream can contain every share, defeating the purpose of
separation.

**Recommendation:** accept secret input from a protected file descriptor or
interactive no-echo prompt; emit each share directly to a separate owner-only
file; require an explicit unsafe flag to print secrets; zeroize recovered secret
buffers after use. Continue labeling this feature as a primitive, not production
key management.

### REV-07 — CI is weaker than the documented release gate

**Severity:** Medium
**Type:** CI/release-policy mismatch
**Evidence:** `.github/workflows/ci.yml:53`,
`.github/workflows/ci.yml:54`, `.github/workflows/ci.yml:76`,
`.github/workflows/ci.yml:82`, `docs/RELEASE_PROCEDURE.md:17`,
`docs/RELEASE_PROCEDURE.md:94`

CI builds without `--locked`, while the release procedure requires a locked
build. The audit job is also `continue-on-error: true`, so a newly disclosed
vulnerability would not fail CI.

**Impact:** dependency resolution drift can enter CI, and serious advisories can
be visually present without blocking a merge or release.

**Recommendation:** use `cargo build --workspace --all-targets --locked` and
`cargo test --workspace --all-targets --locked`. Define an explicit advisory
policy: allow only documented warning IDs, but fail on vulnerabilities and new
unreviewed warnings.

### REV-08 — Documented sliding replay window is not used by live receivers

**Severity:** Medium
**Type:** Documentation correctness / UDP reliability
**Evidence:** `shph-core/src/crypto.rs:286`,
`shph-core/src/crypto.rs:330`, `shph-core/src/crypto.rs:365`,
`SECURITY.md:49`, `SECURITY.md:101`, `docs/RISK_MATRIX.md:54`

`ReplayWindow` implements a sliding bitmap and has unit tests, but live
`ReceiveCipher` instances do not use it. They store only `last_nonce` and reject
every counter less than or equal to the highest authenticated counter.

For TCP, strict monotonic ordering is appropriate because the stream is ordered.
For the UDP shim, legitimate datagram reordering can cause authenticated packets
to be rejected as stale. The security documentation currently claims that the
receiver uses a sliding bitmap window, which is inaccurate for the live path.

**Impact:** external reviewers may believe out-of-order delivery is supported;
the experimental UDP transport can suffer avoidable packet loss or session
behavior differences under reordering.

**Recommendation:** either integrate `ReplayWindow` into the datagram receive
path while retaining strict monotonic behavior for TCP, or correct all claims to
state that live sessions intentionally reject out-of-order frames. Add a UDP
reordering regression test.

### REV-09 — Password-keystore temporary secret buffers are not zeroized

**Severity:** Medium
**Type:** Defense in depth / secret lifetime
**Evidence:** `shph-core/src/keystore.rs:205`,
`shph-core/src/keystore.rs:206`, `shph-core/src/keystore.rs:212`,
`shph-core/src/keystore.rs:235`, `shph-core/src/keystore.rs:251`,
`shph-core/src/keystore.rs:254`

The project carefully zeroizes session keys and signing seeds, but encrypted
keystore operations leave the serialized plaintext keystore and derived PBKDF2
key in ordinary `Vec<u8>` and `[u8; 32]` values until allocator/stack reuse.
Handshake code similarly constructs a combined ECDH/PQ secret in a normal
`Vec<u8>`.

**Impact:** a memory disclosure, crash dump, or swap capture may recover secret
material after the operation completes. This does not break encryption on its
own, but it weakens the stated in-memory hygiene posture.

**Recommendation:** wrap plaintext, derived keys, decoded seed buffers, and
combined shared secrets in `zeroize::Zeroizing`; zeroize password copies where
ownership allows; avoid cloning `KeyStore`/`IdentityKeyPair` unless required.

### REV-10 — Evidence and documentation contain stale or incomplete details

**Severity:** Medium
**Type:** External-review usability
**Evidence:** `docs/RELEASE_PROCEDURE.md:77`,
`docs/RELEASE_PROCEDURE.md:108`, `docs/TESTING.md:42`,
`docs/TESTING.md:53`, `docs/MILESTONE_SCORECARD.md:35`,
`docs/MILESTONE_SCORECARD.md:37`

Examples:

- the procedure requires `docs/CHECKPOINT_MANIFEST.md`, but that file does not
  exist;
- the reviewer path misspells `docs/REPRODUCIBILITY.md` as
  `docs/REPRODCIBILITY.md`;
- the total test count is still 116, but documented crate subtotals are stale
  (`shph-core` currently has 54 unit tests, not 51; CLI has 22 unit tests, not
  21).

**Impact:** reviewers encounter dead paths and inconsistent evidence, reducing
confidence in otherwise strong engineering work.

**Recommendation:** generate test subtotals automatically, create the manifest
or remove the requirement, fix the path, and run a documentation link/check
script in CI.

### REV-11 — Security reporting lacks a direct, verified contact in the checkout

**Severity:** Medium governance risk
**Type:** Vulnerability intake
**Evidence:** `SECURITY.md:18`, `SECURITY.md:19`,
`SECURITY.md:20`

The policy says to email maintainers but does not provide an address. It falls
back to GitHub private advisories, while this checkout has no configured remote
that proves such a repository/advisory channel exists.

**Impact:** a researcher may not have a reliable private disclosure route, and
the five-business-day acknowledgement commitment may be impossible to exercise.

**Recommendation:** publish a monitored security address or verified advisory
URL, document the responsible owner, and periodically test the intake path.

### REV-12 — Optional TUI retains accepted supply-chain warnings

**Severity:** Low
**Type:** Dependency hygiene
**Evidence:** `shph-tui/Cargo.toml:18`,
`docs/SUPPLY_CHAIN_SCAN.md:31`, `docs/SUPPLY_CHAIN_SCAN.md:32`

The optional TUI pulls `paste 1.0.15` and `lru 0.12.5`. The current audit found
no known vulnerability, but one crate is unmaintained and the other has an
unsound API advisory.

**Impact:** low in the current design because the TUI is optional and the
affected mutable iterator does not appear to be used, but the dependency remains
an avoidable assurance burden.

**Recommendation:** upgrade `ratatui`/`lru` when compatible, consider excluding
the TUI from security-critical distributions, and make the allowlist explicit
and expiring.

## 5. Positive Findings

### 5.1 Handshake authentication is now real

The current handshake signs a transcript with an Ed25519 private key and verifies
it with the peer signing public key. The signed material includes the protocol
tag, X25519 identity, Ed25519 key, ML-KEM public key, ephemeral key, nonce, and
timestamp. This is a substantial correction over a public-data digest and is the
right general security direction.

Relevant code: `shph-core/src/crypto.rs:137`,
`shph-core/src/handshake.rs:83`, `shph-core/src/handshake.rs:142`.

### 5.2 Peer policy fails closed

The CLI requires configured peer identity and signing-key matches before
data-plane use. An empty peer store no longer silently disables authentication.
This materially improves the operational meaning of the cryptographic handshake.

Relevant code: `shph-cli/src/main.rs:1252`.

### 5.3 Hybrid key establishment has downgrade checks

The session KDF combines X25519 and ML-KEM-768 shared material, and derivation
fails if the PQ shared secret is absent. The ML-KEM public key is signed in the
hello. The tests include downgrade, corruption, and key-agreement cases.

Relevant code: `shph-core/src/handshake.rs:140`,
`shph-core/src/handshake.rs:172`, `shph-core/tests/handshake_flow.rs`.

### 5.4 Data-plane parsing is bounded and fail-closed

TCP and UDP paths use explicit size caps, exact-length reads for PQ ciphertext,
truncation guards, timeout budgets, source-address checks, malformed-datagram
budgets, and per-IP rate limiting. These are valuable defenses for a prototype.

Relevant code: `shph-transport/src/lib.rs:24`,
`shph-transport/src/lib.rs:38`, `shph-transport/src/lib.rs:1040`,
`shph-transport/src/lib.rs:1254`, `shph-transport/src/lib.rs:1411`.

### 5.5 Authenticated replay state advances only after AEAD verification

The receive counter is updated after successful decryption, preventing an
unauthenticated high-nonce packet from permanently advancing replay state.

Relevant code: `shph-core/src/crypto.rs:334`,
`shph-core/src/crypto.rs:338`.

### 5.6 Unix secret-file handling is thoughtful

The keystore uses bounded reads, `O_NOFOLLOW`, owner-only permissions, exclusive
temporary files, fsync, and rename on Unix. Config and audit persistence also
show deliberate symlink and crash-consistency hardening.

Relevant code: `shph-core/src/keystore.rs:295`,
`shph-core/src/keystore.rs:347`, `shph-config/src/lib.rs:133`,
`shph-core/src/roadmap.rs:621`.

### 5.7 The project states important non-claims honestly

The documentation clearly says the project is not production hardened, does not
provide censorship resistance or browser fingerprint parity, and does not
misrepresent the UDP shim as standards-compliant QUIC. This honesty is a major
strength for funder trust.

Relevant documents: `SECURITY.md`, `docs/RISK_MATRIX.md`,
`docs/FUNDERS.md`, `docs/LAB_PROTOTYPES.md`.

### 5.8 Mirror parity and Rust quality gates are strong

The mirrored trees matched under the documented policy, and formatting, lint,
tests, and locked build all passed on the audited state. Test coverage includes
many negative/fail-closed cases rather than only happy paths.

## 6. My Assessment

### Security maturity

The core cryptographic posture is now credible for controlled experimentation.
The most important previous design failure—non-secret “signatures”—has been
replaced with real public-key authentication. The current combination of peer
pinning, transcript signatures, hybrid KEM, AEAD, bounds, and negative tests is
a meaningful secure-transport foundation.

That does not yet make SHPH a production VPN. Native TUN lifecycle, privilege
separation, Windows secret handling, operational key management, long-running
session behavior, fuzzing, protocol interoperability, traffic-analysis
resistance, and independent cryptographic review remain incomplete.

### Engineering maturity

The Rust code is generally defensive and test-oriented. The largest weakness is
that development has moved faster than release automation and evidence
maintenance. Green unit/integration tests are being treated as if they imply a
green release, but the mandatory demo currently disproves that.

### Funding readiness

I would describe SHPH to a funder as:

> A technically substantial, open, lab-stage secure-transport project with a
> credible hardening trajectory and strong evidence of engineering progress,
> seeking funding to turn a promising prototype into a reproducible,
> independently reviewed, cross-platform product.

I would **not** describe it as production ready, anonymously deployable, fully
audited, censorship resistant, or operationally complete.

Funding is reasonable if milestones are evidence-based and prioritize release
integrity, native Windows verification, fuzzing, privilege separation, and
external review rather than adding more experimental transports.

## 7. Recommended Remediation Order

### Before any new tag, checkpoint, or funder demo

1. Fix and hard-assert `scripts/demo.sh all`.
2. Align `main`/`master` and confirm hosted CI actually runs.
3. commit or intentionally discard the current dirty-tree changes;
4. bump or uniquely identify the development version;
5. bind evidence to the clean commit, lockfile, toolchain, and platform;
6. fix the release-procedure dead path and create the manifest;
7. refresh all evidence and documentation from the final clean tree.

### Before native Windows security claims

1. implement Windows ACL enforcement for config and keystore secrets;
2. implement crash-safe/atomic Windows replacement;
3. run native MSVC build, clippy, tests, demos, Ctrl+C teardown, and
   route/DNS dry-run validation;
4. record native Windows evidence separately from WSL-based evidence.

### Before real secret-management use

1. replace Shamir `--secret` with no-echo/file-descriptor input;
2. write shares to separate protected files;
3. zeroize password-keystore and Shamir temporary buffers;
4. obtain a focused key-management and memory-hygiene review.

### Before broader hostile-network testing

1. add fuzzing for hello, frame, config, audit-journal, and file-adapter parsers;
2. add property tests for replay windows, counter limits, and Shamir recovery;
3. test packet loss, duplication, reordering, fragmentation, and time skew;
4. add load tests for connection floods, UDP source-table pressure, and hostile
   filesystem queues;
5. commission an independent protocol and cryptography review.

## 8. Final Verdict

**Current working tree verdict:** **Not release-ready.**

**Primary reason:** the tree fails its own mandatory demo gate, and its CI/evidence
system does not yet prove the identity of the source being validated.

**Core technology verdict:** **Promising and materially hardened.**

**Funding verdict:** **Worth considering for controlled, milestone-based
engineering funding**, especially for reproducible releases, Windows hardening,
fuzzing, external audit, privilege separation, and operational key management.

The project should continue emphasizing its honest lab-stage status. Its strongest
asset is not that every problem is solved; it is that the codebase now contains
real security improvements, explicit non-claims, and enough tests and structure
to make the remaining work measurable.

## 9. Remediation Addendum — 2026-07-17

### Confidence and boundary

The remediation is verified for the current Linux/WSL working tree and its
source-level Windows paths. I am confident the listed code changes are present
and exercised where this environment permits. I do **not** claim that native
Windows ACL behavior, MSVC/Windows `ring` builds, console teardown, Wintun, or
route/DNS mutation has been fully verified here; those still require execution
on a real Windows host.

### Fixes completed

1. **Mandatory demo and CI release gates**
   - Updated `scripts/demo.sh` to pass pinned Ed25519 signing keys and assert
     expected output.
   - Added the happy-path demo to CI.
   - Aligned CI triggers with both `main` and `master`.
   - Made locked build/test/clippy commands explicit and made the advisory job
     blocking except for the two documented optional-TUI advisories.

2. **Evidence provenance and atomicity**
   - `scripts/capture_evidence.sh` now records commit, branch, tag, dirty state,
     toolchain, target, OS, and `Cargo.lock` SHA-256.
   - Evidence is written to a temporary file and atomically renamed.
   - Dirty-tree capture requires explicit `--allow-dirty`.
   - Evidence now includes workspace test totals, the locked build, and
     `scripts/demo.sh all`.
   - Added `docs/CHECKPOINT_MANIFEST.md` and repaired the reproducibility path.

3. **Version and artifact identity**
   - Development version is now `0.5.0-dev.0`.
   - Added a Git-derived build identifier with a dirty marker.
   - CLI version output identifies the package/build state.

4. **Shamir secret handling**
   - Removed secret values from command-line arguments.
   - Added protected file/stdin input and required protected output files.
   - Writes shares separately with owner-only permissions where supported.
   - Recovered secret buffers are zeroized.

5. **Windows keystore hardening**
   - Added Windows-specific owner-only DACL application.
   - Added Windows symlink/reparse-point refusal for keystore loading.
   - Replaced delete/copy persistence with `ReplaceFileW`/`MoveFileExW` and
     write-through flags.
   - Native Windows behavior remains an operator verification item.

6. **Replay semantics**
   - Kept strict monotonic replay checks for TCP and filesystem adapters.
   - Added a bounded sliding replay window only to the experimental QUIC/UDP
     receiver.
   - Added a regression test proving authenticated reordering is accepted once
     and replay is still rejected.
   - Updated security and risk documentation to match live behavior.

7. **Secret-memory hygiene**
   - Wrapped keystore plaintext, decoded ciphertext/salt/nonce material, and
     derived PBKDF2 keys in zeroizing containers.
   - Wrapped the combined ECDH/PQ handshake secret in zeroizing storage.

8. **Documentation and supply-chain accuracy**
   - Refreshed stale version and test-count claims.
   - Corrected the `REPRODUCIBILITY.md` path.
   - Documented the absence of a verified direct security email rather than
     inventing one.
   - Updated the dependency-scan policy and explicit advisory allowlist.

### Verification performed

The remediation was checked with:

```text
cargo fmt --all -- --check                         PASS
cargo clippy --workspace --all-targets --locked
  -- -D warnings                                   PASS
cargo test --workspace --locked                    PASS
117 passed; 0 failed; 0 ignored
cargo build --workspace --locked                   PASS
scripts/demo.sh all                                PASS
cargo audit --no-fetch
  --ignore RUSTSEC-2024-0436
  --ignore RUSTSEC-2026-0002
  --deny warnings                                  PASS
git diff --check                                   PASS
scripts/sync_mirror.sh --verify                    PASS
```

The generated evidence artifact records the working-tree state as
`tree=dirty`, commit `7de572eddb236469f1aa42c5ee069858c99d9de3`, branch
`master`, and `PASSED=117  FAILED=0  IGNORED=0`. The Windows checkout was synchronized
after the final changes and parity verification passed.

### Revised verdict

The previously identified release-integrity blockers are remediated in the
working tree. The project is still **not production-ready** and should not be
described as fully audited, production QUIC, censorship-resistant, or natively
Windows-verified until the remaining operator-only validation and independent
security review are completed.
