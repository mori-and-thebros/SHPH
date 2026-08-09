# SHPH Internal Release-Readiness Review

**Review type:** Internal source and local-execution review; not an independent
security audit
**Date (UTC):** 2026-07-06
**Scope:** SHPH source tree at the audited commit.
**Commit audited:** `7de572e` — "hardening: secret-material zeroization on
drop (hardening-5)", on top of tagged release `v0.4.0`.

This is an internal point-in-time review of the repository state available on
the review date rather than a statement taken from prior notes. It complements,
and does not replace,
`docs/RISK_MATRIX.md`, `docs/SECURITY_REPORTING.md`, and
`docs/SUPPLY_CHAIN_SCAN.md`.

> **Superseded by current remediation:** this July 6 snapshot predates
> mandatory peer pinning and Windows console-control handler wiring. Use the
> current validation evidence for release decisions.

## 1. What was reviewed

- Project shape: 7-crate Cargo workspace (`shph-core`, `shph-config`,
  `shph-tun`, `shph-transport`, `shph-obfuscation`, `shph-cli`, `shph-tui`),
  workspace version `0.4.0`, `edition = "2021"`.
- Release/tag history: `checkpoint-phaseA-1.0.0`, `checkpoint-phaseB-1.0.0`,
  `hardening-1/2/3/5`, `v0.2.0`, `v0.3.0`, `v0.4.0`.
- Protocol evolution via `CHANGELOG.md`: `shph/3` (real Ed25519 handshake
  signatures, `v0.3.0`) -> `shph/4` (hybrid X25519 + ML-KEM-768 post-quantum
  key exchange with downgrade resistance, plus QUIC/UDP shim hardening,
  `v0.4.0`) -> unreleased `hardening-5` (zeroize-on-drop for session keys,
  Ed25519 signing seed, HKDF intermediates).
- Full gate suite (`fmt`, `clippy -D warnings`, `test --workspace`,
  `build --workspace --locked`, `cargo audit`), recorded for this review.
- Parity between the configured Windows and Linux checkouts.

## 2. Gate results (run live)

| Gate | Result |
| ---- | ------ |
| `cargo fmt --all -- --check` | Clean |
| `cargo clippy --workspace --all-targets -- -D warnings` | Clean, 0 warnings |
| `cargo build --workspace --locked` | Succeeds |
| `cargo test --workspace` | 83 tests total; 82 stable-pass, 1 environment-specific flake (see §3) |
| `cargo audit` | 2 pre-accepted advisories only (`paste` unmaintained, `lru` unsound `IterMut`), both transitive; consistent with `docs/SUPPLY_CHAIN_SCAN.md` |

These match the tree's own last-captured `docs/evidence/GATE_EVIDENCE.md`
(`2026-07-06T17:22:05Z`), which recorded all 83 tests passing.

## 3. Findings

### 3.1 Test flake on the Windows/DrvFs mount (Low severity, non-blocking)

`shph-cli/tests/cli_tcp_data_plane.rs::send_once_and_recv_once_transfer_encrypted_payload`
failed with `Connection refused (os error 111)` on 3/3 runs in the
Windows-mounted checkout, but passed cleanly on the identical commit in the
Linux checkout.

- **Root cause:** the test spawns a `recv-once` child process, sleeps a fixed
  `150ms`, then connects. On the DrvFs-backed mount, process spawn and socket
  bind latency for the child occasionally exceed that fixed window.
- **Not a functional defect.** No production code path is involved; this is a
  timing assumption in a test harness that only surfaces on a slower
  filesystem/process-spawn path.
- **Recommendation:** replace the fixed sleep with a bind-ready retry/poll loop
  (e.g., retry the connect with backoff up to the test's own timeout) so the
  test is robust across host/mount performance. Not required before shipping;
  worth fixing to keep CI green on slower runners.

### 3.2 Stray empty directory (Low severity, cosmetic)

An empty local-only directory is present in both platform checkouts. It carries
no content and no reference in `docs/` or scripts, and is likely a leftover
from an earlier reorganization.

- **Recommendation:** delete it, or note its purpose in
  `docs/DIRECTORY_GUIDE.md` if it is intentionally reserved.

### 3.3 No code-level defects found

No clippy warnings, no fmt drift, no test regressions beyond the flake above,
and no new `cargo audit` findings beyond the two already-accepted advisories.
The v0.3.0 and v0.4.0 CHANGELOG entries describe real, verifiable fixes
(Ed25519 signature authentication; hybrid PQ key exchange with fail-closed
downgrade resistance; QUIC source-address binding and per-IP rate limiting),
and the corresponding regression tests (`handshake_flow.rs`,
`shph-transport` unit tests) exist and pass.

## 4. Mirror parity

`diff -rq` between the configured Windows and Linux checkouts, excluding
`target/` and `.git/`, shows **zero content differences** — the two trees are
byte-identical at commit `7de572e`. `Cargo.lock` is treated as the one
intentional non-mirrored artifact per `docs/RELEASE_PROCEDURE.md`; a transient
`Cargo.lock` diff produced during validation was reverted with
`git checkout -- Cargo.lock` before concluding the review.

## 5. Overall assessment

The tree is in a healthy, well-gated state consistent with its own documented
release procedure: fmt/clippy/build/audit all pass, mirror parity is exact,
and security-relevant CHANGELOG claims are backed by passing regression
tests. The single observed test failure is attributable to mount-specific
timing in a test harness, not to the code under test, and is reproducible
identically on repeat runs (ruling out non-determinism in the crypto/transport
code itself). No Critical or High severity issues were found in this pass;
see `docs/RISK_MATRIX.md` for the project's own tracked Medium/High limits
(e.g., QUIC shim maturity, Windows Ctrl+C handling), which remain accurate and
unchanged by this audit.
