# SHPH Release Procedure & Funding-Checkpoint Tagging

This document defines how a SHPH release is cut, signed off, and tagged as a
**funding checkpoint** artifact. A funding checkpoint is a labeled,
reproducible, fully-evidenced snapshot that a grant reviewer or auditor can
rebuild and verify independently.

## 1. What qualifies as a releasable checkpoint

A commit/tree is releasable as a checkpoint **only when all** of the following
hold:

- `cargo fmt --all -- --check` is clean.
- `cargo clippy --workspace --all-targets -- -D warnings` is clean.
- `cargo test --workspace` passes with **0 failed** (ignored tolerated only if
  documented in the evidence log).
- `cargo build --workspace --locked` succeeds (reproducible, lockfile honored).
- `scripts/capture_evidence.sh` has been re-run and `docs/evidence/GATE_EVIDENCE.md`
  reflects the current tree (non-stale timestamp).
- `scripts/demo.sh all` reproduces all demos (happy / bad-cidr / unreachable).
- Any configured platform checkouts used for the release are in parity,
  verified with `scripts/sync_mirror.sh --verify`.
- The pre-completion security-assessment/remediation gate in
  `ROADMAP_OSS_AND_DELIVERY.md` is closed, with findings remediated or
  explicitly documented. This does not represent an independent audit.
- For a public GitHub release, `docs/GITHUB_PUBLICATION_CHECKLIST.md` is
  complete, including a monitored private vulnerability-reporting channel and
  a review that native host evidence is not overstated.
- Native-host evidence is accurately scoped: Windows Wintun evidence uses the
  hash-pinned application-local loader and a validator that checks the staged
  DLL's Authenticode signature, while Linux two-host reports are captured on
  native Linux rather than WSL, containers, or namespace-only probes.
- A final publication review confirms no private keystores, credentials,
  unredacted host data, or generated build artifacts are staged.

> See `docs/MILESTONE_SCORECARD.md` for the binding definition of "complete" and
> the per-phase scorecard.

## 2. Release tag naming

Tags follow a phase-anchored scheme so checkpoints map directly to the roadmap:

```
checkpoint-phaseA-1.0.0      # end of Phase A (A.1–A.5), review-readiness checkpoint
checkpoint-phaseB-1.0.0      # end of Phase B (B.1–B.2), funding validation
vX.Y.Z                       # semantic-version point releases once a release line is live
```

A versioned release line is live through **`v0.4.0`**. The current workspace is
an unreleased prerelease development line, **`0.6.4-dev`**, and must not be described as
`v0.4.0`. Going forward, SemVer releases (`vX.Y.Z`) are the authoritative tags;
funding checkpoints remain roadmap-anchored milestones. Each checkpoint tag
carries the roadmap phase it closes.

## 3. Cutting a checkpoint (procedure)

> **Note:** This project tree is now a git repository. The first checkpoint
> tag `checkpoint-phaseA-1.0.0` (commit `e0a5949`) closes Phase A + Phase B.1.
> Future checkpoints follow the procedure below; the manifest in section 4 is
> the human-readable counterpart to each tag.

1. **Verify gates.** From the workspace root run, in order:
   ```bash
   source "$HOME/.cargo/env"   # if cargo is not on PATH
   cargo fmt --all -- --check
   cargo clippy --workspace --all-targets -- -D warnings
   cargo test --workspace
   cargo build --workspace --locked
   ```
2. **Refresh evidence.**
   ```bash
   ./scripts/capture_evidence.sh      # regenerates docs/evidence/GATE_EVIDENCE.md
   ./scripts/demo.sh all              # confirm demos still reproduce
   ```
3. **Synchronize and verify any second checkout.**
   ```bash
   export SHPH_SYNC_LINUX_DIR=/path/to/linux-checkout
   export SHPH_SYNC_WINDOWS_DIR=/path/to/windows-checkout
   ./scripts/sync_mirror.sh --to-windows
   ./scripts/sync_mirror.sh --verify
   ```
   The root `Cargo.lock` is intentionally platform-specific and excluded from
   synchronization. After any workspace-version or dependency change, refresh
   it natively in every supported checkout before using `--locked`:
   ```powershell
   cargo check --workspace
   cargo check --workspace --locked
   ```
   Do not copy a WSL-generated root lockfile into the Windows checkout.
4. **Update changelog.** Add a `## [checkpoint-phaseX-Y.Y.Z] - <date>` entry to
   `CHANGELOG.md` summarizing what the checkpoint closes.
5. **Tag** (once under git):
   ```bash
   git add -A
   git commit -m "checkpoint: phaseX <tag>"
   git tag -a checkpoint-phaseX-1.0.0 -m "Funding checkpoint — Phase X. See docs/RELEASE_PROCEDURE.md"
   git push --follow-tags
   ```
6. **Record the manifest.** Fill in `docs/CHECKPOINT_MANIFEST.md` (section 4)
   with the tag, timestamp, evidence hash, and gate totals.
7. **Prepare GitHub publication.**
   ```bash
   git diff --check
   git status --ignored
   if git ls-files | grep -Eiq '(^|/)(keystore\.json|[^/]+\.(pem|key|p12|pfx)|wintun\.dll|benchmark-runs)(/|$)'; then
     echo "Refusing publication: review tracked private or generated artifacts." >&2
     exit 1
   fi
   ```
   Review the staged diff manually, ensure `SECURITY.md`, `README.md`, and
   `CHANGELOG.md` describe only validated capabilities, and attach release
   checksums generated from the final clean checkout.

## 4. Funding-checkpoint manifest

The manifest is the human-readable counterpart to the git tag. Until the tree
is tagged, the manifest is planning evidence; after tagging, the git tag is the
authoritative artifact. Current latest:

```text
Checkpoint : checkpoint-phaseB-1.0.0  (Phase A + Phase B complete)  [LATEST]
Status     : Phase A COMPLETE (5/5); Phase B (B.1+B.2) COMPLETE
Date (UTC) : 2026-06-29
Tag        : checkpoint-phaseB-1.0.0  (annotated)
Points at  : the commit this manifest lives in (git rev-parse checkpoint-phaseB-1.0.0)
Checkouts  : configured platform-specific directories
Parity     : verified via scripts/sync_mirror.sh --verify
Gates      : fmt clean · clippy clean (0 warnings) · test 0 failed · build --locked OK · cargo audit 0 vulns
Evidence   : docs/evidence/GATE_EVIDENCE.md, docs/evidence/CARGO_AUDIT.txt
Demo       : scripts/demo.sh all (happy / bad-cidr / unreachable)

Prior checkpoint: checkpoint-phaseA-1.0.0  (Phase A + B.1; base commit e0a5949)
```

Update this manifest block in place at every checkpoint.

## 5. Reviewer reproduction path

A reviewer receiving a checkpoint should be able to do, with no extra context:

1. Read `docs/FUNDERS.md` (what the project is / is not).
2. Follow `docs/REPRODUCIBILITY.md` to build `--locked`.
3. Run `scripts/capture_evidence.sh` and diff against the committed
   `docs/evidence/GATE_EVIDENCE.md` (gate totals must match).
4. Review `SECURITY.md`, `docs/RISK_MATRIX.md`, and the public validation
   follow-up to confirm every published finding has a documented disposition
   and regression evidence. Treat an independent audit as a separate
   requirement until an actual external engagement is published.
5. Run `scripts/demo.sh all` and confirm the expected fail-closed behavior.
6. Cross-check `docs/MILESTONE_SCORECARD.md` phase status.

If any step diverges, the checkpoint is invalid and must be re-cut.
