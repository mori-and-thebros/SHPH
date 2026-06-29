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
- The two trees (Linux working copy and Windows mirror) are in parity, verified
  with `scripts/sync_mirror.sh --verify`.

> See `docs/MILESTONE_SCORECARD.md` for the binding definition of "complete" and
> the per-phase scorecard.

## 2. Release tag naming

Tags follow a phase-anchored scheme so checkpoints map directly to the roadmap:

```
checkpoint-phaseA-1.0.0      # end of Phase A (A.1–A.5), first external review
checkpoint-phaseB-1.0.0      # end of Phase B (B.1–B.2), funding validation
vX.Y.Z                       # semantic-version point releases once a release line is live
```

Until a versioned release line is established, **funding checkpoints are the
authoritative tags.** Each checkpoint tag carries the roadmap phase it closes.

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
3. **Sync and verify parity.**
   ```bash
   ./scripts/sync_mirror.sh --to-windows
   ./scripts/sync_mirror.sh --verify
   ```
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

## 4. Funding-checkpoint manifest

The manifest is the human-readable counterpart to the git tag. Until the tree
tag is the authoritative artifact. Current latest:

```text
Checkpoint : checkpoint-phaseA-1.0.0  (Phase A complete + Phase B.1)
Status     : Phase A COMPLETE (5/5); Phase B.1 COMPLETE
Date (UTC) : 2026-06-29
Tag        : checkpoint-phaseA-1.0.0  (annotated)
Points at  : the commit this manifest lives in (git rev-parse checkpoint-phaseA-1.0.0)
Prior base : e0a5949 (initial Phase A + B.1 commit)
Trees      : /home/mori/SHPH_working_copy  (canonical Linux)
            D:\FUNDING NEEDED\snap-shroud-rs  (Windows mirror)
Parity     : verified via scripts/sync_mirror.sh --verify
Gates      : fmt clean · clippy clean (0 warnings) · test 0 failed · build --locked OK
Evidence   : docs/evidence/GATE_EVIDENCE.md
Demo       : scripts/demo.sh all (happy / bad-cidr / unreachable)
```

Update this manifest block in place at every checkpoint.

## 5. Reviewer reproduction path

A reviewer receiving a checkpoint should be able to do, with no extra context:

1. Read `docs/FUNDERS.md` (what the project is / is not).
2. Follow `docs/REPRODCIBILITY.md` to build `--locked`.
3. Run `scripts/capture_evidence.sh` and diff against the committed
   `docs/evidence/GATE_EVIDENCE.md` (gate totals must match).
4. Run `scripts/demo.sh all` and confirm the expected fail-closed behavior.
5. Cross-check `docs/MILESTONE_SCORECARD.md` phase status.

If any step diverges, the checkpoint is invalid and must be re-cut.
