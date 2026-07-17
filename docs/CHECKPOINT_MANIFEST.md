# SHPH Checkpoint Manifest

This file is the human-readable companion to a funding-checkpoint tag. It is
updated only when a checkpoint is actually cut; development-tree evidence is
kept separate and marked dirty.

## Current Development Snapshot

```text
Workspace version : 0.5.0-dev.0
Status            : unreleased development line
Canonical tree    : /home/mori/SHPH_working_copy
Windows mirror    : D:\FUNDING NEEDED\snap-shroud-rs
Evidence mode     : capture_evidence.sh --allow-dirty until a clean commit exists
```

## Latest Tagged Checkpoint

```text
Checkpoint : checkpoint-phaseB-1.0.0
Status     : historical funding checkpoint; do not infer current source state
Tag        : checkpoint-phaseB-1.0.0
Evidence   : docs/evidence/GATE_EVIDENCE.md and docs/evidence/CARGO_AUDIT.txt
```

Before publishing a new checkpoint, replace this section with the exact tag,
UTC timestamp, evidence SHA-256, gate totals, demo result, and mirror-parity
result. The tag must point to the commit containing this manifest.
