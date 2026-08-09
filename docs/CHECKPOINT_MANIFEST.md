# SHPH Checkpoint Manifest

This file is the human-readable companion to a release checkpoint tag. It is
updated only when a checkpoint is actually cut; development evidence is kept
separate and clearly labeled.

## Current Development Snapshot

```text
Workspace version : 0.6.0-dev.0
Status            : unreleased development line
Repository        : current checkout
Evidence mode     : development evidence; clean release capture required
```

## Latest Tagged Checkpoint

```text
Checkpoint : checkpoint-phaseB-1.0.0
Status     : historical checkpoint; do not infer current source state
Tag        : checkpoint-phaseB-1.0.0
Evidence   : docs/evidence/GATE_EVIDENCE.md and docs/evidence/CARGO_AUDIT.txt
```

Before publishing a new checkpoint, replace this section with the exact tag,
UTC timestamp, evidence SHA-256, gate totals, demo result, and mirror-parity
result. The tag must point to the commit containing this manifest.
