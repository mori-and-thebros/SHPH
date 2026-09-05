# v0.6.7-dev Pre-Commit Validation Record — 2026-09-04

This is a historical engineering validation capture for the pre-commit
`v0.6.7-dev` candidate. It is not the final release record because the checkout
was intentionally dirty while the release-preparation changes were being
reviewed.

## Provenance

| Field | Value |
| --- | --- |
| Version | `0.6.7-dev` |
| Captured revision | `313cfb8a0cdc095cf7c59a763e64403f0c50f36d` |
| Git state | detached `HEAD`; no `v0.6.7-dev` tag created |
| Host | Windows, `x86_64-pc-windows-msvc` |
| Rust | `rustc 1.96.0 (ac68faa20 2026-05-25)` |
| Cargo | `cargo 1.96.0 (30a34c682 2026-05-25)` |
| `Cargo.lock` SHA-256 | `062497c127ad2fbbe42865dc3441e5d8a6e049f31eeaf2d9209d696031221d85` |
| Collector | `benchmark-runs/release-check-v0.6.7-dev-final2/release-readiness-20260904T223959Z.md` |

## Non-fuzz gates

The strict collector was run with:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\release_readiness.ps1 `
  -OutputDirectory .\benchmark-runs\release-check-v0.6.7-dev-final2 `
  -SkipFuzzSmoke
```

The following non-fuzz checks passed:

- formatting, locked metadata, workspace check, and strict Clippy;
- all 379 workspace tests, including the standards-QUIC CLI test;
- workspace release build and Windows MSVC all-target/release builds;
- benchmark check, format, Clippy, 7 benchmark tests, release build, and
  secure-default/classical-lab smoke suites;
- standalone edge check, tests (38), strict Clippy, HTTP/3 checks/tests/Clippy,
  and release build; and
- root, benchmark, fuzz-manifest, and standalone-edge `cargo audit` scans.

The collector summary was 34 `PASS`, 2 expected provenance/package `FAIL`
results, and 2 explicit `SKIP` results for fuzz smoke and native two-host
validation.

The standards-QUIC integration test was hardened to obtain its loopback UDP
port from the operating system instead of deriving a potentially occupied
port from the clock. It passed five focused reruns and the full workspace
test gate.

## Explicitly unresolved gates

- Fuzz smoke was intentionally skipped for this candidate. The fuzz
  manifests, formatting, check, Clippy, and audit gates passed; this record
  makes no claim that the six fuzz executables launched successfully.
- The native-TUN/two-host campaign remains `SKIP` because it requires a
  dedicated privileged Linux or Windows operator campaign.
- The strict package gate correctly remained `FAIL` while this capture's
  checkout was dirty. A clean-tree package run is required before publication.
- The GitHub release workflow now includes archive verification and artifact
  attestation, but its first `v0.6.7-dev` tag-triggered run has not yet been
  executed or independently verified.

Accordingly, this record is an engineering snapshot, not a release
eligibility claim. No commit, tag, push, or GitHub release was created during
this validation.
