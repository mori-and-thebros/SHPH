# v0.6.6-dev.2 Validation Record — 2026-08-30

This record summarizes a local engineering validation run against the
`v0.6.6-dev.2` publication tag. It is evidence for the development line, not a
release approval or an independent security audit. The working tree contained
local validation and documentation changes during the run.

## Provenance

| Field | Value |
| --- | --- |
| Source tag | `v0.6.6-dev.2` |
| Source revision | `352932cb4a3fd1efe53141c73d06a0d0b0f00611` |
| Windows target | `x86_64-pc-windows-msvc` |
| Rust toolchain | `rustc 1.96.0`, `cargo 1.96.0` |
| Linux environment | WSL2 |
| Tree state | Dirty engineering tree |

## Validation results

### Windows MSVC

- Formatting, workspace check, strict Clippy, workspace tests, and release
  build passed for `x86_64-pc-windows-msvc`.
- Focused reliability, control-plane, killswitch, and firewall tests passed:
  1, 7, 3, and 6 tests respectively.
- The elevated native validator passed signed and SHA-256-pinned Wintun
  loading, adapter/session creation, route and DNS apply/rollback, and
  cleanup checks.
- The Windows benchmark suite completed both `secure-default` and
  `classical-lab` local profiles. These are local measurements, not two-host
  throughput results.
- Post-run checks found no SHPH/Wintun adapter, `198.18.0.0/15` route, DNS
  entry, or SHPH process residue.

### WSL2

- The locked workspace matrix passed formatting, metadata, check, strict
  Clippy, tests, and release build.
- The workspace produced 397 passing test cases with zero failures.
- The standalone `shph-edge` workspace passed its tests (38), strict Clippy,
  release build, and advisory scan.
- The root, benchmark, fuzz, and edge lockfiles passed advisory scans in the
  available WSL2 environment.
- All shell scripts passed `bash -n`, and `scripts/demo.sh all` passed its
  success and fail-closed scenarios.
- All six fuzz targets completed 1,000-run smoke campaigns successfully.
- The Criterion capture completed with 520 report files.
- The isolated native-TUN namespace check passed, and the lifecycle benchmark
  completed 20/20 open/hold/close iterations. This is lifecycle evidence only;
  it is not packet forwarding or two-host throughput evidence.

The Windows retry of the standalone benchmark, fuzz, and edge advisory scans
could not refresh missing registry-index metadata because the configured crate
mirror was not resolvable from that host. The corresponding lockfiles passed
in WSL2; rerun the Windows scans when registry access is available.

## Scope that remains open

This capture does not close:

- clean-tree release evidence and a final sanitized package;
- dedicated Linux/Linux or Windows/Windows native-TUN campaigns;
- packet send/receive coverage across every supported host pairing;
- forced-termination cleanup or crash-time WFP leak behavior;
- explicit DNS, IPv6, PMTU, UDP, and standards-QUIC host validation;
- long-duration and Internet-path performance claims; or
- independent security-audit or hostile-network claims.

The binding release gates and evidence rules remain in
[`docs/RELEASE_READINESS.md`](../RELEASE_READINESS.md).
