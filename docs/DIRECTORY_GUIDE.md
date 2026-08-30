# SHPH Repository Guide

This file maps the repository layout and the main public validation artifacts.

## Top-level Layout

- `Cargo.toml`: workspace definition and shared dependency setup.
- `Cargo.lock`: locked dependency graph.
- `README.md`: entry point, status, and quick start instructions.
- `docs/`: operator/docs set (testing, control plane, TUI, directory guide).
- `shph-cli/`: command-line binary and integration tests.
- `shph-config/`: config model and parser.
- `shph-core/`: handshake, framing, transport negotiation primitives.
- `shph-obfuscation/`: protocol-shaping extension surface.
- `shph-transport/`: transport enum and socket/parsing support.
- `shph-edge/`: standalone owned-domain Phantom One HTTP/2 relay prototype;
  separate manifest and lockfile, outside the workspace release profile.
- `shph-identity/`: isolated experimental signed identity records,
  provider-independent local discovery.
- `shph-tun/`: TUN abstraction crate.
- `shph-tui/`: optional terminal UI shell.
- `fuzz/`: standalone cargo-fuzz targets for parser and replay robustness.
- `benchmarks/`: standalone benchmark crate; its lockfile is intentionally
  separate from the application workspace. `benches/criterion.rs` contains the
  statistical microbenchmark harness.
- `scripts/`: reproducible demos, benchmark operators, evidence capture, and
  optional multi-checkout synchronization.
- `docs/BENCHMARKING.md`: Linux-first benchmark methodology, profiles, and obstacles.
- `docs/GITHUB_BENCHMARKING.md`: GitHub-hosted campaign triggers, artifacts,
  and evidence boundaries.
- `docs/BENCHMARK_RESULTS_2026-08-25.md`: focused local defensive rejection
  benchmark with exact provenance and non-claims.
- `docs/BENCHMARK_RESULTS_2026-08-23.md`: current local development evidence
  for tuned profiles, validation gates, and benchmark boundaries.
- `docs/BENCHMARK_RESULTS_2026-08-22.md`: previous local development evidence
  for the candidate benchmark campaign, near-MTU video profile, validation
  gates, and fuzz status.
- `docs/BENCHMARK_RESULTS_2026-08-17.md`: dated local evidence campaign for
  Shroud2 overhead, pre-authentication CPU paths, and replay-window throughput.
- `docs/BENCHMARK_EXTENDED_RESULTS_2026-08-18.md`: extended local campaign for
  batch framing, MTU/loss modeling, concurrency, session churn, and
  repeatability, with explicit host-capability skips.
- `docs/NETWORK_SIMULATION_EVIDENCE_2026-08-17.md`: audit addendum for MTU/PMTU,
  post-quantum latency, and Poisson-chaff claims.
- `docs/BENCHMARK_RESULTS_2026-08-14.md`: historical Windows-local `0.6.1-dev`
  full-suite benchmark baseline with both explicit profiles.
- `docs/BENCHMARK_RESULTS_2026-08-05.md`: paired WSL2/Linux and native Windows
  benchmark scores captured during the prior `0.5.0-dev.0` development line.
- `docs/evidence/WINDOWS_NATIVE_VALIDATION_2026-08-25.md`: current elevated
  Windows Wintun lifecycle, route/DNS rollback, WFP smoke, and remaining
  packet-path gates.
- `docs/evidence/CROSS_PLATFORM_NATIVE_TUN_VALIDATION_2026-08-25.md`:
  current Windows-to-Linux direct-TCP IPv4 forwarding evidence and its
  remaining coverage limits.
- `docs/evidence/OPTIONAL_XRAY_UNDERLAY_VALIDATION_2026-08-25.md`:
  bounded optional SOCKS5/Xray and Quick Tunnel interoperability evidence.
- `docs/evidence/WINDOWS_NATIVE_VALIDATION_2026-08-09_POST_LOADER.md`: historical
  post-loader Windows validation record.
- `docs/SHROUD2_BENCHMARK_RESULTS_2026-08-04.md`: versioned Shroud 2.0 morphology evidence.
- `docs/MORPHOLOGY_PERFORMANCE.md`: adaptive morphology, reusable-buffer
  tuning, owned-edge relay measurement, and explicit performance boundaries.
- `docs/PHANTOM_ONE_DESIGN.md`: versioned Phantom One boundary, edge separation, and
  explicit non-claims.
- `docs/PHANTOM_ONE_OPERATOR.md`: opt-in TCP operator workflow and edge-prototype
  limitations.
- `docs/PHANTOM_ONE_TESTING.md`: Phantom One testing and evidence taxonomy.
- `docs/PHANTOM_ONE_RELIABILITY.md`: Phantom One lifecycle, cleanup, and bounded-failure
  hardening goals.
- `docs/BENCHMARK_RESULTS_2026-07-28.md`: historical WSL2 benchmark scores and
  the explicit list of measurements still requiring live/native infrastructure.
- `docs/PHASE_D_HARDENING_2026-07-28.md`: fuzzing, QUIC-shim repeatability,
  profile comparison, and operator-skip evidence for Phase D.
- `docs/SUPPORT_MATRIX.md`: authoritative release profile, support levels, and
  non-claims boundary.
- `docs/RELEASE_READINESS.md`: binding release gates and evidence package
  requirements.
- `docs/WHY_CHOOSE_SHPH.md`: public positioning and fit comparison.
- `docs/QUALITY_EVIDENCE.md`: current release validation and benchmark summary.
- `docs/SECURITY_EVIDENCE.md`: threat-to-control mapping, evidence tiers, and
  publication redaction checklist.

## Repository Layout

- Source code lives in the top-level crates.
- Public documentation lives in `README.md`, `CONTRIBUTING.md`, `SECURITY.md`,
  and `docs/`.
- Generated validation records live in `docs/evidence/`.

## Evidence and Historical Artifacts

- Current methodology: `docs/BENCHMARKING.md`.
- Focused defensive rejection evidence:
  `docs/BENCHMARK_RESULTS_2026-08-25.md`.
- Current candidate evidence campaign:
  `docs/BENCHMARK_RESULTS_2026-08-23.md`.
- Extended local evidence campaign:
  `docs/BENCHMARK_EXTENDED_RESULTS_2026-08-18.md`.
- Network-simulation audit:
  `docs/NETWORK_SIMULATION_EVIDENCE_2026-08-17.md`.
- Current Windows-local score:
  `docs/BENCHMARK_RESULTS_2026-08-14.md`.
- Current paired platform scores:
  `docs/BENCHMARK_RESULTS_2026-08-05.md`.
- Current native Windows lifecycle validation:
  `docs/evidence/WINDOWS_NATIVE_VALIDATION_2026-08-25.md`.
- Current cross-platform native-TUN forwarding validation:
  `docs/evidence/CROSS_PLATFORM_NATIVE_TUN_VALIDATION_2026-08-25.md`.
- Current Shroud report: `docs/SHROUD2_BENCHMARK_RESULTS_2026-08-04.md`.
- Historical benchmark reports remain in `docs/` for regression comparison and
  are labeled by date; they are not the current score source.
- Current generated gate evidence lives under `docs/evidence/` and is refreshed
  by `scripts/capture_evidence.sh`.
- Local release/security collectors write engineering snapshots under the
  ignored `benchmark-runs/` directory:
  `scripts/release_readiness.ps1` and `scripts/security_evidence.ps1`.
- Public evidence records are retained under `docs/evidence/` and named by
  validation type and date. Internal assessment and project-context records
  are kept outside the publishable checkout.

## Excluded or Local-Only Artifacts

- `target/`
- IDE metadata folders (`.idea/`, `.vscode/`)
- `fuzz/corpus/` and `fuzz/artifacts/`
- the root `Cargo.lock` when syncing between Linux and Windows
- local tool and placeholder directories

The optional synchronization script can copy `.git/` so two repositories share
history and tags. The standalone `benchmarks/Cargo.lock` and `fuzz/Cargo.lock`
are mirrored; only the root application lockfile is excluded to avoid
cross-platform lock drift.

## Validation Ownership

- Docs and docs-only changes are kept in `docs/*`.
- Test command guidance lives in `docs/TESTING.md`.
- Current code-status is tracked in `README.md`.
- Product support status is tracked in `docs/SUPPORT_MATRIX.md`; release
  eligibility is tracked by `docs/RELEASE_READINESS.md`.

## Review boundaries

Internal assessments, maintainer context notes, and audit dispositions are
not part of the public documentation set. Public reviewers should use
`SECURITY.md`, `docs/RISK_MATRIX.md`, `docs/TESTING.md`, and the reviewed
evidence artifacts instead; none of those documents represents an independent
third-party audit.
- `fuzz/README.md`: fuzzing setup, targets, and bounded run commands.
