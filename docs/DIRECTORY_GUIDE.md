# SHPH Directory Guide

This file is the canonical map for an SHPH checkout.

## Top-level Layout

- `Cargo.toml`: workspace definition and shared dependency setup.
- `Cargo.lock`: locked dependency graph.
- `README.md`: entry point, status, and quick start instructions.
- `ROADMAP_OSS_AND_DELIVERY.md`: roadmap and funding-readiness plan.
- `docs/MILESTONE_SCORECARD.md`: phase scorecard, including the active
  Shroud, hardening/optimization, release-readiness, and Windows TUN gates.
- `docs/`: operator/docs set (testing, control plane, TUI, directory guide).
- `shph-cli/`: command-line binary and integration tests.
- `shph-config/`: config model and parser.
- `shph-core/`: handshake, framing, transport negotiation primitives.
- `shph-obfuscation/`: protocol-shaping extension surface.
- `shph-transport/`: transport enum and socket/parsing support.
- `shph-tun/`: TUN abstraction crate.
- `shph-tui/`: optional terminal UI shell.
- `fuzz/`: standalone cargo-fuzz targets for parser and replay robustness.
- `benchmarks/`: standalone benchmark crate; its lockfile is intentionally
  separate from the application workspace.
- `scripts/`: reproducible demos, benchmark operators, evidence capture, and
  Linux/Windows mirror synchronization.
- `docs/BENCHMARKING.md`: Linux-first benchmark methodology, profiles, and obstacles.
- `docs/BENCHMARK_RESULTS_2026-08-05.md`: paired WSL2/Linux and native Windows
  benchmark scores for workspace version `0.5.0-dev.0`.
- `docs/SHROUD2_BENCHMARK_RESULTS_2026-08-04.md`: versioned Shroud 2.0 morphology evidence.
- `docs/BENCHMARK_RESULTS_2026-07-28.md`: historical WSL2 benchmark scores and
  the explicit list of measurements still requiring live/native infrastructure.
- `docs/PHASE_D_HARDENING_2026-07-28.md`: fuzzing, QUIC-shim repeatability,
  profile comparison, and operator-skip evidence for Phase D.

## Evidence and Historical Artifacts

- Current methodology: `docs/BENCHMARKING.md`.
- Current paired platform scores:
  `docs/BENCHMARK_RESULTS_2026-08-05.md`.
- Current Shroud report: `docs/SHROUD2_BENCHMARK_RESULTS_2026-08-04.md`.
- Historical benchmark reports remain in `docs/` for regression comparison and
  are labeled by date; they are not the current score source.
- Current generated gate evidence lives under `docs/evidence/` and is refreshed
  by `scripts/capture_evidence.sh`.

## Excluded or Local-Only Artifacts

- `target/`
- IDE metadata folders (`.idea/`, `.vscode/`)
- `fuzz/corpus/` and `fuzz/artifacts/`
- the root `Cargo.lock` when syncing between Linux and Windows
- local-only directories such as `THE WORKING ONE/`, `.agents/`, `.codex/`,
  and `.gapcode/`

The mirror script intentionally copies `.git/` so both repositories share
history, tags, and `HEAD`. The standalone `benchmarks/Cargo.lock` and
`fuzz/Cargo.lock` are mirrored; only the root application lockfile is excluded
to avoid cross-platform lock drift.

## Validation Ownership

- Docs and docs-only changes are kept in `docs/*`.
- Test command guidance lives in `docs/TESTING.md`.
- Current code-status is tracked in `README.md`.

## Review And Fuzzing

- `docs/HARDENING.md`: public hardening summary and threat impact.
- `fuzz/README.md`: fuzzing setup, targets, and bounded run commands.
