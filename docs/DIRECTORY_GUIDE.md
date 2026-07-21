# SHPH Directory Guide (Current Working Copy)

This file is the canonical map for `SHPH_working_copy`.

## Top-level Layout

- `Cargo.toml`: workspace definition and shared dependency setup.
- `Cargo.lock`: locked dependency graph.
- `README.md`: entry point, status, and quick start instructions.
- `ROADMAP_OSS_AND_DELIVERY.md`: roadmap and funding-readiness plan.
- `docs/`: operator/docs set (testing, control plane, TUI, directory guide).
- `shph-cli/`: command-line binary and integration tests.
- `shph-config/`: config model and parser.
- `shph-core/`: handshake, framing, transport negotiation primitives.
- `shph-obfuscation/`: protocol-shaping extension surface.
- `shph-transport/`: transport enum and socket/parsing support.
- `shph-tun/`: TUN abstraction crate.
- `shph-tui/`: optional terminal UI shell.
- `fuzz/`: standalone cargo-fuzz targets for parser and replay robustness.
- `docs/BENCHMARKING.md`: Linux-first benchmark methodology, profiles, and obstacles.

## Workspace Workspace Paths to Remember

- Linux source working tree:
  - `/home/mori/SHPH_working_copy`
- Windows funding mirror (cleaned):
  - `D:\FUNDING NEEDED\snap-shroud-rs`

## Excluded Artifacts (Do Not Keep in Source-Tracked Mirror)

- `target/`
- `.git/`
- IDE metadata folders (`.idea/`, `.vscode/`)
- backups/totally unrelated temp directories (e.g., `THE WORKING ONE/`)

## Validation Ownership

- Docs and docs-only changes are kept in `docs/*`.
- Test command guidance lives in `docs/TESTING.md`.
- Current code-status is tracked in `README.md`.

## External Reviews

- `docs/DESCRIBE_PROJECT_SONNET5.md`: independent external project description
  and threat model (adversary-by-adversary coverage table), read from the code
  rather than from the project's own docs.
- `docs/EXTERNAL_AUDIT_SONNET5.md`: independent external gate-verification
  audit (fmt/clippy/build/test/audit run live, mirror-parity check, findings).
- `fuzz/README.md`: fuzzing setup, targets, and bounded run commands.
