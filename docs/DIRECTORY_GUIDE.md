# SHPH Directory Guide (Current Working Copy)

This file is the canonical map for `SHPH_working_copy`.

## Top-level Layout

- `Cargo.toml`: workspace definition and shared dependency setup.
- `Cargo.lock`: locked dependency graph.
- `README.md`: entry point, status, and quick start instructions.
- `ROADMAP_OSS_AND_DELIVERY.md`: roadmap and funding-readiness plan.
- `docs/`: operator/docs set (testing, control plane, TUI, directory guide).
- `src/`: helper error/crypto modules used by root-level utilities.
- `shph-cli/`: command-line binary and integration tests.
- `shph-config/`: config model and parser.
- `shph-core/`: handshake, framing, transport negotiation primitives.
- `shph-obfuscation/`: protocol-shaping extension surface.
- `shph-transport/`: transport enum and socket/parsing support.
- `shph-tun/`: TUN abstraction crate.
- `shph-tui/`: optional terminal UI shell.

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
