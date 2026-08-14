# SHPH TUI (Optional)

`shph-tui` is an operator-facing terminal interface layered on top of the CLI/config state.

## Run

```bash
cargo run -p shph-tui
```

## Current Behavior

- Loads default config path (`~/.shph/config.toml`).
- Shows a snapshot view:
  - interface
  - endpoint
  - peer count
  - session settings
  - control-plane settings
- Keybindings:
  - `q`: quit
  - `r`: reload config

## Scope

- Intended as an optional UX layer.
- CLI remains the stable automation/control backend.
