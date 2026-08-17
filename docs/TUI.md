# SHPH TUI (Optional)

`shph-tui` is an operator-facing, read-only dashboard layered on top of the
SHPH configuration state. It is designed for quick inspection; privileged
session and route/DNS actions remain explicit CLI operations.

## Run

```bash
cargo run -p shph-tui
cargo run -p shph-tui -- --config /path/to/config.toml
```

## Dashboard views

- **Overview**: interface, endpoint, peer/session summary, and readiness checks.
- **Peers**: browse configured peers and inspect endpoint/key presence without
  displaying private material.
- **Session**: review persistent session settings and reconnect policy.
- **Control plane**: review configured routes, DNS servers, and dry-run mode.

The dashboard reloads the configuration on demand and displays a clear error
state when the file is missing or invalid.

## Keybindings

| Key | Action |
| --- | --- |
| `1` | Overview |
| `2` | Peers |
| `3` | Session |
| `4` | Control plane |
| `Tab` | Next view |
| `r` | Reload configuration |
| `j`/`k`, `↑`/`↓` | Select a peer |
| `?` | Help overlay |
| `q`, `Esc` | Quit |

## Scope

- The TUI is intentionally read-only in this phase.
- The CLI remains the stable automation/control backend.
- Use `shph doctor` before starting a session and `shph status` for
  machine-readable or script-friendly status.
