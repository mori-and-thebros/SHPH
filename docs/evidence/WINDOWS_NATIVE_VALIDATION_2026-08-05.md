# Native Windows Validation — 2026-08-05

## Host and Toolchain

- Environment: native Windows checkout
- OS: Windows `10.0.26200.0`
- PowerShell: `5.1.26100.8875`
- Rust: `rustc 1.96.0 (ac68faa20 2026-05-25)`
- Workspace version: `0.5.0-dev.0`

## Commands

```powershell
cargo build --release --manifest-path benchmarks/Cargo.toml --locked
.\scripts\benchmark_windows.ps1 `
  -Suite all -Iterations 5000 -Frames 100000 `
  -OutputDirectory .\benchmark-runs\2026-08-05-windows-final

cargo fmt --all -- --check
cargo check --workspace --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
cargo build --workspace --release --locked
```

## Results

- Benchmark executable build: pass
- `secure-default` benchmark capture: pass
- `classical-lab` benchmark capture: pass
- Format check: pass
- Workspace check: pass
- Strict Clippy: pass
- Workspace tests: 176 passed, 0 failed
- Release workspace build: pass

The first native Windows test run exposed a test portability defect in the
multi-DNS assertion: Windows correctly emits one `netsh set dns` command and
one `netsh add dnsserver` command for two IPv4 servers, while the test assumed
the Linux `resolvectl` shape. The assertion was corrected to validate both
platform contracts, and the complete Windows gates were rerun successfully.

## Scope Boundary

This is native Windows execution evidence for the local benchmark and
workspace. It does not yet validate signed Wintun provenance, administrator
elevation, adapter creation, packet receive/send, route/DNS mutation on a live
adapter, reconnect over two hosts, or native Windows TUN throughput.

Raw benchmark files:

- `benchmark-runs/2026-08-05-windows-final/secure-default.csv`
- `benchmark-runs/2026-08-05-windows-final/classical-lab.csv`
