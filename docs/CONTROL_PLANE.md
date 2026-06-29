# SHPH Control Plane Notes

SHPH control-plane behavior is configured under `[control_plane]` in `config.toml`.

## Example

```toml
[control_plane]
apply_routes = true
route_cidrs = ["10.10.0.0/16"]
apply_dns = true
dns_servers = ["1.1.1.1"]
dry_run = true
```

## Modes

- `dry_run=true`:
  - validates route/DNS values,
  - prints intended mutations,
  - performs no host mutation.
- `dry_run=false`:
  - attempts live route/DNS mutation,
  - tracks applied entries in runtime guard,
  - attempts rollback on normal shutdown and failure paths.
  - **atomic preflight** (Phase A.2): all routes and DNS servers are validated
    *before* any host mutation. If any single entry is invalid, the whole apply
    is rejected and nothing is changed.

## Current Command Backends

- Linux:
  - routes: `ip route replace` / `ip route del`
  - DNS: `resolvectl dns` / `resolvectl revert`
- Windows:
  - routes: `netsh interface {ipv4|ipv6} add|delete route prefix=<cidr> interface=<name> [nexthop=<ip>]`
  - DNS: `netsh interface {ipv4|ipv6} set dns name=<name> static <server>`

## Operational Constraints

- Live apply requires appropriate privileges.
- Missing host tools are reported as unsupported operations.
- Full platform parity and richer rollback ergonomics remain an ongoing hardening task.

## Reliability Guarantees (Phase A.2)

- **Preflight validation:** the control plane builds a fully-validated
  `ControlPlanePlan` (routes + DNS) before applying. A bad CIDR or DNS IP among
  otherwise-valid entries causes the entire apply to fail with no mutation.
- **Rollback ordering:** on apply failure or shutdown, DNS is rolled back first,
  then routes, in reverse order.
- **Best-effort, error-preserving rollback:** rollback collects all errors
  rather than aborting on the first, so partial rollback still removes as much
  applied state as possible. DNS restore failures carry the real command error
  plus family/interface context.
- **Interface requirement:** a non-empty interface name is required to apply
  the control plane; an empty/blank name is rejected.

## Windows Graceful Shutdown

- Unix installs SIGINT/SIGTERM handlers (Phase A.1).
- Windows graceful shutdown via `SetConsoleCtrlHandler` is a tracked follow-up:
  it is a Win32 API not exposed by the `libc` crate, and wiring it requires a
  `windows-sys` dependency compiled and verified on the Windows toolchain.
- Until then, the Windows connect loop relies on default Ctrl+C termination but
  still checks the shutdown flag between stdin lines.
