# SHPH Control Plane Notes

SHPH control-plane behavior is configured under `[control_plane]` in `config.toml`.

## Example

```toml
[control_plane]
apply_interface_address = true
interface_cidr = "10.250.0.2/30"
apply_routes = true
route_cidrs = ["10.250.0.1/32"]
# Keep the local SOCKS/Quick Tunnel endpoint on the physical underlay.
underlay_bypass_cidrs = ["203.0.113.10/32"]
apply_dns = true
dns_servers = ["1.1.1.1"]
dry_run = true
```

## Modes

- `dry_run=true`:
  - validates interface-address, route, and DNS values,
  - prints intended mutations,
  - performs no host mutation.
- `dry_run=false`:
  - attempts live interface-address, route, and DNS mutation,
  - tracks applied entries in runtime guard,
  - attempts rollback on normal shutdown and failure paths.
  - **atomic preflight** (Phase A.2): all routes and DNS servers are validated
    *before* any host mutation. If any single entry is invalid, the whole apply
    is rejected and nothing is changed.

`underlay_bypass_cidrs` is an explicit safety control for full-tunnel sessions
that use a local SOCKS5 underlay. Each listed endpoint route is installed on
the current physical/default interface before SHPH installs the configured
default route. On Windows, SHPH discovers the active default gateway and
interface with the native networking cmdlets; on Linux, it derives them from
`ip route get`. These routes are persisted with the other control-plane state
and removed during `undo`, `down`, normal shutdown, or failed apply.

## Commands

- `shph apply` validates and applies configured routes/DNS. Live applies persist
  the exact applied state beside the config as `<config>.control-plane.json`.
- `shph reconcile` removes recorded state, then applies the current
  configuration. It is safe to repeat.
- `shph undo` removes recorded routes/DNS and deletes the state file.
- `shph down` invokes `undo` before exiting.
- `shph status` reports whether persisted control-plane state is present.

`apply_interface_address=true` is intentionally opt-in. It assigns the local
layer-3 address to the native TUN interface; it does not create a default
route. A typical two-node lab uses `10.250.0.1/30` on the listener and
`10.250.0.2/30` on the connector, with a narrow `/32` route for the opposite
endpoint before attempting broader routing.

SHPH refuses a `0.0.0.0/0` or `::/0` route when the session uses a SOCKS5
underlay unless `underlay_bypass_cidrs` is configured. Without an explicit
route that keeps the proxy's upstream endpoint outside the TUN, the proxy
connection can loop back into SHPH and disconnect the tunnel. Resolve the
actual Quick Tunnel/Xray endpoint first, add its address as a `/32` (or `/128`)
entry, and test the bypass before enabling full-tunnel routing. Keep the list
current if the endpoint's address changes.

## Host leak containment

Firewall containment is a separate, explicit `up` option rather than a
configuration-file default:

- `shph up --killswitch` installs an SHPH-owned policy before native TUN setup.
  Linux uses a dedicated `inet shph_killswitch` nftables table; Windows uses
  persistent, elevated WFP outbound authorization filters.
- Killswitch mode accepts only literal peer IP addresses and non-zero ports.
  Hostname endpoints are rejected so DNS resolution cannot precede the
  allowlist.
- `shph up --killswitch --killswitch-dry-run` prints the bounded plan without
  requiring native TUN, elevation, or firewall mutation.
- `shph up --mss-clamp` installs a separate Linux nftables table for
  bidirectional TCP SYN MSS clamping. Windows reports this option as
  unsupported in the current build.
- `shph down` attempts to remove SHPH-owned firewall state in addition to
  recorded routes and DNS. A cleanup failure is returned to the operator.

These controls remain opt-in and platform-gated. They are source-level
hardening plus command planning until privileged crash-leak and two-host
validation is published.

## Current Command Backends

- Linux:
  - interface address: `ip address add` / `ip address delete`
  - routes: `ip route add` / `ip route del` (avoids deleting a pre-existing route during rollback)
  - DNS: `resolvectl dns` / `resolvectl revert`
- Windows:
  - interface address: `netsh interface ipv4 add|delete address`
  - routes: `netsh interface {ipv4|ipv6} add|delete route prefix=<cidr> interface=<name> [nexthop=<ip>]`
  - DNS: `netsh interface {ipv4|ipv6} set dns name=<name> static <server>`

## Operational Constraints

- Live apply requires appropriate privileges.
- Linux route apply uses `ip route add`, so an existing route is not silently
  replaced and later deleted by SHPH rollback.
- Missing host tools are reported as unsupported operations.
- Full platform parity and richer rollback ergonomics remain an ongoing hardening task.

## Reliability Guarantees (Phase A.2)

- **Preflight validation:** the control plane builds a fully-validated
  `ControlPlanePlan` (interface address + routes + DNS) before applying. A bad
  CIDR or DNS IP among
  otherwise-valid entries causes the entire apply to fail with no mutation.
- **Rollback ordering:** on apply failure or shutdown, DNS is rolled back first,
  then routes in reverse order, then the SHPH-added interface address.
- **Best-effort, error-preserving rollback:** rollback collects all errors
  rather than aborting on the first, so partial rollback still removes as much
  applied state as possible. DNS restore failures carry the real command error
  plus family/interface context.
- **Interface requirement:** a non-empty interface name is required to apply
  the control plane; an empty/blank name is rejected.

## Graceful Shutdown

- Unix installs SIGINT/SIGTERM handlers.
- Windows installs a `SetConsoleCtrlHandler` callback for Ctrl+C, Ctrl+Break,
  console close, logoff, and system shutdown events.
- Session loops poll the shared shutdown flag and perform normal cleanup.
