# Optional Reachability Add-on

SHPH supports an explicit, opt-in SOCKS5 underlay for outbound TCP
connections, including an operator-managed Tor SOCKS endpoint. The intended use
is a locally running proxy when the direct route to an SHPH host is not usable.

This is a route adapter, not a replacement transport. SHPH still performs the
same authenticated, end-to-end handshake and encrypted framing after the
SOCKS5 `CONNECT` succeeds.

## Data path

```text
SHPH client
    |
    | normal SHPH TCP stream
    v
local SOCKS5 listener
    |
    | external, operator-selected route
    v
SHPH host:443
```

The external proxy is not bundled with SHPH and is not configured or managed
by SHPH. This keeps the boundary clear: SHPH owns the authenticated protocol;
the add-on owns only the outbound socket path.

## Usage

Start and secure the local SOCKS5 listener using its own documentation. Keep
it bound to loopback unless there is a deliberate, separately authenticated
network design.

Then select the underlay explicitly:

```bash
shph join --underlay socks5://127.0.0.1:10808 'shph://v1:...'

shph up --to 198.51.100.10:443 \
  --underlay socks5://127.0.0.1:10808 \
  --no-tun

shph connect --peer 198.51.100.10:443 \
  --underlay socks5://127.0.0.1:10808

shph send-once --peer 198.51.100.10:443 \
  --text 'underlay smoke test' \
  --underlay socks5://127.0.0.1:10808

shph connect --peer relay.example.onion:443 \
  --underlay tor://127.0.0.1:9050
```

The `tor://` underlay accepts only a literal loopback SOCKS endpoint. It offers
SOCKS5 username/password authentication with fresh random credentials for each
connection, supporting proxy-side auth-based stream isolation. SHPH does not
manage Tor circuits or isolation policy. Peer hostnames, including `.onion`
names, are sent to the proxy as SOCKS domain targets rather than resolved by
SHPH locally.

For a temporary or changing relay endpoint, keep the ticket in an
owner-only file instead of copying a long command-line value:

```bash
shph host --port 443 \
  --advertise relay.example:443 \
  --ticket-file /run/shph/join.ticket

shph join --ticket-file ./join.ticket \
  --underlay socks5://127.0.0.1:10808 \
  --transport-peer 127.0.0.1:8443
```

`--ticket-file` is bounded and read as UTF-8. Host and identity commands write
the file with owner-only permissions where the platform supports them. The
ticket file is a handoff mechanism, not a secret store: it contains the
advertised endpoint and public identity keys.

Before changing local configuration or opening a TUN interface, run the
no-mutation preflight:

```bash
shph join --ticket-file ./join.ticket \
  --underlay socks5://127.0.0.1:10808 \
  --transport-peer 127.0.0.1:8443 \
  --check
```

The preflight validates the ticket, checks the selected transport path, and
performs one authenticated handshake. It does not write configuration, change
routes or DNS, create a TUN interface, or overwrite peer pins.

For a persistent `up` session, the same value can be stored in the session
configuration:

```toml
[session]
role = "connect"
peer = "198.51.100.10:443"
timeout_secs = 10
underlay = "socks5://127.0.0.1:10808"
```

Use `underlay = "tor://127.0.0.1:9050"` to select an operator-managed Tor
SOCKS listener instead. Omitting `underlay` continues to select direct TCP.

The `--underlay` command-line value takes precedence over the session value.
If neither is present, SHPH uses direct TCP.

For a relay that terminates on the SHPH host itself, `peer` can remain the
public, pinned identity selector while `transport_peer` names the relay's
internal destination:

```toml
[session]
role = "connect"
peer = "relay.example:443"
transport_peer = "127.0.0.1:8443"
underlay = "socks5://127.0.0.1:10808"
```

`transport_peer` changes only the socket destination. Peer identity and policy
verification still use `peer`; it must not be used to bypass the configured
peer pin.

For an existing persistent session, `shph doctor --deep --json` performs the
same style of underlay listener and handshake checks without applying the
configured control plane. It is intended for operator diagnostics and may
report a failure when the external SOCKS5/Xray process or relay is offline.

`socks5h://host:port` is accepted as an alias and normalized to
`socks5://host:port`. The destination SHPH hostname is sent to the proxy as a
SOCKS5 domain target; the proxy address itself is resolved by the local
operating system.

## Deliberate limits

- Only outbound TCP supports this add-on.
- The generic `socks5://` underlay offers no-auth only. The Tor-specific
  `tor://` mode requires a loopback proxy and offers fresh SOCKS auth
  credentials per connection; user-configurable proxy credentials,
  auto-discovery, QUIC-over-SOCKS, and a bundled Tor/Xray runtime are not
  implemented.
- Tor underlay selection alone does not establish native-TUN routing or
  containment through Tor. Do not claim full VPN operation through Tor without
  separate route-containment validation.
- SOCKS setup is bounded by the TCP handshake deadline, but the synchronous
  connect API does not expose cancellation during proxy setup.
- The SOCKS5 listener must not be treated as a public SHPH service endpoint.
- The proxy can still observe connection timing, destination metadata
  available to it, and traffic volume. This feature does not claim to defeat
  all traffic analysis or censorship.
- If the local proxy is unavailable, SHPH fails the connection attempt; it
  does not silently fall back to direct TCP.

## Validation

The repository includes bounded local Xray checks for the two operator
environments:

```powershell
.\scripts\check_xray.ps1
```

```bash
chmod +x scripts/check_xray.sh
./scripts/check_xray.sh
```

They validate the Xray configuration, confirm a loopback SOCKS inbound, and
perform only the SOCKS5 no-auth method probe. They do not print credentials or
attempt to connect to an arbitrary Internet destination.

Run the deterministic transport tests:

```bash
cargo test -p shph-transport --locked
cargo test -p shph-cli --locked
```

For a local protocol smoke test, the transport test suite includes a fake
SOCKS5 listener that verifies:

- the no-auth method negotiation;
- a domain-form `CONNECT` request;
- the requested destination and port; and
- consumption of a successful SOCKS5 bound-address response.

Tor-specific fake-proxy tests also verify fresh auth credentials across
connections, `.onion` domain forwarding, timeout behavior, and failure closure
without a direct peer connection. A live Tor campaign remains separate and is
recorded as `SKIP` when no authorized Tor endpoint is available.

To validate a real deployment, run the SHPH host and local SOCKS5 listener in
the same controlled environment, then compare:

```powershell
Test-NetConnection <host-ip> -Port <host-port>
shph --config <client-config> connect --peer <host-ip>:<host-port> `
  --underlay socks5://127.0.0.1:10808
```

The first command checks the direct route only. The second command is the
underlay path and is the meaningful end-to-end test.
