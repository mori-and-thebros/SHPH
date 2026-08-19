# Optional Reachability Add-on

SHPH supports an explicit, opt-in SOCKS5 underlay for outbound TCP
connections. The intended use is a locally running Xray-compatible client (or
another SOCKS5 implementation) when the direct route to an SHPH host is not
usable.

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
```

For a persistent `up` session, the same value can be stored in the session
configuration:

```toml
[session]
role = "connect"
peer = "198.51.100.10:443"
timeout_secs = 10
underlay = "socks5://127.0.0.1:10808"
```

The `--underlay` command-line value takes precedence over the session value.
If neither is present, SHPH uses direct TCP.

`socks5h://host:port` is accepted as an alias and normalized to
`socks5://host:port`. The destination SHPH hostname is sent to the proxy as a
SOCKS5 domain target; the proxy address itself is resolved by the local
operating system.

## Deliberate limits

- Only outbound TCP supports this add-on.
- The SHPH SOCKS5 client offers the no-auth method only.
- Proxy credentials, proxy auto-discovery, QUIC-over-SOCKS, and a bundled Xray
  runtime are not implemented.
- The SOCKS5 listener must not be treated as a public SHPH service endpoint.
- The proxy can still observe connection timing, destination metadata
  available to it, and traffic volume. This feature does not claim to defeat
  all traffic analysis or censorship.
- If the local proxy is unavailable, SHPH fails the connection attempt; it
  does not silently fall back to direct TCP.

## Validation

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

To validate a real deployment, run the SHPH host and local SOCKS5 listener in
the same controlled environment, then compare:

```powershell
Test-NetConnection <host-ip> -Port <host-port>
shph --config <client-config> connect --peer <host-ip>:<host-port> `
  --underlay socks5://127.0.0.1:10808
```

The first command checks the direct route only. The second command is the
underlay path and is the meaningful end-to-end test.
