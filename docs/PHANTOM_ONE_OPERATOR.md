# Phantom One Operator Notes

Status: prototype, explicit opt-in, authenticated TCP plus an opt-in
standards-QUIC path.

Phantom One is a versioned inner envelope for controlled SHPH TCP sessions and
the opt-in standards-QUIC path. It is not the default, does not support the
legacy QUIC shim, and does not provide a browser fingerprint, anonymity, DPI-evasion, or censorship-
resistance guarantee. Read `docs/PHANTOM_ONE_DESIGN.md` before using it.

## Host and join

The host selects Phantom One explicitly:

```text
shph --config <host-config> host \
  --transport tcp \
  --phantom-one \
  --phantom-one-profile medium \
  --shroud-profile medium \
  --no-tun
```

The resulting `shph://v1:` ticket carries the Phantom One mode and profile. A joiner
must use that complete ticket:

```text
shph --config <client-config> join '<complete-ticket>' --no-tun
```

The CLI validates the ticket and rejects Phantom One tickets paired with the
legacy `quic` shim or unsupported adapters before opening a handshake. For
`quic-standard`, both peers perform a bounded, symmetric profile exchange after
the SHPH handshake; a mismatch closes the QUIC connection. Keep peer identity and
signing-key pinning enabled; Phantom One does not replace SHPH authentication.

For an existing configuration, the opt-in form is:

```text
shph --config <config> up \
  --transport tcp \
  --phantom-one \
  --phantom-one-profile medium \
  --shroud-profile medium \
  --no-tun
```

Use the same Phantom One profile on both sides. Shroud 2 remains the default for
configurations and callers that do not opt in.

## Lower-level API

The framing module is exported as `shph_transport::phantom_one`. It is intended
for authenticated TCP sessions and must be enabled through the lab-session
configuration. The module does not encrypt or authenticate bytes itself; the
existing SHPH AEAD remains the security boundary.

Phantom One's TCP `path_mtu` argument is a logical plaintext frame budget. It must
not be used as an IP MTU, and Phantom One does not fragment packets or change host
routes.

## Edge prototype

The separate `shph-edge/` crate is an owned-domain HTTP/2 and opt-in HTTP/3
relay prototype. It requires operator-controlled TLS material and a configured
backend. It forwards
opaque bytes and uses short-lived signed capability tokens. It does not
impersonate third-party websites, provide a generic open proxy, or make
active-probe or censorship-resistance claims.

The client-side SOCKS5 listener is deliberately unauthenticated and must stay
on a loopback address. The edge configuration rejects non-loopback SOCKS
binds.

The HTTP/2 relay path defaults to `/phantom-one/v1`. If an owned deployment uses a
different path, pass the same exact value to both the serving and connecting
commands:

```text
shph-edge serve ... --relay-path /owned/relay-v2
shph-edge connect ... --relay-path /owned/relay-v2
```

The path is bounded and cannot contain a query, fragment, control character,
or backslash. The edge client uses a bounded HTTP/2 connection pool. Capability
tokens remain one-use: a token file with one token supports one logical SOCKS5
relay stream, while a newline-delimited file of independently issued tokens
allows multiple pooled streams without weakening replay protection. Blank lines
are ignored; token files remain bounded and must not contain secrets beyond the
intended capabilities.

HTTP/3 requires building `shph-edge` with `--features http3`, operator-owned
certificate/CA material, and a separately authorized interoperability test.
The implementation is bounded and standards-library based, but remains
experimental and has no recorded two-host HTTP/3 campaign.

## Evidence boundary

Record the exact revision, host, target, toolchain, configuration, and command
for every run. Focused unit/integration tests prove only the exercised code
path. Loopback relay tests do not prove Internet reachability, throughput,
fingerprint parity, anonymity, or hostile-network behavior.
