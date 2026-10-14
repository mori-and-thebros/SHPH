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

`PhantomOneConfig::for_profile(profile)` can opt into
`SizeSelection::Weighted([u16; 7])`; entries follow the profile's canonical
base-tier order, and unused entries must be zero. `with_padding_budget(bytes)`
sets a session-lifetime limit on random tail-padding bytes. Selection fails
closed if an eligible target cannot fit the remaining budget. Weighted mode is
experimental and does not establish traffic-analysis resistance.

## Experimental policy agreement

`shph_transport::envelope_policy` provides opt-in `NegotiatedTcp` and
`NegotiatedQuic` wrappers. Both peers exchange a bounded v2 offer inside the
already-authenticated session, bind it to the handshake transcript, and verify
the same acknowledgement before the wrapper exposes application `send` and
`recv`. Offers include common profiles, padding and selection settings,
directional frame limits, and directional usage budgets; disagreement or
timeout fails closed without a legacy downgrade. A smaller current QUIC carrier
limit remains authoritative after agreement.

The one-shot CLI exposes the exchange with `send-once` and `recv-once` using
`--negotiate-envelope-policy`; it can also be enabled with
`session.negotiate_envelope_policy = true`. Both endpoints must opt in. This
path supports TCP and standards QUIC only. Persistent `up`/TUN sessions and
other adapters reject the setting rather than silently skipping negotiation.
The option is separate from the legacy Phantom One profile exchange. Do not
mix the wrappers with raw data-plane calls on the same session. Policy wire v2
is experimental and is not compatible with legacy policy peers.

For example, run the receive side and sender with the same explicit option:

```text
shph recv-once --bind 127.0.0.1:7000 --transport tcp --negotiate-envelope-policy
shph send-once --peer 127.0.0.1:7000 --text 'authorized test' --transport tcp --negotiate-envelope-policy
```

## Local active-probe baseline

`scripts/edge_active_probe.py` records bounded per-case HTTP/2 status, body
length/hash, first-byte and total timing, incomplete TLS and HTTP/2 frame
behavior, malformed HTTP/2 handling, and TCP connection churn for an
operator-owned edge. Its summary groups outcomes, statuses, body sizes,
content hashes, and timing ranges by probe. Install a `curl` build with HTTP/2
support, then expose the owned service locally or through an SSH tunnel:

```text
python3 scripts/edge_active_probe.py \
  --endpoint https://edge.example:8443 \
  --ca-file ./edge-ca.pem \
  --confirm-owned-endpoint \
  --repeat 5 \
  --churn 10 \
  --json-out ./edge-probes.json
```

The harness pins connections to `127.0.0.1`; it does not resolve or probe a
remote address. Optional expired-token and invalid-signature cases use
operator-supplied token files. `--probe-replay` additionally requires
`--allow-token-consumption`; the first request uses a valid capability and may
reach the configured backend. The first-use response body is discarded. The
replay denial body is summarized by status, size, hash, and timing; raw bodies
are not printed or included in the report. A local HTTP/2 test compares denial
responses for missing, invalid, expired, and replayed capabilities, checks
that the connection stays usable, and confirms only the authorized first use
reaches the backend. The script still requires an operator backend counter for
a service campaign. Its report does not prove indistinguishability: cache
capacity and live-host campaigns remain separate gates. The probe disables
ambient curl configuration and proxy environment routing before making its
loopback-pinned requests.

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

The edge caps capability verification with
`--max-capability-verifications-per-second` (default `256`, shared across all
clients in one-second windows). Keep the value aligned with the edge's CPU
budget and expected new-stream rate. HTTP/2 and HTTP/3 verify signatures before
waiting asynchronously for the short replay-cache commit; connection
cancellation can abandon a queued commit, and lock waits do not block a runtime
worker. With uniform fallback enabled, overload responses use the configured
normalized response. This is a global resource ceiling, not per-client
fairness; apply network-level rate controls for that purpose.

The HTTP/2 server closes connections after an application-idle interval. The
default is 30 seconds; configure `--http2-idle-timeout-ms` on `serve` between
100 and 600,000 milliseconds. Library callers set
`Limits::http2_idle_timeout_ms`. Request and response body activity refreshes
the deadline, and a connection with an active stream is not closed by this idle
timer. A client that completes TLS but does not start an HTTP/2 request is
closed when the interval expires. This bounds idle connection-slot retention;
it is not a per-client connection-rate limit.

The path is bounded and cannot contain a query, fragment, control character,
or backslash. The edge client uses a bounded HTTP/2 connection pool. Capability
tokens remain one-use: a token file with one token supports one logical SOCKS5
relay stream, while a newline-delimited file of independently issued tokens
allows multiple pooled streams without weakening replay protection. Blank lines
are ignored; token files remain bounded and must not contain secrets beyond the
intended capabilities. Restrict token files to the service user: Unix readers
reject group/other permissions (use mode `0600`); on Windows, configure the ACL
for the edge service identity and administrators only. The public-key file is
not secret and does not use this private-file check.

HTTP/3 requires building `shph-edge` with `--features http3`, operator-owned
certificate/CA material, and a separately authorized interoperability test.
The implementation is bounded and standards-library based, but remains
experimental and has no recorded two-host HTTP/3 campaign.

## Evidence boundary

Record the exact revision, host, target, toolchain, configuration, and command
for every run. Focused unit/integration tests prove only the exercised code
path. Loopback relay tests do not prove Internet reachability, throughput,
fingerprint parity, anonymity, or hostile-network behavior.
