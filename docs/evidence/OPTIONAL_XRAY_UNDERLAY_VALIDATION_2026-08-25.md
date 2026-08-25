# Optional SOCKS5/Xray Underlay Validation - 2026-08-25

This report covers the optional local SOCKS5/Xray-compatible underlay. It is
not part of SHPH's direct TCP release lane and does not claim that Xray,
Cloudflare Quick Tunnel, or any particular reachability provider is
reliable in every network.

## Scope

| Field | Value |
| --- | --- |
| SHPH transport | Authenticated TCP |
| Underlay | Local SOCKS5 listener provided by Xray |
| Relay path | Xray WebSocket transport through a Cloudflare Quick Tunnel to the Linux host |
| SHPH profile | `medium` |
| TUN | Disabled for this check |
| Client identity | Existing authorized lab identity; no new identity was added to the host |
| Validation source | Working tree based on `e44483897574d39a550b2c145d47fc480ffa4e5b`; published in the `v0.6.5-dev.1` follow-up |

No ticket, UUID, private key, password, absolute user path, or raw service log
is included in this report.

## Results

| Check | Result |
| --- | --- |
| Local Xray configuration test | PASS |
| Local SOCKS5 listener | PASS; listener responded on loopback |
| VPS Xray inbound and routing | PASS; WebSocket inbound was routed to the local SHPH listener |
| Cloudflare Quick Tunnel service | PASS; service active and provider prechecks healthy |
| SHPH preflight through SOCKS5 | PASS; peer policy and transcript authentication completed |
| SHPH no-TUN handshake through SOCKS5 | PASS |
| SHPH one-shot payload through SOCKS5 | PASS; 21 payload bytes and 1 encrypted packet, clean exit |
| Full-route and long-lived underlay session | NOT CLAIMED; not validated by this bounded run |

During diagnosis, a stale Quick Tunnel hostname and stale local peer pins
caused expected connection failures. The hostname was synchronized and a
fresh isolated configuration was used. The existing peer policy correctly
rejected an unrelated new client identity; the authorized lab identity then
completed the preflight and payload checks.

An ordinary HTTPS request sent directly through the SOCKS listener is not a
valid SHPH test: the SOCKS listener is configured to carry the SHPH/Xray
underlay, not to act as a general-purpose browser proxy. That probe was
therefore not used as a SHPH success or failure metric.

## Boundaries

This result does not establish:

- censorship resistance or DPI evasion;
- Quick Tunnel uptime or a stable public endpoint;
- full-route operation through the add-on;
- multi-hour or multi-day reconnect behavior;
- IPv6, UDP, QUIC, DNS, or browser traffic forwarding through the add-on; or
- production readiness of Xray or Cloudflare.

The Quick Tunnel is accountless and ephemeral in this lab. A hostname change
requires regenerating the SHPH host ticket and synchronizing the Xray client
configuration. A named, provider-managed tunnel would be a separate
deployment choice and evidence scope.
