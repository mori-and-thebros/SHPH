# Reproducible operator campaigns

`scripts/operator_campaigns.py` provides bounded, cross-platform campaigns for
failure and network-edge behavior. It uses fresh temporary identities for local
TCP sessions and writes one result directory per run under
`benchmark-runs/campaigns/` by default. Choose a new output directory for every
run; an existing directory is never overwritten.

The runner returns:

- `0` when the campaign passes;
- `1` when the campaign ran and found a failure;
- `2` for invalid input;
- `3` when a required host capability is unavailable.

Every result includes `result.json`, `result.md`, and the raw command logs
needed to inspect the claim. The metadata records the current revision and
whether the source tree was dirty. These are lab/operator records, not proof of
production VPN behavior, anonymity, censorship resistance, or an independent
security audit.

## Local TCP reliability

Build `shph` first, then run the bounded reconnect and fresh-process soak
campaigns:

```bash
python scripts/operator_campaigns.py reconnect \
  --output benchmark-runs/campaigns/reconnect-20260901

python scripts/operator_campaigns.py soak \
  --sessions 10 \
  --output benchmark-runs/campaigns/soak-20260901
```

`reconnect` starts two pinned peers, verifies an initial handshake, hard-stops
the listener, waits for a bounded retry, restarts the listener, and verifies a
second handshake plus payload delivery. `soak` uses a fresh identity pair and
fresh endpoint for each one-shot authenticated exchange. Neither campaign
proves long-duration uptime, native-TUN forwarding, or two-host routing.

## IPv6

The IPv6 campaign repeats the same one-shot exchange over IPv6 loopback:

```bash
python scripts/operator_campaigns.py ipv6 \
  --sessions 3 \
  --output benchmark-runs/campaigns/ipv6-20260901
```

This is IPv6 socket and protocol coverage on the local host. It does not prove
Internet IPv6 reachability, router behavior, native-TUN IPv6 forwarding, or
DNS64/NAT64 compatibility.

## DNS control-plane behavior

The default mode is deliberately non-mutating. It initializes a temporary
configuration, runs `apply`, `reconcile`, and `undo` with `dry_run = true`, and
checks that the expected DNS plan is emitted:

```bash
python scripts/operator_campaigns.py dns \
  --output benchmark-runs/campaigns/dns-dry-run-20260901
```

Live apply is guarded and requires an explicitly supplied configuration plus
the platform privilege needed by SHPH:

```bash
sudo python scripts/operator_campaigns.py dns \
  --live \
  --config /etc/shph/config.toml \
  --output benchmark-runs/campaigns/dns-live-20260901
```

Live mode uses `control_plane.dns_servers` from the supplied configuration and
rejects `--servers` to avoid reporting DNS values that are not actually applied.
It always invokes `undo` after attempting `apply`, including timeout and failure
paths. Resolver effectiveness and host-specific rollback must still be checked
by the operator. Do not use a production configuration for an unreviewed
campaign.

## PMTU probing

PMTU mode accepts only a literal IP address and records each platform `ping`
result, including the payload size and raw per-size log:

```bash
python scripts/operator_campaigns.py pmtu \
  --host 198.51.100.10 \
  --min-payload 1200 \
  --max-payload 1472 \
  --step 16 \
  --output benchmark-runs/campaigns/pmtu-20260901
```

Use `--ipv6` for an IPv6 literal. The result reports the largest successful
probe; it intentionally does not infer a production path MTU from a loopback
or single-host observation. Firewalls, routing, and the selected interface can
make a probe fail independently of the tunnel.

## Crash and forced termination

Crash mode is opt-in because it sends a hard termination to the supplied
`shph up` process:

```bash
python scripts/operator_campaigns.py crash \
  --config /path/to/prepared/config.toml \
  --confirm-kill \
  --up-arg=--no-tun \
  --cleanup \
  --output benchmark-runs/campaigns/crash-20260901
```

The runner waits for a caller-selected readiness marker, terminates the target,
and can invoke `shph down` afterward. It does not claim that routes, DNS,
firewall policy, Wintun, or a native TUN device were cleaned up. Those states
must be checked with the platform-specific privileged procedure in
`docs/RELEASE_READINESS.md`.

## WSL2 and native-TUN boundary

WSL2 is useful for workspace tests, standalone edge/HTTP/3 checks, fuzz smoke,
and local IPv4/IPv6 campaigns when its toolchains are installed. WSL2 is not
substituted for native Linux or Windows release evidence. The namespace and
native-TUN helpers report `SKIP` when WSL2 does not grant the required
`CAP_NET_ADMIN`, `/dev/net/tun`, or namespace capability.

For the complete release claim, pair these records with a dedicated native
Linux or elevated Windows TUN campaign and retain the exact host, privilege,
toolchain, and cleanup observations.
