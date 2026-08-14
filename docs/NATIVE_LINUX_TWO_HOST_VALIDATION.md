# Native Linux Two-Host Validation

`scripts/validate_linux_two_host.sh` captures the native Linux two-host
release-gate evidence that cannot be claimed from WSL2, local benchmarks, or
namespace-only TUN probes.

## Preconditions

- Use two separate native Linux hosts or VMs with network reachability.
- Do not run under WSL, WSL2, or a container; the script rejects those
  environments. VMs are allowed.
- Run as root or with effective `CAP_NET_ADMIN` on both hosts.
- Install `cargo`, `iproute2`, `iputils-ping`, `iperf3`, `python3`, and common
  POSIX tools on both hosts.
- Choose unused test-only `/30` addresses and an unused transport/iperf3 port.

## Procedure

Use one shared run ID. Bootstrap identities on both hosts and exchange the two
printed values from each machine:

```bash
sudo scripts/validate_linux_two_host.sh --role listener --run-id native-20260805 --prepare-only
sudo scripts/validate_linux_two_host.sh --role connector --run-id native-20260805 --prepare-only
```

Start the listener on host A:

```bash
sudo scripts/validate_linux_two_host.sh --role listener --run-id native-20260805 \
  --peer-host CONNECTOR_HOST --peer-public-key CONNECTOR_X25519_KEY \
  --peer-signing-public-key CONNECTOR_ED25519_KEY \
  --local-tun-cidr 10.250.0.1/30 --remote-tun-ip 10.250.0.2
```

Once the listener reports its TUN is ready, start the connector on host B:

```bash
sudo scripts/validate_linux_two_host.sh --role connector --run-id native-20260805 \
  --peer-host LISTENER_HOST --peer-public-key LISTENER_X25519_KEY \
  --peer-signing-public-key LISTENER_ED25519_KEY \
  --local-tun-cidr 10.250.0.2/30 --remote-tun-ip 10.250.0.1
```

Both roles build with `cargo build --workspace --release --locked` and set
`SHPH_TUN_NATIVE=1` and explicitly select `--transport tcp` when launching
`shph up`. This validates the stable authenticated TCP data plane through the
Linux `AsyncTunDevice` bridge; it is not standards-QUIC evidence. The
connector captures:

- authenticated `secure-default` handshake completion;
- routed TUN `ping` RTT and jitter summary;
- routed `iperf3` saturation goodput;
- local SHPH CPU (one-core percentage from `/proc/<pid>/stat` interval deltas)
  and RSS samples during saturation; and
- a controlled connector termination, re-establishment timing, and a
  post-reconnect TUN ping.

Reports are written locally as
`docs/evidence/LINUX_TWO_HOST_VALIDATION_<run-id>_<role>.md`; retain both
reports and their raw logs from
`${XDG_STATE_HOME:-$HOME/.local/state}/shph/two-host-validation/` as the
evidence bundle. That state directory contains private keystores and must not
be copied into the repository or published. The listener runtime defaults to
180 seconds; increase
`--listener-runtime-seconds` if the connector host needs longer.

The validator refuses a `--state-dir` inside the repository and verifies its
generated config and keystore are mode `0600`. Publish only the two sanitized
Markdown reports and any reviewed, redacted logs; never publish the state
directory, `keystore.json`, private config files, or unreviewed packet/log
captures.

The generated reports identify the platform and scope. Do not combine them
with WSL2, Windows, containers, namespace probes, or local in-memory benchmark
tables.
