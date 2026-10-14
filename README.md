# SHPH (Shroud-Phantom)

SHPH is an open-source **VPN-first project** focused on private, testable, and auditable secure networking.

It ships a functional TCP-first secure transport plus an explicitly
experimental QUIC-shim, an opt-in standards-compliant QUIC module, and
Shroud-cell lab paths. The legacy shim is not standards-compliant QUIC or
anti-censorship guarantees.

## Current Status (2026-10-12)

Workspace version `0.6.7-dev` (prototype pre-release). SHPH is **functional for controlled lab
environments**, but still **not production-hardened** for hostile-network
claims.

### Release profile

The current release-readiness target is deliberately narrow: authenticated TCP
plus one separately validated OS-native TUN lane. Linux native TUN and Windows
Wintun are independent host-acceptance campaigns. The legacy QUIC shim,
standards QUIC, Shroud morphology, offline-mesh, data-mule, and identity
discovery surfaces remain experimental and are excluded from release-profile
claims. See `docs/SUPPORT_MATRIX.md` and `docs/RELEASE_READINESS.md`.

### Working today

- Native Linux/Windows workspace validation is supported when the complete
  toolchain is installed. The current elevated Windows lifecycle evidence is
  recorded in `docs/evidence/WINDOWS_NATIVE_VALIDATION_2026-08-25.md`; the
  earlier post-loader record remains historical. Workstation-specific tool
  availability is not a project-status claim. See `docs/TESTING.md` for the
  prerequisites and evidence boundary.
  The latest pre-commit candidate validation is recorded in
  `docs/evidence/VALIDATION_2026-09-04_V0.6.7-DEV.md`; it is an engineering
  capture and does not replace clean release evidence.
- Identity + keystore initialization (`init`) and peer/config workflows (`add-peer`, `list-peers`, `show-public-key`, `show-signing-public-key`, `show-config`).
- Guided host/join flow:
  - `shph host --port 443` creates missing local identity/config state and
    prints a `shph://v1:` ticket only after at least one client peer pin is
    configured.
  - `shph join shph://v1:...` creates missing client state, pins the host
    identity from the ticket, and starts the session.
  - There is no unauthenticated first-connection or automatic TOFU enrollment;
    exchange public identity keys and run `add-peer` on the host before sharing
    the ticket.
- `shph id --qr` combines identity inspection with a terminal QR rendering of
  the current shareable ticket.
- Authenticated TCP handshake (`listen` / `connect`) with transcript-bound key derivation.
- Current hardening includes bounded replay state, aggregate TCP handshake
  deadlines, canonical AEAD nonce encoding, outbound TCP frame limits,
  local handshake-state binding, strict identity-record continuity,
  collision-resistant file-adapter paths with bounded polling and
  pre-encryption payload limits, interface-scoped route rollback, low-order
  X25519 rejection, regular-file-only local inputs, failure-path cleanup for
  atomic secret/config/audit writes, strict privileged interface-name
  validation, and anchored identity discovery. See `docs/HARDENING.md` and
  `docs/TESTING.md` for scope and
  validation limits.
- Encrypted framed data transfer (`send-once` / `recv-once`).
- Session-driven `up` mode:
  - one-shot startup payload exchange, or
  - continuous secure loop mode (`connect`/`listen`).
- `shph up --to <host:port>` is a direct-connect shortcut. TCP, TUN-enabled
  operation, and the `medium` discrete profile are the defaults; use
  `--transport`, `--no-tun`, or `--shroud-profile off` to override them.
- Linux native TUN path available behind opt-in flag:
  - set `SHPH_TUN_NATIVE=1` to enable packet read/write via `/dev/net/tun`.
  - Linux `up` uses the Tokio `AsyncFd` bridge with bounded packet queues and
    blocking transport workers; shutdown and transport failures propagate
    without silently falling back.
  - the `up` path keeps the validated device open through control-plane setup
    and reconnect attempts.
  - malformed/oversized IP packets and short kernel writes fail closed; bridge
    packet buffers are zeroized on drop.
- Optional host leak containment controls:
  - `--killswitch` installs a dedicated Linux nftables policy or elevated
    Windows WFP policy before TUN activation.
  - `--killswitch-dry-run` prints the bounded Linux plan (or Windows policy
    summary) without changing host firewall state.
  - peer endpoints must be literal IP addresses with non-zero ports; DNS
    hostname resolution is intentionally rejected in killswitch mode.
  - `--mss-clamp` enables Linux TCP SYN MSS clamping for the 1360-byte native
    TUN MTU. Windows reports unsupported until a safe packet-rewrite backend
    exists.
  - `host` enables SHPH-owned Linux forwarding and masquerade rules when
    native TUN is active; use `host --no-nat` to disable that mutation.
- Windows includes a wired Wintun backend with application-local loading,
  elevation checks, pinned SHA-256 provenance, bounded rings, packet
  validation, shared-session cloning, bounded event waits, and RAII teardown.
  The operator validator additionally requires a valid Authenticode signature.
  An elevated host has now verified the signed runtime, adapter/session
  lifecycle, route/DNS rollback, and a loopback WFP install/teardown smoke. A
  separate controlled Windows-to-Linux direct-TCP campaign also validated native
  IPv4 forwarding, Linux-host egress, bounded throughput, reconnect, session
  hold, and teardown. A separate elevated single-host forced-termination test
  observed seven SHPH-owned WFP filters surviving a hard client kill and zero
  after explicit `shph down`; this is policy-persistence/explicit-cleanup
  evidence, not automatic crash-time cleanup or packet-leak prevention. These
  records do not close Windows-to-Windows, Linux-to-Linux, DNS/IPv6, UDP/QUIC,
  or real-Internet/long-soak gates.
- The historical native Windows validation snapshot records formatting, locked
  checks, strict Clippy, **180 workspace tests**, release builds, Windows-only
   Wintun unit tests, Windows ACL coverage, and both benchmark profiles. The
   `v0.6.4-dev.4` release evidence records 304 workspace tests; these totals
   belong to different snapshots and must not be conflated. The current
   The September 4 `v0.6.7-dev` pre-commit verification reached 379 workspace
   tests with 0 failures, plus 38 passing tests in the standalone edge
   workspace. These are separate engineering snapshots, not a new release
   claim. The lifecycle record reports
   clean adapter, route, DNS, WFP, process, and temporary-directory teardown. See
  `docs/evidence/WINDOWS_NATIVE_VALIDATION_2026-08-25.md`.
- Lab-only controls:
  - set `SHPH_KEYSTORE_PASSWORD` before `init` to encrypt the keystore at rest.
  - set `SHPH_SHROUD_PROFILE=off|low|medium|high|extreme-lab` with
    `--transport quic` to choose explicit lab intensity. `medium` is the
    `up` default;
    `low`, `medium`, and `high` map to `low-latency`, `balanced`, and `bulk`.
    `extreme-lab` uses a larger randomized experimental cell. Named profiles
    such as `randomized-lab` remain accepted.
- Transport options on CLI/session paths:
  - `tcp` (stable), `quic` (experimental UDP shim), `quic-standard`
    (opt-in RFC QUIC for `listen`/`connect`/one-shot commands),
    `offline-mesh` (experimental), `data-mule` (experimental).
  - TCP also accepts an explicit optional SOCKS5 underlay add-on through
    `--underlay socks5://host:port` or `[session].underlay`. This is intended
    for a local Xray-compatible SOCKS5 listener when the direct route is
    unavailable; SHPH still performs its normal end-to-end handshake through
    the proxy. The adapter is TCP-only, supports unauthenticated local
    SOCKS5, and never exposes the proxy as a public SHPH endpoint.
  - `quic-standard` uses Quinn/rustls TLS 1.3 and trusted out-of-band
    certificate distribution. Server commands accept `--quic-cert` and
    `--quic-key`; `host` persists the pair and `join` accepts the public
    certificate path. On Linux, `up --transport quic-standard` uses the async
    standards-QUIC/native-TUN bridge, requires `SHPH_TUN_NATIVE=1`, and reuses
    stable server material across reconnects. Windows one-shot QUIC is
    supported; Windows native-TUN forwarding remains host-gated.
- Seven standalone fuzzing harnesses cover Shroud-cell framing, TOML
  configuration, audit-record JSON, replay-window state transitions, Shroud2
  datagrams, and Phantom One envelopes under `fuzz/`.
- Explicit benchmark profiles are available:
  - `secure-default` keeps authenticated Ed25519 + X25519 + mandatory ML-KEM-768.
  - `classical-lab` is a visible benchmark-only X25519 mode and requires both
    peers to opt in; it is rejected by secure-default peers.
- Optional passive JA4-compatible observability is available through the
  `shph-transport` standards-QUIC API. It is disabled by default, records
  bounded public rustls ClientHello metadata, and does not spoof fingerprints
  or claim stealth. See `docs/JA4_OBSERVABILITY.md`.
- SHPH-native SNAP v1 profile planning is opt-in. Use `shph snap validate`
  and `shph snap plan` with strict JSON or TOML profiles. Persistent sessions
  can select `session.snap_profile`; adapter execution keeps SHPH peer pins and
  authentication. External bridges and relays need operator-owned services,
  and Python SNAP session interoperability is not included. SNAP remains
  outside the release profile.
- Adaptive Shroud 3 is experimental and opt-in for Linux standards-QUIC
  native-TUN sessions through `host`, `join`, `up`, or
  `session.shroud3_adaptive`. Both peers must configure it; Shroud 3 has its
  own bounded workload, size, padding, and pacing engine in the distinct `S3`
  v1 envelope, without negotiation or format fallback. Synthetic in-memory
  comparisons and authenticated loopback bridge tests do not establish
  carrier-visible behavior, classifier improvement, native two-host
  interoperability, or full-session costs. No traffic-resistance claim is
  made.
- Native multi-hop onion routing is an experimental transport API with a
  separate `shph-onion-relay` process. It carries SHPH sessions through two
  or three explicitly pinned TLS relays with fixed target allowlists. It has
  local process-level tests, but no independent protocol review, external
  service campaign, or native-TUN containment evidence. Neither Shroud 3 nor
  onion routing is a release-profile, anonymity, or censorship-resistance
  feature. See `docs/SHROUD_3_IMPLEMENTATION.md` and
  `docs/ONION_CIRCUIT_DESIGN.md`.
- `--json` emits structured error objects as well as the existing JSON reports.
  Error objects contain `ok: false`, a stable sysexits-style `code`, a
  human-readable `error`, and an optional remediation `hint`; malformed
  command-line syntax still uses Clap's native usage error.
- Native Linux benchmark runner:
  `cargo run --manifest-path benchmarks/Cargo.toml --release -- --profile secure-default --suite all --iterations 10000 --frames 100000`
  It reports p50/p95/p99/p99.9 latency, in-memory goodput/wire rate, CPU,
  RSS, peak RSS, allocation pressure, Shroud profiles, and QUIC-shim loopback
  measurements; it does not replace live TUN/two-host testing.
- Operator benchmark wrapper: `scripts/benchmark_operator.sh` measures real
  lifecycle, control-plane, reconnect, and native-TUN prerequisites without
  fabricating unsupported results. `scripts/benchmark_native_tun.sh` measures
  only isolated open/hold/close lifecycle latency.
- Reproducible operator campaigns are provided by
  `scripts/operator_campaigns.py`. They cover bounded reconnect, fresh-process
  soak, IPv6 loopback, DNS dry-run, literal-IP PMTU probes, and explicitly
  confirmed crash termination. See `docs/OPERATOR_CAMPAIGNS.md`; campaign
  output is written beneath the ignored `benchmark-runs/campaigns/` directory.

### Not done yet

- Browser-grade TLS/QUIC fingerprint parity, conformant production QUIC, and
  hostile-network adversarial posture remain roadmap work.
- Offline mesh, Data-Mule physical courier, HSM/PKCS#11, YubiKey/PIV, TPM
  binding, Shamir quorum, and ratchet audit have configuration or CLI
  primitives, but are not production defaults or claims of live hardware/
  transport integrations. Hybrid PQC is shipped in v0.4.0.
- Full production anti-observation claims are explicitly out of scope at this stage.
- Broader native-TUN coverage remains open: Ctrl+C and forced-termination
  behavior beyond the single-host policy test, automatic crash-time WFP
  leak/packet-path testing, Windows-to-Windows and Linux-to-Linux campaigns,
  UDP/QUIC, PMTU/DNS/IPv6 coverage, and standards-QUIC host validation.

The next milestone is authenticated TCP/native-TUN lifecycle reliability:
secret-safe diagnostics, repeatable acceptance on the selected host lane,
failure recovery, and clean teardown. A separate experimental development scope
covers Phantom One/Shroud 2 improvements, carrier and probing resistance
experiments, detectability measurement, and optional onion routing; see
[`docs/PHANTOM_SHROUD_SCOPE.md`](docs/PHANTOM_SHROUD_SCOPE.md). Existing
experimental paths retain regression coverage. These workstreams do not close
the ordered release acceptance checklist in `docs/RELEASE_READINESS.md`.

SHPH inherits core concepts from the Shroud lineage (adaptive framing and profile-driven morphology concepts), reworked for a VPN-first architecture.

## Workspace

```text
shph/
├── Cargo.toml
├── benchmarks/        # standalone Linux-first benchmark harness
├── fuzz/              # standalone cargo-fuzz workspace and targets
├── shph-core/         # crypto, handshake, shared types
├── shph-config/       # TOML config schema + IO
├── shph-tun/          # TUN abstraction
├── shph-transport/    # transport mode/parsing support
├── shph-obfuscation/  # profile surface
├── shph-identity/     # experimental signed identity/discovery boundary
├── shph-cli/          # shph binary + integration tests
├── shph-tui/          # optional terminal UI
├── scripts/            # evidence, demo, benchmark, campaign, and mirror helpers
└── docs/              # operator, roadmap, audit, and evidence docs
```

## Reproducibility

Run validation commands from the repository root. Generated benchmark and
evidence artifacts are written beneath `benchmark-runs/` and `docs/evidence/`
as described in the testing documentation.

## Quick Start

```bash
# from workspace root
cargo build

# guided flow: initialize both sides and pre-pin the client before exposing host
# (see the identity/key exchange commands below)

# keep a changing relay ticket in a bounded owner-only file
cargo run -p shph-cli -- host --port 443 \
  --advertise relay.example:443 \
  --ticket-file /run/shph/join.ticket
cargo run -p shph-cli -- join --ticket-file /run/shph/join.ticket --check

# inspect identity and render the current ticket as a terminal QR
cargo run -p shph-cli -- id --qr

# initialize identities in two folders
cargo run -p shph-cli -- --config /tmp/shph-a/config.toml init --new
cargo run -p shph-cli -- --config /tmp/shph-b/config.toml init --new

# display each identity's public key, then pin peers before sessions
server_key="$(cargo run -q -p shph-cli -- --config /tmp/shph-a/config.toml show-public-key)"
client_key="$(cargo run -q -p shph-cli -- --config /tmp/shph-b/config.toml show-public-key)"
server_sign_key="$(cargo run -q -p shph-cli -- --config /tmp/shph-a/config.toml show-signing-public-key)"
client_sign_key="$(cargo run -q -p shph-cli -- --config /tmp/shph-b/config.toml show-signing-public-key)"
cargo run -q -p shph-cli -- --config /tmp/shph-a/config.toml add-peer client 127.0.0.1 7220 "$client_key" --sign-pubkey "$client_sign_key"
cargo run -q -p shph-cli -- --config /tmp/shph-b/config.toml add-peer server 127.0.0.1 7220 "$server_key" --sign-pubkey "$server_sign_key"

# now the host may be exposed; it refuses to start without the client pin
cargo run -p shph-cli -- --config /tmp/shph-a/config.toml host \
  --port 443 --advertise 198.51.100.10
cargo run -p shph-cli -- --config /tmp/shph-b/config.toml join 'shph://v1:...'

# one-shot encrypted payload demo (TCP default)
cargo run -p shph-cli -- --config /tmp/shph-a/config.toml recv-once --bind 127.0.0.1:7220
cargo run -p shph-cli -- --config /tmp/shph-b/config.toml send-once --peer 127.0.0.1:7220 --text "hello"

# one-shot encrypted payload demo over QUIC shim (experimental)
cargo run -p shph-cli -- --config /tmp/shph-a/config.toml recv-once --bind 127.0.0.1:7220 --transport quic
cargo run -p shph-cli -- --config /tmp/shph-b/config.toml send-once --peer 127.0.0.1:7220 --text "hello" --transport quic

# standards QUIC one-shot demo; copy server.der to the client out of band
cargo run -p shph-cli -- --config /tmp/shph-a/config.toml recv-once \
  --bind 127.0.0.1:7220 --transport quic-standard \
  --quic-cert /tmp/server.der
cargo run -p shph-cli -- --config /tmp/shph-b/config.toml send-once \
  --peer 127.0.0.1:7220 --text "hello" --transport quic-standard \
  --quic-cert /tmp/server.der
```

## Session `up` Mode

`up` can run from `[session]` settings in config:

```toml
[session]
role = "listen"         # or "connect"
bind = "127.0.0.1:7231" # listen only
peer = "127.0.0.1:7231" # connect only
transport_peer = "127.0.0.1:7231" # optional socket target; peer remains the policy selector
timeout_secs = 5
handshake_profile = "secure-default" # or "classical-lab" for paired lab runs
underlay = "socks5://127.0.0.1:10808" # optional local TCP underlay add-on

[session.reconnect]
enabled = true
max_attempts = 5
initial_delay_ms = 250
max_delay_ms = 4000

[control_plane]
apply_interface_address = true
interface_cidr = "10.250.0.2/30"
apply_routes = true
route_cidrs = ["10.250.0.1/32"]
underlay_bypass_cidrs = ["203.0.113.10/32"] # physical path for local SOCKS underlay
apply_dns = true
dns_servers = ["1.1.1.1"]
dry_run = true

# startup_payload = "optional one-shot text"
```

Behavior:

- If `startup_payload` is present:
  - `listen` expects one encrypted payload then exits.
  - `connect` sends one encrypted payload then exits.
- If `startup_payload` is omitted:
  - default: `listen` receives/decrypts frames, `connect` sends stdin lines as frames.
  - with `SHPH_TUN_NATIVE=1` on Linux: bidirectional packet loop (`TUN <-> transport`) is enabled.
  - Linux native TUN now validates interface names, `/dev/net/tun` device mode, and permission requirements before opening.
- If `[session.reconnect]` is enabled:
  - transient transport failures are retried with exponential backoff.
- If `transport_peer` is set:
  - `peer` remains the pinned identity/policy selector;
  - only the TCP/QUIC socket target is overridden, which supports a trusted
    relay terminating on the host's internal listener.
- If `[control_plane]` is enabled:
  - interface-address, route, and DNS input is validated.
  - with `dry_run=true` (recommended default): planned mutations are logged only.
- with `dry_run=false`: SHPH attempts live interface-address, route/DNS apply
  and rollback on shutdown/error.
- SHPH refuses a default route with a SOCKS5 underlay until an explicit
  `underlay_bypass_cidrs` route is configured, preventing a routing loop.
  Bypass routes are installed on the active physical gateway, persisted, and
  rolled back with the rest of the control plane.
- `apply`, `reconcile`, `undo`, and `down` provide persistent control-plane
  lifecycle management outside a session process.
- `up --killswitch` and `up --mss-clamp` require native TUN mode for live
  mutation. `--killswitch-dry-run` is preview-only: it prints the bounded
  policy without requiring native TUN, elevation, or firewall mutation.
- `down` attempts to remove SHPH-owned firewall tables/filters as well as
  recorded control-plane state; cleanup failures are reported rather than
  silently ignored.
- `up` refuses to overwrite a persisted control-plane state file left by an
  interrupted session. Run `shph reconcile` or `shph undo` first.
- `join --check` validates a ticket and performs one authenticated handshake
  without writing configuration or changing TUN, route, or DNS state.
- `doctor --deep` probes the configured underlay and performs a no-mutation
  handshake check for a persistent connect session.

## Optional reachability add-on

When a direct TCP route to the SHPH host is unavailable, run an external
Xray-compatible client or another local SOCKS5 implementation and point SHPH
at its local listener:

```bash
shph join --underlay socks5://127.0.0.1:10808 'shph://v1:...'
shph up --to 198.51.100.10:443 --underlay socks5://127.0.0.1:10808 --no-tun
shph connect --peer 198.51.100.10:443 --underlay socks5://127.0.0.1:10808
shph send-once --peer 198.51.100.10:443 --text "hello" \
  --underlay socks5://127.0.0.1:10808
```

This add-on is deliberately explicit and optional. The proxy carries the
existing SHPH TCP byte stream; it does not terminate SHPH authentication,
decrypt SHPH payloads, or replace the pinned peer identity. The generic
`socks5://` mode does not support credentials. The separate `tor://` mode
requires a literal loopback SOCKS endpoint and offers fresh per-connection
SOCKS credentials for proxy-side stream isolation; SHPH does not manage Tor
circuits or isolation policy. Keep the local SOCKS listener on loopback.
QUIC-over-SOCKS, proxy auto-discovery, and a bundled Xray binary remain out of
scope.

See [`docs/REACHABILITY_ADDON.md`](docs/REACHABILITY_ADDON.md) for the
architecture, operational boundary, and test procedure.

For local Xray diagnostics, use `scripts/check_xray.ps1` on Windows or
`scripts/check_xray.sh` on Linux. These checks validate the configuration and
loopback SOCKS5 listener without sending traffic to an arbitrary destination.

## Main Commands

```text
shph init --new
shph host [--port 443] [--advertise <host[:port]>] [--transport tcp|quic|quic-standard]
  [--shroud-profile medium] [--phantom-one] [--phantom-one-profile medium]
  [--no-tun] [--no-nat]
  [--ticket-file <path>] [--quic-cert <server.der>] [--quic-key <server.key>]
  [--underlay socks5://host:port]
shph join <shph://v1:...> [--ticket-file <path>] [--no-tun]
  [--underlay socks5://host:port] [--quic-cert <server.der>]
  [--transport-peer <host:port>] [--check]
shph id [--qr] [--ticket-file <path>]
shph up [--to <host:port>] [--transport tcp|quic|quic-standard|offline-mesh|data-mule]
  [--shroud-profile off|low|medium|high|extreme-lab] [--phantom-one]
  [--phantom-one-profile medium] [--no-tun]
  [--underlay socks5://host:port]
  [--quic-cert <server.der>] [--quic-key <server.key>]
  [--killswitch] [--killswitch-dry-run] [--mss-clamp]
shph down
shph apply
shph reconcile
shph undo
shph status
shph doctor [--strict] [--deep] [--json]
shph show-fingerprint
shph show-public-key
shph show-signing-public-key
shph list-peers
shph add-peer <alias> <host> <port> <pubkey> --sign-pubkey <ed25519-pubkey>
shph show-config
shph handshake-sim --peer-pubkey-b64 <key>
shph listen --bind <addr> [--transport tcp|quic|quic-standard|offline-mesh|data-mule]
  [--quic-cert <server.der>] [--quic-key <server.key>]
shph connect --peer <addr> [--transport tcp|quic|quic-standard|offline-mesh|data-mule]
  [--underlay socks5://host:port] [--quic-cert <server.der>]
shph send-once --peer <addr> --text <msg> [--transport tcp|quic|quic-standard|offline-mesh|data-mule]
  [--underlay socks5://host:port] [--quic-cert <server.der>]
shph recv-once --bind <addr> [--transport tcp|quic|quic-standard|offline-mesh|data-mule]
  [--quic-cert <server.der>] [--quic-key <server.key>]
cargo run -p shph-tui -- --config <path>
```

When `up`, `host`, or `join` owns an interactive terminal, the active data
plane uses a single stderr status bar with handshake profile, interface,
handshake time, and live TX/RX counters. Non-interactive output keeps the
line-oriented logs suitable for automation.

For automation, use `shph status --json`, `shph doctor --strict --json`, and
`shph list-peers --json`. Human-facing failures include a next-step hint; use
`shph doctor` when a configuration or identity error is unclear. The CLI also
returns stable sysexits-style values: `2` for invalid arguments, `66` for a
missing file, `69` for an unavailable/unsupported operation, `75` for a
transient transport/resource failure, `77` for permission/authentication
failures, and `78` for configuration or keystore failures.

## Development

```bash
cargo fmt --all
cargo check --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Additional docs:

- `FIVE_MINUTE_QUICKSTART.md` (local authenticated encrypted exchange)
- `docs/TESTING.md`
- `docs/OPERATOR_CAMPAIGNS.md` (bounded operator/failure campaign procedures)
- `docs/SUPPORT_MATRIX.md` (authoritative product boundary and support levels)
- `docs/RELEASE_READINESS.md` (binding release gate and evidence rules)
- `docs/WHY_CHOOSE_SHPH.md` (honest fit and comparison guide)
- `docs/QUALITY_EVIDENCE.md` (release tests, benchmark results, and limits)
- `docs/SECURITY_EVIDENCE.md` (threat-to-control map and redaction checklist)
- `docs/CONTROL_PLANE.md`
- `docs/TUI.md`
- `fuzz/README.md`
- `docs/DIRECTORY_GUIDE.md`
- `docs/REPRODUCIBILITY.md`
- `docs/SYNC.md` (optional synchronization for multiple checkouts)
- `docs/RISK_MATRIX.md` (current limits + explicit exclusions)
- `docs/SUPPORT_AND_MAINTENANCE.md` (support model + maintenance plan)
- `docs/evidence/GATE_EVIDENCE.md` (regenerable acceptance-gate evidence log)
- `docs/LEGAL_COMPLIANCE.md` (OSS artifact legal/compliance checklist)
- `docs/API_STABILITY.md` (public-API tiers + validation-window freeze rules)
- `docs/SECURITY_REPORTING.md` (bug-bounty report template + triage SLA)
- `docs/SUPPLY_CHAIN_SCAN.md` (cargo-audit scanner + advisory triage)
- `docs/HARDENING.md` (security-hardening summary + threat impact)
- `docs/BENCHMARKING.md` (Linux-first methodology, profiles, and benchmark plan)
- `docs/GITHUB_BENCHMARKING.md` (hosted CI campaigns, artifacts, and evidence boundaries)
- `docs/BENCHMARK_RESULTS_2026-08-25.md` (focused defensive rejection benchmark and scope)
- `docs/BENCHMARK_RESULTS_2026-08-23.md` (current tuned-profile evidence and limits)
- `docs/BENCHMARK_RESULTS_2026-08-22.md` (previous local candidate evidence and limits)
- `docs/BENCHMARK_RESULTS_2026-08-17.md` (dated Shroud2/pre-authentication evidence baseline)
- `docs/BENCHMARK_EXTENDED_RESULTS_2026-08-18.md` (extended local benchmark
  campaign and explicit host-capability skips)
- `docs/BENCHMARK_RESULTS_2026-08-14.md` (historical Windows-local `0.6.1-dev`
  benchmark baseline)
- `docs/SHROUD2_BENCHMARK_RESULTS_2026-08-04.md` (latest Shroud 2.0 morphology report)
- `docs/MORPHOLOGY_PERFORMANCE.md` (adaptive morphology and bounded performance tuning)
- `docs/BENCHMARK_RESULTS_2026-07-28.md` (historical WSL2 benchmark scores and evidence limits)
- `docs/LAB_PROTOTYPES.md` (operational guide for QUIC-shim, offline-mesh, and data-mule labs)
- `docs/PHANTOM_ONE_OPERATOR.md` (opt-in Phantom One TCP and owned-edge prototype notes)
- `docs/PHANTOM_ONE_DESIGN.md` (Phantom One design boundary and explicit non-claims)
- `docs/PHANTOM_ONE_TESTING.md` (Phantom One test and evidence taxonomy)
- `docs/PHANTOM_ONE_RELIABILITY.md` (Phantom One lifecycle, cleanup, and bounded-failure goals)
- `docs/QUIC_STANDARDS.md` (RFC QUIC architecture, usage, and verification)
- `docs/evidence/CARGO_AUDIT.txt` (regenerable advisory-scan output)
- `CHANGELOG.md` (phase-anchored changelog)
- `SECURITY.md` (vulnerability reporting, threat model, non-claims matrix)
- `CONTRIBUTING.md` (build/test, release checklist, governance)
- `.github/workflows/ci.yml` (Linux + Windows CI template)
- `.github/workflows/release.yml` (tagged package, attestation, and prerelease workflow)
- `scripts/verify_release.py` (sanitized package manifest/checksum verifier)
- `docs/evidence/WINDOWS_NATIVE_VALIDATION_2026-08-25.md` (current elevated Windows lifecycle evidence)
- `docs/evidence/WINDOWS_WFP_CRASH_VALIDATION_2026-09-01.md` (elevated single-host forced-termination and explicit WFP cleanup evidence)
- `docs/evidence/VALIDATION_2026-09-04_V0.6.7-DEV.md` (September 4 pre-commit validation record)
- `docs/evidence/VALIDATION_2026-08-30_V0.6.6-DEV.2.md` (previous tag validation record)
- `docs/evidence/CROSS_PLATFORM_NATIVE_TUN_VALIDATION_2026-08-25.md` (Windows-to-Linux direct-TCP IPv4 forwarding evidence)
- `docs/evidence/OPTIONAL_XRAY_UNDERLAY_VALIDATION_2026-08-25.md` (bounded optional SOCKS5/Xray underlay evidence)

## Security Note

Peer identity and handshake-signing-key pinning are mandatory for all CLI
sessions; register both expected keys with `add-peer` before using `listen`,
`connect`, `send-once`, `recv-once`, or `up`. Do not market current SHPH as
censorship-resistant production transport.
Use it for controlled testing, staged engineering hardening, and transparent OSS validation only.
See `SECURITY.md` for the full threat model and explicit non-claims matrix.

## License

Dual-licensed under MIT OR Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`).
