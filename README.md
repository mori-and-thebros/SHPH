# SHPH (Shroud-Phantom)

SHPH is an open-source **VPN-first project** focused on private, testable, and auditable secure networking.

It ships a functional TCP-first secure transport plus an explicitly
experimental QUIC-shim, an opt-in standards-compliant QUIC module, and
Shroud-cell lab paths. The legacy shim is not standards-compliant QUIC or
anti-censorship guarantees.

## Current Status (2026-08-20)

Workspace version `0.6.4-dev.2` (pre-release). SHPH is **functional for controlled lab
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
  toolchain is installed. Dedicated native Windows validation evidence is
  recorded in `docs/evidence/WINDOWS_NATIVE_VALIDATION_2026-08-09_POST_LOADER.md`;
  workstation-specific tool availability is not a project-status claim.
  See `docs/TESTING.md` for the prerequisites and evidence boundary.
- Identity + keystore initialization (`init`) and peer/config workflows (`add-peer`, `list-peers`, `show-public-key`, `show-signing-public-key`, `show-config`).
- Guided host/join flow:
  - `shph host --port 443` creates missing local identity/config state,
    prints a `shph://v1:` ticket, and bootstraps the first authenticated peer.
  - `shph join shph://v1:...` creates missing client state, pins the host
    identity from the ticket, and starts the session.
  - The first host connection uses explicit TOFU enrollment; subsequent host
    reconnects require the persisted peer pin.
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
  `SHPH_TUN_NATIVE=1` remains host-gated until a real elevated Windows host
  verifies the runtime, adapter lifecycle, and packet path.
- Native Windows validation passes formatting, locked checks, strict Clippy,
  **180 workspace tests**, release builds, Windows-only Wintun unit tests,
  Windows ACL coverage, and both benchmark profiles. The post-loader smoke
  reached a real Wintun adapter/session and left no residue; a clean elevated
  rerun after the route-rollback fix remains the final confirmation. See
  `docs/evidence/WINDOWS_NATIVE_VALIDATION_2026-08-09_POST_LOADER.md`.
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
  - `quic-standard` requires `--quic-cert` and trusted out-of-band
    certificate distribution. On Linux, `up --transport quic-standard` uses
    the async standards-QUIC/native-TUN bridge and requires
    `SHPH_TUN_NATIVE=1`; reconnect is intentionally rejected until persistent
    server certificate/key support is implemented. Other platforms remain
    host-gated.
- Standalone fuzzing harnesses for Shroud-cell framing, TOML configuration,
  audit-record JSON, and replay-window state transitions live under `fuzz/`.
- Explicit benchmark profiles are available:
  - `secure-default` keeps authenticated Ed25519 + X25519 + mandatory ML-KEM-768.
  - `classical-lab` is a visible benchmark-only X25519 mode and requires both
    peers to opt in; it is rejected by secure-default peers.
- Optional passive JA4-compatible observability is available through the
  `shph-transport` standards-QUIC API. It is disabled by default, records
  bounded public rustls ClientHello metadata, and does not spoof fingerprints
  or claim stealth. See `docs/JA4_OBSERVABILITY.md`.
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

### Not done yet

- Browser-grade TLS/QUIC fingerprint parity, conformant production QUIC, and
  hostile-network adversarial posture remain roadmap work.
- Offline mesh, Data-Mule physical courier, HSM/PKCS#11, YubiKey/PIV, TPM
  binding, Shamir quorum, and ratchet audit have configuration or CLI
  primitives, but are not production defaults or claims of live hardware/
  transport integrations. Hybrid PQC is shipped in v0.4.0.
- Full production anti-observation claims are explicitly out of scope at this stage.
- Elevated live Wintun adapter/packet I/O, route/DNS rollback, reconnect,
  Ctrl+C teardown, two-node Windows forwarding, and native Linux two-host
  evidence remain release gates.

The current development sequence is Shroud lab completion, hardening and
optimization, release-readiness, then the remaining native Windows TUN gates.

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
├── scripts/            # evidence, demo, benchmark, and mirror helpers
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

# fastest guided flow (the host prints the one-line ticket)
cargo run -p shph-cli -- host --port 443 --advertise 198.51.100.10
cargo run -p shph-cli -- join 'shph://v1:...'

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
decrypt SHPH payloads, or replace the pinned peer identity. SHPH currently
supports a local unauthenticated SOCKS5 listener only, so keep that listener
bound to loopback or otherwise protected. SOCKS5 credentials, QUIC underlay,
proxy auto-discovery, and a bundled Xray binary are out of scope.

See [`docs/REACHABILITY_ADDON.md`](docs/REACHABILITY_ADDON.md) for the
architecture, operational boundary, and test procedure.

For local Xray diagnostics, use `scripts/check_xray.ps1` on Windows or
`scripts/check_xray.sh` on Linux. These checks validate the configuration and
loopback SOCKS5 listener without sending traffic to an arbitrary destination.

## Main Commands

```text
shph init --new
shph host [--port 443] [--advertise <host[:port]>] [--transport tcp|quic]
  [--shroud-profile medium] [--no-tun] [--no-nat]
  [--ticket-file <path>]
  [--underlay socks5://host:port]
shph join <shph://v1:...> [--ticket-file <path>] [--no-tun]
  [--underlay socks5://host:port] [--transport-peer <host:port>] [--check]
shph id [--qr] [--ticket-file <path>]
shph up [--to <host:port>] [--transport tcp|quic|quic-standard|offline-mesh|data-mule]
  [--shroud-profile off|low|medium|high|extreme-lab] [--no-tun]
  [--underlay socks5://host:port]
  [--quic-cert <server.der>] [--killswitch] [--killswitch-dry-run] [--mss-clamp]
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
shph listen --bind <addr> [--transport tcp|quic|quic-standard|offline-mesh|data-mule] [--quic-cert <server.der>]
shph connect --peer <addr> [--transport tcp|quic|quic-standard|offline-mesh|data-mule]
  [--underlay socks5://host:port] [--quic-cert <server.der>]
shph send-once --peer <addr> --text <msg> [--transport tcp|quic|quic-standard|offline-mesh|data-mule]
  [--underlay socks5://host:port] [--quic-cert <server.der>]
shph recv-once --bind <addr> [--transport tcp|quic|quic-standard|offline-mesh|data-mule] [--quic-cert <server.der>]
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
- `docs/SUPPORT_MATRIX.md` (authoritative product boundary and support levels)
- `docs/RELEASE_READINESS.md` (binding release gate and evidence rules)
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
- `docs/BENCHMARKING.md` (Linux-first benchmark methodology and profile plan)
- `docs/BENCHMARK_EXTENDED_RESULTS_2026-08-18.md` (extended local benchmark
  campaign and explicit host-capability skips)
- `docs/BENCHMARK_RESULTS_2026-08-14.md` (historical Windows-local `0.6.1-dev`
  benchmark baseline)
- `docs/SHROUD2_BENCHMARK_RESULTS_2026-08-04.md` (latest Shroud 2.0 morphology report)
- `docs/BENCHMARK_RESULTS_2026-07-28.md` (historical WSL2 benchmark scores and evidence limits)
- `docs/LAB_PROTOTYPES.md` (operational guide for QUIC-shim, offline-mesh, and data-mule labs)
- `docs/QUIC_STANDARDS.md` (RFC QUIC architecture, usage, and verification)
- `docs/evidence/CARGO_AUDIT.txt` (regenerable advisory-scan output)
- `CHANGELOG.md` (phase-anchored changelog)
- `SECURITY.md` (vulnerability reporting, threat model, non-claims matrix)
- `CONTRIBUTING.md` (build/test, release checklist, governance)
- `.github/workflows/ci.yml` (Linux + Windows CI template)
- `docs/evidence/WINDOWS_NATIVE_VALIDATION_2026-08-09_POST_LOADER.md` (latest native Windows evidence)

## Security Note

Peer identity and handshake-signing-key pinning are mandatory for all CLI
sessions; register both expected keys with `add-peer` before using `listen`,
`connect`, `send-once`, `recv-once`, or `up`. Do not market current SHPH as
censorship-resistant production transport.
Use it for controlled testing, staged engineering hardening, and transparent OSS validation only.
See `SECURITY.md` for the full threat model and explicit non-claims matrix.

## License

Dual-licensed under MIT OR Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`).
