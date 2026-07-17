# SHPH (Shroud-Phantom)

SHPH is an open-source **VPN-first project** focused on private, testable, and auditable secure networking.

It ships a functional TCP-first secure transport plus explicitly experimental
QUIC-shim and Shroud-cell lab paths. These are not standards-compliant QUIC or
anti-censorship guarantees.

## Current Status (2026-07-15)

SHPH is **functional for controlled lab environments**, but still **not production-hardened** for hostile-network claims.

### Working today

- Rust workspace builds cleanly on Linux and Windows toolchains (`cargo check --workspace`).
- Identity + keystore initialization (`init`) and peer/config workflows (`add-peer`, `list-peers`, `show-public-key`, `show-signing-public-key`, `show-config`).
- Authenticated TCP handshake (`listen` / `connect`) with transcript-bound key derivation.
- Encrypted framed data transfer (`send-once` / `recv-once`).
- Session-driven `up` mode:
  - one-shot startup payload exchange, or
  - continuous secure loop mode (`connect`/`listen`).
- Linux native TUN path available behind opt-in flag:
  - set `SHPH_TUN_NATIVE=1` to enable packet read/write via `/dev/net/tun`.
- Windows native TUN is not yet provisioned; setting `SHPH_TUN_NATIVE=1`
  fails explicitly until a signed Wintun runtime is integrated, rather than
  silently using the developer stub.
- Lab-only controls:
  - set `SHPH_KEYSTORE_PASSWORD` before `init` to encrypt the keystore at rest.
  - set `SHPH_SHROUD_PROFILE=balanced|low-latency|bulk` with `--transport quic`
    to wrap UDP-shim frames in fixed-size Shroud cells. Profiles include
    `balanced`, `low-latency`, `bulk`, and the lab-only `randomized-lab`
    profile, whose authenticated inner padding is randomized.
- Transport options on CLI/session paths:
  - `tcp` (stable), `quic` (experimental), `offline-mesh` (experimental), `data-mule` (experimental).
- Standalone fuzzing harnesses for Shroud-cell framing, TOML configuration,
  audit-record JSON, and replay-window state transitions live under `fuzz/`.

### Not done yet

- Browser-grade TLS/QUIC fingerprint parity, conformant production QUIC, and
  hostile-network adversarial posture remain roadmap work.
- Offline mesh, Data-Mule physical courier, HSM/PKCS#11, YubiKey/PIV, TPM
  binding, Shamir quorum, and ratchet audit have configuration or CLI
  primitives, but are not production defaults or claims of live hardware/
  transport integrations. Hybrid PQC is shipped in v0.4.0.
- Full production anti-observation claims are explicitly out of scope at this stage.

For the delivery/funding roadmap, see `ROADMAP_OSS_AND_DELIVERY.md`.

SHPH inherits core concepts from the Shroud lineage (adaptive framing and profile-driven morphology concepts), reworked for a VPN-first architecture.

## Workspace

```text
shph/
├── Cargo.toml
├── shph-core/         # crypto, handshake, shared types
├── shph-config/       # TOML config schema + IO
├── shph-tun/          # TUN abstraction
├── shph-transport/    # transport mode/parsing support
├── shph-obfuscation/  # profile surface (early)
├── shph-cli/          # shph binary + integration tests
├── shph-tui/          # optional terminal UI
├── docs/              # testing/control-plane/TUI/path docs
└── src/               # shared root helpers
```

## Current Verified Artifact Paths

- Primary working copy: `/home/mori/SHPH_working_copy`
- Clean funded mirror: `D:\FUNDING NEEDED\snap-shroud-rs`

## Quick Start

```bash
# from workspace root
cargo build

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
```

## Session `up` Mode

`up` can run from `[session]` settings in config:

```toml
[session]
role = "listen"         # or "connect"
bind = "127.0.0.1:7231" # listen only
peer = "127.0.0.1:7231" # connect only
timeout_secs = 5

[session.reconnect]
enabled = true
max_attempts = 5
initial_delay_ms = 250
max_delay_ms = 4000

[control_plane]
apply_routes = true
route_cidrs = ["10.10.0.0/16"]
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
- If `[control_plane]` is enabled:
  - route/DNS input is validated.
  - with `dry_run=true` (recommended default): planned mutations are logged only.
- with `dry_run=false`: SHPH attempts live route/DNS apply and rollback on shutdown/error.
- `apply`, `reconcile`, `undo`, and `down` provide persistent control-plane
  lifecycle management outside a session process.

## Main Commands

```text
shph init --new
shph up --config <path> [--transport tcp|quic|offline-mesh|data-mule]
shph down
shph apply
shph reconcile
shph undo
shph status
shph show-fingerprint
shph show-public-key
shph show-signing-public-key
shph list-peers
shph add-peer <alias> <host> <port> <pubkey> --sign-pubkey <ed25519-pubkey>
shph show-config
shph handshake-sim --peer-pubkey-b64 <key>
shph listen --bind <addr> [--transport tcp|quic|offline-mesh|data-mule]
shph connect --peer <addr> [--transport tcp|quic|offline-mesh|data-mule]
shph send-once --peer <addr> --text <msg> [--transport tcp|quic|offline-mesh|data-mule]
shph recv-once --bind <addr> [--transport tcp|quic|offline-mesh|data-mule]
cargo run -p shph-tui
```

## Development

```bash
cargo fmt --all
cargo check --workspace
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
```

Additional docs:

- `docs/TESTING.md`
- `docs/CONTROL_PLANE.md`
- `docs/TUI.md`
- `fuzz/README.md`
- `docs/DIRECTORY_GUIDE.md`
- `docs/REPRODUCIBILITY.md`
- `docs/SYNC.md` (mirroring working copy <-> Windows tree)
- `docs/FUNDERS.md` (what SHPH is/is-not, for grant reviewers)
- `docs/CRYPTO_FUNDING_BOOTSTRAP.md` (crypto-only bootstrap campaign draft)
- `docs/RISK_MATRIX.md` (current limits + explicit exclusions)
- `docs/MILESTONE_SCORECARD.md` (measurable phase scorecard + burn-down)
- `docs/SUPPORT_AND_MAINTENANCE.md` (support model + maintenance plan)
- `docs/evidence/GATE_EVIDENCE.md` (regenerable acceptance-gate evidence log)
- `docs/RELEASE_PROCEDURE.md` (funding-checkpoint tagging + manifest)
- `docs/LEGAL_COMPLIANCE.md` (OSS artifact legal/compliance checklist)
- `docs/API_STABILITY.md` (public-API tiers + validation-window freeze rules)
- `docs/SECURITY_REPORTING.md` (bug-bounty report template + triage SLA)
- `docs/SUPPLY_CHAIN_SCAN.md` (cargo-audit scanner + advisory triage)
- `docs/HARDENING.md` (post-funding security-hardening summary + threat impact)
- `docs/LAB_PROTOTYPES.md` (operational guide for QUIC-shim, offline-mesh, and data-mule labs)
- `docs/evidence/CARGO_AUDIT.txt` (regenerable advisory-scan output)
- `docs/DESCRIBE_PROJECT_SONNET5.md` (independent external description + threat model)
- `docs/EXTERNAL_AUDIT_SONNET5.md` (independent external gate-verification audit)
- `CHANGELOG.md` (phase-anchored changelog)
- `SECURITY.md` (vulnerability reporting, threat model, non-claims matrix)
- `CONTRIBUTING.md` (build/test, release checklist, governance)
- `.github/workflows/ci.yml` (Linux + Windows CI template)

## Security Note

Peer identity and handshake-signing-key pinning are mandatory for all CLI
sessions; register both expected keys with `add-peer` before using `listen`,
`connect`, `send-once`, `recv-once`, or `up`. Do not market current SHPH as
censorship-resistant production transport.
Use it for controlled testing, staged engineering hardening, and transparent OSS validation only.
See `SECURITY.md` for the full threat model and explicit non-claims matrix.

## License

Dual-licensed under MIT OR Apache-2.0 (`LICENSE-MIT`, `LICENSE-APACHE`).
