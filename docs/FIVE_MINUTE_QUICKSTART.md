# SHPH Five-Minute Quick Start

This guide proves the basic SHPH flow on **one machine**: two local identities
authenticate each other and exchange one encrypted TCP message.

It is a development and evaluation walkthrough, not a production deployment or
native-TUN validation. It does not require root, Wintun, or
`SHPH_TUN_NATIVE=1`.

## You need

- Rust `1.96.0` (the repository pins the toolchain in `rust-toolchain.toml`);
- two terminals in the repository root; and
- an available local TCP port (this guide uses `7220`).

On Linux shells where Cargo is not already on `PATH`, run:

```bash
source "$HOME/.cargo/env"
```

## 1. Build the CLI

```bash
cargo build -p shph-cli --locked
```

The compiled command is `./target/debug/shph`. The rest of this guide uses
that binary so each command is short and reproducible.

## 2. Create two local identities

```bash
mkdir -p /tmp/shph-quickstart/alice /tmp/shph-quickstart/bob

./target/debug/shph --config /tmp/shph-quickstart/alice/config.toml init --new
./target/debug/shph --config /tmp/shph-quickstart/bob/config.toml init --new
```

`init --new` creates a configuration and a private keystore in each directory.
These are test identities. Do not copy a real keystore into a repository or
share it with another person.

## 3. Exchange and pin both public identities

Run the following in either terminal:

```bash
alice_key="$(./target/debug/shph --config /tmp/shph-quickstart/alice/config.toml show-public-key)"
alice_sign_key="$(./target/debug/shph --config /tmp/shph-quickstart/alice/config.toml show-signing-public-key)"
bob_key="$(./target/debug/shph --config /tmp/shph-quickstart/bob/config.toml show-public-key)"
bob_sign_key="$(./target/debug/shph --config /tmp/shph-quickstart/bob/config.toml show-signing-public-key)"

./target/debug/shph --config /tmp/shph-quickstart/alice/config.toml \
  add-peer bob 127.0.0.1 7220 "$bob_key" --sign-pubkey "$bob_sign_key"

./target/debug/shph --config /tmp/shph-quickstart/bob/config.toml \
  add-peer alice 127.0.0.1 7220 "$alice_key" --sign-pubkey "$alice_sign_key"
```

SHPH requires both the peer identity key and the peer handshake-signing key.
That pinning is intentional: a session fails closed when the remote peer is not
the expected peer.

## 4. Start the receiver

In **Terminal A**, run:

```bash
./target/debug/shph --config /tmp/shph-quickstart/alice/config.toml \
  recv-once --bind 127.0.0.1:7220
```

Leave this terminal running. It waits for one authenticated, encrypted payload.

## 5. Send one encrypted message

In **Terminal B**, run:

```bash
./target/debug/shph --config /tmp/shph-quickstart/bob/config.toml \
  send-once --peer 127.0.0.1:7220 --text "hello from SHPH"
```

Expected result:

- Terminal B reports a successful `send-once` handshake and sent bytes.
- Terminal A reports a successful `recv-once` handshake and prints:

```text
Payload: hello from SHPH
```

That completes the local quick start.

## What this demonstrated

- two independently generated local identities;
- explicit peer identity and signing-key pinning;
- authenticated handshake establishment; and
- one encrypted TCP payload exchange.

It did **not** demonstrate a production VPN, a native TUN adapter, routed
traffic, external-network performance, standards QUIC, DPI resistance, or
censorship resistance.

## Next steps

- Run all development gates: `cargo fmt --all -- --check`,
  `cargo clippy --workspace --all-targets --locked -- -D warnings`,
  `cargo test --workspace --locked`, and `cargo build --workspace --locked`.
- Run `./scripts/demo.sh all` for a compact successful-flow plus fail-closed
  demonstration.
- Read `docs/FUNDERS.md` and `docs/WHY_SHPH.md` for project scope and
  funding-oriented context.
- For controlled native Linux two-host evidence, use
  `docs/NATIVE_LINUX_TWO_HOST_VALIDATION.md`.
- For the current threat model and non-claims, read `SECURITY.md`.

## Clean up

Remove the test identities when finished:

```bash
rm -rf /tmp/shph-quickstart
```
