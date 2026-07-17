# Lab Prototype Operations

SHPH's alternate transports are usable for controlled experiments, local
integration tests, and store-and-forward demonstrations. They are not
production QUIC, a wireless mesh implementation, or a hostile-network
anti-observation system.

## QUIC-like UDP shim

Use `--transport quic` for a point-to-point UDP shim. It performs the normal
authenticated hybrid handshake, binds post-handshake frames to the peer's
source address, bounds datagrams, and rejects replayed AEAD counters.

For fixed-size lab framing:

```text
SHPH_SHROUD_PROFILE=balanced
SHPH_SHROUD_PROFILE=low-latency
SHPH_SHROUD_PROFILE=bulk
SHPH_SHROUD_PROFILE=randomized-lab
```

`randomized-lab` randomizes authenticated inner padding while retaining a
fixed-size cell. This is useful for measuring framing behavior; it is not
traffic-analysis resistance or browser/TLS/QUIC fingerprint mimicry.

## Offline mesh spool

Offline mesh is a filesystem-backed delayed-delivery adapter. It models a
transport where a peer deposits envelopes into a shared or synchronized spool.
It does not discover Bluetooth, Wi-Fi Direct, or DTN peers.

Example roadmap configuration:

```toml
[roadmap.transport]
kind = "offline_mesh"
node_id = "alice"
peer_id = "bob"
spool_dir = "/tmp/shph-spool"
poll_interval_ms = 100
max_idle_entries = 1024
```

Operational behavior:

- Envelopes are written with fsync and a unique temporary filename.
- The receiver validates session and node identity before accepting an
  envelope.
- Invalid or oversized files are quarantined as `.rejected`.
- Replay state is bounded; entries are acknowledged only after successful
  authenticated consumption.
- Queue scans are bounded by entry count and filesystem depth.

The sender and receiver must use the same logical spool, or an external
replication step must copy the sender's output tree into the receiver's spool.

## Data-mule store and forward

Data-mule is a filesystem-backed courier adapter. A sender writes `.shph`
envelopes into the configured outbox; an operator or courier copies that tree
to the receiver's inbox.

Example roadmap configuration:

```toml
[roadmap.transport]
kind = "data_mule"
inbox_dir = "/tmp/shph-mule/inbox"
outbox_dir = "/tmp/shph-mule/outbox"
poll_interval_ms = 250
max_file_bytes = 32768
```

Operational behavior:

- Envelope paths are confined to sanitized peer and envelope components.
- File size, scan depth, and scan count are bounded.
- Invalid and oversized files are quarantined rather than retried forever.
- A courier file is removed only after AEAD authentication succeeds.
- Envelope identity is stable and replay tracking is bounded.

For a two-directory demonstration, copy the sender's outbox contents into the
receiver's inbox after the sender has emitted its envelope:

```text
cp -a /tmp/shph-mule/outbox/. /tmp/shph-mule/inbox/
```

## Lab acceptance checklist

1. Run `cargo test --workspace`.
2. Run a QUIC-shim round trip with `randomized-lab`.
3. Exercise a malformed or oversized courier file and confirm it becomes
   `.rejected`.
4. Copy an offline/data-mule envelope between distinct spool roots.
5. Verify the receiver can retry an envelope after a failed authentication
   attempt and consumes it only after successful decryption.

None of these prototypes should be exposed as a production VPN transport
without a separate design review, interoperability work, and hostile-network
testing.
