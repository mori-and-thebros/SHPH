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
SHPH_SHROUD_PROFILE=off
SHPH_SHROUD_PROFILE=low
SHPH_SHROUD_PROFILE=medium
SHPH_SHROUD_PROFILE=high
SHPH_SHROUD_PROFILE=extreme-lab
```

Named compatibility profiles remain available:

```text
SHPH_SHROUD_PROFILE=randomized-lab
```

`randomized-lab` randomizes authenticated inner padding while retaining a
fixed-size cell. This is useful for measuring framing behavior; it is not
traffic-analysis resistance or browser/TLS/QUIC fingerprint mimicry.

## Shroud 2.0 morphology lab

The standards-QUIC API also exposes an explicit morphology experiment under
`shph_transport::shroud2`. It selects bounded payload-size classes and bounded
inter-datagram delay, then carries a versioned, length-checked envelope over
authenticated RFC 9221 DATAGRAM frames. It is useful for measuring overhead,
tail latency, and payload preservation:

```text
let mut morphology = MorphologyEngine::new(MorphologyProfile::WebBrowsingLab);
connection
    .send_morphology_datagram(&mut morphology, b"lab payload")
    .await?;
let payload = connection.recv_morphology_datagram().await?;
```

This is an opt-in lab morphology tool. It does not provide browser fingerprint
parity, active-probe deflection, censorship bypass, or a stealth guarantee.
See `docs/SHROUD_2_IMPLEMENTATION.md` for the implementation disposition.

## Standards QUIC module

For real RFC QUIC behavior, use `--transport quic-standard` with
`--quic-cert` on `listen`, `connect`, `send-once`, or `recv-once`, or use the
explicit `shph_transport::standards_quic` API documented in
`docs/QUIC_STANDARDS.md`. It is separate from `--transport quic`, which
remains the compatibility name for the legacy UDP shim. The standards module
uses Quinn/rustls TLS 1.3, reliable QUIC streams for control messages, and RFC
9221 QUIC DATAGRAM frames for tunnel payloads. Continuous `up` mode and native
TUN are intentionally not supported by this path yet.

Intensity semantics:

| Selection | Effective profile | Behavior |
| --- | --- | --- |
| `off` | none | No Shroud wrapping; ordinary authenticated UDP-shim frames |
| `low` | `low-latency` | Smaller cells and lower framing delay |
| `medium` | `balanced` | Default lab balance of cell size and padding |
| `high` | `bulk` | Larger cells for bulk-oriented experiments |
| `extreme-lab` | `extreme-lab` | 8 KiB randomized lab cells; highest overhead |

The intensity names are convenience aliases, not security levels. Higher
intensity does not mean stronger cryptography or stealth.

For a no-Shroud baseline, leave `SHPH_SHROUD_PROFILE` unset or set it to
`off`. For repeatable comparisons, use the same named selection on both peers
and record it with the benchmark environment.

Shroud activation is explicit and lab-only. The `SHPH_SHROUD_PROFILE`
environment variable is the transport activation path today; if it is unset,
the transport remains unwrapped. `off` also explicitly disables wrapping. A
`[stealth].shroud_profile` value is validated as configuration metadata but
does not silently activate Shroud. Unknown names are rejected. There is no
implicit fallback from an invalid profile.

Each cell has the fixed `SD` header, a data/chaff frame type, a two-byte
big-endian payload length, and fixed-size padding. The user-data
`max_payload_chunk` limit is enforced at the data transport boundary, while
the low-level cell API separately enforces raw cell capacity for authenticated
ciphertext. Unknown frame types, malformed lengths, wrong cell sizes, and
profile mismatches fail closed.
Encoded cells use canonical zero outer padding; altered padding is rejected
before the frame is exposed to the transport layer.

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
- Senders reject payloads above the configured file bound before performing
  AEAD work; the serialized envelope is still checked against the final file
  limit.
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
max_total_bytes = 4194304
max_age_ms = 86400000
```

Operational behavior:

- Envelope paths are confined to sanitized peer and envelope components.
- File size, scan depth, and scan count are bounded.
- Each inbox and outbox has an aggregate `max_total_bytes` quota; the default
  is 4 MiB and the hard cap is 8 MiB.
- Envelopes older than `max_age_ms` are quarantined during scanning; the
  default is 24 hours and the hard cap is 30 days.
- Payloads above `max_file_bytes` are rejected before AEAD encryption, limiting
  caller-controlled allocation and CPU work.
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
2. Run the focused Shroud matrix with
   `cargo test -p shph-transport quic_shroud`.
3. Run a QUIC-shim round trip with `randomized-lab`.
4. Exercise a malformed or oversized courier file and confirm it becomes
   `.rejected`.
5. Copy an offline/data-mule envelope between distinct spool roots.
6. Verify the receiver can retry an envelope after a failed authentication
   attempt and consumes it only after successful decryption.

None of these prototypes should be exposed as a production VPN transport
without a separate design review, interoperability work, and hostile-network
testing.
