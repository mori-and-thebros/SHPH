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

## Shroud 2 morphology lab

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

Small application messages may be coalesced with
`send_morphology_batch`/`recv_morphology_batch`, or queued through
`MorphologyBatcher::for_profile`. The batch envelope is bounded by the
negotiated datagram limit and 32 messages. Call
`flush_morphology_batch_if_due` from the application's event loop when using a
latency policy. Do not use it for separate native-TUN IP packets: QUIC
DATAGRAM loss would discard the entire batch.

This is an opt-in lab morphology tool. It does not provide browser fingerprint
parity, active-probe deflection, censorship bypass, or a stealth guarantee.
See `docs/SHROUD_2_IMPLEMENTATION.md` for the implementation disposition.

## Phantom One authenticated TCP envelope

Phantom One is a separate, versioned, opt-in inner envelope for authenticated
TCP sessions. It is selected explicitly with `--phantom-one` and an optional
`--phantom-one-profile` on `host`, or through a join ticket that carries the
same mode and profile:

```text
shph host --transport tcp --phantom-one --phantom-one-profile medium --no-tun
shph join 'shph://v1:...' --no-tun
```

Phantom One uses bounded session-scoped padding, an explicit generation, frame types,
and a bounded replay window inside the existing SHPH AEAD. It is available on
authenticated TCP and, with explicit capability negotiation, the opt-in
standards-QUIC path. It is not available on the legacy QUIC shim or filesystem
adapters. Its TCP size limit is a logical encrypted-frame budget, not a physical
path MTU. On standards QUIC, DATAGRAM mode is used for native-TUN packets and a
dedicated reliable stream is available for ordered records. Phantom One does not provide
browser/TLS/QUIC fingerprint parity, active-probe deflection, anonymity, or a
censorship-resistance guarantee.

The separate `shph-edge/` crate is an owned-domain HTTP/2 relay prototype for
forwarding opaque bytes with short-lived signed capabilities. It is not part
of the workspace release profile. Its HTTP/3 carrier is feature-gated and
opt-in; it requires operator-owned TLS material and remains experimental with
no recorded two-host HTTP/3 campaign. See `docs/PHANTOM_ONE_DESIGN.md`,
`docs/PHANTOM_ONE_OPERATOR.md`, and
`docs/PHANTOM_ONE_TESTING.md`.

## Standards QUIC module

For real RFC QUIC behavior, use `--transport quic-standard` with
`--quic-cert` on `listen`, `connect`, `send-once`, or `recv-once`, and add
`--quic-key` to server commands. The `host`/`join` flow also supports
`quic-standard`; the host persists the certificate/key pair and the joiner
receives the public certificate out of band. The explicit
`shph_transport::standards_quic` API is documented in
`docs/QUIC_STANDARDS.md`. This is separate from `--transport quic`, which
remains the compatibility name for the legacy UDP shim. The standards module
uses Quinn/rustls TLS 1.3, reliable QUIC streams for control messages, and RFC
9221 QUIC DATAGRAM frames for tunnel payloads. Continuous `up` mode is
available with Linux native TUN and stable server material; Windows native-TUN
forwarding remains host-gated.

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
- Replay state is bounded and keyed by `(created_at_unix_ms, sequence)` so a
  writer sequence reset after restart cannot silently collide with an older
  envelope; entries are acknowledged only after successful authenticated
  consumption.
- Queue scans are bounded by entry count and filesystem depth.
- Windows claims and atomic persistence use the extended-length Win32 path
  namespace, so nested temporary spool paths do not fall back to legacy
  `MAX_PATH` behavior.

The sender and receiver must use the same logical spool, or an external
replication step must copy the sender's output tree into the receiver's spool.

The local regression suite also exercises a complete authenticated session
round trip on a shared spool and an authenticated envelope copied between
distinct spool roots. These tests prove the bounded file-adapter code path and
AEAD/session binding only; they do not prove physical mesh discovery, courier
delivery, or synchronized-spool consistency under an external filesystem.

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
- The outbox enforces the aggregate `max_total_bytes` write quota; the default
  is 4 MiB and the hard cap is 8 MiB. Inbox work is independently bounded by
  hard scan-entry, scan-byte, per-file, and candidate-memory limits. It checks
  recipient and configured peer metadata before reading eligible candidates,
  then processes a bounded snapshot so unauthenticated ciphertext cannot hold
  later authenticated deliveries behind a spoofed quota claim.
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
5. Run the authenticated offline-mesh and data-mule session round-trip tests.
6. Copy an offline-mesh envelope between distinct spool roots and verify the
   source remains available after destination consumption.
7. Verify the receiver can retry an envelope after a failed authentication
   attempt and consumes it only after successful decryption.
8. Verify a writer sequence reset with a new creation timestamp is accepted,
   while the original `(timestamp, sequence)` replay key remains rejected.

None of these prototypes should be exposed as a production VPN transport
without a separate design review, interoperability work, and hostile-network
testing.
