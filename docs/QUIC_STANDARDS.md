# Standards QUIC Transport

## Status

SHPH now contains an opt-in, standards-compliant QUIC transport in
`shph-transport/src/standards_quic.rs`.

- QUIC transport: Quinn `0.11.x`, implementing RFC 9000 behavior.
- TLS: TLS 1.3 through Quinn/rustls.
- Reliable control plane: length-bounded bidirectional QUIC stream.
- Tunnel data plane: QUIC application DATAGRAM frames (RFC 9221).
- SHPH authentication: the existing signed SHPH handshake runs inside the
  authenticated QUIC connection.
- Hybrid key exchange: the existing ML-KEM-768 plus X25519 exchange is
  performed by the application handshake; the QUIC TLS handshake remains
  standards-compliant.

The existing `TransportMode::Quic` API is intentionally still the legacy
experimental UDP shim. It is not silently redefined, because changing its wire
format would break existing lab users and invalidate historical measurements.
Use the explicit `quic-standard` CLI mode for one-shot and handshake
commands. Continuous `up` mode still rejects this transport because its
async TUN bridge is not implemented; native TUN remains a separate later
phase.

## Architecture Decision

The research correctly rejects implementing QUIC loss recovery, congestion
control, packet-number spaces, migration, and PMTU discovery from scratch.
Quinn supplies those protocol mechanisms instead of leaving them as
placeholders.

The proposed custom s2n-quic crypto-provider skeleton is not used. QUIC
implementations negotiate TLS 1.3 as part of the standardized transport
handshake; replacing that with a raw SHPH/ML-KEM handshake would no longer be
interoperable QUIC. SHPH therefore layers its audited application handshake
over standard QUIC rather than claiming that a custom provider has replaced
TLS.

## Lab Usage

The module provides:

1. `server_endpoint(...)`, which creates a localhost self-signed lab endpoint
   and returns the certificate bytes.
2. `client_endpoint(...)`, which trusts exactly those certificate bytes.
3. `connect(...)` and `accept(...)`, which perform the QUIC handshake followed
   by the selected SHPH handshake profile.
4. `send_control`/`recv_control`, which use bounded reliable stream messages.
5. `send_datagram`/`recv_datagram`, which use bounded unreliable QUIC
   datagrams.

The certificate helper is for controlled lab deployments. Production
deployment still needs an operator-managed certificate and trust distribution
path; the helper must not be mistaken for a public PKI workflow.

## CLI Usage

The server writes a DER certificate and the client reads the same certificate
from an out-of-band, trusted path:

```text
# server
shph listen --bind 127.0.0.1:7220 \
  --transport quic-standard --quic-cert /path/server.der

# client
shph connect --peer 127.0.0.1:7220 \
  --transport quic-standard --quic-cert /path/server.der

# one-shot receive/send
shph recv-once --bind 127.0.0.1:7220 \
  --transport quic-standard --quic-cert /path/server.der
shph send-once --peer 127.0.0.1:7220 --text "hello" \
  --transport quic-standard --quic-cert /path/server.der
```

The client trusts exactly the certificate file supplied with `--quic-cert`;
there is no public-CA fallback. Certificate files are size-bounded, read
without following final-component symlinks, and server replacement refuses an
existing symlink destination. Peer identity and signing-key pinning are still
required by the SHPH application policy.

`up --transport quic-standard` is intentionally rejected until an async
standards-QUIC-to-TUN bridge is implemented and separately tested. Do not
interpret the one-shot CLI support as a native TUN or production VPN claim.

## Hardening

The standards path:

- Rejects empty and oversized stream messages before allocation.
- Caps handshake messages at 16 KiB and control messages at 64 KiB.
- Caps tunnel datagrams at the IPv4 maximum of 65,535 bytes and checks the
  negotiated QUIC datagram limit.
- Bounds the QUIC datagram buffer to 1 MiB and concurrent stream limits to 1024.
- Uses a finite 30-second default idle timeout.
- Applies the configured peer allowlist before one-shot payload send/receive.
- Uses the awaited datagram send path for one-shot delivery so local
  congestion-buffer exhaustion is reported instead of silently dropping the
  payload.
- One-shot CLI sends wait for a bounded receipt acknowledgement on the
  reliable control stream; the receive side keeps the connection alive until
  the sender closes, so success reflects peer receipt rather than only local
  queueing.
- Keeps the legacy shim and native TUN work separate.

## Verification

The focused test
`standards_quic::tests::loopback_handshake_control_and_datagram_roundtrip`
proves, on Linux loopback, that:

- real QUIC/TLS connection establishment succeeds;
- the SHPH classical application handshake succeeds;
- reliable control data crosses a bidirectional stream;
- a QUIC DATAGRAM reaches the peer; and
- an oversized tunnel datagram is rejected.

This is transport interoperability evidence, not a claim that the legacy shim
or native TUN integration is complete. The CLI coverage currently proves
one-shot and handshake operations only; continuous `up` support remains
pending the async TUN bridge.
