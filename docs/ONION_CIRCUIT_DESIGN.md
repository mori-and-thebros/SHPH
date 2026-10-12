# Native Onion Circuit Design and Prototype (O1b)

Status: **experimental bounded prototype; not release validated**. This
document records the original design boundary and the current implementation
shape for O1b in [`PHANTOM_SHROUD_SCOPE.md`](PHANTOM_SHROUD_SCOPE.md). Local
loopback tests exercise two- and three-relay paths, including a process-level
three-relay SHPH exchange, malformed setup, stalled-hop lifetime, concurrency
limit rejection, and bounded shutdown. This is not a production protocol review,
interoperability result, security finding, or anonymity evidence.

## Implemented prototype boundary

The implementation lives in `shph-transport/src/onion.rs` and exposes
`OnionPath`, `RelayHop`, `connect_secure_session_onion`, and the separate
`shph-onion-relay` process. Each hop is configured by numeric endpoint, TLS
server name, pinned certificate, and independent 32-byte authorization token.
Relays accept only exact numeric targets from their configured allowlist.

The client opens an independent TLS 1.3 connection for each hop, using the
previous hop's TLS stream to carry the next handshake. TLS uses the
`shph-onion/1` ALPN. Each relay terminates only its own link, then forwards the
inner TLS stream to the next configured socket. The final tunnel carries the
existing end-to-end SHPH TCP handshake and encrypted session unchanged. No
destination DNS lookup, relay discovery, direct fallback, or retry through an
unconfigured route is implemented.

Each relay bounds concurrent circuits, setup time, lifetime, target count, and
forwarded bytes. The server's bearer token is carried inside TLS and redacted
from `Debug` output. Operators must protect token files and restrict relay
network access. The relay binary reads DER certificate/key files and a raw
32-byte token file. It is a narrow route forwarder, not a public exit service.

This prototype uses TLS 1.3's per-connection key agreement, record sequence,
authentication, and key update behavior rather than a new custom onion cell
format. The earlier sections below that specify custom cell framing and key
derivation remain design requirements for a future reviewed protocol; they are
not implemented by this TLS-stream prototype. Independent protocol and code
review is still required before production-facing use or any broader security
claim.

## Scope and opt-in boundary

- The proposed route is `client -> entry relay -> middle relay -> destination
  SHPH peer`. The relays are explicitly configured and pinned; there is no
  public relay discovery, public exit service, or automatic relay selection.
- Onion routing is a separate, explicit routing choice, off by default. It does
  not imply a padding, cover-traffic, carrier, or DPI-resistance policy.
- The existing client-to-destination SHPH authenticated channel remains the
  application-security boundary. Relays do not terminate that handshake or
  receive its application plaintext. Circuit protection is additional hop and
  forwarding protection, not a replacement for the inner SHPH channel.
- This proposal is about a bounded circuit over configured relay connections.
  It is not a general-purpose proxy service or a claim of native-TUN containment.
  The latter requires separate routing and leak testing.

## Roles and visibility

| Participant | Information available by design |
| --- | --- |
| Client | The selected relay descriptors and pins, destination locator and SHPH peer pin, circuit state, and application data. The client is the origin and is not hidden from itself. |
| Entry relay | The client's network address, its own per-link circuit handle, the next relay's address, direction, timing, and cell-size/volume metadata. It has its own hop keys and sees the next-layer ciphertext, not the destination locator or inner application plaintext. |
| Middle relay | The entry relay's network address, the destination-side locator/connection, its own per-link handle and hop keys, and direction/timing/volume metadata. It forwards inner SHPH ciphertext and does not learn its application plaintext. |
| Destination SHPH peer | The immediate connecting relay's network address and whatever client identity the inner SHPH authentication policy exposes. As the application endpoint, it receives application plaintext; it need not learn the entry relay or full route. |

These are protocol-intended views, not guarantees against compromised hosts,
traffic analysis, collusion, or logging outside the protocol. In particular,
entry and middle operators that collude can combine their adjacent-link views;
shared ownership removes any assumed organizational separation. An observer
able to monitor both client-side and destination-side links may correlate timing,
direction, and volume. The design includes no mixing or cover traffic and makes
no anonymity claim.

The client should pass a destination locator only inside the middle-hop-protected
extension/data layer. If the locator is a hostname, resolution belongs at the
destination-facing relay; the client must not resolve it locally in onion mode.
The destination is still authenticated by the inner SHPH peer policy after the
route is established. A relay's ability to forward to a locator is not proof of
destination identity.

## Candidate wire boundary

The final encoding and assigned identifiers are open design items. A reviewed
protocol would use a length-delimited, bounded cell with at least:

- A protocol-specific magic and explicit major version, plus a minor version or
  capability negotiation whose selected result is bound into the handshake.
- A cell type, canonical flags/reserved fields, a **link-local** opaque circuit
  identifier, key epoch, direction-specific sequence number, and bounded body
  length. Circuit identifiers are independently random per adjacent link, not a
  shared route identifier.
- An authenticated body. All security-relevant header fields are authenticated
  as associated data; control and data messages have distinct, unambiguous types.
- A hard maximum cell size and parser allocation limit chosen before
  implementation. Larger application streams are carried in bounded data cells;
  parsing must not allocate from an untrusted length before checking that limit.

Version and capability offers, the selected version/suite, relay identity pins,
roles, fresh handshake challenges, and ephemeral public keys must be bound to
the authenticated transcript. Unknown major versions, unsupported required
capabilities, malformed/noncanonical fields, oversized or truncated cells, and
unrecognized critical flags fail closed. There is no silent version or suite
downgrade. A protocol version mismatch is an error, not a request to use the
ordinary direct route.

The candidate control vocabulary includes circuit create, extend, created/
extended acknowledgement, data, flow-credit update, rekey, destroy, and bounded
error responses. Exact encodings, numeric identifiers, length limits, suite
selection rules, and transport integration remain to be reviewed and specified;
the names here do not assign wire values.

## Authenticated construction and extension

1. The client opens only to its configured entry endpoint and authenticates the
   entry against the locally pinned relay identity. The relay descriptor should
   bind its endpoint, identity pin, permitted role/capabilities, and applicable
   resource limits. A relay presenting a different identity is rejected.
2. Each hop is established with a fresh, independent ephemeral key agreement and
   an authenticated transcript. The transcript binds the protocol version and
   selected suite, both roles and relay identity, fresh challenges, circuit/link
   context, and the ephemeral keys. Relay identity authentication uses a
   reviewed signature scheme and role-specific transcript domain; it must not
   treat a digest of public handshake data as a signature.
3. To extend through the entry, the client sends an authenticated `EXTEND`
   request inside the entry circuit. The entry learns the next relay endpoint
   because it must connect there, but forwards the middle-hop handshake proof
   opaquely. The middle's authenticated response is bound to the client's fresh
   extension challenge and the extension transcript, so the entry cannot
   substitute its own relay identity or fabricate a successful extension.
4. The client verifies the middle against its configured pin before treating the
   circuit as extended. Further hops, if supported for testing, repeat this
   nested process; each preceding relay learns only its next peer and each hop
   authenticates independently. The prototype must cap the hop count.
5. Application data is admitted only after all configured hops have completed
   authenticated construction. Failed authentication, pin mismatch, timeout,
   or partial extension destroys the partial circuit and returns an error.

Existing SHPH cryptographic building blocks may be candidates for these handshakes,
but this proposal does not declare them suitable as-is or select a cipher suite.
The per-hop scheme, transcript encoding, domain separation, downgrade handling,
and compatibility with the retained hybrid end-to-end handshake require
independent protocol review before implementation or production use.

## Per-hop keys, layering, and replay state

Each relay hop `h` has a distinct ephemeral shared secret `Z_h`; no ephemeral
key, shared secret, traffic key, or nonce space is reused across hops, circuits,
directions, or the inner SHPH application channel. A candidate schedule is:

```text
transcript_h = canonical authenticated transcript for hop h
PRK_h        = reviewed_KDF_Extract(hash(transcript_h), Z_h)
K_h_fwd      = reviewed_KDF_Expand(PRK_h, version || circuit || h || epoch || "forward-data")
K_h_back     = reviewed_KDF_Expand(PRK_h, version || circuit || h || epoch || "backward-data")
K_h_control  = reviewed_KDF_Expand(PRK_h, version || circuit || h || epoch || "control")
```

This is a separation requirement and illustrative schedule, not a frozen KDF
specification. The reviewed schedule must use unambiguous, domain-separated
labels and bind every context that prevents cross-hop, cross-direction,
cross-epoch, or protocol confusion. Control-key separation may instead be
implemented through an equally reviewed, explicit channel label.

- **Forward data:** the client first protects an opaque inner SHPH data unit for
  the destination-facing hop, then wraps it in each preceding hop's forward
  layer. Each relay authenticates and removes exactly its own layer, checks the
  authenticated forwarding instruction, and forwards the remaining ciphertext.
- **Return data:** the destination-facing relay protects the opaque SHPH reply
  with its backward key; each preceding relay adds its own backward layer as the
  cell travels toward the client. The client removes the layers in route order.
- Each direction and control/data channel has independent monotonically
  increasing sequence state per hop and epoch. Sequence/epoch/direction/type
  are authenticated with the cell. Receivers keep bounded replay state and
  reject duplicates, stale cells, invalid epochs, and sequence exhaustion.
  Counters never wrap; exhaustion requires rekey or circuit closure.
- A layer-authentication failure, replay, unexpected hop/epoch, or malformed
  forwarding instruction drops the affected cell and fails the circuit or
  protocol operation. No unauthenticated payload reaches the next hop or
  destination. Relays can still drop, delay, or withhold valid traffic.

The inner SHPH peer handshake and its end-to-end data-plane authentication remain
mandatory. Onion layers prevent an intermediate relay from removing later-hop
protection; the inner channel prevents a relay from impersonating either SHPH
endpoint or reading application data. Neither layer guarantees availability.

## Rekey, expiry, and resource bounds

- Relay descriptors and circuits have explicit validity/expiry, idle-timeout,
  and maximum-lifetime policy. Defaults and hard maxima must be chosen and
  justified before implementation; unbounded lifetimes are not acceptable.
- Rekey is per hop with fresh ephemeral material and a transcript-confirmed new
  epoch. The transition must define how in-flight cells are drained, reject
  ambiguous old/new-epoch traffic, and bound any overlap. If rekey cannot
  complete before the configured limit, fail closed and close the circuit.
- Enforce per-hop and per-circuit limits for active circuits, hops, queued
  bytes/cells, outstanding flow credit, handshake attempts, bytes, rate, and
  lifetime. Enforce global relay limits as well as per-client limits so creating
  many circuits cannot bypass a per-circuit cap.
- Authenticate and validate requests before expensive work or large allocations.
  Reject excess work with bounded responses; do not let extension or error
  handling amplify traffic beyond the input and fixed limits.

Exact limit values belong in a later reviewed implementation specification and
must be measured against the intended transport. They are not established by
this proposal.

## Flow control, errors, and teardown

Flow control uses bounded per-hop credits or windows. A relay forwards only
within granted credit, returns credit through authenticated control cells, and
applies backpressure when its downstream queue is full. Queue sizes, waiting
times, and retry counts are capped. A stalled downstream hop eventually returns
a bounded failure or closes the circuit; it cannot induce unbounded buffering.

Teardown is idempotent and may be initiated by the client, any relay, the
destination-side connection, cancellation, idle/lifetime expiry, quota
exhaustion, authentication failure, or transport failure. A relay releases local
state promptly and best-effort forwards a destroy indication to adjacent peers;
cleanup does not depend on successful notification. Logs and externally visible
errors must not disclose keys, payloads, or unnecessary peer identifiers.

Every route failure is fail-closed. In onion mode, the client must not resolve
the destination locally, open a direct destination connection, or silently
switch to a different carrier or unconfigured relay after setup, extension,
rekey, middle-hop, quota, or transport failure. The caller receives a bounded
error/cancellation result. Reconnection, if requested, constructs a new circuit
under the same explicit onion policy and pins; it never means direct fallback.

## Proposed three-relay test plan

The O1b functional path is client -> entry -> middle -> destination. The
integration fixture should additionally launch **three separate relay processes**
and exercise a configured test-only extension path
`client -> entry -> middle -> final relay -> destination`. The extra hop tests
that extension, independent key state, and layer ordering compose beyond a
two-relay path. All relays and the destination are controlled test endpoints;
this fixture is not a public exit network, and three processes do not imply
three independent operators.

The design's later prototype should test, at minimum:

- Successful authenticated construction and inner SHPH payload delivery through
  both the two-hop target path and the three-process fixture; assert each relay
  sees only its adjacent peers and permitted forwarding metadata.
- Pin mismatch, forged or substituted extension acknowledgement, unsupported
  version/suite, downgrade attempt, circuit/path splice, malformed frame, and
  partial/failed extension; none may deliver application data.
- Per-layer tampering, duplicate and stale cells, reordering where the transport
  permits it, cross-direction/epoch replay, sequence exhaustion, rekey races,
  lost rekey acknowledgement, and relay restart. Assert no replayed or
  unauthenticated payload is delivered.
- A malicious or stalled entry/middle/final relay, downstream refusal, timeout,
  cancellation during setup and active transfer, repeated teardown, circuit
  exhaustion, queue/credit exhaustion, and reconnect after failure. Instrument
  connection attempts to prove no destination-direct fallback or local DNS leak.
- Per-circuit and global memory, queue, byte, rate, handshake, and amplification
  bounds under repeated connection and slow-reader pressure. Capture redacted
  logs and verify secret/payload absence.
- P5 performance captures and D4 first-hop observations separately, as called
  for by [`PHANTOM_SHROUD_SCOPE.md`](PHANTOM_SHROUD_SCOPE.md). Record setup,
  steady-state, idle, and teardown observations, and distinguish measured
  results from in-memory cell sizes.

This is a test plan, not evidence that any test has run or passed. Missing hosts,
carriers, or capture capability must be recorded as `SKIP`, not `PASS`.

## Threat limits and non-claims

The proposal is intended to limit what one non-colluding relay learns from
protocol plaintext and routing metadata. It does not hide the client's network
address from entry, the destination locator from the destination-facing relay,
or the SHPH client's authenticated identity from the destination when the inner
authentication policy reveals it. It does not prevent endpoint compromise,
malicious destination behavior, relay denial of service, traffic confirmation,
global or both-end observation, collusion, shared relay ownership, Sybil
selection, legal/operational correlation, or implementation flaws. It specifies
no mixing, route diversity guarantee, traffic-analysis defense, or censorship
resistance.

More hops are not evidence of anonymity. Relay selection, ownership separation,
logging policy, destination-resolution behavior, and the operator's threat model
must be evaluated explicitly; random rotation alone is not an independence
policy. Any future security or anonymity claim needs new, reviewed, reproducible
evidence and must not be inferred from this design.

## Independent protocol-review gate

An independent protocol review is a hard gate **before production integration,
release use, or any broader security claim**. Reviewers must be independent of
the implementation and examine the complete versioned wire format, relay
authentication and extension transcript, downgrade/path-splice resistance,
per-hop ephemeral key schedule and domain separation, forward/return layering,
nonce and replay rules, rekey/expiry transitions, flow control and resource
limits, error/teardown behavior, destination resolution, trust assumptions, and
collusion/threat analysis.

The review and response to findings must be recorded. Critical and high-severity
findings must be resolved and independently checked before crossing the gate;
material protocol changes require review of the affected design. The gate also
requires multihop tests and dated evidence separate from the review report. A
review of this proposal would not itself validate a future implementation,
establish anonymity, or authorize broader product claims.
