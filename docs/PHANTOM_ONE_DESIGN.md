# Phantom One Design (Public Boundary)

Status: prototype, explicit opt-in, versioned wire break. This document
describes the Phantom One public boundary as of 2026-09-28. It is a
design and boundary record, not a release announcement, an API stability
promise, or a security claim.

## Status and opt-in contract

- Phantom One is **explicitly opt-in**. Nothing in the default SHPH transport,
  CLI profile, or standards-QUIC path selects Phantom One framing or the edge relay
  without an explicit caller or operator choice.
- Phantom One is a **versioned break** from the Shroud 2 envelope
  (`shph-transport/src/shroud2/`). The Phantom One envelope carries its own
  four-byte marker (`PH1\0`) and a one-byte format version (currently `1`). Peers that do
  not agree on generation and version fail closed; there is no silent
  downgrade or compatibility shim to the 2.0 envelope.
- The Phantom One framing code is exported as `shph_transport::phantom_one`
  (`shph-transport/src/phantom_one.rs`). It is an opt-in lab API: selecting it is
  always an explicit caller choice, and it is not covered by any release
  stability promise — names, types, and configuration shapes may change.
  The `shph-edge` crate remains a **separate standalone prototype** and is not
  a workspace member; it has its own manifest and lockfile and is not built or
  released with the SHPH workspace.
- Where behavior is described below in implementation-neutral terms ("the
  boundary requires", "the design expects"), the corresponding Rust API is not
  final.

## Retained SHPH hybrid cryptography

Phantom One does not replace, weaken, or reroute SHPH's cryptographic core:

- The end-to-end SHPH application handshake — hybrid X25519 + ML-KEM-768 key
  exchange, transcript-bound Ed25519 signatures, pinned peer policy, AEAD data
  plane — is retained unchanged. Phantom One does not modify
  `shph-core/src/crypto.rs`, `shph-core/src/keystore.rs`, or the handshake.
- The Phantom One envelope is an **authenticated-transport inner envelope**: it
  provides framing, bounded session-scoped padding, path-MTU checks, and
  replay tracking. It provides **no encryption and no authentication of its
  own**. It is only meaningful inside an already-authenticated SHPH channel,
  exactly like the Shroud 2 envelope, and it is never selected by default.
- The edge relay never sees plaintext SHPH payloads. It forwards opaque bytes
  between a carrier stream and a configured backend; it does not parse,
  decrypt, re-encrypt, or interpret SHPH traffic. Compromise of an edge relay
  must not expose session keys or payload contents — that property comes from
  the retained end-to-end SHPH cryptography, not from the relay.

## Phantom One envelope boundary

The in-tree prototype (`shph-transport/src/phantom_one.rs`) defines:

- A fixed 24-byte header: `PH1\0` marker, format version, profile identifier,
  32-bit generation, frame
  type (data, control, keepalive), 64-bit sequence, 16-bit payload length,
  16-bit target length, and reserved bytes that must be zero.
- The profile byte uses the stable mapping below. Values outside this table are
  rejected; no unknown value maps to a default:

  | ID | Profile | Base size tiers |
  | ---: | --- | --- |
  | `0` | `low` | 128, 256 bytes with bounded low-latency jitter |
  | `1` | `medium` | 128, 256, 512, 1024, 1360 bytes |
  | `2` | `high` | 512, 1024, 1360 bytes |
  | `3` | `tuned-low` | 64, 96, 128, 192, 256, 512, 768 bytes |
  | `4` | `tuned-medium` | 128, 256, 512, 768, 1024, 1360 bytes |
  | `5` | `tuned-high` | 512, 768, 1024, 1280, 1360 bytes |
- A declared target length that must equal the received datagram length and
  must not exceed the path MTU; a payload length that must fit inside the
  target; empty payloads and non-canonical reserved bytes fail closed.
- Session-scoped random tail padding bounded by configuration
  (default 0–64 bytes, hard cap 4,096 bytes). Padding is shape obfuscation
  only; it is not cryptographic padding negotiation. The CLI carries the
  selected Phantom One mode and profile in the join ticket; lower-level callers
  must select the same profile explicitly on both authenticated peers. The
  Phantom One generation is
  then derived from the authenticated transcript.
- A bounded replay window (1–64 entries, default 64) keyed by
  (generation, sequence). Replays, stale sequences, generation mismatch, and
  sequence-space exhaustion fail closed. The 64-bit sequence space never
  wraps; exhaustion returns an explicit error.
- A largest representable envelope of 65,535 bytes, constrained in practice by
  the carrying transport. For the current TCP integration, the configured
  `path_mtu` value is a logical encrypted-frame plaintext budget, not a
  physical IP/TCP path MTU and not a fragmentation mechanism.

The replay window is a duplicate-suppression mechanism inside one
authenticated session. It is not a substitute for the AEAD nonce/replay
protection of the SHPH data plane, which remains the authoritative
anti-replay boundary.

## Separate edge relay

The `shph-edge` prototype implements an **owned-domain edge relay** as a
separate deployable, deliberately outside the SHPH workspace:

- The operator must control the edge domain and its TLS material. This is an
  "owned front" model: SHPH does not provide, rent, or broker domains, and
  nothing in the relay impersonates a third-party service.
- The client-side SOCKS5 adapter is intentionally unauthenticated and is
  required to bind to loopback. It is a local underlay adapter, not a public
  proxy.
- The relay authenticates each incoming stream with a signed, short-lived
  capability (below) and otherwise forwards opaque bytes to a configured
  numeric backend socket address. It has no SHPH protocol logic.
- The HTTP/2 relay path is operator-configurable but tightly bounded. The
  default is `/phantom-one/v1`; paths must be ASCII, begin with `/`, contain no
  query, fragment, control, or backslash characters, and be at most 128 bytes.
  The client and server must use the same exact path.
- Unauthorized requests receive fixed, minimal fallback responses
  (`404 not found`, `405 method not allowed`, `401 unauthorized`). This is a
  fail-closed front door, **not** active-probe decoy routing: the relay does
  not proxy arbitrary sites, does not serve mimicked application content, and
  does not attempt to make invalid probes indistinguishable from a real
  service. No probe-resistance property is claimed.
- Relay logging is redacted by construction: structured events carry event
  kind, carrier, outcome, and byte counts only — no tokens, payloads, peer
  identifiers, or backend contents.

## HTTP/2 and HTTP/3 standards carrier boundaries

- The HTTP/2 carrier uses standards implementations (hyper over rustls
  TLS 1.3). SHPH does not implement its own HTTP/2 framing, TLS stack, or
  congestion control, and does not patch or fingerprint-tune them.
- The Phantom One TCP implementation exposes caller-owned encode buffers and the
  transport reuses one session buffer for outgoing envelopes. SHPH also
  enables `TCP_NODELAY` as a best-effort latency hint on its TCP sockets; this
  does not alter the carrier fingerprint or provide a stealth property.
- Relay streams are carried as `POST` requests to the configured relay path
  (default `/phantom-one/v1`) with `application/octet-stream` bodies. Any request
  outside that path and method, or without a valid capability, fails closed to
  the fixed fallback responses.
  Bounded concurrent streams, a bounded HTTP/2 connection pool, a connection
  semaphore, an application-idle connection deadline, per-stream byte caps,
  and a bounded backend-connect timeout limit resource use. The idle deadline
  refreshes on application stream activity and does not close active streams;
  its default is 30 seconds. Pooling reuses the standards HTTP/2/TLS connection
  only; it does not reuse a capability token.
- The HTTP/3 carrier is **feature-gated and opt-in**. The standalone edge
  crate now contains a standards-library implementation using Quinn, rustls,
  `h3`, and `h3-quinn`, with bounded request/response handling, capability
  verification, replay checks, and coordinated shutdown. It requires
  operator-owned TLS material and is still experimental: no live two-host
  HTTP/3 evidence is recorded, and the `h3` dependency remains an explicitly
  opt-in upstream API. The CLI refuses it when the feature is not compiled.
- Carrier bytes are opaque SHPH payloads inside standards HTTP/TLS. The design
  does not claim that carrier traffic is indistinguishable from any particular
  real application, browser, or CDN behavior. See "Explicit non-claims".

## Signed short-lived capabilities

Edge access is authorized by a bearer capability token, not by SHPH identity
keys:

- Format: `phantom-one.1.<base64url payload>.<base64url Ed25519 signature>`. The
  payload carries an audience string, issued-at, expires-at, and a 128-bit
  random nonce. The signature is computed over a domain-separated input
  (`SHPH-EDGE-CAPABILITY/PHANTOM-ONE/1`) so these tokens cannot be confused with SHPH
  handshake signatures or any other Ed25519 context.
- Verification is fail-closed on every axis: malformed structure, bad
  signature, audience mismatch, not-yet-valid, expired, excessive lifetime,
  and nonce replay are all rejected with the same externally visible
  `401 unauthorized` fallback (distinct error variants exist internally for
  diagnostics but are not leaked to the requester).
- Lifetimes are short: the default maximum is 300 seconds, and configuration
  rejects any bound above 3,600 seconds. Clock skew tolerance is bounded
  (default 5 seconds, maximum 300 seconds).
- Replay suppression uses a bounded nonce cache (default capacity 131,072;
  configurable between 1 and 1,000,000) that prunes expired entries and fails
  closed when full; it does not evict live nonces. The cache is in-memory and
  per edge process, so restarts and separate replicas do not share replay
  state. It is not a distributed revocation system.
- The standalone edge client accepts either one token or a bounded
  newline-delimited token bundle. Each non-empty line is an independent,
  one-use capability for one logical relay stream. This preserves nonce
  replay protection while allowing the HTTP/2 pool to multiplex streams when
  the operator has deliberately issued multiple capabilities.
- Capabilities authorize edge relay use only. They do not authenticate the
  SHPH session behind the relay, do not replace peer pinning, and are not a
  general authorization framework. Issuance, distribution, and rotation of the
  Ed25519 issuer key are operator responsibilities outside the current
  prototype's scope.

## Security invariants

The following invariants define the Phantom One public boundary. Tests and evidence
for them are scoped in `docs/PHANTOM_ONE_TESTING.md`.

1. **Fail-closed parsing.** Every malformed, truncated, oversized,
   non-canonical, wrong-version, or wrong-generation input is rejected; no
   partial frame is ever delivered to the application.
2. **Path-limit authority.** The carrying transport's configured logical frame
   budget is the only accepted size bound; envelopes never exceed it, and Phantom One
   never fragments a TCP frame or treats a logical TCP budget as a physical
   path-MTU measurement.
3. **Bounded resources.** Padding bounds, replay-window size, token size,
   stream byte counts, connection counts, concurrent streams, and replay-cache
   capacity are all explicitly bounded and validated; there are no unbounded
   allocations, sleeps, or retry loops at the Phantom One or edge boundary.
4. **No silent wraparound.** Sequence-space exhaustion is an explicit error,
   not a wrap.
5. **Opaque relay.** The edge relay holds no SHPH key material and cannot
   read, alter, or inject payload bytes; it only forwards.
6. **Redacted observability.** Edge logs contain metadata classes only;
   capability tokens and payload bytes are never logged.
7. **Opt-in isolation.** Phantom One framing and the edge relay activate only on
   explicit selection; default paths are byte-for-byte unchanged.
8. **No crypto novelty.** Phantom One introduces no new cryptographic primitives at
   the transport layer; the only signature added is the domain-separated
   Ed25519 capability, and the end-to-end session remains protected by the
   retained SHPH hybrid handshake and AEAD data plane.

## Explicit non-claims

Phantom One does **not** claim, and documentation, benchmarks, and demos must
not imply, any of the following:

- **DPI evasion or censorship resistance.** Phantom One padding and the HTTP carrier
  are shape and transport choices, not evasion guarantees. No measurement
  establishes resistance to any specific classifier, censor, or active prober.
- **Anonymity.** The owned-domain edge is attributable infrastructure. Phantom One
  provides no sender, receiver, or network-level anonymity property; it is not
  comparable to anonymity networks and must not be described as one.
- **Browser or client fingerprint parity.** SHPH does not forge ClientHello
  extension order, JA4/JA3 values, HTTP/2 settings, header ordering, or any
  browser fingerprint, and does not claim parity with any browser's network
  behavior. The existing passive JA4 observability plugin
  (`docs/JA4_OBSERVABILITY.md`) is unchanged: it observes, it does not spoof.
- **Active-probe deflection.** The edge fallback responses are minimal fixed
  errors, not a decoy service. No claim is made that probing the edge is
  indistinguishable from probing any real website.
- **Production readiness.** Phantom One framing is an opt-in lab API with no
  stability promise, the edge relay is an out-of-workspace prototype, HTTP/3
  is unavailable, and no multi-host, hostile-network, or long-duration
  evidence exists. Phantom One is a lab prototype under the same evidence
  discipline as the rest of SHPH.
- **Traffic-analysis resistance.** Padding bounds are configuration
  parameters; no distance metric, threshold, or resistance claim is attached.

Any future claim beyond this list requires dated, reproducible evidence filed
under `docs/evidence/` with recorded commit, toolchain, platform, and method —
consistent with `docs/SECURITY_EVIDENCE.md` and `docs/REPRODUCIBILITY.md`.
