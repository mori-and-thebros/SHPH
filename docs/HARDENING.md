# SHPH Hardening Summary

This document consolidates the security-hardening work done *after* the
funding-readiness track (Phases A + B). It is the Optional/Research hardening
track from `ROADMAP_OSS_AND_DELIVERY.md`: concrete, tested, verifiable
defenses rather than research-grade features.

Every increment here:
- addresses a concrete weakness or boundary,
- records focused regression coverage where practical,
- states its validation and host-evidence limits explicitly,
- is captured in `CHANGELOG.md`.

The reviewable threat-to-control map and publication checklist are maintained
in `docs/SECURITY_EVIDENCE.md`. Native host and two-node evidence remains a
separate release gate; source-level hardening and local tests must not be
presented as proof of a live VPN deployment.

## Increment 1 — Crypto data-plane (`hardening-1`)

File: `shph-core/src/crypto.rs`.

- **Anti-replay window correctness.** `ReplayWindow` was a `HashSet` that
  cleared the entire set when it filled, so after every `size` packets a
  previously-seen nonce became acceptable again. Replaced with a sliding bitmap
  window over the 64-bit counter space; on every advance the previous-highest
  nonce is recorded as seen so it cannot be replayed.
- **Nonce-reuse prevention.** `SendCipher` now fails closed at
  `AEAD_NONCE_LIMIT` (`2^32 - 1`) instead of letting the 64-bit counter wrap to
  0 and reuse a nonce (a catastrophic ChaCha20-Poly1305 break). The session
  must rekey.
- **Timing-safe verification.** Handshake signature compare now uses a
  constant-time equality check instead of `!=`, removing a timing oracle on how
  much of the digest matched.

Tests: 8 new (replay-window boundary, replay-after-many-advances, nonce-limit
fail-closed, constant-time semantics). `shph-core` 19 -> 27.

## Increment 2 — Keystore secret hygiene (`hardening-2`)

File: `shph-core/src/keystore.rs`.

- **Owner-only file perms.** The keystore (holding the X25519 private key) is
  now written mode `0600` on Unix instead of the umask default (often
  world-readable `0644`).
- **Leaky-file refusal.** `load` rejects a group/other-accessible keystore,
  failing closed rather than silently using a leaked key.
- **Bounded load.** Capped at 1 MiB (`MAX_KEYSTORE_BYTES`) + UTF-8 enforced, so
  a hostile/giant file cannot force a large allocation.
- **Atomic save.** Write to temp + fsync + rename — a crash mid-write can no
  longer leave a truncated/corrupt key file.

Tests: 5 new (roundtrip, 0600, leaky-file refusal, oversized rejection, no
leftover temp files). `shph-core` 27 -> 32.

## Increment 3 — Transport DoS + cleanup (`hardening-3`)

File: `shph-transport/src/lib.rs`.

- **Per-peer connection-rate limiting.** The TCP accept entry path enforces a
  per-source-IP cap (8 connects per 10s) before any handshake work. The accept
  path is deadline-bounded and keeps listening after malformed peers instead of
  terminating after a fixed lifetime attempt count.
- **Anti-slowloris hello read.** `read_tcp_hello` reads 1 KiB chunks into a
  bounded buffer instead of one syscall per byte; same `MAX_HELLO_BYTES` cap.

Cleanup: removed the orphaned, never-compiled root `src/crypto.rs` +
`src/error.rs`.

Tests: 3 new `PeerRateLimiter` tests (under-cap allow, per-IP-not-port keying,
distinct-IP isolation). `shph-transport` 1 -> 4.

## Threat-table impact

| Threat | Before hardening | After hardening |
| ------ | ---------------- | --------------- |
| Replay across window-clear boundary | Vulnerable (set cleared) | Sliding window (fixed) |
| AEAD nonce reuse via counter wrap | Possible (catastrophic) | Fail-closed at limit |
| Signature-verify timing oracle | `!=` compare | Constant-time |
| Private key world-readable at rest | umask default (~0644) | Owner-only (0600) |
| Handshake-flood from one host | Per-loop bound only | + per-IP rate limit |
| Slowloris per-byte hello cost | 1 syscall/byte | Chunked bounded read |

## Increment 4 — Hybrid post-quantum exchange + QUIC shim hardening (v0.4.0)

Files: `shph-core/src/pqc.rs` (new), `shph-core/src/handshake.rs`,
`shph-transport/src/lib.rs`.

- **Hybrid PQECDH (ML-KEM-768).** The handshake now performs a full ML-KEM-768
  encapsulation/decapsulation alongside X25519 ECDH; the session key is HKDF-
  derived from both shared secrets, so a future quantum adversary that breaks
  ECDH cannot decrypt recorded sessions ("harvest now, decrypt later").
- **Downgrade resistance.** `HandshakeMaterial.pq_shared` is `None` until the
  PQ round-trip completes; `verify_and_derive` fails closed on `None`, so a peer
  that strips the PQ ciphertext can never silently negotiate classical-only.
- **PQ transcript binding.** The ML-KEM public key is included in the
  Ed25519-signed transcript, and the exact exchanged ML-KEM ciphertext is
  included in the HKDF transcript, so a MITM cannot swap the key material or
  make peers derive keys for different encapsulation exchanges without a
  transcript mismatch.
- **Bounded PQ transport.** The ML-KEM ciphertext is exchanged as a size-bounded
  follow-up frame (TCP: length-prefixed exactly `ML_KEM_768_CIPHERTEXT_BYTES`;
  UDP: a single fixed-size datagram; offline/data-mule: a bounded payload).
- **QUIC source-address binding.** Post-handshake data-frame datagrams are
  rejected unless they arrive from the authenticated peer address, closing an
  off-path injection/amplification surface.
- **QUIC per-IP rate limiting** (parity with TCP accept path).

## Increment 6 — Audit remediation and adapter hardening

Files: `shph-cli/src/main.rs`, `shph-core/src/crypto.rs`,
`shph-core/src/net.rs`, `shph-core/src/roadmap.rs`,
`shph-config/src/lib.rs`, `shph-transport/src/lib.rs`.

- **Configured peer pinning.** CLI sessions now reject authenticated identities
  that are not present in the local keystore contact allowlist. The pinned
  X25519 identity and Ed25519 handshake-signing key must both match. Outbound
  sessions must also match the configured endpoint.
- **Mandatory peer policy.** Empty contact stores no longer disable the
  allowlist; sessions fail closed until the expected peer is registered.
- **Cross-platform graceful shutdown.** Unix signal handlers and Windows
  `SetConsoleCtrlHandler` callbacks feed the same cleanup-aware shutdown flag.
- **Persistent control-plane lifecycle.** `apply`, `reconcile`, `undo`, and
  `down` use an exact persisted state record so cleanup survives process
  boundaries and repeated operator commands are predictable.
- **Authenticated replay-state advancement.** Receive nonce state advances only
  after AEAD verification succeeds, preventing an unauthenticated high-nonce
  packet from permanently desynchronizing a session.
- **File-adapter confinement and bounds.** Data-mule peer/envelope path
  components are sanitized, configured file limits are capped at 256 KiB, and
  recursive inbox scanning uses bounded reads.
- **Safer config persistence.** Config writes are fsynced, owner-only on Unix,
  and replaced through a temporary file instead of direct truncating writes.
- **Endpoint parsing.** IPv6 bracket notation is accepted and zero/empty
  endpoints are rejected.
- **Bounded address fallback.** TCP hostname connection attempts try each
  resolved address under one overall deadline.
- **Keystore loading.** Unix final-component symlinks are refused and
  encrypted PBKDF2 iteration counts are bounded before key derivation.
- **Audit-journal loading.** Unix audit-journal reads and appends refuse a
  replaced final-component symlink.
- **Handshake time budgets.** TCP and QUIC handshake retries share one overall
  deadline rather than multiplying the configured timeout per attempt.

Regression tests cover the nonce-advance attack, path confinement, excessive
file limits, and the existing UDP-permission test skip behavior.
- **QUIC datagram truncation guard** — a hello filling the receive buffer is
  rejected rather than parsed as a truncated message.

## Increment 7 — Roadmap primitive hardening

- Roadmap validation rejects empty audit paths, zero retention, and unavailable
  hardware identity providers instead of accepting configuration that cannot run.
- Shamir recovery rejects duplicate, out-of-policy, and non-field share values;
  CLI recovery accepts individual share JSON objects or arrays.
- Ratchet audit reads fail closed on malformed journal entries, writes owner-only
  files with fsync, and prunes through an atomic replacement.
- Successful CLI handshakes record peer/transcript audit events after pinning.

## Increment 8 — Lab-grade QUIC-shim, Shroud cells, and keystore encryption

- The existing UDP transport remains explicitly a QUIC-like lab shim, but now
  has a real round-trip test using fixed-size Shroud cells.
- `SHPH_SHROUD_PROFILE=balanced|low-latency|bulk` wraps authenticated UDP-shim
  frames in the selected fixed-size cell profile for lab experiments.
- `SHPH_SHROUD_PROFILE=randomized-lab` additionally uses authenticated,
  randomized inner padding inside fixed-size cells. This is a measurement and
  framing experiment, not a claim of traffic-analysis resistance.
- `SHPH_KEYSTORE_PASSWORD` enables password-encrypted keystore persistence using
  PBKDF2-HMAC-SHA256 and ChaCha20-Poly1305; legacy plaintext keystores remain
  loadable for migration.
- These features do not claim standards-compliant QUIC, TLS fingerprint
  mimicry, or anti-censorship effectiveness.

Tests: 4 new PQ regression tests (hybrid roundtrip, downgrade-blocked, corrupted
ciphertext breaks agreement, classical-only cannot derive) + 1 QUIC
foreign-source rejection test.

Known limitation: the current hybrid exchange does not yet include an explicit
post-KEM key-confirmation message. A modified ML-KEM ciphertext produces
divergent keys that fail closed at the first authenticated data-plane frame,
rather than being rejected during the handshake itself. Correcting that
requires a protocol compatibility change across every transport and is tracked
as future hardening rather than overstated as solved here.

## Increment 10 — Standards QUIC and Shroud boundary hardening

Files: `shph-transport/src/standards_quic.rs`,
`shph-transport/src/shroud2/mod.rs`.

- **Fail-closed idle-timeout bounds.** Standards QUIC now rejects zero,
  sub-second, and greater-than-24-hour idle timeouts. This prevents accidental
  session churn from an ultra-short timeout and avoids an unbounded lifetime
  configuration.
- **Morphology envelope validation.** The Shroud 2.0 lab envelope rejects
  inconsistent declared total lengths, impossible payload lengths, payloads
  that cannot fit the two-byte length field, invalid negotiated path limits,
  and targets below the fixed seven-byte header plus payload.
- **Fallible padding randomness.** OS randomness failure returns a crypto error
  instead of allowing a panic or predictable padding output.
- **Standards QUIC API coverage.** Loopback tests cover the authenticated
  handshake, reliable control stream, raw DATAGRAM path, and opt-in
  morphology DATAGRAM path.

Validation: workspace formatting, Clippy with `-D warnings`, all workspace
tests, locked workspace build, fuzz-manifest checks, benchmark checks, and the
release-mode Shroud validation rerun all pass. Native TUN remains
host-capability and two-host-evidence gated.

## Increment 9 — Lab prototype operational hardening

The alternate transports now behave as bounded, repeatable lab adapters rather
than placeholder queues:

- Offline-mesh validates the session identifier, bounds queue scans, quarantines
  malformed/oversized files, and acknowledges envelopes only after successful
  authenticated consumption.
- Data-mule uses unique temporary filenames, bounded recursive scans, symlink
  avoidance, quarantine for poison files, stable envelope replay identity, and
  post-authentication file removal.
- Offline-mesh configuration now bounds `max_idle_entries` to a practical
  replay-cache range.
- `docs/LAB_PROTOTYPES.md` documents setup, replication/courier workflows,
  failure behavior, and explicit non-claims.

## Threat-table impact (increment 4)

| Threat | Before | After |
| ------ | ------ | ----- |
| Harvest-now-decrypt-later (future quantum breaks ECDH) | Vulnerable | Hybrid ML-KEM-768 mitigates |
| Silent classical downgrade (PQ stripped) | N/A | Fails closed |
| Off-path QUIC frame injection | Accepted from any source | Source-address bound |
| QUIC handshake flood from one host | No per-IP limit | Per-IP rate limited |
| Truncated UDP hello parsing | Possible | Rejected |

## Increment 5 — Secret-material zeroization on drop (`hardening-5`)

Files: `shph-core/src/crypto.rs`, `shph-core/src/handshake.rs`.

- **Session AEAD keys wiped on drop.** `SendCipher` and `ReceiveCipher` hold the
  32-byte ChaCha20-Poly1305 session key in plain heap memory. Previously it
  survived until the allocator reused the page; now both implement `Drop` to
  `zeroize` the key the instant the cipher is discarded. This closes core-dump,
  swap, and memory-disclosure exposure of *live traffic keys* after a session
  ends.
- **`SessionKeys` derived from `ZeroizeOnDrop`.** The `send_key` / `recv_key`
  arrays are now zeroized on drop via the `zeroize` derive (nonces are skipped —
  they are not secret).
- **Identity signing-seed hygiene.** `IdentityKeyPair.sign_seed` (the raw 32-byte
  Ed25519 seed) is now wiped in both `Zeroize` and `Drop`. The X25519
  `StaticSecret` already self-zeroizes; the raw Ed25519 seed previously did not.
- **HKDF intermediate zeroization.** The raw 32-byte HKDF outputs in
  `verify_and_derive` are wrapped in `Zeroizing<Vec<u8>>` so the key material is
  wiped once it has been copied into the session keys, rather than lingering in
  a freed heap buffer.

This is a defense-in-depth / secret-hygiene hardening: it does not change any
wire format or public API, so it is non-breaking. The `zeroize` crate (with the
`derive` feature) was already a direct `shph-core` dependency, so no new
dependency was introduced.

Tests: 4 new regression tests proving the key bytes are wiped after drop
(`send_cipher_zeroizes_key_on_drop`, `receive_cipher_zeroizes_key_on_drop`,
`session_keys_zeroizes_on_drop`, `identity_keypair_zeroizes_sign_seed_on_drop`).
`shph-core` unit tests 35 -> 39.

## Threat-table impact (increment 5)

| Threat | Before | After |
| ------ | ------ | ----- |
| Session AEAD key recoverable from freed memory / core dump | Yes (plain bytes) | Zeroized on drop |
| `SessionKeys` retained after session end | Yes | Zeroized on drop |
| Ed25519 signing seed retained after identity drop | Yes (raw array) | Zeroized on drop |
| HKDF raw output retained in heap | Yes | `Zeroizing` wiped after copy |

## What this is NOT

These are hardening of the existing design, not new anti-observation
capabilities. Per `SECURITY.md`, SHPH still does **not** claim: browser/TLS/QUIC
fingerprint parity, DPI evasion, constant-time guarantees beyond the crypto
crates, or hostile-network adversarial posture. Those remain research-track
items (`ROADMAP_OSS_AND_DELIVERY.md`).

## Increment 10 — TUN and UDP-shim boundary hardening

The working tree adds explicit resource and packet-boundary controls for the
highest-priority lab risks:

- `shph-tun` caps packets at 65,535 bytes, rejects oversized read buffers, and
  validates IPv4/IPv6 version and length fields before TUN injection or
  transport submission. IPv6 jumbo packets are intentionally unsupported.
- The native CLI loop reads one byte beyond the maximum IP packet size so a
  full buffer cannot hide truncation or oversize input.
- QUIC-like UDP handshake timeouts are capped at five minutes, malformed
  handshake datagrams are budgeted, and the per-source rate-limit table is
  capped at 1,024 active IP entries with stale-entry pruning.
- QUIC-like data receive filters foreign-source, malformed, truncated, and
  unauthenticated/replayed datagrams in a bounded loop instead of immediately
  desynchronizing the session.
- Metrics expose malformed packets, replay drops, timeouts, and oversized
  packets separately from generic errors.
- Windows native-TUN selection now fails explicitly instead of silently
  falling back to the developer stub. This prevents a configured tunnel from
  appearing active while forwarding no packets.
- DNS control-plane application preserves all configured servers: Linux uses a
  single `resolvectl` update and Windows emits primary/secondary `netsh`
  commands by address family.
- TCP unauthenticated entry now has both a five-attempt bound and a hard
  aggregate 60-second accept/handshake deadline.

These changes do not turn the UDP shim into standards-compliant QUIC. Loss
recovery, congestion control, stream multiplexing, authenticated close/error
signaling, and interoperability remain open roadmap items.

## Increment 11 — Queue, persistence, and input-boundary bug fixes

- Data-Mule responder handshakes now commit the consumed peer hello before
  waiting for the PQ ciphertext; the hello cannot be selected repeatedly.
- Offline-mesh and Data-Mule polling quarantine malformed base64 candidates and
  continue scanning for a later valid envelope.
- File-adapter reads refuse final-component symlinks on Unix, and atomic
  envelope writes use exclusive temp creation instead of truncatable names.
- TCP connect setup uses `connect_timeout`, so endpoint connection
  establishment is bounded by the configured timeout.
- Unix stdin session mode preserves multiple lines received in one read and
  rejects lines above 64 KiB rather than growing without a bound.
- Config replacement uses unique exclusive temp files, removes failed temps,
  and syncs the containing directory after rename on Unix.

Regression coverage includes malformed-candidate continuation, symlink refusal,
config temp-file symlink resistance, and the existing transport handshake/data
plane suites.

## Increment 12 — Configuration and quarantine hardening

- Configuration loading refuses final-component symlinks on Unix, caps input
  at 1 MiB, and rejects non-UTF-8 contents before TOML parsing.
- File-adapter quarantine names are collision-safe, preserving earlier
  rejected evidence instead of overwriting it.

Regression coverage includes oversized-config rejection, Unix config symlink
refusal, and quarantine collision preservation.

## Increment 13 — Shared Shamir API resource bounds

File: `shph-core/src/roadmap.rs`.

- **Bounded split input.** The public `split_secret` API rejects secrets larger
  than 128 KiB before allocating one row per configured share. CLI callers
  remain stricter at 64 KiB.
- **Canonical share payload cap.** Shamir decoding enforces the 256 KiB raw
  payload limit after base64 decoding as well as before allocation.
- **Bounded recovery work.** Recovery rejects more shares than the configured
  policy allows and caps aggregate decoded share material at 8 MiB.
- **Regression coverage.** Tests cover oversized split input, excessive share
  counts, and decoded payloads above the raw limit.

This closes a library-level resource-exhaustion gap that CLI-only input limits
did not cover. It does not make Shamir a production KMS or provide hardware
custody.

## Increment 14 — Native Linux TUN lifecycle

Files: `shph-tun/src/lib.rs`, `shph-cli/src/main.rs`.

- Added an explicit `TunDevice::open_native` path so native capability checks
  are testable without mutating process-wide environment variables.
- Fixed the `up` lifecycle so the validated Linux TUN file descriptor remains
  open while routes/DNS are applied and while session reconnect attempts run.
  The prior probe/drop/reopen sequence could destroy a non-persistent TUN
  interface before the data-plane loop started.
- Added capability-gated Linux native-open regression coverage and retained
  explicit Windows fail-closed behavior until Wintun is provisioned.

This validates the Linux implementation boundary; it does not claim
privileged-host, two-node routing, or Windows Wintun evidence.

## Increment 15 — Native TUN packet-boundary hardening

Files: `shph-tun/src/lib.rs`, `shph-cli/src/main.rs`,
`docs/NATIVE_TUN_STATUS_2026-08-04.md`.

- Native Linux writes now require one complete kernel write. A short write is
  returned as a TUN error instead of being retried as though it were a second
  packet fragment.
- The native bridge uses zeroizing packet buffers for plaintext ingress and
  egress data.
- Regression coverage now includes complete-write, short-write, and
  would-block classification.

Validation: `cargo fmt --all -- --check`, workspace Clippy with warnings as
errors, all workspace tests, and the locked workspace build pass. The
remaining native-TUN limitations are recorded in the dated status note.

## Increment 16 — Async and Windows native-TUN boundary hardening

Files: `shph-tun/src/lib.rs`, `shph-tun/src/windows.rs`,
`shph-tun/examples/native_tun_probe.rs`, and `scripts/`.

- Added a Linux `AsyncTunDevice` using Tokio `AsyncFd` readiness with the same
  MTU, IP-header, and complete-write validation as the synchronous API.
- Added an isolated namespace smoke test and lifecycle benchmark. They report
  capability failures as `SKIP` and never synthesize throughput or routing
  evidence.
- Added Windows Wintun receive/release and allocate/send wrappers with bounded
  packet sizes, zeroizing receive copies, ring-capacity validation, signed
  application-local DLL loading, administrator checks, and explicit unsafe
  contracts.
- Kept `TunDevice::open_native` fail-closed on Windows until the scaffold is
  integrated into the public backend and verified on an elevated Windows host.

The focused `shph-tun` suite had 10 passing tests at this increment. It did not
claim Windows packet I/O, native Linux saturation, or a completed async CLI
bridge.

## Increment 17 — Linux async native-TUN CLI integration

Files: `shph-cli/src/main.rs`, `shph-tun/src/lib.rs`,
`docs/NATIVE_TUN_STATUS_2026-08-04.md`.

- Integrated Linux `AsyncTunDevice` into the native `up` data plane.
- Added bounded 32-packet queues between async TUN I/O and blocking transport
  workers, preventing unbounded plaintext buffering under backpressure.
- Propagated transport and TUN failures, treated EOF as connection closure,
  observed process shutdown while waiting for packets, and retained zeroizing
  packet ownership through queues and workers.
- Added deterministic async tests for valid packet delivery, malformed packet
  rejection, EOF, and refusal to promote a stub backend.

The Linux CLI bridge is now implemented, but privileged two-host forwarding,
throughput, latency-under-load, reconnect timing, and Windows Wintun runtime
operation remain host-gated evidence requirements.

## Increment 18 — Windows Wintun public-backend wiring

Files: `shph-tun/src/lib.rs`, `shph-tun/src/windows.rs`,
`shph-cli/src/main.rs`.

- Connected the Wintun runtime to `TunDevice::open_native`, `try_clone`,
  `is_native`, `recv_packet`, and `send_packet`.
- Added bounded `WaitForSingleObject` waits for empty receive rings and shared
  one synchronized Wintun session across the Windows directional workers.
- Added a Windows synchronous native bridge while retaining the Linux
  `AsyncFd` bridge as the preferred Linux path.
- Preserved zero-silent-fallback behavior: missing DLLs, insufficient
  elevation, invalid handles, ring exhaustion, and packet validation failures
  return explicit errors.

The source backend is wired, but Windows runtime, signed-DLL provenance,
privileged adapter lifecycle, and two-host packet evidence remain unverified in
this Linux/WSL2 environment.

## Increment 19 — Standards-QUIC replay-safe TLS defaults

Files: `shph-transport/src/standards_quic.rs`,
`docs/QUIC_STANDARDS.md`, `docs/JA4_OBSERVABILITY.md`.

- Replaced Quinn's convenience TLS constructors on the standards path with
  explicit rustls builders using the same ring provider.
- Disabled TLS 1.3 early data (0-RTT) on both client and server endpoints.
  SHPH's signed application handshake and datagram data plane now begin only
  after the normal authenticated handshake, avoiding a replayable early-data
  entry path.
- Added a regression test that inspects both actual rustls configurations and
  asserts `max_early_data_size == 0` and `enable_early_data == false`.

This does not claim replay resistance for every future application protocol
layer; it closes the standards-QUIC endpoint's 0-RTT configuration path.

The same pass also bounds opt-in SNI recording to 255 UTF-8 bytes and makes the
Linux standards-TUN bridge reject oversized datagrams before copying them.
Its malformed-datagram close budget is capped at 4,096 entries.

Native TUN reads and writes also retry interrupted syscalls, treat native EOF
as connection closure, and wipe rejected packet bytes in caller-provided read
buffers.

## Increment 20 — Pre-audit native-TUN boundary hardening

Files: `shph-tun/src/lib.rs`, `shph-tun/src/windows.rs`,
`shph-transport/src/standards_tun.rs`, `docs/NATIVE_TUN_STATUS_2026-08-04.md`,
and `docs/TESTING.md`.

- Linux native TUN opens now use `O_CLOEXEC | O_NOFOLLOW`, request
  `IFF_TUN_EXCL`, and type-check the already-open descriptor. This prevents
  descriptor inheritance, avoids symlink traversal, refuses accidental
  attachment to an existing interface, and removes the prior path-metadata
  check window.
- Synchronous and asynchronous receive paths clear the complete caller buffer
  before each attempt and on terminal errors. This prevents stale plaintext
  from surviving EOF, malformed packets, oversized reads, I/O failures, or
  undersized Windows receive buffers.
- Windows adapter names are bounded by UTF-16 code units and reject control
  characters before crossing the Wintun wide-string FFI boundary.
- Empty packet writes now fail consistently across synchronous, asynchronous,
  and Windows backends instead of being silently treated as successful no-ops.
- Standards-QUIC bridge read and datagram-send failures now explicitly close
  the connection before returning the transport error.
- Regression coverage asserts the Linux open flags, valid-packet tail wiping,
  stale-buffer wiping on malformed/EOF reads, and existing fail-closed
  lifecycle behavior.

This is source-level hardening. Native Linux two-host forwarding and Windows
Wintun runtime evidence remain host-gated.

## Increment 21 — security audit remediation

Files: `shph-core/src/handshake.rs`, `shph-transport/src/lib.rs`,
`shph-transport/src/standards_quic.rs`, `shph-tun/src/windows.rs`,
`shph-core/src/keystore.rs`, `.github/workflows/ci.yml`.

- Responder-side ML-KEM decapsulation now requires the complete peer hello,
  valid Ed25519 signature, and matching `PeerPolicy` before any decapsulation
  work. This closes the file-adapter responder ordering gap as well as the
  equivalent low-level transport boundary.
- The bounded per-IP limiter evicts the oldest source when its table is full,
  so distributed source churn cannot permanently reject every new source.
- Wintun loading now requires `SHPH_WINTUN_SHA256` to contain the expected
  SHA-256 of the application-local `wintun.dll`. The loader rejects missing,
  malformed, oversized, or mismatched files before `LoadLibraryExW`.
- Keystore JSON staging, encrypted staging, and password-bearing configuration
  holders are zeroized on drop. Serialization necessarily creates transient
  plaintext strings/arrays; those copies are bounded and documented rather
  than represented as a production guarantee.

## Increment 22 — Native validation and reconnect hardening

Files: `shph-cli/src/main.rs`, `shph-transport/src/lib.rs`,
`scripts/validate_linux_two_host.sh`,
`docs/NATIVE_LINUX_TWO_HOST_VALIDATION.md`.

- **Reconnect failures are retryable.** Linux and Windows native bridge paths
  now propagate an unexpected remote connection close to the configured
  reconnect loop. Only an operator-requested local shutdown completes cleanly,
  so controlled reconnect evidence actually exercises a new session.
- **Stateful public TCP helpers.** `tcp_secure_send` and
  `tcp_secure_receive` require caller-owned `SendCipher` / `ReceiveCipher`
  state. Recreating a cipher per call would reset its AEAD nonce and permit
  nonce reuse under one session key; a regression test sends two frames with
  one stateful cipher.
- **Evidence boundaries fail closed.** The native Linux two-host script rejects
  WSL and detected containers, explicitly selects TCP for the `AsyncTunDevice`
  bridge gate, confirms `iperf3` server readiness, and samples SHPH CPU from
  `/proc/<pid>/stat` deltas rather than process-lifetime `ps` averages.
- **No standards-QUIC overclaim.** The two-host guide describes the current
  validation scope as TCP native-TUN evidence. Standards-QUIC remains a
  separate opt-in path whose production certificate workflow and host evidence
  are still incomplete.
- CI now executes a smoke iteration for every fuzz target, including
  `shroud2_datagram`.

Native Windows execution is still required to validate the Wintun DLL hash,
signed-loader behavior, adapter lifecycle, and packet I/O on a supported
elevated host.

## Increment 23 — Pre-authentication cookies, deterministic roles, and CDF lab sampling

Files: `shph-core/src/cookie.rs`, `shph-core/src/handshake.rs`,
`shph-transport/src/lib.rs`, `shph-transport/src/shroud2/mod.rs`.

- **Stateless TCP cookie challenge.** Once a source reaches the existing
  per-IP handshake pressure threshold, the responder issues a rotating
  HMAC-SHA256 cookie bound to the observed source IP and port. The cookie must
  be echoed before the responder generates its ML-KEM keypair or accepts the
  ciphertext, and no client-specific cookie state is retained.
- **Deterministic peer-ID tie-break.** `shph-core` exposes a complementary
  lexicographic role decision from the authenticated X25519 peer IDs for
  simultaneous-open orchestration. Connected one-sided sessions retain their
  socket's initiator/responder role as the authoritative key direction.
- **Explicit empirical-CDF morphology input.** The Shroud 2.0 lab engine can
  now sample bounded outer sizes from a caller-supplied normalized histogram.
  The negotiated path limit and payload-envelope minimum remain authoritative;
  this is a measurement primitive, not a browser-mimicry or DPI-evasion claim.

Regression coverage includes cookie rotation/address binding, bounded TCP
challenge framing, pressure-threshold selection, deterministic role
complementarity, histogram-backed morphology bounds, and MTU command
validation. Native firewall execution and privileged two-host evidence remain
platform-gated.

## Increment 24 — Opt-in host leak containment and transcript framing

Files: `shph-cli/src/main.rs`, `shph-tun/src/firewall.rs`,
`shph-tun/src/windows_firewall.rs`, `shph-core/src/handshake.rs`.

- **Linux host killswitch.** `shph up --killswitch` installs a dedicated,
  persistent `inet shph_killswitch` nftables output policy before native TUN
  setup. It permits loopback, the named TUN interface, and only literal
  configured peer IP/port endpoints for the selected TCP/UDP transport.
- **Windows host killswitch.** The same opt-in path installs persistent
  Windows Filtering Platform outbound ALE authorization filters. The policy
  requires elevation, allows loopback/TUN/peer tuples, and removes stale
  SHPH-owned filter keys before reinstallation. `shph down` also attempts
  stale-policy cleanup after control-plane rollback.
- **MSS clamp lifecycle.** `shph up --mss-clamp` installs a separate
  `inet shph_mss_clamp` nftables table with bidirectional TCP SYN
  `rt mtu` MSS rewriting on Linux. Windows fails explicitly because WFP
  filtering does not provide a safe declarative TCP-option rewrite in this
  implementation.
- **Canonical transcript framing.** The signed handshake transcript now uses
  explicit field labels and length prefixes, canonical peer ordering, the
  negotiated profile, the initiator identity, all hybrid public values, and
  the optional KEM ciphertext. This prevents concatenation ambiguity while
  preserving the existing connected socket key-direction contract.
- **Exception-safe session rollback.** Native `up` session failures are
  captured before cleanup, so control-plane state, MSS rules, and killswitch
  state are unwound together on transport errors and early returns.

The firewall paths are opt-in and command-argument bounded. Dry-run mode only
prints the Linux plan or Windows policy summary and does not require native TUN
or elevation. This source-level change does not claim that privileged
nftables/WFP mutation, crash-leak testing, Windows Wintun packet I/O, or
two-host forwarding has been executed on the current development host.

## Increment 25 — bounded untrusted inputs and aggregate handshake deadlines

Date: 2026-08-15

Files: `shph-core/src/crypto.rs`, `shph-core/src/handshake.rs`,
`shph-core/src/keystore.rs`, `shph-core/src/net.rs`,
`shph-core/src/roadmap.rs`, `shph-config/src/lib.rs`,
`shph-transport/src/lib.rs`, `shph-identity/src/lib.rs`, and
`shph-cli/src/main.rs`.

- **Replay-state resource bound.** `ReplayWindow::new` clamps caller/config
  input to 64–65,536 nonce positions before allocating or cloning the bitmap.
  A large untrusted value can no longer create an unbounded receive-side
  allocation/copy cost.
- **Special-file refusal.** Keystore, configuration, audit, identity-provider,
  file-adapter, control-plane, certificate, and secret-input readers now open
  Unix paths with `O_NOFOLLOW | O_NONBLOCK` where applicable and verify the
  opened object is a regular file. The equivalent Windows paths perform the
  regular-file check after reparse-point validation. FIFOs, devices, and other
  unsupported special files therefore fail closed instead of being accepted as
  ordinary bounded documents.
- **Handshake deadline is aggregate.** TCP connect, hello/cookie exchange, and
  the fixed-size ML-KEM ciphertext frame share one deadline capped at 60
  seconds. The line reader consumes exactly one byte at a time so a pipelined
  PQ frame is not accidentally discarded, while the deadline prevents a
  slowloris from resetting progress one read at a time.
- **X25519 low-order input rejection.** Key derivation rejects an all-zero
  X25519 shared secret after the authenticated peer hello is checked.
- **Crash-durable keystore replacement.** Unix keystore saves now sync the
  containing directory after the atomic rename, reducing the chance that a
  completed replacement disappears after a sudden power loss.
- **Safe infallible endpoint fallback.** The legacy `From<Endpoint>` adapter
  degrades malformed input to `127.0.0.1:0`, never to an unspecified wildcard
  address that could accidentally expose a listener.
- **HKDF context arithmetic.** Public in-place HKDF derivation now rejects
  aggregate context-length overflow instead of allowing a wrapped allocation or
  slice boundary.

The source-level hardening is covered by focused regression and static
validation records. Full workspace check/test/Clippy execution belongs to the
dedicated native-platform campaigns; see
`docs/evidence/WINDOWS_NATIVE_VALIDATION_2026-08-09_POST_LOADER.md` and
`docs/TESTING.md` for the evidence boundary.

## Increment 26 — canonical wire boundaries, safe adapter paths, and listener resilience

Date: 2026-08-15

Files: `shph-core/src/crypto.rs`, `shph-core/src/handshake.rs`,
`shph-core/src/lib.rs`, `shph-core/src/roadmap.rs`, and
`shph-transport/src/lib.rs`.

- **Canonical AEAD nonce encoding.** Receive-side ChaCha20-Poly1305 framing now
  rejects any non-zero byte in the reserved first four nonce bytes. A frame
  therefore has one canonical SHPH encoding for each 64-bit counter.
- **Outbound TCP frame bound.** TCP send helpers reject plaintext larger than
  the existing 64 KiB encrypted-frame budget before encryption, so callers
  cannot truncate a length cast or consume a nonce for a frame the receiver
  would reject.
- **Collision-resistant adapter paths.** Offline-mesh, data-mule, and shared
  roadmap path helpers now retain a short readable prefix plus a
  domain-separated digest of the original component. Distinct values such as
  `a/b` and `a_b` no longer alias, and the offline session identifier is safe
  on Windows as well as Unix.
- **Bounded adapter configuration.** Public adapter validation and constructors
  cap polling intervals at 60 seconds and offline replay-cache entries at
  65,536. HKDF contexts are capped at 256 KiB, SHA-256 expansion output is
  capped at 8,160 bytes, and peer policies accept at most 4,096 pins.
- **Peer-local TCP failure handling.** Accept-loop timeout, early-close,
  cookie, hello-write, and PQ-frame failures are recorded and dropped for the
  current peer. The listener continues accepting until its single aggregate
  operator deadline expires.

Regression coverage includes non-canonical nonce rejection, oversized HKDF
contexts and output, peer-policy limits, adapter path collision resistance and
traversal confinement, bounded polling configuration, TCP send-size validation,
and the existing malformed-peer listener survival test.

Full Rust test/Clippy/build execution is a platform-campaign gate rather than a
claim made from an arbitrary workstation. Current native Windows evidence is
preserved in the dated validation record; see `docs/TESTING.md`.

## Increment 27 — handshake state integrity, continuity, and pre-encryption bounds

Date: 2026-08-15

Files: `shph-core/src/handshake.rs`, `shph-identity/src/lib.rs`,
`shph-transport/src/lib.rs`, `shph-cli/src/main.rs`,
`shph-core/src/keystore.rs`, and `shph-config/src/lib.rs`.

- **Local handshake-state binding.** `verify_hello_signature` now validates
  that the caller-supplied local hello still matches the configured identity,
  signing key, ephemeral key, nonce, profile, and post-quantum key material.
  Public handshake APIs therefore cannot derive a session from a locally
  tampered `HandshakeMaterial` object.
- **Strict identity-record continuity.** Sequence-one records cannot name a
  predecessor; every later record must name one, and a resolver update must
  advance exactly one sequence and reference the previously accepted hash once
  a predecessor has been accepted. Higher-numbered updates can no longer skip
  an unseen chain link.
- **Pre-encryption transport bounds.** Unshrouded QUIC payloads are rejected
  before AEAD allocation when they cannot fit the 16 KiB datagram budget.
  Offline-mesh and data-mule senders also reject payloads above their configured
  file bound before encrypting them.
- **Safer rollback and file boundaries.** Linux route cleanup now scopes
  deletion to the SHPH interface. Control-plane temporary files are removed
  when permission or path revalidation fails, and config, keystore, secret
  input, and control-plane loads reject symlinked parent components as well as
  final-component substitutions.

Focused regression coverage was added for local handshake-material mismatch,
identity continuity, unshrouded QUIC frame capacity, file-adapter payload
capacity, and interface-scoped Linux route deletion. The complete native
Windows execution record is maintained separately; see `docs/TESTING.md` and
the dated validation report.

## Increment 28 - failure-path cleanup, anchored discovery, and privileged-name validation

Date: 2026-08-15

Files: `shph-core/src/crypto.rs`, `shph-core/src/keystore.rs`,
`shph-core/src/roadmap.rs`, `shph-core/src/handshake.rs`,
`shph-config/src/lib.rs`,
`shph-identity/src/lib.rs`, `shph-tun/src/lib.rs`, and
`shph-cli/src/main.rs`.

- **Secret-file failure cleanup.** Keystore saves now remove their temporary
  file when permission changes, writes, fsyncs, reparse checks, replacement,
  or parent-directory synchronization fail. Configuration saves apply the
  same cleanup to post-write path revalidation failures.
- **Reduced resident signing-key duplication.** `IdentityKeyPair` retains the
  Ed25519 seed and public bytes, but no longer keeps a second long-lived
  `ring::Ed25519KeyPair` private-key copy. A signing object is reconstructed
  only for the individual signature operation.
- **Audit replacement cleanup and durability.** Ratchet-audit pruning removes
  its temporary journal on every failure path and syncs the containing
  directory after replacement.
- **Anchored identity discovery.** A resolver with no previously accepted
  state now accepts only sequence-one records. A signed sequence-two record
  cannot bootstrap a subject while naming an unseen predecessor hash.
- **Handshake field separation.** Peer hello verification rejects inline PQ
  ciphertext metadata because the ciphertext is transported as a separate
  authenticated frame, and it rejects PQ public keys whose decoded length is
  not exactly the ML-KEM-768 public-key size.
- **Privileged interface validation.** The strict TUN interface-name validator
  is shared with CLI MTU, route, DNS, killswitch, and MSS-clamp paths. `up`
  validates the name before any optional firewall mutation, preventing an
  invalid configuration from reaching privileged command construction.

Regression coverage includes unanchored initial identity updates, inline
PQ-ciphertext rejection, and malformed PQ public-key lengths. The full Rust
test matrix is a dedicated native-platform release gate and is recorded
separately from local workstation diagnostics.

## Increment 29 — deadline-aware resolution, envelope-safe adapters, and pin compatibility

Date: 2026-08-15

Files: `shph-transport/src/lib.rs`, `shph-identity/src/lib.rs`,
`shph-core/src/crypto.rs`, and `shph-core/src/handshake.rs`.

- **Aggregate deadline includes hostname resolution.** TCP and experimental
  QUIC clients now resolve hostnames through a bounded worker pool and wait
  only for the remaining handshake deadline. Literal socket addresses retain
  a fast path, and resolver queues are bounded so stalled system lookups
  cannot create an unbounded thread or request population.
- **Envelope-safe file-adapter capacity.** Offline-mesh and data-mule senders
  calculate a conservative plaintext capacity from the configured serialized
  envelope limit, AEAD nonce/tag overhead, and base64 expansion before
  encrypting. The existing serialized-envelope check remains as a final
  defense for lower-level writers.
- **Data-mule spool containment.** Data-mule configuration now carries bounded
  aggregate spool and envelope-age limits. Senders reject writes that would
  exceed the outbox quota; receivers quarantine expired envelopes and trim
  oldest candidates when an inbox exceeds its configured quota. Existing
  per-file, scan-depth, entry-count, and candidate-memory limits remain in
  force.
- **Automation-safe CLI failures.** Top-level CLI errors now use stable
  sysexits-style exit codes instead of collapsing every failure to `1`.
- **Jittered reconnects.** Bounded exponential reconnect delays now use equal
  jitter, reducing synchronized reconnect bursts without changing the
  configured minimum and maximum backoff bounds.
- **Panic-safe TUI teardown.** The TUI owns terminal state through an RAII
  session guard, catches panics long enough to restore raw mode and the
  alternate screen, and explicitly redraws after resize events.
- **Identity pin compatibility is fail-closed.** `IdentityRecord::to_peer_pin`
  now refuses a currently valid operational Ed25519 signing key because the
  current `shph-core` handshake can emit only the root `IdentityKeyPair`
  signing key. Expired operational keys remain ignored and fall back to the
  root key.
- **Regression build coverage is complete.** Test-only cookie helpers no
  longer trigger strict-Clippy dead-code failures, and all workspace test
  targets compile and link under the available supplemental compatibility path.

Native runtime test execution is covered by the dedicated Windows validation
campaign. The GNU compatibility path is supplemental compile-only evidence,
not a runtime or release claim. See `docs/TESTING.md` for the evidence boundary.

## Increment 30 - protocol identity, queue time, and automation boundaries

Date: 2026-08-17

- **Explicit standards-QUIC protocol identity.** Both TLS endpoints now
  require the `shph/standards-quic/1` ALPN, preventing accidental
  cross-protocol attachment to a certificate-valid QUIC service.
- **Future-dated Data-Mule quarantine.** Envelopes whose timestamps are too far
  ahead of the local clock are quarantined just like stale envelopes, so
  clock-manipulated files cannot remain eligible indefinitely.
- **Structured automation errors.** `--json` now emits stable error objects
  containing `ok`, `error`, `code`, and an optional `hint`; sysexits-style
  process codes remain available for scripts.

## Increment 31 - bounded handshake wire variance

Date: 2026-08-17

File: `shph-transport/src/lib.rs`.

- **Bounded handshake padding.** TCP, experimental QUIC, Offline Mesh, and
  Data-Mule hello serialization now appends 0–64 bytes of JSON whitespace
  selected from OS randomness. The padding is outside the signed `Hello`
  fields and is accepted by the existing JSON decoders.
- **Compatibility boundary.** The change varies serialized wire length without
  changing handshake semantics or authenticated framing. It does not claim
  browser fingerprint parity, DPI resistance, or production traffic stealth.
- **Deferred global bucketing.** Shroud's existing fixed-size cell behavior is
  retained. Global bucketed sizes for unshrouded TCP/QUIC remain deferred until
  a versioned authenticated length envelope can preserve interoperability.
