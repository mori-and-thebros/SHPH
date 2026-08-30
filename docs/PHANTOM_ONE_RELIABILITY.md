# Phantom One Reliability Boundary

Status: engineering hardening snapshot, 2026-08-29.

This document records the reliability goals for the opt-in Phantom One
TCP path. It is a test plan and evidence boundary, not a production-readiness
claim. Phantom One remains an experimental authenticated-transport envelope; it does
not provide encryption, anonymity, browser fingerprint parity, DPI evasion, or
censorship resistance by itself.

## Reliability goals

The implementation must:

- stop all reconnect and worker activity after local shutdown, EOF, or
  cancellation;
- clear handshake-only deadlines after authenticated setup so established
  sessions are not terminated by the handshake timer;
- keep sequence, replay, frame, queue, stream, and retry state bounded;
- treat a peer close, malformed frame, timeout, or backend failure as a
  contained session error rather than a listener-wide failure;
- preserve TCP half-close semantics without leaving a task, permit, or socket
  behind; and
- roll back control-plane mutations after normal shutdown, startup failure, or
  partial apply, while surfacing rollback failures.

## Phantom One-specific checks

Focused tests cover:

- round-trip behavior for data, control, and keepalive frames;
- truncated, oversized, non-canonical, wrong-generation, and wrong-version
  input;
- duplicate, stale, reordered, and out-of-window sequence handling;
- sequence-space exhaustion without wraparound;
- invalid padding configuration and path-budget rejection; and
- repeated session creation and teardown without state leaking between sessions.
- forward jumps beyond the replay bitmap window, with skipped and older
  sequence numbers rejected after the window advances.

Phantom One v1 remains the compatibility baseline. A wire revision is justified only
if a demonstrated defect cannot be fixed at the implementation boundary.

## Session and control-plane checks

The reliability suite must exercise:

1. shutdown during handshake;
2. shutdown during reconnect backoff;
3. peer disconnect during an established session;
4. EOF and TCP half-close in both directions;
5. failure at each control-plane apply stage;
6. repeated cleanup and stale persisted-state handling; and
7. bounded queue behavior under a slow or unavailable peer.

The tests must assert both the returned error and the resulting cleanup state.
An unavailable native TUN, firewall, or two-host capability is recorded as
`SKIP`; it is never converted into a passing host result.

The current implementation also makes reconnect backoff interruptible,
retains failed rollback operations for a later retry, and persists remaining
control-plane state when cleanup cannot complete. These are code-path
hardening properties; they are not yet native crash-containment or two-host
evidence.

The latest hardening pass additionally removes cloneable mutable Phantom One session
state, validates every public Phantom One constructor, rejects decoder construction
panics, and keeps sequence exhaustion fail closed. The Windows audit journal
now validates the opened file handle against reparse points and uses the
keystore's atomic replacement helper when pruning. Native-TUN startup captures
and restores the MTU/route-priority mutations, while WFP cleanup retains failed
filter deletions for retry. These are implementation-level controls, not
evidence of host-wide crash containment.

Local CLI, identity-provider, and filesystem-adapter inputs now share the core
no-reparse regular-file opener; Unix read handles are close-on-exec. The
standalone edge relay has an equivalent bounded reader and a Windows CI gate.
These checks close common final-component symlink/reparse traversal paths, but
do not claim resistance to every concurrent hostile-filesystem race.

Reusable Shroud profile and Phantom One buffers now wipe retired envelope bytes before
reuse or truncation. This reduces residual sensitive-data lifetime in the
caller-owned buffers; it does not guarantee that copies never existed in
allocator, kernel, runtime, or cryptographic-library memory.

Phantom One encode paths clear caller-owned buffers whenever a request is rejected or
an operation fails, so a failed request cannot leave the previous envelope
available through the reported vector contents. Successful reuse overwrites the
new envelope and wipes only bytes retired by a shrink. The standards-QUIC
Shroud2 receive path can decode into one owned vector, avoiding a second
payload allocation; both paths remain bounded by the negotiated path budget.
The authenticated TCP sender applies the same cleanup guarantee around its
validation, AEAD, write, and flush paths.

The morphology sampler now validates bounded empirical inputs, uses a
precomputed cumulative distribution for production sampling, and gives cloned
engines fresh random state. The edge HTTP/2 pool arms its notification wait
before releasing the acquisition lock, and relay response writes propagate
client disconnects into coordinated task cancellation. These are bounded
implementation properties, not network or DPI evidence.

The 2026-08-27 local verification pass completed the workspace gates, the
standalone edge checks, six bounded ASAN fuzz smoke runs, the release
benchmark smoke, and the Criterion microbenchmark capture. Criterion
performance deltas are regression signals for follow-up; they are not
correctness failures and do not establish network or production performance.

## Edge-relay checks

The standalone owned-domain `shph-edge` prototype must additionally test:

- backend connection timeout and refusal;
- request and response stream limits;
- slow readers and writers;
- cancellation while either direction is active;
- half-close and abrupt disconnect;
- capability expiry, audience mismatch, invalid signature, and nonce replay;
- connection-limit release after errors; and
- absence of tokens, payloads, or private peer data in logs.

The focused edge regression suite additionally checks empty SOCKS5-domain
rejection and 32 repeated short relay sessions under a bounded completion
timeout. The HTTP/2 client path now uses a bounded pool of standard
connections and stream slots. Each logical stream consumes one independently
issued capability token, and pool acquisition observes listener cancellation;
pool connection tasks are cancelled when the listener exits. Pool waiters are
armed before checking capacity so a released stream slot cannot be missed;
response-channel disconnects also cancel the corresponding relay tasks. There
is not yet a recorded live-TLS HTTP/2 multiplexing campaign, so these are
implementation and focused-test properties rather than two-host evidence.

The edge remains TLS-required, loopback-only for its SOCKS adapter, opaque, and
owned-domain-only. Its HTTP/3 carrier is now feature-gated and implemented with
standards libraries, but remains experimental until a separately recorded
two-host interoperability and long-run campaign is completed.

## Evidence classification

| Result | What it establishes |
| --- | --- |
| Unit or integration test | The exercised code path behaved as asserted |
| Local stress or Criterion run | A bounded workload measurement on one host |
| CI-hosted run | A bounded workload measurement on a GitHub runner |
| Native host run | The stated platform, privilege, driver, and lifecycle path |
| Two-host run | Real packet forwarding between the recorded hosts |

No reliability result alone establishes production readiness, Internet-scale
uptime, hostile-network resilience, anonymity, or censorship resistance.
Every future evidence record must include the exact revision, platform,
toolchain, command, workload, status, and limitations.
