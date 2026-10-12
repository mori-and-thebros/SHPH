# Changelog

## [Unreleased]

This source snapshot adds opt-in SHPH-native SNAP planning, Shroud 3, and a
native multi-hop onion prototype. These experimental surfaces remain outside
the release profile and still require additional operator, host, measurement,
or independent-review evidence.

- Added strict versioned SNAP profile validation and deterministic planning
  for JSON and TOML, with `shph snap validate` / `shph snap plan`, persistent
  session profile selection, bounded fallback policy, and SHPH peer pinning.
  Local paired adapter tests do not establish external bridge/relay acceptance
  or Python SierraNode session interoperability.

- Added an adaptive `S3` v1 QUIC datagram envelope with caller-supplied
  workload observations, bounded pacing, strict Shroud 2 separation, and a
  deterministic test constructor reserved for tests/labs. Native Linux TUN
  links are activated before route setup and their prior down state is restored
  on cleanup.
- Added nested TLS 1.3 onion paths over two or three explicitly pinned relays,
  a standalone `shph-onion-relay` process with numeric target allowlists and
  bounded per-circuit resources, and local authenticated SHPH loopback tests.
- Added an isolated Linux namespace probe for a real adaptive Shroud 3 TUN
  packet round trip and graceful control-plane cleanup; it is not two-host
  release evidence.
- Added support-boundary, release-readiness, fuzz-target, and operator design
  documentation. No release version was assigned or changed.
- Updated the locked `quinn-proto` dependency to `0.11.19` in all four Cargo
  lockfiles after the October 12 RustSec re-scan found advisories affecting the
  previously locked versions. The updated lockfiles pass warning and yanked
  audits. Local builds against the exact upstream tag source pass; the
  registry-backed locked build and package verification remain unverified
  because the crate archive could not be fetched in this environment.

## [0.6.7-dev] - 2026-09-05

This development snapshot refreshes the publication and validation workflow
after `v0.6.6-dev.2`. It remains a controlled-lab prototype and does not
claim production VPN readiness, censorship resistance, anonymity, or an
independent security audit.

- Bumped the workspace and benchmark package metadata to `0.6.7-dev` and
  refreshed the standalone lockfile provenance.
- Consolidated the current release-readiness, package-integrity, evidence, and
  mirror-synchronization documentation around the candidate snapshot.
- Kept native two-host validation and artifact signing explicitly scoped to
  their required host and publishing environments; the September 4 engineering
  record does not turn unavailable evidence into a pass.

## [0.6.6-dev.2] - 2026-08-30

This patch release fixes the remaining Unix warnings-as-errors path found by
the GitHub-hosted Linux validation after `v0.6.6-dev.1`. It remains a
development prototype for controlled lab environments.

- Scoped Windows-only TUN route and MTU restore helpers, plus their focused
  test, to Windows so Linux build, Clippy, native-TUN, reliability, and
  package checks compile cleanly with warnings denied.
- Refreshed current version metadata and standalone lockfiles for this patch.

## [0.6.6-dev.1] - 2026-08-30

This patch release fixes Linux compilation and standalone validation failures
found after the initial `v0.6.6-dev` prototype publication. It remains a
development prototype for controlled lab environments.

- Fixed the Unix control-plane state loader returning from a platform-specific
  block before the common file result was produced.
- Fixed the standalone edge relay's Linux/HTTP3 warning-as-error caused by an
  intentionally unused metadata binding.
- Refreshed standalone lockfiles and current version metadata for this patch.

## [0.6.6-dev] - 2026-08-30

This engineering snapshot adds the opt-in Phantom One prototype and a separate
owned-domain edge relay prototype. It remains outside the release profile and
does not claim production VPN behavior, anonymity, browser/TLS fingerprint
parity, DPI evasion, censorship resistance, or independent audit status.

- Added a bounded repeated-process CLI reliability test covering eight fresh
  authenticated loopback sessions with cleanup-safe child watchdogs.
- Added a sanitized release packager with an explicit public-document
  allowlist, source/lockfile provenance, payload checksums, regular-file
  checks, and common secret-marker scanning. CI now verifies the package
  manifest and checksums on Linux and Windows.
- Removed a discarded legacy TTY formatting pass so the live status bar has one
  deterministic ASCII-safe rendering path.
- Added a versioned `shph_transport::phantom_one` inner envelope with bounded
  session-scoped padding, explicit generation, frame types, replay-window
  checks, sequence-exhaustion handling, and runtime configuration validation.
- Integrated Phantom One into authenticated TCP sessions only; the existing
  AEAD, peer pinning, transcript signatures, and nonce/replay controls remain
  the security boundary. Phantom One rejects incompatible transports before
  handshake.
- Added the Phantom One CLI/config/ticket path as a separate opt-in prototype;
  Shroud 2 remains the compatibility default for existing configurations.
- Added the standalone `shph-edge` owned-domain HTTP/2 relay prototype with
  signed short-lived capabilities, bounded streams, fixed fallback responses,
  strict URI validation, redacted metadata, paired TLS requirements, and a
  loopback-only SOCKS5 client adapter.
- Added the feature-gated HTTP/3 edge carrier using Quinn, rustls, `h3`, and
  `h3-quinn`, with QUIC address-validation retry, bounded H3 request/response
  handling, one-use capability-token consumption, and coordinated shutdown.
  It remains an experimental standalone add-on with no live two-host H3
  evidence.
- Added Criterion and standalone Phantom One benchmark rows, a real Phantom One
  fuzz target, CI smoke registration, and public design/operator/testing evidence
  documents.
- Hardened Phantom One replay-window advancement so authenticated forward jumps
  beyond the bitmap window reset the receive bitmap instead of stalling after packet
  loss; skipped and older sequences remain stale.
- Made reconnect backoff shutdown-aware and retained failed control-plane
  rollback operations for explicit persistence and retry instead of discarding
  cleanup state.
- Hardened the owned-domain edge prototype with bounded TLS/backend operations,
  configured HTTP/2 stream limits, empty-domain rejection, and cancellation of
  the dedicated HTTP/2 task after each SOCKS5 logical session.
- Hardened Phantom One construction and state ownership: mutable encoder/decoder
  state is no longer cloneable, unchecked configuration construction was removed,
  decoder initialization no longer panics, and sequence/replay boundaries have
  explicit regression coverage.
- Hardened audit-journal persistence on Windows with handle-level
  reparse-point checks and the existing atomic replacement path, while
  preserving bounded reads and owner-only permissions.
- Hardened the edge relay lifecycle with coordinated cancellation, bounded
  public-key/token reads, stricter TLS server-name validation, and checked
  capability-lifetime arithmetic.
- Hardened native-TUN startup rollback and Windows WFP cleanup so failed
  mutations remain retryable and cleanup errors stay visible.
- Consolidated local regular-file input handling across the CLI, identity
  provider, and filesystem adapters around the core no-reparse opener; Unix
  read handles are now close-on-exec.
- Hardened the standalone edge relay's bounded token, public-key, certificate,
  and private-key reads against symlink/reparse traversal, and added a
  Windows-hosted edge test gate.
- Added a bounded, operator-configurable owned relay path and a standards-based
  HTTP/2 connection/stream pool. The client accepts a bounded newline-delimited
  bundle of independently issued one-use capabilities so pooling does not
  weaken nonce replay protection.
- Added seeded Shroud distribution-stability benchmark rows reporting wire-size
  quantiles, entropy, and first-half/second-half drift metrics. These remain
  local morphology measurements and do not establish DPI or censorship
  resistance.
- Hardened reusable Shroud buffers by wiping retired profile and Phantom One
  envelope bytes before reuse or truncation; this is memory-lifetime hygiene,
  not a wire
  security change.
- Bounded empirical morphology histograms by sample and bin count, switched
  production sampling to a precomputed CDF, and ensured cloned engines do not
  duplicate a live random stream.
- Hardened the edge relay lifecycle with cancellation-aware HTTP/2 response
  writes, prompt cleanup of stale producer/connection tasks, and an armed pool
  notification wait that avoids a release/waiter lost-wakeup race.
- Hardened reusable Phantom One and Shroud 2 buffers so rejected encodes clear
  stale contents, added an in-place Shroud 2 decode path for standards-QUIC receive
  loops, and made unweighted morphology classes path-MTU-aware instead of
  collapsing ineligible classes into the MTU ceiling.
- Added bounded zeroization for decoded Phantom One payloads and messages still held
  by an unflushed morphology batcher.
- Hardened reusable legacy profile buffers so early validation, randomness, and
  TCP write failures clear stale contents, and routed stateless TCP/QUIC
  profile encoding through the reusable buffer path.
- Added scoped zeroization for QUIC padded plaintext, received datagram
  storage, and sent packet buffers; hardened weighted morphology selection
  against future profile-shape and weight-overflow changes.
- Refreshed the root, benchmark, fuzz, and standalone edge lockfiles to the
  non-yanked `chacha20 0.10.2` release, clearing the blocking yanked-package
  audit warning without changing SHPH's cryptographic primitives.
- Kept the standalone edge relay's HTTP/3 feature disabled by default and
  retained an explicit CI compile/test gate for the opt-in carrier. The CLI
  still refuses HTTP/3 when the feature is not compiled.
- Added a central configuration validation boundary for normal parse/load/save
  paths, including bounded peer/control-plane/session lists, cross-field
  requirements, endpoint and path checks, reconnect limits, and startup
  payload bounds.
- Added pre-mutation control-plane duplicate detection for semantically
  equivalent CIDRs, underlay bypass routes, and DNS servers.
- Made transport DNS resolution deduplicate and cap returned socket addresses
  before connection attempts, and added regression coverage for the bound.
- Made metrics counters saturating and added stable snapshot serialization plus
  bounded interval deltas for status reporting.
- Added standalone edge configuration tests for unusable backends,
  TLS-enabled server-name requirements, audience validation, and graceful
  SIGTERM/Ctrl+C cancellation behavior.

## [0.6.5-dev.1] - 2026-08-25

This documentation and evidence follow-up records the current controlled
cross-platform validation work and a transport reliability fix. It remains a
prototype release for controlled lab environments; it does not claim
production VPN performance, censorship resistance, anonymity, or independent
security-audit status.

- Fixed established TCP sessions inheriting the short handshake read/write
  deadlines after successful authentication, with focused regression coverage.
- Added sanitized Windows-to-Linux native-TUN evidence covering authenticated
  IPv4 forwarding, bounded transfer, reconnect, impairment, MTU boundaries,
  session hold, and teardown.
- Added a separately scoped optional SOCKS5/Xray underlay evidence report
  covering an authorized no-TUN handshake and one-shot payload.
- Updated the public README, security boundary, support matrix, hardening
  notes, testing guidance, release-readiness rules, and evidence index.
- Corrected current evidence counts and documented Criterion performance
  follow-up signals without presenting them as correctness failures.
- Kept host-pair, crash-containment, DNS/IPv6/UDP, standards-QUIC, and
  long-duration gaps explicit; no production or censorship-resistance claim
  is added.

## [0.6.5-dev] - 2026-08-25

This prototype release packages security hardening, transport reliability
improvements, defensive benchmark coverage, refreshed public evidence, and
cross-platform validation updates. It remains scoped to controlled lab
environments and does not claim production VPN performance, censorship
resistance, or independent security-audit status.

- Removed automatic first-peer TOFU enrollment from `host`; a listener now
  requires a configured client identity/signing-key pin before it can accept
  traffic.
- Added bounded concurrent TCP pre-auth workers with a short header deadline,
  preserving listener availability under slow-client conditions.
- Serialized Windows WFP killswitch ownership with a process-wide mutex so
  stale-filter cleanup cannot remove another active SHPH instance's policy.
- Added handle-aware no-reparse file opens for config, keystore, ticket, and
  Wintun inputs, with post-open validation.
- Hardened offline-mesh replay identity by binding the creation timestamp with
  the sequence number, preventing a post-restart sequence reset from reusing an
  older replay key.
- Added authenticated offline-mesh/data-mule session round-trip tests and a
  distinct-spool offline replication regression test.
- Added Windows extended-length path handling for file-adapter claims,
  persistence, and reparse-point checks, plus Criterion coverage for adapter
  validation, SOCKS5 parsing, and JA4 fingerprint computation.
- Added a `defensive` standalone benchmark suite and Criterion rejection group
  covering malformed Shroud cells, oversized datagrams, cookie failures,
  duplicate nonces, and per-source rate limiting.
- Added Windows CI smoke coverage for the defensive suite and documented its
  local-rejection-only evidence boundary.
- Recorded elevated Windows Wintun lifecycle, route/DNS rollback, and loopback
  WFP smoke evidence; native packet forwarding and two-host gates remain open.
- Updated workspace and standalone benchmark metadata to `0.6.5-dev`.

## [0.6.4-dev.4] - 2026-08-23

This developer release packages tuned Shroud profiles, stateful padding and
morphology improvements, and refreshed reproducible evidence. It remains
scoped to controlled lab environments and does not claim production VPN
performance, censorship resistance, or independent security-audit status.

- Added explicit `tuned`/`optimized` profile aliases with low, medium, and high
  tuned tiers for controlled overhead and morphology experiments.
- Added session-scoped padding state and reusable output buffers across the
  TCP, QUIC, and Shroud2 lab paths to avoid resetting randomness per frame.
- Added tuned profile overhead, morphology, batching, and session-RNG
  Criterion coverage plus tuned-profile fuzz input selection.
- Added the refreshed public benchmark report and evidence dashboard, with
  corrected units and explicit local/synthetic measurement boundaries.
- Revalidated the release candidate with 304 workspace tests, 7 standalone
  benchmark tests, full local `all` and `extended` benchmark campaigns,
  150 Criterion estimate files, five fuzz-target smoke runs, and a clean
  dependency advisory scan.

## [0.6.4-dev.3] - 2026-08-22

This follow-up developer release expands the benchmark and evidence workflow.
It remains scoped to controlled lab environments and does not claim production
VPN performance, censorship resistance, or independent security-audit status.

- Added a Criterion microbenchmark harness for hybrid/classical handshakes,
  AEAD/HKDF, replay and cookie defenses, framing, shared padding profiles,
  Shroud2 morphology/batching, histogram distance, and identity records.
- Added GitHub-hosted Linux and Windows full benchmark campaigns for the
  standalone `all` and `extended` suites plus Criterion reports.
- Added 30-day CI artifact capture with commit, runner, toolchain, scope, and
  determinism metadata.
- Documented the difference between deterministic synthetic inputs,
  GitHub-hosted measurements, local workstation results, and operator/two-host
  evidence.
- Updated the benchmark crate and workspace version to `0.6.4-dev.3`.

## [0.6.4-dev.2] - 2026-08-20

This developer release contains transport reliability fixes, native-TUN
hardening, and public documentation cleanup. It remains scoped to controlled
lab environments.

- Fixed TCP frame-reader desynchronization when polling timeouts split a length
  prefix or ciphertext.
- Added bounded incremental TCP frame buffering and regression coverage.
- Corrected Shroud native-TUN MTU budgeting to account for the profile envelope.
- Hardened underlay bypass and route-priority handling for controlled full-route
  tests.
- Removed maintainer-only planning and publication artifacts from the public
  tree.

## [0.6.4-dev] - 2026-08-20

This developer release improves operator workflow around external reachability
add-ons such as Xray and Quick Tunnel. It does not change the SHPH
cryptographic protocol, and it remains scoped to controlled lab environments.

- Added bounded `--ticket-file` support to `host`, `join`, and `id` for safer
  handoff of long `shph://v1:` tickets without embedding them in shell history.
- Added `join --check`, a no-mutation preflight that validates a ticket,
  checks the selected transport path, and performs one authenticated handshake
  without writing configuration, changing routes/DNS, or opening a TUN device.
- Added `join --transport-peer` so a public ticket endpoint can remain the
  pinned policy identity while a trusted local relay is used as the socket
  destination.
- Added `doctor --deep` diagnostics for persistent connect sessions, including
  transport-peer reporting, underlay reachability, and authenticated handshake
  checks.
- Improved `status` and JSON status output to show the effective transport peer
  separately from the identity/policy peer.
- Added bounded Xray/SOCKS5 readiness checks for Windows and Linux under
  `scripts/check_xray.ps1` and `scripts/check_xray.sh`.
- Added CLI, configuration, ticket-file, transport-peer, and diagnostic
  regression coverage.
- Updated the reachability add-on documentation with Quick Tunnel workflows,
  ticket-file handling, preflight checks, and explicit safety boundaries.

## [0.6.3-dev.3] - 2026-08-19

- Added an explicit, opt-in SOCKS5 underlay add-on for outbound TCP paths.
  This can route the existing SHPH stream through a local Xray-compatible
  listener without changing SHPH authentication or encrypted framing.
- Added CLI and session configuration support through `--underlay` and
  `[session].underlay`, with direct TCP remaining the default.
- Added bounded SOCKS5 negotiation tests and documented the add-on's
  TCP-only, no-auth, external-proxy security boundary.
- Removed internal campaign and sprint material plus personal endpoint examples
  from the publishable repository tree.

## [0.6.3-dev.2] - CLI UX and guided connectivity follow-up (2026-08-18)

This developer release packages the guided CLI workflow, identity sharing, and
transport usability hardening. It remains limited to controlled lab use and
does not claim production VPN, censorship-resistance, or hostile-network
security guarantees.

- Added `shph host` and `shph join` with bounded `shph://v1:` tickets that
  carry the endpoint, transport, Shroud profile, and pinned host keys.
- Added `shph id --qr` for identity inspection and terminal QR sharing.
- Added `shph up --to` with secure defaults: TCP, TUN enabled, and the medium
  Shroud profile, with explicit `--no-tun` and profile overrides.
- Added an interactive TTY status bar with handshake, interface, and live
  traffic counters while preserving line-oriented non-interactive output.
- Added Linux native-TUN forwarding/NAT setup with scoped nftables rules and
  rollback cleanup; non-Linux hosts report the capability boundary.
- Added explicit first-peer TOFU enrollment for `host`, followed by persisted
  identity pin enforcement.
- Added endpoint validation, QR/ticket regression coverage, and bootstrap
  policy tests.

## [0.6.3-dev] - patches, optimizations, and benchmark updates (2026-08-18)

This developer release is limited to transport patches, lab-profile
optimizations, and benchmark/evidence updates; it does not claim a new
production support tier.

- Added bounded 0–64-byte randomized JSON-whitespace padding to serialized
  handshakes across TCP, experimental QUIC, Offline Mesh, and Data Mule.
- Kept the signed `Hello` fields and authenticated framing unchanged, so this
  varies wire length without changing handshake semantics.
- Retained Shroud's existing fixed-size cell behavior and deferred global
  unshrouded frame bucketing until a versioned authenticated length envelope
  is available.
- Added a reproducible `benchmarks --suite evidence` campaign for current
  Shroud2 overhead, pre-authentication CPU paths, and 128-bit replay-window
  throughput; results are explicitly scoped to local lab evidence.
- Added a network-simulation evidence addendum documenting the implemented
  MTU/MSS boundaries and the unsupported synthetic-ICMP, WAN-loss, and
  Poisson-chaff claims.
- Rebalanced the opt-in Shroud2 `LowLatency` lab profile to prefer
  smallest-fitting 128/256/512/1024-byte classes with bounded 65/25/8/2
  weights.
- Rebalanced the opt-in `WebBrowsingLab` and `VideoStreamingLab` profiles
  toward smaller fitting classes with bounded 45/30/15/8/2 weights, while
  preserving their existing discrete class sets; `BulkLab` remains uniform for
  comparison.
- Added a separate `benchmarks --suite extended` campaign for benchmark-only
  batch framing, deterministic MTU/loss matrices, concurrent in-memory
  sessions, session churn, and PowerShell repeatability captures.
- Documented the 2026-08-18 extended results and kept native Linux TUN,
  two-host, reconnect, and MSVC evidence explicitly capability-gated.
- Added a bounded authenticated Shroud2 application-message batch API and
  MTU-aware batcher for small messages; native-TUN IP datagrams remain
  intentionally unbatched to avoid loss amplification.
- Added profile-aware batch policies with explicit caller-driven latency
  deadlines for low-latency, web, video, and bulk application traffic.
- Capped custom batch deadlines at one second, bounded decoded batch payloads
  to the global envelope limit, and removed an internal batch-state panic path.

## [0.6.2-dev.3] - CI hardening follow-up (2026-08-17)

- Refactored the bounded Data-Mule scanner state so strict Clippy checks pass
  without lint exceptions.
- Preserved the existing scan-entry, byte, age, and candidate-memory limits.
- Verified the complete Ubuntu and Windows CI matrix, including Clippy,
  build/test, fuzz smoke tests, benchmarks, audit, and the reproducible demo.

## [0.6.2-dev.2] — hardening follow-up (2026-08-17)

### Security and reliability

- Added bounded aggregate size and age limits for Data-Mule spools.
- Quarantined stale, malformed, and far-future Data-Mule envelopes before
  delivery; outbound writes now fail closed when the configured quota is full.
- Bound standards QUIC to the explicit `shph/standards-quic/1` ALPN and kept
  replayable TLS early data disabled.
- Added equal-jitter reconnect backoff, panic-safe TUI terminal restoration,
  and a fail-closed guard against overwriting persisted control-plane state.

### CLI and validation

- Added stable sysexits-style CLI exit codes for automation.
- Added structured `--json` error objects with `ok`, `error`, `code`, and
  optional `hint` fields.
- Added regression coverage for the new limits, protocol identity, error
  schema, and cleanup boundaries.
- Expanded operator, security, lab-prototype, and standards-QUIC
  documentation.

This is a development snapshot. It does not claim a production VPN,
anti-censorship capability, native two-host TUN completion, or independent
security-audit status.

## [0.6.2-dev.1] — CI and branch migration follow-up (2026-08-17)

- Fixed the Linux QUIC certificate symlink regression so the full Ubuntu
  workspace test gate passes.
- Standardized the public branch, CI triggers, and security documentation on
  `main`; removed the legacy `master` branch.
- Preserved the development-only scope of the `0.6.2` release line.

## [0.6.2-dev] — public release preparation (2026-08-17)

### Release and publication hygiene

- Bumped the workspace and benchmark package metadata to `0.6.2-dev`.
- Added explicit release-readiness, security-evidence, and support-matrix
  documents with honest PASS/FAIL/SKIP boundaries.
- Added public redaction guardrails for credentials, private paths, generated
  evidence, and local-only research material.
- Kept identity discovery visibly experimental and outside the release profile;
  maintainer-only identity design and benchmark-capture notes remain excluded
  from the public tree.

### CLI and TUI usability

- Published the operator-facing CLI/TUI improvements as part of the
  `0.6.2-dev` development snapshot: doctor diagnostics, structured JSON
  output, clearer status/peer views, actionable errors, and the read-only TUI
  dashboard with reload and in-app help.

This tag is a development snapshot. It does not claim production VPN,
anti-censorship, native two-host TUN, or independent security-audit status.

## [0.6.1-dev] — prerelease hardening follow-up (2026-08-15)

### CLI and TUI usability

- Added `shph doctor` with human-readable and strict JSON diagnostics for
  configuration, identity, peer, session, control-plane, and native-TUN
  prerequisites.
- Improved `shph status` and `shph list-peers` with structured JSON output,
  clearer summaries, and compatibility aliases.
- Added actionable CLI error hints and richer top-level help examples.
- Reworked `shph-tui` into a read-only dashboard with Overview, Peers, Session,
  and Control Plane views, reload support, keyboard navigation, and an
  in-app help overlay.

### Security and protocol hardening

- Bounded untrusted input and handshake state: replay windows now clamp their
  allocation size; local secret/config/audit/provider/adapter inputs reject
  special files; TCP handshakes use one aggregate deadline and preserve
  pipelined bytes; and X25519 all-zero shared secrets are rejected.
- Made atomic Unix keystore replacement sync its containing directory and made
  malformed infallible endpoint conversions fall back to loopback rather than
  an unspecified wildcard address.
- Made in-place HKDF context-length accumulation checked so an oversized
  caller-supplied context fails closed instead of wrapping arithmetic, and
  bounded the aggregate context and SHA-256 expansion output before
  intermediate allocation.
- Enforced canonical zero-prefixed AEAD nonce encoding on receive and rejected
  outbound TCP payloads that cannot fit the existing encrypted frame limit
  before consuming a send nonce.
- Replaced lossy file-adapter path sanitization with digest-bound safe
  components, bounded adapter polling intervals and offline replay-cache inputs,
  and capped configured peer-policy pins.
- Made every TCP accept-loop handshake/read failure peer-local, including
  cookie disconnects and timeouts, so malformed or slow peers cannot terminate
  the listener before its aggregate deadline.
- Added a rotating, stateless HMAC-SHA256 TCP cookie challenge after the
  existing per-source pressure threshold. Cookie validation occurs before
  responder ML-KEM key generation and ciphertext decapsulation.
- Added a complementary deterministic peer-ID role decision for
  simultaneous-open orchestration while preserving the connected socket's
  initiator/responder key direction.
- Added explicit empirical-CDF size sampling to the opt-in Shroud 2.0 lab
  morphology engine while retaining negotiated path-MTU and envelope bounds.
- Configured native TUN interfaces to a validated 1360-byte MTU before route,
  DNS, and session setup, with Linux and Windows command builders covered by
  tests.
- Added opt-in host leak containment: Linux installs a dedicated nftables
  killswitch before native TUN setup, while Windows installs persistent WFP
  outbound authorization filters. Both require literal peer IP/port
  allowlists, and `down` removes stale SHPH-owned policy. The
  `--killswitch-dry-run` preview does not require native TUN, elevation, or
  firewall mutation.
- Added opt-in Linux TCP SYN MSS clamping in a separate nftables table.
  Windows reports an explicit unsupported error because this build does not
  perform unsafe host-wide TCP-option rewriting.
- Replaced ambiguous handshake transcript concatenation with canonical,
  length-prefixed field framing that binds the negotiated profile, peer
  ordering, initiator identity, hybrid public values, and optional KEM
  ciphertext.
- Made native `up` capture session failures before cleanup so control-plane,
  MSS-clamp, and killswitch rollback remains consistent on early exits.
- Captured a fresh Windows-local full benchmark suite for `0.6.1-dev` across
  `secure-default` and `classical-lab` with 5,000 latency samples and 100,000
  sustained frames; native TUN and two-host behavior remain outside the run.
- Added the standalone `wire` benchmark suite with AEAD encode/decode,
  authenticated UDP loopback, Shroud2 envelope overhead, MTU-bound payload
  coverage, and explicit wire-bytes/overhead/packet-rate CSV fields.
- Bound public handshake verification to the actual local identity, signing
  key, ephemeral key, nonce, profile, and PQ material, preventing a tampered
  `HandshakeMaterial` value from reaching session-key derivation.
- Tightened experimental identity discovery continuity: non-initial records
  require a predecessor, and accepted updates must advance exactly one
  sequence while naming the accepted predecessor hash. Added an explicit
  linked-update constructor and adjusted standalone benchmark fixtures.
- Rejected oversized unshrouded QUIC and file-adapter payloads before AEAD
  work, keeping caller-controlled allocation and CPU use inside the configured
  transport/file budgets.
- Scoped Linux route rollback deletes to the SHPH interface, cleaned up
  control-plane temp files on permission/path failures, and extended
  parent-component reparse checks to sensitive loads.
- Removed secret/config/audit temporary files on all post-creation failure
  paths, and synced the audit journal's containing directory after pruning.
- Rejected unanchored sequence-two identity records during first discovery,
  preventing a signed update from bootstrapping over an unseen predecessor.
- Rejected inline PQ ciphertext metadata and malformed ML-KEM public-key
  lengths during hello verification.
- Reused strict TUN interface-name validation across privileged CLI command
  builders and validated the name before optional firewall setup.
- Removed the long-lived duplicate Ed25519 private-key object from
  `IdentityKeyPair`; signing reconstructs the ring key object per operation
  while the persisted seed remains explicitly zeroized on drop.
- Made TCP and experimental QUIC hostname resolution share the aggregate
  handshake deadline through bounded resolver workers.
- Derived offline-mesh and data-mule plaintext capacities from AEAD, base64,
  and serialized-envelope overhead before encryption, while retaining the
  final envelope-size check.
- Made identity discovery refuse peer pins that advertise an active
  operational signing key unsupported by the current handshake implementation.

These changes do not claim production traffic morphology, DPI resistance,
privileged firewall execution on every host, or native two-host VPN evidence.

## [0.6.0-dev.0] — release-polish and native-platform hardening (2026-08-09)

This is a development release. It is not a production-ready transport, an
independent security audit, or evidence that the remaining native two-host TUN
release gates have been completed.

### Windows native TUN validation refresh

- Recorded a fresh native Windows validation run: locked workspace checks,
  strict Clippy, release builds, 180 passing workspace tests, Windows-only
  Wintun and ACL regressions, and both local benchmark profiles.
- Removed the host-incompatible strict signed-target DLL flag while retaining
  application-local loading, elevation checks, SHA-256 pinning, and validator
  Authenticode verification.
- Captured a post-loader native Wintun adapter/session smoke and documented the
  remaining packet-I/O, route/DNS rollback confirmation, reconnect, shutdown,
  and two-node evidence gates.
- Fixed Windows route rollback to include the adapter interface in the
  generated `netsh delete route` command.

### Security-assessment remediation

- Made responder-side ML-KEM decapsulation policy-aware: the peer hello
  signature and configured identity/signing-key pin are verified before PQ
  decapsulation in every transport, including file adapters and standards
  QUIC.
- Added collision-safe peer-limiter eviction and corrected its distributed
  source regression assertion.
- Added mandatory application-local Wintun SHA-256 pinning through
  `SHPH_WINTUN_SHA256`; missing, malformed, oversized, or mismatched runtimes
  fail closed before DLL loading.
- Zeroized keystore serialization staging and password-bearing configuration
  holders on drop, while retaining explicit documentation for unavoidable
  API/string copies.
- Added the `shroud2_datagram` target to the CI fuzz smoke loop.
- Made native Linux and Windows bridge disconnects retryable unless shutdown
  was requested locally, so reconnect policy is exercised after a remote close.
- Made public TCP send/receive helpers retain caller-owned AEAD cipher state,
  preventing accidental per-frame nonce-counter resets.
- Added the native Linux two-host validation harness, including host/container
  exclusion, private external state, interval CPU/RSS capture, `iperf3`
  readiness checks, routed ping/goodput measurements, and reconnect evidence.
- Added GitHub issue/PR templates plus a publication checklist that requires
  monitored private vulnerability reporting and sanitized evidence review.
- Made a remotely closed standards-QUIC native-TUN bridge fail explicitly
  instead of completing successfully, and reject standards-QUIC reconnect
  configuration until certificate continuity is implemented.

### Standards/TUN hardening and documentation

- Disabled TLS 1.3 early data (0-RTT) in both explicit standards-QUIC TLS
  builders, preventing replayable application input before the SHPH handshake.
- Bounded opt-in JA4 SNI recording to 255 UTF-8 bytes and preserved the
  partial-observation/non-spoofing contract.
- Rejected oversized standards-QUIC TUN datagrams before copying them into
  zeroizing packet buffers and capped the malformed-datagram close budget.
- Retried interrupted native-TUN syscalls, reported native EOF consistently,
  and wiped rejected packets from caller-provided read buffers.
- Reconciled README, security, testing, project-status, and standards-QUIC docs with
  the implemented Linux native-TUN bridge and its remaining host-evidence
  gates.

### Transport, configuration, and fuzzing hardening

- Added a standalone `cargo-fuzz` workspace with bounded fuzz targets for
  Shroud-cell decoding, configuration parsing, audit-record deserialization,
  and replay-window state transitions.
- Added a public configuration parser entry point so fuzzing exercises the same
  TOML deserialization path used by file loading.
- Fixed Data-Mule responder handshakes leaving the consumed peer hello in the
  inbox, which could cause the same hello to be selected again.
- Fixed offline/Data-Mule queue polling so malformed payload candidates are
  quarantined and do not block later valid envelopes.
- Hardened file-adapter reads against final-component symlink traversal and
  made envelope temp-file creation exclusive.
- Bounded TCP connect setup with the configured timeout instead of relying on
  platform-specific blocking connect behavior.
- Fixed Unix stdin session mode dropping additional lines when one read
  contained multiple newline-delimited messages; oversized lines now fail
  closed at 64 KiB.
- Hardened config persistence with unique exclusive temp files, cleanup on
  failure, and parent-directory sync after replacement.
- Hardened CLI peer authentication by pinning the Ed25519 handshake-signing
  public key alongside the X25519 identity key.
- Added bounded TCP address fallback, Unix keystore symlink refusal, and
  encrypted-keystore KDF parameter bounds.
- Bounded TCP/QUIC handshake retries to one overall timeout and added a hard
  stdin line cap on non-Unix builds.
- Hardened ratchet-audit journal reads/appends against final-component
  symlink replacement.
- Bounded configuration loading to 1 MiB, rejected non-UTF-8 input, and
  refused final-component symlinks on Unix.
- Made malformed file-adapter quarantine collision-safe so rejected evidence is
  not overwritten.
- Added a Linux-first benchmarking roadmap with explicit security/performance
  profile rules; no protocol mode behavior changed.
- Implemented explicit `secure-default` and `classical-lab` handshake profiles.
  Profiles are signed and transcript-bound, profile mismatches fail closed, and
  the CLI/config expose classical benchmarking only as an explicit opt-in.
- Bumped the unreleased handshake protocol identity to `shph/5`; `shph/4`
  peers are intentionally incompatible with the profile-aware wire format.
- Added a standalone native-Linux benchmark runner under `benchmarks/` for
  handshake, framing, AEAD, and replay measurements with environment metadata.

### Earlier development-line remediation

- Made CLI peer identity pinning mandatory; sessions now fail closed when no
  expected peer is configured.
- Added `show-public-key` to make safe `add-peer` registration straightforward.
- Added Windows console-control shutdown handling via `SetConsoleCtrlHandler`.
- Added idempotent `apply`, `reconcile`, and `undo` control-plane commands with
  persisted applied-state tracking.
- Preserved multiple configured DNS servers during control-plane application:
  Linux uses one `resolvectl` update and Windows emits primary/secondary
  `netsh` commands by address family.
- Added a hard aggregate 60-second TCP accept/handshake deadline.
- Made `SHPH_TUN_NATIVE=1` fail explicitly on Windows until signed Wintun
  runtime integration exists; it no longer silently selects the stub backend.
- Added regression coverage for multi-server DNS command generation and
  cross-platform TUN-name validation.
- Refreshed audit, evidence, and mirror verification artifacts.

### Secret-material zeroization

- **Session AEAD keys are now zeroized on drop.** `SendCipher` and
  `ReceiveCipher` implement `Drop` to wipe the 32-byte ChaCha20-Poly1305 session
  key, so live traffic keys no longer persist in heap memory after a session
  ends. This mitigates core-dump, swap, and memory-disclosure recovery of
  session keys.
- **`SessionKeys` derives `ZeroizeOnDrop`** — `send_key` / `recv_key` are wiped
  on drop (nonces are non-secret and skipped).
- **Ed25519 signing-seed hygiene** — `IdentityKeyPair.sign_seed` is now wiped in
  both `Zeroize` and `Drop` (the X25519 `StaticSecret` already self-zeroizes).
- **HKDF intermediates zeroized** — the raw 32-byte HKDF outputs in
  `verify_and_derive` are wrapped in `Zeroizing<Vec<u8>>` and wiped once copied
  into the session keys.

- No wire-format, protocol-tag, or public-API change. The `zeroize` crate was
  already a direct dependency of `shph-core`; no new dependency added.

- 4 new regression tests for zeroize-on-drop (`SendCipher`, `ReceiveCipher`,
  `SessionKeys`, `IdentityKeyPair`). Workspace tests 79 -> 83 (0 failed).

## [0.4.0] — Hybrid post-quantum key exchange + QUIC shim hardening (BREAKING, 2026-07-02)

### Security (hybrid PQECDH)
- **Hybrid post-quantum key exchange (ML-KEM-768) is now layered on X25519.**
  Each handshake performs a full ML-KEM-768 encapsulation/decapsulation in
  addition to the classical X25519 ECDH. The session key is derived from
  **both** the ECDH shared secret **and** the ML-KEM shared secret via HKDF, so
  recorded traffic remains confidential even against a future quantum adversary
  that breaks ECDH ("harvest now, decrypt later").
- **Downgrade resistance.** `verify_and_derive` fails closed if the PQ shared
  secret is absent: a peer that strips the PQ ciphertext can never silently
  negotiate a classical-only key. The PQ public key is bound into the signed
  handshake transcript, so it cannot be swapped by a MITM.
- New `shph-core/src/pqc.rs` module (`PqcKeypair`, `encapsulate_against`,
  `decapsulate`) wrapping RustCrypto `ml-kem` (FIPS-203).

### Breaking changes
- Protocol tag bumped `shph/3` -> `shph/4`; `Hello` gains `pqc_pub_b64` and
  `pqc_ct_b64` fields. Old and new peers are not wire-compatible.
- The handshake now exchanges a small follow-up ML-KEM ciphertext message after
  the hello round-trip (one extra bounded frame/datagram/payload per handshake).
- `HandshakeMaterial` gained a `pq_shared` field and is no longer `Clone`
  (ML-KEM decapsulation keys are not cloneable).

### Hardening (QUIC/UDP shim)
- **Post-handshake source-address binding.** QUIC data-frame datagrams are now
  rejected unless they arrive from the address authenticated during the
  handshake, closing an off-path injection/amplification surface.
- **Per-IP rate limiting on the QUIC accept path** (parity with TCP), so a single
  host cannot exhaust the handshake budget by flooding UDP hellos.
- **Datagram truncation guard:** a hello that fills the receive buffer is
  rejected instead of being parsed as a truncated message.
- PQ ciphertext frames are length-prefixed and size-bounded to exactly
  `ML_KEM_768_CIPHERTEXT_BYTES`; oversized or short reads fail closed.

### Tests
- Hybrid roundtrip, downgrade-blocked, corrupted-ciphertext-breaks-agreement,
  and classical-only-cannot-derive regression tests in `handshake_flow.rs`.
- QUIC foreign-source rejection regression test in `shph-transport`.

### Out of scope (documented, not implemented)
HSM/TPM/YubiKey key binding, browser/DPI/TLS fingerprint shaping, and offline
mesh adversarial posture remain explicitly out of scope — they require hardware
or substantial design work and are tracked in `docs/RISK_MATRIX.md`.

## [0.3.0] — Real Ed25519 handshake authentication (BREAKING, 2026-06-30)

### Security (critical fix)
- **The handshake "signature" was not a real signature.** `sign_handshake`
  computed `SHA256(public-key || transcript)` and verify compared that hash — a
  digest of purely public data with no private-key operation. Anyone could forge
  a valid `sig`, so the handshake had **no authentication / no MITM resistance**.
- Replaced with a **real Ed25519 detached signature** via `ring`. Each identity
  now carries an independent Ed25519 keypair (in addition to the X25519 DH key).
  The signature binds the X25519 identity key, the Ed25519 signing key, the
  ephemeral key, the nonce, and the timestamp, so the keys cannot be swapped by
  a MITM. Only the holder of the peer's Ed25519 private key can complete the
  handshake.

### Breaking changes
- Protocol tag bumped `shph/2` -> `shph/3`; `Hello` gains a `sign_pub_b64`
  field. Old and new peers are not wire-compatible.
- Keystore gains a persisted Ed25519 signing seed (`sign_seed_b64`); pre-0.3
  keystores load with a fallback signing key and should be re-`init`ed.

### Changed
- Workspace version `0.2.0` -> `0.3.0`.
- `SECURITY.md` now documents the implemented Ed25519 handshake signatures;
  the MITM threat row reflects the public-key signature check.

### Tests
- +4 handshake authentication regression tests: real sig verifies; forged
  impersonation rejected; tampered signature bytes rejected; swapped signing key
  rejected. `handshake_flow` 2 -> 6.

All notable changes to SHPH are documented here. This project follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) principles, adapted to
the project's validation and release workflow.

## [Phase B.2] — Stability Before Feature Expansion (2026-06-29)

### Added
- `docs/API_STABILITY.md` — public-API tiers (CLI / config / library), SemVer
  posture, and validation-window freeze rules.
- `docs/SECURITY_REPORTING.md` — bug-bounty-safe redactable report template +
  severity-based triage SLA (complements `SECURITY.md`).
- `docs/SUPPLY_CHAIN_SCAN.md` — `cargo-audit` scanner procedure + advisory triage.
- `docs/evidence/CARGO_AUDIT.txt` — captured advisory-scan output.
- Blocking `cargo audit --deny warnings` job in `.github/workflows/ci.yml`.

### Changed
- `anyhow` bumped `1.0.102 -> 1.0.103` (RUSTSEC-2026-0190, direct dep).
- `ratatui` bumped `0.27 -> 0.28.1` in `shph-tui` (transitive advisory hygiene).

### Fixed
- `shph-tui/src/main.rs`: deprecated `frame.size()` -> `frame.area()` (ratatui 0.28).

### Security
- Resolved the one direct scanner finding (`anyhow` unsound `downcast_mut`,
  never invoked by SHPH). 2 transitive warnings (`paste`, `lru`) accepted and
  documented; both isolated to the optional TUI.

## [Hardening] — Crypto data-plane hardening (2026-06-30)

Concrete security hardening of `shph-core/src/crypto.rs`, each with a
regression test. This is the first increment of the post-baseline hardening
track (Optional/Research), not a release gate.

### Security
- **Anti-replay window correctness:** `ReplayWindow` was a `HashSet` that
  cleared the whole set when it filled, dropping protection across the clear
  boundary (a previously-seen nonce became acceptable again). Replaced with a
  proper sliding bitmap window over the 64-bit counter space; the previous
  highest nonce is recorded as seen on every advance, so it cannot be replayed.
- **Nonce-reuse prevention:** `SendCipher` now fails closed at `AEAD_NONCE_LIMIT`
  (`2^32 - 1`) instead of letting the 64-bit counter wrap and reuse nonce 0
  (which would catastrophically break ChaCha20-Poly1305). The session must
  rekey rather than overflow.
- **Timing-safe verification:** handshake signature comparison now uses a
  constant-time equality check (`constant_time_eq`) instead of `!=`, removing a
  timing oracle on how much of the signature digest matched.

### Tests
- 8 new regression tests in `shph-core` (replay-window boundary, replay after
  many advances, nonce-limit fail-closed, constant-time eq semantics/prefix).
- `shph-core` unit tests: 19 -> 27.

## [Hardening] — Keystore secret hygiene (2026-06-30)

Hardening of `shph-core/src/keystore.rs` (private identity-key storage). Second
increment of the Optional/Research hardening track.

### Security
- **Private-key file permissions:** the keystore (holding the X25519 private
  key) is now written with mode `0600` on Unix (owner-only) instead of the
  process-umask default (often world-readable `0644`).
- **Leaky-file refusal:** `load` now rejects a keystore that is group/other
  accessible, failing closed rather than silently using a leaked key.
- **Bounded load:** keystore load is capped at 1 MiB (`MAX_KEYSTORE_BYTES`) and
  enforces UTF-8, so a hostile/giant file cannot force a large allocation.
- **Atomic save:** the keystore is written to a temp file beside the target,
  fsynced, then renamed into place — a crash mid-write can no longer leave a
  truncated/corrupt key file.

### Tests
- 5 new keystore regression tests (roundtrip, 0600 perms, leaky-file refusal,
  oversized-file rejection, no leftover temp files). `shph-core` 27 -> 32.

## [Hardening] — Transport DoS hardening + dead-code cleanup (2026-06-30)

Third increment of the Optional/Research hardening track (`shph-transport`).

### Security
- **Per-peer connection-rate limiting:** the TCP accept entry path now enforces
  a per-source-IP cap (`MAX_CONNECTS_PER_PEER_PER_WINDOW` = 8 per 10s) before
  any handshake work. This complements the per-loop `TCP_HANDSHAKE_ATTEMPTS`
  bound (which only covers a single accept loop) so one host cannot flood the
  entry path across repeated sessions.
- **Anti-slowloris hello read:** `read_tcp_hello` now reads in 1 KiB chunks into
  a single bounded buffer instead of one syscall per byte, with the same
  `MAX_HELLO_BYTES` cap. A dribbling peer can no longer amplify per-byte cost or
  hold the connection open beyond the cap.

### Changed
- Removed the orphaned, never-compiled root `src/crypto.rs` and `src/error.rs`
  (not part of any workspace crate; the live code is `shph-core/src/`).

### Tests
- 3 new `PeerRateLimiter` regression tests (under-cap allow, per-IP-not-port
  keying, distinct-IP isolation). `shph-transport` 1 -> 4 unit tests.

Gates referenced below: `cargo fmt --all -- --check`,
`cargo clippy --workspace --all-targets -- -D warnings`,
`cargo test --workspace` (0 failed), `cargo build --workspace --locked`.

## [Phase B.1] — External Review Readiness (in progress, 2026-06-29)

### Added
- `scripts/demo.sh` — reproducible demo + failure-mode walk-through (happy,
  bad-cidr, unreachable) running entirely on loopback.
- `scripts/capture_evidence.sh` — regenerates `docs/evidence/GATE_EVIDENCE.md`
  by running every mandatory gate and summing passed/failed/ignored totals.
- `docs/evidence/GATE_EVIDENCE.md` — captured acceptance-gate evidence log.
- `docs/RELEASE_READINESS.md` — release gates and evidence requirements.
- `docs/LEGAL_COMPLIANCE.md` — OSS artifact handling legal/compliance checklist.

### Fixed
- `scripts/capture_evidence.sh` totals: replaced the broken nested-quoted `awk`
  totals line with a shell-summed parser (`PASSED=` / `FAILED=` / `IGNORED=`).
- Evidence script no longer aborts on a single failing gate; all gates are now
  reported before the script returns.

## [Documentation and Maintenance] — 2026-06-29

### Added
- `docs/RISK_MATRIX.md` — severity-rated current limits + explicit exclusions.
- `docs/SUPPORT_AND_MAINTENANCE.md` — support tiers, SLA, maintenance cadence.

## [Phase A.4] — Ops, Packaging, and Trust (2026-06-25)

### Added
- `LICENSE-MIT`, `LICENSE-APACHE` (match `Cargo.toml` `MIT OR Apache-2.0`).
- `SECURITY.md` — disclosure process, threat model, non-claims matrix.
- `CONTRIBUTING.md` — build/test, style, validation, and release checklist.
- `.github/workflows/ci.yml` — Linux + Windows fmt/clippy/build/test matrix.
- `docs/REPRODUCIBILITY.md` — lockfile / `--locked` / `cargo audit` discipline.
- `scripts/sync_mirror.sh` + `docs/SYNC.md` — rsync mirror tooling with parity checks.

## [Phase A.3] — Security Baseline for Deployment (2026-06-24)

### Added
- Anti-replay in `ReceiveCipher` (`shph-core/src/crypto.rs`, monotonic `last_nonce`).
- Bounded accept loop `TCP_HANDSHAKE_ATTEMPTS = 5` (`shph-transport`).
- Security regression tests for replay, EOF, and malformed frames.

### Fixed
- Removed remaining production `.unwrap()`/`.expect()` (kept only in `#[cfg(test)]`).
- `shph-core/src/net.rs` panic on invalid endpoint removed; fail-closed.

## [Phase A.2] — Control-Plane Reliability (2026-06-24)

### Added
- `build_control_plane_plan` atomic preflight (validate all CIDRs/DNS before mutation).
- Error-preserving `restore_dns` and robust multi-error `ControlPlaneGuard::cleanup`.

## [Phase A.1] — Delivery-Critical Networking (2026-06-24)

### Added
- Graceful SIGINT/SIGTERM shutdown (`shph-cli/src/shutdown.rs`).
- Poll-driven stdin so the connect loop observes shutdown within ~200ms.
- Session lifecycle trail (`Session id`/`start`/`end`/`Final metrics`) on all `up` paths.
- `MetricsCollector` (bytes/packets/errors sent+recv) wired into one-shot and loop paths.

### Notes
- Windows graceful shutdown via `SetConsoleCtrlHandler` is now wired through
  `windows-sys`; native Windows verification remains an operator action.
