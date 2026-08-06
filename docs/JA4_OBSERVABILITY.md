# Optional JA4 Observability Plugin

## Scope

SHPH exposes an opt-in, passive JA4-compatible observability plugin for the
standards-QUIC server path. It observes the real rustls `ClientHello` through
the certificate-resolver hook and delivers bounded metadata to an application
callback.

The plugin does **not**:

- rewrite or reorder ClientHello fields;
- select a browser or operating-system fingerprint;
- alter Quinn/rustls defaults, QUIC transport behavior, or certificate policy;
- provide stealth, censorship bypass, DPI evasion, or traffic-analysis
  resistance.

The default `server_endpoint(...)` path remains unchanged and does not create
an observer.

## API

Enable the plugin explicitly:

```rust
use std::sync::Arc;
use shph_transport::ja4::{Ja4ObserverConfig, RecordingJa4Observer};
use shph_transport::standards_quic::{
    server_endpoint_with_ja4_observer, StandardsQuicConfig,
};

let observer = Arc::new(RecordingJa4Observer::new(256)?);
let server = server_endpoint_with_ja4_observer(
    bind_addr,
    StandardsQuicConfig::default(),
    observer.clone(),
    Ja4ObserverConfig::default(),
)?;

let observations = observer.snapshot();
```

`Ja4Observer` is the plugin boundary. Applications can implement it to export
observations to a metrics system, audit sink, or lab collector. The callback
is synchronous, so it must remain bounded and non-blocking. The built-in
recorder uses a bounded ring buffer and accepts capacities from 1 through
4,096.

## Coverage

`Ja4ClientHello` computes the canonical JA4 hash and raw-list form when the
caller supplies complete ClientHello metadata. It removes GREASE values,
counts ciphers and extensions with JA4 limits, includes the SNI-presence and
first-ALPN markers, sorts lists for the hashed form, and preserves supplied
order in the raw form.

Live rustls observations are marked `PublicRustlsSubset`. The public rustls
server hook exposes SNI, ALPN, cipher suites, signature schemes, and named
groups, but does not expose the complete ordered extension list and supported
versions required to claim an exact wire-level JA4. Therefore each live
observation contains:

- `partial_fingerprint`: a stable JA4-compatible rendering of available
  fields;
- `metadata_sha256`: a stable digest of bounded captured metadata;
- `exact_fingerprint: None`; and
- `coverage: PublicRustlsSubset`.

This is deliberate: SHPH does not manufacture missing extension data or label
a partial observation as exact.

## Privacy and resource boundaries

- SNI values are excluded by default. Set
  `Ja4ObserverConfig { include_server_name: true }` only when explicitly
  required by the operator.
- Cipher, signature, named-group, and ALPN lists are bounded before delivery.
- Opt-in SNI recording is capped at 255 UTF-8 bytes and marks the observation
  truncated when the value exceeds that bound.
- The built-in recorder is bounded and evicts the oldest observation.
- An observer callback panic is contained and does not abort certificate
  resolution.
- The standards-QUIC TLS builder disables 0-RTT; observations therefore do not
  create a replayable early-data path around the SHPH application handshake.
- The plugin is passive; it cannot change the handshake being observed.

## Verification

The transport test
`standards_quic::tests::optional_ja4_observer_records_real_client_hello`
establishes a real loopback Quinn/rustls connection and verifies that the
observer receives one bounded, partial observation while the SHPH application
handshake succeeds.

Focused validation:

```text
cargo test -p shph-transport ja4 --lib
cargo test -p shph-transport standards_quic --lib
```

This feature is an observability and lab-analysis aid. It is not a fingerprint
spoofing implementation and does not close SHPH's traffic-analysis or
anti-censorship risk.
