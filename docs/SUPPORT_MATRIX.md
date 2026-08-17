# SHPH Support Matrix

This is the authoritative product-boundary document for the current
development line. If another page makes a broader claim, this matrix wins.

## Release profile

The SHPH release-readiness profile is intentionally narrow:

1. Authenticated TCP transport is the default control/data path.
2. One OS-native TUN path is validated per host campaign.
3. Linux native TUN and Windows Wintun are separate acceptance lanes.
4. Alternate transports and morphology features remain laboratory or research
   surfaces until they have their own interoperability, host, and security
   evidence.

This profile describes a controlled-network engineering release, not a
production VPN, censorship-resistant transport, or hostile-network security
claim.

## Current support levels

| Surface | Current level | Release-profile status | Evidence boundary |
| --- | --- | --- | --- |
| TCP `listen` / `connect` / `send-once` / `recv-once` | Supported for controlled lab use | In scope | CLI integration tests, demo, and locked workspace gates |
| Session `up` without native TUN | Supported for controlled lab use | In scope | Session, shutdown, reconnect, and control-plane tests |
| Linux native TUN | Implemented and capability-gated | In scope for a Linux host campaign | `/dev/net/tun`, privilege, route/DNS, killswitch, packet, and two-host evidence are separate gates |
| Windows Wintun | Wired; adapter/session smoke exists | In scope for a Windows host campaign only after packet evidence | Signed/hash-pinned runtime, elevation, packet I/O, rollback, reconnect, and two-host evidence remain required |
| Linux/Windows control-plane dry run | Supported | In scope | Planner and CLI tests; no host mutation is implied |
| Live route/DNS mutation | Implemented with rollback paths | Host-gated | Requires an isolated privileged operator campaign |
| Linux killswitch and MSS clamp | Implemented as opt-in controls | Host-gated | Unit/planner tests exist; privileged crash-leak and rollback evidence remain open |
| Windows WFP killswitch | Implemented as an opt-in policy backend | Host-gated | Requires elevated Windows policy and packet-path validation |
| Legacy `quic` UDP shim | Experimental | Out of release profile | Lab round trips and malformed-input tests only; not conformant QUIC |
| `quic-standard` | Experimental, host-gated | Out of release profile | Quinn/rustls and RFC 9221 implementation exists; live forwarding and operational trust evidence remain open |
| Shroud morphology profiles | Experimental lab instrumentation | Out of release profile | Benchmark and framing evidence only; no fingerprint or stealth claim |
| `offline-mesh` | Experimental filesystem adapter | Out of release profile | Bounded spool tests; no wireless discovery or delivery guarantee |
| `data-mule` | Experimental filesystem courier adapter | Out of release profile | Bounded file-envelope tests; no courier or hostile-filesystem guarantee |
| Identity discovery/provider boundary | Experimental library surface | Out of release profile | Local/provider-independent tests and benchmark notes; no automatic peer mutation |
| Hardware-backed key custody | Not implemented | Out of scope | HSM/TPM/YubiKey/PKCS#11 claims are prohibited |
| DPI evasion or censorship resistance | Not implemented | Out of scope | No production anti-observation claim is permitted |

## Status vocabulary

- **Supported for controlled lab use**: the documented workflow is exercised
  locally and is suitable for staged engineering; it is not a production
  guarantee.
- **Implemented and capability-gated**: code and focused tests exist, but
  required host privileges, platform runtime, or live-network evidence are
  still a prerequisite.
- **Experimental**: useful for research or measurement, but excluded from the
  release profile and not a supported deployment promise.
- **Out of scope**: do not imply the capability exists.

## Evidence rules

Evidence is valid only when its boundary is recorded:

- A unit or integration test proves the exercised code path, not a native
  packet or two-host deployment.
- A local benchmark proves the measured local workload, not VPN throughput or
  hostile-network behavior.
- A capability-gated test that prints `SKIP` is not a pass.
- WSL2, loopback, and shim results must not be merged into native Linux or
  native Windows TUN claims.
- Historical evidence remains useful for regression comparison, but cannot
  close a newer release gate without a current provenance record.

The binding release checklist is `docs/RELEASE_READINESS.md`. The security
mapping and redaction rules are in `docs/SECURITY_EVIDENCE.md`.
