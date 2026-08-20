# Why Choose SHPH?

SHPH is a VPN-first secure-transport project for operators who want an
auditable, testable networking system rather than a black-box client.

It is not presented as a universal replacement for mature production VPNs.
The right question is which engineering problem you need to solve.

## The short answer

Choose SHPH when you value:

- an authenticated TCP-first data path with a visible hybrid post-quantum
  handshake;
- explicit peer identity and signing-key pinning;
- optional TUN and route/DNS control with dry-run and rollback paths;
- a small Rust workspace that can be tested, fuzzed, benchmarked, and inspected;
- a clear separation between stable release-profile behavior and experimental
  transport or morphology work; and
- an optional SOCKS5 underlay when the direct route is unavailable, without
  replacing SHPH's own end-to-end authentication.

The current release line is `v0.6.4-dev.2`. Its supported boundary is
controlled-lab networking, as defined by
[`docs/SUPPORT_MATRIX.md`](SUPPORT_MATRIX.md).

## What SHPH offers

| Capability | Practical value | Current boundary |
| --- | --- | --- |
| Hybrid authenticated handshake | Combines X25519 with ML-KEM-768 in the secure-default profile and binds the session to signed peer identity material | This is protocol and code-path evidence, not a claim of independent cryptographic certification |
| TCP-first secure transport | Provides a conservative default for authenticated framed traffic | Supported for controlled lab use; not a mature Internet-scale service |
| VPN-first operating model | Can create a TUN session and apply explicit address, route, DNS, NAT, MSS, or killswitch policy | Native packet forwarding and privileged host behavior remain platform-gated |
| Guided `host` / `join` workflow | Reduces setup steps and produces a shareable, identity-bound `shph://v1:` ticket | Ticket handling still requires normal operator protection; never publish private tickets |
| Fail-closed validation | Bounds configuration, frame sizes, replay state, handshake work, file inputs, and control-plane changes | A passing test proves the exercised path, not every deployment |
| Reachability add-on boundary | Can use a local SOCKS5/Xray-compatible underlay while preserving SHPH authentication and encrypted framing | The add-on is optional and does not make SHPH itself censorship-resistant |
| Evidence-oriented development | Includes unit/integration tests, fuzz targets, benchmark suites, release gates, and explicit non-claims | Native two-host, hostile-network, and production evidence require separate campaigns |

## How it fits beside alternatives

| If you are comparing SHPH with... | Prefer the alternative when... | SHPH is a better fit when... |
| --- | --- | --- |
| A mature production VPN | You need a long-established ecosystem, managed clients, broad support, or production SLA | You need an inspectable research/engineering workspace with explicit gates and controlled-lab TUN experiments |
| A generic SSH or TCP tunnel | You only need a simple port forward and do not need peer policy, replay protection, or a TUN control plane | You need authenticated peer enrollment, encrypted framing, session metrics, route policy, and testable failure behavior |
| A proxy or reachability tool | You only need an underlay relay or traffic reachability mechanism | You want the underlay to remain a transport aid while SHPH owns the authenticated endpoint and data-plane protocol |
| A QUIC or obfuscation experiment | You need a specialized standards or morphology experiment as the primary product | You want a conservative TCP release profile with experimental paths kept visibly separate |
| A hosted mesh/VPN service | You want zero-operations onboarding and a managed control plane | You need local key custody, local configuration, and the ability to inspect or modify the full path |

This is a positioning comparison, not a head-to-head performance ranking.
SHPH does not publish evidence that it is faster, safer, or more reachable than
every alternative.

## Choose SHPH if

- you are building or evaluating secure networking in a lab, testbed, or
  controlled deployment;
- you want the cryptographic, framing, identity, and control-plane boundaries
  visible in one repository;
- you need repeatable local regression checks rather than undocumented
  implementation claims;
- you want to experiment with TUN, Shroud morphology, standards QUIC, or
  reachability underlays while keeping the default path narrow; or
- you need a project that states what it does **not** prove.

## Do not choose SHPH if

Use a mature, independently reviewed product instead if you currently need:

- a production VPN guarantee, uptime/SLA, or large-scale fleet management;
- proven censorship resistance, DPI evasion, or browser/TLS fingerprint parity;
- completed native two-host throughput and packet-loss evidence on your target
  network;
- hardware-backed key custody through HSM, TPM, PIV, YubiKey, or PKCS#11; or
- a turnkey service with no operator-managed keys, routes, or host privileges.

## Decision checklist

Before adopting SHPH for a real deployment, verify:

1. The workflow is listed as supported in
   [`docs/SUPPORT_MATRIX.md`](SUPPORT_MATRIX.md).
2. The required host and privilege gates in
   [`docs/RELEASE_READINESS.md`](RELEASE_READINESS.md) are `PASS`, not `SKIP`.
3. Your threat model does not require claims SHPH explicitly excludes.
4. You can protect the local keystore, peer pins, and join tickets.
5. You have a rollback plan for routes, DNS, firewall policy, and TUN state.

SHPH's main advantage is transparency: the implementation, the tests, the
limits, and the missing evidence are intended to be visible together.
