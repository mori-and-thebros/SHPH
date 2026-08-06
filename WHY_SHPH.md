# Why SHPH

## The short version

SHPH (Shroud-Phantom) is an open-source secure-transport project for people
who need a system they can **inspect, test, and improve in public**.

The project is deliberately honest about its maturity. It has a functional,
authenticated encrypted transport, a TCP-first data plane, and optional
network-interface integration work. It does not claim to be a finished
production transport, a censorship-circumvention product, or a
fingerprint-evasion system. Funding helps turn a transparent research and
engineering base into independently validated, deployable infrastructure.

## The problem

Secure-networking projects are often difficult to evaluate:

- security claims can exceed the available evidence;
- prototype code may not have reproducible builds, tests, or release gates;
- platform support can be asserted without host-level validation;
- privacy and anti-censorship features can be conflated; and
- important hardening work can be invisible to users and funders.

SHPH addresses this by making technical scope, evidence, limitations, and
remaining delivery work explicit.

## What SHPH is building

SHPH is a Rust workspace for an authenticated, encrypted point-to-point
transport. Its core focus is the path from peer identity to a usable,
observable, fail-closed data plane:

- mutually authenticated session establishment with pinned peer identity and
  signing keys;
- transcript-bound X25519 plus ML-KEM-768 key establishment for the
  `secure-default` profile;
- a separate Ed25519 signing key for real handshake authentication;
- ChaCha20-Poly1305 framed data protection with fail-closed replay handling;
- a stable TCP-first path for session, one-shot, and continuous exchange;
- experimental transport research paths that remain explicitly labeled:
  a QUIC-like UDP shim, a standards-QUIC module, offline mesh, and data mule;
- Shroud-cell and traffic-morphology research surfaces with benchmarks and
  lab-only profile controls;
- optional Linux TUN and Windows Wintun integration for testing how a secure
  transport behaves at the network-interface boundary;
- route and DNS control-plane apply, rollback, reconcile, and dry-run support;
- reproducible Rust builds, tests, CI, benchmarks, fuzzing targets, and
  operator validation scripts.

The project keeps stable, experimental, and host-gated capabilities separate.
That distinction is central to how SHPH is developed and communicated.

## Why this approach matters

### Evidence before claims

SHPH uses phase gates and release checklists instead of treating a successful
compile as a deployment claim. Native Linux two-host TUN evidence and
privileged Windows Wintun evidence are tracked as real delivery requirements,
not silently substituted with local or WSL benchmarks.

### A transport stack worth inspecting

SHPH is not positioned as a clone or replacement for an established VPN. Its
value is in the research and engineering surface around an authenticated
transport: explicit peer policy, hybrid session establishment, framed
encrypted exchange, replay handling, reconnect behavior, observability,
control-plane lifecycle, and carefully scoped experiments.

The project separates X25519 key agreement from Ed25519 handshake signing.
Session keys bind both classical and post-quantum shared secrets, while peer
identity and signing-key pinning is required at the CLI session boundary. This
gives reviewers concrete protocol roles, code paths, and tests to examine
rather than a vague "encrypted tunnel" assertion.

### Experimental work stays visible

Transport experimentation is useful only when it is not confused with a
shipping claim. SHPH keeps its QUIC-like UDP shim, standards-QUIC module,
Shroud profiles, JA4-compatible observability, offline mesh, and data-mule
work visibly separated from the stable TCP-first path.

That lets contributors investigate transport behavior, packet framing,
morphology, and operational tradeoffs without presenting research features as
stealth, censorship resistance, or production interoperability.

### Integration and operational failure are designed to be visible

Invalid inputs, unexpected peers, malformed frames, missing native TUN
prerequisites, missing Wintun provenance, and unsafe control-plane inputs fail
explicitly. The TUN work is opt-in and host-gated; it does not silently fall
back to a stub adapter. Dry-run control-plane mode is the safe default for
evaluation.

### The project is useful to review today

SHPH is not a slide deck. Reviewers can build it, run the demo, inspect its
security boundaries, execute targeted tests, and see which milestones remain
open. The source, documentation, benchmark methodology, and limitations are
available for public scrutiny.

## What funding enables

Funding is directed toward verifiable engineering outcomes:

1. **Transport validation:** complete and publish controlled native Linux
   two-host data-plane results and Windows Wintun lifecycle/packet-path
   evidence where the transport meets real host networking.
2. **Hardening:** expand fuzzing, protocol and platform-specific tests,
   dependency review,
   and independent security review.
3. **Operations:** improve configuration, key lifecycle, diagnostics,
   service-management, installer, and rollback behavior.
4. **Transport research:** mature experimental paths only when their
   specifications, security model, interoperability, and evidence justify
   promotion.
5. **Sustainable OSS maintenance:** keep reproducible builds, public issue
   intake, private vulnerability reporting, documentation, and release
   discipline maintained over time.

Each outcome can be paired with code, tests, operator evidence, and a
documented claim boundary.

## What SHPH does not claim

SHPH must not be represented as providing the following today:

- a replacement for WireGuard or another established VPN;
- production-hardened VPN service;
- censorship resistance, DPI evasion, or browser/TLS fingerprint parity;
- production-ready standards QUIC deployment;
- hostile-network traffic-analysis resistance;
- HSM, TPM, PKCS#11, YubiKey, or Shamir-quorum production key management;
- a full constant-time or side-channel audit of the stack.

The detailed non-claims and threat model are in `SECURITY.md` and
`docs/RISK_MATRIX.md`.

## How to evaluate SHPH

Start with these public artifacts:

1. `FIVE_MINUTE_QUICKSTART.md` — establish a local authenticated,
   encrypted TCP exchange.
2. `CONTRIBUTING.md` — reproduce formatting, lint, test, and locked-build
   checks.
3. `SECURITY.md` — review the current threat model and explicit exclusions.
4. `docs/FUNDERS.md` — map capabilities and milestones to verification steps.
5. `ROADMAP_OSS_AND_DELIVERY.md` and `docs/MILESTONE_SCORECARD.md` — review
   delivery sequencing and open gates.
6. `docs/NATIVE_LINUX_TWO_HOST_VALIDATION.md` and
   `docs/NATIVE_TUN_STATUS_2026-08-04.md` — see the remaining native-platform
   evidence requirements.

## Invitation

SHPH is an OSS project that welcomes technical review, testing, contribution,
and funding partnership. The goal is not to ask reviewers to trust an
unverified security claim; it is to give them a clear system, clear evidence,
and a clear path for helping move the project forward.
