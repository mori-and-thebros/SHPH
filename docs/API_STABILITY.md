# SHPH API Stability Policy

This is the Phase B.2 "freeze API changes during validation window"
deliverable from `ROADMAP_OSS_AND_DELIVERY.md`. It defines what counts as the
SHPH public API, the current stability guarantees, and the rules that hold
during a **validation window** (the period a checkpoint is under external
review).

## 1. Current versioning

- Workspace version: `0.6.3-dev.2` (see root `Cargo.toml`). `v0.4.0` added hybrid
  post-quantum key exchange (ML-KEM-768) to the handshake (`shph/4`). The
  unreleased profile work adds the breaking, explicitly separated `shph/5`
  `secure-default` and `classical-lab` protocol identities. `v0.3.0` made the
  handshake signature a real Ed25519 signature (protocol bump `shph/3`).
- SHPH is **pre-1.0.** Per SemVer, `0.x.y` changes may break the API in any
  `0.minor` bump. This document narrows that freedom during validation windows.

## 2. What is the "public API"

SHPH's public API has three surfaces, with **different** stability tiers:

### Tier 1 — CLI (`shph` binary)
- Stable within a checkpoint: the subcommands and their flags
  (`init`, `add-peer`, `list-peers`, `show-public-key`, `show-signing-public-key`,
  `show-config`, `status`, `doctor`, `send-once`, `recv-once`,
  `up`, `listen`, `connect`) and the `--config`, `--transport`, `--text`,
  `--bind`, `--peer`, and `--json` flags.
- **Freeze rule:** no subcommand or flag is *removed* or *renamed* during a
  validation window. Additive flags are allowed.

### Tier 2 — Config schema (`docs/`-referenced TOML)
- The `[session]`, `[control_plane]`, and identity/peer config keys.
- **Freeze rule:** existing keys keep their names and accepted values. New keys
  must be optional with safe defaults; removing a key is a breaking change.

### Tier 3 — Library crates (`shph-core`, `shph-config`, etc.)
- The `pub` items exposed by each crate (e.g. `shph_core::crypto::IdentityKeyPair`,
  `shph_core::handshake::{build_hello, verify_and_derive}`,
  `shph_core::framing::{encode_cell, decode_cell}`).
- **Status: unstable.** Library crates are `0.1.0` and are **not** a committed
  stable API. Downstream embedding of these crates is at the consumer's risk.
- **Freeze rule:** even though unstable, signature-breaking changes to the
  crypto/handshake/framing entry points require a CHANGELOG entry and a
  rationale during a validation window.

## 3. Validation-window freeze rules

While a checkpoint tag (`checkpoint-phaseX-Y.Y.Z`) is under external review:

1. **No breaking Tier-1 (CLI) or Tier-2 (config) changes.** Additive changes
   are permitted if they do not alter existing behavior.
2. **Tier-3 (library) breaks allowed only with** a documented rationale in
   `CHANGELOG.md` and a note in this file.
3. **Bug fixes are allowed**, including security fixes, even if they change
   behavior — but a behavior-changing fix must be called out in the CHANGELOG
   and, where possible, gated behind a flag for one checkpoint.
4. **Dependency bumps** that stay within SemVer-compatible ranges are allowed.
   A major-version bump of a runtime dependency (e.g. `ring`, `tokio`) requires
   a checkpoint note.

## 4. How to propose a breaking change

1. Open an issue labeled `breaking-change` describing the surface, the reason,
   and the migration path.
2. If inside a validation window, defer to the next checkpoint.
3. Record the change in `CHANGELOG.md` under a new `[Phase X.Y]` heading.

## 5. Exceptions

Security fixes (per `docs/SECURITY_REPORTING.md` and `SECURITY.md`) override
the freeze. A security fix may break an API; it is documented as such and
ships under the coordinated-disclosure SLA rather than waiting for the window
to close.
