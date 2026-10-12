# Agent Instructions

These instructions apply to the repository unless a deeper `AGENTS.md`
provides more specific direction.

## Start here

- Read `internal/CONTEXT.md` and `internal/GUIDEMAP.md` when they exist. They
  are ignored, local-only maintainer notes and may be absent from another
  checkout; verify time-sensitive facts against the repository.
- Use `docs/DIRECTORY_GUIDE.md` for the broader repository map.
- Treat `docs/SUPPORT_MATRIX.md` as the authority for product support and
  claims, `docs/RELEASE_READINESS.md` for binding release gates, and
  `docs/PHANTOM_SHROUD_SCOPE.md` for experimental roadmap status.

## Preserve the worktree

- The canonical Linux checkout is normally `/home/mori/SHPH_working_copy`; the
  Windows mirror is normally `/mnt/d/FUNDING NEEDED/snap-shroud-rs`. Confirm
  the actual checkout before acting. They are separate working trees, not
  interchangeable paths.
- Inspect `git status --short` and relevant diffs before editing. Preserve
  existing modified and untracked work. Never use `git reset`, `git clean`, a
  broad checkout/restore, or an overwrite-style sync to discard unexplained
  changes.
- Keep changes focused. Do not reformat or rewrite unrelated files, commit, or
  create branches unless explicitly asked.
- `internal/` is local-only and ignored by Git. Do not copy it into public
  docs, release packages, or the Windows mirror.
- Before mirror work, inspect both trees and the exact dry-run. The sync script
  preserves each checkout's Git metadata, excludes root `Cargo.lock`, and
  excludes ignored files. Never acknowledge a dirty destination or prune
  destination-only files until each affected path has been reviewed.

## Source and evidence boundaries

- The root Cargo workspace contains nine crates, including `shph-snap/`.
  `shph-edge/` is a separate standalone crate with its own manifest and
  lockfile. Benchmarks and fuzzing are separate Cargo workspaces too.
- Modify the compiled crate implementation, not stale notes or similarly named
  historical files. Start from the crate paths in `internal/GUIDEMAP.md` and
  confirm workspace membership in `Cargo.toml`.
- A unit test proves only the exercised path; a loopback test is not external
  network evidence; a synthetic trace is not a packet capture; and a local
  benchmark is not complete-session performance. Record unavailable
  capabilities as `SKIP`, not `PASS`.
- Do not claim anonymity, censorship resistance, DPI evasion, browser parity,
  production VPN readiness, or an independent security audit unless the
  corresponding acceptance evidence exists. The 2026-09-28 roadmap checkpoint
  marks no package `VALIDATED`.
- Run active probes only against loopback or infrastructure the operator owns
  or is explicitly authorized to test. Do not run host-mutating, privileged,
  kill/crash, or live firewall/route campaigns without the user's explicit
  authorization and the documented safeguards.

## Validation

Source the Rust environment first when working in the usual Linux shell:

```bash
source "$HOME/.cargo/env"
```

For Rust changes, start with the narrow affected tests, then run the relevant
locked gates. The common workspace gates are:

```bash
cargo fmt --all -- --check
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo build --workspace --release --locked
```

Validate `shph-edge/` separately; workspace success does not cover it. Run its
default and optional HTTP/3 suites when those paths are affected. Use
`docs/TESTING.md`, `docs/RELEASE_READINESS.md`, and `fuzz/README.md` for the
complete commands and host-specific gates. Report exactly what ran and any
`FAIL`, `SKIP`, or `BLOCKED` result; do not imply omitted gates passed.
