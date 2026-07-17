# SHPH Fuzzing

This directory is a standalone `cargo-fuzz` workspace. It is intentionally
outside the production workspace so fuzz-only dependencies do not enter the
application lockfile or release artifacts.

## Prerequisites

```bash
rustup toolchain install nightly
cargo install cargo-fuzz --locked
```

## Targets

- `frame_decode`: bounded Shroud-cell framing and malformed-cell handling.
- `config_parse`: TOML configuration parsing and deserialization.
- `audit_record`: JSONL ratchet-audit record deserialization.
- `replay_window`: replay-window state transitions over arbitrary nonce
  sequences.

## Run

From the repository root:

```bash
cd fuzz
cargo fuzz list
cargo fuzz run frame_decode -- -max_total_time=60
cargo fuzz run config_parse -- -max_total_time=60
cargo fuzz run audit_record -- -max_total_time=60
cargo fuzz run replay_window -- -max_total_time=60
```

Corpus and crash artifacts are written below `fuzz/corpus/` and
`fuzz/artifacts/`; these paths are ignored by Git. Keep minimized,
security-relevant reproducer inputs under version control only after review.

CI performs a one-iteration smoke run for every target. That verifies the
harnesses compile and execute; it is not a substitute for a longer campaign.
