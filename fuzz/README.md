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
- `shroud2_datagram`: bounded Shroud 2 lab-envelope parsing and
  morphology-size selection.
- `phantom_one_envelope`: versioned Phantom One envelope parsing, bounded
  configuration, replay-window behavior, and sequence exhaustion.

## Run

From the repository root:

```bash
cd fuzz
cargo fuzz list
cargo fuzz run frame_decode -- -dict=shroud.dict -max_total_time=60
cargo fuzz run config_parse -- -max_total_time=60
cargo fuzz run audit_record -- -max_total_time=60
cargo fuzz run replay_window -- -max_total_time=60
cargo fuzz run shroud2_datagram -- -max_total_time=60
cargo fuzz run phantom_one_envelope -- -max_total_time=60
```

For a pinned Windows campaign, use the tracked concurrent wrapper after
installing `cargo-fuzz` and the matching nightly toolchain:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\run_fuzz_campaign_concurrent.ps1 `
  -MaxTotalTimeSeconds 21600
```

The default is six targets running concurrently for six hours. The wrapper
records one log and one summary row per target, captures the process exit code
after an explicit `WaitForExit()`, and records whether the libFuzzer completion
marker was present. On Windows with the MSVC AddressSanitizer runtime, it discovers
`clang_rt.asan_dynamic-x86_64.dll` under the installed Visual Studio tree and
adds its directory to the child-process path. The campaign is still
engineering evidence, not proof that all inputs or deployment environments are
safe.

If a long campaign is interrupted after one or more targets complete, resume
it without repeating completed logs:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\run_fuzz_campaign.ps1 `
  -RunsPerTarget 20000000 `
  -OutputDirectory .\benchmark-runs\fuzz-campaign-20260822 `
  -Resume
```

Do not use `cargo test --all-targets` as the fuzz-run gate: libFuzzer targets
are executable harnesses rather than Rust test binaries, so MSVC may report
`LNK1561` when Cargo tries to link them as tests. Use the wrapper above or the
individual `cargo fuzz run <target>` commands.

The `frame_decode` harness selects every current profile:
`balanced`, `low-latency`, `bulk`, `randomized-lab`, and `extreme-lab`.
The dictionary supplies the `SD` header and data/chaff frame markers so
mutations reach deeper framing branches sooner.

Corpus and crash artifacts are written below `fuzz/corpus/` and
`fuzz/artifacts/`; these paths are ignored by Git. Keep minimized,
security-relevant reproducer inputs under version control only after review.

CI performs a one-iteration smoke run for every target. That verifies the
harnesses compile and execute; it is not a substitute for a longer campaign.
