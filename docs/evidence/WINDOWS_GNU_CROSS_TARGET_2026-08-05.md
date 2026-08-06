# Windows GNU Cross-Target Evidence — 2026-08-05

## Scope

This is Linux-hosted compilation evidence for target
`x86_64-pc-windows-gnu`. It does not claim native Windows execution or Wintun
runtime validation.

## Toolchain

System package installation is unavailable in this WSL environment. A
user-space MinGW toolchain was extracted outside the repository at:

```text
<local MinGW toolchain root>
```

The extracted toolchain is not mirrored or required by the source tree.

## Commands and Results

```text
cargo check --workspace --target x86_64-pc-windows-gnu --locked --offline
PASS

cargo clippy --workspace --all-targets \
  --target x86_64-pc-windows-gnu --locked --offline -- -D warnings
PASS

cargo build --workspace --target x86_64-pc-windows-gnu --locked --offline
PASS

cargo test --workspace --target x86_64-pc-windows-gnu --locked --offline --no-run
PASS
```

The first check exposed two real `windows-sys 0.61.2` import errors in
`shph-tun/src/windows.rs`; the imports for `GUID` and `FreeLibrary` were
corrected. Strict target Clippy then found and enabled fixes for a
Windows-only test import, a Windows keystore error constructor, and a
target-specific redundant `return`.

## Remaining Native Gates

- Execute the compiled Windows tests on a supported Windows host.
- Provision and independently verify the signed, deployment-approved
  `wintun.dll` with `SHPH_WINTUN_SHA256`.
- Validate administrator elevation, adapter creation, event waits, packet
  receive/send, teardown, route/DNS operations, reconnect, and rollback.
- Run two-machine Windows tunnel and performance tests.
