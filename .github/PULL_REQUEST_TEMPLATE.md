## Summary

<!-- Describe the behavior change and why it is needed. -->

## Validation

<!-- List commands run and their result. -->

- [ ] `cargo fmt --all -- --check`
- [ ] `cargo clippy --workspace --all-targets -- -D warnings`
- [ ] `cargo test --workspace`
- [ ] Relevant documentation updated

## Safety Checklist

- [ ] No private keys, keystores, credentials, raw two-host logs, or generated benchmark evidence are included.
- [ ] Security/release claims remain accurate and do not treat pending host evidence as complete.
- [ ] Windows mirror impact has been considered.
