# SHPH Release Readiness

This document is the binding gate for release-profile claims. It turns
"implemented", "tested", and "ready to publish" into separate statuses.

The current release profile is defined in `docs/SUPPORT_MATRIX.md`:
authenticated TCP plus one separately validated OS-native TUN lane. The
experimental transports are not release blockers because they are explicitly
outside that profile; they are also not allowed to appear as production
capabilities.

## Gate status

Every gate must be recorded as one of:

- `PASS`: the command or host procedure completed successfully.
- `FAIL`: the command ran and found a defect.
- `SKIP`: a required capability or evidence source was unavailable.
- `BLOCKED`: the gate could not be attempted because an earlier prerequisite
  failed.

For release purposes, `SKIP` and `BLOCKED` are not passes. A release snapshot
is eligible only when every required gate is `PASS`, the tree is clean, the
provenance is recorded, and the claims match the support matrix.

## Gate groups

### 0. Provenance and cleanliness

Record:

- commit or tag;
- branch or detached state;
- Rust and Cargo versions;
- host OS and target triple;
- `Cargo.lock` checksum;
- clean-tree result;
- exact command output location.

Required commands:

```text
git status --short
git diff --check
rustc -Vv
cargo -V
```

Do not publish an evidence record from a dirty tree as a release result. Dirty
research captures must be labeled as such.

### 1. Source and dependency gates

Run from the repository root:

```text
cargo fmt --all -- --check
cargo metadata --format-version 1 --no-deps --locked
cargo check --workspace --all-targets --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --all-targets --locked
cargo build --workspace --release --locked
cargo check --manifest-path benchmarks/Cargo.toml --all-targets --locked
cargo check --manifest-path fuzz/Cargo.toml --all-targets --locked
cargo audit --deny warnings
```

On a disconnected workstation, `--offline` may be added only when the local
cache is known to contain every locked dependency. The result must state that
the offline cache was used.

The Windows MSVC lane requires a complete Visual C++ Build Tools installation,
including `link.exe`. A partial GNU/LLVM-MinGW shim does not close the native
MSVC gate and does not prove that a produced executable can run.

Use the collector to record the result without hiding failures:

```powershell
pwsh -File .\scripts\release_readiness.ps1 -AllowDirty
```

`-AllowDirty` is for an engineering snapshot only; it deliberately leaves the
result ineligible for release.

### 2. Functional controlled-lab gates

The TCP release lane must show:

1. two fresh identities;
2. both peer identity keys pinned;
3. an authenticated `send-once` / `recv-once` exchange;
4. a continuous `up` session with clean shutdown;
5. malformed configuration rejection without partial control-plane apply;
6. reconnect behavior with an isolated peer;
7. no secret material in the captured output.

The no-privilege starting point is:

```bash
./scripts/demo.sh all
```

The demo is necessary but not sufficient for native TUN or two-host claims.

### 3. Control-plane and containment gates

The focused tests must pass before any privileged campaign:

```text
cargo test -p shph-cli --test cli_control_plane --locked
cargo test -p shph-cli killswitch --locked
cargo test -p shph-tun firewall --locked
```

The operator campaign must separately record:

- dry-run plan;
- apply and reconcile;
- route/DNS rollback after normal shutdown;
- rollback after startup failure;
- killswitch policy installation and cleanup;
- crash or forced-termination leak behavior;
- exact privilege and host-tool prerequisites.

No planner or dry-run result is evidence that a privileged host policy worked.

### 4. Native TUN gates

Linux and Windows are separate campaigns. A result on one platform cannot
close the other.

Linux requires `/dev/net/tun`, `CAP_NET_ADMIN` or root, an isolated namespace
or dedicated host, packet injection, route/DNS checks, and two-host forwarding.
The available helpers are:

```bash
./scripts/native_tun_namespace_test.sh
./scripts/benchmark_native_tun.sh --iterations 20 --hold-ms 0
./scripts/benchmark_operator.sh --mode tun-namespace
```

Those helpers can legitimately report `SKIP`; they do not fabricate packet or
throughput evidence.

Windows requires a complete MSVC toolchain, a valid Authenticode-verified and
SHA-256-pinned Wintun runtime, elevation, adapter/session lifecycle, packet
send/receive, route/DNS rollback, reconnect, teardown, and a two-node run.
The benchmark wrapper explicitly keeps native TUN disabled unless a prepared
operator campaign supplies the missing evidence.

### 5. Security evidence gates

Run:

```powershell
pwsh -File .\scripts\security_evidence.ps1 -AllowDirty
```

Then review `docs/SECURITY_EVIDENCE.md` and attach:

- focused test output;
- fuzz target and duration;
- dependency advisory output;
- secret-redaction scan;
- threat-to-control mapping;
- unresolved findings and owner/next action.

This is an evidence pack, not an independent security audit.

## Evidence package layout

Each release candidate should contain:

```text
release-manifest/
  provenance.txt
  support-matrix.md
  gate-results.md
  security-evidence.md
  cargo-audit.txt
  test-output/
  native-linux/
  native-windows/
  checksums.txt
```

Paths, usernames, private keys, keystore contents, peer addresses, and
unredacted packet captures must be removed before publication.

## No-go conditions

Do not call the release profile ready when any of these is true:

- a required command is `SKIP` or `BLOCKED`;
- a Windows binary was produced with an unverified or incomplete runtime;
- native TUN evidence is replaced with WSL2, loopback, or unit-test results;
- route/DNS or killswitch cleanup was not observed after failure;
- the support matrix and README disagree;
- a benchmark is presented as a two-host or production result;
- a secret, private path, or operator credential appears in evidence.
