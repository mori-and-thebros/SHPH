# SHPH Release Readiness

This document is the binding gate for release-profile claims. It turns
"implemented", "tested", and "ready to publish" into separate statuses.

The current release profile is defined in `docs/SUPPORT_MATRIX.md`:
authenticated TCP plus one separately validated OS-native TUN lane. The
experimental transports are not release blockers because they are explicitly
outside that profile; they are also not allowed to appear as production
capabilities.

## Next milestone: TCP/native-TUN lifecycle reliability

Complete the following in order for the TCP/native-TUN release milestone.
The separately scoped experimental program in
[PHANTOM_SHROUD_SCOPE.md](PHANTOM_SHROUD_SCOPE.md) may proceed alongside it;
experimental progress does not close these gates or broaden release claims.
Existing experimental functionality keeps its regression checks; fixes needed
for shared-code correctness remain in scope.

1. **Secret-safe diagnostics.** Redact session keys and keystore passwords in
   debug formatting, including nested handshake state. Verify compact and
   pretty formatting with regression tests. Keep raw private-key storage types
   free of `Debug` implementations.
2. **Local lifecycle baseline.** Run the core tests, CLI control-plane tests,
   and bounded repeated-session reliability suite below on the candidate.
   Resolve failures before privileged acceptance. These tests do not close
   native packet-forwarding gates.
3. **Repeat the selected native lane.** Start with the previously evidenced
   Windows-to-Linux direct-TCP IPv4 configuration. Record both hosts, runtime
   hashes, configuration, candidate revision, and exact commands. Repeat
   authenticated forwarding, peer restart/reconnect, and normal shutdown on
   three fresh sessions. Capture adapter, route, DNS, process, and firewall
   state before and after each session; require no unexplained residue.
4. **Failure and containment acceptance.** On dedicated hosts, record startup
   failure rollback, Ctrl+C teardown, and forced termination separately.
   Observe packet behavior during peer outage and forced termination with
   the killswitch enabled, then verify explicit cleanup. Policy presence alone
   cannot pass the packet-leak gate. Follow the host procedures in gate groups
   3 and 4 and record unavailable capabilities as `SKIP`.
5. **Candidate evidence.** Close every required gate for the selected release
   profile with clean-tree provenance. Update the support matrix only for
   behavior observed in that campaign. Other host pairings, DNS/IPv6, and
   alternate transports require separate evidence before expanding claims.

Local starting commands (no native interface or firewall setup):

```text
cargo test -p shph-core --locked
cargo test -p shph-cli --test cli_control_plane --locked
cargo test -p shph-cli --test cli_reliability --locked -- --test-threads=1
```

The milestone remains open until the required host results and release gates
pass. A green local suite or historical campaign does not complete it.

## SHPH-native SNAP acceptance lane

SNAP v1 is opt-in and remains outside the release profile until this lane is
closed. Its planner and adapter code must not be described as release-supported
based on parsing or loopback evidence alone. The local starting checks are:

```text
cargo test -p shph-snap --locked
cargo test -p shph-transport snap_adapter --locked
cargo test -p shph-cli --test cli_snap --locked
```

The paired SHPH tests must cover each selected adapter, pinned-peer
authentication and wrong-peer rejection, adapter setup failure, allowed and
forbidden fallback, reconnect, and shutdown. Candidate ordering and attempt and
elapsed-time budgets must remain bounded. Python SNAP may be used as the
behavioral reference; Python SierraNode session interoperability is not part
of this lane.

Before SNAP enters a release profile, capture adapter-specific acceptance on
each claimed platform. Exercise TUN forwarding, route and DNS behavior, and
killswitch containment wherever the adapter is used with those controls. Run
external bridges and relays only on operator-owned or explicitly authorized
services with their declared service contracts. Record unavailable Linux,
Windows, carrier, or service evidence as `SKIP`; it does not close this lane.
The release-readiness collector records separate required rows for
`snap-linux-adapter-acceptance`, `snap-windows-adapter-acceptance`, and
`snap-external-service-acceptance`; each needs its own evidence. The broader
`native-tun-two-host` gate remains separate.
Supply those manifests and their hashed artifacts with
`-SnapEvidenceDirectory <path>`; their exact schema and adapter coverage are
defined in [`SNAP_ACCEPTANCE_EVIDENCE.md`](SNAP_ACCEPTANCE_EVIDENCE.md). If a
manifest is absent, the collector records `SKIP`. Malformed or source-mismatched
evidence records `FAIL`. Hash and schema validation does not replace review of
the underlying host results or operator service contracts.
The current support level and evidence boundary are listed in
[`SUPPORT_MATRIX.md`](SUPPORT_MATRIX.md).

## Experimental Shroud 3 and onion prototype checks

These checks exercise opt-in research surfaces outside the release profile;
their success does not make either surface release-supported:

```text
cargo test -p shph-transport shroud3 --locked
cargo test -p shph-transport onion --locked
cargo test -p shph-transport --test onion_process --locked
cargo build -p shph-transport --bin shph-onion-relay --release --locked
```

The relay process test uses three loopback relay processes and an SHPH
destination. Focused onion tests also cover circuit exhaustion, malformed
setup, a stalled destination, lifetime closure, and shutdown with an incomplete
TLS setup. This is process-level local evidence only. Independent protocol
review, authorized external relay operation, full-session measurements, and
native-TUN route/DNS/killswitch containment remain separate gates. Shroud 3
has an explicit Linux `host`/`join`/`up` opt-in for standards-QUIC native-TUN
sessions; both peers must select it. Its authenticated loopback bridge-framing
test does not open a host TUN or establish two-host interoperability. It is not
part of the default release behavior.

The current Shroud 3 implementation has an independent bounded workload and
joint size/delay engine; it does not reuse Shroud 2's encoder or size classes.
The local benchmark compares synthetic Shroud 2 and Shroud 3 workloads and has
a separate benchmark-only cover-policy arm. Those runs measure in-memory
envelopes, not carrier packet captures. No authorized representative captures
are available, so capture fitting and held-out passive-classifier effectiveness
are **BLOCKED**. Active-probe evaluation for the `shph-edge` front door is a
separate evidence lane; loopback probes do not close an owned-host campaign.

The local HTTP/2 regression test compares identical denial status, content
type, and body for missing, invalid, expired, and replayed capabilities. It
also confirms the connection remains usable and that the backend sees only the
authorized first use. The updated operator probe summarizes the replay denial
response and timing. No run of that operator probe against a live edge was
recorded for this change; live service and owned-host campaigns remain open.

On Linux systems that permit user/network namespaces and expose `/dev/net/tun`,
[`validate_shroud3_tun_namespace.sh`](../scripts/validate_shroud3_tun_namespace.sh)
adds a real packet-path check for the experimental Shroud 3 bridge. It starts
two pinned SHPH peers in separate nested network namespaces, carries a UDP
echo through both TUN devices over a namespace-local veth underlay, and checks
graceful shutdown cleanup. Its addresses and routes are confined to those
temporary namespaces. Even a `PASS` is local one-kernel evidence; it does not
replace the selected native two-host release lane or close Shroud 3 host,
containment, interoperability, or performance gates.

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
cargo clippy --manifest-path benchmarks/Cargo.toml --all-targets --locked -- -D warnings
cargo test --manifest-path benchmarks/Cargo.toml --all-targets --locked
cargo build --manifest-path benchmarks/Cargo.toml --release --locked
cargo check --manifest-path fuzz/Cargo.toml --all-targets --locked
cargo clippy --manifest-path fuzz/Cargo.toml --all-targets --locked -- -D warnings
cargo audit --deny warnings
(
  cd benchmarks
  cargo audit --deny warnings
)
(
  cd fuzz
  cargo audit --deny warnings
)
(
  cd shph-edge
  cargo audit --deny warnings
)
cargo test -p shph-cli --test cli_reliability --locked -- --test-threads=1

# standalone owned-domain edge relay prototype
cargo test --manifest-path shph-edge/Cargo.toml --all-targets --locked
cargo clippy --manifest-path shph-edge/Cargo.toml --all-targets --locked -- -D warnings
cargo build --manifest-path shph-edge/Cargo.toml --release --locked
cargo check --manifest-path shph-edge/Cargo.toml --features http3 --all-targets --locked
cargo clippy --manifest-path shph-edge/Cargo.toml --features http3 --all-targets --locked -- -D warnings
cargo test --manifest-path shph-edge/Cargo.toml --features http3 --all-targets --locked

# Windows only, from a Visual Studio developer shell
cargo build --workspace --all-targets --target x86_64-pc-windows-msvc --locked
cargo build --workspace --release --target x86_64-pc-windows-msvc --locked
cargo build --manifest-path benchmarks/Cargo.toml --release \
  --target x86_64-pc-windows-msvc --locked
```

The fuzz workspace contains libFuzzer harnesses and is intentionally checked
with `cargo check` and Clippy rather than a normal `cargo build --release`.
Fuzz execution requires the pinned nightly toolchain and `cargo-fuzz`; use the
campaign commands in `scripts/run_fuzz_campaign.ps1` or `fuzz/README.md`.

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

The collector packages only after the current platform's release-build gate
passes, and runs benchmark smoke profiles only after the matching benchmark
build passes. It uses the explicit Windows MSVC output paths. Existing binaries
left in `target/` by earlier runs do not count as current-run evidence.

On a Windows host with only Windows PowerShell 5.1 installed, use:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\release_readiness.ps1 -AllowDirty
```

`-AllowDirty` is for an engineering snapshot only; it deliberately leaves the
result ineligible for release.

The collector also runs the standalone benchmark smoke, pinned fuzz smoke,
explicit edge HTTP/3 checks, and sanitized package gate by default. Use
`-SkipBenchmarks`, `-SkipFuzzSmoke`, `-SkipHttp3`, or `-SkipPackaging` only
when the omission is recorded as an engineering `SKIP`. `-SkipBuild` and
`-SkipTests` are similarly explicit and never turn an incomplete snapshot into
a release pass.

The Windows native-TUN validator accepts a custom evidence directory so
successive captures cannot overwrite one another:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\validate_windows_tun.ps1 `
  -OutputDirectory .\benchmark-runs\windows-native-<date>
```

The elevated single-host forced-termination/WFP sequence is captured by:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass `
  -File .\scripts\validate_windows_wfp_crash.ps1 `
  -Binary .\target\release\shph.exe `
  -Wintun .\wintun.dll
```

The current record is
[`evidence/WINDOWS_WFP_CRASH_VALIDATION_2026-09-01.md`](evidence/WINDOWS_WFP_CRASH_VALIDATION_2026-09-01.md).
It shows seven SHPH-owned WFP filters before and after hard termination and
zero after an explicit `shph down`, plus clean local residue checks. This is
single-host policy-persistence and operator-cleanup evidence; it does not prove
automatic crash-time WFP cleanup, packet-leak prevention, or either
Windows-to-Windows or Linux-to-Linux forwarding.

For a release candidate, build the platform binary and create a sanitized
package without `--allow-dirty`:

```text
python scripts/package_release.py --binary target/release/shph \
  --output dist/shph-package
```

Use `target/release/shph.exe` for Windows. The package manifest and
`SHA256SUMS` file are provenance/integrity evidence for the selected payload.
The packager's allowlist is intentionally narrower than the repository and
does not include deployment files, scratch output, raw evidence, keystores, or
internal maintainer guidance.

The historical September 2, 2026 engineering package check passed the manifest
file-size/hash checks, `SHA256SUMS` verification, exact public allowlist, and
secret-boundary review for the then-current version `0.6.6-dev.2`. The capture
was made from a dirty checkout and the local Windows executable was not
Authenticode-signed, so it was not a publishable release artifact. The current
`v0.6.7-dev` candidate still requires a clean-tree package run from the
approved revision and completion of the project's artifact-signing step. The
package did not include `docs/evidence/`, `benchmark-runs/`, keystores,
credentials, or runtime DLLs.

### 2. Functional controlled-lab gates

The TCP release lane must show:

1. two fresh identities;
2. both peer identity keys pinned;
3. an authenticated `send-once` / `recv-once` exchange;
4. a continuous `up` session with clean shutdown;
5. malformed configuration rejection without partial control-plane apply;
6. reconnect behavior with an isolated peer;
7. no secret material in the captured output.
8. repeated fresh-process sessions complete under the bounded reliability test.

The no-privilege starting point is:

```bash
./scripts/demo.sh all
```

The demo is necessary but not sufficient for native TUN or two-host claims.

### 2.5 Reproducible failure and edge campaigns

Run the bounded operator campaigns described in
`docs/OPERATOR_CAMPAIGNS.md` when changing lifecycle, reconnect, endpoint,
control-plane, or packet-boundary behavior:

```bash
python scripts/operator_campaigns.py reconnect
python scripts/operator_campaigns.py soak --sessions 10
python scripts/operator_campaigns.py ipv6 --sessions 3
python scripts/operator_campaigns.py dns
python scripts/operator_campaigns.py pmtu --host <literal-ip>
python scripts/operator_campaigns.py crash --config <prepared-config> \
  --confirm-kill --up-arg=--no-tun --cleanup
```

The default DNS campaign is dry-run and does not mutate host state. Crash mode
requires an explicit kill acknowledgement. A local IPv6, PMTU, reconnect, or
soak `PASS` is narrow process/socket evidence and does not close a native-TUN,
two-host, Internet, or long-duration release gate. A campaign exit code `3`
must be recorded as `SKIP`, not converted to `PASS`.

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

The control-plane planner also rejects semantically duplicate routes,
underlay-bypass routes, and DNS servers before applying any host mutation.
This is a deterministic safety property; it does not prove that an operating
system, network manager, or firewall will accept or retain the resulting
policy.

### 3.5 Owned edge relay prototype

`shph-edge/` is a standalone, opt-in prototype and is validated independently
from the SHPH workspace. Its checks include:

- numeric, non-zero backend socket addresses;
- paired TLS certificate/key configuration;
- bounded capability tokens, replay state, streams, connections, and relay
  bytes;
- loopback-only unauthenticated SOCKS5 listening;
- bounded HTTP/2 and optional HTTP/3 carrier behavior;
- graceful cancellation and task reaping on Ctrl+C/SIGTERM.

The edge process must use an owned TLS endpoint and an explicitly configured
backend. It is not a public proxy, does not impersonate third-party sites,
and does not establish browser fingerprint parity, anonymity, or
censorship-resistance claims. The standalone test suite is code-path evidence,
not two-host or hostile-network evidence.

### 4. Native TUN gates

Linux and Windows are separate campaigns. A result on one platform cannot
close the other.

Linux requires `/dev/net/tun`, `CAP_NET_ADMIN` or root, an isolated namespace
or dedicated host, packet injection, route/DNS checks, and two-host forwarding.
The cross-platform Windows-to-Linux direct-TCP campaign is now recorded in
`docs/evidence/CROSS_PLATFORM_NATIVE_TUN_VALIDATION_2026-08-25.md`; it closes
that specific IPv4 forwarding lane, but not the dedicated Linux/Linux campaign
or the standards-QUIC lane.
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
The cross-platform report closes packet forwarding and one service-restart
reconnect path for one direct-TCP IPv4 configuration; it does not close
Windows-to-Windows operation, automatic crash-time WFP cleanup, or packet-leak
prevention.
The dated August 25 record closes only the signed runtime, lifecycle,
temporary route/DNS rollback, and loopback WFP smoke portions.
The dated September 1 record adds single-host hard-termination persistence and
explicit WFP cleanup evidence; it does not replace the required two-node or
automatic crash-leak campaign.
The benchmark wrapper explicitly keeps native TUN disabled unless a prepared
operator campaign supplies the missing evidence. Do not merge the
cross-platform direct-TCP result with standards-QUIC, Xray, IPv6, DNS, PMTU, or
long-duration performance claims.

### 5. Security evidence gates

Run:

```powershell
pwsh -File .\scripts\security_evidence.ps1 -AllowDirty
```

The Windows PowerShell 5.1 equivalent is:

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\security_evidence.ps1 -AllowDirty
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
- automatic crash-time WFP cleanup or packet-leak prevention is claimed from
  policy-state inspection alone;
- the support matrix and README disagree;
- a benchmark is presented as a two-host or production result;
- a secret, private path, or operator credential appears in evidence.
