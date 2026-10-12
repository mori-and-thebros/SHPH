# Quinn `0.11.19` source-tag validation — 2026-10-12

This is engineering validation for the `quinn-proto 0.11.19` lockfile update.
It is not a registry-backed locked build or release-candidate evidence.

## Source and method

- Upstream tag: `quinn-proto-0.11.19`
- Upstream source commit: `8192ed399a26a6e8f0aba43d10ec8badaa5b905e`
- The crates.io package archive was unavailable in this environment. Direct
  crates.io requests timed out; the configured rsproxy download redirected to
  a host that also timed out.
- To continue validation, Cargo used a temporary command-line patch to the
  local checkout of the exact upstream tag. No tracked manifest was changed.
  These runs were offline and did not use `--locked`, because Cargo must record
  the temporary path source while building.
- Afterward, all four original registry lockfiles were restored byte-for-byte
  and re-audited. Their SHA-256 hashes are recorded below.

## Results

Windows native host, with the temporary source-tag patch:

- Root workspace: `cargo check --workspace --all-targets`, Clippy with warnings
  denied, `cargo test --workspace --all-targets`, and release build — **PASS**.
- Benchmark workspace: all-target check, Clippy with warnings denied,
  all-target tests, and release build — **PASS**. The all-target test command
  also ran the Criterion harness successfully using Plotters because Gnuplot
  was unavailable.
- Fuzz workspace: all-target check and Clippy with warnings denied — **PASS**.
  No new `cargo-fuzz` campaign was run in this source-tag validation.
- Standalone `shph-edge`: all-target check, Clippy with warnings denied,
  all-target tests, and release build — **PASS**.
- `shph-edge` HTTP/3 feature: all-target check, Clippy with warnings denied,
  and all-target tests — **PASS**.

Linux WSL2, with the same temporary source-tag patch:

- Root workspace all-target check, Clippy with warnings denied, all-target
  tests, and release build — **PASS**.
- Standalone `shph-edge` default and HTTP/3 check, Clippy, and test suites,
  plus its default release build — **PASS**.
- Benchmark all-target check, Clippy, and tests, and fuzz check and Clippy —
  **PASS**. The Linux benchmark release build exited successfully, but Cargo
  warned that the `0.11.19` patch was unused and compiled `quinn-proto 0.11.18`;
  that result is not counted as `0.11.19` source-tag validation. The Windows
  benchmark release build did compile the patched `0.11.19` source.

Every command above exited successfully. These results establish that SHPH
builds and tests against the code at the upstream tag on the tested hosts.
They do not verify the published `.crate` archive, its locked checksum, registry
resolution, package contents, or release artifacts. The standard registry
command `cargo check --workspace --all-targets --locked --offline` remains
blocked because `quinn-proto 0.11.19` is not present in the Cargo cache.

## Archive checksum verification

- The official crates.io index entry for `quinn-proto 0.11.19` records checksum
  `0e750cca55fe4f0439a15d0bb529da9651e79993e8e72c61a899a36d462befbe`, matching
  all four repository lockfiles.
- A local `cargo package --no-verify --allow-dirty --offline` run from the tag
  source generated an archive with SHA-256
  `486785378C35D721C4F9B19E3727C81BCC63C34A9E87DA3643F27F2F85E2AAC7`. It does
  **not** match the crates.io checksum and is not accepted as a substitute or
  release artifact.
- Reproducing that generated archive from the tag required re-resolving the
  upstream workspace lock against locally available index metadata. The result
  proves only that the tag source packages; it does not prove that the published
  `.crate` archive is present or identical.
- Direct crates.io and rsproxy archive requests timed out at the time of this
  October 12 source-tag validation. The later locked registry validation is
  recorded in [`LOCKED_VALIDATION_2026-10-13.md`](LOCKED_VALIDATION_2026-10-13.md).
- The current-lock Windows release collector at 2026-10-12T19:55:47Z also
  failed to resolve `rsproxy.cn`; it recorded the affected locked compilation
  and test gates as `FAIL`, not `PASS`. These October 12 results were
  superseded by the October 13 locked validation linked above.
- After fixing the collector's stale-binary gate, the full Windows run at
  2026-10-12T20:12:34Z recorded 13 `PASS`, 29 `FAIL`, 3 `BLOCKED`, 4 `SKIP`,
  and one dirty-tree `WARN`. The build failures remain caused by the unavailable
  registry archive and mirror transfer failure. Packaging and both benchmark
  smokes were correctly `BLOCKED` after their build prerequisites failed; the
  four skips are the two-host TUN and three SNAP host/service gates. This is
  dirty October 12 engineering evidence, not a candidate result. The later
  October 13 collector result is summarized in the linked validation record.
- The first October 13 `cargo fetch --locked` attempt failed at the configured
  rsproxy mirror. A later download from the official static archive endpoint
  succeeded and matched the lockfile checksum; locked validation then passed.
  See [`LOCKED_VALIDATION_2026-10-13.md`](LOCKED_VALIDATION_2026-10-13.md).

## Restored lockfiles

The registry lockfiles were restored from byte-for-byte backups after the
temporary path-patch runs. The combined `cargo audit --no-fetch --deny
warnings --deny yanked` scan passed for each file against RustSec database
HEAD `57dcc0f2192e025138907a495c1ac9a7e1e3e123` (1,307 advisories):

| Lockfile | SHA-256 |
| --- | --- |
| `Cargo.lock` | `DCAF3743733DB4EF38925FFA8542486B1CCC85E7A98BD092BB7721559C6067D0` |
| `benchmarks/Cargo.lock` | `1BE973D8109EE618BDEE9044D2F274749D9669615E8D06867AEB3E23C1269DC0` |
| `fuzz/Cargo.lock` | `4A9C8DE97E52FFE3296DF2B684DB0A89EBE4880BD0ED856572D4DC783F1750F8` |
| `shph-edge/Cargo.lock` | `1968948D8EAF5633772E085E7CD0EF5A96BC7A6208A48288F2C2579C4B47B66D` |

Host-specific two-host TUN, Linux and Windows SNAP adapter acceptance, and
authorized external-service evidence remain separate release gates.
