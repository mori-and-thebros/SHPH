# GitHub-hosted benchmark campaigns

SHPH publishes two complementary benchmark layers:

1. The standalone runner in `benchmarks/src/main.rs` exercises longer local
   campaigns: crypto, framing, dataplane loops, Shroud profiles, Shroud2
   morphology, QUIC-shim loopback, identity/provider behavior, wire accounting,
   replay/cookie evidence, bounded defensive rejection paths, and impairment
   models.
2. The Criterion harness in `benchmarks/benches/criterion.rs` measures focused
   microbenchmarks for the same core paths with statistical warmup and
   regression comparison.

The CI workflow runs both layers on `ubuntu-latest` and `windows-latest` for
pushes to `main`, version tags, manual dispatches, and the scheduled campaign.
Pull requests retain the short benchmark smoke job; the full campaign is kept
out of pull requests so review feedback is not delayed by long-running
measurements.

## Triggering a campaign

From the GitHub Actions page, choose `CI`, select **Run workflow**, and run it
from the desired branch. Scheduled runs use the repository's default branch.
Each full run uploads two artifacts:

- `shph-benchmarks-ubuntu-<run-id>`
- `shph-benchmarks-windows-<run-id>`

Artifacts contain the custom runner captures for `all` and `extended`, Criterion
logs and reports, and a small provenance file with commit, runner, toolchain,
campaign, scope, and determinism labels. The retention period is 30 days. The
Windows smoke job also runs the focused `defensive` suite explicitly; the full
`all` suite includes it as well.

Equivalent local commands are:

```bash
cargo +1.96.0 build --release --manifest-path benchmarks/Cargo.toml --locked
./benchmarks/target/release/shph-benchmarks \
  --profile secure-default --suite all --iterations 100 --frames 10000
./benchmarks/target/release/shph-benchmarks \
  --profile secure-default --suite extended --iterations 100 --frames 10000
./benchmarks/target/release/shph-benchmarks \
  --profile secure-default --suite defensive --iterations 2000 --frames 1
bash ./scripts/benchmark_criterion.sh
```

On Windows:

```powershell
cargo +1.96.0 build --release `
  --manifest-path benchmarks/Cargo.toml `
  --target x86_64-pc-windows-msvc --locked
.\scripts\benchmark_windows.ps1 `
  -Suite all -Iterations 100 -Frames 10000 `
  -OutputDirectory .\benchmark-runs\windows-all
.\scripts\benchmark_criterion.ps1 `
  -OutputDirectory .\benchmark-runs\windows-criterion
```

## Evidence boundary

The CI results are GitHub-hosted engineering measurements, not independent
audits. The input models and many seeds are fixed so regressions can be
compared, but the harness still includes OS-randomized padding and runner
noise. Criterion's confidence intervals describe repeated local operations;
they do not describe Internet conditions.

Neither layer proves live VPN throughput, native TUN forwarding, PMTU
discovery, reconnect behavior across a hostile network, CDN indistinguishability,
DPI evasion, censorship bypass, or DDoS capacity. Those require separately
provisioned hosts, packet captures, network impairments, and independently
reviewable methodology. The public result tables must keep local, GitHub-hosted,
operator, and external measurements in separate rows.

The defensive suite adds a narrower boundary: it proves that selected malformed
or policy-disallowed inputs are rejected in the measured local code path. It
does not establish flood capacity, distributed denial-of-service resistance, or
listener behavior under adversarial network conditions.
