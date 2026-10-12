# Windows Native TUN and WFP Closeout — 2026-09-28

This is a sanitized engineering record of two elevated, single-host Windows
checks. The source worktree was dirty. The run does not close the dedicated
two-host native-TUN release gate or establish production VPN readiness.

## Provenance

| Field | Value |
| --- | --- |
| Validation date | September 28, 2026 (UTC) |
| Platform | Windows 11, x64, build 26200 |
| PowerShell | 5.1.26100.9444 |
| Rust | `rustc 1.96.0 (ac68faa20 2026-05-25)` |
| Wintun Authenticode | Valid |
| Wintun SHA-256 | `E5DA8447DC2C320EDC0FC52FA01885C103DE8C118481F683643CACC3220DAFCE` |
| Source worktree | Dirty engineering snapshot |

The raw benchmark and host captures remain in ignored, machine-local
`benchmark-runs/` directories. They are not publication artifacts.

## Native TUN lifecycle

The elevated root validator completed successfully with native Wintun forced
on. It built the locked Windows workspace and benchmark harness, then captured
the `secure-default` and `classical-lab` benchmark profiles using 5,000
iterations and 100,000 frames. These are local benchmark captures; the runner
does not enable TUN for its benchmark measurements.

The validator then created a real Wintun adapter/session, applied a temporary
`198.18.0.0/15` route and `1.1.1.1` DNS setting, and completed normal teardown.
Its log records route deletion and DNS restoration. A post-run check found no
test adapter, reserved route, or temporary phase directory. The source and
application-local Wintun DLL hashes matched.

This validates Windows adapter/session lifecycle and control-plane rollback.
It does not measure TUN throughput or prove packet forwarding, reconnect
behavior, Internet reachability, IPv6, DNS forwarding, or UDP/QUIC reachability.

## Forced termination and WFP cleanup

The elevated loopback-only WFP test began with zero SHPH-owned filters. It
started a native Wintun client with `up --killswitch`, hard-terminated that
client, and observed seven SHPH-owned filters both before and after the kill.
An explicit `shph down` removed all seven filters. The final WFP capture had
zero SHPH-owned filters.

Post-cleanup checks found no test adapter, route, DNS entry, client or listener
process, or temporary test directory. The validator result was `PASS`.

This proves only that the policy remained observable after forced process
termination and that an explicit operator cleanup removed it. It does not
prove automatic crash-time cleanup, packet-leak prevention, or killswitch
effectiveness across two hosts.

## Release-readiness result

The Windows config replacement path received a bounded retry for error 1175
after one workspace run hit that error during the QUIC CLI test. The focused
test passed ten consecutive runs after the change, and the final full
workspace test gate passed.

The final Windows release-readiness collector record, generated at
`2026-09-28T21:27:54Z` with `cargo-audit 0.22.2`, reported 41 `PASS`, one
`WARN`, and one `SKIP` across 43 gates. Formatting, workspace checks, strict
Clippy, tests, release builds, Windows MSVC builds, benchmark and fuzz checks,
standalone `shph-edge` checks (including HTTP/3), and offline dependency audits
passed.

The `WARN` was `clean-tree`; the collector ran with `-AllowDirty`, and the
generated package was marked `source_dirty: true`. The `SKIP` was
`native-tun-two-host`, which requires a dedicated privileged Linux or Windows
operator campaign. The collector reported `release_eligible: false`.

No independent security review is implied. This evidence does not change the
roadmap validation status or authorize anonymity, censorship-resistance, DPI
evasion, or production-VPN claims.
