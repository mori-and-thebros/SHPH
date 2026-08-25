# Cross-Platform Native TUN Validation - 2026-08-25

This report records one controlled two-host SHPH campaign using a native
Windows Wintun client and a native Linux host. It is engineering evidence for
the direct authenticated TCP lane. It is not an independent security audit,
an anonymity result, or evidence of universal censorship resistance.

## Scope and provenance

| Field | Value |
| --- | --- |
| Client | Windows native Wintun, `x86_64-pc-windows-msvc` |
| Host | Native Linux VPS |
| Transport | Direct authenticated TCP |
| Handshake | `secure-default` with hybrid ML-KEM-768 + X25519 |
| TUN mode | Native on both endpoints |
| Address family | IPv4 only |
| Observed TUN MTU | 1,353 bytes |
| Route scope | Client default IPv4 route through SHPH |
| Morphology | `medium` profile |
| Reachability add-on | Not used in this campaign |
| Validation source | Working tree based on `e44483897574d39a550b2c145d47fc480ffa4e5b`, including the transport deadline fix in this follow-up |
| Publication status | Captured before publication; the final follow-up ref is `v0.6.5-dev.1` |

The run also exercised the post-handshake timeout correction: socket
deadlines used during handshake negotiation are cleared after authentication
so an established session does not inherit the handshake deadline.

## Results

| Check | Result |
| --- | --- |
| Direct authenticated preflight | PASS; peer pin and transcript verification completed |
| Native Windows adapter/session | PASS |
| Native Linux TUN endpoint | PASS |
| Client address and default route | PASS |
| Underlay endpoint bypass | PASS; the public host endpoint remained on the physical interface |
| Initial tunnel reachability | PASS; 10/10 pings, 0% loss, approximately 433 ms average RTT |
| External TCP reachability | PASS; `1.1.1.1:443` used the SHPH interface |
| Public egress | PASS; egress resolved to the Linux host |
| External HTTPS | PASS; an HTTPS request completed through the tunnel |
| Controlled 64 MiB transfer | PASS; approximately 53.0 seconds and 1.27 MB/s |
| Service-restart reconnect | PASS; a new authenticated session formed after host restart |
| Post-reconnect reachability | PASS; 5/5 pings, 0% loss |
| 90-second soak | PASS; six samples, no client error lines, no additional reconnect |
| Controlled netem check | PASS for the bounded setup; 2% configured loss and 40 ms delay/jitter still produced 20/20 tunnel pings and HTTP 200 |
| DF/MTU boundary | PASS as a boundary check; 1,320-byte payloads succeeded, while 1,330-1,360-byte DF probes were rejected with the expected fragmentation-needed result |
| Normal teardown | PASS; process, adapter, SHPH routes, and temporary address were removed |
| Post-run residue | PASS; no SHPH process, adapter, tunnel route, or temporary DNS entry remained |

The controlled `netem` result is not an Internet loss-recovery claim. It
shows behavior under the specific local impairment setup and does not model
every loss pattern or middlebox.

The DF result is not a blackhole result. It identifies the configured MTU
boundary and confirms that packets above the path limit are rejected rather
than silently treated as delivered.

## Additional automated evidence from the same engineering pass

| Evidence | Result |
| --- | --- |
| Workspace strict release gates | PASS: format, metadata, check, Clippy with `-D warnings`, all-target tests, release build, benchmark/fuzz manifests, and `cargo audit` |
| Workspace test count | PASS: 316 tests, 0 failures in the release-readiness capture |
| Windows native validator | PASS: signed/hash-pinned Wintun lifecycle, route/DNS rollback, loopback WFP smoke, and residue audit |
| Fuzz smoke | PASS: five checked-in targets, 1,000 executions each, 5,000 requested executions total, with the MSVC sanitizer runtime supplied |
| Criterion capture | PASS: report generated; some baseline comparisons flagged performance regressions and require follow-up |

Criterion comparison signals were not correctness failures. The captured
identity microbenchmarks showed approximately +5-10% for record verification,
+3-9% for JSON parse/verify, and +21-33% for JSON serialization relative to
their stored baseline. The Shroud2 batch push/flush comparison also regressed
by approximately +6-12%. These are performance follow-up items, not reasons
to hide or relabel the capture.

## Interpretation

This campaign closes a limited but important evidence gap: SHPH carried
authenticated IPv4 traffic between two different operating systems through
native TUN devices, and external traffic egressed through the Linux host.
The regression test also confirms that an established session can outlive its
handshake timeout.

It does not prove:

- anonymity or an anonymity set;
- protection against a compromised endpoint or VPS operator;
- IPv6 forwarding, DNS routing, UDP/QUIC forwarding, or universal PMTU behavior;
- production throughput, saturation, or an uptime/SLA guarantee;
- censorship resistance, DPI evasion, or traffic indistinguishability;
- crash-time killswitch containment; or
- production readiness or independent audit status.

The optional SOCKS5/Xray underlay was tested separately and is not part of
this direct-TUN result. See
`docs/evidence/OPTIONAL_XRAY_UNDERLAY_VALIDATION_2026-08-25.md`.

## Remaining follow-up

1. Repeat the campaign on two native Linux hosts.
2. Run a separate Windows-to-Windows native Wintun campaign.
3. Exercise forced termination with the opt-in Linux nftables and Windows WFP
   policies, then verify that no plaintext route remains.
4. Test DNS, IPv6, UDP, standards-QUIC, and longer-duration behavior
   explicitly.
5. Re-run from a clean, committed tree before using the result as release
   evidence.
