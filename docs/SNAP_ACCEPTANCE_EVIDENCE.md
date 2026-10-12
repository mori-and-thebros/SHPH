# SNAP Acceptance Evidence Bundle

The release-readiness collector can validate an operator-produced evidence
bundle with `-SnapEvidenceDirectory <path>`. Keep the bundle outside the Git
checkout so it does not make the source tree dirty. Paths in manifests are
relative to the directory containing that manifest.

```text
bundle/
  linux/manifest.json
  linux/artifacts/...
  windows/manifest.json
  windows/artifacts/...
  services/manifest.json
  services/artifacts/...
```

Run the collector from a clean checkout of the source revision exercised by
the evidence:

```powershell
.\scripts\release_readiness.ps1 -SnapEvidenceDirectory <path-to-bundle>
```

Each manifest is strict UTF-8 JSON with no duplicate or unknown fields. It
records `schema_version: 1`, its documented `kind`, the source `commit`,
`clean: true`, and the SHA-256 digest of the root `Cargo.lock`. Host manifests
also record `platform` (`linux` or `windows`), `observed_at_utc`, and `runner`.
The collector compares the commit and lock digest with its checkout. A
complete evidence bundle still reports `SKIP` if the current checkout is
dirty.

## Host manifests

The `adapters` object must contain exactly these SNAP adapter IDs:

`direct-tcp`, `bridge-onion-tcp`, `bridge-tls`, `bridge-ws`, `shroud-tcp`,
`mesh-dtn-local`, `mule-usb`, `edge-relay`, `quic`, `quic-standard`,
`offline-mesh`, and `data-mule`.

Every adapter records these paired SHPH session checks:

`authenticated_payload_exchange`, `wrong_peer_rejection`,
`malformed_or_failed_setup`, `allowed_fallback`, `forbidden_fallback`,
`reconnect`, and `shutdown`.

Each network adapter also records `tun_forwarding`, `route_updates`, `dns`, and
`killswitch` under `controls`. The two file or store transports, `offline-mesh`
and `data-mule`, must mark each control `N/A` with a reason. `direct-tcp`
records the same checks and controls separately under all four `underlays`:
`direct`, `socks5`, `socks5h`, and `tor`.

Every check is an object with `status`, `evidence`, and `reason`. A `PASS` needs
one or more artifact references and an empty reason. An artifact reference
contains a bundle-relative POSIX `path` and its lowercase SHA-256 digest. A
`SKIP` needs a reason and keeps the corresponding gate incomplete. `N/A` is
accepted only for the four host controls on `offline-mesh` and `data-mule`.
Missing checks, failed checks, malformed data, unsafe paths, source mismatches,
or incorrect artifact hashes fail that gate.
Each manifest is limited to 2 MiB, each referenced artifact to 100 MiB, and
each manifest to 512 distinct artifacts and 1 GiB total artifact data.

## External service manifest

The `services` array must cover each external bridge adapter at least once:
`bridge-onion-tcp`, `bridge-tls`, `bridge-ws`, `shroud-tcp`, and `edge-relay`.
Each service entry records non-empty `owner`, `service_id`, and
`authorization_ref` fields, hashed `contract_evidence`, and the seven paired
session checks listed above. Only operator-owned or explicitly authorized
services belong in this matrix. Do not include credentials in metadata or
artifacts.

The validator checks schema, source identity, required coverage, safe relative
paths, file bounds, and hashes. It does not authenticate the operator, prove
authorization, or establish that a procedure really ran. A reviewer must
inspect the referenced evidence and service contracts before treating a gate
as accepted. This process does not add anonymity, censorship-resistance,
DPI-evasion, or production VPN claims.
