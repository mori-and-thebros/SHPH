# Sanitized package validation

## Result

| Field | Value |
| --- | --- |
| Validation date | 2026-09-02 |
| Status | PASS for engineering packaging checks |
| Version | `0.6.6-dev.2` |
| Source revision | `352932cb4a3fd1efe53141c73d06a0d0b0f00611` |
| Target | `x86_64-pc-windows-msvc` |
| Payload | `shph.exe` |
| Payload bytes | `7,377,920` |
| Payload SHA-256 | `C60C7842F02453A8F58E70C2CE8A0121A73B2BADF2FEE18A0B8C8F9AC9EE986C` |
| Package payload files | `12` |
| Manifest/checksum validation | `PASS` |
| Exact public allowlist | `PASS` |
| Source tree | Dirty; engineering snapshot only |
| Authenticode | Local executable not signed |

## Checks performed

The package was created with `scripts/package_release.py --allow-dirty`.
The verifier confirmed that every manifest record exists with the recorded
size and SHA-256, every `SHA256SUMS` entry matches, and the package contains
only the expected executable, public documents, manifest, and checksum file.

The package surface contains no `docs/evidence/` directory, raw
`benchmark-runs/` output, keystores, credentials, runtime DLLs, or other
unallowlisted repository files. The packager's claims boundary remains that
this is a controlled-lab prototype and not proof of production VPN behavior,
anonymity, DPI evasion, censorship resistance, or independent audit status.

This record is evidence of packaging integrity only. A clean-tree rerun
without `--allow-dirty` and artifact signing are still required before
publication.
