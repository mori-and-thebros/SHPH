#!/usr/bin/env python3
"""Validate SNAP host and operator-service acceptance evidence bundles."""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import stat
from pathlib import Path, PurePosixPath
from typing import Any


HOST_ADAPTERS = (
    "direct-tcp",
    "bridge-onion-tcp",
    "bridge-tls",
    "bridge-ws",
    "shroud-tcp",
    "mesh-dtn-local",
    "mule-usb",
    "edge-relay",
    "quic",
    "quic-standard",
    "offline-mesh",
    "data-mule",
)
DIRECT_UNDERLAYS = ("direct", "socks5", "socks5h", "tor")
EXTERNAL_ADAPTERS = (
    "bridge-onion-tcp",
    "bridge-tls",
    "bridge-ws",
    "shroud-tcp",
    "edge-relay",
)
SESSION_CHECKS = (
    "authenticated_payload_exchange",
    "wrong_peer_rejection",
    "malformed_or_failed_setup",
    "allowed_fallback",
    "forbidden_fallback",
    "reconnect",
    "shutdown",
)
HOST_CONTROLS = ("tun_forwarding", "route_updates", "dns", "killswitch")
HEX_40 = re.compile(r"^[0-9a-fA-F]{40}$")
HEX_64 = re.compile(r"^[0-9a-fA-F]{64}$")
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_ARTIFACT_BYTES = 100 * 1024 * 1024
MAX_ARTIFACT_COUNT = 512
MAX_TOTAL_ARTIFACT_BYTES = 1024 * 1024 * 1024
REPARSE_POINT = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class EvidenceError(ValueError):
    pass


def _object_without_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EvidenceError("duplicate JSON key")
        result[key] = value
    return result


def _strict_object(value: Any, keys: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise EvidenceError(f"invalid {label} fields")
    return value


def _bounded_text(value: Any, label: str, maximum: int = 256) -> str:
    if not isinstance(value, str):
        raise EvidenceError(f"invalid {label}")
    normalized = value.strip()
    if not normalized or len(normalized) > maximum or any(ord(char) < 32 for char in normalized):
        raise EvidenceError(f"invalid {label}")
    return normalized


def _is_link_or_reparse(path: Path) -> bool:
    try:
        info = path.lstat()
    except OSError as error:
        raise EvidenceError("evidence path cannot be inspected") from error
    return stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & REPARSE_POINT)


def _reject_reparse_components(path: Path) -> None:
    absolute = path.absolute()
    current = Path(absolute.anchor)
    for part in absolute.parts[1:] if absolute.anchor else absolute.parts:
        current = current / part
        if os.path.lexists(current) and _is_link_or_reparse(current):
            raise EvidenceError("evidence path contains a link or reparse point")


def _read_json_manifest(path: Path) -> dict[str, Any]:
    _reject_reparse_components(path.parent)
    if _is_link_or_reparse(path):
        raise EvidenceError("manifest cannot be a link or reparse point")
    try:
        size = path.stat().st_size
        if size > MAX_MANIFEST_BYTES:
            raise EvidenceError("manifest exceeds size limit")
        raw = path.read_text(encoding="utf-8")
        parsed = json.loads(raw, object_pairs_hook=_object_without_duplicate_keys)
    except EvidenceError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise EvidenceError("manifest is unreadable or invalid JSON") from error
    if not isinstance(parsed, dict):
        raise EvidenceError("manifest root must be an object")
    return parsed


class ArtifactAudit:
    def __init__(self, base: Path):
        self.base = base
        self.files: dict[Path, tuple[str, int, int]] = {}
        self.total_bytes = 0


def _utc_timestamp(value: Any) -> None:
    text = _bounded_text(value, "observed_at_utc", 64)
    try:
        timestamp = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise EvidenceError("invalid observed_at_utc") from error
    if timestamp.tzinfo is None or timestamp.utcoffset() != dt.timedelta(0):
        raise EvidenceError("observed_at_utc must be UTC")


def _safe_artifact(audit: ArtifactAudit, record: Any) -> None:
    reference = _strict_object(record, {"path", "sha256"}, "artifact reference")
    raw_path = _bounded_text(reference["path"], "artifact path", 512)
    if "\\" in raw_path:
        raise EvidenceError("artifact path must use relative POSIX form")
    rel = PurePosixPath(raw_path)
    if (
        not rel.parts
        or rel.is_absolute()
        or any(part in ("", ".", "..") for part in rel.parts)
        or ":" in rel.parts[0]
    ):
        raise EvidenceError("artifact path must remain within the evidence bundle")
    digest = reference["sha256"]
    if not isinstance(digest, str) or not HEX_64.fullmatch(digest):
        raise EvidenceError("invalid artifact SHA-256")

    base = audit.base
    _reject_reparse_components(base)
    current = base
    for part in rel.parts:
        current = current / part
        if _is_link_or_reparse(current):
            raise EvidenceError("artifact path contains a link or reparse point")
    try:
        resolved_base = base.resolve(strict=True)
        resolved_file = current.resolve(strict=True)
        resolved_file.relative_to(resolved_base)
        info = resolved_file.stat()
        if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_ARTIFACT_BYTES:
            raise EvidenceError("artifact must be a regular file within the size limit")
        cached = audit.files.get(resolved_file)
        if cached is not None and cached[1:] == (info.st_size, info.st_mtime_ns):
            if cached[0] != digest.lower():
                raise EvidenceError("artifact SHA-256 mismatch")
            return
        if cached is None and len(audit.files) >= MAX_ARTIFACT_COUNT:
            raise EvidenceError("evidence bundle references too many artifacts")
        if cached is None and audit.total_bytes + info.st_size > MAX_TOTAL_ARTIFACT_BYTES:
            raise EvidenceError("evidence bundle exceeds total artifact size limit")
        sha = hashlib.sha256()
        with resolved_file.open("rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                sha.update(chunk)
    except EvidenceError:
        raise
    except (OSError, ValueError) as error:
        raise EvidenceError("artifact is missing or outside the evidence bundle") from error
    if sha.hexdigest() != digest.lower():
        raise EvidenceError("artifact SHA-256 mismatch")
    if cached is None:
        audit.total_bytes += info.st_size
    audit.files[resolved_file] = (sha.hexdigest(), info.st_size, info.st_mtime_ns)


def _check_result(value: Any, label: str, audit: ArtifactAudit, *, allow_na: bool = False) -> str:
    result = _strict_object(value, {"status", "evidence", "reason"}, f"{label} result")
    status = result["status"]
    if not isinstance(status, str) or status not in {"PASS", "FAIL", "SKIP", "N/A"}:
        raise EvidenceError(f"invalid status for {label}")
    artifacts = result["evidence"]
    if not isinstance(artifacts, list):
        raise EvidenceError(f"invalid evidence list for {label}")
    for artifact in artifacts:
        _safe_artifact(audit, artifact)
    reason = result["reason"]
    if status == "PASS" and (not artifacts or reason not in (None, "")):
        raise EvidenceError(f"PASS result for {label} needs evidence and no reason")
    if status == "N/A":
        if not allow_na or artifacts:
            raise EvidenceError(f"N/A is not allowed for {label}")
        _bounded_text(reason, f"{label} N/A reason")
    elif status == "SKIP":
        _bounded_text(reason, f"{label} SKIP reason")
    elif status == "FAIL":
        if reason not in (None, ""):
            _bounded_text(reason, f"{label} failure reason")
    elif reason not in (None, ""):
        raise EvidenceError(f"unexpected reason for {label}")
    return status


def _check_map(
    value: Any,
    names: tuple[str, ...],
    label: str,
    audit: ArtifactAudit,
    *,
    allow_na: bool = False,
) -> list[str]:
    fields = _strict_object(value, set(names), label)
    return [
        _check_result(fields[name], f"{label}.{name}", audit, allow_na=allow_na)
        for name in names
    ]


def _validate_source(source: Any, commit: str, lock_sha256: str) -> None:
    fields = _strict_object(source, {"commit", "clean", "cargo_lock_sha256"}, "source")
    recorded_commit = fields["commit"]
    recorded_lock = fields["cargo_lock_sha256"]
    if not isinstance(recorded_commit, str) or not HEX_40.fullmatch(recorded_commit):
        raise EvidenceError("invalid source commit")
    if recorded_commit.lower() != commit.lower():
        raise EvidenceError("source commit does not match this checkout")
    if fields["clean"] is not True:
        raise EvidenceError("evidence source must be clean")
    if not isinstance(recorded_lock, str) or not HEX_64.fullmatch(recorded_lock):
        raise EvidenceError("invalid Cargo.lock digest")
    if recorded_lock.lower() != lock_sha256.lower():
        raise EvidenceError("Cargo.lock digest does not match this checkout")


def _validate_host_manifest(path: Path, platform: str, commit: str, lock_sha256: str) -> str:
    manifest = _read_json_manifest(path)
    fields = _strict_object(
        manifest,
        {"schema_version", "kind", "platform", "source", "observed_at_utc", "runner", "adapters"},
        "host manifest",
    )
    if type(fields["schema_version"]) is not int or fields["schema_version"] != 1 or fields["kind"] != "snap-host-acceptance":
        raise EvidenceError("unsupported host evidence schema")
    if fields["platform"] != platform:
        raise EvidenceError("host manifest platform mismatch")
    _validate_source(fields["source"], commit, lock_sha256)
    _utc_timestamp(fields["observed_at_utc"])
    _bounded_text(fields["runner"], "runner", 128)

    adapters = _strict_object(fields["adapters"], set(HOST_ADAPTERS), "adapters")
    statuses: list[str] = []
    audit = ArtifactAudit(path.parent)
    for adapter in HOST_ADAPTERS:
        adapter_base = _strict_object(
            adapters[adapter],
            {"underlays"} if adapter == "direct-tcp" else {"checks", "controls"},
            f"adapter {adapter}",
        )
        if adapter == "direct-tcp":
            underlays = _strict_object(adapter_base["underlays"], set(DIRECT_UNDERLAYS), "direct TCP underlays")
            for underlay in DIRECT_UNDERLAYS:
                case = _strict_object(underlays[underlay], {"checks", "controls"}, f"underlay {underlay}")
                statuses.extend(_check_map(case["checks"], SESSION_CHECKS, f"{adapter}.{underlay}.checks", audit))
                statuses.extend(
                    _check_map(
                        case["controls"],
                        HOST_CONTROLS,
                        f"{adapter}.{underlay}.controls",
                        audit,
                    )
                )
        else:
            statuses.extend(_check_map(adapter_base["checks"], SESSION_CHECKS, f"{adapter}.checks", audit))
            no_virtual_network = adapter in {"offline-mesh", "data-mule"}
            statuses.extend(
                _check_map(
                    adapter_base["controls"],
                    HOST_CONTROLS,
                    f"{adapter}.controls",
                    audit,
                    allow_na=no_virtual_network,
                )
            )
    if "FAIL" in statuses:
        return "FAIL"
    return "SKIP" if "SKIP" in statuses else "PASS"


def _validate_service_manifest(path: Path, commit: str, lock_sha256: str) -> str:
    manifest = _read_json_manifest(path)
    fields = _strict_object(
        manifest,
        {"schema_version", "kind", "source", "observed_at_utc", "services"},
        "service manifest",
    )
    if type(fields["schema_version"]) is not int or fields["schema_version"] != 1 or fields["kind"] != "snap-service-acceptance":
        raise EvidenceError("unsupported service evidence schema")
    _validate_source(fields["source"], commit, lock_sha256)
    _utc_timestamp(fields["observed_at_utc"])
    services = fields["services"]
    if not isinstance(services, list):
        raise EvidenceError("services must be an array")
    by_adapter: dict[str, list[str]] = {adapter: [] for adapter in EXTERNAL_ADAPTERS}
    seen: set[tuple[str, str]] = set()
    audit = ArtifactAudit(path.parent)
    for index, raw_service in enumerate(services):
        service = _strict_object(
            raw_service,
            {"adapter", "owner", "service_id", "authorization_ref", "contract_evidence", "checks"},
            f"service {index}",
        )
        adapter = service["adapter"]
        if adapter not in by_adapter:
            raise EvidenceError("service manifest contains an unsupported adapter")
        owner = _bounded_text(service["owner"], "service owner")
        service_id = _bounded_text(service["service_id"], "service_id")
        authorization_ref = _bounded_text(service["authorization_ref"], "authorization_ref")
        del owner, authorization_ref
        key = (adapter, service_id)
        if key in seen:
            raise EvidenceError("duplicate service entry")
        seen.add(key)
        contract_evidence = service["contract_evidence"]
        if not isinstance(contract_evidence, list) or not contract_evidence:
            raise EvidenceError("service contract evidence is required")
        for artifact in contract_evidence:
            _safe_artifact(audit, artifact)
        by_adapter[adapter].extend(
            _check_map(service["checks"], SESSION_CHECKS, f"service.{adapter}.checks", audit)
        )
    if any(not by_adapter[adapter] for adapter in EXTERNAL_ADAPTERS):
        raise EvidenceError("service manifest does not cover every external adapter")
    statuses = [status for values in by_adapter.values() for status in values]
    if "FAIL" in statuses:
        return "FAIL"
    return "SKIP" if "SKIP" in statuses else "PASS"


def _gate(gate_id: str, status: str, detail: str) -> dict[str, str]:
    return {"id": gate_id, "status": status, "detail": detail}


def validate_bundle(repository: Path, evidence_directory: Path | None, commit: str, workspace_clean: bool) -> list[dict[str, str]]:
    gate_specs = (
        ("snap-linux-adapter-acceptance", "linux/manifest.json", "linux"),
        ("snap-windows-adapter-acceptance", "windows/manifest.json", "windows"),
        ("snap-external-service-acceptance", "services/manifest.json", "services"),
    )
    if evidence_directory is None:
        return [_gate(gate_id, "SKIP", "no SNAP evidence directory was supplied") for gate_id, _, _ in gate_specs]
    if (
        not os.path.lexists(evidence_directory)
        or _is_link_or_reparse(evidence_directory)
        or not evidence_directory.is_dir()
    ):
        return [_gate(gate_id, "FAIL", "SNAP evidence directory is not a regular directory") for gate_id, _, _ in gate_specs]
    try:
        lock_sha256 = hashlib.sha256((repository / "Cargo.lock").read_bytes()).hexdigest()
    except OSError:
        return [_gate(gate_id, "FAIL", "root Cargo.lock is unavailable") for gate_id, _, _ in gate_specs]

    output: list[dict[str, str]] = []
    for gate_id, relative_manifest, kind in gate_specs:
        manifest_path = evidence_directory / Path(*PurePosixPath(relative_manifest).parts)
        _reject_reparse_components(manifest_path.parent)
        if not os.path.lexists(manifest_path):
            output.append(_gate(gate_id, "SKIP", f"{kind} acceptance manifest is missing"))
            continue
        try:
            if kind == "linux":
                status = _validate_host_manifest(manifest_path, "linux", commit, lock_sha256)
            elif kind == "windows":
                status = _validate_host_manifest(manifest_path, "windows", commit, lock_sha256)
            else:
                status = _validate_service_manifest(manifest_path, commit, lock_sha256)
            if not workspace_clean and status == "PASS":
                status = "SKIP"
            detail = {
                "PASS": "verified acceptance manifest and hashed artifacts",
                "SKIP": "acceptance evidence is incomplete or the current source tree is dirty",
                "FAIL": "acceptance evidence is malformed, mismatched, or records a failed check",
            }[status]
        except EvidenceError:
            status = "FAIL"
            detail = "acceptance evidence is malformed, mismatched, or contains unsafe artifact paths"
        output.append(_gate(gate_id, status, detail))
    return output


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", required=True, type=Path)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--evidence-directory", type=Path)
    parser.add_argument("--workspace-clean", action="store_true")
    args = parser.parse_args()
    if not HEX_40.fullmatch(args.commit):
        gates = [
            _gate(gate_id, "FAIL", "current Git commit is unavailable")
            for gate_id in (
                "snap-linux-adapter-acceptance",
                "snap-windows-adapter-acceptance",
                "snap-external-service-acceptance",
            )
        ]
    else:
        gates = validate_bundle(
            args.repository,
            args.evidence_directory,
            args.commit,
            args.workspace_clean,
        )
    print(json.dumps({"gates": gates}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
