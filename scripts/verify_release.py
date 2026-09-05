#!/usr/bin/env python3
"""Verify a sanitized SHPH release package."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path, PurePosixPath


SECRET_MARKERS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
)


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"verify_release: error: {message}")


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def safe_relative_path(value: str) -> Path:
    parsed = PurePosixPath(value)
    if (
        not value
        or parsed.is_absolute()
        or ".." in parsed.parts
        or ":" in parsed.parts[0]
    ):
        fail(f"unsafe package path: {value!r}")
    return Path(*parsed.parts)


def regular_file(root: Path, relative: str) -> Path:
    path = root / safe_relative_path(relative)
    if path.is_symlink() or not path.is_file():
        fail(f"package file is missing or not regular: {relative}")
    return path


def parse_checksums(path: Path) -> dict[str, str]:
    records: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            checksum, relative = line.split("  ", 1)
        except ValueError:
            fail(f"malformed checksum line: {line!r}")
        if not re.fullmatch(r"[0-9a-fA-F]{64}", checksum):
            fail(f"invalid checksum in line: {line!r}")
        if relative in records:
            fail(f"duplicate checksum entry: {relative}")
        records[relative] = checksum.lower()
    return records


def verify(package: Path, expected_version: str | None) -> None:
    if not package.is_dir():
        fail(f"package directory does not exist: {package}")

    manifest_path = regular_file(package, "manifest.json")
    checksums_path = regular_file(package, "SHA256SUMS")
    try:
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        fail(f"invalid manifest.json: {error}")
    if not isinstance(manifest, dict):
        fail("manifest.json must contain an object")

    if manifest.get("schema") != "shph-release-package/v1":
        fail("unsupported package schema")
    if manifest.get("source_dirty") is not False:
        fail("package was not created from a clean source tree")
    if expected_version is not None and manifest.get("version") != expected_version:
        fail(
            f"version mismatch: manifest={manifest.get('version')!r}, "
            f"expected={expected_version!r}"
        )

    records = manifest.get("files")
    if not isinstance(records, list) or not records:
        fail("manifest contains no payload records")

    payload_paths: set[str] = set()
    for record in records:
        if not isinstance(record, dict):
            fail("manifest contains a non-object payload record")
        relative = record.get("path")
        if not isinstance(relative, str) or relative in payload_paths:
            fail("manifest contains a missing or duplicate payload path")
        payload_paths.add(relative)
        path = regular_file(package, relative)
        if path.stat().st_size != record.get("bytes"):
            fail(f"size mismatch: {relative}")
        if digest(path) != str(record.get("sha256", "")).lower():
            fail(f"payload checksum mismatch: {relative}")
        if path.suffix.lower() in {".md", ".txt", ".json"}:
            text = path.read_text(encoding="utf-8")
            if any(marker.search(text) for marker in SECRET_MARKERS):
                fail(f"secret-like marker found in public package file: {relative}")

    checksums = parse_checksums(checksums_path)
    expected_checksum_paths = payload_paths | {"manifest.json"}
    if set(checksums) != expected_checksum_paths:
        fail(
            "SHA256SUMS entries do not match package contents: "
            f"expected={sorted(expected_checksum_paths)}, "
            f"actual={sorted(checksums)}"
        )
    for relative, expected in checksums.items():
        actual = digest(regular_file(package, relative))
        if actual != expected:
            fail(f"SHA256SUMS mismatch: {relative}")

    actual_files = {
        path.relative_to(package).as_posix()
        for path in package.rglob("*")
        if path.is_file()
    }
    expected_files = expected_checksum_paths | {"SHA256SUMS"}
    if actual_files != expected_files:
        fail(
            "package contains unexpected files: "
            f"{sorted(actual_files - expected_files)}"
        )

    print(
        f"verified {manifest['version']} package: "
        f"{len(payload_paths)} payload files, clean source, checksums valid"
    )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--package", type=Path, required=True)
    parser.add_argument("--version")
    args = parser.parse_args()
    verify(args.package.resolve(), args.version)
    return 0


if __name__ == "__main__":
    sys.exit(main())
