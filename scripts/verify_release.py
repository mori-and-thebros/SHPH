#!/usr/bin/env python3
"""Verify a sanitized SHPH release package."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import stat
import sys
from pathlib import Path

from package_release import (
    MAX_DOCUMENT_BYTES,
    MAX_FILE_BYTES,
    PUBLIC_DOCUMENTS,
    contains_secret_marker,
)

MAIN_EXECUTABLES = {"shph", "shph.exe"}
EDGE_EXECUTABLES = {"shph-edge", "shph-edge.exe"}
WINDOWS_RESERVED_COMPONENTS = {
    "AUX",
    "CON",
    "NUL",
    "PRN",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}
MAX_MANIFEST_BYTES = MAX_DOCUMENT_BYTES
MAX_CHECKSUMS_BYTES = 64 * 1024
MAX_PACKAGE_ENTRIES = 32
VERSION_PATTERN = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)


def fail(message: str) -> "NoReturn":
    raise SystemExit(f"verify_release: error: {message}")


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            value.update(chunk)
    return value.hexdigest()


def read_bounded_text(path: Path, max_bytes: int, description: str) -> str:
    try:
        with path.open("rb") as stream:
            contents = stream.read(max_bytes + 1)
    except OSError as error:
        fail(f"unable to read {description}: {error}")
    if len(contents) > max_bytes:
        fail(f"{description} exceeds {max_bytes} byte limit")
    try:
        return contents.decode("utf-8")
    except UnicodeDecodeError as error:
        fail(f"{description} is not valid UTF-8: {error}")


def validate_file_size(path: Path, relative: str, max_bytes: int) -> int:
    try:
        size = path.stat().st_size
    except OSError as error:
        fail(f"unable to inspect package file {relative}: {error}")
    if size < 1 or size > max_bytes:
        fail(f"package file size is outside the allowed range: {relative}")
    return size


def safe_relative_path(value: str) -> Path:
    if (
        not value
        or "\x00" in value
        or "\\" in value
        or ":" in value
        or value.startswith("/")
    ):
        fail(f"unsafe package path: {value!r}")
    parts = value.split("/")
    if any(
        part in {"", ".", ".."}
        or part.endswith((".", " "))
        or any(character in '<>"|?*' for character in part)
        or part.split(".", 1)[0].rstrip(" ").upper() in WINDOWS_RESERVED_COMPONENTS
        for part in parts
    ):
        fail(f"unsafe package path: {value!r}")
    return Path(*parts)


def regular_file(root: Path, relative: str) -> Path:
    relative_path = safe_relative_path(relative)
    try:
        resolved_root = root.resolve(strict=True)
    except (OSError, RuntimeError):
        fail(f"package directory cannot be resolved: {root}")

    path = resolved_root
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    for part in relative_path.parts:
        path = path / part
        try:
            metadata = path.lstat()
        except OSError:
            fail(f"unsafe or missing package file: {relative}")
        if stat.S_ISLNK(metadata.st_mode) or (
            reparse_flag
            and getattr(metadata, "st_file_attributes", 0) & reparse_flag
        ):
            fail(f"package path contains a link or reparse point: {relative}")
        try:
            resolved_path = path.resolve(strict=True)
            resolved_path.relative_to(resolved_root)
        except (OSError, RuntimeError, ValueError):
            fail(f"unsafe or missing package file: {relative}")

    if not stat.S_ISREG(metadata.st_mode):
        fail(f"package file is missing or not regular: {relative}")
    return resolved_path


def package_files(root: Path) -> tuple[set[str], set[str]]:
    files: set[str] = set()
    found_directories: set[str] = set()
    directories = [root]
    entry_count = 0
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    while directories:
        directory = directories.pop()
        try:
            entries = list(directory.iterdir())
        except OSError:
            fail(f"package directory cannot be read: {directory}")
        for path in entries:
            entry_count += 1
            if entry_count > MAX_PACKAGE_ENTRIES:
                fail(f"package contains more than {MAX_PACKAGE_ENTRIES} entries")
            relative = path.relative_to(root).as_posix()
            try:
                metadata = path.lstat()
            except OSError:
                fail(f"package entry cannot be inspected: {relative}")
            if stat.S_ISLNK(metadata.st_mode) or (
                reparse_flag
                and getattr(metadata, "st_file_attributes", 0) & reparse_flag
            ):
                fail(f"package path contains a link or reparse point: {relative}")
            if stat.S_ISDIR(metadata.st_mode):
                found_directories.add(relative)
                directories.append(path)
            elif stat.S_ISREG(metadata.st_mode):
                files.add(relative)
            else:
                fail(f"package contains a non-regular entry: {relative}")
    return files, found_directories


def parse_checksums(path: Path) -> dict[str, str]:
    records: dict[str, str] = {}
    for line in read_bounded_text(path, MAX_CHECKSUMS_BYTES, "SHA256SUMS").splitlines():
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


def validate_payload_allowlist(payload_paths: set[str]) -> None:
    documents = set(PUBLIC_DOCUMENTS)
    main_binaries = payload_paths & MAIN_EXECUTABLES
    edge_binaries = payload_paths & EDGE_EXECUTABLES
    allowed = documents | MAIN_EXECUTABLES | EDGE_EXECUTABLES
    unexpected = payload_paths - allowed
    if unexpected:
        fail(f"manifest contains non-allowlisted payload paths: {sorted(unexpected)}")
    if len(main_binaries) != 1:
        fail("manifest must contain exactly one allowlisted shph executable")
    if len(edge_binaries) > 1:
        fail("manifest contains multiple allowlisted edge executables")
    if not documents.issubset(payload_paths):
        fail("manifest is missing required public documentation")


def verify(package: Path, expected_version: str | None) -> None:
    if not package.is_dir():
        fail(f"package directory does not exist: {package}")

    manifest_path = regular_file(package, "manifest.json")
    checksums_path = regular_file(package, "SHA256SUMS")
    manifest_text = read_bounded_text(
        manifest_path, MAX_MANIFEST_BYTES, "manifest.json"
    )
    try:
        manifest = json.loads(manifest_text)
    except json.JSONDecodeError as error:
        fail(f"invalid manifest.json: {error}")
    if not isinstance(manifest, dict):
        fail("manifest.json must contain an object")

    if manifest.get("schema") != "shph-release-package/v1":
        fail("unsupported package schema")
    if manifest.get("source_dirty") is not False:
        fail("package was not created from a clean source tree")
    version = manifest.get("version")
    if not isinstance(version, str) or not VERSION_PATTERN.fullmatch(version):
        fail("manifest version is missing or invalid")
    if expected_version is not None and version != expected_version:
        fail(
            f"version mismatch: manifest={version!r}, "
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
    validate_payload_allowlist(payload_paths)

    for record in records:
        relative = record["path"]
        path = regular_file(package, relative)
        expected_size = record.get("bytes")
        if type(expected_size) is not int or expected_size < 1:
            fail(f"invalid payload size: {relative}")
        max_bytes = MAX_DOCUMENT_BYTES if relative in PUBLIC_DOCUMENTS else MAX_FILE_BYTES
        if expected_size > max_bytes:
            fail(f"payload exceeds {max_bytes} byte limit: {relative}")
        if validate_file_size(path, relative, max_bytes) != expected_size:
            fail(f"size mismatch: {relative}")
        expected_digest = record.get("sha256")
        if not isinstance(expected_digest, str) or not re.fullmatch(
            r"[0-9a-fA-F]{64}", expected_digest
        ):
            fail(f"invalid payload checksum: {relative}")
        if digest(path) != expected_digest.lower():
            fail(f"payload checksum mismatch: {relative}")
        if contains_secret_marker(path):
            fail(f"secret-like marker found in public package file: {relative}")

    if contains_secret_marker(manifest_path):
        fail("secret-like marker found in public package file: manifest.json")

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

    actual_files, actual_directories = package_files(package)
    expected_files = expected_checksum_paths | {"SHA256SUMS"}
    expected_directories = {
        parent.as_posix()
        for relative in expected_files
        for parent in Path(relative).parents
        if parent.as_posix() != "."
    }
    if actual_files != expected_files:
        fail(
            "package contains unexpected files: "
            f"{sorted(actual_files - expected_files)}"
        )
    if actual_directories != expected_directories:
        fail(
            "package contains unexpected directories: "
            f"{sorted(actual_directories - expected_directories)}"
        )

    print(
        f"verified {version} package: "
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
