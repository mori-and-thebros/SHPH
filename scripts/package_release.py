#!/usr/bin/env python3
"""Create a small, sanitized SHPH distribution package.

The package intentionally uses an allowlist for public documentation. This
keeps local audit notes, deployment files, scratch output, and credentials out
of a release artifact even when they exist in the working tree.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tempfile
from pathlib import Path


PUBLIC_DOCUMENTS = (
    "CHANGELOG.md",
    "README.md",
    "LICENSE-MIT",
    "LICENSE-APACHE",
    "SECURITY.md",
    "docs/SUPPORT_MATRIX.md",
    "docs/SNAP_PROFILES.md",
    "docs/SNAP_ACCEPTANCE_EVIDENCE.md",
    "docs/RELEASE_READINESS.md",
    "docs/REPRODUCIBILITY.md",
    "docs/SECURITY_EVIDENCE.md",
    "docs/TESTING.md",
    "docs/OPERATOR_CAMPAIGNS.md",
)
MAX_FILE_BYTES = 256 * 1024 * 1024
MAX_DOCUMENT_BYTES = 4 * 1024 * 1024
SECRET_MARKERS = (
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b"),
    re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"),
)
SECRET_MARKERS_BYTES = tuple(
    re.compile(marker.pattern.encode("ascii")) for marker in SECRET_MARKERS
)


def fail(message: str) -> None:
    raise SystemExit(f"package_release: error: {message}")


def run_git(root: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *args],
            check=True,
            capture_output=True,
            text=True,
        )
    except (OSError, subprocess.CalledProcessError):
        return "unknown"
    return result.stdout.strip()


def validate_regular_file(path: Path, *, max_bytes: int) -> None:
    try:
        metadata = path.lstat()
    except OSError:
        fail(f"required regular file is missing: {path}")
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    if stat.S_ISLNK(metadata.st_mode) or (
        reparse_flag and getattr(metadata, "st_file_attributes", 0) & reparse_flag
    ):
        fail(f"refusing link or reparse point: {path}")
    if not stat.S_ISREG(metadata.st_mode):
        fail(f"required regular file is missing: {path}")
    size = metadata.st_size
    if size == 0:
        fail(f"refusing empty file: {path}")
    if size > max_bytes:
        fail(f"file is larger than the configured limit: {path}")


def validate_repository_file(path: Path, root: Path, *, max_bytes: int) -> Path:
    root_absolute = Path(os.path.abspath(root))
    path_absolute = Path(os.path.abspath(path))
    try:
        relative = path_absolute.relative_to(root_absolute)
        resolved_root = root_absolute.resolve(strict=True)
    except (OSError, RuntimeError, ValueError):
        fail(f"artifact must be a regular file inside the repository: {path}")
    if not relative.parts:
        fail(f"artifact must be a regular file inside the repository: {path}")

    current = resolved_root
    metadata = None
    reparse_flag = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    for part in relative.parts:
        current /= part
        try:
            metadata = current.lstat()
        except OSError:
            fail(f"required regular file is missing: {path}")
        if stat.S_ISLNK(metadata.st_mode) or (
            reparse_flag and getattr(metadata, "st_file_attributes", 0) & reparse_flag
        ):
            fail(f"refusing link or reparse point: {path}")
        try:
            resolved_path = current.resolve(strict=True)
            resolved_path.relative_to(resolved_root)
        except (OSError, RuntimeError, ValueError):
            fail(f"artifact must be a regular file inside the repository: {path}")

    if metadata is None or not stat.S_ISREG(metadata.st_mode):
        fail(f"required regular file is missing: {path}")
    validate_regular_file(resolved_path, max_bytes=max_bytes)
    return resolved_path


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def scan_public_text(path: Path) -> None:
    validate_regular_file(path, max_bytes=MAX_DOCUMENT_BYTES)
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as error:
        fail(f"public document is not UTF-8: {path} ({error})")
    for marker in SECRET_MARKERS:
        if marker.search(text):
            fail(f"secret-like marker found in public document: {path}")


def contains_secret_marker(path: Path) -> bool:
    overlap = max(len(marker.pattern) for marker in SECRET_MARKERS_BYTES) - 1
    remainder = b""
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            sample = remainder + chunk
            if any(marker.search(sample) for marker in SECRET_MARKERS_BYTES):
                return True
            remainder = sample[-overlap:]
    return False


def workspace_version(root: Path) -> str:
    cargo = (root / "Cargo.toml").read_text(encoding="utf-8")
    match = re.search(r'(?m)^\s*version\s*=\s*"([^"]+)"\s*$', cargo)
    if not match:
        fail("workspace version not found in Cargo.toml")
    return match.group(1)


def package_files(
    staging: Path,
    root: Path,
    binary: Path,
    edge_binary: Path | None,
) -> list[dict[str, object]]:
    payloads: list[tuple[Path, Path]] = [(binary, Path(binary.name))]
    if edge_binary is not None:
        payloads.append((edge_binary, Path(edge_binary.name)))
    for relative in PUBLIC_DOCUMENTS:
        source = validate_repository_file(
            root / relative, root, max_bytes=MAX_DOCUMENT_BYTES
        )
        scan_public_text(source)
        payloads.append((source, Path(relative)))

    records: list[dict[str, object]] = []
    for source, relative in payloads:
        destination = staging / relative
        destination.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(source, destination)
        if contains_secret_marker(destination):
            fail(f"secret-like marker found in release payload: {relative}")
        records.append(
            {
                "path": relative.as_posix(),
                "bytes": destination.stat().st_size,
                "sha256": sha256(destination),
            }
        )
    return records


def write_manifest(
    staging: Path,
    root: Path,
    records: list[dict[str, object]],
    *,
    version: str,
    dirty: bool,
) -> None:
    lockfiles: dict[str, str] = {}
    for relative in ("Cargo.lock", "benchmarks/Cargo.lock", "fuzz/Cargo.lock"):
        path = root / relative
        if path.is_file() and not path.is_symlink():
            lockfiles[relative] = sha256(path)

    manifest = {
        "schema": "shph-release-package/v1",
        "version": version,
        "source_revision": run_git(root, "rev-parse", "HEAD"),
        "source_dirty": dirty,
        "platform": platform.system(),
        "machine": platform.machine(),
        "python": platform.python_version(),
        "lockfiles_sha256": lockfiles,
        "claims_boundary": (
            "Prototype package for controlled lab environments; not proof of "
            "production VPN behavior, anonymity, DPI evasion, censorship "
            "resistance, or independent audit status."
        ),
        "files": records,
    }
    (staging / "manifest.json").write_text(
        json.dumps(manifest, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )


def write_checksums(staging: Path) -> None:
    files = sorted(
        path
        for path in staging.rglob("*")
        if path.is_file() and path.name != "SHA256SUMS"
    )
    lines = [
        f"{sha256(path)}  {path.relative_to(staging).as_posix()}" for path in files
    ]
    (staging / "SHA256SUMS").write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Create a sanitized SHPH release package."
    )
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--edge-binary", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--allow-dirty",
        action="store_true",
        help="allow a dirty source tree; the manifest still records it",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    root = Path(os.path.abspath(args.root))
    binary = Path(os.path.abspath(args.binary))
    edge_binary = (
        Path(os.path.abspath(args.edge_binary)) if args.edge_binary else None
    )
    output = Path(os.path.abspath(args.output))
    if not root.is_dir():
        fail(f"repository root is not a directory: {root}")
    if output.exists():
        fail(f"output already exists; choose a new path: {output}")
    binary = validate_repository_file(binary, root, max_bytes=MAX_FILE_BYTES)
    if binary.name not in {"shph", "shph.exe"}:
        fail("--binary must be named shph or shph.exe")
    if edge_binary is not None:
        edge_binary = validate_repository_file(
            edge_binary, root, max_bytes=MAX_FILE_BYTES
        )
        if edge_binary.name not in {"shph-edge", "shph-edge.exe"}:
            fail("--edge-binary must be named shph-edge or shph-edge.exe")

    status = run_git(root, "status", "--porcelain=v1", "--untracked-files=all")
    dirty = status not in ("", "unknown")
    if status == "unknown":
        fail("unable to determine git status")
    if dirty and not args.allow_dirty:
        fail("source tree is dirty; use --allow-dirty only for an engineering snapshot")

    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(
        tempfile.mkdtemp(prefix=f".{output.name}.staging-", dir=str(output.parent))
    )
    try:
        records = package_files(staging, root, binary, edge_binary)
        write_manifest(
            staging,
            root,
            records,
            version=workspace_version(root),
            dirty=dirty,
        )
        scan_public_text(staging / "manifest.json")
        write_checksums(staging)
        staging.rename(output)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise

    print(f"created {output}")
    print(f"files: {len(records)} payload files + manifest.json + SHA256SUMS")
    print(f"source_dirty: {str(dirty).lower()}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
