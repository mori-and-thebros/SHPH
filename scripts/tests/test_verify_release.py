import contextlib
import hashlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import verify_release


class SafePackagePathTests(unittest.TestCase):
    def test_rejects_non_posix_or_escaping_paths(self):
        for value in (
            r"..\..\Windows\win.ini",
            "/etc/passwd",
            "C:/Windows/win.ini",
            "file.txt:stream",
            "../outside.txt",
            "nested//file.txt",
            "./file.txt",
            "CON.txt",
            "CON .txt",
            "nested/trailing.",
            "nested/trailing ",
            "nested/bad?.txt",
        ):
            with self.subTest(value=value), self.assertRaisesRegex(
                SystemExit, "unsafe package path"
            ):
                verify_release.safe_relative_path(value)

    def test_accepts_normalized_package_relative_path(self):
        self.assertEqual(
            verify_release.safe_relative_path("nested/file.txt"),
            Path("nested") / "file.txt",
        )

    def test_rejects_file_reached_through_symlinked_parent(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "package"
            outside = Path(temporary_directory) / "outside"
            root.mkdir()
            outside.mkdir()
            (outside / "secret.txt").write_text("outside sentinel", encoding="utf-8")
            try:
                (root / "escape").symlink_to(outside, target_is_directory=True)
            except (NotImplementedError, OSError) as error:
                self.skipTest(f"directory symlinks unavailable: {error}")

            with self.assertRaisesRegex(SystemExit, "link or reparse point"):
                verify_release.regular_file(root, "escape/secret.txt")

    def test_rejects_unlisted_symlinked_package_entries(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "package"
            outside = Path(temporary_directory) / "outside"
            root.mkdir()
            outside.mkdir()
            try:
                (root / "unused-link").symlink_to(outside, target_is_directory=True)
            except (NotImplementedError, OSError) as error:
                self.skipTest(f"directory symlinks unavailable: {error}")

            with self.assertRaisesRegex(SystemExit, "link or reparse point"):
                verify_release.package_files(root)

    def write_package(self, root, payloads):
        root.mkdir(parents=True)
        records = []
        for relative, contents in payloads.items():
            path = root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(contents)
            records.append(
                {
                    "path": relative,
                    "bytes": len(contents),
                    "sha256": hashlib.sha256(contents).hexdigest(),
                }
            )
        manifest = {
            "schema": "shph-release-package/v1",
            "version": "0.1.0",
            "source_dirty": False,
            "files": records,
        }
        manifest_bytes = json.dumps(manifest).encode("utf-8")
        (root / "manifest.json").write_bytes(manifest_bytes)
        checksums = [
            f"{record['sha256']}  {record['path']}" for record in records
        ]
        checksums.append(
            f"{hashlib.sha256(manifest_bytes).hexdigest()}  manifest.json"
        )
        (root / "SHA256SUMS").write_text(
            "\n".join(checksums) + "\n", encoding="utf-8"
        )

    def valid_payloads(self, binary=b"release payload"):
        payloads = {"shph": binary}
        payloads.update({path: b"safe public documentation\n" for path in verify_release.PUBLIC_DOCUMENTS})
        return payloads

    def test_verifies_a_normal_allowlisted_package(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "package"
            self.write_package(root, self.valid_payloads())

            with contextlib.redirect_stdout(io.StringIO()):
                verify_release.verify(root, "0.1.0")

    def test_rejects_missing_or_invalid_version_without_expected_version(self):
        for version in (None, "not-semver"):
            with self.subTest(version=version), tempfile.TemporaryDirectory() as temporary_directory:
                root = Path(temporary_directory) / "package"
                self.write_package(root, self.valid_payloads())
                manifest_path = root / "manifest.json"
                manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
                if version is None:
                    manifest.pop("version")
                else:
                    manifest["version"] = version
                manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

                with self.assertRaisesRegex(SystemExit, "manifest version is missing or invalid"):
                    verify_release.verify(root, None)

    def test_rejects_oversized_manifest_and_checksums(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "manifest-package"
            self.write_package(root, self.valid_payloads())
            (root / "manifest.json").write_bytes(
                b" " * (verify_release.MAX_MANIFEST_BYTES + 1)
            )
            with self.assertRaisesRegex(SystemExit, "manifest.json exceeds"):
                verify_release.verify(root, None)

            root = Path(temporary_directory) / "checksums-package"
            self.write_package(root, self.valid_payloads())
            (root / "SHA256SUMS").write_bytes(
                b" " * (verify_release.MAX_CHECKSUMS_BYTES + 1)
            )
            with self.assertRaisesRegex(SystemExit, "SHA256SUMS exceeds"):
                verify_release.verify(root, None)

    def test_rejects_payload_size_above_packaging_limit(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "package"
            self.write_package(root, self.valid_payloads())
            manifest_path = root / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["files"][0]["bytes"] = verify_release.MAX_FILE_BYTES + 1
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

            with self.assertRaisesRegex(SystemExit, "payload exceeds"):
                verify_release.verify(root, None)

    def test_rejects_unexpected_empty_package_directories(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "package"
            self.write_package(root, self.valid_payloads())
            (root / "unexpected" / "empty").mkdir(parents=True)

            with self.assertRaisesRegex(SystemExit, "unexpected directories"):
                verify_release.verify(root, None)

    def test_rejects_manifest_listed_unexpected_private_key_file(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "package"
            payloads = self.valid_payloads()
            payloads["unexpected-private-key.pem"] = (
                b"-" * 5 + b"BEGIN " + b"PRIVATE KEY" + b"-" * 5
            )
            self.write_package(root, payloads)

            with self.assertRaisesRegex(SystemExit, "non-allowlisted payload"):
                verify_release.verify(root, "0.1.0")

    def test_scans_binary_payloads_for_secret_markers(self):
        with tempfile.TemporaryDirectory() as temporary_directory:
            root = Path(temporary_directory) / "package"
            payloads = self.valid_payloads(
                b"x" * (1024 * 1024 - 2) + b" ghp_" + b"A" * 24 + b"\n"
            )
            self.write_package(root, payloads)

            with self.assertRaisesRegex(SystemExit, "secret-like marker"):
                verify_release.verify(root, "0.1.0")


if __name__ == "__main__":
    unittest.main()
