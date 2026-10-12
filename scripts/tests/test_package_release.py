import importlib.util
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "package_release.py"
SPEC = importlib.util.spec_from_file_location("package_release", SCRIPT)
package_release = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(package_release)


class ReleasePackagingTests(unittest.TestCase):
    def test_snap_profile_guide_is_in_public_release_documents(self):
        self.assertIn("docs/SNAP_PROFILES.md", package_release.PUBLIC_DOCUMENTS)
        self.assertIn("docs/SNAP_ACCEPTANCE_EVIDENCE.md", package_release.PUBLIC_DOCUMENTS)

    def test_system_exit_removes_partially_written_staging_directory(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repository"
            root.mkdir()
            binary = root / "shph"
            binary.write_bytes(b"test binary")
            output = Path(temporary) / "release" / "package"
            arguments = SimpleNamespace(
                root=root,
                binary=binary,
                edge_binary=None,
                output=output,
                allow_dirty=False,
            )

            def fail_after_copy(staging, *_args):
                (staging / "shph").write_bytes(b"secret-bearing test artifact")
                package_release.fail("simulated secret marker failure")

            with (
                mock.patch.object(package_release, "parse_args", return_value=arguments),
                mock.patch.object(package_release, "run_git", return_value=""),
                mock.patch.object(package_release, "package_files", side_effect=fail_after_copy),
                self.assertRaisesRegex(SystemExit, "simulated secret marker failure"),
            ):
                package_release.main()

            self.assertFalse(output.exists())
            self.assertEqual(list(output.parent.glob(".package.staging-*")), [])

    def test_rejects_symlinked_package_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repository"
            root.mkdir()
            outside = Path(temporary) / "outside"
            outside.write_bytes(b"test artifact")
            link = root / "shph"
            try:
                link.symlink_to(outside)
            except (NotImplementedError, OSError) as error:
                self.skipTest(f"symlinks unavailable: {error}")

            with self.assertRaisesRegex(SystemExit, "link or reparse point"):
                package_release.validate_repository_file(
                    link, root, max_bytes=package_release.MAX_FILE_BYTES
                )


if __name__ == "__main__":
    unittest.main()
