import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[2]
SYNC_SCRIPT = REPO_ROOT / "scripts" / "sync_mirror.sh"


def run(command, cwd=None, env=None):
    return subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )


class MirrorSyncTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not shutil.which("git") or not shutil.which("rsync"):
            raise unittest.SkipTest("git and rsync are required")

    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name)
        self.linux = self.root / "linux"
        self.windows = self.root / "windows"
        self.linux.mkdir()
        (self.linux / "src").mkdir()
        (self.linux / "src" / "main.rs").write_text("base\n", encoding="utf-8")
        (self.linux / "Cargo.lock").write_text("linux lock\n", encoding="utf-8")
        run(["git", "init", "-b", "main"], cwd=self.linux)
        run(["git", "config", "user.name", "Mirror Test"], cwd=self.linux)
        run(["git", "config", "user.email", "mirror-test@example.invalid"], cwd=self.linux)
        run(["git", "add", "."], cwd=self.linux)
        run(["git", "commit", "-m", "base"], cwd=self.linux)
        run(["git", "clone", str(self.linux), str(self.windows)], cwd=self.root)
        run(["git", "config", "user.name", "Mirror Test"], cwd=self.windows)
        run(["git", "config", "user.email", "mirror-test@example.invalid"], cwd=self.windows)
        (self.windows / "src" / "main.rs").write_text("stash content\n", encoding="utf-8")
        run(["git", "stash", "push", "-m", "preserve-mirror-stash"], cwd=self.windows)
        self.stash_commit = run(
            ["git", "rev-parse", "refs/stash"], cwd=self.windows
        ).stdout.strip()
        (self.linux / "src" / "main.rs").write_text("linux update\n", encoding="utf-8")
        (self.windows / "src" / "main.rs").write_text("windows edit\n", encoding="utf-8")
        (self.windows / "Cargo.lock").write_text("windows lock\n", encoding="utf-8")
        (self.windows / "windows-only.txt").write_text("keep me\n", encoding="utf-8")
        (self.windows / "target").mkdir()
        (self.windows / "target" / "cache.bin").write_bytes(b"build sentinel")

    def tearDown(self):
        self.temporary_directory.cleanup()

    def sync(self, *arguments, check=True, env=None):
        environment = os.environ.copy()
        environment["SHPH_SYNC_LINUX_DIR"] = str(self.linux)
        environment["SHPH_SYNC_WINDOWS_DIR"] = str(self.windows)
        if env is not None:
            environment.update(env)
        return subprocess.run(
            [str(SYNC_SCRIPT), "--to-windows", *arguments],
            cwd=REPO_ROOT,
            env=environment,
            check=check,
            capture_output=True,
            text=True,
        )

    def verify(self, env=None):
        environment = os.environ.copy()
        environment["SHPH_SYNC_LINUX_DIR"] = str(self.linux)
        environment["SHPH_SYNC_WINDOWS_DIR"] = str(self.windows)
        if env is not None:
            environment.update(env)
        return subprocess.run(
            [str(SYNC_SCRIPT), "--verify"],
            cwd=REPO_ROOT,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )

    def test_dirty_destination_requires_review_before_sync(self):
        result = self.sync("--dry-run", check=False)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("review it", result.stderr)
        self.assertEqual(
            (self.windows / "src" / "main.rs").read_text(encoding="utf-8"),
            "windows edit\n",
        )
        self.assertEqual(
            run(["git", "rev-parse", "refs/stash"], cwd=self.windows).stdout.strip(),
            self.stash_commit,
        )

    def test_sync_preserves_destination_only_files_and_git_state_by_default(self):
        result = self.sync("--accept-dirty-destination", check=False)

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertEqual(
            (self.windows / "src" / "main.rs").read_text(encoding="utf-8"),
            "linux update\n",
        )
        self.assertEqual(
            (self.windows / "Cargo.lock").read_text(encoding="utf-8"),
            "windows lock\n",
        )
        self.assertEqual(
            (self.windows / "windows-only.txt").read_text(encoding="utf-8"),
            "keep me\n",
        )
        self.assertEqual(
            (self.windows / "target" / "cache.bin").read_bytes(), b"build sentinel"
        )
        self.assertEqual(
            run(["git", "rev-parse", "refs/stash"], cwd=self.windows).stdout.strip(),
            self.stash_commit,
        )

    def test_explicit_prune_removes_only_unexcluded_destination_files(self):
        result = self.sync(
            "--accept-dirty-destination",
            "--prune-destination-only",
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertFalse((self.windows / "windows-only.txt").exists())
        self.assertTrue((self.windows / "target" / "cache.bin").exists())
        self.assertEqual(
            (self.windows / "Cargo.lock").read_text(encoding="utf-8"),
            "windows lock\n",
        )
        self.assertEqual(
            run(["git", "rev-parse", "refs/stash"], cwd=self.windows).stdout.strip(),
            self.stash_commit,
        )

    def test_sync_does_not_copy_or_prune_ignored_local_files(self):
        (self.linux / ".gitignore").write_text(".env\n", encoding="utf-8")
        (self.linux / ".env").write_text("linux secret sentinel\n", encoding="utf-8")
        (self.windows / ".env").write_text("windows local sentinel\n", encoding="utf-8")

        result = self.sync(
            "--accept-dirty-destination",
            "--prune-destination-only",
            check=False,
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(
            (self.windows / ".env").read_text(encoding="utf-8"),
            "windows local sentinel\n",
        )
        self.assertFalse((self.windows / "windows-only.txt").exists())

    def test_preflight_rejects_different_active_branches(self):
        run(["git", "branch", "secondary"], cwd=self.linux)
        run(["git", "branch", "secondary"], cwd=self.windows)
        run(["git", "checkout", "secondary"], cwd=self.windows)

        result = self.sync("--dry-run", check=False)

        self.assertNotEqual(result.returncode, 0)
        self.assertIn("active branches differ", result.stderr)

    def test_verify_detects_symlink_differences(self):
        try:
            (self.linux / "source-link").symlink_to("src/main.rs")
        except (NotImplementedError, OSError) as error:
            self.skipTest(f"file symlinks unavailable: {error}")

        result = self.verify()

        self.assertEqual(result.returncode, 3, result.stdout + result.stderr)
        self.assertIn("source-link", result.stdout)

    def test_verify_preserves_rsync_failure_exit_code(self):
        fake_bin = self.root / "fake-bin"
        fake_bin.mkdir()
        fake_rsync = fake_bin / "rsync"
        fake_rsync.write_text("#!/bin/sh\nexit 17\n", encoding="utf-8")
        fake_rsync.chmod(0o755)

        result = self.verify({"PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}"})

        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_sync_preserves_post_sync_rsync_failure_exit_code(self):
        fake_bin = self.root / "fake-bin"
        fake_bin.mkdir()
        fake_rsync = fake_bin / "rsync"
        fake_rsync.write_text(
            "#!/bin/sh\n"
            "if [ -e \"$RSYNC_CALLS\" ]; then exit 17; fi\n"
            ": > \"$RSYNC_CALLS\"\n"
            "exit 0\n",
            encoding="utf-8",
        )
        fake_rsync.chmod(0o755)

        result = self.sync(
            "--accept-dirty-destination",
            check=False,
            env={
                "PATH": f"{fake_bin}{os.pathsep}{os.environ['PATH']}",
                "RSYNC_CALLS": str(self.root / "rsync-calls"),
            },
        )

        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_separate_git_dir_pointer_files_are_preserved(self):
        source = self.root / "separate-linux"
        destination = self.root / "separate-windows"
        source_git = self.root / "separate-linux.git"
        destination_git = self.root / "separate-windows.git"
        source.mkdir()
        run(
            ["git", "init", "--quiet", "-b", "main", f"--separate-git-dir={source_git}", str(source)],
            cwd=self.root,
        )
        (source / "source.txt").write_text("source\n", encoding="utf-8")
        run(["git", "-C", str(source), "config", "user.name", "Mirror Test"])
        run(["git", "-C", str(source), "config", "user.email", "mirror-test@example.invalid"])
        run(["git", "-C", str(source), "add", "."])
        run(["git", "-C", str(source), "commit", "-m", "base"])
        run(
            [
                "git",
                "clone",
                "--quiet",
                "--branch",
                "main",
                f"--separate-git-dir={destination_git}",
                str(source),
                str(destination),
            ],
            cwd=self.root,
        )
        original_pointer = (destination / ".git").read_text(encoding="utf-8")
        environment = os.environ.copy()
        environment["SHPH_SYNC_LINUX_DIR"] = str(source)
        environment["SHPH_SYNC_WINDOWS_DIR"] = str(destination)

        result = subprocess.run(
            [str(SYNC_SCRIPT), "--to-windows"],
            cwd=REPO_ROOT,
            env=environment,
            check=False,
            capture_output=True,
            text=True,
        )

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((destination / ".git").read_text(encoding="utf-8"), original_pointer)
        self.assertEqual(
            run(["git", "-C", str(destination), "rev-parse", "HEAD"]).stdout.strip(),
            run(["git", "-C", str(source), "rev-parse", "HEAD"]).stdout.strip(),
        )


if __name__ == "__main__":
    unittest.main()
