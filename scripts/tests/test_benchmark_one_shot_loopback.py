import contextlib
import io
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import benchmark_one_shot_loopback as benchmark


class ArgumentBoundsTests(unittest.TestCase):
    def test_default_run_is_bounded_and_compares_both_modes(self):
        args = benchmark.parse_args([])

        self.assertEqual(args.iterations, 3)
        self.assertEqual(args.mode, "both")
        self.assertEqual(args.transport, "tcp")
        self.assertLessEqual(args.iterations, benchmark.MAX_ITERATIONS)

    def test_out_of_bounds_values_are_rejected(self):
        for arguments in (
            ["--iterations", "0"],
            ["--iterations", str(benchmark.MAX_ITERATIONS + 1)],
            ["--timeout-secs", "0"],
            ["--timeout-secs", str(benchmark.MAX_TIMEOUT_SECS + 1)],
            ["--payload-bytes", str(benchmark.MIN_PAYLOAD_BYTES - 1)],
            ["--payload-bytes", str(benchmark.MAX_PAYLOAD_BYTES + 1)],
            ["--transport", "offline-mesh"],
        ):
            with self.subTest(arguments=arguments), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    benchmark.parse_args(arguments)


class MeasurementHelperTests(unittest.TestCase):
    def test_payload_has_exact_size_and_distinct_session_marker(self):
        first = benchmark.make_payload(1, 128)
        second = benchmark.make_payload(2, 128)

        self.assertEqual(len(first.encode("ascii")), 128)
        self.assertEqual(len(second.encode("ascii")), 128)
        self.assertNotEqual(first, second)

    def test_summary_reports_percentiles_without_claiming_other_metrics(self):
        summary = benchmark.summarize([1.0, 2.0, 3.0, 100.0])

        self.assertEqual(summary["samples"], 4)
        self.assertEqual(summary["median_ms"], 2.5)
        self.assertEqual(summary["p95_ms"], 100.0)
        self.assertEqual(summary["p99_ms"], 100.0)

    def test_manifest_is_explicitly_loopback_and_non_capture(self):
        with mock.patch.object(benchmark, "create_identity") as create_identity, \
                mock.patch.object(benchmark, "choose_loopback_port", return_value=45454), \
                mock.patch.object(benchmark, "check_peer_command"), \
                mock.patch.object(benchmark, "run_session", return_value=12.5), \
                mock.patch.object(benchmark, "git_state", return_value={"commit": "abc", "working_tree_dirty": True}), \
                mock.patch.object(benchmark.subprocess, "run") as subprocess_run, \
                tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)

            def identity(_binary, directory, role, _timeout):
                config = directory / "config.toml"
                return config, f"{role}-public", f"{role}-signing-public"

            create_identity.side_effect = identity
            subprocess_run.return_value.returncode = 0
            subprocess_run.return_value.stdout = "rustc test\n"
            args = benchmark.parse_args(["--iterations", "1", "--mode", "both"])
            manifest = benchmark.run_benchmark(args, root / "shph")

        self.assertEqual(manifest["scope"], "local-loopback-cli-session-observation")
        self.assertEqual(manifest["environment"]["endpoint_scope"], "127.0.0.1 only")
        self.assertEqual(manifest["workload"]["modes"], ["baseline", "negotiated"])
        self.assertEqual(manifest["unmeasured"]["network_packet_capture"], "not performed")
        self.assertIn("not_P5_acceptance", manifest["evidence_status"])
        self.assertTrue(all(row["payload_verified_by_receiver"] for row in manifest["measurements"]))


class OutputSafetyTests(unittest.TestCase):
    def test_output_refuses_to_overwrite_an_existing_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            output = Path(temporary) / "manifest.json"
            output.write_text("preserve", encoding="utf-8")
            with mock.patch.object(benchmark, "resolve_binary", return_value=Path("shph")), \
                    mock.patch.object(benchmark, "run_benchmark", return_value={"ok": True}), \
                    contextlib.redirect_stderr(io.StringIO()):
                status = benchmark.main(["--output", str(output)])

            self.assertEqual(status, 1)
            self.assertEqual(output.read_text(encoding="utf-8"), "preserve")


if __name__ == "__main__":
    unittest.main()
