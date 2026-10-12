import io
import os
import sys
import tempfile
import unittest
from contextlib import redirect_stderr
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import edge_active_probe as probe


class EndpointValidationTests(unittest.TestCase):
    def test_https_domain_origin_is_pinned_to_loopback(self):
        host, port, origin = probe.parse_origin("https://edge.example:8443")

        self.assertEqual((host, port, origin), ("edge.example", 8443, "https://edge.example:8443"))

    def test_only_local_literal_addresses_are_accepted(self):
        self.assertEqual(probe.parse_origin("https://127.0.0.2:443")[:2], ("127.0.0.2", 443))
        with self.assertRaisesRegex(probe.ProbeError, "loopback"):
            probe.parse_origin("https://203.0.113.10:443")
        with self.assertRaisesRegex(probe.ProbeError, "IPv6"):
            probe.parse_origin("https://[::1]:443")

    def test_non_https_or_non_origin_endpoints_are_rejected(self):
        for endpoint in (
            "http://edge.example:8443",
            "https://user:pass@edge.example:8443",
            "https://edge.example:8443/relay",
            "https://edge.example:8443?probe=1",
        ):
            with self.subTest(endpoint=endpoint), self.assertRaises(probe.ProbeError):
                probe.parse_origin(endpoint)

    def test_port_zero_is_rejected_instead_of_using_the_default_port(self):
        with self.assertRaisesRegex(probe.ProbeError, "port must be between"):
            probe.parse_origin("https://127.0.0.1:0")

    def test_relay_path_is_bounded_and_cannot_smuggle_query_or_fragment(self):
        self.assertEqual(probe.validate_relay_path("/owned/relay-v2"), "/owned/relay-v2")
        for path in ("relative", "/x?y=1", "/x#fragment", "/x\\y", "/" + "a" * 128):
            with self.subTest(path=path), self.assertRaises(probe.ProbeError):
                probe.validate_relay_path(path)


class CapabilityHelpersTests(unittest.TestCase):
    def test_invalid_signature_changes_only_signature_component(self):
        token = "phantom-one.1.payload.signatureA"

        self.assertEqual(probe.tamper_signature(token), "phantom-one.1.payload.AignatureA")

    def test_malformed_token_cannot_be_used_as_signature_probe(self):
        with self.assertRaisesRegex(probe.ProbeError, "valid token"):
            probe.tamper_signature("not-a-token")

    def test_token_reader_is_bounded_and_accepts_one_line(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "token"
            path.write_bytes(b"token-value\n")
            self.assertEqual(probe.read_token(path, "token"), "token-value")
            path.write_bytes(b"first\nsecond\n")
            with self.assertRaisesRegex(probe.ProbeError, "exactly one"):
                probe.read_token(path, "token")
            path.write_bytes(b"x" * (probe.MAX_TOKEN_BYTES + 1))
            with self.assertRaisesRegex(probe.ProbeError, "exceeds"):
                probe.read_token(path, "token")

    @unittest.skipUnless(hasattr(os, "mkfifo") and hasattr(os, "O_NONBLOCK"), "requires POSIX FIFO")
    def test_token_reader_rejects_fifo_without_blocking(self):
        with tempfile.TemporaryDirectory() as directory:
            fifo = Path(directory) / "token.fifo"
            os.mkfifo(fifo)
            with self.assertRaisesRegex(probe.ProbeError, "regular file"):
                probe.read_token(fifo, "token")

    def test_token_never_enters_curl_command_arguments(self):
        with mock.patch.object(probe.subprocess, "run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = b"401\t2\t0.01\t0.02\t0.03\t0.04\t11"
            run.return_value.stderr = b""
            with mock.patch.object(probe.Path, "read_bytes", return_value=b"body"):
                result = probe._curl_probe(
                    curl="curl",
                    host="edge.example",
                    port=443,
                    origin="https://edge.example:443",
                    path="/phantom-one/v1",
                    method="POST",
                    headers=["x-phantom-one-capability: secret-token"],
                    ca_file=Path("ca.pem"),
                    timeout_seconds=1,
                )
            command = run.call_args.args[0]
            self.assertEqual(command[1], "-q")
            self.assertEqual(command[2], "--http2")
            self.assertNotIn("secret-token", command)
            self.assertIn("edge.example:443:127.0.0.1", command)
            self.assertIn(b"secret-token", run.call_args.kwargs["input"])
            self.assertEqual(result["status"], 401)


class ProbeBoundsTests(unittest.TestCase):
    def test_curl_requires_http2_and_in_transfer_size_limit_support(self):
        with mock.patch.object(probe.subprocess, "run") as run:
            run.return_value.returncode = 0
            run.return_value.stdout = "curl 8.3.0\nFeatures: HTTP2\n"
            self.assertFalse(probe.curl_supports_http2("curl"))

            run.return_value.stdout = "curl 8.4.0\nFeatures: HTTP2\n"
            self.assertTrue(probe.curl_supports_http2("curl"))

            run.return_value.stdout = "curl 8.4.0\nFeatures: HTTPS-proxy\n"
            self.assertFalse(probe.curl_supports_http2("curl"))

            probe.curl_supports_http2("curl", timeout_seconds=0.25)
            self.assertEqual(run.call_args.kwargs["timeout"], 0.25)

    def test_curl_header_config_escapes_quotes_and_rejects_newlines(self):
        self.assertEqual(probe.curl_config_header('x-test: a"b'), 'header = "x-test: a\\"b"')
        with self.assertRaises(probe.ProbeError):
            probe.curl_config_header("x-test: a\nb")

    def test_cli_requires_owned_endpoint_confirmation_and_clamps_counts(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            probe.main(["--endpoint", "https://127.0.0.1:443", "--ca-file", "ca.pem"])
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            probe.main(
                [
                    "--endpoint",
                    "https://127.0.0.1:443",
                    "--ca-file",
                    "ca.pem",
                    "--confirm-owned-endpoint",
                    "--repeat",
                    str(probe.MAX_REPEATS + 1),
                ]
            )


if __name__ == "__main__":
    unittest.main()
