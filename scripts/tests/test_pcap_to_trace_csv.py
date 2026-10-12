import hashlib
import importlib.util
import ipaddress
import json
import random
import struct
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT = Path(__file__).resolve().parents[1] / "pcap_to_trace_csv.py"
sys.path.insert(0, str(SCRIPT.parent))
import traffic_detectability as evaluator

SPEC = importlib.util.spec_from_file_location("pcap_to_trace_csv", SCRIPT)
pcap = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = pcap
SPEC.loader.exec_module(pcap)


def ethernet_ipv4(src, dst, protocol, source_port, destination_port, payload=b"", *, fragment=0, flags=0):
    if protocol == 6:
        transport = struct.pack("!HHIIHHHH", source_port, destination_port, 0, 0, (5 << 12) | flags, 0, 0, 0)
    else:
        transport = struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0)
    ip_payload = transport + payload
    ip_header = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(ip_payload),
        1,
        fragment,
        64,
        protocol,
        0,
        ipaddress.IPv4Address(src).packed,
        ipaddress.IPv4Address(dst).packed,
    )
    return b"\x00" * 12 + b"\x08\x00" + ip_header + ip_payload


def pcap_bytes(frames, *, byte_order="<", nanoseconds=False, truncated_index=None):
    if byte_order == "<":
        magic = b"\x4d\x3c\xb2\xa1" if nanoseconds else b"\xd4\xc3\xb2\xa1"
    else:
        magic = b"\xa1\xb2\x3c\x4d" if nanoseconds else b"\xa1\xb2\xc3\xd4"
    data = bytearray(magic + struct.pack(byte_order + "HHIIII", 2, 4, 0, 0, 1_000_064, 1))
    for index, (timestamp, frame) in enumerate(frames):
        seconds = int(timestamp)
        fractional = round((timestamp - seconds) * (1_000_000_000 if nanoseconds else 1_000_000))
        captured = len(frame) - (1 if truncated_index == index else 0)
        data.extend(struct.pack(byte_order + "IIII", seconds, fractional, captured, len(frame)))
        data.extend(frame[:captured])
    return bytes(data)


def options(path, **overrides):
    values = {
        "observer_address": "10.0.0.2",
        "remote_ports": [443],
        "endpoint_port": None,
        "candidate": "control-v1",
        "label": "control",
        "site_id": "site-01",
        "host_id": "host-01",
        "day_id": "day-01",
        "capture_id": "capture-01",
        "idle_timeout_ms": 1_000,
    }
    values.update(overrides)
    return pcap.parse_capture(path, **values)


class PcapConversionTests(unittest.TestCase):
    def test_rejects_spreadsheet_formula_prefixes_in_identifiers(self):
        frame = ethernet_ipv4("10.0.0.2", "198.51.100.5", 17, 50_000, 443)
        formula_values = ("=1+1", "+1+1", "-1+1", "@SUM(A1:A2)", "\ufeff=1+1")
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary) / "capture.pcap"
            capture.write_bytes(pcap_bytes([(1.0, frame)]))
            for field in ("candidate", "site_id", "host_id", "day_id", "capture_id"):
                for value in formula_values:
                    with self.subTest(field=field, value=value):
                        with self.assertRaisesRegex(
                            pcap.CaptureError, "spreadsheet formula prefix"
                        ):
                            options(capture, **{field: value})

    def test_formula_prefix_rejection_holds_for_generated_identifier_tails(self):
        generator = random.Random(7)
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789_.-"
        suffixes = ("",) + tuple(
            "".join(
                generator.choice(alphabet)
                for _ in range(generator.randint(1, 24))
            )
            for _ in range(64)
        )
        for field in ("candidate", "site_id", "host_id", "day_id", "capture_id"):
            for prefix in ("=", "+", "-", "@", "\ufeff="):
                for suffix in suffixes:
                    with self.subTest(field=field, prefix=prefix, suffix=suffix):
                        with self.assertRaisesRegex(
                            pcap.CaptureError, "spreadsheet formula prefix"
                        ):
                            pcap._validate_identifier(
                                prefix + suffix,
                                field,
                                slug=(field == "capture_id"),
                            )

    def test_converts_bidirectional_ipv4_packets_without_identifiers_or_absolute_time(self):
        frames = [
            (100.0, ethernet_ipv4("10.0.0.2", "198.51.100.5", 17, 50_000, 443, b"first")),
            (100.5, ethernet_ipv4("198.51.100.5", "10.0.0.2", 17, 443, 50_000, b"reply")),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary) / "private-name.pcap"
            capture.write_bytes(pcap_bytes(frames))
            rows, manifest = options(capture)

        self.assertEqual([row[7] for row in rows], ["out", "in"])
        self.assertEqual(rows[0][2], rows[1][2])
        self.assertEqual([row[6] for row in rows], ["0", "0.5"])
        self.assertEqual([row[8] for row in rows], ["33", "33"])
        self.assertEqual(manifest["capture_sha256"], hashlib.sha256(pcap_bytes(frames)).hexdigest())
        self.assertNotIn("10.0.0.2", json.dumps(manifest))
        self.assertNotIn("private-name.pcap", json.dumps(manifest))

    def test_supports_big_endian_nanosecond_pcap_and_vlan(self):
        frame = ethernet_ipv4("10.0.0.2", "198.51.100.5", 17, 50_000, 443)
        frame = frame[:12] + b"\x81\x00\x00\x01\x08\x00" + frame[14:]
        reply = ethernet_ipv4("198.51.100.5", "10.0.0.2", 17, 443, 50_000)
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary) / "capture.pcap"
            capture.write_bytes(pcap_bytes(
                [(12.000000123, bytes(frame)), (12.000000323, reply)],
                byte_order=">",
                nanoseconds=True,
            ))
            rows, _ = options(capture)
        self.assertEqual(rows[0][6], "0")
        self.assertEqual(rows[0][7], "out")
        self.assertEqual(rows[1][6], "0.0000002")
        self.assertEqual(rows[1][7], "in")

    def test_converts_ipv6_transport_packets(self):
        source = ipaddress.IPv6Address("2001:db8::2")
        destination = ipaddress.IPv6Address("2001:db8::5")
        transport = struct.pack("!HHHH", 50_000, 443, 8, 0)
        ipv6 = struct.pack(
            "!IHBB16s16s",
            6 << 28,
            len(transport),
            17,
            64,
            source.packed,
            destination.packed,
        )
        frame = b"\x00" * 12 + b"\x86\xdd" + ipv6 + transport
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary) / "ipv6.pcap"
            capture.write_bytes(pcap_bytes([(1.0, frame)]))
            rows, _ = options(capture, observer_address=str(source))
        self.assertEqual(rows[0][7], "out")
        self.assertEqual(rows[0][8], "48")

    def test_idle_timeout_starts_a_new_udp_session(self):
        frames = [
            (1.0, ethernet_ipv4("10.0.0.2", "198.51.100.5", 17, 50_000, 443)),
            (3.0, ethernet_ipv4("10.0.0.2", "198.51.100.5", 17, 50_000, 443)),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary) / "capture.pcap"
            capture.write_bytes(pcap_bytes(frames))
            rows, _ = options(capture)
        self.assertNotEqual(rows[0][2], rows[1][2])
        self.assertEqual(rows[1][6], "0")

    def test_tcp_close_starts_a_fresh_session_for_reused_five_tuple(self):
        frames = [
            (1.0, ethernet_ipv4("10.0.0.2", "198.51.100.5", 6, 50_000, 443)),
            (1.1, ethernet_ipv4("10.0.0.2", "198.51.100.5", 6, 50_000, 443, flags=1)),
            (1.2, ethernet_ipv4("10.0.0.2", "198.51.100.5", 6, 50_000, 443)),
        ]
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary) / "capture.pcap"
            capture.write_bytes(pcap_bytes(frames))
            rows, _ = options(capture)
        self.assertEqual(rows[0][2], rows[1][2])
        self.assertNotEqual(rows[1][2], rows[2][2])

    def test_rejects_truncation_fragments_out_of_order_time_and_pcapng(self):
        valid = ethernet_ipv4("10.0.0.2", "198.51.100.5", 17, 50_000, 443)
        cases = [
            pcap_bytes([(1.0, valid)], truncated_index=0),
            pcap_bytes([(1.0, ethernet_ipv4("10.0.0.2", "198.51.100.5", 17, 50_000, 443, fragment=0x2000))]),
            pcap_bytes([(2.0, valid), (1.0, valid)]),
            b"\x0a\x0d\x0d\x0a" + b"\x00" * 64,
        ]
        with tempfile.TemporaryDirectory() as temporary:
            for index, content in enumerate(cases):
                capture = Path(temporary) / f"invalid-{index}.pcap"
                capture.write_bytes(content)
                with self.subTest(index=index), self.assertRaises(pcap.CaptureError):
                    options(capture)

    def test_ambiguous_loopback_direction_requires_endpoint_port(self):
        frame = ethernet_ipv4("127.0.0.1", "127.0.0.1", 17, 50_000, 443)
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary) / "loopback.pcap"
            capture.write_bytes(pcap_bytes([(1.0, frame)]))
            with self.assertRaisesRegex(pcap.CaptureError, "direction is ambiguous"):
                options(capture, observer_address="127.0.0.1")
            rows, _ = options(capture, observer_address="127.0.0.1", endpoint_port=50_000)
        self.assertEqual(rows[0][7], "out")

    def test_output_bundle_is_atomic_and_refuses_overwrite(self):
        frames = [(1.0, ethernet_ipv4("10.0.0.2", "198.51.100.5", 17, 50_000, 443))]
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary) / "capture.pcap"
            output = Path(temporary) / "bundle"
            capture.write_bytes(pcap_bytes(frames))
            rows, manifest = options(capture)
            pcap.write_capture_bundle(output, rows, manifest)
            self.assertEqual((output / "traces.csv").read_text().splitlines()[0], ",".join(pcap.CSV_COLUMNS))
            self.assertEqual(json.loads((output / "provenance.json").read_text())["session_count"], 1)
            with self.assertRaisesRegex(pcap.CaptureError, "already exists"):
                pcap.write_capture_bundle(output, rows, manifest)

    def test_capture_bundles_load_as_one_grouped_evaluation_dataset(self):
        labels = ("target", "control", "target")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            csv_paths = []
            for index, label in enumerate(labels):
                capture = root / f"input-{index}.pcap"
                bundle = root / f"bundle-{index}"
                frame = ethernet_ipv4(
                    "10.0.0.2",
                    f"198.51.100.{index + 1}",
                    17,
                    50_000 + index,
                    443,
                )
                capture.write_bytes(pcap_bytes([(100.0, frame)]))
                rows, manifest = options(
                    capture,
                    candidate="baseline",
                    label=label,
                    site_id=f"site-{index}",
                    host_id=f"host-{index}",
                    day_id=f"day-{index}",
                    capture_id=f"capture-{index}",
                )
                pcap.write_capture_bundle(bundle, rows, manifest)
                csv_paths.append(bundle / "traces.csv")
            dataset = evaluator.load_dataset(csv_paths)

        self.assertEqual(dataset.candidates, ("baseline",))
        self.assertEqual(dataset.data_rows, 3)
        self.assertEqual(len(dataset.groups), 3)
        self.assertEqual(len(dataset.observations), 3)

    def test_candidate_limit_matches_the_evaluator_schema(self):
        frame = ethernet_ipv4("10.0.0.2", "198.51.100.5", 17, 50_000, 443)
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary) / "capture.pcap"
            capture.write_bytes(pcap_bytes([(1.0, frame)]))
            with self.assertRaisesRegex(pcap.CaptureError, "candidate is empty or exceeds"):
                options(capture, candidate="x" * (pcap.MAX_CANDIDATE_CHARS + 1))

    def test_arbitrary_short_inputs_fail_with_bounded_parser_errors(self):
        generator = random.Random(17)
        with tempfile.TemporaryDirectory() as temporary:
            capture = Path(temporary) / "fuzz.pcap"
            for _ in range(256):
                capture.write_bytes(generator.randbytes(generator.randrange(0, 96)))
                with self.assertRaises(pcap.CaptureError):
                    options(capture)


if __name__ == "__main__":
    unittest.main()
