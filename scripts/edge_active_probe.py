#!/usr/bin/env python3
"""Run bounded active probes against an operator-owned local SHPH edge.

The HTTPS hostname is resolved by curl to 127.0.0.1, so this tool only probes
an edge exposed on loopback (including through an operator-created SSH tunnel).
It records response metadata and hashes, never response bodies or capabilities.
"""

from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
import re
import shutil
import stat
import socket
import ssl
import subprocess
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Sequence
from urllib.parse import urlsplit


MAX_REPEATS = 10
MAX_CHURN = 50
MAX_TIMEOUT_SECONDS = 10
MAX_RUNTIME_SECONDS = 120
MAX_RESPONSE_BYTES = 64 * 1024
MAX_TOKEN_BYTES = 4096
MAX_CA_FILE_BYTES = 1024 * 1024
DEFAULT_RELAY_PATH = "/phantom-one/v1"
HTTP2_WRITE_OUT = (
    "%{http_code}\\t%{http_version}\\t%{time_connect}\\t"
    "%{time_appconnect}\\t%{time_starttransfer}\\t%{time_total}\\t"
    "%{size_download}"
)
HTTP2_CLIENT_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


class ProbeError(Exception):
    """Invalid probe configuration or unavailable required tooling."""


def parse_origin(value: str) -> tuple[str, int, str]:
    try:
        parsed = urlsplit(value)
        parsed_port = parsed.port
        port = 443 if parsed_port is None else parsed_port
    except ValueError as error:
        raise ProbeError("endpoint has an invalid authority or port") from error
    if (
        parsed.scheme.lower() != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in ("", "/")
        or parsed.query
        or parsed.fragment
    ):
        raise ProbeError("endpoint must be an HTTPS origin without credentials or path")
    host = parsed.hostname
    if ":" in host:
        raise ProbeError("IPv6 endpoint names are not supported by the loopback probe")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        try:
            host = host.encode("idna").decode("ascii")
        except UnicodeError as error:
            raise ProbeError("endpoint hostname is invalid") from error
        normalized_host = host[:-1] if host.endswith(".") else host
        labels = normalized_host.split(".")
        if len(host) > 253 or any(
            not label
            or len(label) > 63
            or not label[0].isalnum()
            or not label[-1].isalnum()
            or any(not (char.isalnum() or char == "-") for char in label)
            for label in labels
        ):
            raise ProbeError("endpoint hostname is invalid")
    else:
        if not isinstance(address, ipaddress.IPv4Address) or not address.is_loopback:
            raise ProbeError("literal endpoint addresses must be IPv4 loopback addresses")
    if not 1 <= port <= 65535:
        raise ProbeError("endpoint port must be between 1 and 65535")
    return host, port, f"https://{host}:{port}"


def validate_relay_path(value: str) -> str:
    if (
        not value.startswith("/")
        or len(value.encode("utf-8")) > 128
        or not value.isascii()
        or any(ord(char) <= 0x20 or char in "?#\\" for char in value)
    ):
        raise ProbeError("relay path must be bounded ASCII path text without query or fragment")
    return value


def read_token(path: Path | None, label: str, required: bool = False) -> str | None:
    if path is None:
        if required:
            raise ProbeError(f"{label} is required for this probe")
        return None
    descriptor: int | None = None
    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0)
        flags |= getattr(os, "O_NONBLOCK", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        if not stat.S_ISREG(os.fstat(descriptor).st_mode):
            raise ProbeError(f"{label} must be a regular file")
        with os.fdopen(descriptor, "rb") as stream:
            descriptor = None
            token_bytes = stream.read(MAX_TOKEN_BYTES + 1)
    except ProbeError:
        raise
    except OSError as error:
        raise ProbeError(f"cannot read {label}") from error
    finally:
        if descriptor is not None:
            os.close(descriptor)
    if len(token_bytes) > MAX_TOKEN_BYTES:
        raise ProbeError(f"{label} exceeds {MAX_TOKEN_BYTES} bytes")
    try:
        lines = token_bytes.decode("ascii").splitlines()
    except UnicodeDecodeError as error:
        raise ProbeError(f"{label} must contain ASCII text") from error
    tokens = [line.strip() for line in lines if line.strip()]
    if len(tokens) != 1 or any(any(ord(char) < 0x21 or ord(char) > 0x7E for char in token) for token in tokens):
        raise ProbeError(f"{label} must contain exactly one printable ASCII token")
    return tokens[0]


def tamper_signature(token: str) -> str:
    parts = token.split(".")
    if len(parts) != 4 or parts[0] != "phantom-one" or parts[1] != "1" or not parts[3]:
        raise ProbeError("a valid token file is required to probe invalid signatures")
    replacement = "B" if parts[3][0] == "A" else "A"
    parts[3] = replacement + parts[3][1:]
    return ".".join(parts)


def curl_supports_http2(curl: str, timeout_seconds: float = 5.0) -> bool:
    if timeout_seconds <= 0:
        return False
    try:
        result = subprocess.run(
            [curl, "--version"],
            capture_output=True,
            text=True,
            timeout=min(5.0, timeout_seconds),
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    version = re.search(r"(?m)^curl (\d+)\.(\d+)\.(\d+)", result.stdout)
    return (
        result.returncode == 0
        and version is not None
        and tuple(map(int, version.groups())) >= (8, 4, 0)
        and "HTTP2" in result.stdout
    )


def curl_config_header(value: str) -> str:
    if "\r" in value or "\n" in value:
        raise ProbeError("header values cannot contain line breaks")
    escaped = value.replace("\\", "\\\\").replace('"', '\\"')
    return f'header = "{escaped}"'


def _curl_probe(
    *,
    curl: str,
    host: str,
    port: int,
    origin: str,
    path: str,
    method: str,
    headers: Sequence[str],
    ca_file: Path,
    timeout_seconds: float,
    capture_response: bool = True,
) -> dict[str, object]:
    url = f"{origin}{path}"
    config = "\n".join(curl_config_header(header) for header in headers).encode("ascii")
    with tempfile.TemporaryDirectory(prefix="shph-edge-probe-") as temp_dir:
        body_path = Path(temp_dir) / "response.bin"
        args = [
            curl,
            "-q",
            "--http2",
            "--silent",
            "--show-error",
            "--noproxy",
            "*",
            "--resolve",
            f"{host}:{port}:127.0.0.1",
            "--cacert",
            str(ca_file),
            "--connect-timeout",
            f"{min(timeout_seconds, 3.0):.3f}",
            "--max-time",
            f"{timeout_seconds:.3f}",
            "--max-filesize",
            str(MAX_RESPONSE_BYTES),
            "--output",
            str(body_path) if capture_response else os.devnull,
            "--write-out",
            HTTP2_WRITE_OUT,
            "--request",
            method,
            "--config",
            "-",
            url,
        ]
        if method == "POST":
            args.extend(["--data-binary", ""])
        started = time.monotonic()
        try:
            result = subprocess.run(
                args,
                input=config,
                capture_output=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return {
                "outcome": "timeout",
                "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
                "response_bytes": 0,
                "response_sha256": hashlib.sha256(b"").hexdigest(),
            }
        body = body_path.read_bytes() if capture_response and body_path.exists() else b""
        report: dict[str, object] = {
            "curl_exit_code": result.returncode,
            "response_bytes": len(body) if capture_response else None,
            "response_sha256": hashlib.sha256(body).hexdigest() if capture_response else None,
        }
        fields = result.stdout.decode("ascii", errors="replace").strip().split("\t")
        if len(fields) == 7:
            try:
                status = int(fields[0]) or None
                http_version = fields[1]
                connect_seconds, tls_seconds, ttfb_seconds, total_seconds = map(float, fields[2:6])
                downloaded_bytes = int(float(fields[6]))
                report.update(
                    {
                        "outcome": "response"
                        if status is not None and http_version == "2"
                        else "wrong_http_version"
                        if status is not None
                        else "no_http_response",
                        "status": status,
                        "http_version": http_version,
                        "connect_ms": round(connect_seconds * 1000, 3),
                        "tls_ms": round(tls_seconds * 1000, 3),
                        "first_byte_ms": round(ttfb_seconds * 1000, 3),
                        "total_ms": round(total_seconds * 1000, 3),
                        "reported_response_bytes": downloaded_bytes,
                    }
                )
            except ValueError:
                report["outcome"] = "invalid_curl_metadata"
        else:
            report["outcome"] = "transport_error"
        if result.returncode != 0:
            error = result.stderr.decode("utf-8", errors="replace").strip()
            report["error"] = error[:240] or "curl request failed"
        return report


def _partial_tls_probe(
    port: int, timeout_seconds: float, deadline: float
) -> dict[str, object]:
    payload = b"\x16\x03\x03\x00\x40\x01\x00\x00\x3c\x03\x03" + b"\x00" * 10
    started = time.monotonic()
    received = b""
    outcome = "connected"
    try:
        connect_timeout = min(timeout_seconds, 3.0, max(0.001, deadline - time.monotonic()))
        with socket.create_connection(("127.0.0.1", port), timeout=connect_timeout) as stream:
            stream.sendall(payload)
            stream.shutdown(socket.SHUT_WR)
            read_timeout = min(timeout_seconds, 3.0, deadline - time.monotonic())
            if read_timeout <= 0:
                return {
                    "outcome": "timeout",
                    "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
                    "response_bytes": 0,
                    "response_sha256": hashlib.sha256(b"").hexdigest(),
                }
            stream.settimeout(read_timeout)
            try:
                received = stream.recv(512)
                outcome = "closed" if not received else "tls_response"
            except TimeoutError:
                outcome = "timeout"
    except OSError as error:
        outcome = "connect_error"
        error_kind = type(error).__name__
    return {
        "outcome": outcome,
        "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
        "response_bytes": len(received),
        "response_sha256": hashlib.sha256(received).hexdigest(),
        **({"error": error_kind} if outcome == "connect_error" else {}),
    }


def _http2_framing_probe(
    *,
    host: str,
    port: int,
    ca_file: Path,
    timeout_seconds: float,
    deadline: float,
    case: str,
    frame_bytes: bytes,
) -> dict[str, object]:
    started = time.monotonic()
    received = bytearray()
    remaining = min(timeout_seconds, 3.0, max(0.001, deadline - started))
    outcome = "connected"
    try:
        context = ssl.create_default_context(cafile=str(ca_file))
        context.set_alpn_protocols(["h2"])
        with socket.create_connection(("127.0.0.1", port), timeout=remaining) as raw:
            raw.settimeout(remaining)
            with context.wrap_socket(raw, server_hostname=host) as stream:
                if stream.selected_alpn_protocol() != "h2":
                    outcome = "wrong_alpn"
                else:
                    stream.sendall(HTTP2_CLIENT_PREFACE + frame_bytes)
                    stream.shutdown(socket.SHUT_WR)
                    while len(received) < 512 and time.monotonic() < deadline:
                        try:
                            chunk = stream.recv(512 - len(received))
                        except TimeoutError:
                            outcome = "timeout"
                            break
                        if not chunk:
                            outcome = "closed"
                            break
                        received.extend(chunk)
                    else:
                        outcome = "response_limit" if len(received) >= 512 else "timeout"
                    if received and outcome == "connected":
                        outcome = "response"
    except (OSError, ssl.SSLError) as error:
        outcome = "connect_or_tls_error"
        error_kind = type(error).__name__
    return {
        "probe": case,
        "outcome": outcome,
        "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
        "response_bytes": len(received),
        "response_sha256": hashlib.sha256(received).hexdigest(),
        **({"error": error_kind} if outcome == "connect_or_tls_error" else {}),
    }


def _connection_churn(
    port: int, count: int, timeout_seconds: float, deadline: float
) -> dict[str, object]:
    samples: list[float] = []
    failures: dict[str, int] = {}
    attempted = 0
    while attempted < count and time.monotonic() < deadline:
        started = time.monotonic()
        attempted += 1
        try:
            timeout = min(timeout_seconds, 3.0, max(0.001, deadline - started))
            with socket.create_connection(("127.0.0.1", port), timeout=timeout):
                samples.append((time.monotonic() - started) * 1000)
        except OSError as error:
            error_name = type(error).__name__
            failures[error_name] = failures.get(error_name, 0) + 1
    ordered = sorted(samples)
    return {
        "requested": count,
        "attempted": attempted,
        "connected": len(samples),
        "failures": failures,
        "connect_ms": {
            "min": round(ordered[0], 3) if ordered else None,
            "median": round(ordered[len(ordered) // 2], 3) if ordered else None,
            "max": round(ordered[-1], 3) if ordered else None,
        },
    }


def summarize_probe_observations(samples: Sequence[dict[str, object]]) -> list[dict[str, object]]:
    grouped: dict[str, list[dict[str, object]]] = {}
    for sample in samples:
        grouped.setdefault(str(sample.get("probe", "unknown")), []).append(sample)

    summaries: list[dict[str, object]] = []
    for probe, rows in sorted(grouped.items()):
        statuses: dict[str, int] = {}
        response_sizes: dict[str, int] = {}
        response_hashes: dict[str, int] = {}
        outcomes: dict[str, int] = {}
        for row in rows:
            for field, destination in (
                ("status", statuses),
                ("response_bytes", response_sizes),
                ("response_sha256", response_hashes),
                ("outcome", outcomes),
            ):
                value = row.get(field)
                if value is not None:
                    key = str(value)
                    destination[key] = destination.get(key, 0) + 1

        timing: dict[str, dict[str, float]] = {}
        for field in ("first_byte_ms", "total_ms", "elapsed_ms"):
            values = sorted(
                float(row[field]) for row in rows if isinstance(row.get(field), (int, float))
            )
            if values:
                timing[field] = {
                    "min": round(values[0], 3),
                    "median": round(values[len(values) // 2], 3),
                    "max": round(values[-1], 3),
                }
        summaries.append(
            {
                "probe": probe,
                "samples": len(rows),
                "outcomes": outcomes,
                "statuses": statuses,
                "response_sizes": response_sizes,
                "response_hashes": response_hashes,
                "timing_ms": timing,
            }
        )
    return summaries


def run_probes(args: argparse.Namespace) -> dict[str, object]:
    started_at = datetime.now(timezone.utc).isoformat()
    deadline = time.monotonic() + args.max_runtime
    host, port, origin = parse_origin(args.endpoint)
    relay_path = validate_relay_path(args.relay_path)
    if not args.ca_file.is_file() or args.ca_file.stat().st_size > MAX_CA_FILE_BYTES:
        raise ProbeError("CA file does not exist, is not regular, or exceeds the size limit")
    valid_token = read_token(args.valid_token_file, "valid token file")
    expired_token = read_token(args.expired_token_file, "expired token file")
    if args.probe_replay and not args.allow_token_consumption:
        raise ProbeError("--probe-replay also requires --allow-token-consumption")
    if args.allow_token_consumption and not args.probe_replay:
        raise ProbeError("--allow-token-consumption is only valid with --probe-replay")
    if args.probe_replay and valid_token is None:
        raise ProbeError("--probe-replay requires --valid-token-file")
    curl = shutil.which(args.curl_bin)
    if curl is None:
        raise ProbeError(f"curl executable not found: {args.curl_bin}")
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise ProbeError("probe runtime limit expired during preflight")
    if not curl_supports_http2(curl, remaining):
        if time.monotonic() >= deadline:
            raise ProbeError("probe runtime limit expired during HTTP/2 preflight")
        raise ProbeError("curl 8.4.0 or newer with HTTP/2 support is required")

    base_headers = ["content-type: application/octet-stream"]
    repeated_cases: list[tuple[str, str, str, list[str]]] = [
        ("root_get", "GET", "/", []),
        ("unsupported_method", "GET", relay_path, base_headers),
        ("unmatched_path", "POST", "/not-the-relay", base_headers),
        ("query_on_relay", "POST", relay_path + "?probe=1", base_headers),
        ("missing_capability", "POST", relay_path, base_headers),
        (
            "malformed_capability",
            "POST",
            relay_path,
            base_headers + ["x-phantom-one-capability: malformed"],
        ),
        (
            "duplicate_capability_headers",
            "POST",
            relay_path,
            base_headers
            + [
                "x-phantom-one-capability: first",
                "x-phantom-one-capability: second",
            ],
        ),
    ]
    if valid_token is not None:
        repeated_cases.append(
            (
                "invalid_signature",
                "POST",
                relay_path,
                base_headers + [f"x-phantom-one-capability: {tamper_signature(valid_token)}"],
            )
        )
    if expired_token is not None:
        repeated_cases.append(
            (
                "expired_capability",
                "POST",
                relay_path,
                base_headers + [f"x-phantom-one-capability: {expired_token}"],
            )
        )

    samples: list[dict[str, object]] = []
    truncated = False
    for name, method, path, headers in repeated_cases:
        for repeat_index in range(args.repeat):
            remaining = deadline - time.monotonic()
            if remaining < 0.25:
                truncated = True
                break
            sample = _curl_probe(
                curl=curl,
                host=host,
                port=port,
                origin=origin,
                path=path,
                method=method,
                headers=headers,
                ca_file=args.ca_file,
                timeout_seconds=min(float(args.timeout_seconds), remaining),
            )
            samples.append({"probe": name, "repeat": repeat_index + 1, **sample})
        if truncated:
            break

    replay_results = None
    replay_samples: list[dict[str, object]] = []
    if args.probe_replay and not truncated:
        assert valid_token is not None
        remaining = deadline - time.monotonic()
        if remaining >= 0.25:
            authorized_headers = base_headers + [f"x-phantom-one-capability: {valid_token}"]
            first = _curl_probe(
                curl=curl,
                host=host,
                port=port,
                origin=origin,
                path=relay_path,
                method="POST",
                headers=authorized_headers,
                ca_file=args.ca_file,
                timeout_seconds=min(float(args.timeout_seconds), remaining),
                capture_response=False,
            )
            remaining = deadline - time.monotonic()
            second = None
            if remaining >= 0.25:
                second = _curl_probe(
                    curl=curl,
                    host=host,
                    port=port,
                    origin=origin,
                    path=relay_path,
                    method="POST",
                    headers=authorized_headers,
                    ca_file=args.ca_file,
                    timeout_seconds=min(float(args.timeout_seconds), remaining),
                )
                replay_samples.append({"probe": "replayed_capability", **second})
            replay_results = {"first_use": first, "replay": second}
        else:
            truncated = True

    remaining = deadline - time.monotonic()
    partial_tls = None
    partial_http2 = None
    malformed_http2 = None
    if remaining >= 0.25:
        partial_tls = _partial_tls_probe(
            port, min(args.timeout_seconds, remaining), deadline
        )
        remaining = deadline - time.monotonic()
        if remaining >= 0.25:
            partial_http2 = _http2_framing_probe(
                host=host,
                port=port,
                ca_file=args.ca_file,
                timeout_seconds=min(args.timeout_seconds, remaining),
                deadline=deadline,
                case="partial_http2_frame",
                frame_bytes=bytes.fromhex("000010010400000001") + b"\xff",
            )
        else:
            truncated = True
        remaining = deadline - time.monotonic()
        if remaining >= 0.25:
            malformed_http2 = _http2_framing_probe(
                host=host,
                port=port,
                ca_file=args.ca_file,
                timeout_seconds=min(args.timeout_seconds, remaining),
                deadline=deadline,
                case="malformed_http2_settings_stream",
                frame_bytes=bytes.fromhex("000000040000000001"),
            )
        else:
            truncated = True
    else:
        truncated = True
    remaining = deadline - time.monotonic()
    churn = (
        _connection_churn(
            port, args.churn, min(args.timeout_seconds, remaining), deadline
        )
        if remaining >= 0.25
        else None
    )
    if churn is None:
        truncated = True

    return {
        "schema_version": 1,
        "started_at_utc": started_at,
        "target": {
            "endpoint": f"https://{host}:{port}",
            "relay_path": relay_path,
            "resolved_address": "127.0.0.1",
            "transport": "TLS + HTTP/2",
        },
        "limits": {
            "repeat": args.repeat,
            "connection_churn": args.churn,
            "timeout_seconds": args.timeout_seconds,
            "max_runtime_seconds": args.max_runtime,
            "max_response_bytes": MAX_RESPONSE_BYTES,
        },
        "probes": samples,
        "observable_distributions": summarize_probe_observations(
            [*samples, *replay_samples]
        ),
        "partial_tls_handshake": partial_tls,
        "partial_http2_frame": partial_http2,
        "malformed_http2_settings": malformed_http2,
        "connection_churn": churn,
        "authorized_replay_probe": replay_results,
        "skipped_probes": [
            *(["invalid_signature: no valid token file supplied"] if valid_token is None else []),
            *(["expired_capability: no expired token file supplied"] if expired_token is None else []),
            *(["authorized_replay: not explicitly enabled"] if not args.probe_replay else []),
        ],
        "status": "truncated" if truncated else "completed",
        "disclaimer": (
            "Loopback-only observations are finite measurements, not proof of indistinguishability. "
            "The replay probe intentionally submits one authorized request and may reach the configured backend. "
            "Backend-access counters and replay-cache capacity require separate operator observation."
        ),
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--endpoint", required=True, help="HTTPS origin; connection is pinned to loopback")
    parser.add_argument("--ca-file", required=True, type=Path, help="CA certificate trusted for the endpoint")
    parser.add_argument("--relay-path", default=DEFAULT_RELAY_PATH)
    parser.add_argument("--valid-token-file", type=Path, help="optional token used only for invalid-signature probes")
    parser.add_argument("--expired-token-file", type=Path, help="optional expired signed capability")
    parser.add_argument("--probe-replay", action="store_true", help="use one valid token twice")
    parser.add_argument(
        "--allow-token-consumption",
        action="store_true",
        help="acknowledge the first replay-probe request may connect to the configured backend",
    )
    parser.add_argument("--confirm-owned-endpoint", action="store_true", help="confirm this is your local edge or SSH tunnel")
    parser.add_argument("--repeat", type=int, default=3)
    parser.add_argument("--churn", type=int, default=8, help="number of loopback TCP connect/close attempts")
    parser.add_argument("--timeout-seconds", type=int, default=3)
    parser.add_argument("--max-runtime", type=int, default=30)
    parser.add_argument("--curl-bin", default="curl")
    parser.add_argument("--json-out", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.confirm_owned_endpoint:
        parser.error("--confirm-owned-endpoint is required")
    if not 1 <= args.repeat <= MAX_REPEATS:
        parser.error(f"--repeat must be between 1 and {MAX_REPEATS}")
    if not 0 <= args.churn <= MAX_CHURN:
        parser.error(f"--churn must be between 0 and {MAX_CHURN}")
    if not 1 <= args.timeout_seconds <= MAX_TIMEOUT_SECONDS:
        parser.error(f"--timeout-seconds must be between 1 and {MAX_TIMEOUT_SECONDS}")
    if not 1 <= args.max_runtime <= MAX_RUNTIME_SECONDS:
        parser.error(f"--max-runtime must be between 1 and {MAX_RUNTIME_SECONDS}")
    try:
        report = run_probes(args)
    except ProbeError as error:
        parser.error(str(error))
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.json_out is not None:
        args.json_out.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
