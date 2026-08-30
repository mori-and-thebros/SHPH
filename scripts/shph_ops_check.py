#!/usr/bin/env python3
"""Bounded, read-only SHPH service readiness collector.

The collector intentionally emits a small sanitized report. It never prints
raw SHPH output, configuration contents, environment values, endpoints, keys,
tickets, or service command lines.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
from typing import Any


MAX_CONFIG_BYTES = 256 * 1024
MAX_COMMAND_OUTPUT_BYTES = 64 * 1024
MAX_PATH_BYTES = 4096
SAFE_STATES = {"pass", "fail", "info", "skip", "blocked", "warn"}
SECRET_ASSIGNMENT = re.compile(
    rb"(?im)^\s*([a-z0-9_.-]*(?:password|private[_-]?key|secret|token|ticket|uuid)"
    rb"[a-z0-9_.-]*)\s*=\s*"
)
SAFE_REFERENCE_SUFFIX = re.compile(rb"(?:_env|_path|_file|_ref)$", re.I)


def result(status: str, detail: str = "") -> dict[str, str]:
    return {"status": status, "detail": detail}


def path_display(path: Path) -> str:
    # Reports may be stored as public evidence, so do not include user-specific
    # absolute paths. The actual path is still used for checks internally.
    return "<configured-path>/" + path.name


def validate_regular_file(path_text: str, label: str) -> tuple[dict[str, str], Path | None]:
    if not path_text or len(path_text.encode(errors="ignore")) > MAX_PATH_BYTES:
        return result("fail", f"{label} path is empty or too long"), None

    path = Path(path_text).expanduser()
    if label == "binary" and len(path.parts) == 1:
        located = shutil.which(path_text)
        if located:
            path = Path(located)
    try:
        if path.is_symlink():
            return result("fail", f"{label} must not be a symlink"), None
        info = path.stat()
    except OSError:
        return result("fail", f"{label} is unavailable"), None

    if not stat.S_ISREG(info.st_mode):
        return result("fail", f"{label} is not a regular file"), None

    if os.name != "nt" and (info.st_mode & 0o022):
        return result("fail", f"{label} is group/world writable"), None

    blocked_roots = {
        Path(tempfile.gettempdir()).resolve(),
        Path("/tmp"),
        Path("/var/tmp"),
        Path("/dev/shm"),
    }
    try:
        resolved = path.resolve()
        if any(resolved == root or root in resolved.parents for root in blocked_roots):
            return result("fail", f"{label} is under a temporary directory"), None
    except OSError:
        return result("fail", f"{label} cannot be resolved"), None

    mode_detail = "permission-checked" if os.name != "nt" else "regular-file-checked"
    return result("pass", mode_detail), path


def scan_config(path: Path) -> dict[str, str]:
    try:
        data = path.read_bytes()
    except OSError:
        return result("fail", "configuration could not be read")
    if len(data) > MAX_CONFIG_BYTES:
        return result("fail", "configuration exceeds bounded inspection size")

    for match in SECRET_ASSIGNMENT.finditer(data):
        key = match.group(1)
        if not SAFE_REFERENCE_SUFFIX.search(key):
            return result("fail", "configuration contains a literal secret-bearing assignment")
    return result("pass", "bounded secret-marker scan passed")


class BoundedCommand:
    def __init__(self, argv: list[str], timeout_seconds: float) -> None:
        self.argv = argv
        self.timeout_seconds = timeout_seconds

    def run(self) -> tuple[int | None, bytes, bytes, str | None]:
        with tempfile.TemporaryDirectory(prefix="shph-ops-", dir=None) as temp_dir:
            stdout_path = Path(temp_dir) / "stdout"
            stderr_path = Path(temp_dir) / "stderr"
            start = time.monotonic()
            with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
                try:
                    process = subprocess.Popen(
                        self.argv,
                        stdin=subprocess.DEVNULL,
                        stdout=stdout,
                        stderr=stderr,
                        shell=False,
                        start_new_session=(os.name != "nt"),
                    )
                except OSError as exc:
                    return None, b"", b"", f"command unavailable: {exc.__class__.__name__}"

                timed_out = False
                oversized = False
                while process.poll() is None:
                    if time.monotonic() - start > self.timeout_seconds:
                        timed_out = True
                        break
                    try:
                        if (
                            stdout_path.stat().st_size > MAX_COMMAND_OUTPUT_BYTES
                            or stderr_path.stat().st_size > MAX_COMMAND_OUTPUT_BYTES
                        ):
                            oversized = True
                            break
                    except OSError:
                        break
                    time.sleep(0.05)

                if timed_out or oversized:
                    if os.name == "nt":
                        process.kill()
                    else:
                        try:
                            os.killpg(process.pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                    process.wait(timeout=5)
                    reason = "timeout" if timed_out else "output limit exceeded"
                else:
                    process.wait(timeout=5)
                    reason = None

            stdout_data = stdout_path.read_bytes()[:MAX_COMMAND_OUTPUT_BYTES]
            stderr_data = stderr_path.read_bytes()[:MAX_COMMAND_OUTPUT_BYTES]
            return process.returncode, stdout_data, stderr_data, reason


def run_json_command(binary: Path, config: Path, command: str, strict: bool, timeout: float) -> tuple[dict[str, Any] | None, dict[str, str]]:
    argv = [str(binary), "--config", str(config), "--json", command]
    if command == "doctor" and strict:
        argv.append("--strict")
    exit_code, stdout, _stderr, limit_reason = BoundedCommand(argv, timeout).run()
    if limit_reason:
        return None, result("fail", f"{command} command {limit_reason}")
    if exit_code is None:
        return None, result("fail", f"{command} command could not start")
    try:
        parsed = json.loads(stdout.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, result("fail", f"{command} command did not return bounded JSON")
    if not isinstance(parsed, dict):
        return None, result("fail", f"{command} report was not an object")
    semantic_ok = True
    if command == "doctor":
        semantic_ok = parsed.get("ok") is True
    elif command == "status":
        for section in ("config", "identity"):
            value = parsed.get(section)
            if not isinstance(value, dict) or value.get("state") != "ready":
                semantic_ok = False
                break
    status = "pass" if exit_code == 0 and semantic_ok else "fail"
    detail = f"{command} exit {exit_code}" if semantic_ok else f"{command} reported an unhealthy state"
    return parsed, result(status, detail)


def safe_doctor_report(report: dict[str, Any] | None) -> dict[str, Any]:
    if report is None:
        return {"ok": False, "checks": []}
    checks: list[dict[str, str]] = []
    for item in report.get("checks", []):
        if not isinstance(item, dict):
            continue
        name = str(item.get("name", "unknown"))[:64]
        status = str(item.get("status", "unknown")).lower()
        checks.append({"name": name, "status": status if status in SAFE_STATES else "unknown"})
    return {"ok": bool(report.get("ok", False)), "checks": checks}


def safe_status_report(report: dict[str, Any] | None) -> dict[str, Any]:
    if report is None:
        return {"config_state": "unknown", "identity_state": "unknown", "tunnel_state": "unknown", "peer_count": 0}
    def state(section: str) -> str:
        value = report.get(section)
        if isinstance(value, dict):
            candidate = str(value.get("state", "unknown")).lower()
            return candidate[:32]
        return "unknown"
    peers = report.get("peers", 0)
    return {
        "config_state": state("config"),
        "identity_state": state("identity"),
        "tunnel_state": state("tunnel"),
        "control_plane_state": state("control_plane"),
        "peer_count": peers if isinstance(peers, int) and 0 <= peers <= 65535 else "invalid",
        "session_present": isinstance(report.get("session"), str),
    }


def check_service(unit: str, unit_file: str | None) -> tuple[dict[str, Any], dict[str, str]]:
    if os.name == "nt":
        sc = shutil.which("sc.exe")
        if not sc:
            return {"status": "skip"}, result("skip", "sc.exe unavailable")
        code, _out, _err, reason = BoundedCommand([sc, "query", unit], 5).run()
        if reason:
            return {"status": "fail"}, result("fail", f"service query {reason}")
        if code != 0:
            return {"status": "fail"}, result("fail", "service query failed")
        return {"status": "pass", "active": True}, result("pass", "service reported")

    systemctl = shutil.which("systemctl")
    if not systemctl:
        return {"status": "skip"}, result("skip", "systemctl unavailable")
    active_code, _out, _err, reason = BoundedCommand([systemctl, "is-active", "--quiet", unit], 5).run()
    if reason:
        return {"status": "fail"}, result("fail", f"active-state query {reason}")
    enabled_code, _out, _err, reason = BoundedCommand([systemctl, "is-enabled", "--quiet", unit], 5).run()
    if reason:
        return {"status": "fail"}, result("fail", f"enabled-state query {reason}")

    verify = "not-requested"
    if unit_file:
        analyzer = shutil.which("systemd-analyze")
        if not analyzer:
            verify = "unavailable"
        else:
            verify_code, _out, _err, reason = BoundedCommand([analyzer, "verify", unit_file], 10).run()
            verify = "timeout-or-limit" if reason else ("pass" if verify_code == 0 else "fail")

    active = active_code == 0
    enabled = enabled_code == 0
    status = "pass" if active and enabled and verify in {"not-requested", "pass"} else "fail"
    return {
        "status": status,
        "active": active,
        "enabled": enabled,
        "unit_syntax": verify,
    }, result(status, "read-only systemd lifecycle check")


def parse_listen(value: str) -> tuple[str, int] | None:
    if not value or ":" not in value:
        return None
    host, port_text = value.rsplit(":", 1)
    try:
        port = int(port_text)
    except ValueError:
        return None
    if not 1 <= port <= 65535:
        return None
    return host.strip("[]"), port


def probe_listener(value: str, allow_remote: bool, timeout: float) -> dict[str, str]:
    parsed = parse_listen(value)
    if parsed is None:
        return result("fail", "listen value must be host:port")
    host, port = parsed
    probe_host = host
    try:
        address = ipaddress.ip_address(host)
        is_local = address.is_loopback or address.is_unspecified
        if address.is_unspecified:
            probe_host = "::1" if address.version == 6 else "127.0.0.1"
    except ValueError:
        is_local = host.lower() in {"localhost", "ip6-localhost"}
    if not is_local and not allow_remote:
        return result("blocked", "remote probe requires explicit opt-in")
    family = socket.AF_INET6 if ":" in probe_host else socket.AF_INET
    try:
        with socket.socket(family, socket.SOCK_STREAM) as sock:
            sock.settimeout(min(timeout, 5.0))
            sock.connect((probe_host, port))
        return result("pass", "TCP connect-and-close succeeded")
    except OSError:
        return result("fail", "TCP listener probe failed")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", default="shph", help="SHPH executable")
    parser.add_argument("--config", required=True, help="configuration file to inspect")
    parser.add_argument("--unit", help="systemd unit or Windows service name")
    parser.add_argument("--unit-file", help="systemd unit file to syntax-check")
    parser.add_argument("--listen", help="optional host:port readiness probe")
    parser.add_argument("--allow-remote-probe", action="store_true", help="permit a non-local TCP probe")
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--strict", action="store_true", help="treat blocked/skipped checks as failure")
    parser.add_argument("--output", help="sanitized JSON output path")
    return parser


def main() -> int:
    args = build_parser().parse_args()
    if not 0.1 <= args.timeout <= 120:
        print("timeout must be between 0.1 and 120 seconds", file=sys.stderr)
        return 2

    report: dict[str, Any] = {
        "schema": "shph-ops-check/v1",
        "platform": sys.platform,
        "checks": {},
        "doctor": {"ok": False, "checks": []},
        "status": {},
        "service": None,
        "listener": None,
    }
    failures = False
    incomplete = False

    config_check, config_path = validate_regular_file(args.config, "configuration")
    report["checks"]["config_path"] = config_check
    if config_check["status"] != "pass" or config_path is None:
        failures = True
    else:
        secret_check = scan_config(config_path)
        report["checks"]["config_secret_scan"] = secret_check
        failures |= secret_check["status"] == "fail"

    binary_check, binary_path = validate_regular_file(args.binary, "binary")
    report["checks"]["binary_path"] = binary_check
    if binary_check["status"] != "pass" or binary_path is None:
        failures = True

    if config_path is not None and binary_path is not None:
        doctor, doctor_check = run_json_command(binary_path, config_path, "doctor", args.strict, args.timeout)
        status, status_check = run_json_command(binary_path, config_path, "status", False, args.timeout)
        report["checks"]["doctor_command"] = doctor_check
        report["checks"]["status_command"] = status_check
        report["doctor"] = safe_doctor_report(doctor)
        report["status"] = safe_status_report(status)
        failures |= doctor_check["status"] == "fail" or status_check["status"] == "fail"

    report["checks"]["keystore_password_present"] = result(
        "pass" if os.environ.get("SHPH_KEYSTORE_PASSWORD") else "info",
        "presence only; value never collected",
    )

    if args.unit:
        service_report, service_check = check_service(args.unit, args.unit_file)
        report["service"] = service_report
        report["checks"]["service_lifecycle"] = service_check
        failures |= service_check["status"] == "fail"
        incomplete |= service_check["status"] in {"skip", "blocked"}

    if args.listen:
        listener_check = probe_listener(args.listen, args.allow_remote_probe, args.timeout)
        report["listener"] = {"status": listener_check["status"]}
        report["checks"]["listener"] = listener_check
        failures |= listener_check["status"] == "fail"
        incomplete |= listener_check["status"] in {"skip", "blocked"}

    report["result"] = "FAIL" if failures else ("BLOCKED" if incomplete else "PASS")
    encoded = json.dumps(report, sort_keys=True, indent=2) + "\n"
    if args.output:
        output_path = Path(args.output).expanduser()
        if output_path.exists() and output_path.is_symlink():
            print("output path must not be a symlink", file=sys.stderr)
            return 2
        output_path.parent.mkdir(parents=True, exist_ok=True)
        temp_path = output_path.with_name(output_path.name + ".tmp")
        temp_path.write_text(encoded, encoding="utf-8", newline="\n")
        if os.name != "nt":
            os.chmod(temp_path, 0o600)
        os.replace(temp_path, output_path)
    print(encoded, end="")
    if failures or (args.strict and incomplete):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
