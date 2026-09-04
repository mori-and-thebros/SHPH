#!/usr/bin/env python3
"""Run bounded, reproducible SHPH operator campaigns.

The campaigns in this file are deliberately conservative:

* local TCP/IPv6, reconnect, and soak runs use fresh temporary identities;
* DNS defaults to the non-mutating control-plane dry-run path;
* crash mode requires an explicit confirmation before sending SIGKILL;
* PMTU mode runs the platform ping implementation and records raw outcomes;
* unavailable host capabilities are reported as SKIP, never as PASS.

Exit codes:
  0  PASS
  1  FAIL
  2  usage or invalid input
  3  SKIP (host capability or prerequisite unavailable)
"""

from __future__ import annotations

import argparse
import datetime as dt
import ipaddress
import json
import os
import platform
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Sequence


EXIT_PASS = 0
EXIT_FAIL = 1
EXIT_USAGE = 2
EXIT_SKIP = 3

SKIP = "SKIP"
PASS = "PASS"
FAIL = "FAIL"
DEFAULT_DNS_SERVERS = ("1.1.1.1", "2606:4700:4700::1111")


class CampaignSkip(RuntimeError):
    """Raised when the host cannot perform a campaign safely."""


class CampaignFailure(RuntimeError):
    """Raised when a campaign ran and found a failure."""


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).replace(microsecond=0).isoformat()


def repository_root() -> Path:
    return Path(__file__).resolve().parent.parent


def default_output(root: Path, name: str) -> Path:
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return root / "benchmark-runs" / "campaigns" / f"{name}-{stamp}"


def run_git(root: Path, *args: str) -> str:
    try:
        result = subprocess.run(
            ["git", "-C", str(root), *args],
            check=True,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except (OSError, subprocess.CalledProcessError):
        return "unknown"
    return result.stdout.strip()


def command_text(args: Sequence[object]) -> str:
    return " ".join(str(value) for value in args)


def run_checked(
    args: Sequence[object],
    *,
    cwd: Path | None = None,
    env: dict[str, str] | None = None,
    timeout: float | None = None,
) -> subprocess.CompletedProcess[str]:
    try:
        result = subprocess.run(
            [str(value) for value in args],
            cwd=str(cwd) if cwd else None,
            env=env,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
    except FileNotFoundError as error:
        raise CampaignSkip(f"required command is unavailable: {error.filename}") from error
    except subprocess.TimeoutExpired as error:
        raise CampaignFailure(f"command timed out: {command_text(args)}") from error
    return result


def require_command(name: str) -> None:
    probe = ["where.exe", name] if os.name == "nt" else ["bash", "-lc", f"command -v {name}"]
    if subprocess.run(probe, capture_output=True, text=True).returncode != 0:
        raise CampaignSkip(f"required command is unavailable: {name}")


def resolve_binary(root: Path, value: str | None) -> Path:
    candidates: list[Path] = []
    if value:
        candidates.append(Path(value))
    else:
        suffix = ".exe" if os.name == "nt" else ""
        candidates.extend(
            [
                root / "target" / "release" / f"shph{suffix}",
                root / "target" / "debug" / f"shph{suffix}",
            ]
        )
    for candidate in candidates:
        path = candidate if candidate.is_absolute() else root / candidate
        if path.is_file():
            return path.resolve()
    expected = ", ".join(str(path) for path in candidates)
    raise CampaignSkip(f"SHPH binary was not found; expected one of: {expected}")


def choose_port(host: str) -> int:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    with socket.socket(family, socket.SOCK_STREAM) as sock:
        if family == socket.AF_INET6:
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            sock.bind((host, 0, 0, 0))
        else:
            sock.bind((host, 0))
        return int(sock.getsockname()[1])


def endpoint(host: str, port: int) -> str:
    return f"[{host}]:{port}" if ":" in host and not host.startswith("[") else f"{host}:{port}"


def wait_for_tcp(host: str, port: int, timeout: float) -> None:
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    deadline = time.monotonic() + timeout
    last_error: OSError | None = None
    while time.monotonic() < deadline:
        try:
            with socket.socket(family, socket.SOCK_STREAM) as sock:
                sock.settimeout(min(0.25, max(0.05, deadline - time.monotonic())))
                if family == socket.AF_INET6:
                    sock.connect((host, port, 0, 0))
                else:
                    sock.connect((host, port))
            return
        except OSError as error:
            last_error = error
            time.sleep(0.05)
    detail = f": {last_error}" if last_error else ""
    raise CampaignFailure(f"timed out waiting for TCP listener {endpoint(host, port)}{detail}")


class ManagedProcess:
    """A line-buffered child process with bounded output capture."""

    def __init__(
        self,
        args: Sequence[object],
        *,
        cwd: Path,
        env: dict[str, str] | None = None,
    ) -> None:
        creationflags = 0
        if os.name == "nt":
            creationflags = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)
        try:
            self.process = subprocess.Popen(
                [str(value) for value in args],
                cwd=str(cwd),
                env=env,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                creationflags=creationflags,
            )
        except FileNotFoundError as error:
            raise CampaignSkip(f"required command is unavailable: {error.filename}") from error
        self.args = [str(value) for value in args]
        self.lines: list[str] = []
        self._lock = threading.Lock()
        self._reader = threading.Thread(target=self._read_output, daemon=True)
        self._reader.start()

    def _read_output(self) -> None:
        assert self.process.stdout is not None
        for line in self.process.stdout:
            with self._lock:
                self.lines.append(line.rstrip("\r\n"))

    def text(self) -> str:
        with self._lock:
            return "\n".join(self.lines)

    def count(self, marker: str) -> int:
        with self._lock:
            return sum(marker in line for line in self.lines)

    def wait_for(self, marker: str, timeout: float, *, occurrence: int = 1) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.count(marker) >= occurrence:
                return
            if self.process.poll() is not None:
                raise CampaignFailure(
                    f"process exited before marker {marker!r} (code {self.process.returncode})"
                )
            time.sleep(0.05)
        raise CampaignFailure(f"timed out waiting for marker {marker!r}")

    def send_line(self, value: str) -> None:
        if self.process.stdin is None:
            raise CampaignFailure("child stdin is unavailable")
        try:
            self.process.stdin.write(value + "\n")
            self.process.stdin.flush()
        except (BrokenPipeError, OSError) as error:
            raise CampaignFailure(f"child stdin closed while sending probe: {error}") from error

    def close_stdin(self) -> None:
        if self.process.stdin is not None:
            try:
                self.process.stdin.close()
            except OSError:
                pass
            self.process.stdin = None

    def terminate(self, timeout: float = 5.0) -> int | None:
        if self.process.poll() is None:
            self.close_stdin()
            self.process.terminate()
        try:
            return_code = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.process.kill()
            return_code = self.process.wait(timeout=timeout)
        self._reader.join(timeout=1)
        return return_code

    def wait(self, timeout: float = 5.0) -> int | None:
        """Wait for natural child exit without turning a slow exit into a kill."""
        try:
            return_code = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            return None
        self._reader.join(timeout=1)
        return return_code

    def hard_kill(self, timeout: float = 5.0) -> int | None:
        if self.process.poll() is None:
            if os.name == "nt":
                self.process.kill()
            else:
                os.kill(self.process.pid, signal.SIGKILL)
            self.close_stdin()
        try:
            return_code = self.process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            raise CampaignFailure(f"process did not exit after hard kill: {self.process.pid}") from error
        self._reader.join(timeout=1)
        return return_code


def append_session_config(
    path: Path,
    *,
    role: str,
    peer_endpoint: str,
    reconnect: bool,
    timeout_secs: int = 3,
    max_attempts: int = 8,
    initial_delay_ms: int = 100,
    max_delay_ms: int = 250,
) -> None:
    if role == "listen":
        session = f'role = "listen"\nbind = "{peer_endpoint}"'
    elif role == "connect":
        session = f'role = "connect"\npeer = "{peer_endpoint}"'
    else:
        raise ValueError(f"unsupported session role: {role}")
    text = f"\n[session]\n{session}\ntimeout_secs = {timeout_secs}\n"
    if reconnect:
        text += (
            "\n[session.reconnect]\n"
            "enabled = true\n"
            f"max_attempts = {max_attempts}\n"
            f"initial_delay_ms = {initial_delay_ms}\n"
            f"max_delay_ms = {max_delay_ms}\n"
        )
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(text)


def init_pair(binary: Path, root: Path, host: str, port: int, temp_root: Path) -> tuple[Path, Path]:
    server_dir = temp_root / "server"
    client_dir = temp_root / "client"
    server_dir.mkdir()
    client_dir.mkdir()
    server_config = server_dir / "config.toml"
    client_config = client_dir / "config.toml"
    for config in (server_config, client_config):
        result = run_checked([binary, "--config", config, "init", "--new"], cwd=root)
        if result.returncode != 0:
            raise CampaignFailure(
                f"identity initialization failed ({result.returncode}): "
                f"{result.stderr.strip() or result.stdout.strip()}"
            )

    def key(config: Path, command: str) -> str:
        result = run_checked([binary, "--config", config, command], cwd=root)
        if result.returncode != 0:
            raise CampaignFailure(f"{command} failed: {result.stderr.strip()}")
        value = result.stdout.strip()
        if not value:
            raise CampaignFailure(f"{command} returned an empty key")
        return value

    server_public = key(server_config, "show-public-key")
    server_signing = key(server_config, "show-signing-public-key")
    client_public = key(client_config, "show-public-key")
    client_signing = key(client_config, "show-signing-public-key")
    host_argument = host.strip("[]")
    for config, alias, public, signing in (
        (server_config, "client", client_public, client_signing),
        (client_config, "server", server_public, server_signing),
    ):
        result = run_checked(
            [
                binary,
                "--config",
                config,
                "add-peer",
                alias,
                host_argument,
                str(port),
                public,
                "--sign-pubkey",
                signing,
            ],
            cwd=root,
        )
        if result.returncode != 0:
            raise CampaignFailure(
                f"peer pinning failed ({result.returncode}): "
                f"{result.stderr.strip() or result.stdout.strip()}"
            )
    return server_config, client_config


def write_process_logs(output: Path, name: str, process: ManagedProcess) -> None:
    (output / f"{name}.log").write_text(process.text() + "\n", encoding="utf-8")


def run_reconnect(args: argparse.Namespace, root: Path, output: Path) -> dict[str, object]:
    binary = resolve_binary(root, args.binary)
    host = args.host
    port = args.port or choose_port(host)
    bind = endpoint(host, port)
    with tempfile.TemporaryDirectory(prefix="shph-reconnect-") as temporary:
        server_config, client_config = init_pair(binary, root, host, port, Path(temporary))
        append_session_config(
            server_config,
            role="listen",
            peer_endpoint=bind,
            reconnect=True,
            timeout_secs=args.timeout_secs,
            max_attempts=args.max_attempts,
            initial_delay_ms=args.initial_delay_ms,
            max_delay_ms=args.max_delay_ms,
        )
        append_session_config(
            client_config,
            role="connect",
            peer_endpoint=bind,
            reconnect=True,
            timeout_secs=args.timeout_secs,
            max_attempts=args.max_attempts,
            initial_delay_ms=args.initial_delay_ms,
            max_delay_ms=args.max_delay_ms,
        )
        server: ManagedProcess | None = None
        client: ManagedProcess | None = None
        try:
            server = ManagedProcess(
                [binary, "--config", server_config, "up", "--no-tun"],
                cwd=root,
            )
            server.wait_for("Session mode: listen", args.startup_timeout_secs)
            wait_for_tcp(host, port, args.startup_timeout_secs)
            client = ManagedProcess(
                [binary, "--config", client_config, "up", "--no-tun"],
                cwd=root,
            )
            client.wait_for("handshake connect-loop ok", args.handshake_timeout_secs)
            server.wait_for("handshake listen-loop ok", args.handshake_timeout_secs)

            interrupted_server = server
            interrupted_server.hard_kill()
            write_process_logs(output, "reconnect-server-before-interruption", interrupted_server)
            time.sleep(args.interruption_delay_secs)
            client.send_line("reconnect-trigger")
            client.wait_for("Reconnect: attempt", args.reconnect_timeout_secs)

            server = ManagedProcess(
                [binary, "--config", server_config, "up", "--no-tun"],
                cwd=root,
            )
            server.wait_for("Session mode: listen", args.startup_timeout_secs)
            # The reconnecting client may consume the listener as soon as the
            # server prints its ready marker. A second raw TCP probe races with
            # that legitimate session and can report a false timeout, so the
            # subsequent handshake markers are the restart readiness check.
            client.wait_for(
                "handshake connect-loop ok",
                args.handshake_timeout_secs,
                occurrence=2,
            )
            server.wait_for(
                "handshake listen-loop ok",
                args.handshake_timeout_secs,
                occurrence=1,
            )
            client.send_line("reconnect-after-restart")
            server.wait_for("RX: reconnect-after-restart", args.handshake_timeout_secs)
            return {
                "status": PASS,
                "detail": "peer interruption, bounded retry, restart, re-handshake, and payload delivery passed",
                "endpoint": bind,
                "max_attempts": args.max_attempts,
            }
        finally:
            if client is not None:
                write_process_logs(output, "reconnect-client", client)
                client.terminate()
            if server is not None:
                write_process_logs(output, "reconnect-server", server)
                server.terminate()


def run_soak(args: argparse.Namespace, root: Path, output: Path, *, ipv6: bool = False) -> dict[str, object]:
    binary = resolve_binary(root, args.binary)
    host = "::1" if ipv6 else args.host
    if ":" in host and not socket.has_ipv6:
        raise CampaignSkip("the host Python runtime has no IPv6 support")
    family = socket.AF_INET6 if ":" in host else socket.AF_INET
    if family == socket.AF_INET6:
        try:
            with socket.socket(family, socket.SOCK_STREAM) as probe:
                probe.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                probe.bind((host, 0, 0, 0))
        except OSError as error:
            raise CampaignSkip(f"IPv6 loopback is unavailable: {error}") from error

    completed = 0
    failures: list[str] = []
    durations: list[float] = []
    with tempfile.TemporaryDirectory(prefix="shph-soak-") as temporary:
        temp_root = Path(temporary)
        for index in range(1, args.sessions + 1):
            session_port = args.port or choose_port(host)
            session_root = temp_root / f"session-{index:04d}"
            session_root.mkdir()
            server_config, client_config = init_pair(
                binary,
                root,
                host,
                session_port,
                session_root,
            )
            address = endpoint(host, session_port)
            started = time.monotonic()
            receiver = ManagedProcess(
                [
                    binary,
                    "--config",
                    server_config,
                    "recv-once",
                    "--bind",
                    address,
                    "--timeout-secs",
                    str(args.timeout_secs),
                ],
                cwd=root,
            )
            try:
                wait_for_tcp(host, session_port, args.startup_timeout_secs)
                payload = f"{args.message_prefix}-{index}"
                sender = run_checked(
                    [
                        binary,
                        "--config",
                        client_config,
                        "send-once",
                        "--peer",
                        address,
                        "--text",
                        payload,
                        "--timeout-secs",
                        str(args.timeout_secs),
                    ],
                    cwd=root,
                    timeout=args.timeout_secs + 5,
                )
                receiver_code = receiver.wait(timeout=args.timeout_secs + 2)
                if receiver_code is None:
                    receiver_code = receiver.terminate(timeout=args.timeout_secs + 2)
                receiver_text = receiver.text()
                elapsed = time.monotonic() - started
                durations.append(elapsed)
                if (
                    sender.returncode == 0
                    and receiver_code == 0
                    and f"Payload: {payload}" in receiver_text
                ):
                    completed += 1
                else:
                    failures.append(
                        f"session {index}: sender={sender.returncode}, receiver={receiver_code}"
                    )
            finally:
                write_process_logs(output, f"soak-receiver-{index:04d}", receiver)
                if receiver.process.poll() is None:
                    receiver.terminate()
            if args.interval_ms:
                time.sleep(args.interval_ms / 1000)

    if failures:
        raise CampaignFailure("; ".join(failures))
    return {
        "status": PASS,
        "detail": f"{completed} authenticated one-shot sessions passed",
        "sessions": args.sessions,
        "host": host,
        "ipv6": ipv6,
        "min_seconds": min(durations) if durations else None,
        "p50_seconds": sorted(durations)[len(durations) // 2] if durations else None,
        "max_seconds": max(durations) if durations else None,
    }


def run_dns(args: argparse.Namespace, root: Path, output: Path) -> dict[str, object]:
    binary = resolve_binary(root, args.binary)

    if args.live:
        if args.servers is not None:
            raise CampaignFailure(
                "--servers is only supported for DNS dry-run mode; configure "
                "control_plane.dns_servers in the supplied configuration for --live"
            )
        if not args.config:
            raise CampaignFailure("--config is required with --live")
        config = Path(args.config).resolve()
        if not config.is_file():
            raise CampaignFailure(f"configuration file does not exist: {config}")
        if os.name != "nt" and os.geteuid() != 0:
            raise CampaignSkip("live DNS apply requires root on Unix")
        apply_command = [binary, "--config", config, "apply"]
        cleanup_command = [binary, "--config", config, "undo"]
        apply_error: Exception | None = None
        cleanup_error: Exception | None = None
        try:
            try:
                result = run_checked(apply_command, cwd=root, timeout=args.timeout_secs + 5)
                (output / "dns-apply.log").write_text(
                    result.stdout + result.stderr,
                    encoding="utf-8",
                )
                if result.returncode != 0:
                    apply_error = CampaignFailure(
                        f"live DNS apply failed with code {result.returncode}"
                    )
            except (CampaignSkip, CampaignFailure, OSError) as error:
                apply_error = error
        finally:
            try:
                cleanup = run_checked(cleanup_command, cwd=root, timeout=args.timeout_secs + 5)
                (output / "dns-undo.log").write_text(
                    cleanup.stdout + cleanup.stderr,
                    encoding="utf-8",
                )
                if cleanup.returncode != 0:
                    cleanup_error = CampaignFailure(
                        f"live DNS cleanup failed with code {cleanup.returncode}"
                    )
            except (CampaignSkip, CampaignFailure, OSError) as error:
                cleanup_error = error

        if apply_error is not None:
            if cleanup_error is not None:
                raise CampaignFailure(
                    f"{apply_error}; live DNS cleanup also failed: {cleanup_error}"
                ) from apply_error
            if isinstance(apply_error, (CampaignSkip, CampaignFailure)):
                raise apply_error
            raise CampaignFailure(f"live DNS apply failed: {apply_error}") from apply_error
        if cleanup_error is not None:
            raise CampaignFailure(f"live DNS cleanup failed: {cleanup_error}") from cleanup_error
        return {
            "status": PASS,
            "detail": (
                "live DNS apply and explicit undo passed using DNS settings from "
                "the supplied configuration; resolver effectiveness requires "
                "host-specific verification"
            ),
            "mode": "live",
            "servers_source": "configuration",
        }

    servers = [
        str(value)
        for value in (
            args.servers if args.servers is not None else DEFAULT_DNS_SERVERS
        )
    ]
    for server in servers:
        try:
            address = ipaddress.ip_address(server)
        except ValueError as error:
            raise CampaignFailure(f"invalid DNS server address: {server}") from error
        if address.is_unspecified or address.is_multicast:
            raise CampaignFailure(f"DNS server must be unicast: {server}")

    with tempfile.TemporaryDirectory(prefix="shph-dns-") as temporary:
        config = Path(temporary) / "config.toml"
        result = run_checked([binary, "--config", config, "init", "--new"], cwd=root)
        if result.returncode != 0:
            raise CampaignFailure(f"identity initialization failed: {result.stderr.strip()}")
        with config.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(
                "\n[control_plane]\n"
                "apply_interface_address = false\n"
                "apply_routes = false\n"
                "apply_dns = true\n"
                f"dns_servers = {json.dumps(servers)}\n"
                "dry_run = true\n"
            )
        commands = [
            [binary, "--config", config, "apply"],
            [binary, "--config", config, "reconcile"],
        ]
        outputs: list[str] = []
        for index, command in enumerate(commands, start=1):
            result = run_checked(command, cwd=root)
            text = result.stdout + result.stderr
            outputs.append(text)
            (output / f"dns-{index}.log").write_text(text, encoding="utf-8")
            if result.returncode != 0:
                raise CampaignFailure(f"DNS dry-run command failed: {command_text(command)}")
        cleanup = run_checked([binary, "--config", config, "undo"], cwd=root)
        (output / "dns-undo.log").write_text(cleanup.stdout + cleanup.stderr, encoding="utf-8")
        if cleanup.returncode != 0:
            raise CampaignFailure("DNS dry-run undo failed")
        if not all("dns add" in text for text in outputs):
            raise CampaignFailure("DNS dry-run did not emit the expected planned mutation")
        return {
            "status": PASS,
            "detail": "DNS apply/reconcile/undo dry-run passed without host mutation",
            "mode": "dry-run",
            "servers": servers,
        }


def run_pmtu(args: argparse.Namespace, root: Path, output: Path) -> dict[str, object]:
    require_command("ping")
    try:
        address = ipaddress.ip_address(args.host)
    except ValueError as error:
        raise CampaignFailure(f"--host must be an IP literal for reproducible PMTU probing: {args.host}") from error
    ipv6 = args.ipv6 or address.version == 6
    if ipv6 and address.version != 6:
        raise CampaignFailure("--ipv6 requires an IPv6 host")
    if not ipv6 and address.version != 4:
        raise CampaignFailure("an IPv4 host is required unless --ipv6 is used")
    if not (0 <= args.min_payload <= args.max_payload <= 65500):
        raise CampaignFailure("payload range must be within 0..65500 bytes")
    if args.step <= 0:
        raise CampaignFailure("--step must be positive")

    rows: list[dict[str, object]] = []
    for payload in range(args.min_payload, args.max_payload + 1, args.step):
        if os.name == "nt":
            command = ["ping", "-6" if ipv6 else "-4", "-n", "1", "-w", str(args.timeout_ms)]
            if not ipv6 and args.do_not_fragment:
                command.append("-f")
            command.extend(["-l", str(payload), args.host])
        else:
            command = [
                "ping",
                "-6" if ipv6 else "-4",
                "-c",
                "1",
                "-W",
                str(max(1, args.timeout_ms // 1000)),
            ]
            if args.interface:
                command.extend(["-I", args.interface])
            if not ipv6 and args.do_not_fragment:
                command.extend(["-M", "do"])
            command.extend(["-s", str(payload), args.host])
        started = time.monotonic()
        result = run_checked(command, cwd=root, timeout=(args.timeout_ms / 1000) + 3)
        elapsed = time.monotonic() - started
        rows.append(
            {
                "payload_bytes": payload,
                "status": PASS if result.returncode == 0 else FAIL,
                "elapsed_seconds": round(elapsed, 6),
                "exit_code": result.returncode,
            }
        )
        (output / f"pmtu-{payload}.log").write_text(result.stdout + result.stderr, encoding="utf-8")

    (output / "pmtu.csv").write_text(
        "payload_bytes,status,elapsed_seconds,exit_code\n"
        + "\n".join(
            f"{row['payload_bytes']},{row['status']},{row['elapsed_seconds']},{row['exit_code']}"
            for row in rows
        )
        + "\n",
        encoding="utf-8",
    )
    passing = [int(row["payload_bytes"]) for row in rows if row["status"] == PASS]
    if not passing:
        raise CampaignFailure("no PMTU probes passed; inspect per-size logs for reachability or MTU errors")
    return {
        "status": PASS,
        "detail": "PMTU probes completed; largest successful payload is reported, not an inferred production MTU",
        "host": args.host,
        "ipv6": ipv6,
        "largest_successful_payload": max(passing),
        "probes": len(rows),
    }


def run_crash(args: argparse.Namespace, root: Path, output: Path) -> dict[str, object]:
    binary = resolve_binary(root, args.binary)
    config = Path(args.config).resolve()
    if not config.is_file():
        raise CampaignFailure(f"configuration file does not exist: {config}")
    if not args.confirm_kill:
        raise CampaignSkip("crash mode requires --confirm-kill because it terminates the supplied SHPH process")
    environment = os.environ.copy()
    for item in args.environment:
        name, separator, value = item.partition("=")
        if not separator or not name:
            raise CampaignFailure(f"--env must use NAME=VALUE: {item}")
        environment[name] = value
    command = [binary, "--config", config, "up", *args.up_arg]
    process = ManagedProcess(command, cwd=root, env=environment)
    ready = False
    try:
        process.wait_for(args.ready_marker, args.ready_timeout_secs)
        ready = True
        time.sleep(args.kill_after_secs)
        return_code = process.hard_kill()
        write_process_logs(output, "crash-target", process)
    finally:
        if process.process.poll() is None:
            process.terminate()
    if not ready:
        raise CampaignFailure("crash target did not reach the requested readiness marker")

    cleanup_result: int | None = None
    if args.cleanup:
        cleanup = run_checked(
            [binary, "--config", config, "down"],
            cwd=root,
            timeout=args.cleanup_timeout_secs,
        )
        cleanup_result = cleanup.returncode
        (output / "crash-cleanup.log").write_text(
            cleanup.stdout + cleanup.stderr,
            encoding="utf-8",
        )
        if cleanup_result != 0:
            raise CampaignFailure(f"post-crash `down` failed with code {cleanup_result}")
    return {
        "status": PASS,
        "detail": "target reached readiness marker and was hard-terminated; inspect host state separately",
        "return_code": return_code,
        "cleanup_return_code": cleanup_result,
        "ready_marker": args.ready_marker,
        "host_state_verification": "not automatic",
    }


def write_result(root: Path, output: Path, campaign: str, result: dict[str, object]) -> None:
    output.mkdir(parents=True, exist_ok=True)
    tree = "clean" if not run_git(root, "status", "--porcelain") else "dirty"
    metadata = {
        "schema": "shph-operator-campaign/v1",
        "campaign": campaign,
        "generated_utc": utc_now(),
        "commit": run_git(root, "rev-parse", "HEAD"),
        "branch": run_git(root, "symbolic-ref", "--short", "-q", "HEAD") or "detached",
        "tree": tree,
        "platform": platform.platform(),
        "python": platform.python_version(),
        "result": result,
    }
    (output / "result.json").write_text(
        json.dumps(metadata, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (output / "result.md").write_text(
        "\n".join(
            [
                "# SHPH Operator Campaign",
                "",
                f"- Campaign: `{campaign}`",
                f"- Generated (UTC): `{metadata['generated_utc']}`",
                f"- Commit: `{metadata['commit']}`",
                f"- Tree: `{metadata['tree']}`",
                f"- Platform: `{metadata['platform']}`",
                f"- Status: **{result.get('status', 'UNKNOWN')}**",
                f"- Detail: {result.get('detail', '')}",
                "",
                "This is operator/lab evidence. It does not establish production, "
                "hostile-network, anonymity, or censorship-resistance claims.",
                "",
            ]
        ),
        encoding="utf-8",
    )


def add_common_output(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--binary", help="path to shph; defaults to target/release/shph(.exe)")
    parser.add_argument("--output", help="evidence directory; defaults below benchmark-runs/campaigns")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="campaign", required=True)

    reconnect = subparsers.add_parser("reconnect", help="interrupt a local peer and verify bounded reconnect")
    add_common_output(reconnect)
    reconnect.add_argument("--host", default="127.0.0.1")
    reconnect.add_argument("--port", type=int)
    reconnect.add_argument("--timeout-secs", type=int, default=3)
    reconnect.add_argument("--startup-timeout-secs", type=float, default=10)
    reconnect.add_argument("--handshake-timeout-secs", type=float, default=10)
    reconnect.add_argument("--reconnect-timeout-secs", type=float, default=5)
    reconnect.add_argument("--interruption-delay-secs", type=float, default=0.25)
    reconnect.add_argument("--max-attempts", type=int, default=8)
    reconnect.add_argument("--initial-delay-ms", type=int, default=100)
    reconnect.add_argument("--max-delay-ms", type=int, default=250)

    soak = subparsers.add_parser("soak", help="repeat fresh authenticated one-shot sessions")
    add_common_output(soak)
    soak.add_argument("--host", default="127.0.0.1")
    soak.add_argument("--port", type=int)
    soak.add_argument("--sessions", type=int, default=10)
    soak.add_argument("--interval-ms", type=int, default=100)
    soak.add_argument("--timeout-secs", type=int, default=5)
    soak.add_argument("--startup-timeout-secs", type=float, default=5)
    soak.add_argument("--message-prefix", default="shph-soak")

    ipv6 = subparsers.add_parser("ipv6", help="run the soak transaction over IPv6 loopback")
    add_common_output(ipv6)
    ipv6.add_argument("--port", type=int)
    ipv6.add_argument("--sessions", type=int, default=3)
    ipv6.add_argument("--interval-ms", type=int, default=100)
    ipv6.add_argument("--timeout-secs", type=int, default=5)
    ipv6.add_argument("--startup-timeout-secs", type=float, default=5)
    ipv6.add_argument("--message-prefix", default="shph-ipv6")
    ipv6.set_defaults(host="::1")

    dns = subparsers.add_parser("dns", help="run DNS control-plane dry-run or guarded live apply")
    add_common_output(dns)
    dns.add_argument("--config")
    dns.add_argument(
        "--servers",
        nargs="+",
        default=None,
        help="DNS servers for dry-run mode; live mode reads them from the config",
    )
    dns.add_argument("--live", action="store_true")
    dns.add_argument("--timeout-secs", type=int, default=10)

    pmtu = subparsers.add_parser("pmtu", help="probe an IP literal with DF/fragmentation controls")
    add_common_output(pmtu)
    pmtu.add_argument("--host", required=True)
    pmtu.add_argument("--interface")
    pmtu.add_argument("--ipv6", action="store_true")
    pmtu.add_argument("--min-payload", type=int, default=1200)
    pmtu.add_argument("--max-payload", type=int, default=1472)
    pmtu.add_argument("--step", type=int, default=16)
    pmtu.add_argument("--timeout-ms", type=int, default=2000)
    pmtu.add_argument("--do-not-fragment", action=argparse.BooleanOptionalAction, default=True)

    crash = subparsers.add_parser("crash", help="hard-terminate a prepared SHPH up process")
    add_common_output(crash)
    crash.add_argument("--config", required=True)
    crash.add_argument("--ready-marker", default="Transport loop: active")
    crash.add_argument("--ready-timeout-secs", type=float, default=30)
    crash.add_argument("--kill-after-secs", type=float, default=2)
    crash.add_argument("--cleanup", action="store_true", help="run `shph down` after the hard kill")
    crash.add_argument("--cleanup-timeout-secs", type=int, default=15)
    crash.add_argument("--confirm-kill", action="store_true", help="required acknowledgement of process termination")
    crash.add_argument("--up-arg", action="append", default=[], help="extra argument for `shph up`; use --up-arg=--no-tun")
    crash.add_argument("--env", dest="environment", action="append", default=[], metavar="NAME=VALUE")

    return parser


def validate_args(args: argparse.Namespace) -> None:
    for field in ("sessions", "timeout_secs", "max_attempts"):
        if hasattr(args, field) and getattr(args, field) is not None and getattr(args, field) <= 0:
            raise CampaignFailure(f"--{field.replace('_', '-')} must be positive")
    if hasattr(args, "port") and args.port is not None and not (1 <= args.port <= 65535):
        raise CampaignFailure("--port must be between 1 and 65535")


def main(argv: Sequence[str] | None = None) -> int:
    root = repository_root()
    parser = build_parser()
    args = parser.parse_args(argv)
    output = Path(args.output).resolve() if args.output else default_output(root, args.campaign)
    try:
        validate_args(args)
        output.mkdir(parents=True, exist_ok=False)
        if args.campaign == "reconnect":
            result = run_reconnect(args, root, output)
        elif args.campaign == "soak":
            result = run_soak(args, root, output)
        elif args.campaign == "ipv6":
            result = run_soak(args, root, output, ipv6=True)
        elif args.campaign == "dns":
            result = run_dns(args, root, output)
        elif args.campaign == "pmtu":
            result = run_pmtu(args, root, output)
        elif args.campaign == "crash":
            result = run_crash(args, root, output)
        else:
            raise CampaignFailure(f"unsupported campaign: {args.campaign}")
        write_result(root, output, args.campaign, result)
        print(f"{result['status']},{args.campaign},{result.get('detail', '')}")
        print(f"output={output}")
        return EXIT_PASS
    except CampaignSkip as error:
        result = {"status": SKIP, "detail": str(error)}
        try:
            output.mkdir(parents=True, exist_ok=True)
            write_result(root, output, args.campaign, result)
        except (OSError, ValueError):
            pass
        print(f"{SKIP},{args.campaign},{error}")
        return EXIT_SKIP
    except CampaignFailure as error:
        result = {"status": FAIL, "detail": str(error)}
        try:
            output.mkdir(parents=True, exist_ok=True)
            write_result(root, output, args.campaign, result)
        except (OSError, ValueError):
            pass
        print(f"{FAIL},{args.campaign},{error}", file=sys.stderr)
        return EXIT_FAIL
    except OSError as error:
        print(f"{FAIL},{args.campaign},{error}", file=sys.stderr)
        return EXIT_FAIL


if __name__ == "__main__":
    sys.exit(main())
