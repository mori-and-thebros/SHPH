#!/usr/bin/env python3
"""Measure bounded SHPH one-shot CLI exchanges over local loopback only."""

import argparse
import json
import os
import platform
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
MAX_ITERATIONS = 10
MAX_TIMEOUT_SECS = 15
MIN_PAYLOAD_BYTES = 32
MAX_PAYLOAD_BYTES = 4096
TCP_STARTUP_GRACE_SECS = 0.15
TRANSPORTS = {
    "tcp": "tcp",
    "quic-standard": "quic-standard",
}


class RunnerError(RuntimeError):
    pass


def bounded_int(minimum, maximum):
    def parse(value):
        try:
            parsed = int(value)
        except ValueError as error:
            raise argparse.ArgumentTypeError("must be an integer") from error
        if not minimum <= parsed <= maximum:
            raise argparse.ArgumentTypeError(f"must be between {minimum} and {maximum}")
        return parsed

    return parse


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Run real SHPH send-once/recv-once sessions on 127.0.0.1."
    )
    parser.add_argument("--binary", type=Path, help="SHPH CLI binary (or set SHPH_BIN)")
    parser.add_argument("--transport", choices=tuple(TRANSPORTS), default="tcp")
    parser.add_argument("--mode", choices=("baseline", "negotiated", "both"), default="both")
    parser.add_argument("--iterations", type=bounded_int(1, MAX_ITERATIONS), default=3)
    parser.add_argument(
        "--payload-bytes",
        type=bounded_int(MIN_PAYLOAD_BYTES, MAX_PAYLOAD_BYTES),
        default=256,
    )
    parser.add_argument(
        "--timeout-secs", type=bounded_int(1, MAX_TIMEOUT_SECS), default=5
    )
    parser.add_argument("--output", type=Path, help="new JSON output path; existing files are refused")
    return parser.parse_args(argv)


def percentile(values, quantile):
    ordered = sorted(values)
    index = max(0, min(len(ordered) - 1, int((len(ordered) - 1) * quantile + 0.5)))
    return round(ordered[index], 3)


def summarize(values):
    return {
        "samples": len(values),
        "min_ms": round(min(values), 3),
        "median_ms": round(statistics.median(values), 3),
        "p95_ms": percentile(values, 0.95),
        "p99_ms": percentile(values, 0.99),
        "max_ms": round(max(values), 3),
    }


def make_payload(iteration, size):
    prefix = f"shph-local-{iteration:04d}:".encode("ascii")
    if len(prefix) > size:
        raise RunnerError("payload size is too small for its session marker")
    return (prefix + b"x" * (size - len(prefix))).decode("ascii")


def command_output(command, *, timeout, step):
    try:
        result = subprocess.run(
            command,
            check=False,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as error:
        raise RunnerError(f"{step} exceeded its {timeout}s process limit") from error
    if result.returncode != 0:
        detail = (result.stderr or result.stdout).strip()
        detail = detail[-1200:] if detail else "no diagnostic output"
        raise RunnerError(f"{step} failed with exit code {result.returncode}: {detail}")
    return result.stdout.strip()


def cli_command(binary, config, *arguments):
    return [str(binary), "--config", str(config), *map(str, arguments)]


def create_identity(binary, directory, role, timeout):
    config = directory / "config.toml"
    command_output(cli_command(binary, config, "init", "--new"), timeout=timeout, step=f"init {role}")
    public_key = command_output(
        cli_command(binary, config, "show-public-key"), timeout=timeout, step=f"read {role} public key"
    )
    signing_key = command_output(
        cli_command(binary, config, "show-signing-public-key"),
        timeout=timeout,
        step=f"read {role} signing public key",
    )
    return config, public_key, signing_key


def choose_loopback_port(transport):
    socket_type = socket.SOCK_STREAM if transport == "tcp" else socket.SOCK_DGRAM
    with socket.socket(socket.AF_INET, socket_type) as listener:
        listener.bind(("127.0.0.1", 0))
        return listener.getsockname()[1]


def check_peer_command(binary, config, alias, port, peer_keys, timeout):
    command_output(
        cli_command(
            binary,
            config,
            "add-peer",
            alias,
            "127.0.0.1",
            str(port),
            peer_keys[0],
            "--sign-pubkey",
            peer_keys[1],
        ),
        timeout=timeout,
        step=f"pin {alias} peer",
    )


def receiver_command(binary, config, endpoint, transport, timeout, negotiated, cert, key):
    command = cli_command(
        binary,
        config,
        "recv-once",
        "--bind",
        endpoint,
        "--timeout-secs",
        str(timeout),
        "--transport",
        TRANSPORTS[transport],
    )
    if transport == "quic-standard":
        command.extend(("--quic-cert", str(cert), "--quic-key", str(key)))
    if negotiated:
        command.append("--negotiate-envelope-policy")
    return command


def sender_command(binary, config, endpoint, transport, timeout, negotiated, payload, cert):
    command = cli_command(
        binary,
        config,
        "send-once",
        "--peer",
        endpoint,
        "--text",
        payload,
        "--timeout-secs",
        str(timeout),
        "--transport",
        TRANSPORTS[transport],
    )
    if transport == "quic-standard":
        command.extend(("--quic-cert", str(cert)))
    if negotiated:
        command.append("--negotiate-envelope-policy")
    return command


def wait_for_quic_certificate(process, certificate, private_key, deadline):
    while time.monotonic() < deadline:
        if certificate.is_file() and private_key.is_file():
            return
        if process.poll() is not None:
            stdout, stderr = process.communicate()
            detail = (stderr or stdout).strip()[-1200:]
            raise RunnerError(f"standards-QUIC receiver exited before readiness: {detail}")
        time.sleep(0.02)
    raise RunnerError("standards-QUIC receiver did not create its temporary certificate in time")


def run_session(binary, server_config, client_config, endpoint, transport, timeout,
                negotiated, payload, cert, private_key):
    if transport == "quic-standard":
        for stale_file in (cert, private_key):
            if stale_file.exists():
                stale_file.unlink()
    receiver = subprocess.Popen(
        receiver_command(
            binary, server_config, endpoint, transport, timeout, negotiated, cert, private_key
        ),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    started = time.monotonic_ns()
    try:
        if transport == "quic-standard":
            wait_for_quic_certificate(
                receiver,
                cert,
                private_key,
                time.monotonic() + min(timeout, 5),
            )
        else:
            time.sleep(TCP_STARTUP_GRACE_SECS)
            if receiver.poll() is not None:
                stdout, stderr = receiver.communicate()
                detail = (stderr or stdout).strip()[-1200:]
                raise RunnerError(f"TCP receiver exited before sender start: {detail}")

        try:
            sender = subprocess.run(
                sender_command(
                    binary,
                    client_config,
                    endpoint,
                    transport,
                    timeout,
                    negotiated,
                    payload,
                    cert,
                ),
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout + 5,
            )
        except subprocess.TimeoutExpired as error:
            raise RunnerError("sender exceeded its bounded process limit") from error
        if sender.returncode != 0:
            detail = (sender.stderr or sender.stdout).strip()[-1200:]
            raise RunnerError(f"sender failed with exit code {sender.returncode}: {detail}")

        try:
            receiver_stdout, receiver_stderr = receiver.communicate(timeout=timeout + 5)
        except subprocess.TimeoutExpired as error:
            raise RunnerError("receiver exceeded its bounded process limit") from error
        if receiver.returncode != 0:
            detail = (receiver_stderr or receiver_stdout).strip()[-1200:]
            raise RunnerError(f"receiver failed with exit code {receiver.returncode}: {detail}")
        if f"Payload: {payload}" not in receiver_stdout:
            raise RunnerError("receiver did not report the exact expected payload")
        return (time.monotonic_ns() - started) / 1_000_000
    finally:
        if receiver.poll() is None:
            receiver.kill()
            try:
                receiver.communicate(timeout=2)
            except subprocess.TimeoutExpired:
                pass


def git_state():
    commit = command_output(
        ["git", "-C", str(ROOT), "rev-parse", "HEAD"], timeout=5, step="read git revision"
    )
    status = command_output(
        ["git", "-C", str(ROOT), "status", "--porcelain=v1", "--untracked-files=all"],
        timeout=5,
        step="read git worktree state",
    )
    return {"commit": commit, "working_tree_dirty": bool(status)}


def selected_modes(mode):
    if mode == "both":
        return ("baseline", "negotiated")
    return (mode,)


def run_benchmark(args, binary):
    transport = args.transport
    timeout = args.timeout_secs
    setup_started = time.monotonic_ns()
    sample_values = {mode: [] for mode in selected_modes(args.mode)}
    measurements = []

    with tempfile.TemporaryDirectory(prefix="shph-one-shot-loopback-") as temporary:
        root = Path(temporary)
        server_dir = root / "server"
        client_dir = root / "client"
        server_dir.mkdir()
        client_dir.mkdir()
        server_config, server_public, server_signing = create_identity(
            binary, server_dir, "server", timeout
        )
        client_config, client_public, client_signing = create_identity(
            binary, client_dir, "client", timeout
        )
        port = choose_loopback_port(transport)
        endpoint = f"127.0.0.1:{port}"
        check_peer_command(
            binary, server_config, "client", port, (client_public, client_signing), timeout
        )
        check_peer_command(
            binary, client_config, "server", port, (server_public, server_signing), timeout
        )
        certificate = server_dir / "server.der"
        private_key = server_dir / "server.key"

        for iteration in range(1, args.iterations + 1):
            modes = list(sample_values)
            if iteration % 2 == 0:
                modes.reverse()
            payload = make_payload(iteration, args.payload_bytes)
            for mode in modes:
                elapsed_ms = run_session(
                    binary,
                    server_config,
                    client_config,
                    endpoint,
                    transport,
                    timeout,
                    mode == "negotiated",
                    payload,
                    certificate,
                    private_key,
                )
                sample_values[mode].append(elapsed_ms)
                measurements.append(
                    {
                        "iteration": iteration,
                        "mode": mode,
                        "payload_bytes": args.payload_bytes,
                        "session_wall_clock_ms": round(elapsed_ms, 3),
                        "payload_verified_by_receiver": True,
                    }
                )

    setup_elapsed_ms = (time.monotonic_ns() - setup_started) / 1_000_000
    rustc_path = shutil.which("rustc")
    if rustc_path is None:
        cargo_rustc = Path.home() / ".cargo" / "bin" / ("rustc.exe" if os.name == "nt" else "rustc")
        rustc_path = str(cargo_rustc) if cargo_rustc.is_file() else None
    try:
        rustc = subprocess.run(
            [rustc_path, "--version"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        ) if rustc_path else None
        rustc_version = rustc.stdout.strip() if rustc and rustc.returncode == 0 else None
    except (OSError, subprocess.TimeoutExpired):
        rustc_version = None
    revision = git_state()
    summaries = {mode: summarize(values) for mode, values in sample_values.items()}
    return {
        "schema": "shph-one-shot-loopback-benchmark-v1",
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "scope": "local-loopback-cli-session-observation",
        "evidence_status": "engineering_observation_not_P5_acceptance",
        "revision": revision,
        "environment": {
            "platform": platform.platform(),
            "python": platform.python_version(),
            "rustc": rustc_version,
            "host_roles": "sender and receiver are local CLI processes",
            "endpoint_scope": "127.0.0.1 only",
        },
        "workload": {
            "carrier": transport,
            "pattern": "single fixed-size payload per one-shot session",
            "iterations_per_mode": args.iterations,
            "modes": list(sample_values),
            "payload_bytes_per_session": args.payload_bytes,
            "timeout_secs_per_cli": timeout,
            "order": "alternating baseline-first and negotiated-first when comparing both",
            "seed_controlled": False,
        },
        "setup_wall_clock_ms": round(setup_elapsed_ms, 3),
        "measurements": measurements,
        "session_wall_clock_summary_ms": summaries,
        "unmeasured": {
            "network_packet_capture": "not performed",
            "wire_bytes_and_carrier_overhead": "not observed",
            "envelope_overhead": "not measured",
            "goodput": "not reported; process startup and orchestration are included",
            "cpu_and_memory": "not sampled",
            "loss_delay_reordering_bandwidth_reconnect": "not applied",
        },
        "limitations": [
            "loopback CLI process timing only; not carrier-only latency or throughput",
            "not a packet capture, two-host run, active-probe test, or blocking simulation",
            "does not complete P5 workload, resource, overhead, or observation-point acceptance",
            "temporary identities, private keys, certificates, and configs are removed on exit",
        ],
    }


def resolve_binary(path):
    candidate = path or (Path(os.environ["SHPH_BIN"]) if os.environ.get("SHPH_BIN") else None)
    if candidate is None:
        candidates = (ROOT / "target" / "release" / "shph", ROOT / "target" / "debug" / "shph")
        candidate = next((item for item in candidates if item.is_file()), candidates[0])
    candidate = candidate.expanduser().resolve()
    if not candidate.is_file():
        raise RunnerError(
            f"SHPH binary not found at {candidate}; build it with "
            "`cargo build --locked -p shph-cli --release` or pass --binary"
        )
    return candidate


def main(argv=None):
    args = parse_args(argv)
    try:
        binary = resolve_binary(args.binary)
        manifest = run_benchmark(args, binary)
        output = json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        if args.output:
            destination = args.output.expanduser()
            destination.parent.mkdir(parents=True, exist_ok=True)
            with destination.open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(output)
            print(f"Wrote local-only observation: {destination}")
        else:
            sys.stdout.write(output)
        return 0
    except (RunnerError, OSError) as error:
        print(f"benchmark_one_shot_loopback: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
