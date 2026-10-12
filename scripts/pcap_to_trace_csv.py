#!/usr/bin/env python3
"""Convert bounded Ethernet PCAP captures into D4 packet-summary CSV."""

from __future__ import annotations

import argparse
import csv
import hashlib
import ipaddress
import json
import os
import re
import shutil
import stat
import struct
import sys
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Sequence


CSV_COLUMNS = (
    "candidate",
    "label",
    "session_id",
    "site_id",
    "host_id",
    "day_id",
    "timestamp_s",
    "direction",
    "length_bytes",
)
MAX_CAPTURE_BYTES = 512 * 1024 * 1024
MAX_CAPTURE_RECORDS = 200_000
MAX_CAPTURED_PACKET_BYTES = 1_000_064
MAX_PACKET_LENGTH = 1_000_000
MAX_OUTPUT_ROWS = 40_000
MAX_OUTPUT_SESSIONS = 3_000
MAX_CANDIDATE_CHARS = 48
MAX_IDENTIFIER_CHARS = 128
MAX_CAPTURE_ID_CHARS = 48
MAX_IDLE_TIMEOUT_MS = 3_600_000
ETHERNET_LINK_TYPE = 1
VLAN_ETHERTYPES = {0x8100, 0x88A8, 0x9100}
PCAP_MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1_000),
    b"\xa1\xb2\xc3\xd4": (">", 1_000),
    b"\x4d\x3c\xb2\xa1": ("<", 1),
    b"\xa1\xb2\x3c\x4d": (">", 1),
}


class CaptureError(Exception):
    """Malformed, unsupported, or over-limit capture input."""


@dataclass(frozen=True)
class IpPacket:
    source: ipaddress.IPv4Address | ipaddress.IPv6Address
    destination: ipaddress.IPv4Address | ipaddress.IPv6Address
    protocol: int
    ip_length: int
    transport_offset: int
    ip_end: int
    fragmented: bool


@dataclass
class FlowState:
    session_id: str
    first_timestamp_ns: int
    last_timestamp_ns: int


def _read_exact(handle: BinaryIO, length: int, digest: "hashlib._Hash", label: str) -> bytes:
    value = handle.read(length)
    if len(value) != length:
        raise CaptureError(f"truncated PCAP {label}")
    digest.update(value)
    return value


def _parse_ethernet(frame: bytes) -> IpPacket | None:
    if len(frame) < 14:
        raise CaptureError("truncated Ethernet frame")
    ethertype = int.from_bytes(frame[12:14], "big")
    offset = 14
    vlan_depth = 0
    while ethertype in VLAN_ETHERTYPES:
        if vlan_depth >= 4 or offset + 4 > len(frame):
            raise CaptureError("invalid or excessively nested VLAN header")
        ethertype = int.from_bytes(frame[offset + 2:offset + 4], "big")
        offset += 4
        vlan_depth += 1

    if ethertype == 0x0800:
        return _parse_ipv4(frame, offset)
    if ethertype == 0x86DD:
        return _parse_ipv6(frame, offset)
    return None


def _parse_ipv4(frame: bytes, offset: int) -> IpPacket | None:
    if offset + 20 > len(frame):
        raise CaptureError("truncated IPv4 header")
    first = frame[offset]
    if first >> 4 != 4:
        raise CaptureError("invalid IPv4 version")
    header_length = (first & 0x0F) * 4
    if header_length < 20 or offset + header_length > len(frame):
        raise CaptureError("invalid IPv4 header length")
    total_length = int.from_bytes(frame[offset + 2:offset + 4], "big")
    if total_length < header_length or offset + total_length > len(frame):
        raise CaptureError("invalid or truncated IPv4 packet")
    protocol = frame[offset + 9]
    if protocol not in (6, 17):
        return None
    fragment = int.from_bytes(frame[offset + 6:offset + 8], "big")
    fragmented = bool(fragment & 0x3FFF)
    return IpPacket(
        source=ipaddress.IPv4Address(frame[offset + 12:offset + 16]),
        destination=ipaddress.IPv4Address(frame[offset + 16:offset + 20]),
        protocol=protocol,
        ip_length=total_length,
        transport_offset=offset + header_length,
        ip_end=offset + total_length,
        fragmented=fragmented,
    )


def _parse_ipv6(frame: bytes, offset: int) -> IpPacket | None:
    if offset + 40 > len(frame) or frame[offset] >> 4 != 6:
        raise CaptureError("truncated or invalid IPv6 header")
    payload_length = int.from_bytes(frame[offset + 4:offset + 6], "big")
    if payload_length == 0:
        raise CaptureError("IPv6 jumbograms are unsupported")
    ip_end = offset + 40 + payload_length
    if ip_end > len(frame):
        raise CaptureError("truncated IPv6 packet")
    source = ipaddress.IPv6Address(frame[offset + 8:offset + 24])
    destination = ipaddress.IPv6Address(frame[offset + 24:offset + 40])
    protocol = frame[offset + 6]
    transport_offset = offset + 40
    fragmented = False

    for _ in range(8):
        if protocol in (0, 43, 60):
            if transport_offset + 2 > ip_end:
                raise CaptureError("truncated IPv6 extension header")
            next_protocol = frame[transport_offset]
            header_length = (frame[transport_offset + 1] + 1) * 8
            if transport_offset + header_length > ip_end:
                raise CaptureError("invalid IPv6 extension header length")
            protocol = next_protocol
            transport_offset += header_length
            continue
        if protocol == 44:
            if transport_offset + 8 > ip_end:
                raise CaptureError("truncated IPv6 fragment header")
            next_protocol = frame[transport_offset]
            fragment = int.from_bytes(frame[transport_offset + 2:transport_offset + 4], "big")
            fragmented = bool(fragment & 0xFFF9)
            protocol = next_protocol
            transport_offset += 8
            continue
        if protocol == 51:
            if transport_offset + 2 > ip_end:
                raise CaptureError("truncated IPv6 authentication header")
            next_protocol = frame[transport_offset]
            header_length = (frame[transport_offset + 1] + 2) * 4
            if transport_offset + header_length > ip_end:
                raise CaptureError("invalid IPv6 authentication header length")
            protocol = next_protocol
            transport_offset += header_length
            continue
        break
    else:
        if protocol in (0, 43, 44, 51, 60):
            raise CaptureError("IPv6 extension-header chain exceeds the safety limit")

    if protocol not in (6, 17):
        return None
    return IpPacket(
        source=source,
        destination=destination,
        protocol=protocol,
        ip_length=40 + payload_length,
        transport_offset=transport_offset,
        ip_end=ip_end,
        fragmented=fragmented,
    )


def _parse_transport(frame: bytes, packet: IpPacket) -> tuple[int, int, int]:
    if packet.fragmented:
        raise CaptureError("fragmented TCP/UDP traffic cannot be converted without bias")
    offset = packet.transport_offset
    if packet.protocol == 6:
        if offset + 20 > packet.ip_end:
            raise CaptureError("truncated TCP header")
        header_length = (frame[offset + 12] >> 4) * 4
        if header_length < 20 or offset + header_length > packet.ip_end:
            raise CaptureError("invalid TCP header length")
        flags = frame[offset + 13]
    else:
        if offset + 8 > packet.ip_end:
            raise CaptureError("truncated UDP header")
        udp_length = int.from_bytes(frame[offset + 4:offset + 6], "big")
        if udp_length < 8 or udp_length > packet.ip_end - offset:
            raise CaptureError("invalid UDP length")
        flags = 0
    source_port = int.from_bytes(frame[offset:offset + 2], "big")
    destination_port = int.from_bytes(frame[offset + 2:offset + 4], "big")
    return source_port, destination_port, flags


def _validate_identifier(
    value: str,
    name: str,
    *,
    slug: bool = False,
    max_chars: int = MAX_IDENTIFIER_CHARS,
) -> str:
    if not value or len(value) > (MAX_CAPTURE_ID_CHARS if slug else max_chars):
        raise CaptureError(f"{name} is empty or exceeds the safety limit")
    if any(character.isspace() or ord(character) < 32 or ord(character) == 127 for character in value):
        raise CaptureError(f"{name} contains whitespace or control characters")
    if value.lstrip("\ufeff")[:1] in ("=", "+", "-", "@"):
        raise CaptureError(f"{name} must not start with a spreadsheet formula prefix")
    if slug and re.fullmatch(r"[A-Za-z0-9._-]+", value) is None:
        raise CaptureError(f"{name} must contain only ASCII letters, digits, dot, underscore, or dash")
    return value


def _timestamp_text(timestamp_ns: int, start_ns: int) -> str:
    seconds, nanoseconds = divmod(timestamp_ns - start_ns, 1_000_000_000)
    return f"{seconds}.{nanoseconds:09d}".rstrip("0").rstrip(".")


def parse_capture(
    path: str | Path,
    *,
    observer_address: str,
    remote_ports: Sequence[int],
    endpoint_port: int | None,
    candidate: str,
    label: str,
    site_id: str,
    host_id: str,
    day_id: str,
    capture_id: str,
    idle_timeout_ms: int,
) -> tuple[list[tuple[str, ...]], dict[str, object]]:
    try:
        observer = ipaddress.ip_address(observer_address)
    except ValueError as error:
        raise CaptureError("observer address must be a literal IPv4 or IPv6 address") from error
    if not remote_ports or any(port < 1 or port > 65535 for port in remote_ports):
        raise CaptureError("at least one valid remote TCP/UDP port is required")
    if endpoint_port is not None and not 1 <= endpoint_port <= 65535:
        raise CaptureError("endpoint port must be between 1 and 65535")
    if not 1 <= idle_timeout_ms <= MAX_IDLE_TIMEOUT_MS:
        raise CaptureError("idle timeout must be between 1 and 3600000 milliseconds")
    candidate = _validate_identifier(candidate, "candidate", max_chars=MAX_CANDIDATE_CHARS)
    if label not in ("control", "target"):
        raise CaptureError("label must be control or target")
    site_id = _validate_identifier(site_id, "site identifier")
    host_id = _validate_identifier(host_id, "host identifier")
    day_id = _validate_identifier(day_id, "day identifier")
    capture_id = _validate_identifier(capture_id, "capture identifier", slug=True)

    source = Path(path).expanduser()
    try:
        file_stat = source.stat(follow_symlinks=False)
    except OSError as error:
        raise CaptureError("unable to inspect input capture") from error
    if not stat.S_ISREG(file_stat.st_mode) or source.is_symlink():
        raise CaptureError("input capture must be a regular non-symlink file")
    if file_stat.st_size < 24 or file_stat.st_size > MAX_CAPTURE_BYTES:
        raise CaptureError("input capture size is outside the supported bounds")

    digest = hashlib.sha256()
    rows: list[tuple[str, ...]] = []
    flows: dict[tuple[object, ...], FlowState] = {}
    record_count = 0
    skipped_records = 0
    session_count = 0
    previous_timestamp_ns: int | None = None
    idle_timeout_ns = idle_timeout_ms * 1_000_000

    try:
        flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(source, flags)
        with os.fdopen(descriptor, "rb") as handle:
            opened_stat = os.fstat(handle.fileno())
            if not stat.S_ISREG(opened_stat.st_mode) or opened_stat.st_size < 24 or opened_stat.st_size > MAX_CAPTURE_BYTES:
                raise CaptureError("opened capture is outside the supported bounds")
            file_stat = opened_stat
            magic = _read_exact(handle, 4, digest, "global header")
            format_info = PCAP_MAGICS.get(magic)
            if format_info is None:
                raise CaptureError("unsupported PCAP magic or PCAPNG input")
            byte_order, fraction_divisor = format_info
            global_header = _read_exact(handle, 20, digest, "global header")
            major, minor, _timezone, _sigfigs, snaplen, link_type = struct.unpack(
                byte_order + "HHIIII", global_header
            )
            if (major, minor) != (2, 4):
                raise CaptureError("only classic PCAP version 2.4 is supported")
            if link_type != ETHERNET_LINK_TYPE:
                raise CaptureError("only Ethernet-link PCAP captures are supported")
            if not 1 <= snaplen <= MAX_CAPTURED_PACKET_BYTES:
                raise CaptureError("PCAP snapshot length exceeds the safety limit")

            while True:
                record_header = handle.read(16)
                if not record_header:
                    break
                digest.update(record_header)
                if handle.tell() > MAX_CAPTURE_BYTES:
                    raise CaptureError("capture data exceeds the byte limit")
                if len(record_header) != 16:
                    raise CaptureError("truncated PCAP packet header")
                record_count += 1
                if record_count > MAX_CAPTURE_RECORDS:
                    raise CaptureError("PCAP packet count exceeds the safety limit")
                seconds, fraction, captured_length, original_length = struct.unpack(
                    byte_order + "IIII", record_header
                )
                fraction_limit = 1_000_000_000 // fraction_divisor
                if fraction >= fraction_limit:
                    raise CaptureError("invalid PCAP packet timestamp fraction")
                if (
                    captured_length > snaplen
                    or captured_length > MAX_CAPTURED_PACKET_BYTES
                    or original_length < captured_length
                    or original_length > MAX_CAPTURED_PACKET_BYTES
                ):
                    raise CaptureError("PCAP packet length exceeds the safety limit")
                if captured_length != original_length:
                    raise CaptureError("truncated captured packets are not accepted")
                if handle.tell() + captured_length > MAX_CAPTURE_BYTES:
                    raise CaptureError("capture data exceeds the byte limit")
                frame = _read_exact(handle, captured_length, digest, "packet data")
                timestamp_ns = seconds * 1_000_000_000 + fraction * fraction_divisor
                if previous_timestamp_ns is not None and timestamp_ns < previous_timestamp_ns:
                    raise CaptureError("PCAP timestamps are not in nondecreasing order")
                previous_timestamp_ns = timestamp_ns

                packet = _parse_ethernet(frame)
                if packet is None:
                    skipped_records += 1
                    continue
                if packet.source != observer and packet.destination != observer:
                    skipped_records += 1
                    continue
                if packet.ip_length > MAX_PACKET_LENGTH:
                    raise CaptureError("selected IP packet exceeds the evaluator size limit")
                source_port, destination_port, tcp_flags = _parse_transport(frame, packet)

                if packet.source == observer and packet.destination != observer:
                    direction = "out"
                    remote_port = destination_port
                elif packet.destination == observer and packet.source != observer:
                    direction = "in"
                    remote_port = source_port
                elif endpoint_port is not None and source_port == endpoint_port and destination_port != endpoint_port:
                    direction = "out"
                    remote_port = destination_port
                elif endpoint_port is not None and destination_port == endpoint_port and source_port != endpoint_port:
                    direction = "in"
                    remote_port = source_port
                elif endpoint_port is None:
                    raise CaptureError("loopback direction is ambiguous; set endpoint port")
                else:
                    skipped_records += 1
                    continue
                if remote_port not in remote_ports:
                    skipped_records += 1
                    continue

                source_endpoint = (packet.source.version, packet.source.packed, source_port)
                destination_endpoint = (packet.destination.version, packet.destination.packed, destination_port)
                flow_key = (packet.protocol, *sorted((source_endpoint, destination_endpoint)))
                state = flows.get(flow_key)
                if state is not None and timestamp_ns - state.last_timestamp_ns > idle_timeout_ns:
                    del flows[flow_key]
                    state = None
                if state is None:
                    session_count += 1
                    if session_count > MAX_OUTPUT_SESSIONS:
                        raise CaptureError("selected flow count exceeds the safety limit")
                    state = FlowState(
                        session_id=f"{capture_id}-{session_count:06d}",
                        first_timestamp_ns=timestamp_ns,
                        last_timestamp_ns=timestamp_ns,
                    )
                    flows[flow_key] = state
                state.last_timestamp_ns = timestamp_ns
                if len(rows) >= MAX_OUTPUT_ROWS:
                    raise CaptureError("selected packet count exceeds the evaluator limit")
                rows.append((
                    candidate,
                    label,
                    state.session_id,
                    site_id,
                    host_id,
                    day_id,
                    _timestamp_text(timestamp_ns, state.first_timestamp_ns),
                    direction,
                    str(packet.ip_length),
                ))
                if packet.protocol == 6 and tcp_flags & 0x05:
                    flows.pop(flow_key, None)
    except CaptureError:
        raise
    except (OSError, struct.error) as error:
        raise CaptureError("unable to parse input capture") from error

    if not rows:
        raise CaptureError("capture contains no packets matching the selected endpoint and ports")

    manifest: dict[str, object] = {
        "schema_version": 1,
        "converter": "pcap_to_trace_csv.py",
        "capture_format": "classic-pcap-2.4",
        "link_type": "ethernet",
        "capture_sha256": digest.hexdigest(),
        "capture_size_bytes": file_stat.st_size,
        "record_count": record_count,
        "skipped_record_count": skipped_records,
        "selected_packet_count": len(rows),
        "session_count": session_count,
        "candidate": candidate,
        "label": label,
        "site_id": site_id,
        "host_id": host_id,
        "day_id": day_id,
        "capture_id": capture_id,
        "observer_address_recorded": False,
        "remote_ports": sorted(set(remote_ports)),
        "endpoint_port": endpoint_port,
        "idle_timeout_ms": idle_timeout_ms,
        "timestamp_origin": "first observed packet in each flow session",
        "length_definition": "outer IPv4 total length or outer IPv6 header plus payload; Ethernet header excluded",
        "limitations": [
            "authorized captures only; this tool does not collect packets",
            "selected fragmented, truncated, ambiguous, and unsupported packets fail closed",
            "classic Ethernet PCAP only; PCAPNG and other link types are unsupported",
            "TCP retransmissions and acknowledgements remain separate observed packets",
            "no addresses, ports, packet payloads, or absolute timestamps are written to CSV",
        ],
    }
    return rows, manifest


def write_capture_bundle(output_dir: str | Path, rows: Sequence[Sequence[str]], manifest: dict[str, object]) -> None:
    destination = Path(output_dir).expanduser()
    if destination.exists() or destination.is_symlink():
        raise CaptureError("output directory already exists")
    parent = destination.parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=f".{destination.name}.tmp-", dir=parent))
    except OSError as error:
        raise CaptureError("unable to prepare output directory") from error
    try:
        with (staging / "traces.csv").open("x", encoding="utf-8", newline="") as output:
            writer = csv.writer(output, lineterminator="\n")
            writer.writerow(CSV_COLUMNS)
            writer.writerows(rows)
        with (staging / "provenance.json").open("x", encoding="utf-8", newline="\n") as output:
            json.dump(manifest, output, indent=2, sort_keys=True)
            output.write("\n")
        staging.rename(destination)
    except OSError as error:
        raise CaptureError("unable to write output bundle") from error
    finally:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)


def _port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as error:
        raise argparse.ArgumentTypeError("port must be an integer") from error
    if not 1 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 1 and 65535")
    return port


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("capture", help="authorized classic Ethernet PCAP input")
    parser.add_argument("--output-dir", required=True, help="new directory for traces.csv and provenance.json")
    parser.add_argument("--observer-address", required=True, help="literal address assigned to the observed endpoint")
    parser.add_argument("--port", action="append", type=_port, required=True, help="remote TCP/UDP port to include; repeat as needed")
    parser.add_argument("--endpoint-port", type=_port, help="local socket port for direction on loopback captures")
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--label", choices=("control", "target"), required=True)
    parser.add_argument("--site-id", required=True, help="pseudonymous grouping identifier")
    parser.add_argument("--host-id", required=True, help="pseudonymous grouping identifier")
    parser.add_argument("--day-id", required=True, help="pseudonymous grouping identifier")
    parser.add_argument("--capture-id", required=True, help="non-sensitive identifier used to create session IDs")
    parser.add_argument("--idle-timeout-ms", type=int, default=60_000)
    args = parser.parse_args(argv)

    try:
        rows, manifest = parse_capture(
            args.capture,
            observer_address=args.observer_address,
            remote_ports=args.port,
            endpoint_port=args.endpoint_port,
            candidate=args.candidate,
            label=args.label,
            site_id=args.site_id,
            host_id=args.host_id,
            day_id=args.day_id,
            capture_id=args.capture_id,
            idle_timeout_ms=args.idle_timeout_ms,
        )
        write_capture_bundle(args.output_dir, rows, manifest)
    except CaptureError as error:
        print(f"capture conversion failed: {error}", file=sys.stderr)
        return 2

    print(json.dumps({
        "status": "converted",
        "output_dir": str(Path(args.output_dir).expanduser()),
        "selected_packet_count": len(rows),
        "session_count": manifest["session_count"],
        "capture_sha256": manifest["capture_sha256"],
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
