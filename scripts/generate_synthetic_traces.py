#!/usr/bin/env python3
"""Generate deterministic synthetic traces for evaluator smoke tests only."""

from __future__ import annotations

import argparse
import csv
import json
import random
from pathlib import Path
from typing import Sequence

from traffic_detectability import CSV_COLUMNS, MAX_DATA_ROWS, MAX_SESSIONS


PACKETS_PER_SESSION = 12
BACKGROUND_SESSIONS_PER_CLASS = 3
CANDIDATES = ("baseline", "variant")
SESSIONS_PER_GROUP = len(CANDIDATES) * (BACKGROUND_SESSIONS_PER_CLASS + 1)
ROWS_PER_GROUP = SESSIONS_PER_GROUP * PACKETS_PER_SESSION
MAX_GROUPS = min(
    400,
    MAX_DATA_ROWS // ROWS_PER_GROUP,
    MAX_SESSIONS // SESSIONS_PER_GROUP,
)
BACKGROUND_SIZES = (64, 80, 96, 128, 192, 256, 384, 512, 768, 1024, 1200, 1400)
BASELINE_PATTERN = (
    ("out", 80, 0.035),
    ("in", 1340, 0.090),
    ("in", 128, 0.018),
    ("out", 512, 0.130),
    ("in", 96, 0.022),
    ("out", 768, 0.180),
    ("in", 1280, 0.075),
    ("in", 88, 0.025),
    ("out", 256, 0.110),
    ("in", 112, 0.030),
    ("out", 640, 0.160),
    ("in", 96, 0.040),
)


def _background_sequence(
    generator: random.Random, size_scale: float, gap_scale: float
) -> list[tuple[float, str, int]]:
    sequence = []
    timestamp = 0.0
    prior_direction = "in"
    for _ in range(PACKETS_PER_SESSION):
        if generator.random() < 0.62:
            direction = "out" if prior_direction == "in" else "in"
        else:
            direction = generator.choice(("out", "in"))
        length = max(40, min(1500, round(generator.choice(BACKGROUND_SIZES) * size_scale)))
        interarrival = max(0.002, min(1.5, generator.expovariate(5.0) * gap_scale))
        timestamp += interarrival
        sequence.append((timestamp, direction, length))
        prior_direction = direction
    return sequence


def _baseline_sequence(
    generator: random.Random, size_scale: float, gap_scale: float
) -> list[tuple[float, str, int]]:
    sequence = []
    timestamp = 0.0
    for direction, base_length, base_interarrival in BASELINE_PATTERN:
        length = max(40, min(1500, round(base_length * size_scale * generator.uniform(0.94, 1.06))))
        interarrival = base_interarrival * gap_scale * generator.uniform(0.90, 1.10)
        timestamp += interarrival
        sequence.append((timestamp, direction, length))
    return sequence


def generate_rows(groups: int = 180, seed: int = 7) -> list[tuple[object, ...]]:
    if not 3 <= groups <= MAX_GROUPS:
        raise ValueError(f"groups must be between 3 and {MAX_GROUPS}")
    if not 0 <= seed <= 2**32 - 1:
        raise ValueError("seed must be between 0 and 4294967295")
    generator = random.Random(seed)
    rows: list[tuple[object, ...]] = []
    for group_index in range(groups):
        site_id = f"synthetic-site-{group_index:04d}"
        host_id = f"synthetic-host-{group_index:04d}"
        day_id = f"synthetic-day-{group_index:04d}"
        group_rng = random.Random(generator.getrandbits(64))
        size_scale = group_rng.uniform(0.90, 1.10)
        gap_scale = group_rng.uniform(0.80, 1.20)
        for candidate in CANDIDATES:
            for label, replicas in (("target", 1), ("control", BACKGROUND_SESSIONS_PER_CLASS)):
                for replica in range(replicas):
                    session_id = f"{candidate}-{label}-{group_index:04d}-{replica}"
                    session_rng = random.Random(generator.getrandbits(64))
                    if candidate == "baseline" and label == "target":
                        sequence = _baseline_sequence(session_rng, size_scale, gap_scale)
                    else:
                        sequence = _background_sequence(session_rng, size_scale, gap_scale)
                    for timestamp, direction, length in sequence:
                        rows.append(
                            (
                                candidate,
                                label,
                                session_id,
                                site_id,
                                host_id,
                                day_id,
                                f"{timestamp:.6f}",
                                direction,
                                length,
                            )
                        )
    return rows


def write_synthetic_traces(path: str | Path, groups: int = 180, seed: int = 7) -> int:
    rows = generate_rows(groups, seed)
    output_path = Path(path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream, lineterminator="\n")
        writer.writerow(CSV_COLUMNS)
        writer.writerows(rows)
    return len(rows)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("output_csv", type=Path)
    parser.add_argument("--groups", type=int, default=180)
    parser.add_argument("--seed", type=int, default=7)
    args = parser.parse_args(argv)
    if not 3 <= args.groups <= MAX_GROUPS:
        parser.error(f"--groups must be between 3 and {MAX_GROUPS}")
    if not 0 <= args.seed <= 2**32 - 1:
        parser.error("--seed must be between 0 and 4294967295")
    row_count = write_synthetic_traces(args.output_csv, args.groups, args.seed)
    print(
        json.dumps(
            {
                "status": "created",
                "dataset_kind": "synthetic_only_not_captured_traffic",
                "output_csv": str(args.output_csv),
                "groups": args.groups,
                "candidates": list(CANDIDATES),
                "packet_rows": row_count,
                "seed": args.seed,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
