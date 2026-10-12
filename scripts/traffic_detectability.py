#!/usr/bin/env python3
"""Offline experimental detectability and flow-blocking baseline.

Usage::

    python3 scripts/traffic_detectability.py baseline.csv variant.csv --seed 7

The input is a UTF-8 CSV with this exact header and column order::

    candidate,label,session_id,site_id,host_id,day_id,timestamp_s,direction,length_bytes

Each data row describes one packet from an authorized trace. ``candidate`` is
the baseline or variant name; ``label`` is ``target`` or ``control``;
timestamps are nondecreasing seconds relative to the start of that session;
direction is ``out`` or ``in`` from the observed endpoint's perspective; and
length is the observed packet length in bytes. ``session_id`` identifies a
trace within a candidate. The site, host, and day identifiers are used only to
keep related traces in the same split and are not emitted in the report.

The evaluator accepts one or more schema-matched CSVs, subject to shared file,
row, candidate, session, and runtime limits. It holds out site/host/day groups
and extracts bounded opening-sequence
and coarse whole-session timing/size features, fits a regularized
logistic-regression baseline, and chooses operating thresholds on calibration
data for fixed 1%, 5%, and 10% false-positive targets. Each threshold also
reports a hypothetical flow-level block decision on the held-out test split.
It uses only the Python standard library and never opens a network connection
or reads packet-capture formats.

The block simulation does not alter packets or routes. This is a simple
experimental baseline, not evidence of censorship resistance. Results depend
on trace collection and grouping quality; use only authorized traces and
interpret sample warnings and group-bootstrap intervals cautiously.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import math
import random
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable, Sequence


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
LABELS = ("control", "target")
FPR_TARGETS = (0.01, 0.05, 0.10)
BASE_FEATURE_NAMES = (
    "log_packets",
    "log_duration_s",
    "log_total_bytes",
    "log_out_packets",
    "log_in_packets",
    "log_out_bytes",
    "log_in_bytes",
    "mean_packet_bytes",
    "std_packet_bytes",
    "mean_interarrival_s",
    "std_interarrival_s",
    "max_interarrival_s",
    "out_packet_fraction",
    "out_byte_fraction",
)
MAX_SEQUENCE_PREFIX_PACKETS = 12
WHOLE_SESSION_TIME_BINS = 8
FEATURE_NAMES = BASE_FEATURE_NAMES + tuple(
    f"prefix_{packet_index:02d}_{feature_name}"
    for packet_index in range(MAX_SEQUENCE_PREFIX_PACKETS)
    for feature_name in ("direction", "log_packet_bytes", "log_interarrival_s")
) + tuple(
    f"timeline_{bin_index:02d}_{feature_name}"
    for bin_index in range(WHOLE_SESSION_TIME_BINS)
    for feature_name in ("log_packets", "out_packet_fraction", "mean_log_packet_bytes", "mean_log_interarrival_s")
)

MAX_FILE_BYTES = 16 * 1024 * 1024
MAX_INPUT_FILES = 256
MAX_DATA_ROWS = 40_000
MAX_SESSIONS = 3_000
MAX_CANDIDATES = 5
MAX_IDENTIFIER_CHARS = 128
MAX_CANDIDATE_CHARS = 48
MAX_PACKET_LENGTH = 1_000_000
MAX_TIMESTAMP_SECONDS = 1_000_000_000_000.0
MAX_TRAINING_ITERATIONS = 160
BOOTSTRAP_REPLICATES = 200
MAX_RUNTIME_SECONDS = 20.0
MIN_RECOMMENDED_SESSIONS_PER_SPLIT_CLASS = 20
MIN_RECOMMENDED_GROUPS_PER_SPLIT_CLASS = 5
MIN_CONTROL_SESSIONS_FOR_ONE_PERCENT = 100
MIN_TEST_TARGET_SESSIONS = 30


class EvaluationError(Exception):
    """Input or configured-resource-limit error safe to show in the CLI."""


GroupKey = tuple[str, str, str]


@dataclass
class SessionAggregate:
    candidate: str
    label: str
    group: GroupKey
    packet_count: int = 0
    out_packets: int = 0
    in_packets: int = 0
    total_bytes: int = 0
    out_bytes: int = 0
    in_bytes: int = 0
    first_timestamp: float = 0.0
    last_timestamp: float = 0.0
    size_mean: float = 0.0
    size_m2: float = 0.0
    gap_count: int = 0
    gap_mean: float = 0.0
    gap_m2: float = 0.0
    max_gap: float = 0.0
    sequence: list[tuple[float, str, int]] = field(default_factory=list)

    def add(self, timestamp: float, direction: str, length: int) -> None:
        if self.packet_count and timestamp < self.last_timestamp:
            raise EvaluationError("packet timestamps must be nondecreasing within each session")

        if self.packet_count == 0:
            self.first_timestamp = timestamp
        else:
            gap = timestamp - self.last_timestamp
            self.gap_count += 1
            gap_delta = gap - self.gap_mean
            self.gap_mean += gap_delta / self.gap_count
            self.gap_m2 += gap_delta * (gap - self.gap_mean)
            self.max_gap = max(self.max_gap, gap)

        self.packet_count += 1
        size_delta = length - self.size_mean
        self.size_mean += size_delta / self.packet_count
        self.size_m2 += size_delta * (length - self.size_mean)
        self.total_bytes += length
        if direction == "out":
            self.out_packets += 1
            self.out_bytes += length
        else:
            self.in_packets += 1
            self.in_bytes += length
        self.last_timestamp = timestamp
        self.sequence.append((timestamp, direction, length))

    def features(self) -> tuple[float, ...]:
        if self.packet_count == 0:
            raise EvaluationError("empty sessions are not valid")
        packet_std = math.sqrt(self.size_m2 / self.packet_count)
        gap_std = math.sqrt(self.gap_m2 / self.gap_count) if self.gap_count else 0.0
        duration = self.last_timestamp - self.first_timestamp
        base_features = (
            math.log1p(self.packet_count),
            math.log1p(duration),
            math.log1p(self.total_bytes),
            math.log1p(self.out_packets),
            math.log1p(self.in_packets),
            math.log1p(self.out_bytes),
            math.log1p(self.in_bytes),
            self.size_mean,
            packet_std,
            self.gap_mean,
            gap_std,
            self.max_gap,
            self.out_packets / self.packet_count,
            self.out_bytes / self.total_bytes if self.total_bytes else 0.0,
        )
        prefix_features: list[float] = []
        for packet_index in range(MAX_SEQUENCE_PREFIX_PACKETS):
            if packet_index >= len(self.sequence):
                prefix_features.extend((0.0, 0.0, 0.0))
                continue
            timestamp, direction, length = self.sequence[packet_index]
            interarrival = (
                timestamp - self.sequence[packet_index - 1][0]
                if packet_index
                else 0.0
            )
            prefix_features.extend(
                (
                    1.0 if direction == "out" else -1.0,
                    math.log1p(length),
                    math.log1p(interarrival),
                )
            )

        timeline = [[0, 0, 0.0, 0.0, 0] for _ in range(WHOLE_SESSION_TIME_BINS)]
        duration = self.last_timestamp - self.first_timestamp
        for packet_index, (timestamp, direction, length) in enumerate(self.sequence):
            elapsed_fraction = (timestamp - self.first_timestamp) / duration if duration else 0.0
            bin_index = min(int(elapsed_fraction * WHOLE_SESSION_TIME_BINS), WHOLE_SESSION_TIME_BINS - 1)
            bin_stats = timeline[bin_index]
            bin_stats[0] += 1
            bin_stats[1] += int(direction == "out")
            bin_stats[2] += math.log1p(length)
            if packet_index:
                interarrival = timestamp - self.sequence[packet_index - 1][0]
                bin_stats[3] += math.log1p(interarrival)
                bin_stats[4] += 1

        timeline_features: list[float] = []
        for packet_count, out_packets, log_packet_bytes, log_interarrivals, gap_count in timeline:
            if not packet_count:
                timeline_features.extend((0.0, 0.0, 0.0, 0.0))
                continue
            timeline_features.extend(
                (
                    math.log1p(packet_count),
                    out_packets / packet_count,
                    log_packet_bytes / packet_count,
                    log_interarrivals / gap_count if gap_count else 0.0,
                )
            )
        features = base_features + tuple(prefix_features) + tuple(timeline_features)
        if len(features) != len(FEATURE_NAMES):
            raise EvaluationError("internal feature-count mismatch")
        return features


@dataclass(frozen=True)
class Observation:
    candidate: str
    label: str
    group: GroupKey
    features: tuple[float, ...]


@dataclass(frozen=True)
class Dataset:
    observations: tuple[Observation, ...]
    candidates: tuple[str, ...]
    groups: frozenset[GroupKey]
    data_rows: int


def _check_deadline(deadline: float) -> None:
    if time.monotonic() > deadline:
        raise EvaluationError(f"configured {MAX_RUNTIME_SECONDS:.0f}-second runtime limit exceeded")


def _required_text(value: str, name: str, max_chars: int) -> str:
    value = value.strip()
    if not value:
        raise EvaluationError(f"{name} must not be empty")
    if len(value) > max_chars:
        raise EvaluationError(f"{name} exceeds the {max_chars}-character limit")
    return value


def load_dataset(path: str | Path | Sequence[str | Path], deadline: float | None = None) -> Dataset:
    """Read bounded CSV files of per-packet authorized trace summaries."""
    started = time.monotonic()
    deadline = deadline if deadline is not None else started + MAX_RUNTIME_SECONDS
    input_paths = [path] if isinstance(path, (str, Path)) else list(path)
    if not input_paths:
        raise EvaluationError("at least one input CSV is required")
    if len(input_paths) > MAX_INPUT_FILES:
        raise EvaluationError(f"input exceeds the {MAX_INPUT_FILES}-file limit")

    combined = io.StringIO(newline="")
    combined_writer = csv.writer(combined, lineterminator="\n")
    total_bytes = 0
    for input_index, value in enumerate(input_paths):
        input_path = Path(value)
        try:
            if not input_path.is_file():
                raise EvaluationError("input must be a regular local CSV file")
            with input_path.open("rb") as stream:
                raw = stream.read(MAX_FILE_BYTES - total_bytes + 1)
        except OSError as exc:
            raise EvaluationError(f"cannot read input file: {exc.strerror or 'I/O error'}") from exc
        total_bytes += len(raw)
        if total_bytes > MAX_FILE_BYTES:
            raise EvaluationError(f"input set exceeds the {MAX_FILE_BYTES}-byte file limit")
        try:
            text = raw.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise EvaluationError("input must be valid UTF-8 CSV") from exc

        reader = csv.reader(io.StringIO(text, newline=""), strict=True)
        try:
            header = next(reader)
        except StopIteration as exc:
            raise EvaluationError("input CSV is empty") from exc
        except csv.Error as exc:
            raise EvaluationError("input CSV has a malformed header") from exc
        if tuple(header) != CSV_COLUMNS:
            raise EvaluationError("CSV header must exactly match the documented schema and column order")
        if input_index == 0:
            combined_writer.writerow(header)
        try:
            for row in reader:
                combined_writer.writerow(row)
        except csv.Error as exc:
            raise EvaluationError("input CSV contains a malformed row") from exc
        _check_deadline(deadline)

    aggregates: dict[tuple[str, str, str], SessionAggregate] = {}
    session_labels: dict[tuple[str, str], str] = {}
    session_groups: dict[tuple[str, str], GroupKey] = {}
    candidates: set[str] = set()
    row_count = 0
    first_row = True
    try:
        for row in csv.reader(io.StringIO(combined.getvalue(), newline=""), strict=True):
            if first_row:
                first_row = False
                continue
            row_count += 1
            if row_count > MAX_DATA_ROWS:
                raise EvaluationError(f"input exceeds the {MAX_DATA_ROWS}-row limit")
            if row_count % 256 == 0:
                _check_deadline(deadline)
            if len(row) != len(CSV_COLUMNS):
                raise EvaluationError(f"CSV data row {row_count} must have exactly {len(CSV_COLUMNS)} fields")

            values = dict(zip(CSV_COLUMNS, row))
            candidate = _required_text(values["candidate"], "candidate", MAX_CANDIDATE_CHARS)
            label = _required_text(values["label"], "label", 16)
            if label not in LABELS:
                raise EvaluationError("label must be exactly 'target' or 'control'")
            session_id = _required_text(values["session_id"], "session_id", MAX_IDENTIFIER_CHARS)
            site_id = _required_text(values["site_id"], "site_id", MAX_IDENTIFIER_CHARS)
            host_id = _required_text(values["host_id"], "host_id", MAX_IDENTIFIER_CHARS)
            day_id = _required_text(values["day_id"], "day_id", MAX_IDENTIFIER_CHARS)
            group = (site_id, host_id, day_id)
            direction = _required_text(values["direction"], "direction", 8)
            if direction not in ("out", "in"):
                raise EvaluationError("direction must be exactly 'out' or 'in'")

            try:
                timestamp = float(values["timestamp_s"])
                length = int(values["length_bytes"])
            except ValueError as exc:
                raise EvaluationError("timestamp_s must be numeric and length_bytes must be an integer") from exc
            if not math.isfinite(timestamp) or timestamp < 0 or timestamp > MAX_TIMESTAMP_SECONDS:
                raise EvaluationError("timestamp_s must be finite and within the configured range")
            if length <= 0 or length > MAX_PACKET_LENGTH:
                raise EvaluationError(f"length_bytes must be between 1 and {MAX_PACKET_LENGTH}")

            candidate_session = (candidate, session_id)
            prior_label = session_labels.setdefault(candidate_session, label)
            if prior_label != label:
                raise EvaluationError("a candidate session cannot have multiple labels")
            prior_group = session_groups.setdefault(candidate_session, group)
            if prior_group != group:
                raise EvaluationError("a session_id must retain the same site_id, host_id, and day_id")

            candidates.add(candidate)
            if len(candidates) > MAX_CANDIDATES:
                raise EvaluationError(f"input exceeds the {MAX_CANDIDATES}-candidate limit")
            key = (candidate, label, session_id)
            aggregate = aggregates.get(key)
            if aggregate is None:
                if len(aggregates) >= MAX_SESSIONS:
                    raise EvaluationError(f"input exceeds the {MAX_SESSIONS}-session limit")
                aggregate = SessionAggregate(candidate=candidate, label=label, group=group)
                aggregates[key] = aggregate
            aggregate.add(timestamp, direction, length)
    except csv.Error as exc:
        raise EvaluationError("input CSV contains a malformed row") from exc
    _check_deadline(deadline)
    if not aggregates:
        raise EvaluationError("input CSV contains no packet rows")

    observations = tuple(
        Observation(aggregate.candidate, aggregate.label, aggregate.group, aggregate.features())
        for aggregate in aggregates.values()
    )
    return Dataset(
        observations=observations,
        candidates=tuple(sorted(candidates)),
        groups=frozenset(observation.group for observation in observations),
        data_rows=row_count,
    )


def split_group_ids(groups: Iterable[GroupKey], seed: int) -> dict[GroupKey, str]:
    """Assign complete site/host/day groups to train, calibration, or test."""
    ordered_groups = sorted(set(groups))
    if len(ordered_groups) < 3:
        raise EvaluationError("at least three distinct site/host/day groups are required for held-out splits")
    random.Random(seed).shuffle(ordered_groups)
    train_count = min(len(ordered_groups) - 2, max(1, int(len(ordered_groups) * 0.60)))
    calibration_count = min(
        len(ordered_groups) - train_count - 1,
        max(1, int(len(ordered_groups) * 0.20)),
    )
    assignments: dict[GroupKey, str] = {}
    for index, group in enumerate(ordered_groups):
        if index < train_count:
            assignments[group] = "train"
        elif index < train_count + calibration_count:
            assignments[group] = "calibration"
        else:
            assignments[group] = "test"
    return assignments


def _standardize(
    training: Sequence[Observation], records: Sequence[Observation]
) -> tuple[list[list[float]], list[list[float]]]:
    feature_count = len(FEATURE_NAMES)
    if any(len(record.features) != feature_count for record in (*training, *records)):
        raise EvaluationError("internal feature-count mismatch")
    means = [sum(record.features[index] for record in training) / len(training) for index in range(feature_count)]
    scales: list[float] = []
    for index, mean in enumerate(means):
        variance = sum((record.features[index] - mean) ** 2 for record in training) / len(training)
        scales.append(math.sqrt(variance) or 1.0)

    def transform(source: Sequence[Observation]) -> list[list[float]]:
        return [
            [(record.features[index] - means[index]) / scales[index] for index in range(feature_count)]
            for record in source
        ]

    return transform(training), transform(records)


def _fit_logistic(
    features: Sequence[Sequence[float]], labels: Sequence[int], deadline: float
) -> tuple[list[float], float]:
    if not features or len(features) != len(labels) or len(features[0]) != len(FEATURE_NAMES):
        raise EvaluationError("training data is empty or malformed")
    weights = [0.0] * len(FEATURE_NAMES)
    bias = 0.0
    learning_rate = 0.12
    regularization = 0.01
    for _ in range(MAX_TRAINING_ITERATIONS):
        _check_deadline(deadline)
        gradients = [regularization * weight for weight in weights]
        bias_gradient = 0.0
        for row, label in zip(features, labels):
            linear = bias + sum(weight * value for weight, value in zip(weights, row))
            probability = 1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, linear))))
            error = probability - label
            bias_gradient += error
            for index, value in enumerate(row):
                gradients[index] += error * value
        factor = learning_rate / len(features)
        weights = [weight - factor * gradient for weight, gradient in zip(weights, gradients)]
        bias -= factor * bias_gradient
    return weights, bias


def _predict(features: Sequence[Sequence[float]], model: tuple[Sequence[float], float]) -> list[float]:
    weights, bias = model
    scores = []
    for row in features:
        linear = bias + sum(weight * value for weight, value in zip(weights, row))
        scores.append(1.0 / (1.0 + math.exp(-max(-30.0, min(30.0, linear)))))
    return scores


def roc_pr_metrics(labels: Sequence[int], scores: Sequence[float]) -> dict[str, object]:
    """Return tie-aware ROC/PR curves, ROC AUC, and average precision."""
    if len(labels) != len(scores) or not labels:
        raise EvaluationError("metric inputs must be nonempty and equal in length")
    if any(label not in (0, 1) for label in labels):
        raise EvaluationError("metric labels must be binary")
    positives = sum(labels)
    negatives = len(labels) - positives
    if positives == 0 or negatives == 0:
        raise EvaluationError("ROC and PR metrics require both target and control examples")
    if any(not math.isfinite(score) for score in scores):
        raise EvaluationError("metric scores must be finite")

    ranked = sorted(zip(scores, labels), key=lambda item: item[0], reverse=True)
    roc_fpr = [0.0]
    roc_tpr = [0.0]
    pr_recall = [0.0]
    pr_precision = [1.0]
    true_positives = 0
    false_positives = 0
    average_precision = 0.0
    index = 0
    while index < len(ranked):
        score = ranked[index][0]
        while index < len(ranked) and ranked[index][0] == score:
            if ranked[index][1] == 1:
                true_positives += 1
            else:
                false_positives += 1
            index += 1
        recall = true_positives / positives
        precision = true_positives / (true_positives + false_positives)
        pr_recall.append(recall)
        pr_precision.append(precision)
        average_precision += (recall - pr_recall[-2]) * precision
        roc_tpr.append(recall)
        roc_fpr.append(false_positives / negatives)

    roc_auc = sum(
        (roc_fpr[index] - roc_fpr[index - 1]) * (roc_tpr[index] + roc_tpr[index - 1]) / 2.0
        for index in range(1, len(roc_fpr))
    )
    return {
        "roc_auc": roc_auc,
        "pr_average_precision": average_precision,
        "roc_curve": {"fpr": roc_fpr, "tpr": roc_tpr},
        "pr_curve": {"recall": pr_recall, "precision": pr_precision},
    }


def select_calibration_threshold(
    labels: Sequence[int], scores: Sequence[float], target_fpr: float
) -> tuple[float | None, int, int]:
    """Choose the highest calibration TPR within the predeclared FPR budget."""
    if len(labels) != len(scores) or not labels or not 0 < target_fpr < 1:
        raise EvaluationError("threshold selection requires data and an FPR target between zero and one")
    negatives = sum(label == 0 for label in labels)
    if negatives == 0 or sum(labels) == 0:
        raise EvaluationError("threshold calibration requires both target and control examples")
    allowed_false_positives = math.floor(target_fpr * negatives)
    ranked = sorted(zip(scores, labels), key=lambda item: item[0], reverse=True)
    best_threshold: float | None = None
    best_true_positives = 0
    best_false_positives = 0
    true_positives = 0
    false_positives = 0
    index = 0
    while index < len(ranked):
        threshold = ranked[index][0]
        while index < len(ranked) and ranked[index][0] == threshold:
            if ranked[index][1] == 1:
                true_positives += 1
            else:
                false_positives += 1
            index += 1
        if false_positives <= allowed_false_positives and true_positives > best_true_positives:
            best_threshold = threshold
            best_true_positives = true_positives
            best_false_positives = false_positives
    return best_threshold, best_true_positives, best_false_positives


def _threshold_counts(labels: Sequence[int], scores: Sequence[float], threshold: float | None) -> dict[str, int]:
    predicted = [threshold is not None and score >= threshold for score in scores]
    return {
        "true_positives": sum(label == 1 and prediction for label, prediction in zip(labels, predicted)),
        "false_positives": sum(label == 0 and prediction for label, prediction in zip(labels, predicted)),
        "true_negatives": sum(label == 0 and not prediction for label, prediction in zip(labels, predicted)),
        "false_negatives": sum(label == 1 and not prediction for label, prediction in zip(labels, predicted)),
    }


def _simulate_flow_blocking(
    target_fpr: float,
    threshold: float | None,
    test_counts: dict[str, int],
    target_sessions: int,
    control_sessions: int,
) -> dict[str, object]:
    return {
        "decision_unit": "complete_session",
        "policy": "block_session_when_score_at_or_above_calibrated_threshold",
        "target_fpr_budget": target_fpr,
        "threshold": threshold,
        "threshold_source": "calibration_split",
        "evaluation_split": "held_out_test",
        "target_sessions": target_sessions,
        "blocked_target_sessions": test_counts["true_positives"],
        "allowed_target_sessions": test_counts["false_negatives"],
        "target_block_rate": test_counts["true_positives"] / target_sessions,
        "control_sessions": control_sessions,
        "collateral_blocked_control_sessions": test_counts["false_positives"],
        "allowed_control_sessions": test_counts["true_negatives"],
        "collateral_block_rate": test_counts["false_positives"] / control_sessions,
        "network_side_effects": "none; this is an offline decision simulation",
    }


def _quantile_interval(values: Sequence[float]) -> list[float] | None:
    if len(values) < BOOTSTRAP_REPLICATES // 2:
        return None
    ordered = sorted(values)

    def quantile(probability: float) -> float:
        position = (len(ordered) - 1) * probability
        lower = int(position)
        upper = min(lower + 1, len(ordered) - 1)
        fraction = position - lower
        return ordered[lower] * (1.0 - fraction) + ordered[upper] * fraction

    return [quantile(0.025), quantile(0.975)]


def _group_bootstrap(
    records: Sequence[Observation],
    scores: Sequence[float],
    thresholds: Sequence[float | None],
    seed: int,
    deadline: float,
) -> dict[str, object]:
    by_group: dict[GroupKey, list[tuple[int, float]]] = {}
    for record, score in zip(records, scores):
        by_group.setdefault(record.group, []).append((int(record.label == "target"), score))
    group_keys = sorted(by_group)
    metric_names = ["roc_auc", "pr_average_precision"]
    metric_names.extend(f"fpr_at_{target:g}" for target in FPR_TARGETS)
    metric_names.extend(f"tpr_at_{target:g}" for target in FPR_TARGETS)
    values: dict[str, list[float]] = {name: [] for name in metric_names}
    if len(group_keys) < MIN_RECOMMENDED_GROUPS_PER_SPLIT_CLASS:
        return {
            "method": "site_host_day_group_percentile_bootstrap",
            "replicates_requested": BOOTSTRAP_REPLICATES,
            "replicates_valid": 0,
            "groups": len(group_keys),
            "intervals_95": {name: None for name in metric_names},
            "status": "insufficient_groups",
        }

    rng = random.Random(seed)
    for _ in range(BOOTSTRAP_REPLICATES):
        _check_deadline(deadline)
        selected = [rng.choice(group_keys) for _ in group_keys]
        sample = [row for group in selected for row in by_group[group]]
        labels = [item[0] for item in sample]
        sample_scores = [item[1] for item in sample]
        if not any(labels) or all(labels):
            continue
        metrics = roc_pr_metrics(labels, sample_scores)
        values["roc_auc"].append(float(metrics["roc_auc"]))
        values["pr_average_precision"].append(float(metrics["pr_average_precision"]))
        for target, threshold in zip(FPR_TARGETS, thresholds):
            counts = _threshold_counts(labels, sample_scores, threshold)
            positive_count = sum(labels)
            negative_count = len(labels) - positive_count
            values[f"fpr_at_{target:g}"].append(counts["false_positives"] / negative_count)
            values[f"tpr_at_{target:g}"].append(counts["true_positives"] / positive_count)
    return {
        "method": "site_host_day_group_percentile_bootstrap",
        "replicates_requested": BOOTSTRAP_REPLICATES,
        "replicates_valid": min((len(items) for items in values.values()), default=0),
        "groups": len(group_keys),
        "intervals_95": {name: _quantile_interval(items) for name, items in values.items()},
        "status": "available" if all(_quantile_interval(items) is not None for items in values.values()) else "unstable",
    }


def _class_counts(records: Sequence[Observation], groups: set[GroupKey]) -> dict[str, dict[str, int]]:
    result: dict[str, dict[str, int]] = {}
    for label in LABELS:
        matching = [record for record in records if record.label == label]
        result[label] = {
            "sessions": len(matching),
            "groups": len({record.group for record in matching} & groups),
        }
    return result


def _sample_warnings(split_counts: dict[str, dict[str, dict[str, int]]]) -> list[str]:
    warnings: list[str] = []
    for split_name, classes in split_counts.items():
        for label in LABELS:
            counts = classes[label]
            if counts["sessions"] < MIN_RECOMMENDED_SESSIONS_PER_SPLIT_CLASS:
                warnings.append(
                    f"{split_name}_{label}_sessions_below_{MIN_RECOMMENDED_SESSIONS_PER_SPLIT_CLASS}"
                )
            if counts["groups"] < MIN_RECOMMENDED_GROUPS_PER_SPLIT_CLASS:
                warnings.append(
                    f"{split_name}_{label}_groups_below_{MIN_RECOMMENDED_GROUPS_PER_SPLIT_CLASS}"
                )
    if split_counts["calibration"]["control"]["sessions"] < MIN_CONTROL_SESSIONS_FOR_ONE_PERCENT:
        warnings.append("calibration_control_sessions_below_100_for_1pct_target")
    if split_counts["test"]["control"]["sessions"] < MIN_CONTROL_SESSIONS_FOR_ONE_PERCENT:
        warnings.append("test_control_sessions_below_100_for_1pct_target")
    if split_counts["test"]["target"]["sessions"] < MIN_TEST_TARGET_SESSIONS:
        warnings.append(f"test_target_sessions_below_{MIN_TEST_TARGET_SESSIONS}")
    return warnings


def _evaluate_candidate(
    candidate: str,
    records: Sequence[Observation],
    assignments: dict[GroupKey, str],
    seed: int,
    deadline: float,
) -> dict[str, object]:
    candidate_records = [record for record in records if record.candidate == candidate]
    partitions = {
        name: [record for record in candidate_records if assignments.get(record.group) == name]
        for name in ("train", "calibration", "test")
    }
    split_counts = {
        split_name: _class_counts(split_records, {record.group for record in split_records})
        for split_name, split_records in partitions.items()
    }
    warnings = _sample_warnings(split_counts)
    result: dict[str, object] = {
        "candidate": candidate,
        "status": "insufficient_data",
        "counts": split_counts,
        "sample_warnings": warnings,
        "metrics": None,
    }
    missing_classes = [
        f"{split_name}_{label}"
        for split_name, classes in split_counts.items()
        for label in LABELS
        if classes[label]["sessions"] == 0
    ]
    if missing_classes:
        result["insufficient_reason"] = "missing required classes in: " + ", ".join(missing_classes)
        return result

    training = partitions["train"]
    calibration = partitions["calibration"]
    testing = partitions["test"]
    train_features, calibration_features = _standardize(training, calibration)
    _, test_features = _standardize(training, testing)
    train_labels = [int(record.label == "target") for record in training]
    calibration_labels = [int(record.label == "target") for record in calibration]
    test_labels = [int(record.label == "target") for record in testing]
    model = _fit_logistic(train_features, train_labels, deadline)
    calibration_scores = _predict(calibration_features, model)
    test_scores = _predict(test_features, model)

    operating_points: list[dict[str, object]] = []
    thresholds: list[float | None] = []
    for target_fpr in FPR_TARGETS:
        threshold, calibration_tp, calibration_fp = select_calibration_threshold(
            calibration_labels, calibration_scores, target_fpr
        )
        thresholds.append(threshold)
        calibration_positive_count = sum(calibration_labels)
        calibration_negative_count = len(calibration_labels) - calibration_positive_count
        test_counts = _threshold_counts(test_labels, test_scores, threshold)
        test_positive_count = sum(test_labels)
        test_negative_count = len(test_labels) - test_positive_count
        support_warnings = []
        resolution_count = math.ceil(1.0 / target_fpr)
        if calibration_negative_count < resolution_count:
            support_warnings.append(f"calibration_controls_below_{resolution_count}")
        if test_negative_count < resolution_count:
            support_warnings.append(f"test_controls_below_{resolution_count}")
        operating_points.append(
            {
                "target_fpr": target_fpr,
                "threshold": threshold,
                "calibration": {
                    "target_sessions": calibration_positive_count,
                    "control_sessions": calibration_negative_count,
                    "true_positive_rate": calibration_tp / calibration_positive_count,
                    "false_positive_rate": calibration_fp / calibration_negative_count,
                },
                "test": {
                    "target_sessions": test_positive_count,
                    "control_sessions": test_negative_count,
                    "true_positive_rate": test_counts["true_positives"] / test_positive_count,
                    "false_positive_rate": test_counts["false_positives"] / test_negative_count,
                    **test_counts,
                },
                "simulated_blocking": _simulate_flow_blocking(
                    target_fpr,
                    threshold,
                    test_counts,
                    test_positive_count,
                    test_negative_count,
                ),
                "sample_warnings": support_warnings,
            }
        )

    curve_metrics = roc_pr_metrics(test_labels, test_scores)
    candidate_seed = (seed + sum((index + 1) * byte for index, byte in enumerate(candidate.encode("utf-8")))) % (2**32)
    uncertainty = _group_bootstrap(testing, test_scores, thresholds, candidate_seed, deadline)
    result["status"] = "evaluated_with_sample_warnings" if warnings else "evaluated"
    result["metrics"] = {
        **curve_metrics,
        "test_sessions": len(testing),
        "operating_points": operating_points,
        "uncertainty": uncertainty,
        "uncertainty_note": "Group-bootstrap intervals condition on thresholds selected from calibration data.",
    }
    return result


def evaluate_dataset(dataset: Dataset, seed: int = 0, deadline: float | None = None) -> dict[str, object]:
    """Evaluate each candidate with grouped train/calibration/test partitions."""
    if not 0 <= seed <= 2**32 - 1:
        raise EvaluationError("seed must be between 0 and 4294967295")
    deadline = deadline if deadline is not None else time.monotonic() + MAX_RUNTIME_SECONDS
    group_counts = {name: 0 for name in ("train", "calibration", "test")}
    if len(dataset.groups) < 3:
        results = []
        for candidate in dataset.candidates:
            candidate_records = [record for record in dataset.observations if record.candidate == candidate]
            results.append(
                {
                    "candidate": candidate,
                    "status": "insufficient_data",
                    "counts": {"all": _class_counts(candidate_records, set(dataset.groups))},
                    "sample_warnings": ["fewer_than_3_distinct_site_host_day_groups"],
                    "insufficient_reason": "at least three site/host/day groups are required",
                    "metrics": None,
                }
            )
        return {
            "schema_version": 2,
            "status": "insufficient_data",
            "disclaimer": "Simple experimental baseline only; not evidence of censorship resistance.",
            "method": {
                "split_group": ["site_id", "host_id", "day_id"],
                "seed": seed,
                "classifier": "standard-library regularized logistic regression",
                "feature_count": len(FEATURE_NAMES),
                "feature_extraction": {
                    "global_session_summaries": len(BASE_FEATURE_NAMES),
                    "ordered_opening_packets": MAX_SEQUENCE_PREFIX_PACKETS,
                    "whole_session_time_bins": WHOLE_SESSION_TIME_BINS,
                },
                "blocking_simulation": "not performed because held-out splits lack both classes",
            },
            "counts": {
                "packet_rows": dataset.data_rows,
                "sessions": len(dataset.observations),
                "groups": len(dataset.groups),
                "candidates": len(dataset.candidates),
                "split_groups": group_counts,
            },
            "results": results,
        }

    assignments = split_group_ids(dataset.groups, seed)
    for partition in assignments.values():
        group_counts[partition] += 1
    results = [
        _evaluate_candidate(candidate, dataset.observations, assignments, seed, deadline)
        for candidate in dataset.candidates
    ]
    return {
        "schema_version": 2,
        "status": "complete" if all(result["status"] == "evaluated" for result in results) else "partial",
        "disclaimer": "Simple experimental baseline only; not evidence of censorship resistance.",
        "method": {
            "split_group": ["site_id", "host_id", "day_id"],
            "split_proportions_approximate": {"train": 0.60, "calibration": 0.20, "test": 0.20},
            "seed": seed,
            "classifier": "standard-library regularized logistic regression",
            "feature_extraction": {
                "global_session_summaries": len(BASE_FEATURE_NAMES),
                "ordered_opening_packets": MAX_SEQUENCE_PREFIX_PACKETS,
                "whole_session_time_bins": WHOLE_SESSION_TIME_BINS,
                "features_per_opening_packet": 3,
                "features_per_time_bin": 4,
            },
            "feature_count": len(FEATURE_NAMES),
            "feature_names": list(FEATURE_NAMES),
            "predeclared_false_positive_targets": list(FPR_TARGETS),
            "threshold_selection": "maximum calibration true-positive rate within each empirical FPR target",
            "blocking_simulation": "offline flow-level decisions on held-out sessions; no packet or route changes",
        },
        "limits": {
            "max_file_bytes": MAX_FILE_BYTES,
            "max_data_rows": MAX_DATA_ROWS,
            "max_sessions": MAX_SESSIONS,
            "max_candidates": MAX_CANDIDATES,
            "max_training_iterations": MAX_TRAINING_ITERATIONS,
            "bootstrap_replicates": BOOTSTRAP_REPLICATES,
            "max_runtime_seconds": MAX_RUNTIME_SECONDS,
        },
        "counts": {
            "packet_rows": dataset.data_rows,
            "sessions": len(dataset.observations),
            "groups": len(dataset.groups),
            "candidates": len(dataset.candidates),
            "split_groups": group_counts,
        },
        "results": results,
    }


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input_csv", nargs="+", help="one or more local CSVs of authorized per-packet trace summaries")
    parser.add_argument("--seed", type=int, default=0, help="deterministic group-split seed (0..4294967295)")
    args = parser.parse_args(argv)
    deadline = time.monotonic() + MAX_RUNTIME_SECONDS
    try:
        dataset = load_dataset(args.input_csv, deadline)
        report = evaluate_dataset(dataset, args.seed, deadline)
    except EvaluationError as exc:
        parser.exit(2, f"error: {exc}\n")
    print(json.dumps(report, indent=2, sort_keys=True, allow_nan=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
