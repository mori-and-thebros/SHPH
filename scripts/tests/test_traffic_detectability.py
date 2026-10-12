import csv
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import traffic_detectability as evaluator


def write_csv(path, rows):
    with path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(evaluator.CSV_COLUMNS)
        writer.writerows(rows)


def packet_row(candidate, label, session, site, host, day, timestamp, direction, length):
    return [candidate, label, session, site, host, day, timestamp, direction, length]


class GroupSplitTests(unittest.TestCase):
    def test_group_assignment_is_deterministic_and_disjoint(self):
        groups = {(f"site-{index}", f"host-{index}", f"day-{index}") for index in range(30)}
        first = evaluator.split_group_ids(groups, 17)
        second = evaluator.split_group_ids(groups, 17)

        self.assertEqual(first, second)
        self.assertEqual(set(first), groups)
        self.assertEqual(set(first.values()), {"train", "calibration", "test"})
        self.assertEqual(len(first), len(set(first)))

    def test_all_sessions_sharing_site_host_day_stay_in_one_partition(self):
        shared = ("site-a", "host-a", "day-a")
        groups = {shared, ("site-b", "host-b", "day-b"), ("site-c", "host-c", "day-c")}
        assignment = evaluator.split_group_ids(groups, 3)
        paired_candidate_sessions = [
            evaluator.Observation("baseline", "target", shared, (0.0,) * len(evaluator.FEATURE_NAMES)),
            evaluator.Observation("variant", "target", shared, (0.0,) * len(evaluator.FEATURE_NAMES)),
        ]

        self.assertEqual(assignment[paired_candidate_sessions[0].group], assignment[paired_candidate_sessions[1].group])

    def test_requires_three_distinct_groups(self):
        with self.assertRaises(evaluator.EvaluationError):
            evaluator.split_group_ids({("site", "host", "day")}, 0)


class MetricTests(unittest.TestCase):
    def test_tied_scores_produce_half_auc_and_average_precision(self):
        metrics = evaluator.roc_pr_metrics([1, 0, 1, 0], [0.5, 0.5, 0.2, 0.2])

        self.assertAlmostEqual(metrics["roc_auc"], 0.5)
        self.assertAlmostEqual(metrics["pr_average_precision"], 0.5)
        self.assertEqual(metrics["roc_curve"]["fpr"], [0.0, 0.5, 1.0])

    def test_metrics_reject_one_class(self):
        with self.assertRaises(evaluator.EvaluationError):
            evaluator.roc_pr_metrics([1, 1], [0.8, 0.2])

    def test_threshold_is_selected_under_calibration_fpr_budget(self):
        threshold, true_positives, false_positives = evaluator.select_calibration_threshold(
            [1, 1, 0, 0], [0.9, 0.7, 0.8, 0.1], 0.5
        )

        self.assertEqual(threshold, 0.7)
        self.assertEqual(true_positives, 2)
        self.assertEqual(false_positives, 1)


class InputLimitTests(unittest.TestCase):
    def test_model_dimensions_and_runtime_are_capped(self):
        self.assertEqual(len(evaluator.FEATURE_NAMES), 82)
        self.assertLessEqual(evaluator.MAX_TRAINING_ITERATIONS, 200)
        self.assertLessEqual(evaluator.MAX_RUNTIME_SECONDS, 30)

    def test_sequence_features_distinguish_packet_order_with_same_size_multiset(self):
        first_order = evaluator.SessionAggregate("candidate", "target", ("site", "host", "day"))
        second_order = evaluator.SessionAggregate("candidate", "target", ("site", "host", "day"))
        first_sequence = ((0.0, "out", 100), (1.0, "in", 200), (2.0, "out", 300))
        second_sequence = ((0.0, "out", 300), (1.0, "in", 200), (2.0, "out", 100))
        for packet in first_sequence:
            first_order.add(*packet)
        for packet in second_sequence:
            second_order.add(*packet)

        first_features = first_order.features()
        second_features = second_order.features()
        self.assertEqual(len(first_features), len(evaluator.FEATURE_NAMES))
        self.assertEqual(len(second_features), len(evaluator.FEATURE_NAMES))
        self.assertNotEqual(first_features[len(evaluator.BASE_FEATURE_NAMES):], second_features[len(evaluator.BASE_FEATURE_NAMES):])

    def test_flow_blocking_simulation_reports_target_and_collateral_counts(self):
        simulation = evaluator._simulate_flow_blocking(
            0.05,
            0.7,
            {"true_positives": 3, "false_positives": 2, "true_negatives": 4, "false_negatives": 1},
            4,
            6,
        )

        self.assertEqual(simulation["blocked_target_sessions"], 3)
        self.assertEqual(simulation["allowed_target_sessions"], 1)
        self.assertEqual(simulation["collateral_blocked_control_sessions"], 2)
        self.assertAlmostEqual(simulation["target_block_rate"], 0.75)
        self.assertAlmostEqual(simulation["collateral_block_rate"], 1 / 3)
        self.assertEqual(simulation["network_side_effects"], "none; this is an offline decision simulation")

    def test_file_size_limit_is_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "traces.csv"
            path.write_text("not relevant", encoding="utf-8")
            with mock.patch.object(evaluator, "MAX_FILE_BYTES", 4):
                with self.assertRaisesRegex(evaluator.EvaluationError, "file limit"):
                    evaluator.load_dataset(path)

    def test_data_row_limit_is_enforced(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "traces.csv"
            rows = [
                packet_row("base", "target", "session", "site", "host", "day", 0, "out", 100),
                packet_row("base", "target", "session", "site", "host", "day", 1, "in", 100),
            ]
            write_csv(path, rows)
            with mock.patch.object(evaluator, "MAX_DATA_ROWS", 1):
                with self.assertRaisesRegex(evaluator.EvaluationError, "row limit"):
                    evaluator.load_dataset(path)

    def test_session_ids_may_repeat_across_candidates_and_capture_groups(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "traces.csv"
            write_csv(
                path,
                [
                    packet_row("baseline", "target", "session-1", "site-a", "host-a", "day-a", 0, "out", 100),
                    packet_row("variant", "target", "session-1", "site-b", "host-b", "day-b", 0, "out", 120),
                ],
            )

            dataset = evaluator.load_dataset(path)

        self.assertEqual(len(dataset.observations), 2)
        self.assertEqual(len(dataset.groups), 2)

    def test_multiple_capture_csvs_share_one_validated_dataset(self):
        with tempfile.TemporaryDirectory() as directory:
            baseline = Path(directory) / "baseline.csv"
            variant = Path(directory) / "variant.csv"
            write_csv(
                baseline,
                [packet_row("baseline", "target", "capture-a-000001", "site-a", "host-a", "day-a", 0, "out", 100)],
            )
            write_csv(
                variant,
                [packet_row("variant", "target", "capture-b-000001", "site-b", "host-b", "day-b", 0, "out", 120)],
            )
            dataset = evaluator.load_dataset([baseline, variant])

        self.assertEqual(dataset.candidates, ("baseline", "variant"))
        self.assertEqual(len(dataset.observations), 2)
        self.assertEqual(len(dataset.groups), 2)
        self.assertEqual(dataset.data_rows, 2)

    def test_combined_file_and_row_limits_apply_across_capture_csvs(self):
        with tempfile.TemporaryDirectory() as directory:
            first = Path(directory) / "first.csv"
            second = Path(directory) / "second.csv"
            row = packet_row("base", "target", "session", "site", "host", "day", 0, "out", 100)
            write_csv(first, [row])
            write_csv(second, [row])
            per_file_bytes = first.stat().st_size
            with mock.patch.object(evaluator, "MAX_FILE_BYTES", per_file_bytes):
                with self.assertRaisesRegex(evaluator.EvaluationError, "input set exceeds.*file limit"):
                    evaluator.load_dataset([first, second])
            with mock.patch.object(evaluator, "MAX_DATA_ROWS", 1):
                with self.assertRaisesRegex(evaluator.EvaluationError, "row limit"):
                    evaluator.load_dataset([first, second])

    def test_input_rejects_nonmonotonic_session_timestamps(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "traces.csv"
            write_csv(
                path,
                [
                    packet_row("base", "target", "session", "site", "host", "day", 1, "out", 100),
                    packet_row("base", "target", "session", "site", "host", "day", 0, "in", 100),
                ],
            )
            with self.assertRaisesRegex(evaluator.EvaluationError, "nondecreasing"):
                evaluator.load_dataset(path)


class SmallSampleTests(unittest.TestCase):
    def test_sparse_dataset_is_reported_as_insufficient_data(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "traces.csv"
            rows = []
            for index in range(2):
                rows.append(
                    packet_row("base", "target", f"target-{index}", f"site-{index}", f"host-{index}", f"day-{index}", 0, "out", 100)
                )
                rows.append(
                    packet_row("base", "control", f"control-{index}", f"site-{index}", f"host-{index}", f"day-{index}", 0, "in", 120)
                )
            write_csv(path, rows)
            report = evaluator.evaluate_dataset(evaluator.load_dataset(path), seed=2)

        self.assertEqual(report["status"], "insufficient_data")
        self.assertEqual(report["results"][0]["status"], "insufficient_data")
        self.assertIn("fewer_than_3_distinct_site_host_day_groups", report["results"][0]["sample_warnings"])

    def test_evaluated_small_sample_has_explicit_warnings(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "traces.csv"
            rows = []
            for index in range(3):
                site, host, day = f"site-{index}", f"host-{index}", f"day-{index}"
                rows.append(packet_row("base", "target", f"target-{index}", site, host, day, 0, "out", 100))
                rows.append(packet_row("base", "control", f"control-{index}", site, host, day, 0, "in", 120))
            write_csv(path, rows)
            report = evaluator.evaluate_dataset(evaluator.load_dataset(path), seed=1)

        candidate = report["results"][0]
        self.assertEqual(candidate["status"], "evaluated_with_sample_warnings")
        self.assertTrue(candidate["sample_warnings"])
        self.assertEqual(candidate["metrics"]["uncertainty"]["status"], "insufficient_groups")
        self.assertIn("not evidence of censorship resistance", report["disclaimer"])

    def test_group_bootstrap_emits_intervals_when_group_count_allows(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "traces.csv"
            rows = []
            for index in range(25):
                site, host, day = f"site-{index}", f"host-{index}", f"day-{index}"
                rows.append(packet_row("base", "target", f"target-{index}", site, host, day, 0, "out", 100 + index))
                rows.append(packet_row("base", "control", f"control-{index}", site, host, day, 0, "in", 120 + index))
            write_csv(path, rows)
            report = evaluator.evaluate_dataset(evaluator.load_dataset(path), seed=1)

        uncertainty = report["results"][0]["metrics"]["uncertainty"]
        self.assertEqual(uncertainty["status"], "available")
        self.assertEqual(uncertainty["replicates_valid"], evaluator.BOOTSTRAP_REPLICATES)
        self.assertIsNotNone(uncertainty["intervals_95"]["roc_auc"])


if __name__ == "__main__":
    unittest.main()
