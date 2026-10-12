import csv
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import generate_synthetic_traces as generator
import traffic_detectability as evaluator


class SyntheticTraceGeneratorTests(unittest.TestCase):
    def test_output_is_deterministic_bounded_and_uses_evaluator_schema(self):
        with tempfile.TemporaryDirectory() as directory:
            first_path = Path(directory) / "first.csv"
            second_path = Path(directory) / "nested" / "second.csv"
            first_count = generator.write_synthetic_traces(first_path, groups=4, seed=19)
            second_count = generator.write_synthetic_traces(second_path, groups=4, seed=19)

            self.assertEqual(first_count, second_count)
            self.assertEqual(first_path.read_bytes(), second_path.read_bytes())
            with first_path.open(newline="", encoding="utf-8") as stream:
                reader = csv.DictReader(stream)
                rows = list(reader)

        self.assertEqual(tuple(reader.fieldnames), evaluator.CSV_COLUMNS)
        self.assertEqual(first_count, 4 * len(generator.CANDIDATES) * 4 * generator.PACKETS_PER_SESSION)
        self.assertEqual(len({(row["site_id"], row["host_id"], row["day_id"]) for row in rows}), 4)
        self.assertEqual({row["candidate"] for row in rows}, set(generator.CANDIDATES))
        self.assertEqual({row["label"] for row in rows}, {"target", "control"})
        self.assertLessEqual(first_count, evaluator.MAX_DATA_ROWS)

    def test_seed_and_group_bounds_are_enforced(self):
        with self.assertRaisesRegex(ValueError, "groups must"):
            generator.generate_rows(groups=generator.MAX_GROUPS + 1)
        with self.assertRaisesRegex(ValueError, "seed must"):
            generator.generate_rows(groups=3, seed=2**32)

    def test_maximum_group_count_stays_within_evaluator_session_limit(self):
        rows = generator.generate_rows(groups=generator.MAX_GROUPS, seed=11)
        session_ids = {(row[0], row[1], row[2]) for row in rows}

        self.assertLessEqual(len(session_ids), evaluator.MAX_SESSIONS)
        self.assertLessEqual(len(rows), evaluator.MAX_DATA_ROWS)


if __name__ == "__main__":
    unittest.main()
