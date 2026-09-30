"""Builder tests for fixed missing cells and observed extra attempts."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from benchmarks import build_file_holdout_manifest as builder


class ManifestBuilderTests(unittest.TestCase):
    def test_primary_attempt_uses_start_time_not_uuid_and_keeps_unknown_failure_first(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for suffix, started in (
                ("aaa", "2026-09-30T02:00:00+00:00"),
                ("zzz", "2026-09-30T01:00:00+00:00"),
            ):
                child = root / f"case-a-model-{suffix}"
                child.mkdir()
                (child / "result.json").write_text(
                    json.dumps({"started_at": started}), encoding="utf-8"
                )
            rows = builder.plan_attempts(["case-a"], "model", [root])
            self.assertEqual(rows[0]["attempt_id"], "case-a-model-zzz")
            (root / "case-a-model-unknown").mkdir()
            rows = builder.plan_attempts(["case-a"], "model", [root])
            self.assertEqual(rows[0]["attempt_id"], "case-a-model-unknown")

    def test_plan_retains_missing_expected_repeats_and_extra_attempts(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "repeat-01"
            root.mkdir()
            (root / "case-a-model-run1").mkdir()
            (root / "case-a-model-run2").mkdir()
            (root / "case-a-model-run3").mkdir()

            second_root = Path(temporary) / "repeat-02"
            second_root.mkdir()
            rows = builder.plan_attempts(["case-a", "case-b"], "model", [root, second_root])

        self.assertEqual(len(rows), 6)
        self.assertEqual(
            [row["attempt_id"] for row in rows],
            [
                "case-a-model-run1",
                "case-a-model-run2",
                "case-a-model-run3",
                "missing-repeat-01-model-case-b",
                "missing-repeat-02-model-case-a",
                "missing-repeat-02-model-case-b",
            ],
        )
        self.assertNotIn("artifacts", rows[4])
        self.assertIn("artifacts", rows[2])

    def test_unassignable_directory_fails_instead_of_disappearing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "not-a-frozen-case").mkdir()
            with self.assertRaisesRegex(ValueError, "unassignable"):
                builder.plan_attempts(["case-a"], "model", [root])


if __name__ == "__main__":
    unittest.main()
