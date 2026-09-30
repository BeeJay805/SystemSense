"""Focused tests for raw saved-run family adapters."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from typing import Any

from benchmarks import private_alpha_raw_adapters as adapters

# These tests deliberately exercise adapter boundaries with malformed saved artifacts.
# pyright: reportPrivateUsage=false


class RawAdapterTests(unittest.TestCase):
    def test_explicit_failed_restoration_is_not_overridden_by_cleanup_fallback(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as temp:
            case = Path(temp) / "attempt"
            case.mkdir()
            (case / "result-index.json").write_text(
                json.dumps({"case_id": "case-a", "status": "complete"})
            )
            (case / "product-case.json").write_text(
                json.dumps(
                    {
                        "case_id": "product-a",
                        "status": "complete",
                        "read_only": True,
                        "evidence": [],
                    }
                )
            )
            (case / "runtime.json").write_text(json.dumps({"elapsed_ms": 10}))
            (case / "cases.db").touch()
            evaluator = case / "evaluator"
            evaluator.mkdir()
            (evaluator / "restored.json").write_text(json.dumps({"verified": False}))
            (evaluator / "cleanup.json").write_text(
                json.dumps({"owned_helpers_exited": True, "restored_before_cleanup": True})
            )
            row = adapters._mechanics("case-a", case, case_key="case_id")
            self.assertFalse(row["restoration_verified"])
            self.assertTrue(row["cleanup_verified"])

    def test_result_index_completion_requires_complete_product_report(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            case = Path(temp) / "attempt"
            case.mkdir()
            (case / "result-index.json").write_text(
                json.dumps({"case_id": "case-a", "status": "complete"})
            )
            (case / "product-case.json").write_text(
                json.dumps({"case_id": "product-a", "status": "failed"})
            )
            (case / "runtime.json").write_text(json.dumps({"elapsed_ms": 25}))
            (case / "cases.db").touch()
            row = adapters._mechanics("case-a", case, case_key="case_id")
            self.assertFalse(row["completed"])
            self.assertTrue(row["failure_recorded"])
            self.assertEqual(row["elapsed_ms"], 25)

    def test_timing_from_failed_attempt_stays_in_percentiles(self) -> None:
        rows: list[dict[str, Any]] = [
            {
                "completed": False,
                "failure_recorded": True,
                "present": True,
                "restoration_verified": False,
                "cleanup_verified": True,
                "elapsed_ms": 2000.0,
                "tree_cpu_seconds_observed": 0.4,
                "tree_rss_peak_bytes": 100,
                "laya_receipts": 0,
                "sol_receipts": 0,
                "review": {"status": "missing"},
            },
            {
                "completed": False,
                "failure_recorded": True,
                "present": False,
                "restoration_verified": None,
                "cleanup_verified": None,
                "elapsed_ms": None,
                "tree_cpu_seconds_observed": None,
                "tree_rss_peak_bytes": None,
                "laya_receipts": 0,
                "sol_receipts": 0,
                "review": {"status": "missing"},
            },
        ]
        summary = adapters._arm_summary(rows, None)
        self.assertEqual(summary["recorded_failures"], 2)
        self.assertEqual(summary["missing_timing"], 1)
        self.assertEqual(summary["median_elapsed_s"], 2.0)
        self.assertEqual(summary["max_elapsed_s"], 2.0)

    def test_review_join_requires_saved_report_and_database_hashes(self) -> None:
        row: dict[str, Any] = {
            "attempt_id": "attempt-a",
            "artifact_hashes": {"report_sha256": "a" * 64, "database_sha256": "b" * 64},
            "completed_probe_ids": ["task.sample"],
            "observed_probe_ids": ["task.sample"],
        }
        review: dict[str, Any] = {
            "attempt": "attempt-a",
            "report_sha256": "a" * 64,
            "database_sha256": "0" * 64,
            "outcome": "supported_explanation",
            "judgment": "bounded finding",
        }
        adapters._join_reviews([row], [review], attempt_key="attempt")
        self.assertEqual(row["review"]["status"], "artifact_hash_mismatch")
        self.assertEqual(row["review"]["outcome"], "supported_explanation")

    def test_review_cannot_bind_null_artifact_hashes(self) -> None:
        row: dict[str, Any] = {
            "attempt_id": "attempt-a",
            "artifact_hashes": {"report_sha256": None, "database_sha256": None},
        }
        review: dict[str, Any] = {
            "attempt": "attempt-a",
            "report_sha256": None,
            "database_sha256": None,
            "outcome": "supported_explanation",
        }
        adapters._join_reviews([row], [review], attempt_key="attempt")
        self.assertEqual(row["review"]["status"], "review_missing_report_or_database_artifact")


if __name__ == "__main__":
    unittest.main()
