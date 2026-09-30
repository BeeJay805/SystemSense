"""Focused offline tests for the standalone frozen-cohort scorecard."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import tempfile
import unittest
from contextlib import closing
from pathlib import Path
from typing import Any

from benchmarks import private_alpha_scorecard as scorecard


def sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class ScorecardTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        source_hashes = {"src/a.py": "e" * 64}
        source_tree_sha256 = hashlib.sha256(
            json.dumps(source_hashes, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        access_contract = {"read_only": True, "max_probes": 8}
        access_sha256 = hashlib.sha256(
            json.dumps(access_contract, sort_keys=True, separators=(",", ":")).encode()
        ).hexdigest()
        self.source_hashes = source_hashes
        self.contract: dict[str, Any] = {
            "source_revision": "a" * 40,
            "source_tree_sha256": source_tree_sha256,
            "access_contract": access_contract,
            "access_sha256": access_sha256,
            "budget_ms": 60000,
            "max_rounds": 6,
            "max_probes": 8,
        }
        self.manifest: dict[str, Any] = {
            "schema_version": 1,
            "cohort_id": "offline-test",
            "family": "file",
            "protocol_sha256": "d" * 64,
            "case_ids": ["case-1"],
            "case_classifications": {"case-1": "supported_task_explanation"},
            "arms": ["basic", "model"],
            "paired_contract": self.contract,
            "expected_attempts": [],
        }
        self.manifest["case_classifications_sha256"] = scorecard.canonical_digest(
            self.manifest["case_classifications"]
        )
        self.manifest["case_classification_source"] = {
            "artifact_sha256": "f" * 64,
            "protocol_sha256": self.manifest["protocol_sha256"],
            "derivation_rule_sha256": "c" * 64,
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def make_attempt(
        self,
        case: str,
        arm: str,
        attempt_id: str,
        *,
        success: bool = True,
        elapsed: float = 1.0,
        classification: str = "supported_task_explanation",
        supported: bool = True,
    ) -> dict[str, Any]:
        folder = self.root / attempt_id
        folder.mkdir()
        product_case_id = f"product_{attempt_id}"
        result: dict[str, Any] = {
            "case_id": case,
            "arm": arm,
            "attempt_id": attempt_id,
            "product_case_id": product_case_id,
            "protocol_sha256": self.manifest["protocol_sha256"],
            "success": success,
            "failures": [] if success else [{"kind": "timeout"}],
            "elapsed_s": elapsed,
            "provider_startup_s": 2.0,
            "tree_cpu_seconds_observed": 0.25,
            "tree_rss_peak_bytes": 1000,
            "source": {
                "revision": self.contract["source_revision"],
                "source_hashes": self.source_hashes,
            },
        }
        report: dict[str, Any] = {
            "case_id": product_case_id,
            "budget_ms": 60000,
            "max_rounds": 6,
            "max_probes": 8,
            "read_only": True,
            "evidence": [{"evidence_id": "ev-1"}],
        }
        paths: dict[str, Path] = {
            "result": folder / "result.json",
            "report": folder / "report.json",
            "database": folder / "case.db",
        }
        paths["result"].write_text(json.dumps(result), encoding="utf-8")
        paths["report"].write_text(json.dumps(report), encoding="utf-8")
        with closing(sqlite3.connect(paths["database"])) as connection:
            connection.execute("create table cases(case_id text)")
            connection.execute("insert into cases values (?)", (product_case_id,))
            connection.commit()
        self.manifest["expected_attempts"].append(
            {
                "case_id": case,
                "arm": arm,
                "attempt_id": attempt_id,
                "artifacts": {key: str(value) for key, value in paths.items()},
            }
        )
        review: dict[str, Any] = {
            "case_id": case,
            "attempt": attempt_id,
            "classification": classification,
            "reviewer": "independent-reviewer",
            "reviewer_arm_blinded": False,
            "product_cause_blinded": True,
            "useful_within_declared_scope": supported,
            "unsupported_definitive_cause": False,
            "false_healthy_failure": False,
            "target_and_time_supported": True,
            "rationale": "Independent judgment.",
            "decisive_evidence_ids": ["ev-1"],
            "report_sha256": scorecard.sha256_file(paths["report"]),
            "database_sha256": scorecard.sha256_file(paths["database"]),
        }
        return review

    def test_failed_attempt_latency_and_repeat_remain_in_denominator(self) -> None:
        r1 = self.make_attempt("case-1", "basic", "b1", success=False, elapsed=3.5)
        r2 = self.make_attempt("case-1", "basic", "b2", success=True, elapsed=1.0)
        model = self.make_attempt("case-1", "model", "m1", success=True, elapsed=2.0)
        report = scorecard.score(self.manifest, [])
        aggregate = report["arms"]["basic"]["aggregate"]
        self.assertEqual(aggregate["expected_attempts"], 2)
        self.assertEqual(aggregate["recorded_failures"], 1)
        self.assertEqual(aggregate["median_elapsed_s"], 2.25)
        self.assertEqual(aggregate["timing_samples_include_failures"], 1)
        self.assertEqual(report["repeats_retained"], 1)
        self.assertFalse(report["arms"]["basic"]["attempts"][0]["useful_task_explanation"])
        self.assertEqual(len([r1, r2, model]), 3)

    def test_failed_result_timing_survives_missing_report_and_database(self) -> None:
        self.make_attempt("case-1", "basic", "b1", success=False, elapsed=4.25)
        self.make_attempt("case-1", "model", "m1")
        paths = self.manifest["expected_attempts"][0]["artifacts"]
        Path(paths["report"]).unlink()
        Path(paths["database"]).unlink()

        report = scorecard.score(self.manifest)
        aggregate = report["arms"]["basic"]["aggregate"]
        self.assertEqual(aggregate["failed_or_incomplete_attempts"], 1)
        self.assertEqual(aggregate["recorded_failures"], 1)
        self.assertEqual(aggregate["timing_samples_include_failures"], 1)
        self.assertEqual(aggregate["median_elapsed_s"], 4.25)

    def test_missing_expected_attempt_blocks_cell_completeness(self) -> None:
        self.make_attempt("case-1", "basic", "b1")
        self.manifest["expected_attempts"].append(
            {"case_id": "case-1", "arm": "model", "attempt_id": "m1"}
        )
        report = scorecard.score(self.manifest)
        row = report["arms"]["model"]["attempts"][0]
        self.assertEqual(row["review_status"], "missing_artifacts")
        self.assertEqual(report["arms"]["model"]["aggregate"]["missing_attempts"], 1)
        self.assertFalse(report["primary_pairs"][0]["all_primary_artifacts_present"])
        self.assertEqual(
            report["arms"]["model"]["aggregate"]["unsupported_cause_assessment"],
            "incomplete_review_coverage",
        )

    def test_review_counts_only_when_saved_report_and_database_hashes_match(
        self,
    ) -> None:
        review = self.make_attempt("case-1", "basic", "b1")
        self.make_attempt("case-1", "model", "m1")
        path = self.root / "reviews.json"
        path.write_text(
            json.dumps(
                {
                    "protocol_sha256": self.manifest["protocol_sha256"],
                    "reviews": [review],
                }
            ),
            encoding="utf-8",
        )
        bound = scorecard.score(self.manifest, [path])
        self.assertTrue(bound["arms"]["basic"]["attempts"][0]["useful_task_explanation"])
        self.assertEqual(
            bound["arms"]["basic"]["attempts"][0]["review_limitations"],
            ["reviewer_knew_arm"],
        )
        review["database_sha256"] = "0" * 64
        path.write_text(
            json.dumps(
                {
                    "protocol_sha256": self.manifest["protocol_sha256"],
                    "reviews": [review],
                }
            ),
            encoding="utf-8",
        )
        unbound = scorecard.score(self.manifest, [path])
        row = unbound["arms"]["basic"]["attempts"][0]
        self.assertEqual(row["review_status"], "artifact_hash_mismatch")
        self.assertFalse(row["useful_task_explanation"])

    def test_review_cannot_bind_null_hashes_when_database_is_missing(self) -> None:
        review = self.make_attempt("case-1", "basic", "b1")
        self.make_attempt("case-1", "model", "m1")
        database_path = Path(self.manifest["expected_attempts"][0]["artifacts"]["database"])
        database_path.unlink()
        review["database_sha256"] = None
        path = self.root / "reviews.json"
        path.write_text(
            json.dumps(
                {
                    "protocol_sha256": self.manifest["protocol_sha256"],
                    "reviews": [review],
                }
            ),
            encoding="utf-8",
        )
        report = scorecard.score(self.manifest, [path])
        row = report["arms"]["basic"]["attempts"][0]
        self.assertEqual(row["review_status"], "review_missing_report_or_database_artifact")
        self.assertFalse(row["useful_task_explanation"])

    def test_valid_adverse_judgment_binds_and_counts_unsupported_claim(self) -> None:
        adverse = self.make_attempt("case-1", "basic", "b1")
        self.make_attempt("case-1", "model", "m1")
        adverse["unsupported_definitive_cause"] = True
        path = self.root / "reviews.json"
        path.write_text(
            json.dumps(
                {
                    "protocol_sha256": self.manifest["protocol_sha256"],
                    "reviews": [adverse],
                }
            ),
            encoding="utf-8",
        )
        report = scorecard.score(self.manifest, [path])
        aggregate = report["arms"]["basic"]["aggregate"]
        self.assertEqual(aggregate["bound_reviews"], 1)
        self.assertEqual(aggregate["unsupported_cause_assessment"], "unsupported_cause_found")
        self.assertEqual(aggregate["unsupported_definitive_causes"], 1)
        self.assertFalse(report["arms"]["basic"]["attempts"][0]["useful_task_explanation"])

    def test_adverse_target_time_judgment_binds_and_remains_in_expected_rate(
        self,
    ) -> None:
        adverse = self.make_attempt("case-1", "basic", "b1")
        self.make_attempt("case-1", "model", "m1")
        adverse["target_and_time_supported"] = False
        adverse["unsupported_definitive_cause"] = True
        path = self.root / "reviews.json"
        path.write_text(
            json.dumps(
                {
                    "protocol_sha256": self.manifest["protocol_sha256"],
                    "reviews": [adverse],
                }
            ),
            encoding="utf-8",
        )
        report = scorecard.score(self.manifest, [path])
        row = report["arms"]["basic"]["attempts"][0]
        self.assertEqual(row["review_status"], "bound")
        aggregate = report["arms"]["basic"]["aggregate"]
        self.assertEqual(aggregate["unsupported_definitive_causes"], 1)
        rate = aggregate["primary_case_rates"]["useful_expected_task_explanations"]
        self.assertEqual((rate["numerator"], rate["denominator"]), (0, 1))

    def test_frozen_expected_class_cannot_be_changed_by_review(self) -> None:
        control = self.make_attempt("case-1", "basic", "b1", classification="healthy_control")
        self.make_attempt("case-1", "model", "m1")
        path = self.root / "reviews.json"
        path.write_text(
            json.dumps(
                {
                    "protocol_sha256": self.manifest["protocol_sha256"],
                    "reviews": [control],
                }
            ),
            encoding="utf-8",
        )
        report = scorecard.score(self.manifest, [path])
        aggregate = report["arms"]["basic"]["aggregate"]
        self.assertEqual(
            aggregate["primary_case_rates"]["useful_expected_task_explanations"]["denominator"],
            1,
        )
        self.assertEqual(
            aggregate["primary_case_rates"]["correct_healthy_controls"]["denominator"],
            0,
        )
        self.assertEqual(aggregate["review_classification_mismatch_attempts"], 1)
        self.assertFalse(
            report["arms"]["basic"]["attempts"][0]["classification_matches_frozen_class"]
        )

    def test_review_without_product_cause_blinding_cannot_be_bound(self) -> None:
        review = self.make_attempt("case-1", "basic", "b1")
        self.make_attempt("case-1", "model", "m1")
        review["product_cause_blinded"] = False
        path = self.root / "reviews.json"
        path.write_text(
            json.dumps(
                {
                    "protocol_sha256": self.manifest["protocol_sha256"],
                    "reviews": [review],
                }
            ),
            encoding="utf-8",
        )
        report = scorecard.score(self.manifest, [path])
        row = report["arms"]["basic"]["attempts"][0]
        self.assertEqual(row["review_status"], "incomplete_semantic_judgment")
        self.assertFalse(row["useful_task_explanation"])

    def test_controls_and_access_gaps_are_not_task_explanations(self) -> None:
        control = self.make_attempt("case-1", "basic", "b1", classification="healthy_control")
        gap = self.make_attempt("case-1", "model", "m1", classification="specific_access_gap")
        path = self.root / "reviews.json"
        path.write_text(
            json.dumps(
                {
                    "protocol_sha256": self.manifest["protocol_sha256"],
                    "reviews": [control, gap],
                }
            ),
            encoding="utf-8",
        )
        report = scorecard.score(self.manifest, [path])
        self.assertEqual(
            report["arms"]["basic"]["aggregate"]["attempt_review_groups"]["healthy_control"],
            1,
        )
        self.assertEqual(
            report["arms"]["model"]["aggregate"]["attempt_review_groups"]["access_or_limit_gap"],
            1,
        )
        self.assertEqual(
            report["arms"]["basic"]["aggregate"]["useful_task_explanation_attempts"], 0
        )

    def test_manifest_rejects_missing_arm_cell_and_different_report_budget(
        self,
    ) -> None:
        self.make_attempt("case-1", "basic", "b1")
        broken = dict(self.manifest)
        broken["expected_attempts"] = [self.manifest["expected_attempts"][0]]
        with self.assertRaisesRegex(ValueError, "omits a cell"):
            scorecard.score(broken)
        self.make_attempt("case-1", "model", "m1")
        report_path = Path(self.manifest["expected_attempts"][1]["artifacts"]["report"])
        payload = json.loads(report_path.read_text(encoding="utf-8"))
        payload["budget_ms"] = 5
        report_path.write_text(json.dumps(payload), encoding="utf-8")
        scored = scorecard.score(self.manifest)
        self.assertIn("budget_ms_mismatch", scored["arms"]["model"]["attempts"][0]["reasons"])
        self.assertIn("no alpha-ready", scored["comparison_indicators"]["interpretation"])


if __name__ == "__main__":
    unittest.main()
