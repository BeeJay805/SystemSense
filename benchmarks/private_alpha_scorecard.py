"""Offline scorecard for explicitly frozen private-alpha cohorts.

This module reads only the artifact paths named in a cohort manifest. It does not
run product code, discover attempts, or infer semantic quality from product prose.
Review rows count only when their report and database SHA-256 values match the
saved artifacts for that exact attempt. The output is descriptive and never
asserts alpha readiness.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sqlite3
import statistics
from collections.abc import Callable
from contextlib import closing
from pathlib import Path
from typing import Any, cast

_SCHEMA_VERSION = 1
_REVIEW_CLASSIFICATIONS = {
    "healthy_control",
    "specific_access_gap",
    "specific_limit_gap",
    "supported_task_explanation",
}
_EXPECTED_CLASSES = _REVIEW_CLASSIFICATIONS


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _load_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"expected JSON object: {path}")
    return cast(dict[str, Any], value)


def _positive_contract(value: object) -> bool:
    return type(value) is int and value > 0


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def source_tree_digest(source_hashes: object) -> str | None:
    if not isinstance(source_hashes, dict) or not source_hashes:
        return None
    source_hash_map = cast(dict[object, object], source_hashes)
    if any(
        not isinstance(path, str) or not _is_sha256(digest)
        for path, digest in source_hash_map.items()
    ):
        return None
    encoded = json.dumps(source_hashes, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def canonical_digest(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _finite_nonnegative(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    number = float(value)
    return number if math.isfinite(number) and number >= 0 else None


def _validate_manifest(
    manifest: dict[str, Any],
) -> tuple[list[str], list[str], list[dict[str, Any]]]:
    if manifest.get("schema_version") != _SCHEMA_VERSION:
        raise ValueError("unsupported manifest schema_version")
    if not str(manifest.get("cohort_id", "")).strip():
        raise ValueError("cohort_id is required")
    if not str(manifest.get("family", "")).strip():
        raise ValueError("family is required")
    if not _is_sha256(manifest.get("protocol_sha256")):
        raise ValueError("protocol_sha256 must be a lowercase SHA-256")
    cases_value, arms_value = manifest.get("case_ids"), manifest.get("arms")
    if not isinstance(cases_value, list) or not cases_value:
        raise ValueError("case_ids must be a nonempty unique list")
    case_values = cast(list[object], cases_value)
    if any(not isinstance(item, str) or not item for item in case_values):
        raise ValueError("case_ids must be a nonempty unique list")
    cases = cast(list[str], case_values)
    if len(set(cases)) != len(cases):
        raise ValueError("case_ids must be a nonempty unique list")
    expected_classes = manifest.get("case_classifications")
    if not isinstance(expected_classes, dict):
        raise TypeError("case_classifications must be an object")
    classes_object = cast(dict[object, object], expected_classes)
    if set(classes_object) != set(cases) or any(
        not isinstance(value, str) or value not in _EXPECTED_CLASSES
        for value in classes_object.values()
    ):
        raise ValueError("case_classifications must freeze one known expected class per case")
    expected_classes = cast(dict[str, str], expected_classes)
    if manifest.get("case_classifications_sha256") != canonical_digest(expected_classes):
        raise ValueError("case classification freeze digest differs")
    class_source = manifest.get("case_classification_source")
    if not isinstance(class_source, dict):
        raise TypeError("case_classification_source must be an object")
    class_source = cast(dict[str, Any], class_source)
    if (
        not _is_sha256(class_source.get("artifact_sha256"))
        or class_source.get("protocol_sha256") != manifest.get("protocol_sha256")
        or not _is_sha256(class_source.get("derivation_rule_sha256"))
    ):
        raise ValueError("case_classification_source must bind the frozen source and derivation")
    if not isinstance(arms_value, list):
        raise TypeError("arms must be a list")
    arm_values = cast(list[object], arms_value)
    if len(arm_values) < 2 or any(not isinstance(item, str) or not item for item in arm_values):
        raise ValueError("arms must be a unique list containing at least two arms")
    arms = cast(list[str], arm_values)
    if len(set(arms)) != len(arms):
        raise ValueError("arms must be a unique list containing at least two arms")
    contract = manifest.get("paired_contract")
    if not isinstance(contract, dict):
        raise TypeError("paired_contract must be an object")
    contract = cast(dict[str, Any], contract)
    if (
        not _is_sha256(contract.get("source_tree_sha256"))
        or not _is_sha256(contract.get("access_sha256"))
        or not isinstance(contract.get("access_contract"), dict)
        or not all(
            _positive_contract(contract.get(name))
            for name in ("budget_ms", "max_rounds", "max_probes")
        )
    ):
        raise ValueError("paired_contract requires source/access hashes and positive budgets")
    if (
        canonical_digest(cast(dict[str, Any], contract["access_contract"]))
        != contract["access_sha256"]
    ):
        raise ValueError("access contract digest does not match its frozen contents")
    expected = manifest.get("expected_attempts")
    if not isinstance(expected, list) or not expected:
        raise ValueError("expected_attempts must explicitly define the denominator")
    expected_values = cast(list[object], expected)
    if any(not isinstance(item, dict) for item in expected_values):
        raise ValueError("each expected attempt must be an object")
    expected = cast(list[dict[str, Any]], expected_values)
    ids: set[str] = set()
    cells: set[tuple[str, str, str]] = set()
    for attempt in expected:
        case_id_value, arm_value, attempt_id = (
            attempt.get("case_id"),
            attempt.get("arm"),
            attempt.get("attempt_id"),
        )
        if (
            not isinstance(case_id_value, str)
            or case_id_value not in cases
            or not isinstance(arm_value, str)
            or arm_value not in arms
            or not isinstance(attempt_id, str)
            or not attempt_id
        ):
            raise ValueError("attempt references an unplanned case/arm or lacks attempt_id")
        case_id, arm = case_id_value, arm_value
        cell = (case_id, arm, attempt_id)
        if cell in cells or attempt_id in ids:
            raise ValueError("attempt_id must be unique; preserve repeats with distinct IDs")
        cells.add(cell)
        ids.add(attempt_id)
        artifacts = attempt.get("artifacts")
        if artifacts is not None:
            if not isinstance(artifacts, dict):
                raise ValueError("artifacts must be an object")
            artifacts = cast(dict[str, Any], artifacts)
            if any(
                not isinstance(artifacts.get(key), str) for key in ("result", "report", "database")
            ) or ("failure" in artifacts and not isinstance(artifacts["failure"], str)):
                raise ValueError(
                    "artifacts must name result, report, and database paths; failure is optional"
                )
    for case_id in cases:
        for arm in arms:
            if not any(row.get("case_id") == case_id and row.get("arm") == arm for row in expected):
                raise ValueError(f"frozen denominator omits a cell: {case_id}/{arm}")
    return cases, arms, expected


def _attempt_record(
    attempt: dict[str, Any],
    protocol_sha256: str,
    contract: dict[str, Any],
    expected_class: str,
) -> dict[str, Any]:
    attempt_id = attempt["attempt_id"]
    record: dict[str, Any] = {
        "case_id": attempt["case_id"],
        "expected_classification": expected_class,
        "arm": attempt["arm"],
        "attempt_id": attempt_id,
        "present": False,
        "success": False,
        "failure_recorded": False,
        "review_status": "missing_artifacts",
        "classification": None,
        "useful_task_explanation": False,
        "unsupported_definitive_cause": None,
        "false_healthy_failure": None,
        "reviewer_arm_blinded": None,
        "review_limitations": [],
        "elapsed_s": None,
        "timing_includes_failure": False,
        "cold_start_s": None,
        "cpu_seconds_observed": None,
        "peak_sampled_rss_bytes": None,
        "report_sha256": None,
        "database_sha256": None,
        "reasons": [],
    }
    paths = attempt.get("artifacts")
    if paths is None:
        record["reasons"].append("no_artifact_paths_declared")
        return record
    result_path, report_path, database_path = (
        Path(paths[k]) for k in ("result", "report", "database")
    )
    failure_path = Path(paths["failure"]) if paths.get("failure") else None
    result = _load_json(result_path) if result_path.is_file() else None
    report = _load_json(report_path) if report_path.is_file() else None
    failure = (
        _load_json(failure_path) if failure_path is not None and failure_path.is_file() else None
    )
    record["present"] = any(
        path is not None and path.is_file()
        for path in (result_path, report_path, database_path, failure_path)
    )
    record["success"] = result is not None and result.get("success") is True
    record["failure_recorded"] = (
        bool(result and result.get("failures"))
        or (result is not None and result.get("success") is False)
        or failure is not None
    )
    if not record["present"]:
        record["reasons"].append("one_or_more_artifacts_missing")
        return record
    if result is None:
        record["reasons"].append("result_artifact_missing")
    else:
        if result.get("attempt_id") != attempt_id:
            record["reasons"].append("attempt_id_mismatch")
        if result.get("case_id") != attempt["case_id"] or result.get("arm") != attempt["arm"]:
            record["reasons"].append("result_case_or_arm_mismatch")
        if result.get("protocol_sha256") != protocol_sha256:
            record["reasons"].append("protocol_digest_mismatch")
        source = result.get("source")
        if (
            not isinstance(source, dict)
            or cast(dict[str, Any], source).get("revision") != contract.get("source_revision")
            or source_tree_digest(cast(dict[str, Any], source).get("source_hashes"))
            != contract["source_tree_sha256"]
        ):
            record["reasons"].append("source_revision_or_tree_mismatch")
        record["cold_start_s"] = _finite_nonnegative(result.get("provider_startup_s"))
        record["cpu_seconds_observed"] = _finite_nonnegative(
            result.get("tree_cpu_seconds_observed")
        )
        record["peak_sampled_rss_bytes"] = _finite_nonnegative(result.get("tree_rss_peak_bytes"))
    elapsed = _finite_nonnegative(result.get("warm_elapsed_s")) if result is not None else None
    if elapsed is None and result is not None:
        # Whole-attempt duration is retained for successes and recorded failures.
        elapsed = _finite_nonnegative(result.get("elapsed_s"))
    if elapsed is None and failure is not None:
        failure_ms = _finite_nonnegative(failure.get("elapsed_ms"))
        elapsed = None if failure_ms is None else failure_ms / 1000
    record["elapsed_s"] = elapsed
    record["timing_includes_failure"] = record["failure_recorded"] and elapsed is not None
    if report is None:
        record["reasons"].append("report_artifact_missing")
    else:
        record["report_sha256"] = sha256_file(report_path)
        if result is None or report.get("case_id") != result.get("product_case_id"):
            record["reasons"].append("report_product_case_identity_mismatch")
        if report.get("budget_ms") != contract["budget_ms"]:
            record["reasons"].append("budget_ms_mismatch")
        if report.get("max_rounds") != contract["max_rounds"]:
            record["reasons"].append("max_rounds_mismatch")
        if report.get("max_probes") != contract["max_probes"]:
            record["reasons"].append("max_probes_mismatch")
        if report.get("read_only") is not True:
            record["reasons"].append("read_only_contract_not_verified")
        evidence_value = report.get("evidence")
        evidence_items = (
            cast(list[object], evidence_value) if isinstance(evidence_value, list) else []
        )
        record["evidence_ids"] = sorted(
            str(cast(dict[str, Any], item).get("evidence_id"))
            for item in evidence_items
            if isinstance(item, dict) and cast(dict[str, Any], item).get("evidence_id")
        )
    if not database_path.is_file():
        record["reasons"].append("database_artifact_missing")
    else:
        record["database_sha256"] = sha256_file(database_path)
        try:
            uri = database_path.resolve().as_uri() + "?mode=ro"
            with closing(sqlite3.connect(uri, uri=True)) as connection:
                db_case_ids = [row[0] for row in connection.execute("SELECT case_id FROM cases")]
            if result is None or db_case_ids != [result.get("product_case_id")]:
                record["reasons"].append("database_product_case_identity_mismatch")
        except sqlite3.Error:
            record["reasons"].append("database_case_identity_unavailable")
    return record


def _read_reviews(path: Path, protocol_sha256: str) -> list[dict[str, Any]]:
    artifact = _load_json(path)
    if artifact.get("protocol_sha256") != protocol_sha256:
        raise ValueError("review protocol digest differs from selected cohort")
    reviews = artifact.get("reviews")
    if not isinstance(reviews, list):
        raise TypeError("reviews must be a list")
    review_rows = cast(list[object], reviews)
    if any(not isinstance(review, dict) for review in review_rows):
        raise ValueError("each semantic review must be an object")
    return cast(list[dict[str, Any]], review_rows)


def _bind_reviews(records: list[dict[str, Any]], reviews: list[dict[str, Any]]) -> None:
    by_attempt = {record["attempt_id"]: record for record in records}
    seen: set[str] = set()
    for review in reviews:
        attempt_id_value = review.get("attempt")
        if not isinstance(attempt_id_value, str):
            raise TypeError("review attempt ID must be a string")
        attempt_id = attempt_id_value
        record = by_attempt.get(attempt_id)
        if record is None or attempt_id in seen:
            raise ValueError("review references an unknown or repeated attempt")
        seen.add(attempt_id)
        if not record["present"]:
            record["review_status"] = "review_without_saved_artifacts"
            continue
        if not _is_sha256(record.get("report_sha256")) or not _is_sha256(
            record.get("database_sha256")
        ):
            record["review_status"] = "review_missing_report_or_database_artifact"
            continue
        if review.get("case_id") != record["case_id"]:
            record["review_status"] = "attempt_case_mismatch"
            record["reasons"].append("review_case_id_mismatch")
            continue
        expected = {
            "report_sha256": record["report_sha256"],
            "database_sha256": record["database_sha256"],
        }
        if any(review.get(key) != value for key, value in expected.items()):
            record["review_status"] = "artifact_hash_mismatch"
            record["reasons"].append("semantic_review_not_bound_to_saved_artifacts")
            continue
        classification = review.get("classification")
        if classification not in _REVIEW_CLASSIFICATIONS:
            record["review_status"] = "invalid_classification"
            continue
        evidence_ids = set(cast(list[str], record.get("evidence_ids", [])))
        cited = review.get("decisive_evidence_ids")
        cited_ids: set[str] = set()
        if isinstance(cited, list):
            cited_items = cast(list[object], cited)
            if all(isinstance(item, str) for item in cited_items):
                cited_ids = set(cast(list[str], cited_items))
        complete_judgment = (
            bool(str(review.get("reviewer", "")).strip())
            and review.get("product_cause_blinded") is True
            and bool(str(review.get("rationale", "")).strip())
            and type(review.get("target_and_time_supported")) is bool
            and type(review.get("unsupported_definitive_cause")) is bool
            and type(review.get("false_healthy_failure")) is bool
            and bool(cited_ids)
            and cited_ids.issubset(evidence_ids)
        )
        expected_class = record["expected_classification"]
        class_match = classification == expected_class
        useful = (
            expected_class == "supported_task_explanation"
            and class_match
            and record["success"]
            and not record["reasons"]
            and review.get("useful_within_declared_scope") is True
            and complete_judgment
            and review.get("target_and_time_supported") is True
            and review.get("unsupported_definitive_cause") is False
            and review.get("false_healthy_failure") is False
        )
        record.update(
            review_status="bound" if complete_judgment else "incomplete_semantic_judgment",
            semantic_judgment_complete=complete_judgment,
            classification_matches_frozen_class=class_match,
            target_and_time_supported=review.get("target_and_time_supported"),
            classification=classification,
            useful_task_explanation=useful,
            unsupported_definitive_cause=review.get("unsupported_definitive_cause"),
            false_healthy_failure=review.get("false_healthy_failure"),
            reviewer_arm_blinded=review.get("reviewer_arm_blinded") is True,
            review_limitations=(
                [] if review.get("reviewer_arm_blinded") is True else ["reviewer_knew_arm"]
            ),
        )
        if classification == "healthy_control":
            record["review_group"] = "healthy_control"
        elif classification in {"specific_access_gap", "specific_limit_gap"}:
            record["review_group"] = "access_or_limit_gap"
        elif classification == "supported_task_explanation":
            record["review_group"] = "task_explanation"


def _percentile90(values: list[float]) -> float | None:
    if not values:
        return None
    return sorted(values)[math.ceil(0.9 * len(values)) - 1]


def _aggregate(rows: list[dict[str, Any]]) -> dict[str, Any]:
    timings = [row["elapsed_s"] for row in rows if row["elapsed_s"] is not None]
    rss = [
        row["peak_sampled_rss_bytes"] for row in rows if row["peak_sampled_rss_bytes"] is not None
    ]
    cpu = [row["cpu_seconds_observed"] for row in rows if row["cpu_seconds_observed"] is not None]
    cold = [row["cold_start_s"] for row in rows if row["cold_start_s"] is not None]
    groups = {"task_explanation": 0, "healthy_control": 0, "access_or_limit_gap": 0}
    for row in rows:
        group = row.get("review_group")
        if group in groups:
            groups[group] += 1
    review_complete = bool(rows) and all(row["review_status"] == "bound" for row in rows)
    unsupported_count = sum(row["unsupported_definitive_cause"] is True for row in rows)
    false_healthy_count = sum(row["false_healthy_failure"] is True for row in rows)
    first_by_case: dict[str, dict[str, Any]] = {}
    for row in rows:
        first_by_case.setdefault(row["case_id"], row)
    primary_rows = list(first_by_case.values())

    def category_rate(expected: str, predicate: Callable[[dict[str, Any]], bool]) -> dict[str, Any]:
        denominator = sum(row["expected_classification"] == expected for row in primary_rows)
        numerator = sum(
            row["expected_classification"] == expected and predicate(row) for row in primary_rows
        )
        return {
            "numerator": numerator,
            "denominator": denominator,
            "rate": None if denominator == 0 else numerator / denominator,
        }

    def correctly_reviewed_group(row: dict[str, Any], expected: str) -> bool:
        return (
            row["review_status"] == "bound"
            and row.get("classification") == expected
            and row.get("classification_matches_frozen_class") is True
            and row.get("target_and_time_supported") is True
            and row.get("unsupported_definitive_cause") is False
            and row.get("false_healthy_failure") is False
        )

    return {
        "expected_attempts": len(rows),
        "present_attempts": sum(row["present"] for row in rows),
        "successful_attempts": sum(row["success"] for row in rows),
        "failed_or_incomplete_attempts": sum(not row["success"] for row in rows),
        "recorded_failures": sum(row["failure_recorded"] for row in rows),
        "missing_attempts": sum(not row["present"] for row in rows),
        "missing_timings": len(rows) - len(timings),
        "timing_samples_include_failures": sum(row["timing_includes_failure"] for row in rows),
        "median_elapsed_s": statistics.median(timings) if timings else None,
        "p90_elapsed_s": _percentile90(timings),
        "max_elapsed_s": max(timings) if timings else None,
        "cold_start_median_s": statistics.median(cold) if cold else None,
        "cold_start_missing": len(rows) - len(cold),
        "peak_sampled_rss_bytes": max(rss) if rss else None,
        "rss_missing": len(rows) - len(rss),
        "cpu_seconds_observed_total": sum(cpu) if cpu else None,
        "cpu_missing": len(rows) - len(cpu),
        "bound_reviews": sum(row["review_status"] == "bound" for row in rows),
        "unbound_or_missing_reviews": sum(row["review_status"] != "bound" for row in rows),
        "independent_review_coverage_complete": review_complete,
        "useful_task_explanation_attempts": sum(row["useful_task_explanation"] for row in rows),
        "attempt_review_groups": groups,
        "primary_case_rate_basis": "first_attempt_per_case",
        "review_classification_mismatch_attempts": sum(
            row.get("classification_matches_frozen_class") is False for row in rows
        ),
        "review_classification_mismatches": [
            {
                "case_id": row["case_id"],
                "attempt_id": row["attempt_id"],
                "expected": row["expected_classification"],
                "reviewed": row.get("classification"),
            }
            for row in rows
            if row.get("classification_matches_frozen_class") is False
        ],
        "primary_case_rates": {
            "useful_expected_task_explanations": category_rate(
                "supported_task_explanation", lambda row: row["useful_task_explanation"]
            ),
            "correct_healthy_controls": category_rate(
                "healthy_control",
                lambda row: correctly_reviewed_group(row, "healthy_control"),
            ),
            "correct_specific_access_gaps": category_rate(
                "specific_access_gap",
                lambda row: correctly_reviewed_group(row, "specific_access_gap"),
            ),
            "correct_specific_limit_gaps": category_rate(
                "specific_limit_gap",
                lambda row: correctly_reviewed_group(row, "specific_limit_gap"),
            ),
        },
        "unsupported_definitive_causes": unsupported_count,
        "unsupported_cause_assessment": (
            "incomplete_review_coverage"
            if not review_complete
            else "unsupported_cause_found"
            if unsupported_count
            else "complete_no_unsupported_causes"
        ),
        "false_healthy_failures": false_healthy_count,
        "false_healthy_assessment": (
            "incomplete_review_coverage"
            if not review_complete
            else "false_healthy_failure_found"
            if false_healthy_count
            else "complete_no_false_healthy_failures"
        ),
    }


def score(manifest: dict[str, Any], review_paths: list[Path] | None = None) -> dict[str, Any]:
    case_ids, arms, expected = _validate_manifest(manifest)
    protocol_sha = manifest["protocol_sha256"]
    contract = manifest["paired_contract"]
    classes = manifest["case_classifications"]
    attempts = [
        _attempt_record(row, protocol_sha, contract, classes[row["case_id"]]) for row in expected
    ]
    all_reviews = [
        review for path in (review_paths or []) for review in _read_reviews(path, protocol_sha)
    ]
    _bind_reviews(attempts, all_reviews)
    by_arm = {arm: [row for row in attempts if row["arm"] == arm] for arm in arms}
    primary_by_cell: dict[tuple[str, str], dict[str, Any]] = {}
    for row in attempts:
        cell = (row["case_id"], row["arm"])
        primary_by_cell.setdefault(cell, row)
    paired: list[dict[str, Any]] = []
    for case_id in case_ids:
        pair = [primary_by_cell[(case_id, arm)] for arm in arms]
        paired.append(
            {
                "case_id": case_id,
                "arms": {
                    arm: {
                        "attempt_id": primary_by_cell[(case_id, arm)]["attempt_id"],
                        "useful_task_explanation": primary_by_cell[(case_id, arm)][
                            "useful_task_explanation"
                        ],
                        "elapsed_s": primary_by_cell[(case_id, arm)]["elapsed_s"],
                        "present": primary_by_cell[(case_id, arm)]["present"],
                    }
                    for arm in arms
                },
                "all_primary_artifacts_present": all(row["present"] for row in pair),
            }
        )
    first_arm, second_arm = arms[0], arms[1]
    useful_uplift = sum(
        item["arms"][second_arm]["useful_task_explanation"]
        and not item["arms"][first_arm]["useful_task_explanation"]
        for item in paired
    )
    burden_lower = sum(
        item["all_primary_artifacts_present"]
        and item["arms"][first_arm]["elapsed_s"] is not None
        and item["arms"][second_arm]["elapsed_s"] is not None
        and item["arms"][second_arm]["elapsed_s"] < item["arms"][first_arm]["elapsed_s"]
        for item in paired
    )
    return {
        "schema_version": _SCHEMA_VERSION,
        "cohort_id": manifest["cohort_id"],
        "family": manifest["family"],
        "protocol_sha256": protocol_sha,
        "paired_contract": contract,
        "case_count": len(case_ids),
        "expected_attempt_count": len(expected),
        "repeats_retained": len(expected) - len(case_ids) * len(arms),
        "arms": {
            arm: {"aggregate": _aggregate(rows), "attempts": rows} for arm, rows in by_arm.items()
        },
        "primary_pairs": paired,
        "comparison_indicators": {
            "baseline_arm": first_arm,
            "candidate_arm": second_arm,
            "matched_useful_task_explanation_uplifts": useful_uplift,
            "matched_lower_elapsed_attempts": burden_lower,
            "interpretation": (
                "Descriptive indicators only; no alpha-ready or automatic superiority claim."
            ),
        },
        "qualification": (
            "offline_descriptive_scorecard; independent artifact-bound semantic judgments required"
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cohort", type=Path, required=True)
    parser.add_argument("--reviews", type=Path, action="append", default=[])
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = score(_load_json(args.cohort), args.reviews)
    if args.output.exists():
        raise FileExistsError(args.output)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({arm: item["aggregate"] for arm, item in report["arms"].items()}, indent=2))


if __name__ == "__main__":
    main()
