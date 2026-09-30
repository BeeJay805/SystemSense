"""Read-only adapters for saved loopback and owned-process private-alpha cohorts.

The adapters never start a product/model or read evaluator recipes. Frozen run
metadata supplies the denominator and paired source identity; each case's
result-index, product report, runtime, evaluator snapshots, and database are
read as saved. Reviewer labels count only when their report/database hashes bind.
Mechanics and semantic judgments remain separate in the returned scorecard.
"""

from __future__ import annotations

import hashlib
import json
import math
import sqlite3
import statistics
from collections.abc import Iterable
from contextlib import closing
from pathlib import Path
from typing import Any, cast


def _read(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError(f"expected JSON object: {path}")
    return cast(dict[str, Any], value)


def _sha(path: Path) -> str | None:
    if not path.is_file():
        return None
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(char in "0123456789abcdef" for char in value)
    )


def _number(value: object) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    number = float(value)
    return number if math.isfinite(number) and number >= 0 else None


def _median(values: list[float]) -> float | None:
    return statistics.median(values) if values else None


def _p90(values: list[float]) -> float | None:
    return sorted(values)[math.ceil(0.9 * len(values)) - 1] if values else None


def _db_case_ids(path: Path) -> list[str] | None:
    if not path.is_file():
        return None
    try:
        with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as conn:
            return [str(row[0]) for row in conn.execute("SELECT case_id FROM cases")]
    except sqlite3.Error:
        return None


def _mechanics(
    case_id: str,
    case_dir: Path | None,
    *,
    case_key: str,
) -> dict[str, Any]:
    row: dict[str, Any] = {
        "case_id": case_id,
        "attempt_id": case_dir.name if case_dir is not None else None,
        "present": case_dir is not None and case_dir.is_dir(),
        "completed": False,
        "failure_recorded": False,
        "restoration_verified": None,
        "cleanup_verified": None,
        "elapsed_ms": None,
        "tree_cpu_seconds_observed": None,
        "tree_rss_peak_bytes": None,
        "laya_receipts": 0,
        "sol_receipts": 0,
        "artifact_hashes": {},
        "evidence_ids": [],
        "completed_probe_ids": [],
        "observed_probe_ids": [],
        "review": {"status": "missing", "outcome": None, "judgment": None},
        "reasons": [],
    }
    if case_dir is None or not case_dir.is_dir():
        row["reasons"].append("expected_case_directory_missing")
        return row
    result_path = case_dir / "result-index.json"
    report_path = case_dir / "product-case.json"
    runtime_path = case_dir / "runtime.json"
    db_path = case_dir / "cases.db"
    result, product, runtime = (
        _read(result_path),
        _read(report_path),
        _read(runtime_path),
    )
    if result is None:
        row["reasons"].append("result_index_missing")
    else:
        if result.get(case_key) is not None and result.get(case_key) != case_id:
            row["reasons"].append("result_index_case_id_mismatch")
        row["result_index_complete"] = result.get("status") == "complete"
        row["failure_recorded"] = result.get("status") not in {"complete", None}
        row["outcome"] = result.get("outcome")
    if product is None:
        row["reasons"].append("product_report_missing")
    else:
        row["artifact_hashes"]["report_sha256"] = _sha(report_path)
        if product.get("status") != "complete":
            row["failure_recorded"] = True
        if product.get("read_only") is not True:
            row["reasons"].append("product_report_not_read_only")
        row["product_case_id"] = product.get("case_id")
        row["budget"] = {
            key: product.get(key)
            for key in (
                "objective",
                "reported_task_action_sha256",
                "budget_ms",
                "max_rounds",
                "max_probes",
                "read_only",
            )
        }
        evidence_value = product.get("evidence")
        evidence_rows = (
            cast(list[object], evidence_value) if isinstance(evidence_value, list) else []
        )
        row["evidence_ids"] = sorted(
            str(cast(dict[str, Any], item).get("evidence_id"))
            for item in evidence_rows
            if isinstance(item, dict) and cast(dict[str, Any], item).get("evidence_id")
        )
        row["completed_probe_ids"] = sorted(map(str, product.get("completed_probe_ids", [])))
        row["observed_probe_ids"] = sorted(
            {
                str(cast(dict[str, Any], item).get("probe_id"))
                for item in evidence_rows
                if isinstance(item, dict)
                and cast(dict[str, Any], item).get("probe_id")
                and cast(dict[str, Any], item).get("status") == "observed"
            }
        )
        row["completed"] = (
            result is not None
            and result.get("status") == "complete"
            and product.get("status") == "complete"
        )
        calls = product.get("provider_calls", [])
        if isinstance(calls, list):
            call_rows = cast(list[object], calls)
            row["laya_receipts"] = sum(
                cast(dict[str, Any], item).get("provider_id") == "laya-local-decision"
                and not cast(dict[str, Any], item).get("degraded")
                for item in call_rows
                if isinstance(item, dict)
            )
            row["sol_receipts"] = sum(
                cast(dict[str, Any], item).get("provider_id") == "codex-subscription-reasoning"
                and not cast(dict[str, Any], item).get("degraded")
                for item in call_rows
                if isinstance(item, dict)
            )
    if runtime is None:
        row["reasons"].append("runtime_measurement_missing")
    else:
        row["elapsed_ms"] = _number(runtime.get("elapsed_ms"))
        row["tree_cpu_seconds_observed"] = _number(runtime.get("tree_cpu_seconds_observed"))
        row["tree_rss_peak_bytes"] = _number(runtime.get("tree_rss_peak_bytes"))
        row["artifact_hashes"]["runtime_sha256"] = _sha(runtime_path)
    row["artifact_hashes"]["database_sha256"] = _sha(db_path)
    db_case_ids = _db_case_ids(db_path)
    if product is None or db_case_ids is None or db_case_ids != [product.get("case_id")]:
        row["reasons"].append("saved_database_report_identity_mismatch_or_missing")
    evaluator_dir = case_dir / "evaluator"
    restored_path = (
        (evaluator_dir / "restored.json") if evaluator_dir.is_dir() else case_dir / "restored.json"
    )
    cleanup_path = (
        (evaluator_dir / "cleanup.json") if evaluator_dir.is_dir() else case_dir / "cleanup.json"
    )
    restored = _read(restored_path)
    cleanup = _read(cleanup_path)
    if restored is None:
        row["reasons"].append("restoration_receipt_missing")
    else:
        if "verified" in restored:
            row["restoration_verified"] = restored.get("verified") is True
        elif isinstance(restored.get("target"), dict) and isinstance(restored.get("control"), dict):
            row["restoration_verified"] = (
                restored["target"].get("running") is True
                and restored["control"].get("running") is True
            )
    if cleanup is None:
        row["reasons"].append("cleanup_receipt_missing")
    else:
        row["cleanup_verified"] = (
            cleanup.get("owned_helpers_exited") is True
            or cleanup.get("owned_processes_exited") is True
            or cleanup.get("owned_servers_stopped") is True
        )
        if row["restoration_verified"] is None and cleanup.get("restored_before_cleanup") is True:
            row["restoration_verified"] = True
    return row


def _join_reviews(
    rows: list[dict[str, Any]], reviews: list[dict[str, Any]], *, attempt_key: str
) -> None:
    indexed = {row["attempt_id"]: row for row in rows if row["attempt_id"] is not None}
    for review in reviews:
        row = indexed.get(str(review.get(attempt_key)))
        if row is None:
            continue
        report_sha = row["artifact_hashes"].get("report_sha256")
        database_sha = row["artifact_hashes"].get("database_sha256")
        if not _is_sha256(report_sha) or not _is_sha256(database_sha):
            row["review"] = {
                "status": "review_missing_report_or_database_artifact",
                "outcome": review.get("outcome"),
                "judgment": review.get("judgment"),
            }
            continue
        if (
            review.get("report_sha256") != report_sha
            or review.get("database_sha256") != database_sha
        ):
            row["review"] = {
                "status": "artifact_hash_mismatch",
                "outcome": review.get("outcome"),
                "judgment": review.get("judgment"),
            }
            continue
        row["review"] = {
            "status": "bound",
            "outcome": review.get("outcome"),
            "judgment": review.get("judgment"),
            "semantic_judgment": review.get("semantic_judgment"),
            "full_loop_credit": review.get("full_loop_credit"),
            "reviewer_arm_blinded": False,
            "selected_probe": review.get("selected_probe"),
            "review_claimed_executed": review.get("executed"),
            "selected_probe_executed_and_observed": (
                review.get("executed") is True
                and review.get("selected_probe") in row.get("completed_probe_ids", [])
                and review.get("selected_probe") in row.get("observed_probe_ids", [])
            ),
        }


def _arm_summary(rows: list[dict[str, Any]], cold_start_ms: float | None) -> dict[str, Any]:
    times = [row["elapsed_ms"] / 1000 for row in rows if row["elapsed_ms"] is not None]
    cpu = [
        row["tree_cpu_seconds_observed"]
        for row in rows
        if row["tree_cpu_seconds_observed"] is not None
    ]
    rss = [row["tree_rss_peak_bytes"] for row in rows if row["tree_rss_peak_bytes"] is not None]
    reviews = [row for row in rows if row["review"]["status"] == "bound"]
    return {
        "expected_cases": len(rows),
        "present_attempts": sum(row["present"] for row in rows),
        "completed": sum(row["completed"] for row in rows),
        "failed_or_incomplete": sum(not row["completed"] for row in rows),
        "recorded_failures": sum(row["failure_recorded"] for row in rows),
        "restored": sum(row["restoration_verified"] is True for row in rows),
        "restoration_missing_or_failed": sum(
            row["restoration_verified"] is not True for row in rows
        ),
        "cleaned_up": sum(row["cleanup_verified"] is True for row in rows),
        "cleanup_missing_or_failed": sum(row["cleanup_verified"] is not True for row in rows),
        "missing_timing": len(rows) - len(times),
        "median_elapsed_s": _median(times),
        "p90_elapsed_s": _p90(times),
        "max_elapsed_s": max(times) if times else None,
        "cold_start_s": None if cold_start_ms is None else cold_start_ms / 1000,
        "cpu_seconds_observed_total": sum(cpu) if cpu else None,
        "cpu_measurement_missing": len(rows) - len(cpu),
        "peak_sampled_rss_bytes": max(rss) if rss else None,
        "rss_measurement_missing": len(rows) - len(rss),
        "laya_provider_receipts": sum(row["laya_receipts"] for row in rows),
        "sol_provider_receipts": sum(row["sol_receipts"] for row in rows),
        "artifact_bound_reviews": len(reviews),
        "review_missing_or_unbound": len(rows) - len(reviews),
        "review_outcome_counts": _counts(row["review"].get("outcome") for row in reviews),
        "review_judgment_counts": _counts(row["review"].get("judgment") for row in reviews),
        "full_loop_credit_labels": _counts(
            row["review"].get("full_loop_credit") for row in reviews
        ),
        "review_selected_probe_claims": sum(
            row["review"].get("selected_probe") is not None for row in reviews
        ),
        "selected_probe_execution_and_observation_matches": sum(
            row["review"].get("selected_probe_executed_and_observed") is True for row in reviews
        ),
        "unsupported_cause_assessment": "not_separately_structured_in_review_schema",
    }


def _paired_report_issues(
    basic_rows: list[dict[str, Any]], model_rows: list[dict[str, Any]]
) -> list[str]:
    issues: list[str] = []
    keys = ("budget_ms", "max_rounds", "max_probes", "read_only")
    for baseline, candidate in zip(basic_rows, model_rows, strict=False):
        left, right = baseline.get("budget"), candidate.get("budget")
        if left is None or right is None or any(left.get(key) != right.get(key) for key in keys):
            issues.append(f"paired_access_or_budget_differs:{baseline['case_id']}")
    if len(basic_rows) != len(model_rows):
        issues.append("paired_report_row_count_differs")
    return issues


def _counts(values: Iterable[object]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for value in values:
        if value is None:
            continue
        label = str(value)
        counts[label] = counts.get(label, 0) + 1
    return counts


def _validate_frozen_inputs(basic: dict[str, Any], model: dict[str, Any]) -> list[str]:
    issues: list[str] = []
    for route, metadata in (("basic", basic), ("model", model)):
        if metadata.get("route") != route:
            issues.append(f"{route}_route_mismatch")
    fields = (
        "head",
        "dirty_diff_sha256",
        "case_manifest_sha256",
        "evaluator_key_sha256",
        "split",
    )
    if any(basic.get(key) != model.get(key) for key in fields):
        issues.append("paired_frozen_inputs_or_source_differ")
    return issues


def score_loopback_repeat(
    basic_dir: Path,
    model_dir: Path,
    case_manifest_path: Path,
    review_path: Path,
) -> dict[str, Any]:
    """Score one paired frozen-input loopback repeat without opening its evaluator key."""
    basic_meta, model_meta = (
        _read(basic_dir / "frozen-input.json"),
        _read(model_dir / "frozen-input.json"),
    )
    if basic_meta is None or model_meta is None:
        raise ValueError("both frozen-input.json files are required")
    issues = _validate_frozen_inputs(basic_meta, model_meta)
    if _sha(case_manifest_path) != basic_meta.get("case_manifest_sha256"):
        issues.append("case_manifest_digest_mismatch")
    manifest = _read(case_manifest_path)
    if manifest is None or not isinstance(manifest.get("cases"), list):
        raise ValueError("case manifest with explicit case IDs is required")
    expected = [
        str(item["case_id"])
        for item in manifest["cases"]
        if item.get("split") == basic_meta.get("split")
    ]
    review_doc = _read(review_path)
    review_section = None if review_doc is None else review_doc.get("loopback_repeat")
    review_cases: list[dict[str, Any]] = []
    if isinstance(review_section, dict):
        cases_value = cast(dict[str, Any], review_section).get("cases")
        if isinstance(cases_value, list):
            case_rows = cast(list[object], cases_value)
            review_cases = [
                cast(dict[str, Any], item) for item in case_rows if isinstance(item, dict)
            ]
    if review_doc is not None and not isinstance(review_section, dict):
        raise ValueError("review JSON lacks loopback_repeat.cases")
    if review_doc and review_doc.get("frozen_product_revision") != basic_meta.get("head"):
        issues.append("review_product_revision_mismatch")
    arms: dict[str, Any] = {}
    run_info: dict[str, Any] = {}
    for route, run_dir in (("basic", basic_dir), ("model", model_dir)):
        arm_meta = basic_meta if route == "basic" else model_meta
        by_case = {path.name: path for path in run_dir.iterdir() if path.is_dir()}
        rows = [_mechanics(case, by_case.get(case), case_key="case_id") for case in expected]
        _join_reviews(rows, review_cases, attempt_key="attempt")
        startup = _read(run_dir / "model-startup.json")
        arms[route] = {
            "aggregate": _arm_summary(
                rows, _number(None if startup is None else startup.get("elapsed_ms"))
            ),
            "cases": rows,
        }
        run_info[route] = {
            key: arm_meta.get(key)
            for key in (
                "head",
                "dirty_diff_sha256",
                "case_manifest_sha256",
                "evaluator_key_sha256",
                "split",
            )
        }
    closure = (
        None
        if review_doc is None
        else review_doc.get("loopback_repeat", {}).get("canonical_closure")
    )
    return {
        "schema_version": 1,
        "family": "loopback_http",
        "cohort_id": f"{basic_dir.name}__{model_dir.name}",
        "source_contract": run_info,
        "paired_contract_issues": issues,
        "case_count": len(expected),
        "arms": arms,
        "independent_review": {
            "artifact": str(review_path),
            "hash_binding_required": True,
            "reviewer_arm_blinded": False,
            "canonical_closure_review": closure,
            "unsupported_cause_assessment": "not_separately_structured_in_review_schema",
        },
        "qualification": (
            "offline_saved_artifacts_only; descriptive, no automatic alpha-ready claim"
        ),
    }


def score_process_repeat(
    basic_dir: Path,
    model_dir: Path,
    review_path: Path,
) -> dict[str, Any]:
    """Score paired host-owned-process artifacts using run.json case IDs as denominator."""
    basic_run, model_run = _read(basic_dir / "run.json"), _read(model_dir / "run.json")
    if basic_run is None or model_run is None:
        raise ValueError("both run.json files are required")
    issues: list[str] = []
    for route, metadata in (("basic", basic_run), ("model", model_run)):
        if metadata.get("route") != route:
            issues.append(f"{route}_route_mismatch")
    compare = (
        "case_ids",
        "fixture_source_sha256",
        "manifest_sha256",
        "recipes_sha256",
        "source_state",
        "split",
    )
    if any(basic_run.get(key) != model_run.get(key) for key in compare):
        issues.append("paired_run_contract_or_source_differs")
    expected_value = basic_run.get("case_ids")
    if not isinstance(expected_value, list) or not expected_value:
        raise ValueError("basic run.json must contain a unique nonempty case_ids denominator")
    expected_objects = cast(list[object], expected_value)
    if any(not isinstance(item, str) for item in expected_objects):
        raise ValueError("case_ids must contain strings")
    expected = cast(list[str], expected_objects)
    if len(set(expected)) != len(expected):
        raise ValueError("basic run.json must contain a unique nonempty case_ids denominator")
    review_doc = _read(review_path)
    review_section = None if review_doc is None else review_doc.get("process_holdout")
    review_cases: list[dict[str, Any]] = []
    if isinstance(review_section, dict):
        cases_value = cast(dict[str, Any], review_section).get("cases")
        if isinstance(cases_value, list):
            case_rows = cast(list[object], cases_value)
            review_cases = [
                cast(dict[str, Any], item) for item in case_rows if isinstance(item, dict)
            ]
    if review_doc is not None and not isinstance(review_section, dict):
        raise ValueError("review JSON lacks process_holdout.cases")
    source_state = basic_run.get("source_state")
    source_head = (
        cast(dict[str, Any], source_state).get("head") if isinstance(source_state, dict) else None
    )
    if review_doc and review_doc.get("frozen_product_revision") != source_head:
        issues.append("review_product_revision_mismatch")
    arms: dict[str, Any] = {}
    for route, run_dir in (("basic", basic_dir), ("model", model_dir)):
        by_case = {path.name: path for path in run_dir.iterdir() if path.is_dir()}
        rows = [
            _mechanics(str(case), by_case.get(str(case)), case_key="case_id") for case in expected
        ]
        _join_reviews(rows, review_cases, attempt_key="case")
        setup = _read(run_dir / "setup.json")
        arms[route] = {
            "aggregate": _arm_summary(
                rows, _number(None if setup is None else setup.get("elapsed_ms"))
            ),
            "cases": rows,
        }
    issues.extend(_paired_report_issues(arms["basic"]["cases"], arms["model"]["cases"]))
    return {
        "schema_version": 1,
        "family": "owned_process",
        "cohort_id": f"{basic_dir.name}__{model_dir.name}",
        "source_contract": {"basic": basic_run, "model": model_run},
        "paired_contract_issues": issues,
        "case_count": len(expected),
        "arms": arms,
        "independent_review": {
            "artifact": str(review_path),
            "hash_binding_required": True,
            "reviewer_arm_blinded": False,
            "unsupported_cause_assessment": "not_separately_structured_in_review_schema",
        },
        "qualification": (
            "offline_saved_artifacts_only; descriptive, no automatic alpha-ready claim"
        ),
    }
