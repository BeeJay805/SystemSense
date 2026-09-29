"""Mechanical paired scorecard for frozen owned-process Windows trials.

Evidence checks are necessary conditions, not semantic or causal judgments.
Review each saved summary for supported findings and false claims separately.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sqlite3
import statistics
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "benchmarks" / "fixtures" / "private_alpha_host_cases.json"
RECIPES = ROOT / "benchmarks" / "ground_truth" / "private_alpha_host_recipes.json"


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _p90(values: list[float]) -> float | None:
    return None if not values else sorted(values)[math.ceil(0.9 * len(values)) - 1]


def _process_search(case: dict[str, Any]) -> str | None:
    for evidence in case.get("evidence", []):
        if evidence.get("probe_id") != "application.snapshot":
            continue
        searches = evidence.get("facts", {}).get("target_process_search", [])
        if len(searches) == 1:
            return str(searches[0].get("status"))
    return None


def _target_samples(case: dict[str, Any]) -> list[float]:
    for evidence in case.get("evidence", []):
        if evidence.get("probe_id") != "application.target_pressure":
            continue
        pressure = evidence.get("facts", {}).get("target_pressure", {})
        return [
            float(item["cpu_percent"])
            for item in pressure.get("samples", [])
            if item.get("delta_status") == "measured"
            and isinstance(item.get("cpu_percent"), int | float)
        ]
    return []


def _laya_rank_receipts(database: Path) -> int:
    if not database.is_file():
        return 0
    with sqlite3.connect(database) as connection:
        rows = connection.execute("SELECT response_json FROM candidate_decision_snapshots")
        count = 0
        for (raw,) in rows:
            response = json.loads(str(raw))
            if not isinstance(response, dict):
                continue
            typed = cast("dict[str, Any]", response)
            provider = typed.get("provider")
            if (
                isinstance(provider, dict)
                and cast("dict[str, Any]", provider).get("provider_id") == "laya-local-decision"
                and typed.get("cache_hit") is False
            ):
                count += 1
        return count


def _row(directory: Path, case_id: str, recipe: str) -> dict[str, Any]:
    root = directory / case_id
    product_path = root / "product-case.json"
    runtime_path = root / "runtime.json"
    error_path = root / "evaluator" / "error.json"
    product = _load(product_path) if product_path.is_file() else {}
    runtime = _load(runtime_path) if runtime_path.is_file() else {}
    attempt_path = root / "evaluator" / "attempt-runtime.json"
    attempt = _load(attempt_path) if attempt_path.is_file() else {}
    during = (
        _load(root / "evaluator" / "during.json")
        if (root / "evaluator" / "during.json").is_file()
        else {}
    )
    midpoint = (
        _load(root / "evaluator" / "midpoint.json")
        if (root / "evaluator" / "midpoint.json").is_file()
        else {}
    )
    restored = (
        _load(root / "evaluator" / "restored.json")
        if (root / "evaluator" / "restored.json").is_file()
        else {}
    )
    cleanup = (
        _load(root / "evaluator" / "cleanup.json")
        if (root / "evaluator" / "cleanup.json").is_file()
        else {}
    )
    status = _process_search(product)
    samples = _target_samples(product)
    expected_status = (
        "no_matching_process_in_saved_complete_table"
        if recipe == "stopped"
        else "matching_process_observed"
    )
    observation_match = status == expected_status
    if recipe == "busy":
        observation_match = observation_match and len(samples) >= 2 and all(x >= 1 for x in samples)
    if recipe in {"idle", "idle_with_busy_control"}:
        observation_match = (
            observation_match and len(samples) >= 2 and all(x <= 0.5 for x in samples)
        )
    calls = product.get("provider_calls", [])
    return {
        "case_id": case_id,
        "recipe": recipe,
        "complete": product.get("status") == "complete" and not error_path.exists(),
        "error": _load(error_path) if error_path.is_file() else None,
        "product_outcome": product.get("outcome"),
        "summary": product.get("summary"),
        "product_process_search": status,
        "product_target_cpu_samples": samples,
        "product_observation_matches_oracle": observation_match,
        "independent_during_target": during.get("target"),
        "independent_midpoint_target": midpoint.get("target"),
        "independent_control_present": bool(during.get("control", {}).get("running"))
        and bool(midpoint.get("control", {}).get("running")),
        "restored_before_cleanup": bool(cleanup.get("restored_before_cleanup"))
        and bool(restored.get("target", {}).get("running"))
        and bool(restored.get("control", {}).get("running")),
        "all_owned_helpers_exited": cleanup.get("owned_processes_exited") is True,
        "warm_elapsed_ms": attempt.get("elapsed_ms", runtime.get("elapsed_ms")),
        "tree_rss_peak_bytes": runtime.get("tree_rss_peak_bytes"),
        "laya_provider_call_receipts": sum(
            call.get("provider_id") == "laya-local-decision" and not call.get("degraded")
            for call in calls
        ),
        "laya_candidate_rank_receipts": _laya_rank_receipts(root / "cases.db"),
        "sol_calls": sum(
            call.get("provider_id") == "codex-subscription-reasoning" and not call.get("degraded")
            for call in calls
        ),
        "basic_rule_calls": sum(call.get("provider_id") == "keyword-baseline" for call in calls),
        "semantic_review_required": True,
    }


def _aggregate(rows: list[dict[str, Any]], setup: dict[str, Any]) -> dict[str, Any]:
    times = [
        float(row["warm_elapsed_ms"]) / 1000 for row in rows if row["warm_elapsed_ms"] is not None
    ]
    return {
        "cases": len(rows),
        "completed": sum(row["complete"] for row in rows),
        "product_observation_matches_oracle": sum(
            row["product_observation_matches_oracle"] for row in rows
        ),
        "independent_restored": sum(row["restored_before_cleanup"] for row in rows),
        "owned_helpers_exited": sum(row["all_owned_helpers_exited"] for row in rows),
        "laya_provider_call_receipts": sum(row["laya_provider_call_receipts"] for row in rows),
        "laya_candidate_rank_receipts": sum(row["laya_candidate_rank_receipts"] for row in rows),
        "sol_calls": sum(row["sol_calls"] for row in rows),
        "warm_median_s": statistics.median(times) if times else None,
        "warm_p90_s": _p90(times),
        "warm_max_s": max(times) if times else None,
        "cold_setup_s": float(setup["elapsed_ms"]) / 1000,
        "peak_tree_rss_mib": max((row["tree_rss_peak_bytes"] or 0) for row in rows) / 1024**2,
        "missing_or_failed_timing_rows": len(rows) - len(times),
    }


def score(model_dir: Path, basic_dir: Path) -> dict[str, Any]:
    model_meta = _load(model_dir / "run.json")
    basic_meta = _load(basic_dir / "run.json")
    for route, meta in (("model", model_meta), ("basic", basic_meta)):
        if (
            meta["route"] != route
            or meta["manifest_sha256"] != _sha(MANIFEST)
            or meta["recipes_sha256"] != _sha(RECIPES)
        ):
            raise ValueError("paired frozen inputs or route differ")
    if (
        model_meta["split"] != basic_meta["split"]
        or model_meta["source_state"] != basic_meta["source_state"]
    ):
        raise ValueError("paired split or source revision differs")
    manifest = _load(MANIFEST)
    recipes = _load(RECIPES)["recipes"]
    case_ids = [
        item["case_id"] for item in manifest["cases"] if item["split"] == model_meta["split"]
    ]
    model = [_row(model_dir, cid, recipes[cid]) for cid in case_ids]
    basic = [_row(basic_dir, cid, recipes[cid]) for cid in case_ids]
    return {
        "schema_version": 1,
        "split": model_meta["split"],
        "source_state": model_meta["source_state"],
        "manifest_sha256": model_meta["manifest_sha256"],
        "recipes_sha256": model_meta["recipes_sha256"],
        "model": {"aggregate": _aggregate(model, _load(model_dir / "setup.json")), "cases": model},
        "basic": {"aggregate": _aggregate(basic, _load(basic_dir / "setup.json")), "cases": basic},
        "meaning": (
            "Mechanical observation and provenance checks only; human review decides "
            "useful findings, false claims, and diagnostic accuracy. Laya provider-call "
            "and candidate-rank receipts may overlap and must not be added."
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", type=Path, required=True)
    parser.add_argument("--basic", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = score(args.model, args.basic)
    if args.output.exists():
        raise FileExistsError(args.output)
    args.output.write_text(json.dumps(report, indent=2, sort_keys=True), encoding="utf-8")
    print(json.dumps({route: report[route]["aggregate"] for route in ("model", "basic")}, indent=2))


if __name__ == "__main__":
    main()
