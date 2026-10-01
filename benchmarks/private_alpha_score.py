"""Reproducible narrow task-finding scorecard for the frozen alpha loopback suite.

Automated checks identify candidates for human semantic review. They never turn
an observed response or a cautious unknown into a verified root-cause diagnosis.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import sqlite3
import statistics
from contextlib import closing
from pathlib import Path
from typing import Any

_ROOT = Path(__file__).resolve().parents[1]
_CASES = _ROOT / "benchmarks" / "fixtures" / "private_alpha_cases.json"
_KEY = _ROOT / "benchmarks" / "ground_truth" / "private_alpha_recipes.json"


def _load(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _p90(values: list[float]) -> float | None:
    return None if not values else sorted(values)[math.ceil(0.9 * len(values)) - 1]


def _validate_pair_metadata(
    model: dict[str, Any], basic: dict[str, Any], manifest_sha: str, key_sha: str
) -> None:
    for expected_route, metadata in (("model", model), ("basic", basic)):
        if (
            metadata.get("route") != expected_route
            or metadata.get("case_manifest_sha256") != manifest_sha
            or metadata.get("evaluator_key_sha256") != key_sha
            or metadata.get("split") not in {"development", "holdout"}
        ):
            raise ValueError("frozen inputs, route, or split do not match")
    if model["split"] != basic["split"]:
        raise ValueError("frozen inputs, route, or split do not match")
    if model.get("head") != basic.get("head") or model.get("dirty_diff_sha256") != basic.get(
        "dirty_diff_sha256"
    ):
        raise ValueError("paired routes used different source revisions")


def _task_outcome(case: dict[str, Any]) -> str | None:
    task = [
        item
        for item in case.get("evidence", [])
        if item.get("probe_id") == "task.loopback_http" and item.get("status") == "observed"
    ]
    return task[0].get("facts", {}).get("outcome") if len(task) == 1 else None


def _applied_scoped_review(case: dict[str, Any], database: Path) -> bool:
    """Require an applied Sol review of the exact task and later listener evidence."""
    if case.get("summary_source") != "coordinator" or not database.is_file():
        return False
    task_ids = {
        item.get("evidence_id")
        for item in case.get("evidence", [])
        if item.get("probe_id") == "task.loopback_http" and item.get("status") == "observed"
    }
    listener_ids = {
        item.get("evidence_id")
        for item in case.get("evidence", [])
        if item.get("probe_id") == "network.listeners" and item.get("status") == "observed"
    }
    if len(task_ids) != 1 or len(listener_ids) != 1:
        return False
    try:
        with closing(sqlite3.connect(f"file:{database.as_posix()}?mode=ro", uri=True)) as conn:
            rows = conn.execute(
                "SELECT task_json,result_json FROM deep_mailbox "
                "WHERE case_id=? AND status='applied' AND result_json IS NOT NULL",
                (case.get("case_id"),),
            ).fetchall()
        for task_json, result_json in rows:
            task: dict[str, Any] = json.loads(task_json)
            result: dict[str, Any] = json.loads(result_json)
            response: dict[str, Any] = result.get("response") or {}
            if response.get("degraded") or response.get("provider", {}).get("provider_id") != (
                "codex-subscription-reasoning"
            ):
                continue
            expected = task_ids | listener_ids
            presented = {
                item.get("evidence_id")
                for item in task.get("request", {}).get("evidence_context", [])
            }
            considered = set(response.get("considered_evidence_ids") or [])
            if expected <= presented & considered:
                return True
    except (OSError, sqlite3.Error, ValueError, TypeError):
        return False
    return False


def _specific_finding(
    case: dict[str, Any], mode: str, task_outcome: str | None, route: str
) -> bool:
    summary = str(case.get("summary") or "")
    if route == "basic":
        if mode in {"healthy", "intermittent"} and task_outcome == "http_200_nonce_match":
            if mode == "intermittent" and "A later exact request ended in http_503" in summary:
                return "These observations do not identify" in summary
            return (
                "HTTP 200" in summary or "http_200_nonce_match" in summary
            ) and "No failure was reproduced" in summary
        if mode == "http_503" and task_outcome == "http_503":
            return ("HTTP 503" in summary and "reason remains unknown" in summary) or (
                "ended in http_503" in summary and "These observations do not identify" in summary
            )
        if mode == "wrong_nonce" and task_outcome == "wrong_response":
            return (
                "HTTP 200" in summary and "body did not match the expected nonce" in summary
            ) or (
                "ended in wrong_response" in summary
                and "These observations do not identify" in summary
            )
        if mode in {"no_listener", "stall"} and task_outcome in {
            "timeout",
            "connection_refused",
            "request_error",
        }:
            later = (
                "A later complete listener-table search found no listener on that port"
                if mode == "no_listener"
                else "A later listener snapshot found an owner on that port"
            )
            return (
                later in summary
                and "does not establish listener state or request handling during the GET"
                in summary
                and "request-time cause remains unresolved" in summary
                and any(
                    item.get("probe_id") == "network.listeners" and item.get("status") == "observed"
                    for item in case.get("evidence", [])
                )
            )
        return False
    if mode == "missing_access":
        return (
            task_outcome == "http_503"
            and "HTTP 503" in summary
            and "denied" in summary.lower()
            and any(
                item.get("probe_id") == "network.listeners" and item.get("status") == "denied"
                for item in case.get("evidence", [])
            )
        )
    if case.get("summary_source") != "coordinator":
        return False
    if not any(
        item.get("probe_id") == "network.listeners" and item.get("status") == "observed"
        for item in case.get("evidence", [])
    ):
        return False
    if mode == "intermittent" and task_outcome == "http_200_nonce_match":
        return (
            "HTTP 200" in summary
            and "A later exact request failed after that successful response" in summary
            and "different request outcomes establish changed behavior, not its cause" in summary
        )
    if mode == "healthy" and task_outcome == "http_200_nonce_match":
        return "HTTP 200" in summary and "No failure was reproduced" in summary
    if mode == "intermittent" and task_outcome == "http_503":
        return "HTTP 503" in summary and "not observable" in summary
    if mode == "http_503":
        return task_outcome == "http_503" and "HTTP 503" in summary and "handler" in summary
    if mode == "wrong_nonce":
        return (
            task_outcome == "wrong_response"
            and "HTTP 200" in summary
            and "body did not match the expected nonce" in summary
        )
    if mode in {"no_listener", "stall"}:
        if task_outcome not in {"timeout", "connection_refused", "request_error"}:
            return False
        if mode == "stall":
            return (
                "timed out twice" in summary
                and "listener snapshot bound port" in summary
                and "does not prove which handler ran or why" in summary
            )
        return (
            task_outcome in summary
            and "found no listener" in summary
            and "request-time cause remains unresolved" in summary
        )
    return False


def _case_record(directory: Path, case_id: str, mode: str, route: str) -> dict[str, Any]:
    case_dir = directory / case_id
    product_path = case_dir / "product-case.json"
    failure_path = case_dir / "failure.json"
    if failure_path.exists() or not product_path.exists():
        failure = _load(failure_path) if failure_path.exists() else None
        product = _load(product_path) if product_path.exists() else None
        return {
            "case_id": case_id,
            "mode": mode,
            "route": route,
            "completed": False,
            "failure": failure,
            "task_outcome_inside_product": None if product is None else _task_outcome(product),
            "elapsed_ms": None if failure is None else failure.get("elapsed_ms"),
            "automated_useful_finding_candidate": False,
            "synthetic_access_control": mode == "missing_access",
            "semantic_review_required": True,
        }
    case = _load(product_path)
    runtime = _load(case_dir / "runtime.json")
    during = _load(case_dir / "evaluator" / "during.json")
    restored = _load(case_dir / "evaluator" / "restored.json")
    task_outcome = _task_outcome(case)
    calls = case.get("provider_calls", [])
    laya = sum(
        call.get("provider_id") == "laya-local-decision" and not call.get("degraded")
        for call in calls
    )
    sol = sum(
        call.get("provider_id") == "codex-subscription-reasoning" and not call.get("degraded")
        for call in calls
    )
    specific = _specific_finding(case, mode, task_outcome, route)
    model_route = route == "model"
    scoped_review = _applied_scoped_review(case, case_dir / "cases.db") if model_route else False
    return {
        "case_id": case_id,
        "mode": mode,
        "route": route,
        "completed": case.get("status") == "complete",
        "outcome": case.get("outcome"),
        "task_outcome_inside_product": task_outcome,
        "independent_during_outcome": during["target"].get("outcome"),
        "independent_healthy_control": during["control"].get("outcome") == "healthy",
        "independent_restoration": restored.get("verified") is True,
        "laya_calls": laya,
        "sol_calls": sol,
        "basic_rule_calls": sum(call.get("provider_id") == "keyword-baseline" for call in calls),
        "scoped_reviewed_closure": scoped_review,
        "specific_finding": specific,
        "automated_useful_finding_candidate": (
            case.get("status") == "complete"
            and specific
            and (not model_route or (laya > 0 and sol > 0 and scoped_review))
            and restored.get("verified") is True
            and during["control"].get("outcome") == "healthy"
        ),
        "elapsed_ms": runtime["elapsed_ms"],
        "tree_rss_first_bytes": runtime["tree_rss_first_bytes"],
        "tree_rss_peak_bytes": runtime["tree_rss_peak_bytes"],
        "synthetic_access_control": mode == "missing_access",
        "semantic_review_required": True,
    }


def score(model_dir: Path, basic_dir: Path) -> dict[str, Any]:
    manifest = _load(_CASES)
    key = _load(_KEY)
    metadata = _load(model_dir / "frozen-input.json")
    basic_metadata = _load(basic_dir / "frozen-input.json")
    _validate_pair_metadata(metadata, basic_metadata, _sha(_CASES), _sha(_KEY))
    split = metadata["split"]
    ids = [item["case_id"] for item in manifest["cases"] if item["split"] == split]
    model = [_case_record(model_dir, cid, key["recipes"][cid]["mode"], "model") for cid in ids]
    basic = [_case_record(basic_dir, cid, key["recipes"][cid]["mode"], "basic") for cid in ids]
    times = [float(item["elapsed_ms"]) / 1000 for item in model if item["elapsed_ms"] is not None]
    real = [item for item in model if not item["synthetic_access_control"]]
    return {
        "schema_version": 2,
        "scope": "exact user-owned local HTTP health tasks only; not general diagnosis",
        "split": split,
        "manifest_sha256": _sha(_CASES),
        "evaluator_key_sha256": _sha(_KEY),
        "model_revision": metadata["head"],
        "model_dirty_diff_sha256": metadata["dirty_diff_sha256"],
        "model_cases": model,
        "basic_cases": basic,
        "count": len(model),
        "real_access_count": len(real),
        "synthetic_access_count": len(model) - len(real),
        "automated_useful_finding_candidates_real": sum(
            item["automated_useful_finding_candidate"] for item in real
        ),
        "automated_useful_finding_candidates_basic_real": sum(
            item["automated_useful_finding_candidate"]
            for item in basic
            if not item["synthetic_access_control"]
        ),
        "median_warm_seconds": None if not times else statistics.median(times),
        "p90_warm_seconds": _p90(times),
        "max_warm_seconds": None if not times else max(times),
        "cold_model_startup_ms": _load(model_dir / "model-startup.json")["elapsed_ms"],
        "peak_sampled_model_tree_rss_bytes": max(
            (item["tree_rss_peak_bytes"] for item in model if item.get("tree_rss_peak_bytes")),
            default=None,
        ),
        "manual_semantic_review": (
            "required for unsupported definitive causes, false healthy claims, "
            "and actual usefulness"
        ),
    }


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--model-dir", type=Path, required=True)
    parser.add_argument("--basic-dir", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.output.exists():
        raise FileExistsError(args.output)
    args.output.write_text(
        json.dumps(score(args.model_dir, args.basic_dir), indent=2) + "\n", encoding="utf-8"
    )
