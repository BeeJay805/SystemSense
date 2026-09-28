"""Read-only inventory of frozen overnight attempts and their existing scores.

This reporter does not rescore, load the hidden oracle, or grade model prose.
Every discovered attempt remains in the denominator, including failed and
unscored attempts. A separate reviewer sidecar can attach human judgments to
the exact score bytes that were reviewed.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any, cast

from benchmarks.overnight_suite import (
    FrozenSuite,
    RunStamp,
    compare_frozen_contracts,
    load_frozen_suite,
)

_SHA = re.compile(r"[0-9a-f]{64}\Z")
_REV = re.compile(r"[0-9a-f]{7,40}\Z")
_MECHANICAL_COUNTS = (
    "fast_choice_execution_links",
    "deep_choice_execution_links",
    "fast_useful_check_choices",
    "deep_useful_check_choices",
    "fast_complete_mechanical_loops",
    "deep_complete_mechanical_loops",
    "fast_complete_useful_observation_loops",
    "deep_complete_useful_observation_loops",
)
_METRIC_KEYS = (
    "completed_mailbox_durations_ms",
    "completed_mailbox_duration_kind",
    "raw_invalid_retries",
    "raw_invalid_retry_metric_scope",
    "startup_ms",
    "cold_startup_ms",
    "warm_runtime_reused",
    "provider_calls",
    "laya_worker_calls",
    "resource_observations",
    "case_started_at",
    "case_finished_at",
    "codex_acknowledged_runtime",
)


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON key: {key}")
        value[key] = item
    return value


def _read_json(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_unique_pairs)
    if not isinstance(value, dict):
        raise ValueError("JSON root must be an object")
    return cast(dict[str, Any], value)


def _digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _read_or_error(path: Path, errors: list[str], label: str) -> dict[str, Any] | None:
    try:
        return _read_json(path)
    except (OSError, UnicodeError, ValueError):
        errors.append(f"{label}_invalid")
        return None


def _elapsed_ms(metrics: dict[str, Any]) -> int | None:
    start, finish = metrics.get("case_started_at"), metrics.get("case_finished_at")
    if not isinstance(start, str) or not isinstance(finish, str):
        return None
    try:
        before, after = datetime.fromisoformat(start), datetime.fromisoformat(finish)
        if before.tzinfo is None or after.tzinfo is None or after < before:
            return None
        return round((after - before).total_seconds() * 1000)
    except ValueError:
        return None


def _attempt_row(
    path: Path, suite: FrozenSuite, scorer_revision: str, oracle_sha256: str
) -> tuple[dict[str, Any], bool]:
    case_id, phase, arm, attempt_id = path.parts[-4:]
    errors: list[str] = []
    start_path = path / "start.json"
    start = _read_or_error(start_path, errors, "start") if start_path.exists() else None
    if start is None and not start_path.exists():
        errors.append("start_missing")
    start_sha = _digest(start_path) if start_path.exists() else None
    valid_start = False
    try:
        case = suite.case(case_id)
    except ValueError:
        case = None
        errors.append("case_not_in_frozen_suite")
    if case is not None and start is not None:
        expected = {
            "schema_version": 1,
            "attempt_id": attempt_id,
            "suite_sha256": suite.sha256,
            "case_id": case_id,
            "split": case.split,
            "phase": phase,
            "arm": arm,
            "oracle_sha256": oracle_sha256,
            "visible_input_sha256": case.visible.visible_input_sha256,
            "initial_evidence_sha256": case.visible.initial_evidence_sha256,
            "action_contract_sha256": case.visible.action_contract_sha256,
            "budget_ms": case.visible.budget_ms,
        }
        if any(start.get(key) != value for key, value in expected.items()):
            errors.append("start_case_binding_mismatch")
        else:
            try:
                RunStamp(
                    phase=phase,
                    arm=arm,
                    code_revision=str(start["code_revision"]),
                    baseline_revision=str(start["baseline_revision"]),
                    candidate_revision=start.get("candidate_revision"),
                    oracle_sha256=oracle_sha256,
                ).validate(case.split)
                valid_start = True
            except (ValueError, TypeError, KeyError):
                errors.append("start_revision_invalid")

    failure_path = path / "failure.json"
    failure_sha = _digest(failure_path) if failure_path.exists() else None
    if failure_sha is not None:
        failure = _read_or_error(failure_path, errors, "failure")
        if failure is not None and not isinstance(failure.get("type"), str):
            errors.append("failure_type_invalid")
    capture_path = path / "capture.json"
    capture_sha = _digest(capture_path) if capture_path.exists() else None
    if not capture_path.exists():
        capture_state = "missing_with_failure" if failure_sha else "missing_without_failure"
    else:
        receipt_path = path / "capture.sha256.json"
        receipt = (
            _read_or_error(receipt_path, errors, "capture_receipt")
            if receipt_path.exists()
            else None
        )
        capture_state = (
            "digest_verified"
            if receipt is not None and receipt.get("sha256") == capture_sha
            else "digest_mismatch"
            if receipt is not None
            else "missing_or_invalid_receipt"
        )
        if capture_state == "digest_verified":
            capture = _read_or_error(capture_path, errors, "capture")
            if capture is None:
                capture_state = "invalid"
            elif capture.get("case_id") != case_id:
                capture_state = "case_binding_mismatch"
                errors.append("capture_case_binding_mismatch")
            elif case is not None:
                contract_value = capture.get("contract")
                contract = (
                    cast(dict[str, Any], contract_value) if isinstance(contract_value, dict) else {}
                )
                if any(
                    contract.get(key) != getattr(case.visible, key)
                    for key in (
                        "visible_input_sha256",
                        "initial_evidence_sha256",
                        "action_contract_sha256",
                    )
                ):
                    capture_state = "contract_mismatch"
                    errors.append("capture_contract_mismatch")
        if capture_state != "digest_verified":
            errors.append("capture_integrity_invalid")
    if failure_sha and capture_sha:
        errors.append("capture_and_failure_both_present")

    score_path = path / f"score-{scorer_revision}.json"
    score_sha = _digest(score_path) if score_path.exists() else None
    score = _read_or_error(score_path, errors, "score") if score_sha else None
    score_state = "missing" if score_sha is None else "invalid" if score is None else "present"
    if score is not None and score.get("scorer_revision") != scorer_revision:
        errors.append("scorer_revision_mismatch")
    if score is not None and failure_sha and score.get("status") != "failed":
        errors.append("score_failure_mismatch")
    if score is not None and not failure_sha and score.get("status") == "failed":
        errors.append("score_failure_mismatch")
    if score is not None and not failure_sha and capture_state != "digest_verified":
        errors.append("score_capture_unverified")
    if (
        score is not None
        and score.get("status") != "failed"
        and any(key not in score for key in _MECHANICAL_COUNTS)
    ):
        errors.append("score_mechanical_missing")
    if score is not None:
        for key in _MECHANICAL_COUNTS:
            value = score.get(key, 0)
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                errors.append("score_mechanical_invalid")
                break
    trusted = valid_start and score is not None and not errors
    if score is not None and not trusted:
        score_state = "present_untrusted"
    metrics_value = score.get("metrics") if trusted and score is not None else None
    metrics = cast(dict[str, Any], metrics_value) if isinstance(metrics_value, dict) else {}
    reported_metrics: dict[str, object] | None = None
    if trusted:
        reported_metrics = {key: metrics.get(key) for key in _METRIC_KEYS}
        reported_metrics["case_elapsed_ms"] = _elapsed_ms(metrics)
        reported_metrics["resource_scope"] = "recorded_process_samples_not_host_or_gpu_peaks"
        reported_metrics["laya_worker_call_scope"] = (
            "worker_protocol_requests_not_neural_forwards"
            if metrics.get("laya_worker_calls") is not None
            else "unknown_not_captured"
        )
    mechanical = (
        {key: score.get(key, 0) for key in _MECHANICAL_COUNTS}
        if trusted and score is not None
        else None
    )
    row: dict[str, Any] = {
        "attempt_id": attempt_id,
        "attempt_relative_path": "/".join(path.parts[-4:]),
        "case_id": case_id,
        "family_group": case.family_group if case is not None else None,
        "split": case.split if case is not None else None,
        "phase": phase,
        "arm": arm,
        "code_revision": start.get("code_revision") if start else None,
        "baseline_revision": start.get("baseline_revision") if start else None,
        "candidate_revision": start.get("candidate_revision") if start else None,
        "start_sha256": start_sha,
        "capture_sha256": capture_sha,
        "capture_state": capture_state,
        "failure_sha256": failure_sha,
        "failure_state": "present" if failure_sha else "missing",
        "score_sha256": score_sha,
        "score_state": score_state,
        "score_status": score.get("status") if trusted and score else None,
        "route_realization": score.get("route_realization") if trusted and score else None,
        "deep_origin_attribution": score.get("deep_proposed_execution")
        if trusted and score
        else None,
        "mechanical": mechanical,
        "useful_choice_observed": score.get("useful_choice_observed")
        if trusted and score
        else None,
        "metrics": reported_metrics,
        "semantic_review": None,
        "integrity_errors": sorted(set(errors)),
    }
    return row, valid_start


def _reviews(path: Path | None) -> tuple[dict[tuple[str, str], dict[str, Any]], str | None]:
    if path is None:
        return {}, None
    payload = _read_json(path)
    if set(payload) != {"schema_version", "reviews"} or payload["schema_version"] != 1:
        raise ValueError("review sidecar schema mismatch")
    entries = payload["reviews"]
    if not isinstance(entries, list):
        raise ValueError("review sidecar must contain a list")
    reviews: dict[tuple[str, str], dict[str, Any]] = {}
    for raw_entry in cast(list[object], entries):
        entry = cast(dict[str, object], raw_entry) if isinstance(raw_entry, dict) else None
        if not isinstance(entry, dict) or set(entry) != {"attempt_id", "score_sha256", "review"}:
            raise ValueError("review sidecar entry schema mismatch")
        attempt_id = entry["attempt_id"]
        score_sha = entry["score_sha256"]
        review = entry["review"]
        if (
            not isinstance(attempt_id, str)
            or not isinstance(score_sha, str)
            or not _SHA.fullmatch(score_sha)
            or not isinstance(review, dict)
        ):
            raise ValueError("review sidecar entry invalid")
        key = (attempt_id, score_sha)
        if key in reviews:
            raise ValueError("duplicate review sidecar entry")
        reviews[key] = cast(dict[str, Any], review)
    return reviews, _digest(path)


def summarize_attempts(
    suite: FrozenSuite,
    attempts_root: Path,
    scorer_revision: str,
    oracle_sha256: str,
    *,
    reviews_path: Path | None = None,
) -> dict[str, Any]:
    """Inventory all attempts under one suite without changing any input file."""
    if not _REV.fullmatch(scorer_revision) or not _SHA.fullmatch(oracle_sha256):
        raise ValueError("invalid frozen scorer or oracle digest")
    if _digest(suite.path) != suite.sha256:
        raise ValueError("frozen suite digest changed before reporting")
    suite_dir = attempts_root / suite.sha256
    paths = sorted(path for path in suite_dir.glob("*/*/*/attempt-*") if path.is_dir())
    rows: list[dict[str, Any]] = []
    valid_paths: dict[str, Path] = {}
    for path in paths:
        row, valid_start = _attempt_row(path, suite, scorer_revision, oracle_sha256)
        attempt_id = cast(str, row["attempt_id"])
        if attempt_id in valid_paths or any(item["attempt_id"] == attempt_id for item in rows):
            raise ValueError("duplicate attempt ID across frozen suite")
        rows.append(row)
        if valid_start:
            valid_paths[attempt_id] = path

    reviews, review_sha = _reviews(reviews_path)
    used_reviews: set[tuple[str, str]] = set()
    for row in rows:
        attempt_id, score_sha = str(row["attempt_id"]), row["score_sha256"]
        if score_sha is None:
            continue
        key = (attempt_id, str(score_sha))
        if key in reviews:
            if row["score_state"] != "present":
                raise ValueError("review refers to an untrusted score")
            row["semantic_review"] = reviews[key]
            used_reviews.add(key)
    if len(used_reviews) != len(reviews):
        raise ValueError("review sidecar attempt ID or score hash not found")

    groups: dict[tuple[str, str, str, str | None], list[str]] = {}
    for row in rows:
        key = (
            str(row["case_id"]),
            str(row["phase"]),
            str(row["arm"]),
            cast(str | None, row["code_revision"]),
        )
        groups.setdefault(key, []).append(str(row["attempt_id"]))
    grouped = [
        {
            "case_id": key[0],
            "phase": key[1],
            "arm": key[2],
            "code_revision": key[3],
            "attempt_ids": sorted(ids),
            "attempt_count": len(ids),
        }
        for key, ids in sorted(
            groups.items(), key=lambda item: (item[0][0], item[0][1], item[0][2], item[0][3] or "")
        )
    ]

    comparison_pairs: list[dict[str, object]] = []
    paired_attempts: set[str] = set()
    for candidate in rows:
        phase = str(candidate["phase"])
        if phase not in {"development_candidate", "heldout_candidate"}:
            continue
        baseline_phase = phase.replace("candidate", "baseline")
        for baseline in rows:
            if (
                baseline["phase"] != baseline_phase
                or baseline["case_id"] != candidate["case_id"]
                or baseline["arm"] != candidate["arm"]
                or baseline["code_revision"] != candidate["baseline_revision"]
                or baseline["attempt_id"] not in valid_paths
                or candidate["attempt_id"] not in valid_paths
            ):
                continue
            parity = compare_frozen_contracts(
                [
                    valid_paths[str(baseline["attempt_id"])],
                    valid_paths[str(candidate["attempt_id"])],
                ]
            )
            comparison_pairs.append(
                {
                    "case_id": candidate["case_id"],
                    "arm": candidate["arm"],
                    "baseline_attempt_id": baseline["attempt_id"],
                    "candidate_attempt_id": candidate["attempt_id"],
                    **parity,
                }
            )
            paired_attempts.update((str(baseline["attempt_id"]), str(candidate["attempt_id"])))

    totals = {key: 0 for key in _MECHANICAL_COUNTS}
    trusted_scores = 0
    for row in rows:
        mechanical = row["mechanical"]
        if not isinstance(mechanical, dict):
            continue
        trusted_scores += 1
        for key in _MECHANICAL_COUNTS:
            totals[key] += cast(dict[str, int], mechanical)[key]
    return {
        "schema_version": 1,
        "report_scope": "all_discovered_attempts_mechanical_inventory_not_diagnostic_accuracy",
        "suite_sha256": suite.sha256,
        "oracle_sha256": oracle_sha256,
        "scorer_revision": scorer_revision,
        "review_sidecar_sha256": review_sha,
        "attempt_count": len(rows),
        "attempts": rows,
        "groups": grouped,
        "comparison_pairs": comparison_pairs,
        "unpaired_attempt_ids": sorted(
            str(row["attempt_id"]) for row in rows if row["attempt_id"] not in paired_attempts
        ),
        "mechanical_totals": {
            **totals,
            "trusted_score_attempts": trusted_scores,
            "unknown_score_attempts": len(rows) - trusted_scores,
            "denominator": "all_discovered_attempts",
            "semantic_correctness": "not_aggregated_requires_independent_review",
        },
    }


def write_report(path: Path, report: dict[str, object]) -> None:
    """Write once to a private absolute path, preserving earlier reports."""
    if not path.is_absolute() or path.resolve().is_relative_to(Path(__file__).resolve().parents[1]):
        raise ValueError("report output must be absolute and outside the repository")
    with path.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True, ensure_ascii=False, allow_nan=False)
        stream.write("\n")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--suite", type=Path, required=True)
    parser.add_argument("--suite-sha256", required=True)
    parser.add_argument("--attempts-root", type=Path, required=True)
    parser.add_argument("--scorer-revision", required=True)
    parser.add_argument("--oracle-sha256", required=True)
    parser.add_argument("--reviews", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    suite = load_frozen_suite(args.suite, args.suite_sha256)
    report = summarize_attempts(
        suite,
        args.attempts_root,
        args.scorer_revision,
        args.oracle_sha256,
        reviews_path=args.reviews,
    )
    write_report(args.output, report)
    print(json.dumps({"report": str(args.output), "attempt_count": report["attempt_count"]}))


if __name__ == "__main__":
    main()
