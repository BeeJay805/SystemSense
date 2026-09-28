from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path

import pytest

from benchmarks.overnight_report import summarize_attempts, write_report
from benchmarks.overnight_suite import (
    FrozenSuite,
    RunStamp,
    VisibleCase,
    load_frozen_suite,
    run_attempt,
    score_attempt,
)


def _put(path: Path, value: object) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _suite(tmp_path: Path) -> tuple[FrozenSuite, dict[str, object]]:
    cases: list[dict[str, object]] = [
        {
            "case_id": "case-aaaaaaaaaaaa",
            "split": "development",
            "family_group": "network",
            "source": "synthetic",
            "visible_input_sha256": "a" * 64,
            "initial_evidence_sha256": "b" * 64,
            "action_contract_sha256": "c" * 64,
            "budget_ms": 5000,
        }
    ]
    path = tmp_path / "suite.json"
    digest = _put(path, {"schema_version": 1, "cases": cases})
    return load_frozen_suite(path, digest), cases[0]


def _attempt(
    root: Path,
    suite_sha: str,
    case: Mapping[str, object],
    *,
    name: str,
    phase: str,
    code_revision: str,
    baseline_revision: str,
    candidate_revision: str | None,
    scorer_revision: str,
    scored: bool = True,
    failed: bool = False,
    legacy_deep: bool = False,
) -> Path:
    attempt = root / suite_sha / str(case["case_id"]) / phase / "laya_sol" / name
    attempt.mkdir(parents=True)
    _put(
        attempt / "start.json",
        {
            "schema_version": 1,
            "attempt_id": name,
            "suite_sha256": suite_sha,
            "case_id": case["case_id"],
            "split": case["split"],
            "phase": phase,
            "arm": "laya_sol",
            "code_revision": code_revision,
            "baseline_revision": baseline_revision,
            "candidate_revision": candidate_revision,
            "oracle_sha256": "d" * 64,
            "visible_input_sha256": case["visible_input_sha256"],
            "initial_evidence_sha256": case["initial_evidence_sha256"],
            "action_contract_sha256": case["action_contract_sha256"],
            "budget_ms": case["budget_ms"],
            "started_at": "2026-09-28T00:00:00+00:00",
        },
    )
    if failed:
        _put(attempt / "failure.json", {"type": "RuntimeError", "message": "scripted failure"})
    else:
        capture_sha = _put(
            attempt / "capture.json",
            {
                "case_id": case["case_id"],
                "contract": {
                    "visible_input_sha256": case["visible_input_sha256"],
                    "initial_evidence_sha256": case["initial_evidence_sha256"],
                    "action_contract_sha256": case["action_contract_sha256"],
                },
            },
        )
        _put(attempt / "capture.sha256.json", {"sha256": capture_sha})
    if scored:
        _put(
            attempt / f"score-{scorer_revision}.json",
            {
                "scorer_revision": scorer_revision,
                "status": "failed" if failed else "completed",
                "fast_choice_execution_links": 0 if failed else 1,
                "deep_choice_execution_links": 0,
                "fast_useful_check_choices": 0 if failed else 1,
                "deep_useful_check_choices": 0,
                "fast_complete_mechanical_loops": 0 if failed else 1,
                "deep_complete_mechanical_loops": 0,
                "fast_complete_useful_observation_loops": 0 if failed else 1,
                "deep_complete_useful_observation_loops": 0,
                "deep_proposed_execution": "unknown_legacy_or_missing_receipt_table"
                if legacy_deep
                else "no_verified_deep_origin",
                "useful_choice_observed": not failed,
                "semantic_correctness": "human_review_pending",
                "route_realization": {"status": "demonstrated"},
                "metrics": {
                    "case_started_at": "2026-09-28T00:00:00+00:00",
                    "case_finished_at": "2026-09-28T00:00:02+00:00",
                    "completed_mailbox_durations_ms": [1200],
                    "completed_mailbox_duration_kind": "mailbox_wall_time_not_pure_model_latency",
                    "raw_invalid_retries": 1,
                    "raw_invalid_retry_metric_scope": "validation_retry_prompts_lower_bound",
                    "laya_worker_calls": None,
                    "resource_observations": [],
                },
            },
        )
    return attempt


def test_report_keeps_all_attempts_failures_missing_scores_and_legacy_unknown(
    tmp_path: Path,
) -> None:
    suite, case = _suite(tmp_path)
    root = tmp_path / "attempts"
    scorer = "e" * 40
    baseline = "a" * 40
    candidate = "b" * 40
    _attempt(
        root,
        suite.sha256,
        case,
        name="attempt-base",
        phase="development_baseline",
        code_revision=baseline,
        baseline_revision=baseline,
        candidate_revision=None,
        scorer_revision=scorer,
        legacy_deep=True,
    )
    _attempt(
        root,
        suite.sha256,
        case,
        name="attempt-candidate",
        phase="development_candidate",
        code_revision=candidate,
        baseline_revision=baseline,
        candidate_revision=candidate,
        scorer_revision=scorer,
    )
    _attempt(
        root,
        suite.sha256,
        case,
        name="attempt-failed",
        phase="development_candidate",
        code_revision=candidate,
        baseline_revision=baseline,
        candidate_revision=candidate,
        scorer_revision=scorer,
        failed=True,
    )
    _attempt(
        root,
        suite.sha256,
        case,
        name="attempt-unscored",
        phase="development_candidate",
        code_revision=candidate,
        baseline_revision=baseline,
        candidate_revision=candidate,
        scorer_revision=scorer,
        scored=False,
    )

    report = summarize_attempts(suite, root, scorer, "d" * 64)
    assert report["attempt_count"] == 4
    attempts = {row["attempt_id"]: row for row in report["attempts"]}
    assert attempts["attempt-failed"]["failure_sha256"] is not None
    assert attempts["attempt-failed"]["capture_state"] == "missing_with_failure"
    assert attempts["attempt-unscored"]["score_state"] == "missing"
    assert (
        attempts["attempt-base"]["deep_origin_attribution"]
        == "unknown_legacy_or_missing_receipt_table"
    )
    assert attempts["attempt-candidate"]["metrics"]["case_elapsed_ms"] == 2000
    assert (
        attempts["attempt-candidate"]["metrics"]["raw_invalid_retry_metric_scope"]
        == "validation_retry_prompts_lower_bound"
    )
    assert report["mechanical_totals"]["fast_complete_useful_observation_loops"] == 2
    assert report["mechanical_totals"]["unknown_score_attempts"] == 1
    assert len(report["comparison_pairs"]) == 3
    assert all(pair["matched_normalized_starting_contract"] for pair in report["comparison_pairs"])
    assert len(report["groups"]) == 2


def test_review_sidecar_requires_exact_attempt_and_score_hash(tmp_path: Path) -> None:
    suite, case = _suite(tmp_path)
    root = tmp_path / "attempts"
    scorer = "e" * 40
    attempt = _attempt(
        root,
        suite.sha256,
        case,
        name="attempt-reviewed",
        phase="development_baseline",
        code_revision="a" * 40,
        baseline_revision="a" * 40,
        candidate_revision=None,
        scorer_revision=scorer,
    )
    score_sha = hashlib.sha256((attempt / f"score-{scorer}.json").read_bytes()).hexdigest()
    reviews = tmp_path / "reviews.json"
    _put(
        reviews,
        {
            "schema_version": 1,
            "reviews": [
                {
                    "attempt_id": attempt.name,
                    "score_sha256": score_sha,
                    "review": {"semantic_correctness": "reviewer_pass", "notes": "scripted"},
                }
            ],
        },
    )
    report = summarize_attempts(suite, root, scorer, "d" * 64, reviews_path=reviews)
    assert report["attempts"][0]["semantic_review"] == {
        "semantic_correctness": "reviewer_pass",
        "notes": "scripted",
    }
    assert report["mechanical_totals"].get("semantic_passes") is None
    write_report(tmp_path / "report.json", report)
    with pytest.raises(FileExistsError):
        write_report(tmp_path / "report.json", report)
    _put(
        reviews,
        {
            "schema_version": 1,
            "reviews": [
                {
                    "attempt_id": attempt.name,
                    "score_sha256": "0" * 64,
                    "review": {"semantic_correctness": "reviewer_pass"},
                }
            ],
        },
    )
    with pytest.raises(ValueError, match="score hash"):
        summarize_attempts(suite, root, scorer, "d" * 64, reviews_path=reviews)


def test_report_flags_corrupt_capture_and_start_without_dropping_attempt(tmp_path: Path) -> None:
    suite, case = _suite(tmp_path)
    root = tmp_path / "attempts"
    scorer = "e" * 40
    attempt = _attempt(
        root,
        suite.sha256,
        case,
        name="attempt-corrupt",
        phase="development_baseline",
        code_revision="a" * 40,
        baseline_revision="a" * 40,
        candidate_revision=None,
        scorer_revision=scorer,
    )
    (attempt / "capture.json").write_text("{}", encoding="utf-8")
    (attempt / "start.json").write_text("{}", encoding="utf-8")
    report = summarize_attempts(suite, root, scorer, "d" * 64)
    assert report["attempt_count"] == 1
    row = report["attempts"][0]
    assert row["capture_state"] == "digest_mismatch"
    assert "start_case_binding_mismatch" in row["integrity_errors"]
    assert report["mechanical_totals"]["fast_complete_useful_observation_loops"] == 0


def test_matching_capture_digest_cannot_hide_wrong_frozen_contract(tmp_path: Path) -> None:
    suite, case = _suite(tmp_path)
    root = tmp_path / "attempts"
    scorer = "e" * 40
    attempt = _attempt(
        root,
        suite.sha256,
        case,
        name="attempt-copied",
        phase="development_baseline",
        code_revision="a" * 40,
        baseline_revision="a" * 40,
        candidate_revision=None,
        scorer_revision=scorer,
    )
    capture_path = attempt / "capture.json"
    capture = json.loads(capture_path.read_text(encoding="utf-8"))
    capture["contract"]["action_contract_sha256"] = "0" * 64
    changed_sha = _put(capture_path, capture)
    _put(attempt / "capture.sha256.json", {"sha256": changed_sha})

    report = summarize_attempts(suite, root, scorer, "d" * 64)
    row = report["attempts"][0]
    assert row["capture_state"] == "contract_mismatch"
    assert row["score_state"] == "present_untrusted"
    assert report["mechanical_totals"]["fast_complete_useful_observation_loops"] == 0


def test_report_accepts_actual_failed_attempt_score_shape(tmp_path: Path) -> None:
    suite, case = _suite(tmp_path)
    oracle = tmp_path / "oracle.json"
    oracle_sha = _put(
        oracle,
        {"schema_version": 1, "suite_sha256": suite.sha256, "cases": {case["case_id"]: {}}},
    )
    root = tmp_path / "attempts"
    revision = "a" * 40
    scorer = "e" * 40

    def fail(_visible: VisibleCase, _arm: str, _attempt: Path) -> dict[str, object]:
        raise RuntimeError("scripted runner failure")

    attempt = run_attempt(
        suite,
        str(case["case_id"]),
        RunStamp("development_baseline", "laya_sol", revision, revision, None, oracle_sha),
        root,
        fail,
    )
    score_attempt(attempt, suite, oracle, oracle_sha, score_revision=scorer)
    report = summarize_attempts(suite, root, scorer, oracle_sha)
    row = report["attempts"][0]
    assert row["score_state"] == "present"
    assert row["capture_state"] == "missing_with_failure"
    assert row["failure_state"] == "present"
    assert row["mechanical"]["fast_complete_useful_observation_loops"] == 0
