"""The alpha scorecard must count incomplete cases without hiding their time."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from benchmarks.private_alpha_score import (
    _applied_scoped_review,  # pyright: ignore[reportPrivateUsage]
    _case_record,  # pyright: ignore[reportPrivateUsage]
    _specific_finding,  # pyright: ignore[reportPrivateUsage]
    _validate_pair_metadata,  # pyright: ignore[reportPrivateUsage]
)


def test_failed_case_keeps_elapsed_time_and_product_task_outcome(tmp_path: Path) -> None:
    case_dir = tmp_path / "case-a"
    case_dir.mkdir()
    (case_dir / "failure.json").write_text(
        json.dumps({"elapsed_ms": 4231.0, "error_type": "TimeoutError"}), encoding="utf-8"
    )
    (case_dir / "product-case.json").write_text(
        json.dumps(
            {
                "evidence": [
                    {
                        "probe_id": "task.loopback_http",
                        "status": "observed",
                        "facts": {"outcome": "http_503"},
                    }
                ]
            }
        ),
        encoding="utf-8",
    )

    result = _case_record(tmp_path, "case-a", "http_503", "model")

    assert result["completed"] is False
    assert result["elapsed_ms"] == 4231.0
    assert result["task_outcome_inside_product"] == "http_503"
    assert result["automated_useful_finding_candidate"] is False
    assert result["synthetic_access_control"] is False
    assert result["semantic_review_required"] is True


def test_basic_route_can_earn_observation_credit_without_a_model_review() -> None:
    case = {
        "summary": "Exact local health GET returned HTTP 503. The endpoint answered, "
        "but its application-internal reason remains unknown.",
        "stop_reason": "No eligible unused probe can distinguish the remaining explanations.",
        "evidence": [
            {
                "probe_id": "task.loopback_http",
                "status": "observed",
                "facts": {"outcome": "http_503"},
            }
        ],
    }

    assert _specific_finding(case, "http_503", "http_503", "basic")
    assert not _specific_finding(case, "no_listener", "timeout", "basic")


@pytest.mark.parametrize(
    ("mode", "later"),
    [
        ("no_listener", "A later complete listener-table search found no listener on that port"),
        ("stall", "A later listener snapshot found an owner on that port"),
    ],
)
def test_basic_listener_distinction_requires_observed_check_and_time_limit(
    mode: str, later: str
) -> None:
    summary = (
        f"The exact local health GET ended in timeout. {later}, but it does not "
        "establish listener state or request handling during the GET. "
        "The request-time cause remains unresolved."
    )
    case = {
        "summary": summary,
        "evidence": [{"probe_id": "network.listeners", "status": "observed"}],
    }
    assert _specific_finding(case, mode, "timeout", "basic")
    assert not _specific_finding({**case, "evidence": []}, mode, "timeout", "basic")
    assert not _specific_finding(
        {**case, "summary": summary.replace("remains unresolved", "was no listener")},
        mode,
        "timeout",
        "basic",
    )


def test_paired_score_rejects_different_source_revisions() -> None:
    model = {
        "route": "model",
        "split": "holdout",
        "case_manifest_sha256": "a" * 64,
        "evaluator_key_sha256": "b" * 64,
        "head": "c" * 40,
        "dirty_diff_sha256": "d" * 64,
    }
    basic = {**model, "route": "basic"}

    _validate_pair_metadata(model, basic, "a" * 64, "b" * 64)
    with pytest.raises(ValueError, match="source revision"):
        _validate_pair_metadata(model, {**basic, "head": "e" * 40}, "a" * 64, "b" * 64)
    with pytest.raises(ValueError, match="source revision"):
        _validate_pair_metadata(model, {**basic, "dirty_diff_sha256": "f" * 64}, "a" * 64, "b" * 64)


@pytest.mark.parametrize(
    ("mode", "task_outcome", "summary"),
    [
        (
            "healthy",
            "http_200_nonce_match",
            "The exact GET returned HTTP 200 with the matching nonce. "
            "No failure was reproduced in the observed requests.",
        ),
        (
            "http_503",
            "http_503",
            "The exact GET returned HTTP 503. The response reached a handler, "
            "but its request-time reason is not observable.",
        ),
        (
            "stall",
            "timeout",
            "The exact GET timed out twice. A listener snapshot bound port 61234 "
            "to an owner. Its CPU sample does not prove which handler ran or why "
            "it did not respond.",
        ),
    ],
)
def test_model_scoped_observation_does_not_depend_on_old_stop_sentence(
    mode: str, task_outcome: str, summary: str
) -> None:
    case = {
        "summary": summary,
        "summary_source": "coordinator",
        "stop_reason": "Exact task and listener were used in an applied deep review.",
        "evidence": [{"probe_id": "network.listeners", "status": "observed"}],
    }
    assert _specific_finding(case, mode, task_outcome, "model")
    assert not _specific_finding(
        {**case, "summary_source": "advisory_async"}, mode, task_outcome, "model"
    )


def test_both_routes_credit_observed_change_without_claiming_its_cause() -> None:
    model = {
        "summary_source": "coordinator",
        "summary": "The exact GET returned HTTP 200 with the matching nonce. "
        "A later exact request failed after that successful response. "
        "The different request outcomes establish changed behavior, not its cause.",
        "evidence": [{"probe_id": "network.listeners", "status": "observed"}],
    }
    basic: dict[str, Any] = {
        "summary": "The exact health GET ended in http_200_nonce_match. "
        "A later exact request ended in http_503. "
        "These observations do not identify the earlier request's cause.",
        "evidence": [],
    }
    assert _specific_finding(model, "intermittent", "http_200_nonce_match", "model")
    assert _specific_finding(basic, "intermittent", "http_200_nonce_match", "basic")


@pytest.mark.parametrize(
    ("mode", "outcome", "summary"),
    [
        (
            "healthy",
            "http_200_nonce_match",
            "The exact health GET ended in http_200_nonce_match. "
            "No failure was reproduced in these exact requests.",
        ),
        (
            "http_503",
            "http_503",
            "The exact health GET ended in http_503. These observations do not "
            "identify the earlier request's cause.",
        ),
        (
            "wrong_nonce",
            "wrong_response",
            "The exact health GET ended in wrong_response. These observations do not "
            "identify the earlier request's cause.",
        ),
    ],
)
def test_basic_task_outcome_is_scored_with_current_wording(
    mode: str, outcome: str, summary: str
) -> None:
    assert _specific_finding({"summary": summary}, mode, outcome, "basic")


def test_scoped_review_requires_same_case_task_and_listener_in_applied_result(
    tmp_path: Path,
) -> None:
    database = tmp_path / "cases.db"
    case: dict[str, Any] = {
        "case_id": "case-a",
        "summary_source": "coordinator",
        "evidence": [
            {"probe_id": "task.loopback_http", "status": "observed", "evidence_id": "task-a"},
            {"probe_id": "network.listeners", "status": "observed", "evidence_id": "listener-a"},
        ],
    }
    with sqlite3.connect(database) as conn:
        conn.execute(
            "CREATE TABLE deep_mailbox "
            "(case_id TEXT, status TEXT, task_json TEXT, result_json TEXT)"
        )
        conn.execute(
            "INSERT INTO deep_mailbox VALUES (?,?,?,?)",
            (
                "case-a",
                "applied",
                json.dumps(
                    {
                        "request": {
                            "evidence_context": [
                                {"evidence_id": "task-a"},
                                {"evidence_id": "listener-a"},
                            ]
                        }
                    }
                ),
                json.dumps(
                    {
                        "response": {
                            "degraded": False,
                            "provider": {"provider_id": "codex-subscription-reasoning"},
                            "considered_evidence_ids": ["task-a", "listener-a"],
                        }
                    }
                ),
            ),
        )
    assert _applied_scoped_review(case, database)
    assert not _applied_scoped_review({**case, "case_id": "other-case"}, database)
    assert not _applied_scoped_review(
        {
            **case,
            "evidence": [
                {**case["evidence"][0]},
                {**case["evidence"][1], "evidence_id": "other-listener"},
            ],
        },
        database,
    )
