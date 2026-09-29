"""The alpha scorecard must count incomplete cases without hiding their time."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks.private_alpha_score import (
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
