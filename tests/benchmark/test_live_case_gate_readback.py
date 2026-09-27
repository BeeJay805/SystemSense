"""A real model response is an opportunity, not an independently labeled answer."""

from __future__ import annotations

from typing import Any

import pytest

from benchmarks.live_case_gate_readback import review_live_case

CASE = "case_" + "a" * 32
EVIDENCE = "ev_" + "b" * 32
OTHER = "ev_" + "c" * 32


def _detail(evidence_id: str, literal: str) -> dict[str, object]:
    return {"evidence_id": evidence_id, "match_literals": [literal]}


def _applied(
    *, detail: dict[str, object], support: str = EVIDENCE
) -> tuple[str, dict[str, Any], dict[str, Any]]:
    return (
        "applied",
        {"request": {"case_id": CASE, "evidence_context": [{"evidence_id": EVIDENCE}]}},
        {
            "response": {
                "degraded": False,
                "considered_evidence_ids": [EVIDENCE],
                "hypotheses": [
                    {
                        "status": "unresolved",
                        "supporting_evidence_ids": [support],
                        "contradicting_evidence_ids": [],
                    }
                ],
                "requested_details": [detail],
            }
        },
    )


def test_applied_deep_citations_do_not_label_unverified_task_and_lost_detail() -> None:
    completed = _detail(EVIDENCE, "one")
    unaccounted = _detail(EVIDENCE, "two")
    report = {
        "case_id": CASE,
        "reported_task": {"source": "user_report", "verification": "unverified"},
        "assessment": None,
        "outcome": "budget_exhausted",
        "completed_probe_ids": ["network.configuration"],
        "completed_detail_requests": [completed],
        "requested_details": [],
        "provider_calls": [{"role": "reasoning", "degraded": False}] * 2,
    }

    review = review_live_case(
        report,
        (_applied(detail=completed), _applied(detail=unaccounted)),
    )

    assert review["applied_deep_results"] == 2
    assert review["valid_visible_citations"] == 2
    assert review["invalid_visible_citations"] == 0
    assert review["unaccounted_eligible_detail_requests"] == 1
    assert review["unknown_cause_opportunities"] == 2
    assert review["independently_supported_causes"] is None
    assert review["independently_wrong_causes"] is None
    assert review["first_evidence_gate"] == "affected_task_outcome_unverified"


def test_absent_citation_and_pending_detail_are_distinct_gaps() -> None:
    pending = _detail(EVIDENCE, "pending")
    report = {
        "case_id": CASE,
        "reported_task": {"source": "user_report", "verification": "unverified"},
        "assessment": None,
        "outcome": "budget_exhausted",
        "completed_probe_ids": [],
        "completed_detail_requests": [],
        "requested_details": [pending],
        "provider_calls": [],
    }
    review = review_live_case(report, (_applied(detail=pending, support=OTHER),))

    assert review["invalid_visible_citations"] == 1
    assert review["unaccounted_eligible_detail_requests"] == 0
    assert review["pending_detail_requests"] == 1
    assert review["unknown_cause_opportunities"] == 1


def test_mismatched_mailbox_case_is_not_replayed() -> None:
    report = {"case_id": CASE, "reported_task": None, "assessment": None}
    status, task, result = _applied(detail=_detail(EVIDENCE, "one"))
    task["request"]["case_id"] = "case_" + "d" * 32

    with pytest.raises(ValueError, match="mailbox case mismatch"):
        review_live_case(report, ((status, task, result),))
