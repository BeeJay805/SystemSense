from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from systemsense.domain.ids import EvidenceId
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus

NOW = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)


def test_evidence_context_carries_bounded_redacted_content() -> None:
    context = EvidenceContext(
        evidence_id=EvidenceId.new(),
        observed_at=NOW,
        captured_at=NOW + timedelta(seconds=1),
        probe_id="application.snapshot",
        summary="Process exited with code 1.",
        facts={"process.exit_code": 1},
        status=EvidenceContextStatus.OBSERVED,
    )

    assert context.redaction_applied is True
    assert context.facts == {"process.exit_code": 1}


def test_evidence_context_marks_clock_order_uncertainty_without_rewriting_timestamps() -> None:
    common = {
        "evidence_id": EvidenceId.new(),
        "observed_at": NOW,
        "captured_at": NOW,
        "probe_id": "application.snapshot",
        "summary": "bounded",
        "status": "observed",
    }
    context = EvidenceContext.model_validate({**common, "observed_at": NOW + timedelta(seconds=1)})
    assert context.observed_at > context.captured_at
    assert "source_clock_after_capture" in context.limitations


def test_evidence_context_rejects_unbounded_or_invalid_content() -> None:
    common = {
        "evidence_id": EvidenceId.new(),
        "observed_at": NOW,
        "captured_at": NOW,
        "probe_id": "application.snapshot",
        "summary": "bounded",
        "status": "observed",
    }
    with pytest.raises(ValidationError, match="facts"):
        EvidenceContext.model_validate(
            {**common, "facts": {f"fact.{index}": index for index in range(33)}}
        )
    with pytest.raises(ValidationError, match="facts content"):
        EvidenceContext.model_validate({**common, "facts": {"message": "x" * 8193}})
    with pytest.raises(ValidationError, match="redaction_applied"):
        EvidenceContext.model_validate({**common, "redaction_applied": False})
