from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from systemsense.domain.diagnostic_progress import (
    DiagnosticProgressContextV1,
    DiagnosticProgressScopeV1,
)
from systemsense.domain.ids import CaseId, EvidenceId
from systemsense.domain.probes import MeasurementWindow


def progress_context(*, observed: bool | None = True) -> DiagnosticProgressContextV1:
    now = datetime(2026, 9, 24, tzinfo=UTC)
    return DiagnosticProgressContextV1(
        question_id="wlan.association.next",
        branch_id="wlan.association",
        uncertainty_id="wlan.association_state",
        predicate_id="network.wifi_associated",
        scope=DiagnosticProgressScopeV1(
            case_id=CaseId.new(),
            target_handle="11f51fe3-6175-437e-825b-d8a74d3c64aa",
            window=MeasurementWindow(start=now, end=now + timedelta(seconds=30)),
        ),
        terminal_status="evaluated",
        observed=observed,
        reason="Observed the next scoped association state.",
        evidence_ids=(EvidenceId.new(),),
        matched_alternative_ids=("wlan.associated",),
        disfavored_alternative_ids=("wlan.disconnected",),
        unresolved_assumption_ids=(),
        custody_status="verified",
        unknown=False,
        dead_end=False,
        branch_dead_end_count=0,
    )


def test_progress_context_roundtrips_exact_scoped_terminal() -> None:
    context = progress_context()
    assert DiagnosticProgressContextV1.model_validate_json(context.model_dump_json()) == context


def test_progress_context_accepts_cited_negative_state() -> None:
    context = progress_context()
    negative = DiagnosticProgressContextV1.model_validate(
        {
            **context.model_dump(mode="json"),
            "observed": False,
            "matched_alternative_ids": ["wlan.disconnected"],
            "disfavored_alternative_ids": ["wlan.associated"],
        }
    )
    assert negative.observed is False


def test_progress_context_rejects_uncited_boolean_and_conflicting_alternatives() -> None:
    context = progress_context()
    with pytest.raises(ValidationError):
        DiagnosticProgressContextV1.model_validate(
            {**context.model_dump(mode="json"), "evidence_ids": []}
        )
    with pytest.raises(ValidationError):
        DiagnosticProgressContextV1.model_validate(
            {
                **context.model_dump(mode="json"),
                "disfavored_alternative_ids": ["wlan.associated"],
            }
        )


def test_progress_context_keeps_all_terminal_citations() -> None:
    context = progress_context()
    evidence_ids = tuple(EvidenceId.new() for _ in range(9))
    enriched = DiagnosticProgressContextV1.model_validate(
        {**context.model_dump(mode="json"), "evidence_ids": evidence_ids}
    )
    assert enriched.evidence_ids == evidence_ids


def test_progress_context_rejects_noncanonical_scope_and_wrong_state_match() -> None:
    context = progress_context()
    with pytest.raises(ValidationError):
        DiagnosticProgressScopeV1.model_validate(
            {**context.scope.model_dump(mode="json"), "target_handle": "C:\\Windows"}
        )
    with pytest.raises(ValidationError):
        DiagnosticProgressContextV1.model_validate(
            {
                **context.model_dump(mode="json"),
                "matched_alternative_ids": ["wlan.disconnected"],
                "disfavored_alternative_ids": ["wlan.associated"],
            }
        )


def test_progress_context_rejects_string_boolean_at_validation_boundary() -> None:
    context = progress_context()
    with pytest.raises(ValidationError):
        DiagnosticProgressContextV1.model_validate(
            {**context.model_dump(mode="json"), "observed": "true"}
        )


def test_unknown_progress_explicitly_preserves_dead_end_and_limitations() -> None:
    context = progress_context()
    unknown = DiagnosticProgressContextV1.model_validate(
        {
            **context.model_dump(mode="json"),
            "terminal_status": "failed",
            "observed": None,
            "evidence_ids": [],
            "matched_alternative_ids": [],
            "disfavored_alternative_ids": [],
            "custody_status": "missing",
            "unknown": True,
            "dead_end": True,
            "branch_dead_end_count": 1,
        }
    )
    assert unknown.observed is None
    with pytest.raises(ValidationError):
        DiagnosticProgressContextV1.model_validate(
            {**unknown.model_dump(mode="json"), "unknown": False}
        )
