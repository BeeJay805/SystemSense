import json
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest
from pydantic import ValidationError

from systemsense.decision.contracts import DecisionRequest, ProbeCapability, ProviderIdentity
from systemsense.decision.laya import LayaDecisionProvider
from systemsense.decision.ollama import OllamaDecisionProvider
from systemsense.domain.diagnostic_progress import DiagnosticProgressContextV1
from systemsense.domain.ids import CaseId, EvidenceId
from systemsense.inference.ollama import OllamaChatClient
from systemsense.inference.settings import LocalInferenceConfig
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.reasoning.contracts import (
    ReasoningRequest,
    ReasoningResponse,
    ReasoningStatus,
    ReasoningValidationError,
)
from systemsense.reasoning.ollama import OllamaReasoningProvider


def _request_values() -> dict[str, object]:
    return {
        "case_id": CaseId.new(),
        "state_version": 1,
        "correlation_id": "corr_progress",
        "deadline_at": datetime.now(UTC) + timedelta(minutes=1),
        "available_probes": (
            ProbeCapability(
                probe_id="network.connectivity",
                description="Read-only connectivity snapshot",
                cost_ms=100,
                resource_class=ResourceClass.CPU,
            ),
        ),
        "budget_ms": 500,
        "max_probes": 1,
    }


def _context(case_id: CaseId) -> DiagnosticProgressContextV1:
    now = datetime.now(UTC)
    return DiagnosticProgressContextV1.model_validate(
        {
            "question_id": "wlan.association.next",
            "branch_id": "wlan.association",
            "uncertainty_id": "wlan.association_state",
            "predicate_id": "network.wifi_associated",
            "scope": {
                "case_id": str(case_id),
                "target_handle": "11f51fe3-6175-437e-825b-d8a74d3c64aa",
                "window": {"start": now, "end": now + timedelta(seconds=30)},
            },
            "terminal_status": "unknown",
            "observed": None,
            "reason": "No unambiguous scoped WLAN state was observed.",
            "evidence_ids": (EvidenceId.new(),),
            "matched_alternative_ids": (),
            "disfavored_alternative_ids": (),
            "unresolved_assumption_ids": ("wlan.association_state",),
            "custody_status": "verified",
            "unknown": True,
            "dead_end": True,
            "branch_dead_end_count": 1,
        }
    )


@pytest.mark.parametrize(
    "request_type,text_field", [(DecisionRequest, "symptom"), (ReasoningRequest, "objective")]
)
def test_diagnostic_progress_requires_request_schema_four(
    request_type: type[DecisionRequest] | type[ReasoningRequest], text_field: str
) -> None:
    values = _request_values()
    values[text_field] = "WLAN association is unresolved"
    context = _context(cast(CaseId, values["case_id"]))
    current = request_type.model_validate(
        {**values, "schema_version": 4, "diagnostic_progress": (context,)}
    )
    assert current.diagnostic_progress == (context,)
    for schema_version in (1, 2, 3):
        old = request_type.model_validate({**values, "schema_version": schema_version})
        assert old.diagnostic_progress == ()
        with pytest.raises(ValidationError, match="diagnostic progress"):
            request_type.model_validate(
                {**values, "schema_version": schema_version, "diagnostic_progress": (context,)}
            )


@pytest.mark.parametrize(
    "request_type,text_field", [(DecisionRequest, "symptom"), (ReasoningRequest, "objective")]
)
def test_diagnostic_progress_is_bounded_to_eight_and_current_case(
    request_type: type[DecisionRequest] | type[ReasoningRequest], text_field: str
) -> None:
    values = _request_values()
    values[text_field] = "WLAN association is unresolved"
    context = _context(cast(CaseId, values["case_id"]))
    with pytest.raises(ValidationError):
        request_type.model_validate(
            {**values, "schema_version": 4, "diagnostic_progress": (context,) * 9}
        )
    foreign = _context(CaseId.new())
    with pytest.raises(ValidationError, match="case"):
        request_type.model_validate(
            {**values, "schema_version": 4, "diagnostic_progress": (foreign,)}
        )


def test_laya_worker_state_contains_scoped_unknown_progress() -> None:
    values = _request_values()
    values["symptom"] = "WLAN association unresolved"
    context = _context(cast(CaseId, values["case_id"]))
    request = DecisionRequest.model_validate(
        {**values, "schema_version": 4, "diagnostic_progress": (context,)}
    )
    state = LayaDecisionProvider.state_for_laya(request)
    assert state["diagnostic_progress"] == [context.model_dump(mode="json")]


def test_request_schema_four_keeps_catalog_only_evidence_out_of_deep_citations() -> None:
    values = _request_values()
    values["objective"] = "Explain WLAN failure"
    evidence_id = EvidenceId.new()
    request = ReasoningRequest.model_validate(
        {**values, "schema_version": 4, "evidence_ids": (evidence_id,)}
    )
    response = ReasoningResponse(
        schema_version=3,
        provider=ProviderIdentity(
            provider_id="test-reasoner", provider_version="1", role="reasoning"
        ),
        case_id=request.case_id,
        state_version=request.state_version,
        correlation_id=request.correlation_id,
        deadline_at=request.deadline_at,
        status=ReasoningStatus.UNRESOLVED,
        summary="Cause unknown.",
        considered_evidence_ids=(evidence_id,),
    )
    with pytest.raises(ReasoningValidationError, match="catalog-only"):
        response.validate_against(request)


@pytest.mark.parametrize("role", ["decision", "reasoning"])
def test_ollama_actual_prompt_contains_scoped_unknown_progress(
    monkeypatch: pytest.MonkeyPatch, role: str
) -> None:
    values = _request_values()
    context = _context(cast(CaseId, values["case_id"]))
    captured: list[dict[str, object]] = []

    def complete(
        _self: OllamaChatClient,
        *,
        model: str,
        prompt: str,
        schema: dict[str, object],
        timeout_seconds: float,
    ) -> dict[str, object]:
        del model, schema, timeout_seconds
        captured.append(json.loads(prompt))
        return (
            {"summary": "Cause remains unknown.", "hypotheses": []}
            if role == "reasoning"
            else {"proposals": []}
        )

    monkeypatch.setattr(OllamaChatClient, "complete", complete)

    def fits_context(_self: OllamaChatClient, prompt: str, schema: dict[str, object]) -> bool:
        del prompt, schema
        return True

    monkeypatch.setattr(OllamaChatClient, "fits_context", fits_context)
    if role == "reasoning":
        values["objective"] = "Explain WLAN failure"
        request = ReasoningRequest.model_validate(
            {**values, "schema_version": 4, "diagnostic_progress": (context,)}
        )
        OllamaReasoningProvider(
            LocalInferenceConfig(enabled=True, reasoning_model="small-local")
        ).investigate(request)
    else:
        values["symptom"] = "WLAN association unresolved"
        request = DecisionRequest.model_validate(
            {**values, "schema_version": 4, "diagnostic_progress": (context,)}
        )
        OllamaDecisionProvider(
            LocalInferenceConfig(enabled=True, decision_model="small-local")
        ).decide(request)
    assert captured
    assert captured[0]["diagnostic_progress"] == [context.model_dump(mode="json")]
