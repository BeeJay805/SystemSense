"""Candidate IDs are model-visible references, never executable invocations."""

from datetime import UTC, datetime, timedelta

import pytest

from systemsense.decision.candidates import (
    AdmittedCandidateRefV1,
    CandidateDecisionRequestV1,
    CandidateDecisionResponseV1,
    CandidateProposalV1,
    candidate_decision_request_json,
    candidate_decision_request_sha256,
)
from systemsense.decision.contracts import (
    DecisionPresentationTrace,
    DecisionRequest,
    DiagnosticPurpose,
    ProviderIdentity,
    presentation_payload_sha256,
)
from systemsense.domain.ids import CaseId, JsonValue
from systemsense.domain.probes import SafetyClass
from systemsense.orchestration.scheduler import ResourceClass


def _candidate(
    suffix: str, *, description: str = "Selected application pressure"
) -> AdmittedCandidateRefV1:
    return AdmittedCandidateRefV1(
        candidate_id="cand_v1_" + suffix * 32,
        probe_id="application.target_pressure",
        description=description,
        manifest_sha256="a" * 64,
        invocation_sha256=suffix * 64,
        cost_ms=1000,
        resource_class=ResourceClass.PROCESS,
        safety_class=SafetyClass.R1,
    )


def _request() -> CandidateDecisionRequestV1:
    return CandidateDecisionRequestV1(
        case_id=CaseId.new(),
        state_version=7,
        correlation_id="candidate:case:7",
        deadline_at=datetime.now(UTC) + timedelta(seconds=30),
        symptom="Which PDF process is slow?",
        available_candidates=(_candidate("a"), _candidate("b")),
        budget_ms=4000,
        max_candidates=1,
    )


def test_two_instances_of_one_probe_are_distinct_and_order_is_frozen() -> None:
    request = _request()
    assert [item.probe_id for item in request.available_candidates] == [
        "application.target_pressure",
        "application.target_pressure",
    ]
    assert (
        request.candidate_manifest_sha256
        != request.model_copy(
            update={"available_candidates": tuple(reversed(request.available_candidates))}
        ).candidate_manifest_sha256
    )
    assert CandidateDecisionRequestV1.model_validate_json(request.model_dump_json()) == request
    assert candidate_decision_request_json(request) == candidate_decision_request_json(
        CandidateDecisionRequestV1.model_validate_json(request.model_dump_json())
    )
    assert candidate_decision_request_sha256(request) != candidate_decision_request_sha256(
        request.model_copy(update={"state_version": request.state_version + 1})
    )
    with pytest.raises(ValueError):
        CandidateDecisionRequestV1.model_validate(
            request.model_dump() | {"available_candidates": [request.available_candidates[0]] * 2}
        )


def test_response_requires_exact_candidate_permutation_and_bounded_proposals() -> None:
    request = _request()
    ids = tuple(item.candidate_id for item in request.available_candidates)
    response = CandidateDecisionResponseV1(
        provider=ProviderIdentity(
            provider_id="laya-local-decision", provider_version="1", role="fast_decision"
        ),
        case_id=request.case_id,
        state_version=request.state_version,
        correlation_id=request.correlation_id,
        deadline_at=request.deadline_at,
        ranked_candidate_ids=tuple(reversed(ids)),
        considered_candidate_ids=ids,
        proposals=(
            CandidateProposalV1(
                candidate_id=ids[1], purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES, priority=1.0
            ),
        ),
    ).validate_against(request)
    assert response.proposals[0].candidate_id == ids[1]
    for ranked in ((ids[0],), (ids[0], ids[0]), (ids[0], "cand_v1_" + "c" * 32)):
        with pytest.raises(ValueError):
            response.model_copy(update={"ranked_candidate_ids": ranked}).validate_against(request)
    with pytest.raises(ValueError):
        response.model_copy(update={"considered_candidate_ids": (ids[0],)}).validate_against(
            request
        )
    with pytest.raises(ValueError):
        response.model_copy(
            update={
                "proposals": (
                    CandidateProposalV1(
                        candidate_id=ids[0], purpose=DiagnosticPurpose.CHECK_COVERAGE, priority=1.0
                    ),
                )
            }
        ).validate_against(request)
    forged_payload: dict[str, JsonValue] = {
        "candidate_manifest_sha256": "0" * 64,
        "ordered_candidates": [],
        "microbatches": [],
    }
    forged_trace = DecisionPresentationTrace(
        provider=response.provider,
        format_id="laya-worker-candidate-attention-v1",
        payload=forged_payload,
        payload_sha256=presentation_payload_sha256(forged_payload),
    )
    with pytest.raises(ValueError, match="trace binding"):
        response.model_copy(update={"presentation_trace": forged_trace}).validate_against(request)


def test_model_cannot_attach_selectors_and_legacy_contract_cannot_masquerade() -> None:
    request = _request()
    with pytest.raises(ValueError):
        AdmittedCandidateRefV1.model_validate(
            request.available_candidates[0].model_dump() | {"target_handle": "proc_secret"}
        )
    with pytest.raises(ValueError):
        CandidateProposalV1.model_validate(
            {
                "candidate_id": request.available_candidates[0].candidate_id,
                "purpose": "refresh_evidence",
                "priority": 1.0,
                "parameters": {"pid": 123},
            }
        )
    with pytest.raises(ValueError):
        DecisionRequest.model_validate(request.model_dump())
    with pytest.raises(ValueError):
        CandidateDecisionRequestV1.model_validate(
            {"schema_version": 3, **request.model_dump(exclude={"schema_version"})}
        )
