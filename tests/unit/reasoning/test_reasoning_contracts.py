from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from systemsense.decision.contracts import (
    FastSignalKind,
    ProbeCapability,
    ProviderIdentity,
    ResourceClass,
)
from systemsense.domain.ids import CaseId, EntityId, EvidenceId
from systemsense.evidence.graph import (
    AssertionStatus,
    EvidenceRelation,
    MemoryLayer,
    RelationKind,
)
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.knowledge.windows_errors import WindowsErrorCatalog, WindowsErrorSource
from systemsense.reasoning.contracts import (
    FastAttentionConcern,
    Hypothesis,
    HypothesisStatus,
    ReasoningRequest,
    ReasoningResponse,
    ReasoningStatus,
    ReasoningValidationError,
)


def test_fast_concern_to_deep_brain_must_reference_visible_evidence() -> None:
    req = make_request()
    visible = EvidenceContext(
        evidence_id=req.evidence_ids[0],
        observed_at=datetime(2026, 9, 21, 12, 0, tzinfo=UTC),
        captured_at=datetime(2026, 9, 21, 12, 0, tzinfo=UTC),
        probe_id="application.snapshot",
        summary="Service status was observed",
        status=EvidenceContextStatus.OBSERVED,
    )
    concern = FastAttentionConcern(
        kind=FastSignalKind.CONTRADICTION_SUSPECTED,
        evidence_ids=(req.evidence_ids[0],),
        hypothesis_brief="A service dependency may be unavailable.",
    )
    admitted = ReasoningRequest.model_validate(
        {
            **req.model_dump(mode="json"),
            "evidence_context": [visible.model_dump(mode="json")],
            "fast_concerns": [concern.model_dump(mode="json")],
        }
    )
    assert admitted.fast_concerns == (concern,)
    with pytest.raises(ValidationError, match=r"fast concern.*evidence"):
        ReasoningRequest.model_validate(
            {
                **req.model_dump(mode="json"),
                "evidence_context": [visible.model_dump(mode="json")],
                "fast_concerns": [
                    concern.model_copy(update={"evidence_ids": (EvidenceId.new(),)}).model_dump(
                        mode="json"
                    )
                ],
            }
        )
    with pytest.raises(ValidationError, match=r"fast concern.*focused"):
        ReasoningRequest.model_validate(
            {
                **req.model_dump(mode="json"),
                "fast_concerns": [concern.model_dump(mode="json")],
            }
        )


def make_request() -> ReasoningRequest:
    return ReasoningRequest(
        case_id=CaseId.new(),
        state_version=2,
        correlation_id="corr_reasoning",
        deadline_at=datetime(2026, 9, 21, 12, 0, tzinfo=UTC) + timedelta(minutes=1),
        objective="explain the launch failure",
        evidence_ids=(EvidenceId.new(), EvidenceId.new()),
        available_probes=(
            ProbeCapability(
                probe_id="application.snapshot",
                description="application snapshot",
                keywords=frozenset({"launch"}),
                cost_ms=200,
                resource_class=ResourceClass.CPU,
            ),
        ),
        budget_ms=500,
        max_probes=2,
    )


def test_next_catalog_page_requires_available_complete_non_degraded_page() -> None:
    base = make_request()
    request = base.model_copy(update={"schema_version": 3, "catalog_has_more": True})
    response = ReasoningResponse(
        schema_version=3,
        provider=ProviderIdentity(
            provider_id="local-reasoner", provider_version="1", role="reasoning"
        ),
        case_id=request.case_id,
        state_version=request.state_version,
        correlation_id=request.correlation_id,
        deadline_at=request.deadline_at,
        status=ReasoningStatus.UNRESOLVED,
        summary="More catalog entries may matter.",
        request_next_catalog_page=True,
    )
    assert response.validate_against(request) == response
    with pytest.raises(ReasoningValidationError, match="catalog page"):
        response.validate_against(base)
    with pytest.raises(ReasoningValidationError, match="truncated"):
        response.model_copy(update={"catalog_page_truncated": True}).validate_against(request)
    with pytest.raises(ReasoningValidationError, match="degraded"):
        response.model_copy(update={"degraded": True}).validate_against(request)
    with pytest.raises(ValidationError, match="version 3"):
        ReasoningRequest.model_validate({**base.model_dump(mode="json"), "catalog_has_more": True})


def test_catalog_pagination_does_not_make_unretrieved_id_citable() -> None:
    base = make_request()
    visible = EvidenceContext(
        evidence_id=base.evidence_ids[0],
        observed_at=datetime(2026, 9, 21, 12, tzinfo=UTC),
        captured_at=datetime(2026, 9, 21, 12, tzinfo=UTC),
        probe_id="application.snapshot",
        summary="Observed launch state",
        status=EvidenceContextStatus.OBSERVED,
    )
    request = base.model_copy(
        update={
            "schema_version": 3,
            "catalog_has_more": True,
            "evidence_context": (visible,),
        }
    )
    response = ReasoningResponse(
        schema_version=3,
        provider=ProviderIdentity(
            provider_id="local-reasoner", provider_version="1", role="reasoning"
        ),
        case_id=request.case_id,
        state_version=request.state_version,
        correlation_id=request.correlation_id,
        deadline_at=request.deadline_at,
        status=ReasoningStatus.UNRESOLVED,
        summary="A known but unretrieved record might matter.",
        hypotheses=(
            Hypothesis(
                hypothesis_id="h_unretrieved",
                statement="Unretrieved record indicates failure.",
                status=HypothesisStatus.UNRESOLVED,
                supporting_evidence_ids=(base.evidence_ids[1],),
            ),
        ),
    )
    with pytest.raises(ReasoningValidationError, match="hypothesis references unknown evidence"):
        response.validate_against(request)


def test_catalog_only_id_cannot_be_marked_as_considered_fact() -> None:
    base = make_request()
    visible = EvidenceContext(
        evidence_id=base.evidence_ids[0],
        observed_at=datetime(2026, 9, 21, 12, tzinfo=UTC),
        captured_at=datetime(2026, 9, 21, 12, tzinfo=UTC),
        probe_id="application.snapshot",
        summary="Observed launch state",
        status=EvidenceContextStatus.OBSERVED,
    )
    request = base.model_copy(update={"schema_version": 3, "evidence_context": (visible,)})
    response = ReasoningResponse(
        schema_version=3,
        provider=ProviderIdentity(
            provider_id="local-reasoner", provider_version="1", role="reasoning"
        ),
        case_id=request.case_id,
        state_version=request.state_version,
        correlation_id=request.correlation_id,
        deadline_at=request.deadline_at,
        status=ReasoningStatus.UNRESOLVED,
        summary="Catalog metadata was not retrieved as a fact.",
        considered_evidence_ids=(base.evidence_ids[1],),
    )
    with pytest.raises(ReasoningValidationError, match="catalog-only evidence"):
        response.validate_against(request)


def _error_reference():  # type: ignore[no-untyped-def]
    catalog = WindowsErrorCatalog.from_constants(
        {"ERROR_ACCESS_DENIED": 5},
        message_resolver=lambda _code: "Access is denied.",
        source=WindowsErrorSource(
            catalog_provider="fixture",
            catalog_version="1",
            message_provider="fixture",
            os_version="fixture Windows",
            runtime_observed=False,
        ),
    )
    result = catalog.lookup_win32(5)
    assert result is not None
    return result


def test_reasoning_response_preserves_competing_evidence_links() -> None:
    req = make_request()
    response = ReasoningResponse(
        provider=ProviderIdentity(
            provider_id="local-reasoner", provider_version="1", role="reasoning"
        ),
        case_id=req.case_id,
        state_version=req.state_version,
        correlation_id=req.correlation_id,
        deadline_at=req.deadline_at,
        status=ReasoningStatus.UNRESOLVED,
        summary="Two explanations remain plausible.",
        hypotheses=(
            Hypothesis(
                hypothesis_id="h_missing_dependency",
                statement="A dependency may be unavailable.",
                status=HypothesisStatus.CONTESTED,
                supporting_evidence_ids=(req.evidence_ids[0],),
                contradicting_evidence_ids=(req.evidence_ids[1],),
                missing_evidence_ids=(req.evidence_ids[1],),
                distinguishing_probe_ids=("application.snapshot",),
            ),
            Hypothesis(
                hypothesis_id="h_configuration",
                statement="A configuration mismatch may block launch.",
                status=HypothesisStatus.UNRESOLVED,
                missing_evidence_ids=(req.evidence_ids[0],),
                distinguishing_probe_ids=("application.snapshot",),
            ),
        ),
        distinguishing_probes=(),
    )
    assert response.validate_against(req) == response


def test_reasoning_rejects_evidence_not_in_request() -> None:
    req = make_request()
    response = ReasoningResponse(
        provider=ProviderIdentity(
            provider_id="local-reasoner", provider_version="1", role="reasoning"
        ),
        case_id=req.case_id,
        state_version=req.state_version,
        correlation_id=req.correlation_id,
        deadline_at=req.deadline_at,
        status=ReasoningStatus.UNRESOLVED,
        summary="Insufficient evidence.",
        hypotheses=(
            Hypothesis(
                hypothesis_id="h_unknown",
                statement="Unknown",
                status=HypothesisStatus.UNRESOLVED,
                supporting_evidence_ids=(EvidenceId.new(),),
            ),
        ),
    )
    with pytest.raises(ReasoningValidationError, match="evidence"):
        response.validate_against(req)


def test_reasoning_rejects_stale_state() -> None:
    req = make_request()
    response = ReasoningResponse(
        provider=ProviderIdentity(
            provider_id="local-reasoner", provider_version="1", role="reasoning"
        ),
        case_id=req.case_id,
        state_version=req.state_version - 1,
        correlation_id=req.correlation_id,
        deadline_at=req.deadline_at,
        status=ReasoningStatus.UNRESOLVED,
        summary="Stale result.",
    )
    with pytest.raises(ReasoningValidationError, match="state_version"):
        response.validate_against(req)


def test_unavailable_reasoning_is_an_honest_degraded_result() -> None:
    req = make_request()
    from systemsense.reasoning.unavailable import UnavailableReasoningProvider

    result = UnavailableReasoningProvider().investigate(req)
    assert result.status is ReasoningStatus.UNAVAILABLE
    assert result.hypotheses == ()
    assert result.validate_against(req) == result


def test_reasoning_request_accepts_context_and_previous_hypotheses() -> None:
    req = make_request()
    previous = Hypothesis(
        hypothesis_id="h_previous",
        statement="A dependency may be unavailable.",
        status=HypothesisStatus.UNRESOLVED,
        supporting_evidence_ids=(req.evidence_ids[0],),
    )
    context = EvidenceContext(
        evidence_id=req.evidence_ids[0],
        observed_at=datetime(2026, 9, 21, 12, 0, tzinfo=UTC),
        captured_at=datetime(2026, 9, 21, 12, 0, tzinfo=UTC),
        probe_id="application.snapshot",
        summary="Dependency state was unavailable.",
        facts={"dependency.available": False},
        status=EvidenceContextStatus.OBSERVED,
    )

    enriched = req.model_copy(
        update={"evidence_context": (context,), "previous_hypotheses": (previous,)}
    )
    validated = ReasoningRequest.model_validate(enriched.model_dump())
    assert validated.previous_hypotheses == (previous,)


def test_reasoning_request_carries_bounded_typed_error_references() -> None:
    req = make_request()
    reference = _error_reference()

    validated = ReasoningRequest.model_validate(
        {**req.model_dump(mode="json"), "error_references": [reference.model_dump(mode="json")]}
    )

    assert validated.error_references == (reference,)
    with pytest.raises(ValidationError):
        ReasoningRequest.model_validate(
            {
                **req.model_dump(mode="json"),
                "error_references": [reference.model_dump(mode="json")] * 5,
            }
        )


def test_reasoning_request_priority_and_completed_ids_must_be_known_and_unique() -> None:
    req = make_request()
    known = req.evidence_ids

    validated = ReasoningRequest.model_validate(
        {
            **req.model_dump(mode="json"),
            "priority_evidence_ids": [str(known[0])],
            "completed_evidence_requests": [str(known[1])],
        }
    )

    assert validated.priority_evidence_ids == (known[0],)
    assert validated.completed_evidence_requests == (known[1],)
    for field in ("priority_evidence_ids", "completed_evidence_requests"):
        with pytest.raises(ValidationError, match="known evidence"):
            ReasoningRequest.model_validate(
                {**req.model_dump(mode="json"), field: [str(EvidenceId.new())]}
            )
        with pytest.raises(ValidationError, match="unique"):
            ReasoningRequest.model_validate(
                {**req.model_dump(mode="json"), field: [str(known[0]), str(known[0])]}
            )


def test_supported_hypothesis_requires_uncontested_support() -> None:
    req = make_request()
    unsupported = ReasoningResponse(
        provider=ProviderIdentity(
            provider_id="local-reasoner", provider_version="1", role="reasoning"
        ),
        case_id=req.case_id,
        state_version=req.state_version,
        correlation_id=req.correlation_id,
        deadline_at=req.deadline_at,
        status=ReasoningStatus.SUPPORTED,
        summary="Claimed support.",
        hypotheses=(
            Hypothesis(
                hypothesis_id="h_unsupported",
                statement="A cause was asserted without evidence.",
                status=HypothesisStatus.SUPPORTED,
            ),
        ),
    )
    with pytest.raises(ReasoningValidationError, match="supporting evidence"):
        unsupported.validate_against(req)

    evidence_id = req.evidence_ids[0]
    contradictory = unsupported.model_copy(
        update={
            "hypotheses": (
                unsupported.hypotheses[0].model_copy(
                    update={
                        "supporting_evidence_ids": (evidence_id,),
                        "contradicting_evidence_ids": (evidence_id,),
                    }
                ),
            )
        }
    )
    with pytest.raises(ReasoningValidationError, match="support and contradict"):
        contradictory.validate_against(req)

    no_supported_hypothesis = unsupported.model_copy(
        update={
            "hypotheses": (
                unsupported.hypotheses[0].model_copy(
                    update={
                        "status": HypothesisStatus.UNRESOLVED,
                        "supporting_evidence_ids": (evidence_id,),
                    }
                ),
            )
        }
    )
    with pytest.raises(ReasoningValidationError, match="supported hypothesis"):
        no_supported_hypothesis.validate_against(req)


def test_reasoning_request_accepts_only_evidence_grounded_relationships() -> None:
    req = make_request()
    relation = EvidenceRelation(
        relation_id="rel_abcdefabcdefabcdefabcdefabcdefab",
        source_entity_id=EntityId.new(),
        target_entity_id=EntityId.new(),
        relationship=RelationKind.DEPENDS_ON,
        memory_layer=MemoryLayer.MACHINE,
        assertion_status=AssertionStatus.OBSERVED,
        relation_version=1,
        evidence_ids=(req.evidence_ids[0],),
    )
    values = req.model_dump()
    values["relationships"] = (relation,)
    assert ReasoningRequest.model_validate(values).relationships == (relation,)

    values["relationships"] = (relation.model_copy(update={"evidence_ids": (EvidenceId.new(),)}),)
    with pytest.raises(ValidationError, match=r"relationship.*evidence"):
        ReasoningRequest.model_validate(values)
