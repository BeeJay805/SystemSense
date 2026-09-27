from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from systemsense.decision.contracts import (
    FastSignalKind,
    ProbeCapability,
    ProviderIdentity,
    ResourceClass,
)
from systemsense.domain.affected_task import SourceTaskRelationV1, TaskObservationContextV1
from systemsense.domain.ids import CaseId, EntityId, EvidenceId, ExecutionId
from systemsense.domain.probes import ProbePredictionOutputV1
from systemsense.evidence.graph import (
    AssertionStatus,
    EvidenceRelation,
    MemoryLayer,
    RelationKind,
)
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.knowledge.windows_errors import WindowsErrorCatalog, WindowsErrorSource
from systemsense.reasoning.contracts import (
    ExpectedFact,
    FastAttentionConcern,
    Hypothesis,
    HypothesisStatus,
    ReasoningRequest,
    ReasoningResponse,
    ReasoningStatus,
    ReasoningValidationError,
    SelectedSourceContextV1,
)


def test_selected_fixture_source_requires_visible_bound_task_and_exact_relation() -> None:
    base = make_request()
    start = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)
    task_id, source_id = base.evidence_ids
    task = TaskObservationContextV1(
        case_id=base.case_id,
        evidence_id=task_id,
        source_id="src_" + "a" * 64,
        collector_id="fixture.task_baseline",
        collector_version=1,
        execution_id=ExecutionId.new(),
        record_sha256="b" * 64,
        target_handle="synthetic:browser-profile:one",
        action="Navigate",
        expected="Success",
        observed="Failure",
        window_start=start,
        window_end=start + timedelta(seconds=1),
        sample_window_ms=1000,
        observed_at=start + timedelta(seconds=1),
        captured_at=start + timedelta(seconds=1),
        limitation="Synthetic fixture; no Windows task execution.",
    )
    relation = SourceTaskRelationV1(
        case_id=base.case_id,
        task_evidence_id=task_id,
        task_record_sha256=task.record_sha256,
        source_evidence_id=source_id,
        status="same_target_full_window",
    )
    selected = SelectedSourceContextV1(
        item_id="fr_v1_" + "c" * 64,
        evidence_id=source_id,
        source_record_sha256="d" * 64,
        source_task_relation=relation,
    )
    visible = tuple(
        EvidenceContext(
            evidence_id=evidence_id,
            observed_at=start,
            captured_at=start,
            probe_id="fixture.source",
            summary="Synthetic observation",
            status=EvidenceContextStatus.OBSERVED,
            case_scope="current_case",
        )
        for evidence_id in (task_id, source_id)
    )
    request = ReasoningRequest.model_validate(
        {
            **base.model_dump(mode="json"),
            "schema_version": 5,
            "evidence_context": [item.model_dump(mode="json") for item in visible],
            "task_observation": task.model_dump(mode="json"),
            "selected_sources": [selected.model_dump(mode="json")],
        }
    )
    assert request.selected_sources[0].source_task_relation == relation
    with pytest.raises(ValidationError, match="request version 5"):
        ReasoningRequest.model_validate({**request.model_dump(mode="json"), "schema_version": 4})
    with pytest.raises(ValidationError, match="focused current-case"):
        ReasoningRequest.model_validate({**request.model_dump(mode="json"), "evidence_context": []})
    with pytest.raises(ValidationError, match="differs from bound task"):
        ReasoningRequest.model_validate(
            {
                **request.model_dump(mode="json"),
                "selected_sources": [
                    selected.model_copy(
                        update={
                            "source_task_relation": relation.model_copy(
                                update={"task_record_sha256": "e" * 64}
                            )
                        }
                    ).model_dump(mode="json")
                ],
            }
        )


def test_deep_expected_fact_must_name_registered_probe() -> None:
    request = make_request()
    response = ReasoningResponse(
        provider=ProviderIdentity(
            provider_id="local-reasoner", provider_version="1", role="reasoning"
        ),
        case_id=request.case_id,
        state_version=request.state_version,
        correlation_id=request.correlation_id,
        deadline_at=request.deadline_at,
        status=ReasoningStatus.UNRESOLVED,
        summary="A testable possibility remains.",
        hypotheses=(
            Hypothesis(
                hypothesis_id="h_device",
                statement="The device reports no problem code.",
                status=HypothesisStatus.UNRESOLVED,
                expected_facts=(
                    ExpectedFact(
                        probe_id="application.snapshot",
                        fact_name="device.problem_code",
                        expected_value=0,
                    ),
                ),
            ),
        ),
    )

    assert response.validate_against(request) == response
    invalid = response.model_copy(
        update={
            "hypotheses": (
                response.hypotheses[0].model_copy(
                    update={
                        "expected_facts": (
                            ExpectedFact(
                                probe_id="windows.unregistered",
                                fact_name="device.problem_code",
                                expected_value=0,
                            ),
                        )
                    }
                ),
            )
        }
    )
    with pytest.raises(ReasoningValidationError, match=r"expected fact.*probe"):
        invalid.validate_against(request)
    forged_time = response.model_copy(
        update={
            "hypotheses": (
                response.hypotheses[0].model_copy(
                    update={"expected_facts_observed_after": datetime(2026, 9, 21, tzinfo=UTC)}
                ),
            )
        }
    )
    with pytest.raises(ReasoningValidationError, match="coordinator-owned"):
        forged_time.validate_against(request)
    for unsafe_value in ("user_secret_abc123", 123456):
        with pytest.raises(ValidationError):
            ExpectedFact(
                probe_id="application.snapshot",
                fact_name="device.problem_code",
                expected_value=unsafe_value,
            )


def test_v6_expected_fact_requires_future_eligible_probe_execution() -> None:
    base = make_request()
    capability = base.available_probes[0].model_copy(
        update={
            "probe_version": 1,
            "prediction_outputs": (
                ProbePredictionOutputV1(
                    name="application_state", allowed_values=("failed", "running")
                ),
            ),
        }
    )
    request = ReasoningRequest.model_validate(
        {
            **base.model_dump(mode="json"),
            "schema_version": 6,
            "available_probes": [capability.model_dump(mode="json")],
        }
    )
    response = ReasoningResponse(
        provider=ProviderIdentity(
            provider_id="local-reasoner", provider_version="1", role="reasoning"
        ),
        case_id=request.case_id,
        state_version=request.state_version,
        correlation_id=request.correlation_id,
        deadline_at=request.deadline_at,
        status=ReasoningStatus.UNRESOLVED,
        summary="A registered outcome can test the explanation.",
        hypotheses=(
            Hypothesis(
                hypothesis_id="h_application",
                statement="The application remains failed.",
                status=HypothesisStatus.UNRESOLVED,
                expected_facts=(
                    ExpectedFact(
                        probe_id="application.snapshot",
                        fact_name="application_state",
                        expected_value="failed",
                    ),
                ),
            ),
        ),
    )
    assert response.validate_against(request) == response

    completed = ReasoningRequest.model_validate(
        {**request.model_dump(mode="json"), "completed_probe_ids": ["application.snapshot"]}
    )
    with pytest.raises(ReasoningValidationError):
        response.validate_against(completed)

    legacy = ReasoningRequest.model_validate(
        {**completed.model_dump(mode="json"), "schema_version": 5}
    )
    assert response.validate_against(legacy) == response


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


def test_reasoning_response_rejects_duplicate_hypothesis_ids_before_next_turn() -> None:
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
        summary="Competing mechanisms are uncertain.",
        hypotheses=(
            Hypothesis(
                hypothesis_id="h_shared",
                statement="A dependency may be unavailable.",
                status=HypothesisStatus.UNRESOLVED,
            ),
            Hypothesis(
                hypothesis_id="h_shared",
                statement="A setting may be incorrect.",
                status=HypothesisStatus.UNRESOLVED,
            ),
        ),
    )

    with pytest.raises(ReasoningValidationError, match="hypotheses must have unique IDs"):
        response.validate_against(req)


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
