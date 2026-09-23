import json
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from systemsense.decision.contracts import (
    DecisionRequest,
    DecisionResponse,
    DiagnosticPurpose,
    FastSignal,
    FastSignalKind,
    ProbeCapability,
    ProbeProposal,
    ProviderIdentity,
    ResourceClass,
    ResponseValidationError,
    SafetyClass,
)
from systemsense.domain.ids import CaseId, EntityId, EvidenceId
from systemsense.domain.probes import MeasurementNeed, MeasurementWindow
from systemsense.evidence.graph import (
    AssertionStatus,
    EvidenceRelation,
    MemoryLayer,
    RelationKind,
)
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.storage.decision_snapshots import decision_request_json

NOW = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)


def capability(
    probe_id: str = "core.system",
    *,
    keywords: frozenset[str] = frozenset({"system"}),
    common: bool = False,
    cost_ms: int = 100,
) -> ProbeCapability:
    return ProbeCapability(
        probe_id=probe_id,
        description="bounded read-only snapshot",
        keywords=keywords,
        common=common,
        baseline_priority=0.8,
        cost_ms=cost_ms,
        resource_class=ResourceClass.CPU,
    )


def request(*, state_version: int = 4, budget_ms: int = 500) -> DecisionRequest:
    return DecisionRequest(
        case_id=CaseId.new(),
        state_version=state_version,
        correlation_id="corr_1234567890",
        deadline_at=NOW + timedelta(seconds=30),
        symptom="the application is slow",
        target_traits=frozenset({"application"}),
        evidence_ids=(EvidenceId.new(),),
        fresh_probe_ids=frozenset(),
        available_probes=(
            capability(common=True),
            capability(
                "application.snapshot", keywords=frozenset({"application", "slow"}), cost_ms=200
            ),
        ),
        budget_ms=budget_ms,
        max_probes=4,
    )


def proposal(probe_id: str = "core.system", *, cost_ms: int = 100) -> ProbeProposal:
    return ProbeProposal(
        probe_id=probe_id,
        purpose=DiagnosticPurpose.REFRESH_EVIDENCE,
        priority=0.8,
        estimated_cost_ms=cost_ms,
        resource_class=ResourceClass.CPU,
        dedupe_key=f"{probe_id}:current",
    )


def valid_response(req: DecisionRequest) -> DecisionResponse:
    return DecisionResponse(
        provider=ProviderIdentity(provider_id="test", provider_version="1", role="fast_decision"),
        case_id=req.case_id,
        state_version=req.state_version,
        correlation_id=req.correlation_id,
        deadline_at=req.deadline_at,
        proposals=(proposal(),),
        requires_reasoning=False,
    )


def test_contracts_are_immutable_and_versioned() -> None:
    req = request()
    assert req.schema_version == 1
    with pytest.raises(ValidationError):
        req.state_version = 5  # type: ignore[misc]


def test_typed_proposal_names_registered_target_observable_and_window() -> None:
    handle = "proc_" + "a" * 32
    registered = ProbeCapability.model_validate(
        {
            **capability("application.target_pressure").model_dump(mode="json"),
            "observable_ids": ["application.target_pressure"],
            "target_handles": [handle],
            "supports_window": False,
        }
    )
    req = request().model_copy(update={"available_probes": (registered,)})
    need = MeasurementNeed(
        capability_id=registered.probe_id,
        observable="application.target_pressure",
        target_handle=handle,
    )
    typed = ProbeProposal.model_validate(
        {
            **proposal("application.target_pressure").model_dump(mode="json"),
            "schema_version": 2,
            "measurement_need": need.model_dump(mode="json"),
        }
    )
    response = valid_response(req).model_copy(update={"proposals": (typed,)})
    assert response.validate_against(req).proposals[0].measurement_need == need

    wrong = typed.model_copy(
        update={"measurement_need": need.model_copy(update={"target_handle": "proc_" + "b" * 32})}
    )
    with pytest.raises(ResponseValidationError, match="target handle"):
        response.model_copy(update={"proposals": (wrong,)}).validate_against(req)

    unsupported_window = need.model_copy(
        update={"window": MeasurementWindow(start=NOW, end=NOW + timedelta(seconds=1))}
    )
    with pytest.raises(ResponseValidationError, match="window"):
        response.model_copy(
            update={
                "proposals": (typed.model_copy(update={"measurement_need": unsupported_window}),)
            }
        ).validate_against(req)


def test_typed_proposal_requires_new_schema_version() -> None:
    with pytest.raises(ValidationError, match="schema version"):
        ProbeProposal.model_validate(
            {
                **proposal().model_dump(mode="json"),
                "measurement_need": MeasurementNeed(
                    capability_id="core.system", observable="core.system"
                ).model_dump(mode="json"),
            }
        )


def test_version_two_snapshot_sorts_all_unordered_probe_sets() -> None:
    initial = request()
    updated = DecisionRequest.model_validate(
        {
            **initial.model_dump(mode="json"),
            "schema_version": 2,
            "available_probes": [
                *[probe.model_dump(mode="json") for probe in initial.available_probes],
                capability("devices.snapshot").model_dump(mode="json"),
                capability("network.snapshot").model_dump(mode="json"),
            ],
            "completed_probe_ids": ["core.system", "application.snapshot"],
            "satisfied_probe_ids": ["core.system", "application.snapshot"],
            "retryable_probe_ids": ["network.snapshot", "devices.snapshot"],
        }
    )
    serialized = json.loads(decision_request_json(updated))
    assert serialized["satisfied_probe_ids"] == ["application.snapshot", "core.system"]
    assert serialized["retryable_probe_ids"] == ["devices.snapshot", "network.snapshot"]


def test_related_broad_probe_hints_require_typed_bounded_entity_ids() -> None:
    entity = EntityId.new()
    item = capability().model_copy(update={"probe_id": "driver.details"})
    bound = ProbeCapability.model_validate(
        {**item.model_dump(mode="json"), "related_entity_hint_ids": [str(entity)]}
    )
    assert bound.related_entity_hint_ids == (entity,)
    with pytest.raises(ValidationError):
        ProbeCapability.model_validate(
            {**item.model_dump(mode="json"), "inspectable_entity_ids": [str(entity)]}
        )
    with pytest.raises(ValidationError):
        ProbeCapability.model_validate(
            {**item.model_dump(mode="json"), "related_entity_hint_ids": [str(entity), str(entity)]}
        )
    with pytest.raises(ValidationError):
        ProbeCapability.model_validate(
            {**item.model_dump(mode="json"), "related_entity_hint_ids": ["driver"]}
        )
    with pytest.raises(ValidationError):
        ProbeCapability.model_validate(
            {
                **item.model_dump(mode="json"),
                "related_entity_hint_ids": [str(EntityId.new()) for _ in range(65)],
            }
        )


def test_response_accepts_known_read_only_probe_with_matching_budget() -> None:
    req = request()
    assert valid_response(req).validate_against(req) == valid_response(req)


def test_fast_escalation_is_typed_grounded_and_requires_reasoning() -> None:
    bare = request()
    context = EvidenceContext(
        evidence_id=bare.evidence_ids[0],
        observed_at=NOW,
        captured_at=NOW,
        probe_id="core.system",
        summary="The driver version differs from the expected version.",
        facts={"driver_version": "1.0"},
        status=EvidenceContextStatus.OBSERVED,
    )
    req = bare.model_copy(
        update={"hypothesis_briefs": ("Driver mismatch",), "evidence_context": (context,)}
    )
    signal = FastSignal(
        kind=FastSignalKind.CONTRADICTION_SUSPECTED,
        evidence_ids=(req.evidence_ids[0],),
        hypothesis_index=0,
    )
    response = valid_response(req).model_copy(
        update={
            "requires_reasoning": True,
            "signals": (signal,),
            "considered_evidence_ids": (req.evidence_ids[0],),
        }
    )
    assert response.validate_against(req) == response
    with pytest.raises(ResponseValidationError, match="not visible"):
        response.validate_against(
            bare.model_copy(update={"hypothesis_briefs": req.hypothesis_briefs})
        )
    with pytest.raises(ResponseValidationError, match="requires reasoning"):
        response.model_copy(update={"requires_reasoning": False}).validate_against(req)
    with pytest.raises(ResponseValidationError, match="typed fast signal"):
        response.model_copy(update={"signals": ()}).validate_against(req)
    with pytest.raises(ResponseValidationError, match="not considered"):
        response.model_copy(update={"considered_evidence_ids": ()}).validate_against(req)
    with pytest.raises(ResponseValidationError, match="unknown evidence"):
        response.model_copy(
            update={"signals": (signal.model_copy(update={"evidence_ids": (EvidenceId.new(),)}),)}
        ).validate_against(req)
    with pytest.raises(ResponseValidationError, match="unknown hypothesis"):
        response.model_copy(
            update={"signals": (signal.model_copy(update={"hypothesis_index": 1}),)}
        ).validate_against(req)
    with pytest.raises(ValidationError):
        FastSignal(kind=FastSignalKind.CONTRADICTION_SUSPECTED)


def test_progress_signal_can_escalate_without_inventing_evidence() -> None:
    req = request()
    signal = FastSignal(kind=FastSignalKind.NO_PROGRESS_SUSPECTED)
    response = valid_response(req).model_copy(
        update={"requires_reasoning": True, "signals": (signal,)}
    )
    assert response.validate_against(req) == response


def test_response_rejects_stale_state() -> None:
    req = request(state_version=4)
    response = valid_response(req).model_copy(update={"state_version": 3})
    with pytest.raises(ResponseValidationError, match="state_version"):
        response.validate_against(req)


@pytest.mark.parametrize(
    ("proposals", "message"),
    [
        ((proposal("unknown.probe"),), "unknown probe"),
        ((proposal(), proposal()), "duplicate"),
        ((proposal(cost_ms=100), proposal("application.snapshot", cost_ms=200)), "budget"),
    ],
)
def test_response_rejects_unknown_duplicate_or_over_budget_proposals(
    proposals: tuple[ProbeProposal, ...],
    message: str,
) -> None:
    req = request(budget_ms=250)
    req = req.model_copy(
        update={
            "available_probes": (
                capability(cost_ms=100),
                capability(
                    "application.snapshot", keywords=frozenset({"application"}), cost_ms=200
                ),
            ),
        }
    )
    response = valid_response(req).model_copy(update={"proposals": proposals})
    with pytest.raises(ResponseValidationError, match=message):
        response.validate_against(req)


def test_response_rejects_capability_mismatch() -> None:
    req = request()
    response = valid_response(req).model_copy(
        update={
            "proposals": (proposal().model_copy(update={"resource_class": ResourceClass.DISK}),)
        }
    )
    with pytest.raises(ResponseValidationError, match="resource_class"):
        response.validate_against(req)


def test_response_rejects_provider_cost_below_catalog_cost() -> None:
    req = request(budget_ms=500)
    response = valid_response(req).model_copy(update={"proposals": (proposal(cost_ms=1),)})

    with pytest.raises(ResponseValidationError, match="catalog cost"):
        response.validate_against(req)


def test_response_rejects_unselected_or_cyclic_dependencies() -> None:
    req = request().model_copy(
        update={
            "available_probes": (
                capability(),
                capability(
                    "application.snapshot", keywords=frozenset({"application"}), cost_ms=200
                ),
            )
        }
    )
    missing = valid_response(req).model_copy(
        update={
            "proposals": (proposal().model_copy(update={"depends_on": ("application.snapshot",)}),)
        }
    )
    with pytest.raises(ResponseValidationError, match="not selected"):
        missing.validate_against(req)

    cyclic = valid_response(req).model_copy(
        update={"proposals": (proposal().model_copy(update={"depends_on": ("core.system",)}),)}
    )
    with pytest.raises(ResponseValidationError, match="cycle"):
        cyclic.validate_against(req)


def test_response_accepts_dependency_satisfied_in_a_prior_batch() -> None:
    req = request().model_copy(
        update={
            "schema_version": 2,
            "completed_probe_ids": frozenset({"core.system"}),
            "satisfied_probe_ids": frozenset({"core.system"}),
        }
    )
    dependent = proposal("application.snapshot", cost_ms=200).model_copy(
        update={"depends_on": ("core.system",)}
    )
    response = valid_response(req).model_copy(update={"proposals": (dependent,)})

    assert response.validate_against(req) == response


def test_failed_prior_attempt_does_not_satisfy_a_dependency() -> None:
    req = request().model_copy(update={"completed_probe_ids": frozenset({"core.system"})})
    dependent = proposal("application.snapshot", cost_ms=200).model_copy(
        update={"depends_on": ("core.system",)}
    )
    response = valid_response(req).model_copy(update={"proposals": (dependent,)})

    with pytest.raises(ResponseValidationError, match="dependency"):
        response.validate_against(req)


def test_request_rejects_duplicate_probe_capabilities() -> None:
    with pytest.raises(ValidationError, match="unique"):
        values = request().model_dump()
        values["available_probes"] = (capability(), capability())
        DecisionRequest.model_validate(values)


def test_response_rejects_wrong_provider_role() -> None:
    req = request()
    response = valid_response(req).model_copy(
        update={
            "provider": ProviderIdentity(
                provider_id="reasoner", provider_version="1", role="reasoning"
            )
        }
    )
    with pytest.raises(ResponseValidationError, match="role"):
        response.validate_against(req)


def test_extra_command_path_url_and_authority_fields_are_forbidden() -> None:
    with pytest.raises(ValidationError):
        ProbeProposal.model_validate(
            {**proposal().model_dump(), "command": "powershell Get-Process"}
        )


def test_capability_rejects_non_read_only_safety_class() -> None:
    with pytest.raises(ValidationError, match="R0 or R1"):
        ProbeCapability(
            probe_id="fixture.unsafe",
            description="not eligible for investigation",
            cost_ms=100,
            resource_class=ResourceClass.CPU,
            safety_class=SafetyClass.R2,
        )


def test_request_accepts_relevant_evidence_content_and_completed_probes() -> None:
    req = request()
    context = EvidenceContext(
        evidence_id=req.evidence_ids[0],
        observed_at=NOW,
        captured_at=NOW,
        probe_id="core.system",
        summary="CPU was below saturation.",
        facts={"cpu.percent": 12.5},
        status=EvidenceContextStatus.OBSERVED,
    )

    enriched = req.model_copy(
        update={
            "evidence_context": (context,),
            "completed_probe_ids": frozenset({"core.system"}),
        }
    )
    assert DecisionRequest.model_validate(enriched.model_dump()).evidence_context == (context,)


def test_request_rejects_unknown_context_and_completed_probe_references() -> None:
    req = request()
    context = EvidenceContext(
        evidence_id=EvidenceId.new(),
        observed_at=NOW,
        captured_at=NOW,
        probe_id="unknown.probe",
        summary="Not part of the request.",
        status=EvidenceContextStatus.OBSERVED,
    )
    values = req.model_dump()
    values["evidence_context"] = (context,)
    with pytest.raises(ValidationError, match="evidence context"):
        DecisionRequest.model_validate(values)

    values = req.model_dump()
    values["completed_probe_ids"] = ("unknown.probe",)
    with pytest.raises(ValidationError, match="completed probe"):
        DecisionRequest.model_validate(values)


def test_attention_count_uses_unique_page_evidence_not_compact_context_size() -> None:
    req = request()
    first = EvidenceContext(
        evidence_id=req.evidence_ids[0],
        observed_at=NOW,
        captured_at=NOW,
        probe_id="core.system",
        summary="First page",
        facts={"cpu.percent": 12.5},
        status=EvidenceContextStatus.OBSERVED,
    )
    second = first.model_copy(update={"evidence_id": EvidenceId.new(), "summary": "Other evidence"})
    req = DecisionRequest.model_validate(
        req.model_copy(
            update={
                "evidence_ids": (first.evidence_id, second.evidence_id),
                "evidence_context": (first,),
                "attention_context": (first, first, second),
            }
        ).model_dump()
    )
    response = valid_response(req).model_copy(update={"considered_evidence_count": 2})
    assert response.validate_against(req) == response
    with pytest.raises(ResponseValidationError, match="count exceeds"):
        response.model_copy(update={"considered_evidence_count": 3}).validate_against(req)


def test_request_relationships_require_evidence_grounded_in_the_request() -> None:
    req = request()
    relation = EvidenceRelation(
        relation_id="rel_0123456789abcdef0123456789abcdef",
        source_entity_id=EntityId.new(),
        target_entity_id=EntityId.new(),
        relationship=RelationKind.CORRELATED_WITH,
        memory_layer=MemoryLayer.MACHINE,
        assertion_status=AssertionStatus.OBSERVED,
        relation_version=1,
        evidence_ids=(req.evidence_ids[0],),
    )
    values = req.model_dump()
    values["relationships"] = (relation,)
    assert DecisionRequest.model_validate(values).relationships == (relation,)

    values["relationships"] = (relation.model_copy(update={"evidence_ids": (EvidenceId.new(),)}),)
    with pytest.raises(ValidationError, match=r"relationship.*evidence"):
        DecisionRequest.model_validate(values)

    values["relationships"] = (
        relation.model_copy(
            update={
                "evidence_ids": (),
                "source_ids": ("src_" + "1" * 64,),
            }
        ),
    )
    with pytest.raises(ValidationError, match=r"relationship.*grounded"):
        DecisionRequest.model_validate(values)
