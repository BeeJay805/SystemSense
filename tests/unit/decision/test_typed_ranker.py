"""Contract tests for the optional CPU-only typed-feature decision challenger."""

from datetime import UTC, datetime, timedelta
from typing import Literal

from systemsense.decision.contracts import (
    DecisionRequest,
    DiagnosticPurpose,
    ProbeCapability,
    ResourceClass,
)
from systemsense.decision.typed_ranker import TypedFeatureDecisionProvider
from systemsense.domain.ids import CaseId, EntityId, EvidenceId
from systemsense.evidence.graph import (
    AssertionStatus,
    EvidenceRelation,
    MemoryLayer,
    RelationKind,
)
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.knowledge.models import (
    KnowledgeNode,
    KnowledgeNodeKind,
    KnowledgePacket,
    KnowledgeRelation,
    KnowledgeRelationKind,
    KnowledgeSource,
)

NOW = datetime.now(UTC)


def _probe(
    probe_id: str,
    *,
    keywords: frozenset[str] = frozenset(),
    traits: frozenset[str] = frozenset(),
    common: bool = False,
    cost_ms: int = 100,
    related_entities: tuple[EntityId, ...] = (),
) -> ProbeCapability:
    return ProbeCapability(
        probe_id=probe_id,
        description=f"Read-only {probe_id} snapshot",
        keywords=keywords,
        target_traits=traits,
        common=common,
        cost_ms=cost_ms,
        resource_class=ResourceClass.CPU,
        related_entity_hint_ids=related_entities,
    )


def _evidence(
    probe_id: str,
    status: EvidenceContextStatus,
    *,
    age_minutes: int = 1,
    facts: dict[str, object] | None = None,
    case_scope: Literal["current_case", "historical", "unspecified"] = "unspecified",
    incident_relevant: bool | None = None,
) -> EvidenceContext:
    observed = NOW - timedelta(minutes=age_minutes)
    return EvidenceContext(
        evidence_id=EvidenceId.new(),
        observed_at=observed,
        captured_at=observed,
        probe_id=probe_id,
        summary=f"{probe_id} reported {status.value}",
        facts=facts or {},  # type: ignore[arg-type]
        status=status,
        case_scope=case_scope,
        incident_relevant=incident_relevant,
    )


def _request(
    probes: tuple[ProbeCapability, ...],
    *,
    evidence: tuple[EvidenceContext, ...] = (),
    symptom: str = "Wi-Fi is disconnected",
    traits: frozenset[str] = frozenset({"wireless"}),
    budget_ms: int = 1000,
    deadline_at: datetime | None = None,
    completed: frozenset[str] = frozenset(),
    fresh: frozenset[str] = frozenset(),
    references: tuple[dict[str, object], ...] = (),
    relationships: tuple[EvidenceRelation, ...] = (),
    attention_only: bool = False,
) -> DecisionRequest:
    return DecisionRequest(
        case_id=CaseId.new(),
        state_version=3,
        correlation_id="typed-feature-test",
        deadline_at=deadline_at or NOW + timedelta(minutes=1),
        symptom=symptom,
        target_traits=traits,
        evidence_ids=tuple(item.evidence_id for item in evidence),
        evidence_context=evidence,
        available_probes=probes,
        completed_probe_ids=completed,
        fresh_probe_ids=fresh,
        reference_context=references,  # type: ignore[arg-type]
        relationships=relationships,
        budget_ms=budget_ms,
        max_probes=4,
        attention_only=attention_only,
    )


def _reference(probe_id: str, *, source: bool = True) -> dict[str, object]:
    return {
        "nodes": [
            {"node_id": "kn_wifi", "label": "Wi-Fi disconnection"},
            {"node_id": "kn_driver", "label": "Wireless driver"},
        ],
        "sources": [{"source_id": "ks_ms_wifi"}] if source else [],
        "relations": [
            {
                "relation_id": "kr_wifi_driver",
                "source_node_id": "kn_driver",
                "target_node_id": "kn_wifi",
                "mechanism": "Wireless driver failure can disconnect Wi-Fi.",
                "symptoms": ["Wi-Fi is disconnected"],
                "distinguishing_probe_ids": [probe_id],
                "source_ids": ["ks_ms_wifi"],
                "conditions": ["The adapter uses this driver"],
            }
        ],
    }


def test_relevant_probe_outranks_irrelevant_common_probe() -> None:
    request = _request(
        (
            _probe("core.system", common=True),
            _probe("network.wifi", keywords=frozenset({"wi-fi", "disconnected"})),
        )
    )
    result = TypedFeatureDecisionProvider().decide(request)
    assert tuple(item.probe_id for item in result.proposals) == ("network.wifi",)
    assert result.validate_against(request) == result
    assert result.provider.provider_id == "typed-feature-challenger"


def test_stale_and_partial_evidence_have_a_larger_coverage_gap() -> None:
    probes = (
        _probe("network.a", traits=frozenset({"wireless"})),
        _probe("network.b", traits=frozenset({"wireless"})),
        _probe("network.c", traits=frozenset({"wireless"})),
    )
    request = _request(
        probes,
        evidence=(
            _evidence("network.a", EvidenceContextStatus.OBSERVED, facts={"omitted_count": 0}),
            _evidence("network.b", EvidenceContextStatus.PARTIAL),
            _evidence("network.c", EvidenceContextStatus.STALE, age_minutes=60),
        ),
    )
    scores = {
        item.probe_id: item for item in TypedFeatureDecisionProvider().score_candidates(request)
    }
    assert scores["network.a"].features.coverage_gap < scores["network.b"].features.coverage_gap
    assert scores["network.b"].features.coverage_gap < scores["network.c"].features.coverage_gap
    assert scores["network.a"].features.status > scores["network.b"].features.status
    assert scores["network.c"].features.freshness < scores["network.a"].features.freshness


def test_sourced_reference_graph_routes_related_probe_without_claiming_cause() -> None:
    probes = (_probe("devices.wifi"), _probe("core.system", common=True))
    request = _request(probes, references=(_reference("devices.wifi"),))
    provider = TypedFeatureDecisionProvider()
    result = provider.decide(request)
    assert tuple(item.probe_id for item in result.proposals) == ("devices.wifi",)
    assert provider.score_candidates(request)[0].features.reference_graph > 0
    assert not result.requires_reasoning


def test_malformed_or_unsourced_reference_data_cannot_add_graph_score() -> None:
    probe = _probe("devices.wifi")
    malformed = _reference("devices.wifi", source=False)
    request = _request((probe,), references=(malformed, {"relations": ["not-a-relation"]}))
    assert TypedFeatureDecisionProvider().score_candidates(request) == ()
    assert TypedFeatureDecisionProvider().decide(request).proposals == ()


def test_machine_relation_without_typed_probe_bridge_cannot_claim_cross_probe_relevance() -> None:
    evidence = _evidence("devices.wifi", EvidenceContextStatus.OBSERVED)
    relation = EvidenceRelation(
        relation_id="rel_" + "a" * 32,
        source_entity_id=EntityId.new(),
        target_entity_id=EntityId.new(),
        relationship=RelationKind.USES_DRIVER,
        memory_layer=MemoryLayer.MACHINE,
        assertion_status=AssertionStatus.OBSERVED,
        relation_version=1,
        evidence_ids=(evidence.evidence_id,),
        valid_from=evidence.observed_at,
        valid_until=evidence.observed_at,
    )
    request = _request(
        (
            _probe("devices.wifi", traits=frozenset({"wireless"})),
            _probe("network.wifi", traits=frozenset({"wireless"})),
        ),
        evidence=(evidence,),
        relationships=(relation,),
    )
    scores = {
        item.probe_id: item for item in TypedFeatureDecisionProvider().score_candidates(request)
    }
    assert scores["devices.wifi"].features.machine_graph == 0
    assert scores["network.wifi"].features.machine_graph == 0


def test_observed_machine_edge_weakly_suggests_distinct_related_probe() -> None:
    evidence = _evidence(
        "devices.snapshot",
        EvidenceContextStatus.OBSERVED,
        case_scope="current_case",
        incident_relevant=True,
    )
    target = EntityId.new()
    relation = EvidenceRelation(
        relation_id="rel_" + "c" * 32,
        source_entity_id=EntityId.new(),
        target_entity_id=target,
        relationship=RelationKind.USES_DRIVER,
        memory_layer=MemoryLayer.MACHINE,
        assertion_status=AssertionStatus.OBSERVED,
        relation_version=1,
        evidence_ids=(evidence.evidence_id,),
        applicability=("devices.snapshot",),
        valid_from=evidence.observed_at,
        valid_until=evidence.observed_at,
    )
    request = _request(
        (
            _probe("devices.snapshot"),
            _probe("driver.details", related_entities=(target,)),
            _probe("unrelated.common", common=True),
        ),
        evidence=(evidence,),
        relationships=(relation,),
        completed=frozenset({"devices.snapshot"}),
        symptom="The device stopped working",
        traits=frozenset(),
    )
    provider = TypedFeatureDecisionProvider(clock=lambda: NOW)
    result = provider.decide(request)
    assert tuple(proposal.probe_id for proposal in result.proposals) == ("driver.details",)
    assert provider.score_candidates(request)[0].features.machine_graph == 0.25
    assert result.provider.provider_version == "3"
    assert result.proposals[0].dedupe_key == "driver.details:typed-feature-v3"
    assert result.validate_against(request) == result


def test_graph_hint_requires_observed_source_and_matching_relation_target() -> None:
    evidence = _evidence(
        "devices.snapshot",
        EvidenceContextStatus.OBSERVED,
        case_scope="current_case",
        incident_relevant=True,
    )
    target = EntityId.new()
    relation = EvidenceRelation(
        relation_id="rel_" + "d" * 32,
        source_entity_id=EntityId.new(),
        target_entity_id=target,
        relationship=RelationKind.USES_DRIVER,
        memory_layer=MemoryLayer.MACHINE,
        assertion_status=AssertionStatus.OBSERVED,
        relation_version=1,
        evidence_ids=(evidence.evidence_id,),
        applicability=("devices.snapshot",),
    )
    base = _request(
        (_probe("devices.snapshot"), _probe("driver.details", related_entities=(target,))),
        evidence=(evidence,),
        relationships=(relation,),
        completed=frozenset({"devices.snapshot"}),
        traits=frozenset(),
    )
    provider = TypedFeatureDecisionProvider(clock=lambda: NOW)
    assert tuple(item.probe_id for item in provider.decide(base).proposals) == ("driver.details",)
    for scope, relevant in (
        ("historical", True),
        ("current_case", False),
        ("unspecified", True),
        ("current_case", None),
    ):
        unqualified = evidence.model_copy(
            update={"case_scope": scope, "incident_relevant": relevant}
        )
        assert (
            provider.decide(base.model_copy(update={"evidence_context": (unqualified,)})).proposals
            == ()
        )
    stale = evidence.model_copy(
        update={
            "observed_at": NOW - timedelta(minutes=6),
            "captured_at": NOW - timedelta(minutes=6),
        }
    )
    assert provider.decide(base.model_copy(update={"evidence_context": (stale,)})).proposals == ()
    assert (
        provider.decide(base.model_copy(update={"completed_probe_ids": frozenset()})).proposals
        == ()
    )
    assert (
        provider.decide(
            base.model_copy(
                update={
                    "available_probes": (
                        _probe("devices.snapshot"),
                        _probe("driver.details", related_entities=(EntityId.new(),)),
                    )
                }
            )
        ).proposals
        == ()
    )
    inferred = relation.model_copy(update={"assertion_status": AssertionStatus.INFERRED})
    assert provider.decide(base.model_copy(update={"relationships": (inferred,)})).proposals == ()
    unrelated = relation.model_copy(update={"relationship": RelationKind.CORRELATED_WITH})
    assert provider.decide(base.model_copy(update={"relationships": (unrelated,)})).proposals == ()
    failed = evidence.model_copy(update={"status": EvidenceContextStatus.FAILED})
    assert provider.decide(base.model_copy(update={"evidence_context": (failed,)})).proposals == ()
    self_only = base.model_copy(
        update={
            "available_probes": (_probe("devices.snapshot", related_entities=(target,)),),
            "completed_probe_ids": frozenset(),
        }
    )
    assert provider.decide(self_only).proposals == ()


def test_shared_related_entity_hint_is_independent_of_catalog_order() -> None:
    evidence = _evidence(
        "devices.snapshot",
        EvidenceContextStatus.OBSERVED,
        case_scope="current_case",
        incident_relevant=True,
    )
    target = EntityId.new()
    relation = EvidenceRelation(
        relation_id="rel_" + "e" * 32,
        source_entity_id=EntityId.new(),
        target_entity_id=target,
        relationship=RelationKind.USES_DRIVER,
        memory_layer=MemoryLayer.MACHINE,
        assertion_status=AssertionStatus.OBSERVED,
        relation_version=1,
        evidence_ids=(evidence.evidence_id,),
        applicability=("devices.snapshot",),
    )
    probes = (
        _probe("devices.snapshot"),
        _probe("driver.identity", related_entities=(target,)),
        _probe("driver.status", related_entities=(target,)),
    )
    request = _request(
        probes,
        evidence=(evidence,),
        relationships=(relation,),
        completed=frozenset({"devices.snapshot"}),
        traits=frozenset(),
    )
    provider = TypedFeatureDecisionProvider(clock=lambda: NOW)
    assert tuple(item.probe_id for item in provider.decide(request).proposals) == (
        "driver.identity",
        "driver.status",
    )
    reversed_request = request.model_copy(update={"available_probes": tuple(reversed(probes))})
    assert provider.decide(reversed_request).proposals == provider.decide(request).proposals


def test_reference_probe_bridge_can_route_different_probe_with_grounded_machine_context() -> None:
    evidence = _evidence("devices.wifi", EvidenceContextStatus.OBSERVED)
    relation = EvidenceRelation(
        relation_id="rel_" + "b" * 32,
        source_entity_id=EntityId.new(),
        target_entity_id=EntityId.new(),
        relationship=RelationKind.USES_DRIVER,
        memory_layer=MemoryLayer.MACHINE,
        assertion_status=AssertionStatus.OBSERVED,
        relation_version=1,
        evidence_ids=(evidence.evidence_id,),
        valid_from=evidence.observed_at,
        valid_until=evidence.observed_at,
    )
    request = _request(
        (_probe("network.wifi"), _probe("devices.wifi")),
        evidence=(evidence,),
        relationships=(relation,),
        references=(_reference("network.wifi"),),
    )
    scores = TypedFeatureDecisionProvider().score_candidates(request)
    assert scores[0].probe_id == "network.wifi"
    assert scores[0].features.reference_graph > 0
    assert scores[0].features.machine_graph == 0


def test_repeated_failed_evidence_increases_no_progress_penalty() -> None:
    probe = _probe("network.wifi", traits=frozenset({"wireless"}))
    one = _request((probe,), evidence=(_evidence("network.wifi", EvidenceContextStatus.FAILED),))
    repeated = _request(
        (probe,),
        evidence=(
            _evidence("network.wifi", EvidenceContextStatus.FAILED),
            _evidence("network.wifi", EvidenceContextStatus.FAILED),
        ),
    )
    provider = TypedFeatureDecisionProvider()
    assert (
        provider.score_candidates(repeated)[0].features.revisit_penalty
        > provider.score_candidates(one)[0].features.revisit_penalty
    )
    assert provider.score_candidates(repeated)[0].score < provider.score_candidates(one)[0].score


def test_completed_fresh_budget_and_deadline_are_hard_eligibility_gates() -> None:
    probes = (
        _probe("network.done", traits=frozenset({"wireless"})),
        _probe("network.fresh", traits=frozenset({"wireless"})),
        _probe("network.expensive", traits=frozenset({"wireless"}), cost_ms=500),
        _probe("network.cheap", traits=frozenset({"wireless"}), cost_ms=100),
    )
    request = _request(
        probes,
        completed=frozenset({"network.done"}),
        fresh=frozenset({"network.fresh"}),
        budget_ms=150,
    )
    provider = TypedFeatureDecisionProvider()
    assert tuple(item.probe_id for item in provider.decide(request).proposals) == ("network.cheap",)
    expired = request.model_copy(update={"deadline_at": NOW - timedelta(seconds=1)})
    assert provider.decide(expired).proposals == ()


def test_ranking_order_is_deterministic_across_catalog_order() -> None:
    probes = (
        _probe("network.z", traits=frozenset({"wireless"})),
        _probe("network.a", traits=frozenset({"wireless"})),
    )
    provider = TypedFeatureDecisionProvider()
    first = provider.decide(_request(probes))
    second = provider.decide(_request(tuple(reversed(probes))))
    assert tuple(item.probe_id for item in first.proposals) == ("network.a", "network.z")
    assert tuple(item.probe_id for item in second.proposals) == ("network.a", "network.z")
    assert all(0 <= item.priority <= 1 for item in first.proposals)


def test_attention_only_never_dispatches_a_probe() -> None:
    observed = _evidence("network.wifi", EvidenceContextStatus.OBSERVED)
    missing = _evidence("network.wifi", EvidenceContextStatus.MISSING)
    request = _request(
        (_probe("network.wifi", traits=frozenset({"wireless"})),),
        evidence=(observed, missing),
        attention_only=True,
    )
    result = TypedFeatureDecisionProvider(clock=lambda: NOW).decide(request)
    assert result.proposals == ()
    assert result.ranked_evidence_ids == (observed.evidence_id, missing.evidence_id)
    assert result.considered_evidence_count == 2


def test_page_ranking_reports_full_denominator_and_rank_limit() -> None:
    pages = tuple(_evidence("network.wifi", EvidenceContextStatus.OBSERVED) for _ in range(65))
    request = _request(
        (_probe("network.wifi"),), evidence=pages[:64], attention_only=True
    ).model_copy(
        update={"attention_context": pages, "evidence_ids": tuple(p.evidence_id for p in pages)}
    )

    result = TypedFeatureDecisionProvider(clock=lambda: NOW).decide(request)

    assert len(result.ranked_attention_page_ids) == 64
    assert result.considered_evidence_count == 64
    assert "pages_ranked=64_of_65" in result.attention_notes
    assert "pages_not_ranked=1" in result.attention_notes


def test_attention_prioritizes_suspicious_observed_facts_over_missing_and_future_pages() -> None:
    suspicious = _evidence(
        "network.wifi", EvidenceContextStatus.OBSERVED, facts={"authentication_failures": 3}
    )
    missing = _evidence("network.wifi", EvidenceContextStatus.MISSING)
    impossible_future = _evidence(
        "network.wifi", EvidenceContextStatus.OBSERVED, age_minutes=-60, facts={"errors": 999}
    )
    request = _request(
        (_probe("network.wifi", traits=frozenset({"wireless"})),),
        evidence=(missing, impossible_future, suspicious),
        attention_only=True,
    )
    result = TypedFeatureDecisionProvider(clock=lambda: NOW).decide(request)
    assert result.ranked_evidence_ids[0] == suspicious.evidence_id
    assert result.ranked_evidence_ids[-1] == impossible_future.evidence_id


def test_unexplored_probe_has_a_coverage_gap_and_check_coverage_purpose() -> None:
    request = _request((_probe("network.wifi", traits=frozenset({"wireless"})),))
    provider = TypedFeatureDecisionProvider(clock=lambda: NOW)
    score = provider.score_candidates(request)[0]
    assert score.features.coverage_gap == 1
    assert provider.decide(request).proposals[0].purpose is DiagnosticPurpose.CHECK_COVERAGE


def test_source_observed_after_capture_is_not_counted_as_fresh_coverage() -> None:
    evidence = EvidenceContext(
        evidence_id=EvidenceId.new(),
        observed_at=NOW - timedelta(minutes=1),
        captured_at=NOW - timedelta(minutes=2),
        probe_id="network.wifi",
        summary="source clock was after capture",
        status=EvidenceContextStatus.OBSERVED,
    )
    request = _request(
        (_probe("network.wifi", traits=frozenset({"wireless"})),), evidence=(evidence,)
    )
    features = TypedFeatureDecisionProvider(clock=lambda: NOW).score_candidates(request)[0].features
    assert features.freshness == 0
    assert features.status == 0
    assert features.coverage_gap == 1


def test_injected_clock_makes_replay_scores_reproducible() -> None:
    request = _request(
        (_probe("network.wifi", traits=frozenset({"wireless"})),),
        evidence=(_evidence("network.wifi", EvidenceContextStatus.OBSERVED),),
        deadline_at=NOW + timedelta(seconds=1),
    )
    provider = TypedFeatureDecisionProvider(clock=lambda: NOW)
    assert provider.decide(request) == provider.decide(request)
    assert provider.score_candidates(request) == provider.score_candidates(request)


def test_real_serialized_knowledge_packet_routes_only_its_sourced_probe() -> None:
    packet = KnowledgePacket(
        pack_id="windows-it-test",
        pack_version=1,
        nodes=(
            KnowledgeNode(
                node_id="kn_wireless_link",
                label="Wi-Fi disconnection",
                category="wifi",
                kind=KnowledgeNodeKind.SYMPTOM,
            ),
            KnowledgeNode(
                node_id="kn_wireless_driver",
                label="Wireless driver",
                category="wifi",
                kind=KnowledgeNodeKind.MECHANISM,
            ),
        ),
        relations=(
            KnowledgeRelation(
                relation_id="kr_wireless_driver",
                source_node_id="kn_wireless_driver",
                target_node_id="kn_wireless_link",
                relationship=KnowledgeRelationKind.CAN_CONTRIBUTE_TO,
                mechanism="A failed wireless driver may disconnect the network interface.",
                conditions=("The affected adapter uses the driver.",),
                symptoms=("Wi-Fi disconnects",),
                distinguishing_probe_ids=("devices.wifi",),
                counterevidence=("The adapter remains connected.",),
                limitations=("A driver relation does not establish causality.",),
                applicability=("Windows laptop",),
                source_ids=("ks_ms_wifi",),
            ),
        ),
        sources=(
            KnowledgeSource(
                source_id="ks_ms_wifi",
                title="Wi-Fi documentation",
                publisher="Microsoft",
                url="https://learn.microsoft.com/windows/wifi",
                usage_note="Documented mechanism only.",
            ),
        ),
        truncated=False,
        omitted_relation_count=0,
        limitations=(),
        disclaimer="Reference knowledge is not machine evidence or a diagnosis.",
    )
    request = _request(
        (_probe("devices.wifi"), _probe("core.system", common=True)),
        references=(packet.model_dump(mode="json"),),
    )
    assert tuple(
        item.probe_id for item in TypedFeatureDecisionProvider().decide(request).proposals
    ) == ("devices.wifi",)
