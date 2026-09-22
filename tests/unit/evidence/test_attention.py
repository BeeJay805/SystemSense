from datetime import UTC, datetime

from systemsense.domain.ids import EntityId, EvidenceId
from systemsense.evidence.attention import focus_evidence
from systemsense.evidence.graph import AssertionStatus, EvidenceRelation, MemoryLayer, RelationKind
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus


def context(index: int, *, missing: bool = False) -> EvidenceContext:
    return EvidenceContext(
        evidence_id=EvidenceId(root=f"ev_{index:032x}"),
        observed_at=datetime.now(UTC),
        captured_at=datetime.now(UTC),
        probe_id=f"domain{index}.snapshot",
        summary=f"Observation {index}",
        facts={"value": index},
        status=EvidenceContextStatus.MISSING if missing else EvidenceContextStatus.OBSERVED,
    )


def test_attention_expands_real_dependency_provenance_and_preserves_missing_data() -> None:
    evidence = tuple(context(i, missing=i == 5) for i in range(1, 7))
    edges = tuple(
        EvidenceRelation(
            relation_id=f"rel_{i:032x}",
            source_entity_id=EntityId(root=f"entity_{i:032x}"),
            target_entity_id=EntityId(root=f"entity_{i + 1:032x}"),
            relationship=RelationKind.DEPENDS_ON,
            memory_layer=MemoryLayer.MACHINE,
            assertion_status=AssertionStatus.OBSERVED,
            relation_version=1,
            evidence_ids=(evidence[i - 1].evidence_id,),
        )
        for i in (1, 2, 3)
    )
    result = focus_evidence(
        evidence,
        ranked_ids=(evidence[0].evidence_id,),
        relationships=edges,
        max_observations=3,
        max_chars=5000,
    )
    ids = {str(item.evidence_id) for item in result.context}
    assert str(evidence[0].evidence_id) in ids
    assert str(evidence[1].evidence_id) in ids
    assert str(evidence[4].evidence_id) in ids  # Missing telemetry is not silently hidden.
    assert result.graph_expanded_ids
    assert result.omitted_count > 0


def test_attention_cannot_invent_evidence_or_discard_required_contradictions() -> None:
    evidence = tuple(context(i) for i in range(1, 8))
    unknown = EvidenceId.new()
    result = focus_evidence(
        evidence,
        ranked_ids=(unknown, evidence[0].evidence_id),
        relationships=(),
        required_ids=(evidence[-1].evidence_id,),
        max_observations=2,
        max_chars=5000,
    )
    ids = {str(item.evidence_id) for item in result.context}
    assert str(unknown) not in ids
    assert str(evidence[-1].evidence_id) in ids
    assert str(evidence[0].evidence_id) in ids


def test_attention_is_bounded_and_reports_oversized_facts() -> None:
    item = context(1).model_copy(update={"facts": {"detail": "x" * 7000}})
    result = focus_evidence(
        (item,), ranked_ids=(item.evidence_id,), relationships=(), max_chars=1400
    )
    assert len(result.model_dump_json()) <= 1400
    assert result.context
    assert result.context[0].limitations


def test_dependency_expansion_has_two_hops_not_an_order_dependent_transitive_flood() -> None:
    evidence = tuple(context(i) for i in range(1, 9))
    edges = tuple(
        EvidenceRelation(
            relation_id=f"rel_{i:032x}",
            source_entity_id=EntityId(root=f"entity_{i:032x}"),
            target_entity_id=EntityId(root=f"entity_{i + 1:032x}"),
            relationship=RelationKind.DEPENDS_ON,
            memory_layer=MemoryLayer.MACHINE,
            assertion_status=AssertionStatus.OBSERVED,
            relation_version=1,
            evidence_ids=(evidence[i - 1].evidence_id,),
        )
        for i in range(1, 8)
    )
    result = focus_evidence(evidence, ranked_ids=(evidence[0].evidence_id,), relationships=edges)
    assert evidence[2].evidence_id in result.graph_expanded_ids
    assert evidence[3].evidence_id not in result.graph_expanded_ids
    assert any("does not establish causality" in item for item in result.context[0].limitations)


def test_attention_prioritizes_exact_selected_page_without_rewriting_its_facts() -> None:
    exact = context(1).model_copy(
        update={
            "facts": {"selected.detail": "x" * 1800},
            "limitations": (
                "Exact fact pages selected by local attention; full observation remains stored.",
            ),
        }
    )
    gap = context(2, missing=True)

    result = focus_evidence(
        (exact, gap),
        ranked_ids=(exact.evidence_id,),
        relationships=(),
        max_chars=2500,
    )

    selected = next(item for item in result.context if item.evidence_id == exact.evidence_id)
    assert selected.facts == exact.facts
