"""A case brief must retain cited evidence and report what did not fit."""

from datetime import UTC, datetime
from typing import Literal

import pytest

from systemsense.domain.ids import EntityId, EvidenceId
from systemsense.evidence.graph import AssertionStatus, EvidenceRelation, MemoryLayer, RelationKind
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.reasoning.case_brief import assemble_case_brief
from systemsense.reasoning.contracts import EvidenceDetailRequest, Hypothesis, HypothesisStatus

NOW = datetime(2026, 9, 27, 2, 0, tzinfo=UTC)


def _id(index: int) -> EvidenceId:
    return EvidenceId(root=f"ev_{index:032x}")


def _context(
    index: int,
    *,
    status: EvidenceContextStatus = EvidenceContextStatus.OBSERVED,
    scope: Literal["current_case", "historical", "unspecified"] = "current_case",
    detail: str = "value",
) -> EvidenceContext:
    return EvidenceContext(
        evidence_id=_id(index),
        observed_at=NOW,
        captured_at=NOW,
        probe_id="application.snapshot",
        summary=f"Exact recorded observation {index}",
        facts={"detail": detail},
        status=status,
        case_scope=scope,
        incident_relevant=True,
    )


def _hypothesis(index: int, *, support: int, contradiction: int) -> Hypothesis:
    return Hypothesis(
        hypothesis_id=f"hypothesis_{index}",
        statement=f"Competing explanation {index}",
        status=HypothesisStatus.CONTESTED,
        supporting_evidence_ids=(_id(support),),
        contradicting_evidence_ids=(_id(contradiction),),
    )


def test_competing_rivals_keep_both_sides_of_prior_citations() -> None:
    contexts = tuple(_context(index) for index in range(1, 6))
    result = assemble_case_brief(
        candidate_context=contexts,
        previous_hypotheses=(
            _hypothesis(1, support=1, contradiction=3),
            _hypothesis(2, support=2, contradiction=4),
        ),
        ranked_evidence_ids=(_id(5),),
        max_contexts=4,
        max_chars=4_000,
    )

    assert tuple(item.evidence_id for item in result.context) == (
        _id(3),
        _id(4),
        _id(1),
        _id(2),
    )
    assert result.context == (contexts[2], contexts[3], contexts[0], contexts[1])
    assert result.omitted_required_ids == ()
    assert result.unavailable_required_ids == ()
    assert result.omitted_context_count == 1
    assert not result.insufficient_context


def test_new_required_counterevidence_precedes_old_rivals_and_reports_loss() -> None:
    contexts = tuple(_context(index) for index in range(1, 7))
    result = assemble_case_brief(
        candidate_context=contexts,
        previous_hypotheses=(
            _hypothesis(1, support=1, contradiction=3),
            _hypothesis(2, support=2, contradiction=4),
        ),
        ranked_evidence_ids=(_id(6),),
        required_evidence_ids=(_id(5),),
        max_contexts=3,
        max_chars=4_000,
    )

    assert tuple(item.evidence_id for item in result.context) == (_id(5), _id(3), _id(4))
    assert {str(item) for item in result.omitted_required_ids} == {str(_id(1)), str(_id(2))}
    assert result.unavailable_required_ids == ()
    assert result.insufficient_context
    assert any("required" in note.lower() for note in result.notes)


def test_missing_requested_context_and_pending_detail_are_explicit() -> None:
    missing = _context(1, status=EvidenceContextStatus.MISSING)
    available = _context(2, status=EvidenceContextStatus.PARTIAL)
    detail = EvidenceDetailRequest(evidence_id=available.evidence_id, match_literals=("fault",))
    result = assemble_case_brief(
        candidate_context=(missing, available),
        previous_hypotheses=(),
        ranked_evidence_ids=(missing.evidence_id,),
        pending_evidence_ids=(_id(3),),
        pending_detail_requests=(detail,),
        max_contexts=2,
        max_chars=4_000,
    )

    assert result.context == (available, missing)
    assert result.unavailable_required_ids == (_id(3),)
    assert result.insufficient_context
    assert any("detail" in note.lower() for note in result.notes)
    assert result.context[1].status is EvidenceContextStatus.MISSING


def test_hard_char_limit_never_rewrites_required_evidence() -> None:
    oversized = _context(1, detail="x" * 7_000)
    small = _context(2)
    result = assemble_case_brief(
        candidate_context=(oversized, small),
        previous_hypotheses=(),
        ranked_evidence_ids=(small.evidence_id,),
        required_evidence_ids=(oversized.evidence_id,),
        max_contexts=2,
        max_chars=1_024,
    )

    assert result.context == (small,)
    assert result.omitted_required_ids == (oversized.evidence_id,)
    assert result.insufficient_context
    assert result.context_chars <= 1_024
    assert oversized.facts["detail"] == "x" * 7_000


def test_reference_relationship_cannot_promote_a_historical_context() -> None:
    current = _context(1)
    rival = _context(2)
    historical = _context(3, scope="historical")
    reference_edge = EvidenceRelation(
        relation_id=f"rel_{1:032x}",
        source_entity_id=EntityId(root=f"entity_{1:032x}"),
        target_entity_id=EntityId(root=f"entity_{2:032x}"),
        relationship=RelationKind.CORRELATED_WITH,
        memory_layer=MemoryLayer.REFERENCE,
        assertion_status=AssertionStatus.INFERRED,
        relation_version=1,
        evidence_ids=(current.evidence_id, historical.evidence_id),
    )
    result = assemble_case_brief(
        candidate_context=(historical, rival, current),
        previous_hypotheses=(),
        ranked_evidence_ids=(current.evidence_id, rival.evidence_id),
        relationships=(reference_edge,),
        max_contexts=2,
        max_chars=4_000,
    )

    assert result.context == (current, rival)
    assert all(item.case_scope == "current_case" for item in result.context)
    assert any("reference" in note.lower() for note in result.notes)


def test_case_relationship_expands_existing_context_without_claiming_cause() -> None:
    seed = _context(1)
    unrelated = _context(2)
    neighbor = _context(3)
    edge = EvidenceRelation(
        relation_id=f"rel_{2:032x}",
        source_entity_id=EntityId(root=f"entity_{3:032x}"),
        target_entity_id=EntityId(root=f"entity_{4:032x}"),
        relationship=RelationKind.CORRELATED_WITH,
        memory_layer=MemoryLayer.MACHINE,
        assertion_status=AssertionStatus.OBSERVED,
        relation_version=1,
        evidence_ids=(seed.evidence_id, neighbor.evidence_id),
    )
    result = assemble_case_brief(
        candidate_context=(seed, unrelated, neighbor),
        previous_hypotheses=(),
        ranked_evidence_ids=(seed.evidence_id,),
        relationships=(edge,),
        max_contexts=2,
        max_chars=4_000,
    )

    assert result.context == (seed, neighbor)
    assert any("does not establish causality" in note for note in result.notes)


def test_empty_context_is_explicitly_insufficient() -> None:
    result = assemble_case_brief(
        candidate_context=(), previous_hypotheses=(), ranked_evidence_ids=()
    )
    assert result.context == ()
    assert result.insufficient_context
    assert any("No case evidence" in note for note in result.notes)


def test_required_missing_or_historical_context_is_quality_limited() -> None:
    missing = _context(1, status=EvidenceContextStatus.MISSING)
    historical = _context(2, scope="historical")
    result = assemble_case_brief(
        candidate_context=(historical, missing),
        previous_hypotheses=(),
        ranked_evidence_ids=(),
        required_evidence_ids=(missing.evidence_id, historical.evidence_id),
        max_contexts=2,
        max_chars=4_000,
    )

    assert result.context == (missing, historical)
    assert result.quality_limited_required_ids == (missing.evidence_id, historical.evidence_id)
    assert result.insufficient_context
    assert any("quality" in note.lower() for note in result.notes)


def test_invalid_bounds_and_duplicate_context_ids_fail_closed() -> None:
    item = _context(1)
    with pytest.raises(ValueError, match="bounds"):
        assemble_case_brief(
            candidate_context=(item,),
            previous_hypotheses=(),
            ranked_evidence_ids=(),
            max_contexts=0,
        )
    with pytest.raises(ValueError, match="duplicate"):
        assemble_case_brief(
            candidate_context=(item, item),
            previous_hypotheses=(),
            ranked_evidence_ids=(),
        )
