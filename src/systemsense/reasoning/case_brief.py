"""Pure, bounded assembly of already admitted evidence for a reasoning turn."""

from __future__ import annotations

import json

from pydantic import Field

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import EvidenceId
from systemsense.evidence.attention import focus_evidence
from systemsense.evidence.graph import EvidenceRelation, MemoryLayer
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.reasoning.contracts import EvidenceDetailRequest, Hypothesis


class CaseBriefAssembly(FrozenModel):
    """Selection metadata for the existing ReasoningRequest evidence fields."""

    context: tuple[EvidenceContext, ...]
    omitted_required_ids: tuple[EvidenceId, ...] = ()
    unavailable_required_ids: tuple[EvidenceId, ...] = ()
    quality_limited_required_ids: tuple[EvidenceId, ...] = ()
    omitted_context_count: int = Field(ge=0)
    context_chars: int = Field(ge=2)
    insufficient_context: bool
    notes: tuple[str, ...] = ()


def _unique_ids(ids: tuple[EvidenceId, ...]) -> tuple[EvidenceId, ...]:
    return tuple(dict.fromkeys(ids))


def hypothesis_citations(hypotheses: tuple[Hypothesis, ...]) -> tuple[EvidenceId, ...]:
    """Rotate causal and missing citations without promoting contextual refs."""
    ordered: list[EvidenceId] = []
    for field in (
        "contradicting_evidence_ids",
        "supporting_evidence_ids",
        "missing_evidence_ids",
    ):
        groups: tuple[tuple[EvidenceId, ...], ...] = tuple(
            getattr(hypothesis, field) for hypothesis in hypotheses
        )
        for index in range(max((len(group) for group in groups), default=0)):
            ordered.extend(group[index] for group in groups if index < len(group))
    return _unique_ids(tuple(ordered))


def hypothesis_claim_windows(hypotheses: tuple[Hypothesis, ...]) -> tuple[EvidenceId, ...]:
    """Retain exact claim scope as context, never as causal support."""
    return _unique_ids(
        tuple(
            hypothesis.claim_window_evidence_id
            for hypothesis in hypotheses
            if hypothesis.claim_window_evidence_id is not None
        )
    )


def hypothesis_noncausal_refs(hypotheses: tuple[Hypothesis, ...]) -> tuple[EvidenceId, ...]:
    """Rotate prior reviewed context after causal citations for source fitting."""
    groups = tuple(
        tuple(item.evidence_id for item in hypothesis.noncausal_observation_refs)
        for hypothesis in hypotheses
    )
    return _unique_ids(
        tuple(
            group[index]
            for index in range(max((len(group) for group in groups), default=0))
            for group in groups
            if index < len(group)
        )
    )


def _context_chars(context: tuple[EvidenceContext, ...]) -> int:
    return len(
        json.dumps(
            [item.model_dump(mode="json") for item in context],
            ensure_ascii=False,
            separators=(",", ":"),
        )
    )


def assemble_case_brief(
    *,
    candidate_context: tuple[EvidenceContext, ...],
    previous_hypotheses: tuple[Hypothesis, ...],
    ranked_evidence_ids: tuple[EvidenceId, ...],
    required_evidence_ids: tuple[EvidenceId, ...] = (),
    relationships: tuple[EvidenceRelation, ...] = (),
    pending_evidence_ids: tuple[EvidenceId, ...] = (),
    pending_detail_requests: tuple[EvidenceDetailRequest, ...] = (),
    max_contexts: int = 12,
    max_chars: int = 16_000,
) -> CaseBriefAssembly:
    """Select existing excerpts and expose missing citations without changing facts.

    ``max_chars`` bounds serialized selected contexts; fit and coverage notes are
    separate coordinator metadata. The caller still validates the full request.
    """
    if not 1 <= max_contexts <= 48 or not 1_024 <= max_chars <= 100_000:
        raise ValueError("case brief bounds are outside the allowed range")
    if (
        len(candidate_context) > 256
        or len(previous_hypotheses) > 16
        or len(relationships) > 256
        or len(ranked_evidence_ids) > 256
        or len(required_evidence_ids) > 256
        or len(pending_evidence_ids) > 256
        or len(pending_detail_requests) > 32
    ):
        raise ValueError("case brief input exceeds bounded collection limits")
    by_id = {item.evidence_id: item for item in candidate_context}
    if len(by_id) != len(candidate_context):
        raise ValueError("duplicate candidate evidence IDs")

    required = _unique_ids(
        (
            *required_evidence_ids,
            *(item.evidence_id for item in pending_detail_requests),
            *pending_evidence_ids,
            *hypothesis_claim_windows(previous_hypotheses),
            *hypothesis_citations(previous_hypotheses),
            *hypothesis_noncausal_refs(previous_hypotheses),
        )
    )
    # Only case-machine relationships may affect attention order. Reference
    # relationships remain advice and cannot promote an observation or scope.
    case_relationships = tuple(
        relation for relation in relationships if relation.memory_layer is MemoryLayer.MACHINE
    )
    scoped_candidates = tuple(
        item
        for _, item in sorted(
            enumerate(candidate_context),
            key=lambda pair: (
                {"current_case": 0, "unspecified": 1, "historical": 2}[pair[1].case_scope],
                pair[0],
            ),
        )
    )
    focused = focus_evidence(
        scoped_candidates,
        ranked_ids=ranked_evidence_ids,
        relationships=case_relationships,
        required_ids=required,
        max_observations=max_contexts,
        max_chars=100_000,
    )
    order = _unique_ids(
        (
            *required,
            *(item.evidence_id for item in focused.context),
            *ranked_evidence_ids,
            *(item.evidence_id for item in scoped_candidates),
        )
    )
    selected: list[EvidenceContext] = []
    for evidence_id in order:
        item = by_id.get(evidence_id)
        if item is None or len(selected) >= max_contexts:
            continue
        trial = (*selected, item)
        if _context_chars(trial) <= max_chars:
            selected.append(item)

    selected_context = tuple(selected)
    selected_ids = {str(item.evidence_id) for item in selected_context}
    omitted_required = tuple(
        evidence_id
        for evidence_id in required
        if evidence_id in by_id and str(evidence_id) not in selected_ids
    )
    unavailable_required = tuple(
        evidence_id for evidence_id in required if evidence_id not in by_id
    )
    quality_limited_required = tuple(
        evidence_id
        for evidence_id in required
        if str(evidence_id) in selected_ids
        and (
            by_id[evidence_id].status is not EvidenceContextStatus.OBSERVED
            or by_id[evidence_id].case_scope != "current_case"
            or by_id[evidence_id].incident_relevant is not True
        )
    )
    omitted_count = len(candidate_context) - len(selected_context)
    notes: list[str] = []
    if omitted_required:
        notes.append(f"Required evidence omitted by case brief bounds: {len(omitted_required)}.")
    if unavailable_required:
        notes.append(
            f"Required evidence unavailable in candidate contexts: {len(unavailable_required)}."
        )
    if quality_limited_required:
        notes.append(
            f"Required evidence has unresolved quality or case-scope limits: "
            f"{len(quality_limited_required)}."
        )
    if omitted_count:
        notes.append(f"Candidate evidence contexts omitted by case brief bounds: {omitted_count}.")
    if not selected_context:
        notes.append("No case evidence context fits the brief or was available.")
    if pending_detail_requests:
        notes.append(f"Pending detail requests remain unresolved: {len(pending_detail_requests)}.")
    if len(case_relationships) != len(relationships):
        notes.append("Reference or historical relationships excluded from case evidence focus.")
    if focused.graph_expanded_ids:
        notes.append("Case graph adjacency guided ordering; it does not establish causality.")
    if any(item.case_scope != "current_case" for item in selected_context):
        notes.append("Non-current context retains its recorded case scope.")
    if any(item.status is not EvidenceContextStatus.OBSERVED for item in selected_context):
        notes.append("Missing or degraded context retains its recorded collection status.")
    return CaseBriefAssembly(
        context=selected_context,
        omitted_required_ids=omitted_required,
        unavailable_required_ids=unavailable_required,
        quality_limited_required_ids=quality_limited_required,
        omitted_context_count=omitted_count,
        context_chars=_context_chars(selected_context),
        insufficient_context=bool(
            omitted_required
            or unavailable_required
            or quality_limited_required
            or not selected_context
        ),
        notes=tuple(notes),
    )
