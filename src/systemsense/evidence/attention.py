"""Bounded attention maps: model ranking never erases provenance or coverage gaps."""

from pydantic import Field

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import EvidenceId
from systemsense.evidence.graph import EvidenceRelation
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus

_EXACT_PAGE_LIMITATION = (
    "Exact fact pages selected by local attention; full observation remains stored."
)


class FocusedEvidenceMap(FrozenModel):
    context: tuple[EvidenceContext, ...]
    graph_expanded_ids: tuple[EvidenceId, ...] = ()
    omitted_count: int = Field(ge=0)


def focus_evidence(
    context: tuple[EvidenceContext, ...],
    *,
    ranked_ids: tuple[EvidenceId, ...],
    relationships: tuple[EvidenceRelation, ...],
    required_ids: tuple[EvidenceId, ...] = (),
    max_observations: int = 12,
    max_chars: int = 16_000,
) -> FocusedEvidenceMap:
    """Expand two dependency hops and reserve space for missing/negative evidence.

    Traversal uses stored endpoints for association, in either direction, without
    manufacturing reversed edges or treating connectivity as evidence of causality.
    All input is already scoped to the case's incident and explicit history window.
    """
    if not 1 <= max_observations <= 48 or not 1024 <= max_chars <= 100_000:
        raise ValueError("attention bounds are outside the allowed range")
    by_id = {item.evidence_id: item for item in context}
    seeds = tuple(eid for eid in ranked_ids if eid in by_id)[:max_observations]
    if not seeds:
        seeds = tuple(item.evidence_id for item in context[:max_observations])
    known = set(seeds[:4])
    entities: set[str] = set()
    expanded: list[EvidenceId] = []
    for _ in range(3):
        frontier_evidence = frozenset(known)
        frontier_entities = frozenset(entities)
        for edge in relationships[:256]:
            endpoints = {str(edge.source_entity_id), str(edge.target_entity_id)}
            if frontier_evidence.intersection(edge.evidence_ids) or frontier_entities.intersection(
                endpoints
            ):
                entities.update(endpoints)
                for eid in edge.evidence_ids:
                    if eid in by_id and eid not in known:
                        known.add(eid)
                        expanded.append(eid)
    gaps = tuple(
        item.evidence_id for item in context if item.status is not EvidenceContextStatus.OBSERVED
    )[:8]
    exact_seeds = tuple(
        evidence_id
        for evidence_id in seeds
        if _EXACT_PAGE_LIMITATION in by_id[evidence_id].limitations
    )
    # Required citations include both sides of earlier hypotheses. They precede
    # new ranked candidates; a fresh guess cannot silently erase its contradiction.
    # Exact pages explicitly selected by local attention precede general gaps so
    # their measurements are not silently replaced with empty facts to fit more rows.
    order = tuple(
        dict.fromkeys(
            (
                *required_ids,
                *exact_seeds,
                *gaps,
                *seeds[:4],
                *expanded,
                *seeds[4:],
                *by_id,
            )
        )
    )
    selected: list[EvidenceContext] = []
    observation_count = 0
    for eid in order:
        item = by_id.get(eid)
        if item is None:
            continue
        is_observation = item.status is EvidenceContextStatus.OBSERVED
        if is_observation and observation_count >= max_observations:
            continue
        trial = FocusedEvidenceMap(
            context=(*selected, item),
            graph_expanded_ids=tuple(i.evidence_id for i in selected if i.evidence_id in expanded),
            omitted_count=max(0, len(context) - len(selected) - 1),
        )
        if len(trial.model_dump_json()) > max_chars:
            if _EXACT_PAGE_LIMITATION in item.limitations:
                continue
            item = item.model_copy(
                update={
                    "facts": {},
                    "summary": item.summary[:360],
                    "limitations": (
                        *item.limitations[:3],
                        "Facts omitted from focused model packet; retained in local evidence.",
                    ),
                }
            )
            trial = trial.model_copy(update={"context": (*selected, item)})
            if len(trial.model_dump_json()) > max_chars:
                continue
        selected.append(item)
        observation_count += int(is_observation)
    selected_ids = {str(item.evidence_id) for item in selected}
    result = FocusedEvidenceMap(
        context=tuple(selected),
        graph_expanded_ids=tuple(eid for eid in expanded if str(eid) in selected_ids),
        omitted_count=max(0, len(context) - len(selected)),
    )
    graph_notes: list[str] = []
    if expanded:
        graph_notes.append(
            "Graph expansion is bounded to two association hops and does not establish causality."
        )
    if len(relationships) > 256:
        graph_notes.append(
            "Graph traversal considered the first 256 supplied relationships; "
            "later edges were omitted."
        )
    if graph_notes and result.context:
        first = result.context[0]
        retained = first.limitations[: max(0, 16 - len(graph_notes))]
        annotated = first.model_copy(
            update={"limitations": tuple(dict.fromkeys((*retained, *graph_notes)))}
        )
        result = result.model_copy(update={"context": (annotated, *result.context[1:])})
    # The final graph metadata also counts against the serialized envelope.
    while len(result.model_dump_json()) > max_chars and result.context:
        result = result.model_copy(
            update={
                "context": result.context[:-1],
                "graph_expanded_ids": tuple(
                    eid
                    for eid in result.graph_expanded_ids
                    if eid != result.context[-1].evidence_id
                ),
                "omitted_count": result.omitted_count + 1,
            }
        )
    return result
