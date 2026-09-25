"""Deterministic discovery of stored evidence and registered measurement references.

Reference graph edges guide fair exploration; they are never case facts, causal
proof, probe authority, or permission to execute a host measurement.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime

from systemsense.decision.candidates import AdmittedCandidateRefV1
from systemsense.domain.ids import CaseId, EvidenceId
from systemsense.domain.probes import MeasurementWindow
from systemsense.evidence.retrieval import (
    EvidenceCatalogCursor,
    EvidenceCatalogEntry,
    EvidenceCatalogQuery,
    EvidenceRelationRepository,
    EvidenceRetrievalQuery,
    EvidenceRetriever,
    RetrievedEvidence,
)
from systemsense.knowledge.models import KnowledgePacket, probe_roles_for_relation
from systemsense.storage.case_candidates import CandidateGap, CaseCandidateRegistry
from systemsense.storage.search_frontier import (
    FrontierBranchReferenceV2,
    FrontierItemV1,
    FrontierReference,
    FrontierReferenceV1,
    FrontierStatus,
    RelevantVersionsV1,
    SearchFrontierRepository,
)
from systemsense.storage.sqlite_store import SQLiteStore


@dataclass(frozen=True, slots=True)
class FrontierDiscoveryResult:
    items: tuple[FrontierItemV1, ...]
    catalog_entries_scanned: int
    catalog_has_more: bool
    next_cursor: EvidenceCatalogCursor | None
    omitted_reference_count: int
    limitations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FrontierRetrievalResult:
    item_id: str
    status: FrontierStatus
    evidence: RetrievedEvidence | None
    limitations: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FrontierRetrievalPage:
    """One complete small catalog page for durable turn continuation."""

    entries: tuple[EvidenceCatalogEntry, ...]
    eligible_entries: tuple[EvidenceCatalogEntry, ...]
    generation: int
    cursor_before: EvidenceCatalogCursor | None
    cursor_after: EvidenceCatalogCursor | None
    has_more: bool


def discover_retrieval_page(
    *,
    case_id: CaseId,
    retriever: EvidenceRetriever,
    expected_generation: int,
    cursor: EvidenceCatalogCursor | None,
    visible_evidence_ids: tuple[EvidenceId, ...],
    incident_start: datetime,
    incident_end: datetime,
    current_collection_start: datetime,
    page_limit: int = 8,
) -> FrontierRetrievalPage:
    """Return every eligible reference in one page, without truncating its tail.

    A caller may advance ``cursor_after`` only in the same durable write that
    preserves all returned eligible references. Scanning is not admission.
    """

    if not 1 <= page_limit <= 8 or expected_generation < 0:
        raise ValueError("retrieval page bounds are invalid")
    if len(visible_evidence_ids) > 256 or len({str(item) for item in visible_evidence_ids}) != len(
        visible_evidence_ids
    ):
        raise ValueError("visible evidence references are invalid")
    if incident_end < incident_start:
        raise ValueError("incident window is invalid")
    page = retriever.discover(
        EvidenceCatalogQuery(
            case_id=case_id,
            observed_from=incident_start,
            observed_until=incident_end,
            current_collection_start=current_collection_start,
            cursor=cursor,
            limit=page_limit,
        )
    )
    if page.case_evidence_generation != expected_generation:
        raise ValueError("retrieval catalog generation changed")
    if any(entry.case_id != case_id for entry in page.entries) or len(
        {str(entry.evidence_id) for entry in page.entries}
    ) != len(page.entries):
        raise ValueError("retrieval catalog page source is invalid")
    if page.next_cursor is not None and (not page.entries or page.next_cursor == cursor):
        raise ValueError("retrieval catalog cursor did not advance")
    visible = {str(item) for item in visible_evidence_ids}
    eligible = tuple(
        entry
        for entry in page.entries
        if str(entry.evidence_id) not in visible
        and (
            incident_start <= entry.observed_at <= incident_end
            or entry.captured_at >= current_collection_start
        )
    )
    return FrontierRetrievalPage(
        entries=page.entries,
        eligible_entries=eligible,
        generation=page.case_evidence_generation,
        cursor_before=cursor,
        cursor_after=page.next_cursor,
        has_more=page.next_cursor is not None,
    )


def _relation_branches(knowledge: KnowledgePacket) -> dict[str, str]:
    """Map reviewed probe hints to a stable branch, without assigning causal weight."""

    node_ids = {node.node_id for node in knowledge.nodes}
    branches: dict[str, str] = {}
    for relation in sorted(knowledge.relations, key=lambda item: item.relation_id):
        if relation.source_node_id not in node_ids or relation.target_node_id not in node_ids:
            continue
        roles = probe_roles_for_relation(knowledge, relation)
        for probe_id in (*roles.screening_probe_ids, *roles.discriminating_probe_ids):
            branches.setdefault(probe_id, relation.relation_id)
    return branches


def _interleave(
    evidence: tuple[EvidenceCatalogEntry, ...],
    candidates: tuple[AdmittedCandidateRefV1, ...],
    branches: dict[str, str],
    windows_by_candidate: dict[str, MeasurementWindow | None] | None = None,
) -> tuple[tuple[FrontierReferenceV1, int], ...]:
    """One stored result and one new measurement per branch before its tail."""

    stored: dict[str, list[FrontierReferenceV1]] = defaultdict(list)
    measurements: dict[str, list[tuple[FrontierReferenceV1, int]]] = defaultdict(list)
    for entry in evidence:
        branch = branches.get(entry.collector_id, f"unmapped:{entry.collector_id}")
        stored[branch].append(
            FrontierReferenceV1(kind="retrieve_evidence", evidence_id=entry.evidence_id)
        )
    for candidate in candidates:
        branch = branches.get(candidate.probe_id, f"unmapped:{candidate.probe_id}")
        measurements[branch].append(
            (
                FrontierReferenceV1(
                    kind="measure",
                    candidate_id=candidate.candidate_id,
                    window=(windows_by_candidate or {}).get(candidate.candidate_id),
                ),
                candidate.cost_ms,
            )
        )
    queues: dict[str, deque[tuple[FrontierReferenceV1, int]]] = {}
    for branch in sorted(stored.keys() | measurements.keys()):
        stored_refs = stored.get(branch, [])
        measurement_refs = measurements.get(branch, [])
        order: list[tuple[FrontierReferenceV1, int]] = []
        if stored_refs:
            order.append((stored_refs[0], 0))
        if measurement_refs:
            order.append(measurement_refs[0])
        order.extend((reference, 0) for reference in stored_refs[1:])
        order.extend(measurement_refs[1:])
        if order:
            queues[branch] = deque(order)
    selected: list[tuple[FrontierReferenceV1, int]] = []
    while queues:
        for branch in tuple(queues):
            selected.append(queues[branch].popleft())
            if not queues[branch]:
                del queues[branch]
    return tuple(selected)


def seed_frontier_discovery(
    *,
    case_id: CaseId,
    retriever: EvidenceRetriever,
    frontier: SearchFrontierRepository,
    versions: RelevantVersionsV1,
    candidates: tuple[AdmittedCandidateRefV1, ...],
    candidate_registry: CaseCandidateRegistry | None = None,
    candidate_epoch: int | None = None,
    knowledge: KnowledgePacket,
    packet_evidence_ids: tuple[EvidenceId, ...] = (),
    source_store: SQLiteStore | None = None,
    branch_relations: tuple[tuple[str, int], ...] = (),
    consult_deep: bool = False,
    start_cursor: EvidenceCatalogCursor | None = None,
    page_limit: int = 32,
    max_pages: int = 4,
    max_items: int = 32,
) -> FrontierDiscoveryResult:
    """Page one case catalog, then seed stable IDs from only typed local inputs.

    The caller supplies registry-issued candidates; this function never creates
    invocation arguments or invokes their probes. A page cap is reported, not
    confused with catalog exhaustion.
    """

    if not 1 <= page_limit <= 64 or not 1 <= max_pages <= 8 or not 1 <= max_items <= 64:
        raise ValueError("frontier discovery bounds exceeded")
    if len(candidates) > 128 or len(set(item.candidate_id for item in candidates)) != len(
        candidates
    ):
        raise ValueError("candidate references exceed bound or repeat")
    if (candidate_registry is None) != (candidate_epoch is None):
        raise ValueError("candidate window readback requires registry and epoch")
    windows_by_candidate: dict[str, MeasurementWindow | None] = {}
    if candidate_registry is not None and candidate_epoch is not None:
        for reference in candidates:
            resolved = candidate_registry.resolve(case_id, candidate_epoch, reference.candidate_id)
            if isinstance(resolved, CandidateGap) or (
                resolved.candidate.model_dump(mode="json", exclude={"schema_version"})
                != reference.model_dump(mode="json", exclude={"schema_version"})
            ):
                raise ValueError("frontier candidate differs from exact registry readback")
            windows_by_candidate[reference.candidate_id] = resolved.invocation.window
    if len(packet_evidence_ids) > 256:
        raise ValueError("packet evidence reference bound exceeded")
    if len(branch_relations) > 16 or len(set(branch_relations)) != len(branch_relations):
        raise ValueError("branch source references exceed bound or repeat")
    if (branch_relations or consult_deep) and source_store is None:
        raise ValueError("branch and deep discovery require local source readback")
    if source_store is not None and not frontier.same_database(source_store):
        raise ValueError("frontier store mismatch")
    visible = set(packet_evidence_ids)
    entries: list[EvidenceCatalogEntry] = []
    seen: set[EvidenceId] = set()
    cursor = start_cursor
    generation: int | None = None
    more = False
    for _ in range(max_pages):
        page = retriever.discover(
            EvidenceCatalogQuery(case_id=case_id, cursor=cursor, limit=page_limit)
        )
        if generation is None:
            generation = page.case_evidence_generation
        elif page.case_evidence_generation != generation:
            raise ValueError("catalog generation changed during discovery")
        for entry in page.entries:
            if entry.case_id != case_id or entry.evidence_id in seen:
                raise ValueError("catalog page contains foreign or repeated evidence")
            seen.add(entry.evidence_id)
            if entry.evidence_id not in visible:
                entries.append(entry)
        more = page.next_cursor is not None
        if not more:
            break
        if page.next_cursor == cursor or not page.entries:
            raise ValueError("catalog cursor did not advance")
        cursor = page.next_cursor
    assert generation is not None
    if versions.evidence != generation:
        raise ValueError("frontier evidence version differs from catalog generation")
    # A writer may have changed this case after the last page was read.
    current = retriever.discover(EvidenceCatalogQuery(case_id=case_id, limit=1))
    if current.case_evidence_generation != generation:
        raise ValueError("catalog generation changed before frontier seeding")

    ordered = _interleave(
        tuple(entries), candidates, _relation_branches(knowledge), windows_by_candidate
    )
    if source_store is not None and (branch_relations or consult_deep):
        extra: list[tuple[FrontierReference, int]] = []
        relation_repository = EvidenceRelationRepository(source_store)
        for relation_id, relation_version in branch_relations:
            relation = relation_repository.read_latest(relation_id)
            if (
                relation is None
                or relation.relation_version != relation_version
                or not relation.evidence_ids
            ):
                raise ValueError("branch source relation is unavailable or ungrounded")
            if any(
                source_store.evidence(case_id=str(case_id), evidence_id=str(evidence_id)) is None
                for evidence_id in relation.evidence_ids
            ):
                raise ValueError("branch source evidence is outside this case")
            extra.append(
                (
                    FrontierBranchReferenceV2.from_relation(relation),
                    0,
                )
            )
        if consult_deep:
            row = source_store.connection.execute(
                "SELECT symptom FROM cases WHERE case_id=?", (str(case_id),)
            ).fetchone()
            if row is None:
                raise ValueError("deep question case source is unavailable")
            source = f"{case_id}|{row[0]}|{versions.objective}|{versions.evidence}"
            question_id = "question_v1_" + hashlib.sha256(source.encode()).hexdigest()[:32]
            extra.append((FrontierReferenceV1(kind="consult_deep", question_id=question_id), 0))
        # Reserve early attention for one stored result, each sourced branch,
        # and a deep review before any single catalog tail can fill the page.
        mixed: list[tuple[FrontierReference, int]] = []
        if ordered:
            mixed.append(ordered[0])
        mixed.extend(extra)
        mixed.extend(ordered[1:])
        ordered = tuple(mixed)
    chosen = ordered[:max_items]
    items = tuple(
        frontier.upsert_item(case_id, reference, versions, cost_ms=cost_ms)
        for reference, cost_ms in chosen
    )
    limitations: list[str] = []
    if more:
        limitations.append("catalog_more_pages_unscanned")
    if knowledge.truncated or knowledge.omitted_relation_count:
        limitations.append("knowledge_relations_omitted")
    if len(ordered) > max_items:
        limitations.append("frontier_seed_budget_omitted")
    return FrontierDiscoveryResult(
        items=items,
        catalog_entries_scanned=len(seen),
        catalog_has_more=more,
        next_cursor=cursor if more else None,
        omitted_reference_count=len(ordered) - len(chosen),
        limitations=tuple(limitations),
    )


def process_claimed_retrieval(
    *,
    item_id: str,
    case_id: CaseId,
    retriever: EvidenceRetriever,
    frontier: SearchFrontierRepository,
    expected_versions: RelevantVersionsV1,
    defer_satisfaction: bool = False,
) -> FrontierRetrievalResult:
    """Read an exact existing ID and durably close its one-shot frontier item."""

    item = frontier.readback(item_id)
    if item.case_id != case_id or item.reference.kind != "retrieve_evidence":
        raise ValueError("frontier retrieval reference does not match case and kind")
    if item.status is not FrontierStatus.CLAIMED:
        raise ValueError("frontier retrieval item is not claimed")
    if item.versions != expected_versions:
        raise ValueError("frontier relevant versions changed")
    evidence_id = item.reference.evidence_id
    assert evidence_id is not None
    generation = retriever.discover(
        EvidenceCatalogQuery(case_id=case_id, limit=1)
    ).case_evidence_generation
    if generation != expected_versions.evidence:
        frontier.transition(
            item_id, FrontierStatus.CLAIMED, FrontierStatus.OBSOLETE, "stale_catalog"
        )
        return FrontierRetrievalResult(
            item_id=item_id,
            status=FrontierStatus.OBSOLETE,
            evidence=None,
            limitations=("catalog_generation_changed",),
        )
    frontier.transition(item_id, FrontierStatus.CLAIMED, FrontierStatus.ADMITTED, "admitted")
    frontier.transition(item_id, FrontierStatus.ADMITTED, FrontierStatus.RUNNING, "retrieving")
    try:
        packet = retriever.retrieve(
            EvidenceRetrievalQuery(
                current_case_id=case_id,
                evidence_ids=(evidence_id,),
                evidence_limit=1,
                coverage_limit=1,
                candidate_limit=1,
            )
        )
        current = retriever.discover(
            EvidenceCatalogQuery(case_id=case_id, limit=1)
        ).case_evidence_generation
    except (RuntimeError, ValueError):
        frontier.transition(
            item_id, FrontierStatus.RUNNING, FrontierStatus.FAILED, "retrieval_error"
        )
        return FrontierRetrievalResult(
            item_id=item_id,
            status=FrontierStatus.FAILED,
            evidence=None,
            limitations=("stored_evidence_retrieval_error",),
        )
    if current != generation:
        frontier.transition(
            item_id, FrontierStatus.RUNNING, FrontierStatus.OBSOLETE, "stale_catalog"
        )
        return FrontierRetrievalResult(
            item_id=item_id,
            status=FrontierStatus.OBSOLETE,
            evidence=None,
            limitations=("catalog_generation_changed",),
        )
    record = next((item for item in packet.evidence if item.evidence_id == evidence_id), None)
    if record is None:
        limitation = (
            "stored_evidence_truncated"
            if packet.truncated and packet.omitted_evidence_count
            else "stored_evidence_not_found"
        )
        frontier.transition(item_id, FrontierStatus.RUNNING, FrontierStatus.FAILED, limitation)
        return FrontierRetrievalResult(
            item_id=item_id,
            status=FrontierStatus.FAILED,
            evidence=None,
            limitations=(limitation,),
        )
    if not defer_satisfaction:
        frontier.transition(item_id, FrontierStatus.RUNNING, FrontierStatus.SATISFIED, "retrieved")
    return FrontierRetrievalResult(
        item_id=item_id,
        status=FrontierStatus.RUNNING if defer_satisfaction else FrontierStatus.SATISFIED,
        evidence=record,
        limitations=record.limitations,
    )
