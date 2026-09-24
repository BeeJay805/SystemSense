"""Read-only resolution of a selected, pinned current-case graph branch."""

from dataclasses import dataclass

from systemsense.domain.evidence import EvidenceRecord
from systemsense.domain.ids import CaseId, EvidenceId
from systemsense.domain.time import utc_now
from systemsense.evidence.graph import EvidenceRelation
from systemsense.evidence.retrieval import (
    EvidenceCatalogQuery,
    EvidenceRelationRepository,
    EvidenceRetrievalQuery,
    EvidenceRetriever,
    RetrievedEvidence,
)
from systemsense.storage.search_frontier import (
    FrontierBranchReferenceV2,
    FrontierItemV1,
    FrontierStatus,
    RelevantVersionsV1,
    SearchFrontierRepository,
)
from systemsense.storage.sqlite_store import SQLiteStore


@dataclass(frozen=True, slots=True)
class FrontierBranchResultV1:
    item_id: str
    status: FrontierStatus
    evidence: RetrievedEvidence | None
    limitations: tuple[str, ...]


def process_claimed_branch(
    *,
    case_id: CaseId,
    selected: FrontierItemV1,
    branch_relation: EvidenceRelation,
    current_packet_evidence_ids: tuple[EvidenceId, ...],
    expected_versions: RelevantVersionsV1,
    store: SQLiteStore,
    retriever: EvidenceRetriever,
    frontier: SearchFrontierRepository,
) -> FrontierBranchResultV1:
    """Resolve one omitted cited record; coordinator confirms focused delivery.

    Success deliberately remains RUNNING. Only the coordinator, after showing
    the returned ID in a stable focused packet, may transition to SATISFIED.
    """

    live = frontier.readback(selected.item_id)
    if (
        live != selected
        or live.case_id != case_id
        or live.status is not FrontierStatus.CLAIMED
        or not isinstance(live.reference, FrontierBranchReferenceV2)
        or not frontier.same_database(store)
        or getattr(retriever, "_store", None) is not store
    ):
        raise ValueError("claimed branch does not match its case and source store")

    phase = FrontierStatus.CLAIMED

    def close(status: FrontierStatus, reason: str) -> FrontierBranchResultV1:
        frontier.transition(selected.item_id, phase, status, reason)
        return FrontierBranchResultV1(selected.item_id, status, None, (reason,))

    def current_relation() -> EvidenceRelation | None:
        reference = live.reference
        assert isinstance(reference, FrontierBranchReferenceV2)
        repository = EvidenceRelationRepository(store)
        try:
            relation = repository.read_version(reference.relation_id, reference.relation_version)
            latest = repository.read_latest(reference.relation_id)
        except ValueError:
            return None
        if (
            relation is None
            or latest is None
            or latest.relation_version != relation.relation_version
            or relation != branch_relation
            or FrontierBranchReferenceV2.from_relation(relation) != reference
            or not relation.is_valid_at(utc_now())
            or not 1 <= len(relation.evidence_ids) <= 8
        ):
            return None
        sources: set[str] = set()
        for evidence_id in relation.evidence_ids:
            row = store.evidence(case_id=str(case_id), evidence_id=str(evidence_id))
            if row is None:
                return None
            indexed_source = store.connection.execute(
                "SELECT source_id FROM evidence WHERE case_id=? AND evidence_id=?",
                (str(case_id), str(evidence_id)),
            ).fetchone()
            try:
                record = EvidenceRecord.model_validate_json(row.record_json)
            except ValueError:
                return None
            if (
                record.case_id != case_id
                or record.evidence_id != evidence_id
                or indexed_source is None
                or record.source.source_id != indexed_source[0]
                or record.observed_at > record.captured_at
                or record.observed_at.isoformat() != row.observed_at
                or record.captured_at.isoformat() != row.captured_at
            ):
                return None
            sources.add(record.source.source_id)
        if not set(relation.source_ids) <= sources:
            return None
        return relation

    def generation() -> int:
        return retriever.discover(
            EvidenceCatalogQuery(case_id=case_id, limit=1)
        ).case_evidence_generation

    if selected.versions != expected_versions:
        return close(FrontierStatus.OBSOLETE, "catalog_generation_changed")
    try:
        current_generation = generation()
    except (RuntimeError, ValueError):
        return close(FrontierStatus.OBSOLETE, "branch_catalog_error")
    if current_generation != expected_versions.evidence:
        return close(FrontierStatus.OBSOLETE, "catalog_generation_changed")
    relation = current_relation()
    if relation is None:
        return close(FrontierStatus.OBSOLETE, "branch_source_changed")
    visible = {str(item) for item in current_packet_evidence_ids}
    if not any(str(item) in visible for item in relation.evidence_ids):
        return close(FrontierStatus.OBSOLETE, "branch_not_anchored_in_packet")
    neighbor = next((item for item in relation.evidence_ids if str(item) not in visible), None)
    if neighbor is None:
        return close(FrontierStatus.OBSOLETE, "no_unseen_neighbor")
    try:
        current_generation = generation()
    except (RuntimeError, ValueError):
        return close(FrontierStatus.OBSOLETE, "branch_catalog_error")
    if current_generation != expected_versions.evidence:
        return close(FrontierStatus.OBSOLETE, "catalog_generation_changed")

    frontier.transition(
        selected.item_id, FrontierStatus.CLAIMED, FrontierStatus.ADMITTED, "admitted"
    )
    frontier.transition(
        selected.item_id, FrontierStatus.ADMITTED, FrontierStatus.RUNNING, "retrieving"
    )
    phase = FrontierStatus.RUNNING
    try:
        packet = retriever.retrieve(
            EvidenceRetrievalQuery(
                current_case_id=case_id,
                evidence_ids=(neighbor,),
                evidence_limit=1,
                coverage_limit=1,
                candidate_limit=1,
            )
        )
        stable_generation = generation() == expected_versions.evidence
        stable_relation = current_relation() == relation
    except (RuntimeError, ValueError):
        return close(FrontierStatus.FAILED, "branch_retrieval_error")
    if not stable_generation:
        return close(FrontierStatus.OBSOLETE, "catalog_generation_changed")
    if not stable_relation:
        return close(FrontierStatus.OBSOLETE, "branch_source_changed")
    evidence = next((item for item in packet.evidence if item.evidence_id == neighbor), None)
    if evidence is None or evidence.case_id != case_id:
        return close(FrontierStatus.FAILED, "branch_neighbor_unavailable")
    row = store.evidence(case_id=str(case_id), evidence_id=str(neighbor))
    indexed_source = store.connection.execute(
        "SELECT source_id FROM evidence WHERE case_id=? AND evidence_id=?",
        (str(case_id), str(neighbor)),
    ).fetchone()
    if (
        row is None
        or indexed_source is None
        or evidence.source_id != indexed_source[0]
        or evidence.observed_at.isoformat() != row.observed_at
        or evidence.captured_at.isoformat() != row.captured_at
    ):
        return close(FrontierStatus.OBSOLETE, "branch_source_changed")
    return FrontierBranchResultV1(
        item_id=selected.item_id,
        status=FrontierStatus.RUNNING,
        evidence=evidence,
        limitations=evidence.limitations,
    )
