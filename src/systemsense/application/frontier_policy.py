"""Current-case advisory frontier assembly and one bounded local action.

Only the case store and candidate registry attest source meaning. Ranking does
not admit a probe: the outer investigator must revalidate and authorize any
returned measurement reference. Branch and deep selections remain advisory.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass

from systemsense.application.frontier_discovery import (
    FrontierRetrievalResult,
    process_claimed_retrieval,
)
from systemsense.decision.candidates import AdmittedCandidateRefV1
from systemsense.decision.contracts import ProviderIdentity
from systemsense.decision.frontier_ranker import (
    FrontierItemSemanticV1,
    FrontierRankRequestV1,
    FrontierRankResponseV1,
    MixedFrontierRanker,
    SemanticPacketRefV1,
)
from systemsense.domain.evidence import EvidenceRecord, StatementKind
from systemsense.domain.ids import CaseId
from systemsense.domain.time import UtcDateTime, utc_now
from systemsense.evidence.graph import AssertionStatus, EvidenceRelation, MemoryLayer
from systemsense.evidence.retrieval import (
    EvidenceCatalogEntry,
    EvidenceCatalogQuery,
    EvidenceRelationRepository,
    EvidenceRetriever,
)
from systemsense.storage.case_candidates import CandidateResolution, CaseCandidateRegistry
from systemsense.storage.search_frontier import (
    FrontierBranchReferenceV2,
    FrontierItemV1,
    FrontierStatus,
    RelevantVersionsV1,
    SearchFrontierRepository,
)
from systemsense.storage.sqlite_store import SQLiteStore


@dataclass(frozen=True, slots=True)
class FrontierPolicyStepV1:
    """One selected reference; a measurement is advisory, never dispatchable."""

    selected: FrontierItemV1
    ranking: FrontierRankResponseV1
    retrieval: FrontierRetrievalResult | None = None
    measurement: AdmittedCandidateRefV1 | None = None
    branch_relation: EvidenceRelation | None = None
    deep_question_id: str | None = None
    snapshot_id: str | None = None


@dataclass(frozen=True, slots=True)
class PreparedFrontierStepV1:
    """Owner-attested request and the instant its source bindings were frozen."""

    request: FrontierRankRequestV1
    frozen_at: UtcDateTime


def _sha256_json(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _evidence_semantic(
    *,
    item: FrontierItemV1,
    entry: EvidenceCatalogEntry,
    store: SQLiteStore,
) -> FrontierItemSemanticV1:
    evidence_id = item.reference.evidence_id
    assert evidence_id is not None
    row = store.evidence(case_id=str(item.case_id), evidence_id=str(evidence_id))
    if row is None:
        raise ValueError("catalog source evidence is absent")
    record = EvidenceRecord.model_validate_json(row.record_json)
    if (
        entry.case_id != item.case_id
        or entry.evidence_id != evidence_id
        or record.case_id != item.case_id
        or record.evidence_id != evidence_id
        or record.observed_at != entry.observed_at
        or record.captured_at != entry.captured_at
        or record.observed_at > record.captured_at
        or record.observed_at.isoformat() != row.observed_at
        or record.captured_at.isoformat() != row.captured_at
        or (row.execution_id is not None and str(record.collector.execution_id) != row.execution_id)
        or record.collector.id != entry.collector_id
        or record.source.source_id != entry.source_id
        or record.summary[:240] != entry.summary
    ):
        raise ValueError("catalog metadata does not match source record")
    limitations: list[str] = []
    if record.limitations:
        first = record.limitations[0]
        limitations.append(
            first if 1 <= len(first) <= 80 else "source_limitation_text_exceeds_budget"
        )
    projection_limits: list[str] = []
    if len(record.limitations) > 1:
        projection_limits.append("src_more")
    if row.time_quality == "unknown":
        projection_limits.append("observation_time_unknown")
    if record.statement_kind is not StatementKind.OBSERVED_FACT:
        projection_limits.append("non_observed")
    summary = record.summary[:130]
    if len(record.summary) > len(summary):
        projection_limits.append("summary_truncated")
    if len(record.collector.id) > 60:
        projection_limits.append("col_cut")
    if projection_limits:
        limitations.append(";".join(projection_limits))
    quality = "limited" if limitations else "observed"
    return FrontierItemSemanticV1(
        item_id=item.item_id,
        case_id=item.case_id,
        reference_id=str(evidence_id),
        source_kind="evidence_repository",
        source_record_sha256=hashlib.sha256(row.record_json.encode("utf-8")).hexdigest(),
        source_recorded_at=record.captured_at,
        source_time_quality="source_recorded",
        quality=quality,
        limitations=tuple(limitations),
        information_goal=f"What does stored {record.collector.id[:60]} evidence show: {summary}?",
        target_scope="unknown",
        target_label=record.collector.id[:80],
    )


def _candidate_semantic(
    *,
    item: FrontierItemV1,
    candidate: AdmittedCandidateRefV1,
    registry: CaseCandidateRegistry,
    candidate_epoch: int,
) -> FrontierItemSemanticV1:
    candidate_id = item.reference.candidate_id
    assert candidate_id is not None
    resolution = registry.resolve(item.case_id, candidate_epoch, candidate_id)
    if not isinstance(resolution, CandidateResolution):
        raise ValueError("candidate registry could not revalidate source")
    resolved = AdmittedCandidateRefV1.model_validate(
        resolution.candidate.model_dump(mode="json", exclude={"schema_version"})
    )
    if (
        candidate.candidate_id != candidate_id
        or candidate != resolved
        or resolution.invocation.window != item.reference.window
        or item.cost_ms != resolved.cost_ms
    ):
        raise ValueError("candidate reference does not match registry source")
    # The current registry has no persisted semantic question or target label.
    # This bounded template quotes its validated description and declares the
    # missing semantic fields rather than inventing target details.
    clipped = candidate.description[:170]
    limitations = ["registry_question_and_target_scope_not_recorded"]
    if len(candidate.description) > len(clipped):
        limitations.append("candidate_description_truncated_for_attention")
    return FrontierItemSemanticV1(
        item_id=item.item_id,
        case_id=item.case_id,
        reference_id=candidate_id,
        source_kind="capability_registry",
        source_record_sha256=_sha256_json(resolution.candidate.model_dump(mode="json")),
        source_recorded_at=None,
        source_time_quality="not_available",
        quality="limited",
        limitations=tuple(limitations),
        information_goal=f"What would the registered measurement reveal: {clipped}?",
        target_scope="unknown",
        target_label="Registered measurement",
        measurement_window=resolution.invocation.window,
    )


def _branch_relation(*, item: FrontierItemV1, store: SQLiteStore) -> EvidenceRelation:
    reference = item.reference
    if not isinstance(reference, FrontierBranchReferenceV2):
        raise ValueError("legacy branch reference lacks exact source")
    repository = EvidenceRelationRepository(store)
    relation = repository.read_version(reference.relation_id, reference.relation_version)
    if relation is None:
        raise ValueError("branch source is unbound")
    if _sha256_json(relation.model_dump(mode="json")) != reference.relation_sha256:
        raise ValueError("branch source content differs from pinned reference")
    latest = repository.read_latest(reference.relation_id)
    if latest is None or latest.relation_version != reference.relation_version:
        raise ValueError("branch source version was superseded")
    for evidence_id in relation.evidence_ids:
        row = store.evidence(case_id=str(item.case_id), evidence_id=str(evidence_id))
        if row is None:
            raise ValueError("branch source evidence is outside this case")
    if not relation.evidence_ids:
        raise ValueError("branch requires current-case evidence provenance")
    return relation


def _branch_semantic(*, item: FrontierItemV1, store: SQLiteStore) -> FrontierItemSemanticV1:
    relation = _branch_relation(item=item, store=store)
    reference = item.reference
    assert isinstance(reference, FrontierBranchReferenceV2)
    limitations = ["relationship_is_not_causal_proof"]
    if relation.memory_layer is MemoryLayer.REFERENCE:
        limitations.append("reference_not_machine_observation")
    elif not relation.is_valid_at(utc_now()):
        limitations.append("relationship_not_current")
    quality = (
        "inferred"
        if relation.assertion_status is AssertionStatus.INFERRED
        else "limited"
        if relation.memory_layer is MemoryLayer.REFERENCE or not relation.is_valid_at(utc_now())
        else "observed"
    )
    return FrontierItemSemanticV1(
        item_id=item.item_id,
        case_id=item.case_id,
        reference_id=reference.branch_id,
        source_kind="knowledge_graph",
        source_record_sha256=_sha256_json(relation.model_dump(mode="json")),
        source_recorded_at=None,
        source_time_quality="not_available",
        quality=quality,
        information_goal=(
            f"What would inspecting this {relation.relationship.value} relationship reveal?"
        ),
        target_scope="unknown",
        target_label=str(relation.target_entity_id),
        relation_id=relation.relation_id,
        relation_kind=relation.relationship,
        relation_assertion_status=relation.assertion_status,
        relation_source_label=str(relation.source_entity_id),
        relation_target_label=str(relation.target_entity_id),
        limitations=tuple(limitations),
    )


def _deep_question_semantic(
    *, item: FrontierItemV1, store: SQLiteStore, requested_symptom: str
) -> FrontierItemSemanticV1:
    row = store.connection.execute(
        "SELECT symptom,created_at FROM cases WHERE case_id=?",
        (str(item.case_id),),
    ).fetchone()
    if row is None:
        raise ValueError("deep question case source is unavailable")
    symptom, created_at = str(row[0]), str(row[1])
    if symptom != requested_symptom:
        raise ValueError("deep question symptom differs from case source")
    source = f"{item.case_id}|{symptom}|{item.versions.objective}|{item.versions.evidence}"
    question_id = "question_v1_" + hashlib.sha256(source.encode()).hexdigest()[:32]
    if item.reference.question_id != question_id:
        raise ValueError("deep question does not match case source")
    return FrontierItemSemanticV1(
        item_id=item.item_id,
        case_id=item.case_id,
        reference_id=question_id,
        source_kind="reasoning_question",
        source_record_sha256=_sha256_json(
            {
                "case_id": str(item.case_id),
                "symptom": symptom,
                "created_at": created_at,
                "objective_version": item.versions.objective,
                "evidence_generation": item.versions.evidence,
            }
        ),
        source_recorded_at=None,
        source_time_quality="not_available",
        quality="proposed",
        information_goal="Which explanation merits focused deep review of the case evidence?",
        target_scope="unknown",
        target_label="Current case",
    )


def assemble_frontier_request(
    *,
    case_id: CaseId,
    items: tuple[FrontierItemV1, ...],
    versions: RelevantVersionsV1,
    symptom: str,
    hypothesis_briefs: tuple[str, ...],
    deadline_at: UtcDateTime,
    provider: ProviderIdentity,
    model_weight_sha256: str,
    catalog_entries: tuple[EvidenceCatalogEntry, ...],
    candidate_refs: tuple[AdmittedCandidateRefV1, ...],
    candidate_registry: CaseCandidateRegistry | None,
    candidate_epoch: int,
    store: SQLiteStore,
    retriever: EvidenceRetriever,
    frontier: SearchFrontierRepository,
    evidence_packets: tuple[SemanticPacketRefV1, ...] = (),
    allow_evidence_generation_advance: bool = False,
) -> FrontierRankRequestV1:
    """Bind every offered ID to authoritative local readback before inference."""

    if not 1 <= len(items) <= 32:
        raise ValueError("frontier policy requires one to 32 items")
    # Receipt-backed mixed requests pass packet bytes without requesting
    # generation advancement; retrieval IDs need the exact catalog generation.
    if allow_evidence_generation_advance and any(
        item.reference.kind != "measure" for item in items
    ):
        raise ValueError("generation advancement is only supported for receipt-bound measurements")
    if deadline_at <= utc_now():
        raise ValueError("frontier policy deadline expired")
    if len({str(item.evidence_id) for item in catalog_entries}) != len(catalog_entries):
        raise ValueError("catalog contains duplicate evidence IDs")
    if len({item.candidate_id for item in candidate_refs}) != len(candidate_refs):
        raise ValueError("candidate references repeat an ID")
    catalog = {item.evidence_id: item for item in catalog_entries}
    candidates = {item.candidate_id: item for item in candidate_refs}
    generation = retriever.discover(
        EvidenceCatalogQuery(case_id=case_id, limit=1)
    ).case_evidence_generation
    if versions.evidence != generation and not (
        allow_evidence_generation_advance
        and versions.evidence is not None
        and generation >= versions.evidence
    ):
        raise ValueError("catalog generation changed before frontier ranking")
    semantics: list[FrontierItemSemanticV1] = []
    for offered in items:
        item = frontier.readback(offered.item_id)
        if (
            item != offered
            or item.case_id != case_id
            or item.status is not FrontierStatus.REQUESTED
            or item.versions != versions
        ):
            raise ValueError("frontier item readback differs from offered item")
        if item.reference.kind == "retrieve_evidence":
            evidence_id = item.reference.evidence_id
            assert evidence_id is not None
            entry = catalog.get(evidence_id)
            if entry is None:
                raise ValueError("catalog entry is missing for frontier evidence")
            semantics.append(_evidence_semantic(item=item, entry=entry, store=store))
        elif item.reference.kind == "measure":
            candidate_id = item.reference.candidate_id
            assert candidate_id is not None
            candidate = candidates.get(candidate_id)
            if candidate is None or candidate_registry is None:
                raise ValueError("candidate source is missing for frontier measurement")
            semantics.append(
                _candidate_semantic(
                    item=item,
                    candidate=candidate,
                    registry=candidate_registry,
                    candidate_epoch=candidate_epoch,
                )
            )
        elif item.reference.kind == "review_branch":
            semantics.append(_branch_semantic(item=item, store=store))
        elif item.reference.kind == "consult_deep":
            semantics.append(
                _deep_question_semantic(item=item, store=store, requested_symptom=symptom)
            )
        else:
            raise AssertionError("unsupported frontier kind")
    return FrontierRankRequestV1(
        case_id=case_id,
        provider=provider,
        model_weight_sha256=model_weight_sha256,
        deadline_at=deadline_at,
        symptom=symptom,
        hypothesis_briefs=hypothesis_briefs,
        items=items,
        item_semantics=tuple(semantics),
        evidence_packets=evidence_packets,
    )


def _current_frontier_request(
    *,
    case_id: CaseId,
    items: tuple[FrontierItemV1, ...],
    versions: RelevantVersionsV1,
    symptom: str,
    hypothesis_briefs: tuple[str, ...],
    deadline_at: UtcDateTime,
    provider: ProviderIdentity,
    model_weight_sha256: str,
    catalog_entries: tuple[EvidenceCatalogEntry, ...],
    candidate_refs: tuple[AdmittedCandidateRefV1, ...],
    candidate_registry: CaseCandidateRegistry | None,
    candidate_epoch: int,
    store: SQLiteStore,
    retriever: EvidenceRetriever,
    frontier: SearchFrontierRepository,
    evidence_packets: tuple[SemanticPacketRefV1, ...] = (),
    packet_receipt_id: str | None = None,
) -> FrontierRankRequestV1:
    from systemsense.storage.frontier_packet_receipts import FrontierPacketReceiptRepository

    packets = evidence_packets
    if packet_receipt_id is not None:
        receipt = FrontierPacketReceiptRepository(store).readback(packet_receipt_id)
        if receipt.case_id != case_id or receipt.epoch_state_version != candidate_epoch:
            raise ValueError("frontier packet receipt does not bind candidate epoch")
        packets = receipt.packets
    return assemble_frontier_request(
        case_id=case_id,
        items=items,
        versions=versions,
        symptom=symptom,
        hypothesis_briefs=hypothesis_briefs,
        deadline_at=deadline_at,
        provider=provider,
        model_weight_sha256=model_weight_sha256,
        catalog_entries=catalog_entries,
        candidate_refs=candidate_refs,
        candidate_registry=candidate_registry,
        candidate_epoch=candidate_epoch,
        store=store,
        retriever=retriever,
        frontier=frontier,
        evidence_packets=packets,
        allow_evidence_generation_advance=packet_receipt_id is not None
        and all(item.reference.kind == "measure" for item in items),
    )


def prepare_frontier_step(
    *,
    case_id: CaseId,
    items: tuple[FrontierItemV1, ...],
    versions: RelevantVersionsV1,
    symptom: str,
    hypothesis_briefs: tuple[str, ...],
    deadline_at: UtcDateTime,
    provider: ProviderIdentity,
    model_weight_sha256: str,
    catalog_entries: tuple[EvidenceCatalogEntry, ...],
    candidate_refs: tuple[AdmittedCandidateRefV1, ...],
    candidate_registry: CaseCandidateRegistry | None,
    candidate_epoch: int,
    store: SQLiteStore,
    retriever: EvidenceRetriever,
    frontier: SearchFrontierRepository,
    evidence_packets: tuple[SemanticPacketRefV1, ...] = (),
    packet_receipt_id: str | None = None,
) -> PreparedFrontierStepV1:
    """Freeze an authoritative request on the case owner before ranking."""

    request = _current_frontier_request(
        case_id=case_id,
        items=items,
        versions=versions,
        symptom=symptom,
        hypothesis_briefs=hypothesis_briefs,
        deadline_at=deadline_at,
        provider=provider,
        model_weight_sha256=model_weight_sha256,
        catalog_entries=catalog_entries,
        candidate_refs=candidate_refs,
        candidate_registry=candidate_registry,
        candidate_epoch=candidate_epoch,
        store=store,
        retriever=retriever,
        frontier=frontier,
        evidence_packets=evidence_packets,
        packet_receipt_id=packet_receipt_id,
    )
    return PreparedFrontierStepV1(request=request, frozen_at=utc_now())


def rank_frozen_frontier(
    request: FrontierRankRequestV1, ranker: MixedFrontierRanker
) -> FrontierRankResponseV1:
    """Rank a frozen value without any store or machine authority."""

    return ranker.rank(request).validate_against(request)


def finalize_frontier_step(
    *,
    prepared: PreparedFrontierStepV1,
    ranking: FrontierRankResponseV1,
    case_id: CaseId,
    items: tuple[FrontierItemV1, ...],
    versions: RelevantVersionsV1,
    symptom: str,
    hypothesis_briefs: tuple[str, ...],
    deadline_at: UtcDateTime,
    provider: ProviderIdentity,
    model_weight_sha256: str,
    catalog_entries: tuple[EvidenceCatalogEntry, ...],
    candidate_refs: tuple[AdmittedCandidateRefV1, ...],
    candidate_registry: CaseCandidateRegistry | None,
    candidate_epoch: int,
    store: SQLiteStore,
    retriever: EvidenceRetriever,
    frontier: SearchFrontierRepository,
    evidence_packets: tuple[SemanticPacketRefV1, ...] = (),
    packet_receipt_id: str | None = None,
    defer_retrieval_satisfaction: bool = False,
) -> FrontierPolicyStepV1:
    """Validate the exact frozen rank and all live sources before side effects."""

    request = prepared.request
    ranking.validate_against(request)
    if request.deadline_at != deadline_at:
        raise ValueError("frontier deadline differs from frozen request")
    if utc_now() >= deadline_at:
        raise ValueError("frontier policy deadline expired after ranking")
    # Ranking is outside the database transaction. Re-read all authoritative
    # source bindings before claiming, so a changed registry/catalog fails closed.
    current = _current_frontier_request(
        case_id=case_id,
        items=items,
        versions=versions,
        symptom=symptom,
        hypothesis_briefs=hypothesis_briefs,
        deadline_at=deadline_at,
        provider=provider,
        model_weight_sha256=model_weight_sha256,
        catalog_entries=catalog_entries,
        candidate_refs=candidate_refs,
        candidate_registry=candidate_registry,
        candidate_epoch=candidate_epoch,
        store=store,
        retriever=retriever,
        frontier=frontier,
        evidence_packets=evidence_packets,
        packet_receipt_id=packet_receipt_id,
    )
    if current != request:
        raise ValueError("frontier semantic source changed after ranking")
    selected_id = ranking.ranked_item_ids[0]
    selected_before_claim = next(item for item in items if item.item_id == selected_id)
    snapshot_id: str | None = None
    if selected_before_claim.reference.kind == "measure":
        if candidate_registry is None:
            raise ValueError("measurement requires current candidate registry")
        from systemsense.storage.candidate_decision_snapshots import (
            CandidateDecisionSnapshotRepository,
        )

        snapshot_id = (
            CandidateDecisionSnapshotRepository(store)
            .capture_frontier(
                request,
                ranking,
                registry=candidate_registry,
                retriever=retriever,
                frontier=frontier,
                catalog_entries=catalog_entries,
                candidate_refs=candidate_refs,
                selected_item_id=selected_id,
                epoch_state_version=candidate_epoch,
                request_frozen_at=prepared.frozen_at,
                packet_receipt_id=packet_receipt_id,
            )
            .snapshot_id
        )
    selected = frontier.claim_ready(selected_id, versions)
    if selected.reference.kind == "retrieve_evidence":
        retrieval = process_claimed_retrieval(
            item_id=selected_id,
            case_id=case_id,
            retriever=retriever,
            frontier=frontier,
            expected_versions=versions,
            defer_satisfaction=defer_retrieval_satisfaction,
        )
        return FrontierPolicyStepV1(selected=selected, ranking=ranking, retrieval=retrieval)
    if selected.reference.kind == "measure":
        candidate_id = selected.reference.candidate_id
        assert candidate_id is not None
        candidate = next(item for item in candidate_refs if item.candidate_id == candidate_id)
        return FrontierPolicyStepV1(
            selected=selected, ranking=ranking, measurement=candidate, snapshot_id=snapshot_id
        )
    if selected.reference.kind == "review_branch":
        frozen_semantic = next(
            semantic for semantic in request.item_semantics if semantic.item_id == selected.item_id
        )
        try:
            live_semantic = _branch_semantic(item=selected, store=store)
        except ValueError as error:
            frontier.transition(
                selected.item_id, FrontierStatus.CLAIMED, FrontierStatus.OBSOLETE, "source_changed"
            )
            raise ValueError("branch source changed after claim") from error
        if live_semantic != frozen_semantic:
            frontier.transition(
                selected.item_id, FrontierStatus.CLAIMED, FrontierStatus.OBSOLETE, "source_changed"
            )
            raise ValueError("branch source changed after claim")
        try:
            relation = _branch_relation(item=selected, store=store)
        except ValueError as error:
            frontier.transition(
                selected.item_id, FrontierStatus.CLAIMED, FrontierStatus.OBSOLETE, "source_changed"
            )
            raise ValueError("branch source changed after claim") from error
        if _sha256_json(relation.model_dump(mode="json")) != frozen_semantic.source_record_sha256:
            frontier.transition(
                selected.item_id, FrontierStatus.CLAIMED, FrontierStatus.OBSOLETE, "source_changed"
            )
            raise ValueError("branch source changed after claim")
        return FrontierPolicyStepV1(selected=selected, ranking=ranking, branch_relation=relation)
    if selected.reference.kind == "consult_deep":
        frozen_semantic = next(
            semantic for semantic in request.item_semantics if semantic.item_id == selected.item_id
        )
        try:
            live_semantic = _deep_question_semantic(
                item=selected, store=store, requested_symptom=symptom
            )
        except ValueError as error:
            frontier.transition(
                selected.item_id, FrontierStatus.CLAIMED, FrontierStatus.OBSOLETE, "source_changed"
            )
            raise ValueError("deep question source changed after claim") from error
        if live_semantic != frozen_semantic:
            frontier.transition(
                selected.item_id, FrontierStatus.CLAIMED, FrontierStatus.OBSOLETE, "source_changed"
            )
            raise ValueError("deep question source changed after claim")
        return FrontierPolicyStepV1(
            selected=selected,
            ranking=ranking,
            deep_question_id=selected.reference.question_id,
        )
    raise AssertionError("unsupported frontier kind passed request assembly")


def run_frontier_step(
    *,
    case_id: CaseId,
    items: tuple[FrontierItemV1, ...],
    versions: RelevantVersionsV1,
    symptom: str,
    hypothesis_briefs: tuple[str, ...],
    deadline_at: UtcDateTime,
    provider: ProviderIdentity,
    model_weight_sha256: str,
    catalog_entries: tuple[EvidenceCatalogEntry, ...],
    candidate_refs: tuple[AdmittedCandidateRefV1, ...],
    candidate_registry: CaseCandidateRegistry | None,
    candidate_epoch: int,
    store: SQLiteStore,
    retriever: EvidenceRetriever,
    frontier: SearchFrontierRepository,
    ranker: MixedFrontierRanker,
    evidence_packets: tuple[SemanticPacketRefV1, ...] = (),
    packet_receipt_id: str | None = None,
    defer_retrieval_satisfaction: bool = False,
) -> FrontierPolicyStepV1:
    """Preserve the synchronous policy entry point for existing callers."""

    prepared = prepare_frontier_step(
        case_id=case_id,
        items=items,
        versions=versions,
        symptom=symptom,
        hypothesis_briefs=hypothesis_briefs,
        deadline_at=deadline_at,
        provider=provider,
        model_weight_sha256=model_weight_sha256,
        catalog_entries=catalog_entries,
        candidate_refs=candidate_refs,
        candidate_registry=candidate_registry,
        candidate_epoch=candidate_epoch,
        store=store,
        retriever=retriever,
        frontier=frontier,
        evidence_packets=evidence_packets,
        packet_receipt_id=packet_receipt_id,
    )
    ranking = rank_frozen_frontier(prepared.request, ranker)
    return finalize_frontier_step(
        prepared=prepared,
        ranking=ranking,
        case_id=case_id,
        items=items,
        versions=versions,
        symptom=symptom,
        hypothesis_briefs=hypothesis_briefs,
        deadline_at=deadline_at,
        provider=provider,
        model_weight_sha256=model_weight_sha256,
        catalog_entries=catalog_entries,
        candidate_refs=candidate_refs,
        candidate_registry=candidate_registry,
        candidate_epoch=candidate_epoch,
        store=store,
        retriever=retriever,
        frontier=frontier,
        evidence_packets=evidence_packets,
        packet_receipt_id=packet_receipt_id,
        defer_retrieval_satisfaction=defer_retrieval_satisfaction,
    )
