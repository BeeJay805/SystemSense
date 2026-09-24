"""Current-case advisory frontier assembly and one bounded local action.

Only the case store and candidate registry attest source meaning. Ranking does
not admit a probe: the outer investigator must revalidate and authorize any
returned measurement reference. Reference branches and deep questions remain
unsupported until their source identity/semantic schemas are persisted.
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
from systemsense.evidence.retrieval import (
    EvidenceCatalogEntry,
    EvidenceCatalogQuery,
    EvidenceRetriever,
)
from systemsense.storage.case_candidates import CandidateResolution, CaseCandidateRegistry
from systemsense.storage.search_frontier import (
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
    snapshot_id: str | None = None


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
        else:
            raise ValueError("branch and deep frontier sources are not yet authoritative")
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
) -> FrontierPolicyStepV1:
    """Rank then claim exactly one; retrieve stored bytes or return a typed need."""

    def current_request() -> FrontierRankRequestV1:
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
            allow_evidence_generation_advance=packet_receipt_id is not None,
        )

    request = current_request()
    frozen_at = utc_now()
    ranking = ranker.rank(request).validate_against(request)
    if utc_now() >= deadline_at:
        raise ValueError("frontier policy deadline expired after ranking")
    # Ranking is outside the database transaction. Re-read all authoritative
    # source bindings before claiming, so a changed registry/catalog fails closed.
    current = current_request()
    if current.item_semantics != request.item_semantics:
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
                request_frozen_at=frozen_at,
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
        )
        return FrontierPolicyStepV1(selected=selected, ranking=ranking, retrieval=retrieval)
    if selected.reference.kind == "measure":
        candidate_id = selected.reference.candidate_id
        assert candidate_id is not None
        candidate = next(item for item in candidate_refs if item.candidate_id == candidate_id)
        return FrontierPolicyStepV1(
            selected=selected, ranking=ranking, measurement=candidate, snapshot_id=snapshot_id
        )
    raise AssertionError("unsupported frontier kind passed request assembly")
