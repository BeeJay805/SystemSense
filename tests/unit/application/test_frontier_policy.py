"""A frontier policy may read stored evidence, never grant host authority."""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import TypedDict

import pytest
from pydantic import BaseModel

from systemsense.application.frontier_policy import (
    _candidate_semantic_from_resolution,  # pyright: ignore[reportPrivateUsage]
    assemble_frontier_request,
    finalize_frontier_step,
    prepare_frontier_step,
    rank_frozen_frontier,
    run_frontier_step,
)
from systemsense.decision.candidates import AdmittedCandidateRefV1
from systemsense.decision.contracts import ProviderIdentity
from systemsense.decision.frontier_ranker import (
    FrontierRankRequestV1,
    FrontierRankResponseV1,
    MixedFrontierRanker,
    SemanticPacketRefV1,
    _candidate_description,  # pyright: ignore[reportPrivateUsage]
)
from systemsense.domain.evidence import (
    CollectorReference,
    EvidenceRecord,
    EvidenceSource,
    Extraction,
    Sensitivity,
    StatementKind,
)
from systemsense.domain.ids import CaseId, EntityId, EvidenceId, ExecutionId, stable_source_id
from systemsense.domain.probes import (
    MeasurementNeed,
    MeasurementWindow,
    Privilege,
    ProbeInvocation,
    ProbeLimits,
    ProbeManifest,
    ProbeSafety,
    SafetyClass,
)
from systemsense.domain.time import utc_now
from systemsense.evidence.graph import AssertionStatus, EvidenceRelation, MemoryLayer, RelationKind
from systemsense.evidence.retrieval import (
    EvidenceCatalogEntry,
    EvidenceCatalogQuery,
    EvidenceRelationRepository,
    EvidenceRetriever,
)
from systemsense.inference.laya_runtime import LayaWorkerPresentation
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.storage.candidate_decision_snapshots import CandidateDecisionSnapshotRepository
from systemsense.storage.candidate_dispatch_admissions import CandidateDispatchAdmissionRepository
from systemsense.storage.case_candidates import (
    CandidateGap,
    CandidateRecord,
    CandidateRegistration,
    CandidateTargetBinding,
    CaseCandidateRegistry,
)
from systemsense.storage.frontier_packet_receipts import FrontierPacketReceiptRepository
from systemsense.storage.search_frontier import (
    FrontierBranchReferenceV2,
    FrontierItemV1,
    FrontierReferenceV1,
    FrontierStatus,
    RelevantVersionsV1,
    SearchFrontierRepository,
)
from systemsense.storage.sqlite_store import SQLiteStore

CASE = CaseId(root="case_" + "a" * 32)
NOW = datetime.now(UTC)
PROVIDER = ProviderIdentity(provider_id="laya-policy", provider_version="1", role="fast_decision")
MODEL_SHA = "b" * 64
EPOCH = 2


class _FrontierStepInputs(TypedDict):
    case_id: CaseId
    items: tuple[FrontierItemV1, ...]
    versions: RelevantVersionsV1
    symptom: str
    hypothesis_briefs: tuple[str, ...]
    deadline_at: datetime
    provider: ProviderIdentity
    model_weight_sha256: str
    catalog_entries: tuple[EvidenceCatalogEntry, ...]
    candidate_refs: tuple[AdmittedCandidateRefV1, ...]
    candidate_registry: CaseCandidateRegistry | None
    candidate_epoch: int
    store: SQLiteStore
    retriever: EvidenceRetriever
    frontier: SearchFrontierRepository


class TargetParametersV1(BaseModel):
    pid: int


def _candidate_fixture(
    store: SQLiteStore,
) -> tuple[CaseCandidateRegistry, EvidenceRetriever, SearchFrontierRepository]:
    now = utc_now()
    store.create_case(
        case_id=str(CASE),
        kind="incident",
        symptom="Game stutters",
        created_at=(now - timedelta(seconds=10)).isoformat(),
        status="collecting",
        state_version=EPOCH,
    )
    store.connection.execute(
        "INSERT INTO investigation_checkpoints (case_id,record_json) VALUES (?,?)",
        (
            str(CASE),
            json.dumps(
                {
                    "case_id": str(CASE),
                    "state_version": EPOCH,
                    "status": "running",
                    "deadline_at": (now + timedelta(minutes=5)).isoformat(),
                    "budget_ms": 1000,
                    "spent_cost_ms": 0,
                    "max_probes": 10,
                    "completed_probe_ids": [],
                    "pending_probe_ids": [],
                    "interrupted_probe_ids": [],
                    "unrecorded_attempt_count": 0,
                }
            ),
        ),
    )
    source_id = EvidenceId(root="ev_" + "9" * 32)
    execution_id = ExecutionId(root="exec_" + "9" * 32)
    captured_at = now - timedelta(seconds=2)
    source = EvidenceRecord(
        evidence_id=source_id,
        case_id=CASE,
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=captured_at,
        captured_at=captured_at,
        source=EvidenceSource(
            type="test.fixture",
            source_id=stable_source_id("test.fixture", {"case_id": str(CASE)}),
            locator={},
        ),
        collector=CollectorReference(id="fixture.inventory", version=1, execution_id=execution_id),
        summary="Two inventory processes",
        extraction=Extraction(confidence=1, parser="test.fixture", parser_version=1),
        sensitivity=Sensitivity.SYSTEM_METADATA,
    )
    with store.transaction() as transaction:
        transaction.record_probe_execution(
            execution_id=str(execution_id),
            case_id=str(CASE),
            probe_id="fixture.inventory",
            probe_version=1,
            status="ok",
            parameters_json="{}",
            started_at=(captured_at - timedelta(seconds=1)).isoformat(),
            finished_at=captured_at.isoformat(),
            state_version=EPOCH,
        )
        transaction.insert_evidence(
            case_id=str(CASE),
            evidence_id=str(source_id),
            source_id=source.source.source_id,
            record_json=source.model_dump_json(),
            observed_at=captured_at.isoformat(),
            captured_at=captured_at.isoformat(),
            execution_id=str(execution_id),
            time_basis="source_observed",
            time_quality="exact",
        )
    manifest = ProbeManifest(
        probe_id="fixture.pressure",
        version=1,
        implementation_id="builtin.fixture.pressure",
        question="Read process pressure",
        safety=ProbeSafety(
            safety_class=SafetyClass.R0,
            privilege=Privilege.STANDARD,
            target_state_effect="none",
            outbound_network=False,
        ),
        input_model="TargetParametersV1",
        limits=ProbeLimits(timeout_ms=1000, max_output_bytes=4096, max_records=4),
        category="application",
    )
    registry = CaseCandidateRegistry(
        store,
        registrations=(
            CandidateRegistration(
                manifest=manifest,
                parameter_model=TargetParametersV1,
                observable="fixture.pressure",
                description="Read process pressure",
                cost_ms=100,
                resource_class=ResourceClass.CPU,
                source_evidence_id=source_id,
                freshness_ttl_seconds=60,
                targets=(
                    CandidateTargetBinding(
                        handle="proc_" + "a" * 32,
                        parameters={"pid": 101},
                        description="Read pressure for game process 101",
                    ),
                    CandidateTargetBinding(
                        handle="proc_" + "b" * 32,
                        parameters={"pid": 202},
                        description="Read pressure for launcher process 202",
                    ),
                ),
            ),
        ),
        manifest_lookup=lambda probe_id: manifest if probe_id == "fixture.pressure" else None,
        revalidate_target=lambda case_id, target, invocation: (
            case_id == CASE
            and invocation.target_handle == target.handle
            and invocation.parameters["pid"] == target.parameters["pid"]
        ),
        clock=utc_now,
    )
    return registry, EvidenceRetriever(store), SearchFrontierRepository(store)


def _stored_record(store: SQLiteStore, index: int = 1) -> EvidenceId:
    evidence_id = EvidenceId(root=f"ev_{index:032x}")
    record = EvidenceRecord(
        evidence_id=evidence_id,
        case_id=CASE,
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=NOW - timedelta(seconds=3),
        captured_at=NOW - timedelta(seconds=2),
        source=EvidenceSource(type="test.fixture", source_id="src_" + f"{index:064x}", locator={}),
        collector=CollectorReference(
            id="network.adapter", version=1, execution_id=ExecutionId(root=f"exec_{index:032x}")
        ),
        summary=f"WLAN configuration {index}",
        extraction=Extraction(confidence=1, parser="test.fixture", parser_version=1),
        sensitivity=Sensitivity.SYSTEM_METADATA,
    )
    with store.transaction() as transaction:
        transaction.insert_evidence(
            case_id=str(CASE),
            evidence_id=str(evidence_id),
            source_id=record.source.source_id,
            record_json=record.model_dump_json(),
            observed_at=record.observed_at.isoformat(),
            captured_at=record.captured_at.isoformat(),
        )
    return evidence_id


def _case(store: SQLiteStore) -> tuple[EvidenceRetriever, SearchFrontierRepository]:
    store.create_case(
        case_id=str(CASE), kind="incident", symptom="WiFi is slow", created_at=NOW.isoformat()
    )
    return EvidenceRetriever(store), SearchFrontierRepository(store)


def _versions(retriever: EvidenceRetriever) -> RelevantVersionsV1:
    page = retriever.discover(EvidenceCatalogQuery(case_id=CASE, limit=1))
    return RelevantVersionsV1(objective=1, evidence=page.case_evidence_generation)


def _ranker() -> MixedFrontierRanker:
    return MixedFrontierRanker(ranker=None, provider=PROVIDER, model_weight_sha256=MODEL_SHA)


def _branch_reference(relation: EvidenceRelation) -> FrontierBranchReferenceV2:
    body = json.dumps(
        relation.model_dump(mode="json"), sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    source_sha = hashlib.sha256(body.encode()).hexdigest()
    branch_id = (
        "branch_v2_"
        + hashlib.sha256(
            f"{relation.relation_id}:{relation.relation_version}:{source_sha}".encode()
        ).hexdigest()[:32]
    )
    return FrontierBranchReferenceV2(
        branch_id=branch_id,
        relation_id=relation.relation_id,
        relation_version=relation.relation_version,
        relation_sha256=source_sha,
    )


def test_receipt_generation_advance_rejects_retrieval_offer(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "mixed-frontier-receipt.db") as store:
        registry, retriever, frontier = _candidate_fixture(store)
        versions = _versions(retriever)
        item = frontier.upsert_item(
            CASE,
            FrontierReferenceV1(
                kind="retrieve_evidence", evidence_id=EvidenceId(root="ev_" + "9" * 32)
            ),
            versions,
            cost_ms=100,
        )
        with pytest.raises(ValueError, match="only supported for receipt-bound measurements"):
            assemble_frontier_request(
                case_id=CASE,
                items=(item,),
                versions=versions,
                symptom="Game stutters",
                hypothesis_briefs=(),
                deadline_at=utc_now() + timedelta(minutes=5),
                provider=PROVIDER,
                model_weight_sha256=MODEL_SHA,
                catalog_entries=(),
                candidate_refs=(),
                candidate_registry=registry,
                candidate_epoch=EPOCH,
                store=store,
                retriever=retriever,
                frontier=frontier,
                allow_evidence_generation_advance=True,
            )


def test_frontier_measurement_snapshot_preserves_actual_rank_input_and_selection(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "frontier-custody.db") as store:
        registry, retriever, frontier = _candidate_fixture(store)
        candidate = _issued_candidates(registry)[0]
        versions = _versions(retriever)
        item = frontier.upsert_item(
            CASE,
            FrontierReferenceV1(kind="measure", candidate_id=candidate.candidate_id),
            versions,
            cost_ms=candidate.cost_ms,
        )
        request = assemble_frontier_request(
            case_id=CASE,
            items=(item,),
            versions=versions,
            symptom="Game stutters",
            hypothesis_briefs=(),
            deadline_at=utc_now() + timedelta(minutes=5),
            provider=PROVIDER,
            model_weight_sha256=MODEL_SHA,
            catalog_entries=(),
            candidate_refs=(candidate,),
            candidate_registry=registry,
            candidate_epoch=EPOCH,
            store=store,
            retriever=retriever,
            frontier=frontier,
        )
        frozen_at = utc_now()
        response = _ranker().rank(request)
        repository = CandidateDecisionSnapshotRepository(store)
        snapshot = repository.capture_frontier(
            request,
            response,
            registry=registry,
            retriever=retriever,
            frontier=frontier,
            catalog_entries=(),
            candidate_refs=(candidate,),
            selected_item_id=item.item_id,
            epoch_state_version=EPOCH,
            request_frozen_at=frozen_at,
        )
        restored = repository.readback_frontier(snapshot.snapshot_id)

        assert restored.request == request
        assert restored.request.evidence_packets == ()
        assert (
            store.connection.execute(
                "SELECT receipt_id FROM frontier_packet_snapshot_bindings WHERE snapshot_id=?",
                (snapshot.snapshot_id,),
            ).fetchone()
            is None
        )
        assert restored.response == response
        assert restored.candidate_id == candidate.candidate_id
        forged = request.model_copy(
            update={
                "item_semantics": (
                    request.item_semantics[0].model_copy(
                        update={"information_goal": "What does a forged source say?"}
                    ),
                )
            }
        )
        with pytest.raises(ValueError, match="source"):
            repository.capture_frontier(
                forged,
                _ranker().rank(forged),
                registry=registry,
                retriever=retriever,
                frontier=frontier,
                catalog_entries=(),
                candidate_refs=(candidate,),
                selected_item_id=item.item_id,
                epoch_state_version=EPOCH,
                request_frozen_at=utc_now(),
            )
        nonexistent_id = "ev_" + "f" * 32
        page_id = f"{nonexistent_id}:0"
        packet = SemanticPacketRefV1(
            evidence_id=nonexistent_id,
            page_id=page_id,
            fragment_id=f"{page_id}:fact:invented",
            description=json.dumps(
                {
                    "projection": "semantic_fact_packets_v1",
                    "packet_kind": "fact",
                    "evidence_id": nonexistent_id,
                    "page_id": page_id,
                    "observed_at": NOW.isoformat(),
                    "captured_at": NOW.isoformat(),
                    "metric": "invented",
                    "value_quality": "exact",
                    "value": 100,
                }
            ),
        )
        packet_request = request.model_copy(update={"evidence_packets": (packet,)})
        with pytest.raises(ValueError, match="not source-bound"):
            repository.capture_frontier(
                packet_request,
                _ranker().rank(packet_request),
                registry=registry,
                retriever=retriever,
                frontier=frontier,
                catalog_entries=(),
                candidate_refs=(candidate,),
                selected_item_id=item.item_id,
                epoch_state_version=EPOCH,
                request_frozen_at=utc_now(),
            )
        assert (
            repository.verify_selection(
                snapshot.snapshot_id,
                CASE,
                EPOCH,
                candidate.candidate_id,
                candidate.invocation_sha256,
            ).candidate_id
            == candidate.candidate_id
        )

        admission = CandidateDispatchAdmissionRepository(store, registry=registry).admit(
            snapshot_id=snapshot.snapshot_id,
            candidate_id=candidate.candidate_id,
            case_id=CASE,
            epoch_state_version=EPOCH,
            task_id="probe-0-frontier",
            invocation_sha256=candidate.invocation_sha256,
            cost_ms=candidate.cost_ms,
        )
        with pytest.raises(ValueError, match="registry"):
            CandidateDispatchAdmissionRepository(store).claim_for_worker(
                admission.admission_id,
                case_id=CASE,
                epoch_state_version=EPOCH,
                task_id="probe-0-frontier",
                invocation_sha256=candidate.invocation_sha256,
            )
        claimed = CandidateDispatchAdmissionRepository(store, registry=registry).claim_for_worker(
            admission.admission_id,
            case_id=CASE,
            epoch_state_version=EPOCH,
            task_id="probe-0-frontier",
            invocation_sha256=candidate.invocation_sha256,
        )
        assert claimed.claimed_at is not None
        assert claimed.outcome_status == "claimed_unlinked"
        resolved = registry.resolve(CASE, EPOCH, candidate.candidate_id)
        assert not isinstance(resolved, CandidateGap)
        execution_id = ExecutionId.new()
        started_at = utc_now()
        with store.transaction() as transaction:
            transaction.record_probe_execution(
                execution_id=str(execution_id),
                case_id=str(CASE),
                probe_id=resolved.invocation.probe_id,
                probe_version=resolved.invocation.probe_version,
                status="ok",
                parameters_json=json.dumps(
                    resolved.invocation.parameters, sort_keys=True, separators=(",", ":")
                ),
                started_at=started_at.isoformat(),
                finished_at=started_at.isoformat(),
                state_version=EPOCH,
            )
            CandidateDispatchAdmissionRepository(store).link_execution(
                admission.admission_id, str(execution_id), resolved.invocation
            )
        assert (
            CandidateDispatchAdmissionRepository(store)
            .readback(admission.admission_id)
            .outcome_status
            == "linked"
        )
        with pytest.raises(ValueError, match="already admitted"):
            CandidateDispatchAdmissionRepository(store, registry=registry).admit(
                snapshot_id=snapshot.snapshot_id,
                candidate_id=candidate.candidate_id,
                case_id=CASE,
                epoch_state_version=EPOCH,
                task_id="probe-1-frontier",
                invocation_sha256=candidate.invocation_sha256,
                cost_ms=candidate.cost_ms,
            )


def test_frontier_candidate_admission_rejects_changed_evidence_generation(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "frontier-stale-generation.db") as store:
        registry, retriever, frontier = _candidate_fixture(store)
        candidate = _issued_candidates(registry)[0]
        item = frontier.upsert_item(
            CASE,
            FrontierReferenceV1(kind="measure", candidate_id=candidate.candidate_id),
            _versions(retriever),
            cost_ms=candidate.cost_ms,
        )
        request = assemble_frontier_request(
            case_id=CASE,
            items=(item,),
            versions=item.versions,
            symptom="Game stutters",
            hypothesis_briefs=(),
            deadline_at=utc_now() + timedelta(minutes=5),
            provider=PROVIDER,
            model_weight_sha256=MODEL_SHA,
            catalog_entries=(),
            candidate_refs=(candidate,),
            candidate_registry=registry,
            candidate_epoch=EPOCH,
            store=store,
            retriever=retriever,
            frontier=frontier,
        )
        snapshot = CandidateDecisionSnapshotRepository(store).capture_frontier(
            request,
            _ranker().rank(request),
            registry=registry,
            retriever=retriever,
            frontier=frontier,
            catalog_entries=(),
            candidate_refs=(candidate,),
            selected_item_id=item.item_id,
            epoch_state_version=EPOCH,
            request_frozen_at=utc_now(),
        )
        _stored_record(store, index=17)

        with pytest.raises(ValueError, match="generation"):
            CandidateDispatchAdmissionRepository(store, registry=registry).admit(
                snapshot_id=snapshot.snapshot_id,
                candidate_id=candidate.candidate_id,
                case_id=CASE,
                epoch_state_version=EPOCH,
                task_id="probe-0-stale",
                invocation_sha256=candidate.invocation_sha256,
                cost_ms=candidate.cost_ms,
            )
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_dispatch_admissions"
        ).fetchone() == (0,)


def test_exact_catalog_source_is_assembled_and_retrieved_locally(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "policy.db") as store:
        retriever, frontier = _case(store)
        evidence_id = _stored_record(store)
        versions = _versions(retriever)
        item = frontier.upsert_item(
            CASE, FrontierReferenceV1(kind="retrieve_evidence", evidence_id=evidence_id), versions
        )
        entry = retriever.discover(EvidenceCatalogQuery(case_id=CASE, limit=1)).entries[0]

        step = run_frontier_step(
            case_id=CASE,
            items=(item,),
            versions=versions,
            symptom="WiFi is slow",
            hypothesis_briefs=(),
            deadline_at=utc_now() + timedelta(minutes=5),
            provider=PROVIDER,
            model_weight_sha256=MODEL_SHA,
            catalog_entries=(entry,),
            candidate_refs=(),
            candidate_registry=None,
            candidate_epoch=0,
            store=store,
            retriever=retriever,
            frontier=frontier,
            ranker=_ranker(),
        )

        assert step.ranking.model_abstained is True
        assert step.selected.item_id == item.item_id
        assert step.retrieval is not None
        assert step.retrieval.evidence is not None
        assert step.retrieval.evidence.evidence_id == evidence_id
        assert step.measurement is None
        assert frontier.readback(item.item_id).status is FrontierStatus.SATISFIED
        assert store.connection.execute("SELECT COUNT(*) FROM probe_executions").fetchone()[0] == 0


def test_catalog_metadata_tamper_rejects_before_claim(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "tamper.db") as store:
        retriever, frontier = _case(store)
        evidence_id = _stored_record(store)
        versions = _versions(retriever)
        item = frontier.upsert_item(
            CASE, FrontierReferenceV1(kind="retrieve_evidence", evidence_id=evidence_id), versions
        )
        entry = retriever.discover(EvidenceCatalogQuery(case_id=CASE, limit=1)).entries[0]
        forged = entry.model_copy(update={"summary": "Changed after catalog read"})

        with pytest.raises(ValueError, match=r"catalog metadata does not match source record"):
            assemble_frontier_request(
                case_id=CASE,
                items=(item,),
                versions=versions,
                symptom="WiFi is slow",
                hypothesis_briefs=(),
                deadline_at=utc_now() + timedelta(minutes=5),
                provider=PROVIDER,
                model_weight_sha256=MODEL_SHA,
                catalog_entries=(forged,),
                candidate_refs=(),
                candidate_registry=None,
                candidate_epoch=0,
                store=store,
                retriever=retriever,
                frontier=frontier,
            )
        assert frontier.readback(item.item_id).status is FrontierStatus.REQUESTED


def test_source_execution_mismatch_rejects_even_with_fresh_catalog(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "execution-mismatch.db") as store:
        retriever, frontier = _case(store)
        evidence_id = _stored_record(store)
        with store.transaction():
            store.connection.execute(
                "UPDATE evidence SET execution_id=? WHERE evidence_id=?",
                ("exec_" + "f" * 32, str(evidence_id)),
            )
        versions = _versions(retriever)
        entry = retriever.discover(EvidenceCatalogQuery(case_id=CASE, limit=1)).entries[0]
        item = frontier.upsert_item(
            CASE, FrontierReferenceV1(kind="retrieve_evidence", evidence_id=evidence_id), versions
        )

        with pytest.raises(ValueError, match="catalog metadata does not match source record"):
            assemble_frontier_request(
                case_id=CASE,
                items=(item,),
                versions=versions,
                symptom="WiFi is slow",
                hypothesis_briefs=(),
                deadline_at=utc_now() + timedelta(minutes=5),
                provider=PROVIDER,
                model_weight_sha256=MODEL_SHA,
                catalog_entries=(entry,),
                candidate_refs=(),
                candidate_registry=None,
                candidate_epoch=0,
                store=store,
                retriever=retriever,
                frontier=frontier,
            )


def test_long_stored_metadata_discloses_all_projection_limits(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "long-summary.db") as store:
        retriever, frontier = _case(store)
        evidence_id = _stored_record(store)
        with store.transaction():
            store.connection.execute(
                "UPDATE evidence SET record_json=json_set(record_json, '$.summary', ?, "
                "'$.limitations', json_array(?)) WHERE evidence_id=?",
                ("network metadata " * 40, "source parser was partial", str(evidence_id)),
            )
        versions = _versions(retriever)
        entry = retriever.discover(EvidenceCatalogQuery(case_id=CASE, limit=1)).entries[0]
        item = frontier.upsert_item(
            CASE, FrontierReferenceV1(kind="retrieve_evidence", evidence_id=evidence_id), versions
        )

        request = assemble_frontier_request(
            case_id=CASE,
            items=(item,),
            versions=versions,
            symptom="WiFi is slow",
            hypothesis_briefs=(),
            deadline_at=utc_now() + timedelta(minutes=5),
            provider=PROVIDER,
            model_weight_sha256=MODEL_SHA,
            catalog_entries=(entry,),
            candidate_refs=(),
            candidate_registry=None,
            candidate_epoch=0,
            store=store,
            retriever=retriever,
            frontier=frontier,
        )
        semantic = request.item_semantics[0]
        assert semantic.quality == "limited"
        assert "source parser was partial" in semantic.limitations
        assert "summary_truncated" in " ".join(semantic.limitations)
        assert "observation_time_unknown" in " ".join(semantic.limitations)
        assert semantic.information_goal.endswith("?")


def _issued_candidates(registry: CaseCandidateRegistry) -> tuple[AdmittedCandidateRefV1, ...]:
    issued = tuple(
        registry.issue(
            CASE,
            EPOCH,
            MeasurementNeed(
                capability_id="fixture.pressure",
                observable="fixture.pressure",
                target_handle="proc_" + suffix * 32,
            ),
        )
        for suffix in ("a", "b")
    )
    assert all(not isinstance(item, CandidateGap) for item in issued)
    return tuple(
        AdmittedCandidateRefV1.model_validate(
            item.model_dump(mode="json", exclude={"schema_version"})
        )
        for item in issued
    )


def test_two_same_probe_targets_keep_distinct_registry_semantics(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "targets.db") as store:
        registry, retriever, frontier = _candidate_fixture(store)
        candidates = _issued_candidates(registry)
        versions = _versions(retriever)
        items = tuple(
            frontier.upsert_item(
                CASE,
                FrontierReferenceV1(kind="measure", candidate_id=candidate.candidate_id),
                versions,
                cost_ms=candidate.cost_ms,
            )
            for candidate in candidates
        )

        request = assemble_frontier_request(
            case_id=CASE,
            items=items,
            versions=versions,
            symptom="Game stutters",
            hypothesis_briefs=(),
            deadline_at=utc_now() + timedelta(minutes=5),
            provider=PROVIDER,
            model_weight_sha256=MODEL_SHA,
            catalog_entries=(),
            candidate_refs=candidates,
            candidate_registry=registry,
            candidate_epoch=EPOCH,
            store=store,
            retriever=retriever,
            frontier=frontier,
        )

        first, second = request.item_semantics
        assert "game process 101" in first.information_goal
        assert "launcher process 202" in second.information_goal
        assert first.source_record_sha256 != second.source_record_sha256
        assert all(item.quality == "limited" for item in request.item_semantics)
        assert first.target_scope == second.target_scope == "application"
        assert first.target_label == "Application process PID 101"
        assert second.target_label == "Application process PID 202"
        assert first.measurement is not None and second.measurement is not None
        assert first.measurement.probe_id == second.measurement.probe_id == "fixture.pressure"
        assert first.measurement.observable == second.measurement.observable == "fixture.pressure"
        assert [
            (item.name, item.value_type, item.value_hint) for item in first.measurement.parameters
        ] == [("pid", "integer", "101")]
        assert first.measurement.invocation_sha256 != second.measurement.invocation_sha256
        assert _candidate_description(items[0], first) != _candidate_description(items[1], second)
        assert "proc_" not in request.model_dump_json()


def test_measurement_semantics_bind_safe_parameter_and_window_to_invocation(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "semantic-binding.db") as store:
        registry, retriever, frontier = _candidate_fixture(store)
        candidate_ref = _issued_candidates(registry)[0]
        resolved = registry.resolve(CASE, EPOCH, candidate_ref.candidate_id)
        assert not isinstance(resolved, CandidateGap)
        candidate = resolved.candidate
        invocation = resolved.invocation
        item = frontier.upsert_item(
            CASE,
            FrontierReferenceV1(kind="measure", candidate_id=candidate.candidate_id),
            _versions(retriever),
            cost_ms=candidate.cost_ms,
        )
        first = _candidate_semantic_from_resolution(
            item=item, candidate=candidate, invocation=invocation
        )
        assert first.measurement is not None
        changed_invocation = invocation.model_copy(update={"parameters": {"pid": 303}})
        changed_digest = hashlib.sha256(
            json.dumps(
                changed_invocation.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode()
        ).hexdigest()
        changed_candidate = CandidateRecord.model_validate(
            candidate.model_copy(update={"invocation_sha256": changed_digest}).model_dump()
        )
        second = _candidate_semantic_from_resolution(
            item=item, candidate=changed_candidate, invocation=changed_invocation
        )
        assert second.measurement is not None
        assert second.measurement.parameters[0].value_hint == "303"
        assert _candidate_description(item, first) != _candidate_description(item, second)

        window = MeasurementWindow(start=NOW - timedelta(seconds=20), end=NOW)
        windowed_invocation = ProbeInvocation.model_validate(
            changed_invocation.model_copy(update={"window": window}).model_dump(mode="json")
        )
        window_digest = hashlib.sha256(
            json.dumps(
                windowed_invocation.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode()
        ).hexdigest()
        windowed_candidate = changed_candidate.model_copy(
            update={"invocation_sha256": window_digest}
        )
        windowed_item = frontier.upsert_item(
            CASE,
            FrontierReferenceV1(kind="measure", candidate_id=candidate.candidate_id, window=window),
            _versions(retriever),
            cost_ms=candidate.cost_ms,
        )
        third = _candidate_semantic_from_resolution(
            item=windowed_item, candidate=windowed_candidate, invocation=windowed_invocation
        )
        assert third.measurement_window == window
        assert _candidate_description(windowed_item, second) != _candidate_description(
            windowed_item, third
        )
        private_invocation = invocation.model_copy(
            update={"parameters": {"pid": 101, "private_selector": "alice@example.com"}}
        )
        private_digest = hashlib.sha256(
            json.dumps(
                private_invocation.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
            ).encode()
        ).hexdigest()
        private_candidate = candidate.model_copy(update={"invocation_sha256": private_digest})
        private_semantic = _candidate_semantic_from_resolution(
            item=item, candidate=private_candidate, invocation=private_invocation
        )
        assert "unknown_parameter_values_masked" in private_semantic.limitations
        assert "alice@example.com" not in private_semantic.model_dump_json()
        assert "private_selector" not in private_semantic.model_dump_json()
        assert private_semantic.measurement is not None
        assert any(
            param.value_type == "masked" for param in private_semantic.measurement.parameters
        )
        with pytest.raises(ValueError, match="invocation"):
            _candidate_semantic_from_resolution(
                item=item, candidate=candidate, invocation=changed_invocation
            )


def test_retrieval_precedes_measurement_when_model_abstains(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "ordered.db") as store:
        registry, retriever, frontier = _candidate_fixture(store)
        candidate = _issued_candidates(registry)[0]
        entry = retriever.discover(EvidenceCatalogQuery(case_id=CASE, limit=1)).entries[0]
        versions = _versions(retriever)
        retrieval = frontier.upsert_item(
            CASE,
            FrontierReferenceV1(kind="retrieve_evidence", evidence_id=entry.evidence_id),
            versions,
        )
        measurement = frontier.upsert_item(
            CASE,
            FrontierReferenceV1(kind="measure", candidate_id=candidate.candidate_id),
            versions,
            cost_ms=candidate.cost_ms,
        )

        step = run_frontier_step(
            case_id=CASE,
            items=(retrieval, measurement),
            versions=versions,
            symptom="Game stutters",
            hypothesis_briefs=(),
            deadline_at=utc_now() + timedelta(minutes=5),
            provider=PROVIDER,
            model_weight_sha256=MODEL_SHA,
            catalog_entries=(entry,),
            candidate_refs=(candidate,),
            candidate_registry=registry,
            candidate_epoch=EPOCH,
            store=store,
            retriever=retriever,
            frontier=frontier,
            ranker=_ranker(),
        )

        assert step.selected.item_id == retrieval.item_id
        assert step.ranking.model_abstained is True
        assert step.ranking.ranked_item_ids == (retrieval.item_id, measurement.item_id)
        assert frontier.readback(retrieval.item_id).status is FrontierStatus.SATISFIED
        assert frontier.readback(measurement.item_id).status is FrontierStatus.REQUESTED
        assert store.connection.execute("SELECT COUNT(*) FROM probe_executions").fetchone()[0] == 1


def test_candidate_tamper_rejects_before_claim(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "candidate-tamper.db") as store:
        registry, retriever, frontier = _candidate_fixture(store)
        candidate = _issued_candidates(registry)[0]
        versions = _versions(retriever)
        item = frontier.upsert_item(
            CASE,
            FrontierReferenceV1(kind="measure", candidate_id=candidate.candidate_id),
            versions,
            cost_ms=candidate.cost_ms,
        )
        spoofed = candidate.model_copy(update={"description": "Read a different target"})

        with pytest.raises(ValueError, match="candidate reference does not match registry source"):
            assemble_frontier_request(
                case_id=CASE,
                items=(item,),
                versions=versions,
                symptom="Game stutters",
                hypothesis_briefs=(),
                deadline_at=utc_now() + timedelta(minutes=5),
                provider=PROVIDER,
                model_weight_sha256=MODEL_SHA,
                catalog_entries=(),
                candidate_refs=(spoofed,),
                candidate_registry=registry,
                candidate_epoch=EPOCH,
                store=store,
                retriever=retriever,
                frontier=frontier,
            )
        assert frontier.readback(item.item_id).status is FrontierStatus.REQUESTED


def test_measurement_step_returns_only_advisory_reference(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "measure.db") as store:
        registry, retriever, frontier = _candidate_fixture(store)
        candidate = _issued_candidates(registry)[0]
        versions = _versions(retriever)
        item = frontier.upsert_item(
            CASE,
            FrontierReferenceV1(kind="measure", candidate_id=candidate.candidate_id),
            versions,
            cost_ms=candidate.cost_ms,
        )

        step = run_frontier_step(
            case_id=CASE,
            items=(item,),
            versions=versions,
            symptom="Game stutters",
            hypothesis_briefs=(),
            deadline_at=utc_now() + timedelta(minutes=5),
            provider=PROVIDER,
            model_weight_sha256=MODEL_SHA,
            catalog_entries=(),
            candidate_refs=(candidate,),
            candidate_registry=registry,
            candidate_epoch=EPOCH,
            store=store,
            retriever=retriever,
            frontier=frontier,
            ranker=_ranker(),
        )

        assert step.measurement == candidate
        assert step.retrieval is None
        assert step.selected.status is FrontierStatus.CLAIMED
        assert frontier.readback(item.item_id).status is FrontierStatus.CLAIMED
        assert store.connection.execute("SELECT COUNT(*) FROM probe_executions").fetchone()[0] == 1


def test_unbound_branch_ref_is_rejected_before_model_or_claim(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "branch.db") as store:
        retriever, frontier = _case(store)
        versions = _versions(retriever)
        item = frontier.upsert_item(
            CASE,
            FrontierReferenceV1(kind="review_branch", branch_id="branch_v1_" + "a" * 32),
            versions,
        )

        with pytest.raises(ValueError, match="legacy branch reference lacks exact source"):
            assemble_frontier_request(
                case_id=CASE,
                items=(item,),
                versions=versions,
                symptom="WiFi is slow",
                hypothesis_briefs=(),
                deadline_at=utc_now() + timedelta(minutes=5),
                provider=PROVIDER,
                model_weight_sha256=MODEL_SHA,
                catalog_entries=(),
                candidate_refs=(),
                candidate_registry=None,
                candidate_epoch=0,
                store=store,
                retriever=retriever,
                frontier=frontier,
            )
        assert frontier.readback(item.item_id).status is FrontierStatus.REQUESTED


def test_persisted_case_relation_can_be_ranked_as_advisory_branch(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "sourced-branch.db") as store:
        retriever, frontier = _case(store)
        evidence_id = _stored_record(store)
        relation = EvidenceRelation(
            relation_id="rel_" + "a" * 32,
            source_entity_id=EntityId(root="entity_" + "1" * 32),
            target_entity_id=EntityId(root="entity_" + "2" * 32),
            relationship=RelationKind.USES_DRIVER,
            memory_layer=MemoryLayer.MACHINE,
            assertion_status=AssertionStatus.OBSERVED,
            relation_version=1,
            evidence_ids=(evidence_id,),
        )
        EvidenceRelationRepository(store).append(relation)
        versions = _versions(retriever)
        branch = _branch_reference(relation)
        item = frontier.upsert_item(
            CASE,
            branch,
            versions,
        )
        step = run_frontier_step(
            case_id=CASE,
            items=(item,),
            versions=versions,
            symptom="WiFi is slow",
            hypothesis_briefs=(),
            deadline_at=utc_now() + timedelta(minutes=5),
            provider=PROVIDER,
            model_weight_sha256=MODEL_SHA,
            catalog_entries=(),
            candidate_refs=(),
            candidate_registry=None,
            candidate_epoch=0,
            store=store,
            retriever=retriever,
            frontier=frontier,
            ranker=_ranker(),
        )
        assert step.branch_relation == relation
        assert step.selected.status is FrontierStatus.CLAIMED
        assert step.retrieval is None and step.measurement is None
        assert frontier.readback(item.item_id).status is FrontierStatus.CLAIMED
        assert store.connection.execute("SELECT COUNT(*) FROM probe_executions").fetchone()[0] == 0
        legacy = frontier.upsert_item(
            CASE,
            FrontierReferenceV1(
                kind="review_branch", branch_id="branch_v1_" + relation.relation_id[4:]
            ),
            versions,
        )
        with pytest.raises(ValueError, match="legacy branch reference lacks exact source"):
            assemble_frontier_request(
                case_id=CASE,
                items=(legacy,),
                versions=versions,
                symptom="WiFi is slow",
                hypothesis_briefs=(),
                deadline_at=utc_now() + timedelta(minutes=5),
                provider=PROVIDER,
                model_weight_sha256=MODEL_SHA,
                catalog_entries=(),
                candidate_refs=(),
                candidate_registry=None,
                candidate_epoch=0,
                store=store,
                retriever=retriever,
                frontier=frontier,
            )


def test_branch_source_change_during_claim_obsoletes_advisory_choice(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "branch-race.db") as store:
        retriever, frontier = _case(store)
        evidence_id = _stored_record(store)
        relation = EvidenceRelation(
            relation_id="rel_" + "a" * 32,
            source_entity_id=EntityId(root="entity_" + "1" * 32),
            target_entity_id=EntityId(root="entity_" + "2" * 32),
            relationship=RelationKind.USES_DRIVER,
            memory_layer=MemoryLayer.MACHINE,
            assertion_status=AssertionStatus.OBSERVED,
            relation_version=1,
            evidence_ids=(evidence_id,),
        )
        relations = EvidenceRelationRepository(store)
        relations.append(relation)
        versions = _versions(retriever)
        item = frontier.upsert_item(
            CASE,
            _branch_reference(relation),
            versions,
        )
        real_claim = frontier.claim_ready

        def claim_then_change(item_id: str, expected: RelevantVersionsV1):
            claimed = real_claim(item_id, expected)
            relations.append(relation.model_copy(update={"relation_version": 2}))
            return claimed

        monkeypatch.setattr(frontier, "claim_ready", claim_then_change)
        with pytest.raises(ValueError, match="branch source changed after claim"):
            run_frontier_step(
                case_id=CASE,
                items=(item,),
                versions=versions,
                symptom="WiFi is slow",
                hypothesis_briefs=(),
                deadline_at=utc_now() + timedelta(minutes=5),
                provider=PROVIDER,
                model_weight_sha256=MODEL_SHA,
                catalog_entries=(),
                candidate_refs=(),
                candidate_registry=None,
                candidate_epoch=0,
                store=store,
                retriever=retriever,
                frontier=frontier,
                ranker=_ranker(),
            )
        assert frontier.readback(item.item_id).status is FrontierStatus.OBSOLETE


def test_deep_question_requires_exact_case_objective_and_evidence_epoch(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "deep-question.db") as store:
        retriever, frontier = _case(store)
        versions = _versions(retriever)
        source = f"{CASE}|WiFi is slow|{versions.objective}|{versions.evidence}"
        question_id = "question_v1_" + hashlib.sha256(source.encode()).hexdigest()[:32]
        item = frontier.upsert_item(
            CASE, FrontierReferenceV1(kind="consult_deep", question_id=question_id), versions
        )
        with pytest.raises(ValueError, match="deep question symptom differs from case source"):
            assemble_frontier_request(
                case_id=CASE,
                items=(item,),
                versions=versions,
                symptom="Repair my PC",
                hypothesis_briefs=(),
                deadline_at=utc_now() + timedelta(minutes=5),
                provider=PROVIDER,
                model_weight_sha256=MODEL_SHA,
                catalog_entries=(),
                candidate_refs=(),
                candidate_registry=None,
                candidate_epoch=0,
                store=store,
                retriever=retriever,
                frontier=frontier,
            )
        step = run_frontier_step(
            case_id=CASE,
            items=(item,),
            versions=versions,
            symptom="WiFi is slow",
            hypothesis_briefs=(),
            deadline_at=utc_now() + timedelta(minutes=5),
            provider=PROVIDER,
            model_weight_sha256=MODEL_SHA,
            catalog_entries=(),
            candidate_refs=(),
            candidate_registry=None,
            candidate_epoch=0,
            store=store,
            retriever=retriever,
            frontier=frontier,
            ranker=_ranker(),
        )
        assert step.deep_question_id == question_id
        assert step.selected.status is FrontierStatus.CLAIMED
        assert step.retrieval is None and step.measurement is None
        assert store.connection.execute("SELECT COUNT(*) FROM probe_executions").fetchone()[0] == 0

        spoofed = frontier.upsert_item(
            CASE,
            FrontierReferenceV1(kind="consult_deep", question_id="question_v1_" + "f" * 32),
            versions,
        )
        with pytest.raises(ValueError, match="deep question does not match case source"):
            assemble_frontier_request(
                case_id=CASE,
                items=(spoofed,),
                versions=versions,
                symptom="WiFi is slow",
                hypothesis_briefs=(),
                deadline_at=utc_now() + timedelta(minutes=5),
                provider=PROVIDER,
                model_weight_sha256=MODEL_SHA,
                catalog_entries=(),
                candidate_refs=(),
                candidate_registry=None,
                candidate_epoch=0,
                store=store,
                retriever=retriever,
                frontier=frontier,
            )


def test_deep_question_source_change_during_claim_is_obsolete(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "deep-race.db") as store:
        retriever, frontier = _case(store)
        versions = _versions(retriever)
        source = f"{CASE}|WiFi is slow|{versions.objective}|{versions.evidence}"
        item = frontier.upsert_item(
            CASE,
            FrontierReferenceV1(
                kind="consult_deep",
                question_id="question_v1_" + hashlib.sha256(source.encode()).hexdigest()[:32],
            ),
            versions,
        )
        real_claim = frontier.claim_ready

        def claim_then_change(item_id: str, expected: RelevantVersionsV1):
            claimed = real_claim(item_id, expected)
            store.connection.execute(
                "UPDATE cases SET symptom=? WHERE case_id=?", ("Changed symptom", str(CASE))
            )
            return claimed

        monkeypatch.setattr(frontier, "claim_ready", claim_then_change)
        with pytest.raises(ValueError, match="deep question source changed after claim"):
            run_frontier_step(
                case_id=CASE,
                items=(item,),
                versions=versions,
                symptom="WiFi is slow",
                hypothesis_briefs=(),
                deadline_at=utc_now() + timedelta(minutes=5),
                provider=PROVIDER,
                model_weight_sha256=MODEL_SHA,
                catalog_entries=(),
                candidate_refs=(),
                candidate_registry=None,
                candidate_epoch=0,
                store=store,
                retriever=retriever,
                frontier=frontier,
                ranker=_ranker(),
            )
        assert frontier.readback(item.item_id).status is FrontierStatus.OBSOLETE


def test_unrelated_case_checkpoint_increment_does_not_stale_deep_question(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "deep-checkpoint.db") as store:
        retriever, frontier = _case(store)
        versions = _versions(retriever)
        source = f"{CASE}|WiFi is slow|{versions.objective}|{versions.evidence}"
        question_id = "question_v1_" + hashlib.sha256(source.encode()).hexdigest()[:32]
        item = frontier.upsert_item(
            CASE, FrontierReferenceV1(kind="consult_deep", question_id=question_id), versions
        )
        real_claim = frontier.claim_ready

        def claim_then_checkpoint(item_id: str, expected: RelevantVersionsV1):
            claimed = real_claim(item_id, expected)
            store.connection.execute(
                "UPDATE cases SET state_version=state_version+1 WHERE case_id=?", (str(CASE),)
            )
            return claimed

        monkeypatch.setattr(frontier, "claim_ready", claim_then_checkpoint)
        step = run_frontier_step(
            case_id=CASE,
            items=(item,),
            versions=versions,
            symptom="WiFi is slow",
            hypothesis_briefs=(),
            deadline_at=utc_now() + timedelta(minutes=5),
            provider=PROVIDER,
            model_weight_sha256=MODEL_SHA,
            catalog_entries=(),
            candidate_refs=(),
            candidate_registry=None,
            candidate_epoch=0,
            store=store,
            retriever=retriever,
            frontier=frontier,
            ranker=_ranker(),
        )
        assert step.deep_question_id == question_id
        assert frontier.readback(item.item_id).status is FrontierStatus.CLAIMED


@pytest.mark.parametrize("kind", ["retrieve_evidence", "measure"])
def test_split_frontier_step_selects_authoritative_item(tmp_path: Path, kind: str) -> None:
    with SQLiteStore(tmp_path / f"split-{kind}.db") as store:
        registry, retriever, frontier = _candidate_fixture(store)
        candidate = _issued_candidates(registry)[0]
        entry = retriever.discover(EvidenceCatalogQuery(case_id=CASE, limit=1)).entries[0]
        versions = _versions(retriever)
        reference = (
            FrontierReferenceV1(kind="retrieve_evidence", evidence_id=entry.evidence_id)
            if kind == "retrieve_evidence"
            else FrontierReferenceV1(kind="measure", candidate_id=candidate.candidate_id)
        )
        item = frontier.upsert_item(
            CASE, reference, versions, cost_ms=candidate.cost_ms if kind == "measure" else 0
        )
        inputs: _FrontierStepInputs = {
            "case_id": CASE,
            "items": (item,),
            "versions": versions,
            "symptom": "Game stutters",
            "hypothesis_briefs": (),
            "deadline_at": utc_now() + timedelta(minutes=5),
            "provider": PROVIDER,
            "model_weight_sha256": MODEL_SHA,
            "catalog_entries": (entry,) if kind == "retrieve_evidence" else (),
            "candidate_refs": (candidate,) if kind == "measure" else (),
            "candidate_registry": registry,
            "candidate_epoch": EPOCH,
            "store": store,
            "retriever": retriever,
            "frontier": frontier,
        }
        prepared = prepare_frontier_step(**inputs)
        assert frontier.readback(item.item_id).status is FrontierStatus.REQUESTED
        ranking = rank_frozen_frontier(prepared.request, _ranker())
        step = finalize_frontier_step(prepared=prepared, ranking=ranking, **inputs)
        assert step.selected.item_id == item.item_id
        if kind == "measure":
            assert step.measurement == candidate
            assert step.snapshot_id is not None
            assert frontier.readback(item.item_id).status is FrontierStatus.CLAIMED
        else:
            assert step.retrieval is not None
            assert frontier.readback(item.item_id).status is FrontierStatus.SATISFIED


@pytest.mark.parametrize("failure", ["forged", "mismatched", "source_changed", "expired"])
def test_split_frontier_rejection_has_no_snapshot_or_claim(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, failure: str
) -> None:
    with SQLiteStore(tmp_path / f"split-reject-{failure}.db") as store:
        registry, retriever, frontier = _candidate_fixture(store)
        candidate = _issued_candidates(registry)[0]
        versions = _versions(retriever)
        item = frontier.upsert_item(
            CASE,
            FrontierReferenceV1(kind="measure", candidate_id=candidate.candidate_id),
            versions,
            cost_ms=candidate.cost_ms,
        )
        inputs: _FrontierStepInputs = {
            "case_id": CASE,
            "items": (item,),
            "versions": versions,
            "symptom": "Game stutters",
            "hypothesis_briefs": (),
            "deadline_at": utc_now() + timedelta(minutes=5),
            "provider": PROVIDER,
            "model_weight_sha256": MODEL_SHA,
            "catalog_entries": (),
            "candidate_refs": (candidate,),
            "candidate_registry": registry,
            "candidate_epoch": EPOCH,
            "store": store,
            "retriever": retriever,
            "frontier": frontier,
        }
        prepared = prepare_frontier_step(**inputs)
        ranking = rank_frozen_frontier(prepared.request, _ranker())
        if failure == "forged":
            ranking = ranking.model_copy(update={"context_sha256": "f" * 64})
        elif failure == "mismatched":
            other_request = prepared.request.model_copy(update={"symptom": "Another symptom"})
            ranking = rank_frozen_frontier(other_request, _ranker())
        elif failure == "source_changed":
            _stored_record(store, index=18)
        else:
            monkeypatch.setattr(
                "systemsense.application.frontier_policy.utc_now",
                lambda: inputs["deadline_at"] + timedelta(seconds=1),
            )
        with pytest.raises(ValueError):
            finalize_frontier_step(prepared=prepared, ranking=ranking, **inputs)
        assert frontier.readback(item.item_id).status is FrontierStatus.REQUESTED
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_decision_snapshots"
        ).fetchone() == (0,)


def test_frontier_step_forwards_opt_in_worker_capture(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "frontier-capture-forward.db") as store:
        registry, retriever, frontier = _candidate_fixture(store)
        candidate = _issued_candidates(registry)[0]
        versions = _versions(retriever)
        item = frontier.upsert_item(
            CASE,
            FrontierReferenceV1(kind="measure", candidate_id=candidate.candidate_id),
            versions,
            cost_ms=candidate.cost_ms,
        )
        ranker = _ranker()
        original = ranker.rank
        seen: list[object] = []

        def recording_rank(
            request: FrontierRankRequestV1, **kwargs: object
        ) -> FrontierRankResponseV1:
            seen.append(kwargs.get("capture_worker_batch"))
            return original(request)

        monkeypatch.setattr(ranker, "rank", recording_rank)

        def marker(
            _phase: str,
            _index: int,
            _call: dict[str, object],
            _proof: LayaWorkerPresentation,
        ) -> None:
            return None

        step = run_frontier_step(
            case_id=CASE,
            items=(item,),
            versions=versions,
            symptom="Game stutters",
            hypothesis_briefs=(),
            deadline_at=utc_now() + timedelta(minutes=5),
            provider=PROVIDER,
            model_weight_sha256=MODEL_SHA,
            catalog_entries=(),
            candidate_refs=(candidate,),
            candidate_registry=registry,
            candidate_epoch=EPOCH,
            store=store,
            retriever=retriever,
            frontier=frontier,
            ranker=ranker,
            capture_worker_batch=marker,
        )
        assert step.snapshot_id is not None
        assert seen == [marker]


def test_split_frontier_rejects_same_packets_from_a_different_receipt(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "split-receipt-swap.db") as store:
        registry, retriever, frontier = _candidate_fixture(store)
        checkpoint = store.connection.execute(
            "SELECT record_json FROM investigation_checkpoints WHERE case_id=?", (str(CASE),)
        ).fetchone()
        assert checkpoint is not None
        state = json.loads(str(checkpoint[0]))
        now = utc_now()
        state.update(
            objective="Game stutters",
            created_at=(now - timedelta(seconds=10)).isoformat(),
            updated_at=now.isoformat(),
            incident_start=(now - timedelta(minutes=1)).isoformat(),
            incident_end=now.isoformat(),
        )
        store.connection.execute(
            "UPDATE investigation_checkpoints SET record_json=? WHERE case_id=?",
            (json.dumps(state), str(CASE)),
        )
        candidate = _issued_candidates(registry)[0]
        versions = _versions(retriever)
        item = frontier.upsert_item(
            CASE,
            FrontierReferenceV1(kind="measure", candidate_id=candidate.candidate_id),
            versions,
            cost_ms=candidate.cost_ms,
        )
        receipts = FrontierPacketReceiptRepository(store)
        source_id = EvidenceId(root="ev_" + "9" * 32)
        first = receipts.freeze(
            case_id=CASE,
            epoch_state_version=EPOCH,
            evidence_ids=(source_id,),
            expected_generation=versions.evidence or 0,
        )
        second = receipts.freeze(
            case_id=CASE,
            epoch_state_version=EPOCH,
            evidence_ids=(source_id,),
            expected_generation=versions.evidence or 0,
        )
        assert first.receipt_id != second.receipt_id
        assert first.packets == second.packets
        inputs: _FrontierStepInputs = {
            "case_id": CASE,
            "items": (item,),
            "versions": versions,
            "symptom": "Game stutters",
            "hypothesis_briefs": (),
            "deadline_at": utc_now() + timedelta(minutes=5),
            "provider": PROVIDER,
            "model_weight_sha256": MODEL_SHA,
            "catalog_entries": (),
            "candidate_refs": (candidate,),
            "candidate_registry": registry,
            "candidate_epoch": EPOCH,
            "store": store,
            "retriever": retriever,
            "frontier": frontier,
        }
        prepared = prepare_frontier_step(**inputs, packet_receipt_id=first.receipt_id)
        ranking = rank_frozen_frontier(prepared.request, _ranker())
        with pytest.raises(ValueError, match="receipt"):
            finalize_frontier_step(
                prepared=prepared,
                ranking=ranking,
                **inputs,
                packet_receipt_id=second.receipt_id,
            )
        assert frontier.readback(item.item_id).status is FrontierStatus.REQUESTED
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_decision_snapshots"
        ).fetchone() == (0,)


@pytest.mark.parametrize("changed_source", [None, "branch", "deep"])
def test_receipt_backed_four_kind_snapshot_rechecks_advisory_sources(
    tmp_path: Path, changed_source: str | None
) -> None:
    with SQLiteStore(tmp_path / "four-kind-snapshot.db") as store:
        registry, retriever, frontier = _candidate_fixture(store)
        checkpoint = store.connection.execute(
            "SELECT record_json FROM investigation_checkpoints WHERE case_id=?", (str(CASE),)
        ).fetchone()
        assert checkpoint is not None
        state = json.loads(str(checkpoint[0]))
        now = utc_now()
        state.update(
            objective="Game stutters",
            created_at=(now - timedelta(seconds=10)).isoformat(),
            updated_at=now.isoformat(),
            incident_start=(now - timedelta(minutes=1)).isoformat(),
            incident_end=now.isoformat(),
        )
        store.connection.execute(
            "UPDATE investigation_checkpoints SET record_json=? WHERE case_id=?",
            (json.dumps(state), str(CASE)),
        )
        candidate = _issued_candidates(registry)[0]
        entry = retriever.discover(EvidenceCatalogQuery(case_id=CASE, limit=1)).entries[0]
        relation = EvidenceRelation(
            relation_id="rel_" + "a" * 32,
            source_entity_id=EntityId(root="entity_" + "1" * 32),
            target_entity_id=EntityId(root="entity_" + "2" * 32),
            relationship=RelationKind.USES_DRIVER,
            memory_layer=MemoryLayer.MACHINE,
            assertion_status=AssertionStatus.OBSERVED,
            relation_version=1,
            evidence_ids=(entry.evidence_id,),
        )
        relations = EvidenceRelationRepository(store)
        relations.append(relation)
        versions = _versions(retriever)
        source = f"{CASE}|Game stutters|{versions.objective}|{versions.evidence}"
        question_id = "question_v1_" + hashlib.sha256(source.encode()).hexdigest()[:32]
        items = (
            frontier.upsert_item(
                CASE,
                FrontierReferenceV1(kind="measure", candidate_id=candidate.candidate_id),
                versions,
                cost_ms=candidate.cost_ms,
            ),
            frontier.upsert_item(
                CASE,
                FrontierReferenceV1(kind="retrieve_evidence", evidence_id=entry.evidence_id),
                versions,
            ),
            frontier.upsert_item(CASE, _branch_reference(relation), versions),
            frontier.upsert_item(
                CASE, FrontierReferenceV1(kind="consult_deep", question_id=question_id), versions
            ),
        )
        receipt = FrontierPacketReceiptRepository(store).freeze(
            case_id=CASE,
            epoch_state_version=EPOCH,
            evidence_ids=(entry.evidence_id,),
            expected_generation=versions.evidence or 0,
        )
        frozen_at = utc_now()
        request = assemble_frontier_request(
            case_id=CASE,
            items=items,
            versions=versions,
            symptom="Game stutters",
            hypothesis_briefs=(),
            deadline_at=now + timedelta(minutes=5),
            provider=PROVIDER,
            model_weight_sha256=MODEL_SHA,
            catalog_entries=(entry,),
            candidate_refs=(candidate,),
            candidate_registry=registry,
            candidate_epoch=EPOCH,
            store=store,
            retriever=retriever,
            frontier=frontier,
            evidence_packets=receipt.packets,
        )
        ranking = rank_frozen_frontier(request, _ranker())
        snapshots = CandidateDecisionSnapshotRepository(store)
        snapshot = snapshots.capture_frontier(
            request,
            ranking,
            registry=registry,
            retriever=retriever,
            frontier=frontier,
            catalog_entries=(entry,),
            candidate_refs=(candidate,),
            selected_item_id=items[0].item_id,
            epoch_state_version=EPOCH,
            request_frozen_at=frozen_at,
            packet_receipt_id=receipt.receipt_id,
        )
        assert snapshots.readback_frontier(snapshot.snapshot_id).request == request
        if changed_source == "branch":
            relations.append(relation.model_copy(update={"relation_version": 2}))
        elif changed_source == "deep":
            store.connection.execute(
                "UPDATE cases SET symptom=? WHERE case_id=?", ("Changed symptom", str(CASE))
            )
        if changed_source is not None:
            with pytest.raises(ValueError, match=r"source|semantic"):
                snapshots.readback_frontier(snapshot.snapshot_id)
