"""A frontier policy may read stored evidence, never grant host authority."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import BaseModel

from systemsense.application.frontier_policy import (
    assemble_frontier_request,
    run_frontier_step,
)
from systemsense.decision.candidates import AdmittedCandidateRefV1
from systemsense.decision.contracts import ProviderIdentity
from systemsense.decision.frontier_ranker import MixedFrontierRanker, SemanticPacketRefV1
from systemsense.domain.evidence import (
    CollectorReference,
    EvidenceRecord,
    EvidenceSource,
    Extraction,
    Sensitivity,
    StatementKind,
)
from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId, stable_source_id
from systemsense.domain.probes import (
    MeasurementNeed,
    Privilege,
    ProbeLimits,
    ProbeManifest,
    ProbeSafety,
    SafetyClass,
)
from systemsense.domain.time import utc_now
from systemsense.evidence.retrieval import EvidenceCatalogQuery, EvidenceRetriever
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.storage.candidate_decision_snapshots import CandidateDecisionSnapshotRepository
from systemsense.storage.candidate_dispatch_admissions import CandidateDispatchAdmissionRepository
from systemsense.storage.case_candidates import (
    CandidateGap,
    CandidateRegistration,
    CandidateTargetBinding,
    CaseCandidateRegistry,
)
from systemsense.storage.search_frontier import (
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
        assert all(item.target_scope == "unknown" for item in request.item_semantics)
        assert "pid" not in request.model_dump_json().lower()


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

        with pytest.raises(ValueError, match="branch and deep frontier sources"):
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
