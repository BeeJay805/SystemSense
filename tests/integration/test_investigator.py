import hashlib
import json
import sqlite3
import threading
import time
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest
from pydantic import BaseModel, ConfigDict

from systemsense.application.case_service import CaseService
from systemsense.application.investigation_state import InvestigationOutcome, InvestigationStatus
from systemsense.application.investigator import Investigator
from systemsense.application.runtime import DiagnosticRuntime
from systemsense.decision.baseline import KeywordBaselineDecisionProvider
from systemsense.decision.contracts import (
    DecisionRequest,
    DecisionResponse,
    DiagnosticPurpose,
    ProbeCapability,
    ProbeProposal,
    ProviderIdentity,
)
from systemsense.decision.laya import LayaDecisionProvider, eligible_laya_candidates
from systemsense.decision.provider import FastDecisionProvider
from systemsense.decision.typed_ranker import TypedFeatureDecisionProvider
from systemsense.domain.cases import CaseKind, CaseStatus, CaseTimeWindowBasis
from systemsense.domain.coverage import CoverageRecord, CoverageStatus
from systemsense.domain.evidence import (
    CollectorReference,
    EvidenceFact,
    EvidenceRecord,
    EvidenceSource,
    Extraction,
    Sensitivity,
    StatementKind,
)
from systemsense.domain.ids import (
    CaseId,
    EntityId,
    EvidenceId,
    ExecutionId,
    JsonValue,
    stable_source_id,
)
from systemsense.domain.probes import (
    Privilege,
    ProbeLimits,
    ProbeManifest,
    ProbeSafety,
    SafetyClass,
    SelfWrite,
)
from systemsense.evidence.graph import (
    AssertionStatus,
    EvidenceRelation,
    MemoryLayer,
    RelationKind,
)
from systemsense.evidence.retrieval import (
    EvidenceRelationRepository,
    EvidenceRetrievalQuery,
    EvidenceRetriever,
)
from systemsense.inference.context import EvidenceContextStatus
from systemsense.knowledge.catalog import ReferenceKnowledgeGraph
from systemsense.knowledge.windows_errors import (
    WindowsErrorCatalog,
    WindowsErrorReference,
    WindowsErrorSource,
)
from systemsense.orchestration.planner import DeterministicPlanner, ProbeCandidate
from systemsense.orchestration.probes import ProbeDefinition, ProbeObservation, ProbeRunner
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.reasoning.contracts import (
    ExpectedFact,
    Hypothesis,
    HypothesisStatus,
    ReasoningRequest,
    ReasoningResponse,
    ReasoningStatus,
)
from systemsense.reasoning.deterministic import DeterministicReasoningProvider
from systemsense.reasoning.provider import ReasoningProvider
from systemsense.reasoning.unavailable import UnavailableReasoningProvider
from systemsense.storage.decision_snapshots import (
    DecisionSnapshotRepository,
    ProbeManifestRef,
    decision_request_sha256,
)
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.sqlite_store import SQLiteStore


class _NoParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def probe_definition(category: str) -> ProbeDefinition:
    probe_id = f"{category}.snapshot"

    def collect(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        observed_at = datetime.now(UTC)
        return ProbeObservation(
            summary=f"Collected {category} snapshot",
            facts={"category": category, "value": 1},
            observed_at=observed_at,
            captured_at=observed_at,
        )

    return ProbeDefinition(
        manifest=ProbeManifest(
            probe_id=probe_id,
            version=1,
            implementation_id=f"builtin.{probe_id}",
            question=f"What is the current {category} state?",
            safety=ProbeSafety(
                safety_class=SafetyClass.R1,
                privilege=Privilege.STANDARD,
                target_state_effect="none",
                self_writes=(SelfWrite.AUDIT_RECORD, SelfWrite.EVIDENCE_RECORD),
            ),
            input_model="NoParametersV1",
            limits=ProbeLimits(timeout_ms=1_000, max_output_bytes=32_768, max_records=64),
            category=category,
        ),
        parameter_model=_NoParameters,
        handler=collect,
        isolated=False,
    )


def investigator(
    store: SQLiteStore,
    *,
    definitions: tuple[ProbeDefinition, ...] | None = None,
    reasoning: ReasoningProvider | None = None,
    decision: FastDecisionProvider | None = None,
) -> Investigator:
    definitions = definitions or tuple(
        probe_definition(name) for name in ("core", "network", "devices")
    )
    planner = DeterministicPlanner(
        candidates=tuple(
            ProbeCandidate(probe_id=d.manifest.probe_id, cost_ms=1, value=1, common=True)
            for d in definitions
        )
    )
    return Investigator(
        store=store,
        runtime=DiagnosticRuntime(
            store=store,
            case_service=CaseService(store, planner),
            probe_runner=ProbeRunner(definitions=definitions),
        ),
        capabilities=tuple(
            ProbeCapability(
                probe_id=d.manifest.probe_id,
                description=d.manifest.question,
                common=True,
                cost_ms=1,
                resource_class=ResourceClass.CPU,
            )
            for d in definitions
        ),
        decision=decision or KeywordBaselineDecisionProvider(),
        reasoning=reasoning or UnavailableReasoningProvider(),
    )


def _port_error_reference() -> WindowsErrorReference:
    catalog = WindowsErrorCatalog.from_constants(
        {"WSAEADDRINUSE": 10048},
        message_resolver=lambda _code: "Only one usage of each socket address is permitted.",
        source=WindowsErrorSource(
            catalog_provider="fixture",
            catalog_version="1",
            message_provider="fixture",
            os_version="fixture Windows",
            runtime_observed=False,
        ),
    )
    reference = catalog.lookup_win32(10048)
    assert reference is not None
    return reference


def _persist_evidence(
    store: SQLiteStore,
    *,
    case_id: CaseId,
    facts: dict[str, JsonValue],
    captured_at: datetime,
    sequence: int,
) -> EvidenceRecord:
    execution_id = ExecutionId(root=f"exec_{sequence:032x}")
    source_id = stable_source_id(
        "fixture.history",
        {"case_id": str(case_id), "sequence": sequence},
    )
    record = EvidenceRecord(
        evidence_id=EvidenceId.new(),
        case_id=case_id,
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=captured_at,
        captured_at=captured_at,
        source=EvidenceSource(
            type="fixture.history",
            source_id=source_id,
            locator={"sequence": sequence},
        ),
        collector=CollectorReference(
            id="fixture.history",
            version=1,
            execution_id=execution_id,
        ),
        summary=f"Fixture observation {sequence}",
        facts=tuple(EvidenceFact(name=name, value=value) for name, value in facts.items()),
        extraction=Extraction(confidence=1.0, parser="fixture", parser_version=1),
        sensitivity=Sensitivity.SYSTEM_METADATA,
    )
    with store.transaction() as transaction:
        transaction.insert_evidence(
            case_id=str(case_id),
            evidence_id=str(record.evidence_id),
            source_id=source_id,
            record_json=record.model_dump_json(),
            observed_at=captured_at.isoformat(),
            captured_at=captured_at.isoformat(),
            execution_id=str(execution_id),
            dedupe_key=f"fixture:{sequence}",
            time_basis="source_observed",
            time_quality="exact",
        )
    return record


def _passive_evidence(
    store: SQLiteStore,
    *,
    captured_at: datetime,
    sequence: int = 1,
) -> EvidenceRecord:
    case_id = CaseId.new()
    store.create_case(
        case_id=str(case_id),
        kind=CaseKind.PASSIVE.value,
        symptom="Passive fixture",
        created_at=captured_at.isoformat(),
        status=CaseStatus.COMPLETE.value,
        time_window_start=captured_at.isoformat(),
        time_window_end=captured_at.isoformat(),
        time_window_basis=CaseTimeWindowBasis.UNKNOWN.value,
    )
    return _persist_evidence(
        store,
        case_id=case_id,
        facts={"history_marker": sequence},
        captured_at=captured_at,
        sequence=sequence,
    )


def test_packet_prioritizes_linked_current_observation_outside_initial_page(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "graph-priority.db") as store:
        app = investigator(store)
        state = app.create(objective="why is the application failing?", budget_ms=10_000)
        target = _persist_evidence(
            store,
            case_id=state.case_id,
            facts={"driver_problem": 1},
            captured_at=state.created_at + timedelta(seconds=1),
            sequence=1,
        )
        mixed_target = _persist_evidence(
            store,
            case_id=state.case_id,
            facts={"untrusted_link": 1},
            captured_at=state.created_at + timedelta(milliseconds=500),
            sequence=50,
        )
        partial_target = _persist_evidence(
            store,
            case_id=state.case_id,
            facts={"incomplete_link": 1},
            captured_at=state.created_at + timedelta(milliseconds=700),
            sequence=52,
        )
        multi_first = _persist_evidence(
            store,
            case_id=state.case_id,
            facts={"multi_link": 1},
            captured_at=state.created_at + timedelta(milliseconds=800),
            sequence=53,
        )
        multi_second = _persist_evidence(
            store,
            case_id=state.case_id,
            facts={"multi_link": 2},
            captured_at=state.created_at + timedelta(milliseconds=900),
            sequence=54,
        )
        stale = _persist_evidence(
            store,
            case_id=state.case_id,
            facts={"stale": 1},
            captured_at=state.incident_start - timedelta(minutes=1),
            sequence=55,
        )
        foreign_case = CaseId.new()
        store.create_case(
            case_id=str(foreign_case),
            kind=CaseKind.GENERAL.value,
            symptom="unrelated case",
            created_at=state.created_at.isoformat(),
        )
        foreign = _persist_evidence(
            store,
            case_id=foreign_case,
            facts={"foreign": 1},
            captured_at=state.created_at + timedelta(seconds=2),
            sequence=51,
        )
        for sequence in range(2, 49):
            _persist_evidence(
                store,
                case_id=state.case_id,
                facts={"unrelated": sequence},
                captured_at=state.created_at + timedelta(seconds=sequence),
                sequence=sequence,
            )
        seed = _persist_evidence(
            store,
            case_id=state.case_id,
            facts={"process_id": 42},
            captured_at=state.created_at + timedelta(seconds=49),
            sequence=49,
        )
        process = EntityId(root=f"entity_{1:032x}")
        module = EntityId(root=f"entity_{2:032x}")
        driver = EntityId(root=f"entity_{3:032x}")
        repository = EvidenceRelationRepository(store)
        repository.append(
            EvidenceRelation(
                relation_id=f"rel_{1:032x}",
                source_entity_id=process,
                target_entity_id=module,
                relationship=RelationKind.DEPENDS_ON,
                memory_layer=MemoryLayer.MACHINE,
                assertion_status=AssertionStatus.OBSERVED,
                relation_version=1,
                evidence_ids=(seed.evidence_id,),
            )
        )
        repository.append(
            EvidenceRelation(
                relation_id=f"rel_{2:032x}",
                source_entity_id=module,
                target_entity_id=driver,
                relationship=RelationKind.USES_DRIVER,
                memory_layer=MemoryLayer.MACHINE,
                assertion_status=AssertionStatus.OBSERVED,
                relation_version=1,
                evidence_ids=(target.evidence_id,),
            )
        )
        repository.append(
            EvidenceRelation(
                relation_id=f"rel_{3:032x}",
                source_entity_id=module,
                target_entity_id=EntityId(root=f"entity_{4:032x}"),
                relationship=RelationKind.USES_DEVICE,
                memory_layer=MemoryLayer.MACHINE,
                assertion_status=AssertionStatus.OBSERVED,
                relation_version=1,
                evidence_ids=(mixed_target.evidence_id, foreign.evidence_id),
                source_ids=(foreign.source.source_id,),
            )
        )
        repository.append(
            EvidenceRelation(
                relation_id=f"rel_{4:032x}",
                source_entity_id=module,
                target_entity_id=EntityId(root=f"entity_{5:032x}"),
                relationship=RelationKind.USES_DEVICE,
                memory_layer=MemoryLayer.MACHINE,
                assertion_status=AssertionStatus.OBSERVED,
                relation_version=1,
                evidence_ids=(partial_target.evidence_id, stale.evidence_id),
            )
        )
        fully_grounded = EvidenceRelation(
            relation_id=f"rel_{5:032x}",
            source_entity_id=module,
            target_entity_id=EntityId(root=f"entity_{6:032x}"),
            relationship=RelationKind.USES_DEVICE,
            memory_layer=MemoryLayer.MACHINE,
            assertion_status=AssertionStatus.OBSERVED,
            relation_version=1,
            evidence_ids=(multi_first.evidence_id, multi_second.evidence_id),
        )
        repository.append(fully_grounded)

        initial = EvidenceRetriever(store).retrieve(
            EvidenceRetrievalQuery(
                current_case_id=state.case_id,
                observed_from=state.incident_start,
                observed_until=state.incident_end,
                current_collection_start=state.created_at,
                evidence_limit=48,
                coverage_limit=16,
                max_chars=48_000,
                max_fact_chars=4096,
            )
        )
        initial_ids = {str(item.evidence_id) for item in initial.evidence}
        assert str(target.evidence_id) not in initial_ids
        assert str(mixed_target.evidence_id) not in initial_ids
        assert str(multi_first.evidence_id) not in initial_ids
        assert str(multi_second.evidence_id) not in initial_ids

        packet = app.packet(str(state.case_id))
        visible = {str(item.evidence_id) for item in packet.evidence}
        assert str(seed.evidence_id) in visible
        assert str(target.evidence_id) in visible
        assert str(mixed_target.evidence_id) not in visible
        assert str(partial_target.evidence_id) not in visible
        assert str(multi_first.evidence_id) in visible
        assert str(multi_second.evidence_id) in visible
        assert len(packet.evidence) <= 48
        assert packet.omitted_evidence_count == 5
        assert fully_grounded in app.relationships(app.context(str(state.case_id)))


def test_investigation_persists_rounds_without_repeating_probes(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "test.db") as store:
        app = investigator(store)
        initial = app.create(objective="why is the computer slow?", budget_ms=2000)
        result = app.run(str(initial.case_id))
        assert result.status is InvestigationStatus.COMPLETE
        assert result.outcome is InvestigationOutcome.INSUFFICIENT_OBSERVABILITY
        assert len(result.completed_probe_ids) == 3
        assert store.probe_execution_count(case_id=str(initial.case_id)) == 3
        assert len(InvestigationRepository(store).steps(str(initial.case_id))) >= 4
        assert result.reasoning_provider == "reasoning-unavailable"
    with SQLiteStore(tmp_path / "test.db") as store:
        assert InvestigationRepository(store).load(str(initial.case_id)) == result


def test_next_probe_decision_request_is_durably_captured_before_collection(
    tmp_path: Path,
) -> None:
    class RecordingDecision:
        identity = KeywordBaselineDecisionProvider().identity

        def __init__(self) -> None:
            self.requests: list[DecisionRequest] = []

        def decide(self, request: DecisionRequest) -> DecisionResponse:
            self.requests.append(request)
            return KeywordBaselineDecisionProvider().decide(request)

    decision = RecordingDecision()
    database = tmp_path / "snapshot.db"
    with SQLiteStore(database) as store:
        app = investigator(store, decision=decision)
        initial = app.create(objective="why is the computer slow?", budget_ms=4000)
        app.run(str(initial.case_id))
        assert any(not request.attention_only for request in decision.requests)
        assert any(request.attention_only for request in decision.requests)
        rows = store.connection.execute(
            """SELECT snapshot_id, case_id, schema_version, serializer_version,
                      correlation_id, captured_at, request_json, request_sha256,
                      candidate_probe_ids_json, probe_manifest_refs_json
               FROM decision_snapshots WHERE case_id = ? ORDER BY captured_at, snapshot_id""",
            (str(initial.case_id),),
        ).fetchall()
        normal_requests = [request for request in decision.requests if not request.attention_only]
        assert len(rows) == len(normal_requests)
        assert all(row[2] == 1 and row[3] == "decision-request-json-v1" for row in rows)
        assert len({row[0] for row in rows}) == len(rows)
        for row, request in zip(rows, normal_requests, strict=True):
            assert row[1] == str(initial.case_id)
            assert row[4] == request.correlation_id
            assert datetime.fromisoformat(row[5]).tzinfo is not None
            assert DecisionRequest.model_validate_json(row[6]) == request
            assert row[7] == hashlib.sha256(row[6].encode("utf-8")).hexdigest()
            assert row[7] == decision_request_sha256(request)
            assert json.loads(row[8]) == [probe.probe_id for probe in request.available_probes]
            refs = json.loads(row[9])
            assert [ref["probe_id"] for ref in refs] == json.loads(row[8])
            assert all(ref["manifest_version"] == 1 for ref in refs)
            assert all(len(ref["catalog_sha256"]) == 64 for ref in refs)
        projections = store.connection.execute(
            """SELECT correlation_id, laya_projection_version, laya_state_json,
                      laya_evidence_json, laya_candidates_json
               FROM decision_snapshots WHERE case_id = ? ORDER BY captured_at, snapshot_id""",
            (str(initial.case_id),),
        ).fetchall()
        for row, request in zip(projections, normal_requests, strict=True):
            assert row[0] == request.correlation_id
            assert row[1] == "laya-preworker-v1"
            assert json.loads(row[2]) == LayaDecisionProvider.state_for_laya(request)
            assert json.loads(row[3]) == list(
                LayaDecisionProvider.evidence_fragments_for_laya(request)
            )
            assert json.loads(row[4]) == [
                {"probe_id": candidate.probe_id, "description": candidate.description}
                for candidate in eligible_laya_candidates(request)
            ]
    with SQLiteStore(database) as store:
        snapshots = DecisionSnapshotRepository(store).snapshots(case_id=str(initial.case_id))
        assert [snapshot.request for snapshot in snapshots] == normal_requests
        assert [snapshot.laya_candidates for snapshot in snapshots] == [
            tuple(
                {"probe_id": candidate.probe_id, "description": candidate.description}
                for candidate in eligible_laya_candidates(request)
            )
            for request in normal_requests
        ]


def test_decision_snapshots_link_only_their_persisted_probe_executions(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "linked-executions.db") as store:
        app = investigator(store)
        initial = app.create(objective="why is the computer slow?", budget_ms=4000)
        app.run(str(initial.case_id))
        repository = DecisionSnapshotRepository(store)
        snapshots = repository.snapshots(case_id=str(initial.case_id))
        links = tuple(
            link
            for snapshot in snapshots
            for link in repository.execution_links(snapshot.snapshot_id)
        )

        assert links
        assert len({link.execution_id for link in links}) == len(links)
        assert all(link.schema_version == 1 for link in links)
        for link in links:
            snapshot = next(item for item in snapshots if item.snapshot_id == link.snapshot_id)
            execution = store.probe_execution(link.execution_id)
            assert execution is not None
            assert execution.case_id == snapshot.case_id == link.case_id
            assert execution.probe_id == link.probe_id
            assert execution.probe_id in snapshot.candidate_probe_ids
            assert execution.state_version > snapshot.state_version
        assert all(not snapshot.request.attention_only for snapshot in snapshots)
        assert len(links) == store.probe_execution_count(case_id=str(initial.case_id))


def test_decision_execution_link_rejects_cross_case_reuse(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cross-case-link.db") as store:
        app = investigator(store)
        first = app.create(objective="why is the computer slow?", budget_ms=4000)
        app.run(str(first.case_id))
        second = app.create(objective="why is the computer slow?", budget_ms=4000)
        app.run(str(second.case_id))
        repository = DecisionSnapshotRepository(store)
        first_snapshot = repository.snapshots(case_id=str(first.case_id))[0]
        second_snapshot = repository.snapshots(case_id=str(second.case_id))[0]
        first_execution_id = repository.execution_links(first_snapshot.snapshot_id)[0].execution_id

        with pytest.raises(ValueError, match="does not match frozen decision"):
            with store.transaction() as transaction:
                transaction.link_decision_execution(
                    snapshot_id=second_snapshot.snapshot_id,
                    execution_id=first_execution_id,
                )
        assert all(
            link.execution_id != first_execution_id
            for link in repository.execution_links(second_snapshot.snapshot_id)
        )


@pytest.mark.parametrize(
    ("start_offset", "finish_offset"),
    [(-1, 1), (1, 0), (1, None)],
)
def test_decision_execution_link_rejects_invalid_chronology(
    tmp_path: Path, start_offset: int, finish_offset: int | None
) -> None:
    with SQLiteStore(tmp_path / "predated-link.db") as store:
        app = investigator(store)
        initial = app.create(objective="why is the computer slow?", budget_ms=4000)
        app.run(str(initial.case_id))
        snapshot = DecisionSnapshotRepository(store).snapshots(case_id=str(initial.case_id))[0]
        execution_id = str(ExecutionId.new())

        with pytest.raises(ValueError, match="chronology"):
            with store.transaction() as transaction:
                store.connection.execute(
                    """INSERT INTO probe_executions
                       (execution_id, case_id, probe_id, probe_version, status,
                        parameters_json, started_at, finished_at, state_version)
                       VALUES (?, ?, ?, 1, 'ok', '{}', ?, ?, ?)""",
                    (
                        execution_id,
                        snapshot.case_id,
                        snapshot.candidate_probe_ids[0],
                        (snapshot.captured_at + timedelta(seconds=start_offset)).isoformat(),
                        (
                            None
                            if finish_offset is None
                            else (
                                snapshot.captured_at + timedelta(seconds=finish_offset)
                            ).isoformat()
                        ),
                        snapshot.state_version + 1,
                    ),
                )
                transaction.link_decision_execution(
                    snapshot_id=snapshot.snapshot_id, execution_id=execution_id
                )


def test_decision_execution_link_readback_rejects_rewritten_run_time(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "rewritten-link.db") as store:
        app = investigator(store)
        initial = app.create(objective="why is the computer slow?", budget_ms=4000)
        app.run(str(initial.case_id))
        repository = DecisionSnapshotRepository(store)
        snapshot = repository.snapshots(case_id=str(initial.case_id))[0]
        link = repository.execution_links(snapshot.snapshot_id)[0]

        store.connection.execute(
            "UPDATE probe_executions SET started_at = ? WHERE execution_id = ?",
            (
                (snapshot.captured_at - timedelta(seconds=1)).isoformat(),
                link.execution_id,
            ),
        )
        with pytest.raises(ValueError, match="chronology"):
            repository.execution_links(snapshot.snapshot_id)


def test_decision_snapshot_read_rejects_tampered_projection(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "tampered-snapshot.db") as store:
        app = investigator(store)
        initial = app.create(objective="why is the computer slow?", budget_ms=4000)
        app.run(str(initial.case_id))
        assert DecisionSnapshotRepository(store).snapshots(case_id=str(initial.case_id))
        store.connection.execute("DROP TRIGGER decision_snapshots_no_update")
        store.connection.execute(
            """UPDATE decision_snapshots SET laya_candidates_json = '[]'
               WHERE snapshot_id = (
                   SELECT snapshot_id FROM decision_snapshots WHERE case_id = ? LIMIT 1
               )""",
            (str(initial.case_id),),
        )
        with pytest.raises(ValueError, match=r"projection.*mismatch"):
            DecisionSnapshotRepository(store).snapshots(case_id=str(initial.case_id))


def test_decision_snapshots_follow_whole_case_deletion(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "case-delete.db") as store:
        app = investigator(store)
        initial = app.create(objective="why is the computer slow?", budget_ms=4000)
        app.run(str(initial.case_id))
        snapshots = DecisionSnapshotRepository(store).snapshots(case_id=str(initial.case_id))
        assert snapshots
        assert DecisionSnapshotRepository(store).execution_links(snapshots[0].snapshot_id)

        store.connection.execute("DELETE FROM cases WHERE case_id = ?", (str(initial.case_id),))

        assert DecisionSnapshotRepository(store).snapshots(case_id=str(initial.case_id)) == ()
        assert DecisionSnapshotRepository(store).execution_links(snapshots[0].snapshot_id) == ()


def test_snapshot_write_failure_does_not_block_next_probe_decision(tmp_path: Path) -> None:
    class RecordingDecision:
        identity = KeywordBaselineDecisionProvider().identity

        def __init__(self) -> None:
            self.next_probe_calls = 0

        def decide(self, request: DecisionRequest) -> DecisionResponse:
            if not request.attention_only:
                self.next_probe_calls += 1
            return KeywordBaselineDecisionProvider().decide(request)

    decision = RecordingDecision()
    with SQLiteStore(tmp_path / "failed-capture.db") as store:
        app = investigator(store, decision=decision)
        initial = app.create(objective="why is the computer slow?", budget_ms=4000)
        store.connection.execute(
            """CREATE TRIGGER reject_snapshot BEFORE INSERT ON decision_snapshots
               BEGIN SELECT RAISE(ABORT, 'injected snapshot failure'); END"""
        )

        result = app.run(str(initial.case_id))

        assert decision.next_probe_calls > 0
        assert result.completed_probe_ids
        assert any("Decision snapshot unavailable" in warning for warning in result.warnings)
        count = store.connection.execute("SELECT COUNT(*) FROM decision_snapshots").fetchone()
        assert count == (0,)


def test_provider_mutation_cannot_change_frozen_next_probe_snapshot(tmp_path: Path) -> None:
    class MutatingDecision:
        identity = KeywordBaselineDecisionProvider().identity

        def __init__(self) -> None:
            self.originals: dict[str, DecisionRequest] = {}
            self.mutated = 0

        def decide(self, request: DecisionRequest) -> DecisionResponse:
            if not request.attention_only and request.evidence_context:
                self.originals[request.correlation_id] = request.model_copy(deep=True)
                request.evidence_context[0].facts["forged.provider.fact"] = True
                self.mutated += 1
            return KeywordBaselineDecisionProvider().decide(request)

    decision = MutatingDecision()
    with SQLiteStore(tmp_path / "mutation.db") as store:
        app = investigator(store, decision=decision)
        initial = app.create(objective="why is the computer slow?", budget_ms=4000)
        app.run(str(initial.case_id))
        assert decision.mutated > 0
        snapshots = DecisionSnapshotRepository(store).snapshots(case_id=str(initial.case_id))
        for snapshot in snapshots:
            if snapshot.correlation_id in decision.originals:
                assert snapshot.request == decision.originals[snapshot.correlation_id]
                assert all(
                    "forged.provider.fact" not in page.facts
                    for page in snapshot.request.evidence_context
                )


def test_reasoning_provider_cannot_mutate_trusted_assessed_evidence(tmp_path: Path) -> None:
    class MutatingReasoning:
        identity = DeterministicReasoningProvider().identity

        def __init__(self) -> None:
            self.mutated = False

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            if request.evidence_context:
                request.evidence_context[0].facts["forged.provider.fact"] = True
                self.mutated = True
            return DeterministicReasoningProvider().investigate(request)

    reasoning = MutatingReasoning()
    with SQLiteStore(tmp_path / "reasoning-mutation.db") as store:
        app = investigator(store, reasoning=reasoning)
        initial = app.create(objective="why is the computer slow?", budget_ms=4000, max_rounds=1)

        result = app.run(str(initial.case_id))

        assert reasoning.mutated
        assert all("forged.provider.fact" not in item.facts for item in result.assessed_context)
        assert all(
            "forged.provider.fact" not in item.facts for item in app.context(str(initial.case_id))
        )


def test_mutating_reasoning_provider_cannot_admit_unregistered_action(tmp_path: Path) -> None:
    class MutatingReasoning:
        identity = DeterministicReasoningProvider().identity

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            if request.evidence_context:
                request.evidence_context[0].facts["forged.provider.fact"] = True
            response = DeterministicReasoningProvider().investigate(request)
            return response.model_copy(
                update={
                    "distinguishing_probes": (
                        ProbeProposal(
                            probe_id="repair.proxy",
                            purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
                            priority=1.0,
                            estimated_cost_ms=1,
                            resource_class=ResourceClass.CPU,
                            dedupe_key="repair.proxy:malicious",
                        ),
                    )
                }
            )

    with SQLiteStore(tmp_path / "reasoning-action.db") as store:
        app = investigator(store, reasoning=MutatingReasoning())
        initial = app.create(objective="why is the computer slow?", budget_ms=4000, max_rounds=1)

        result = app.run(str(initial.case_id))

        assert "repair.proxy" not in result.completed_probe_ids
        assert "repair.proxy" not in (
            item.probe_id for item in result.pending_distinguishing_probes
        )
        assert any("Reasoning unavailable or rejected" in warning for warning in result.warnings)
        assert all("forged.provider.fact" not in item.facts for item in result.assessed_context)


def test_optional_snapshot_capture_uses_short_lock_wait(tmp_path: Path) -> None:
    database = tmp_path / "capture-lock.db"
    with SQLiteStore(database) as store:
        app = investigator(store)
        initial = app.create(objective="why is the computer slow?", budget_ms=4000)
        app.run(str(initial.case_id))
        snapshot = DecisionSnapshotRepository(store).snapshots(case_id=str(initial.case_id))[0]
        original_timeout = store.connection.execute("PRAGMA busy_timeout").fetchone()[0]
        with SQLiteStore(database) as blocker:
            blocker.connection.execute("BEGIN IMMEDIATE")
            started = time.monotonic()
            try:
                with pytest.raises(sqlite3.OperationalError, match="locked"):
                    DecisionSnapshotRepository(store).capture(
                        snapshot.request,
                        probe_manifest_refs=snapshot.probe_manifest_refs,
                    )
            finally:
                blocker.connection.rollback()
            assert time.monotonic() - started < 0.5
        assert store.connection.execute("PRAGMA busy_timeout").fetchone()[0] == original_timeout


def test_whole_case_deletion_removes_private_decision_snapshots(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "snapshot-retention.db") as store:
        app = investigator(store)
        initial = app.create(objective="why is the computer slow?", budget_ms=4000)
        app.run(str(initial.case_id))
        assert DecisionSnapshotRepository(store).snapshots(case_id=str(initial.case_id))
        with store.transaction():
            store.connection.execute("DELETE FROM cases WHERE case_id = ?", (str(initial.case_id),))
        assert not DecisionSnapshotRepository(store).snapshots(case_id=str(initial.case_id))


def test_snapshot_manifest_digest_rejects_wrong_registered_probe() -> None:
    manifest = probe_definition("network").manifest
    with pytest.raises(ValueError, match="manifest probe ID"):
        ProbeManifestRef.from_manifest("windows.different", manifest)


def test_repeated_failed_probe_batches_stop_as_no_progress(tmp_path: Path) -> None:
    def fail(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        raise RuntimeError("injected collection failure")

    definitions = tuple(
        replace(probe_definition(f"fault{index}"), handler=fail) for index in range(8)
    )
    with SQLiteStore(tmp_path / "failed.db") as store:
        app = investigator(store, definitions=definitions)
        initial = app.create(objective="unrecognized symptom", budget_ms=5000, max_probes=8)

        result = app.run(str(initial.case_id))

        assert result.status is InvestigationStatus.COMPLETE
        assert result.outcome is InvestigationOutcome.NO_PROGRESS
        assert result.stagnant_rounds == 2
        assert len(result.completed_probe_ids) == 8
        assert store.probe_execution_count(case_id=str(initial.case_id)) == 8
        snapshots = DecisionSnapshotRepository(store).snapshots(case_id=str(initial.case_id))
        links = tuple(
            link
            for snapshot in snapshots
            for link in DecisionSnapshotRepository(store).execution_links(snapshot.snapshot_id)
        )
        assert links
        for link in links:
            execution = store.probe_execution(link.execution_id)
            assert execution is not None
            assert execution.status == "failed"
        assert "no fresh usable observations" in (result.stop_reason or "")


def test_fast_request_receives_durable_stagnation_context(tmp_path: Path) -> None:
    class CapturingDecision(KeywordBaselineDecisionProvider):
        seen: list[DecisionRequest]

        def __init__(self) -> None:
            self.seen = []

        def decide(self, request: DecisionRequest) -> DecisionResponse:
            self.seen.append(request)
            return super().decide(request)

    decision = CapturingDecision()
    with SQLiteStore(tmp_path / "fast-stagnation.db") as store:
        app = investigator(store, decision=decision)
        initial = app.create(objective="unrecognized symptom", budget_ms=4000)
        app.repository.save(
            initial.model_copy(
                update={
                    "stagnant_rounds": 2,
                    "hypotheses": (
                        Hypothesis(
                            hypothesis_id="h_core",
                            statement="The core status should be clear.",
                            status=HypothesisStatus.UNRESOLVED,
                            expected_facts=(
                                ExpectedFact(
                                    probe_id="core.snapshot",
                                    fact_name="value",
                                    expected_value=1,
                                ),
                            ),
                            expected_facts_observed_after=datetime.now(UTC) - timedelta(seconds=2),
                        ),
                    ),
                }
            ),
            expected_version=initial.state_version,
            event="test_checkpoint",
            detail="Durable no-progress context",
        )

        app.run(str(initial.case_id))

        assert decision.seen
        assert decision.seen[0].schema_version == 3
        assert decision.seen[0].stagnant_rounds == 2
        assert decision.seen[0].hypothesis_checks[0].fact_name == "value"


def test_coordinator_stamps_deep_fact_prediction_after_reasoning(tmp_path: Path) -> None:
    class PredictingReasoner(DeterministicReasoningProvider):
        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            return ReasoningResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="The next core status remains uncertain.",
                hypotheses=(
                    Hypothesis(
                        hypothesis_id="h_core_prediction",
                        statement="Core status should be clear.",
                        status=HypothesisStatus.UNRESOLVED,
                        expected_facts=(
                            ExpectedFact(
                                probe_id="core.snapshot",
                                fact_name="value",
                                expected_value=1,
                            ),
                        ),
                    ),
                ),
            )

    with SQLiteStore(tmp_path / "prediction-time.db") as store:
        app = investigator(store, reasoning=PredictingReasoner())
        initial = app.create(objective="unknown symptom", budget_ms=3000)
        before = datetime.now(UTC)

        result = app.run(str(initial.case_id))

        after = datetime.now(UTC)
        assert result.hypotheses
        prediction_time = result.hypotheses[0].expected_facts_observed_after
        assert prediction_time is not None
        assert before <= prediction_time <= after


def test_successful_baseline_does_not_mask_two_later_failed_batches(tmp_path: Path) -> None:
    def fail(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        raise RuntimeError("injected collection failure")

    network = probe_definition("network")
    baseline = replace(
        network,
        manifest=network.manifest.model_copy(
            update={
                "probe_id": "network.connectivity",
                "implementation_id": "builtin.network.connectivity",
            }
        ),
    )
    failed = tuple(replace(probe_definition(f"fault{index}"), handler=fail) for index in range(8))
    with SQLiteStore(tmp_path / "baseline.db") as store:
        app = investigator(store, definitions=(baseline, *failed))
        initial = app.create(objective="wifi disconnected", budget_ms=5000, max_probes=9)

        result = app.run(str(initial.case_id))

        assert result.outcome is InvestigationOutcome.NO_PROGRESS
        assert result.stagnant_rounds == 2
        assert "network.connectivity" in result.completed_probe_ids
        assert len(result.completed_probe_ids) == 9
        baseline_execution = store.connection.execute(
            """SELECT execution_id FROM probe_executions
               WHERE case_id = ? AND probe_id = 'network.connectivity'""",
            (str(initial.case_id),),
        ).fetchone()
        assert baseline_execution is not None
        snapshots = DecisionSnapshotRepository(store).snapshots(case_id=str(initial.case_id))
        linked_ids = {
            link.execution_id
            for snapshot in snapshots
            for link in DecisionSnapshotRepository(store).execution_links(snapshot.snapshot_id)
        }
        assert linked_ids
        assert str(baseline_execution[0]) not in linked_ids
        assert len(linked_ids) == store.probe_execution_count(case_id=str(initial.case_id)) - 1


def test_no_progress_gate_allows_new_deep_brain_distinguishing_probe(tmp_path: Path) -> None:
    def fail(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        raise RuntimeError("injected collection failure")

    class RedirectingReasoner:
        calls = 0

        @property
        def identity(self) -> ProviderIdentity:
            return ProviderIdentity(
                provider_id="fixture-redirect",
                provider_version="1",
                role="reasoning",
            )

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            self.calls += 1
            rescue = next(
                item for item in request.available_probes if item.probe_id == "zrescue.snapshot"
            )
            proposed = (
                (
                    ProbeProposal(
                        probe_id=rescue.probe_id,
                        purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
                        priority=1.0,
                        estimated_cost_ms=rescue.cost_ms,
                        resource_class=rescue.resource_class,
                        dedupe_key="fixture:rescue",
                    ),
                )
                if self.calls == 2
                else ()
            )
            return ReasoningResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="Try the independent rescue probe." if proposed else "Cause unverified.",
                distinguishing_probes=proposed,
            )

    failed = tuple(replace(probe_definition(f"fault{index}"), handler=fail) for index in range(8))
    reasoner = RedirectingReasoner()
    with SQLiteStore(tmp_path / "redirect.db") as store:
        app = investigator(
            store,
            definitions=(*failed, probe_definition("zrescue")),
            reasoning=reasoner,
        )
        initial = app.create(objective="unrecognized symptom", budget_ms=5000, max_probes=9)

        result = app.run(str(initial.case_id))

        assert reasoner.calls >= 3
        assert "zrescue.snapshot" in result.completed_probe_ids
        context = app.context(str(initial.case_id))
        assert any(
            item.probe_id == "zrescue.snapshot" and item.status is EvidenceContextStatus.OBSERVED
            for item in context
        )


def test_deep_redirect_wins_last_probe_slot_over_fast_brain(tmp_path: Path) -> None:
    class CompetingDecision:
        @property
        def identity(self) -> ProviderIdentity:
            return ProviderIdentity(
                provider_id="fixture-fast", provider_version="1", role="fast_decision"
            )

        def decide(self, request: DecisionRequest) -> DecisionResponse:
            next_id = (
                "first.snapshot"
                if "first.snapshot" not in request.completed_probe_ids
                else "fast_second.snapshot"
            )
            capability = next(p for p in request.available_probes if p.probe_id == next_id)
            return DecisionResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                proposals=(
                    ProbeProposal(
                        probe_id=next_id,
                        purpose=DiagnosticPurpose.CHECK_COVERAGE,
                        priority=1.0,
                        estimated_cost_ms=capability.cost_ms,
                        resource_class=capability.resource_class,
                        dedupe_key=f"fixture:{next_id}",
                    ),
                ),
            )

    class RedirectingReasoner:
        @property
        def identity(self) -> ProviderIdentity:
            return ProviderIdentity(
                provider_id="fixture-reasoner", provider_version="1", role="reasoning"
            )

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            capability = next(
                p for p in request.available_probes if p.probe_id == "deep_second.snapshot"
            )
            proposed = ()
            if "deep_second.snapshot" not in request.completed_probe_ids:
                proposed = (
                    ProbeProposal(
                        probe_id=capability.probe_id,
                        purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
                        priority=1.0,
                        estimated_cost_ms=capability.cost_ms,
                        resource_class=capability.resource_class,
                        dedupe_key="fixture:deep-redirect",
                    ),
                )
            return ReasoningResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="Use the deep distinguishing test.",
                distinguishing_probes=proposed,
            )

    with SQLiteStore(tmp_path / "deep-priority.db") as store:
        app = investigator(
            store,
            definitions=(
                probe_definition("first"),
                probe_definition("fast_second"),
                probe_definition("deep_second"),
            ),
            decision=CompetingDecision(),
            reasoning=RedirectingReasoner(),
        )
        case = app.create(objective="unknown intermittent symptom", budget_ms=5000, max_probes=2)

        result = app.run(str(case.case_id))

        assert result.completed_probe_ids == ("first.snapshot", "deep_second.snapshot")
        assert "fast_second.snapshot" not in result.completed_probe_ids
        assert result.pending_distinguishing_probes == ()


def test_pending_deep_redirect_survives_checkpoint_and_resume(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "pending-redirect.db") as store:
        app = investigator(
            store,
            definitions=(probe_definition("fast"), probe_definition("deep")),
        )
        case = app.create(objective="unrecognized intermittent symptom", max_probes=1)
        deep = next(p for p in app.capabilities if p.probe_id == "deep.snapshot")
        redirect = ProbeProposal(
            probe_id=deep.probe_id,
            purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
            priority=1.0,
            estimated_cost_ms=deep.cost_ms,
            resource_class=deep.resource_class,
            dedupe_key="fixture:durable-deep",
        )
        app.repository.save(
            case.model_copy(
                update={
                    "status": InvestigationStatus.INTERRUPTED,
                    "pending_distinguishing_probes": (redirect,),
                }
            ),
            expected_version=case.state_version,
            event="interrupted",
            detail="Persisted a validated deep redirect before restart.",
        )

    with SQLiteStore(tmp_path / "pending-redirect.db") as store:
        app = investigator(
            store,
            definitions=(probe_definition("fast"), probe_definition("deep")),
        )
        resumed = app.resume(str(case.case_id))
        assert resumed.pending_distinguishing_probes == (redirect,)
        finished = app.run(str(case.case_id))
        assert finished.completed_probe_ids == ("deep.snapshot",)
        assert finished.pending_distinguishing_probes == ()


def test_checkpoint_cannot_be_loaded_under_another_case_id(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "case-binding.db") as store:
        app = investigator(store)
        case = app.create(objective="unrecognized intermittent symptom")
        foreign = CaseId.new()
        corrupted = case.model_copy(update={"case_id": foreign})
        with store.transaction():
            store.connection.execute(
                "UPDATE investigation_checkpoints SET record_json = ? WHERE case_id = ?",
                (corrupted.model_dump_json(), str(case.case_id)),
            )

        with pytest.raises(ValueError, match="another case"):
            app.repository.load(str(case.case_id))


def test_removed_deep_probe_is_retired_on_resume_without_crashing(tmp_path: Path) -> None:
    database = tmp_path / "removed-deep.db"
    with SQLiteStore(database) as store:
        app = investigator(
            store,
            definitions=(probe_definition("fast"), probe_definition("deep")),
        )
        case = app.create(objective="unrecognized intermittent symptom", max_probes=1)
        deep = next(p for p in app.capabilities if p.probe_id == "deep.snapshot")
        redirect = ProbeProposal(
            probe_id=deep.probe_id,
            purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
            priority=1.0,
            estimated_cost_ms=deep.cost_ms,
            resource_class=deep.resource_class,
            dedupe_key="fixture:removed-deep",
        )
        app.repository.save(
            case.model_copy(
                update={
                    "status": InvestigationStatus.INTERRUPTED,
                    "pending_distinguishing_probes": (redirect,),
                }
            ),
            expected_version=case.state_version,
            event="interrupted",
            detail="The registered probe is removed before case resume.",
        )

    with SQLiteStore(database) as store:
        app = investigator(store, definitions=(probe_definition("fast"),))
        app.resume(str(case.case_id))
        finished = app.run(str(case.case_id))

        assert finished.completed_probe_ids == ("fast.snapshot",)
        assert finished.pending_distinguishing_probes == ()
        assert any("deep probe requests were retired" in item for item in finished.warnings)


def test_deep_brain_can_rescue_empty_fast_brain_routing(tmp_path: Path) -> None:
    class EmptyDecision:
        @property
        def identity(self) -> ProviderIdentity:
            return ProviderIdentity(
                provider_id="fixture-empty", provider_version="1", role="fast_decision"
            )

        def decide(self, request: DecisionRequest) -> DecisionResponse:
            return DecisionResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
            )

    class RescueReasoner:
        @property
        def identity(self) -> ProviderIdentity:
            return ProviderIdentity(
                provider_id="fixture-rescue", provider_version="1", role="reasoning"
            )

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            rescue = next(p for p in request.available_probes if p.probe_id == "rescue.snapshot")
            proposals = ()
            if rescue.probe_id not in request.completed_probe_ids:
                proposals = (
                    ProbeProposal(
                        probe_id=rescue.probe_id,
                        purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
                        priority=1.0,
                        estimated_cost_ms=rescue.cost_ms,
                        resource_class=rescue.resource_class,
                        dedupe_key="fixture:empty-fast-rescue",
                    ),
                )
            return ReasoningResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="Rescue probe requested.",
                distinguishing_probes=proposals,
            )

    with SQLiteStore(tmp_path / "empty-fast.db") as store:
        app = investigator(
            store,
            definitions=(probe_definition("rescue"),),
            decision=EmptyDecision(),
            reasoning=RescueReasoner(),
        )
        case = app.create(objective="unrecognized intermittent symptom", max_probes=1)

        result = app.run(str(case.case_id))

        assert result.completed_probe_ids == ("rescue.snapshot",)


def test_merged_deep_and_fast_proposals_keep_one_four_probe_batch(tmp_path: Path) -> None:
    class FourWayDecision:
        @property
        def identity(self) -> ProviderIdentity:
            return ProviderIdentity(
                provider_id="fixture-four-fast", provider_version="1", role="fast_decision"
            )

        def decide(self, request: DecisionRequest) -> DecisionResponse:
            ids = (
                tuple(f"fast{index}.snapshot" for index in range(4))
                if "start.snapshot" in request.completed_probe_ids
                else ("start.snapshot",)
            )
            capabilities = {p.probe_id: p for p in request.available_probes}
            return DecisionResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                proposals=tuple(
                    ProbeProposal(
                        probe_id=probe_id,
                        purpose=DiagnosticPurpose.CHECK_COVERAGE,
                        priority=1.0,
                        estimated_cost_ms=capabilities[probe_id].cost_ms,
                        resource_class=capabilities[probe_id].resource_class,
                        dedupe_key=f"fixture:{probe_id}",
                    )
                    for probe_id in ids
                ),
            )

    class FourWayReasoner:
        @property
        def identity(self) -> ProviderIdentity:
            return ProviderIdentity(
                provider_id="fixture-four-deep", provider_version="1", role="reasoning"
            )

        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            capabilities = {p.probe_id: p for p in request.available_probes}
            proposals = tuple(
                ProbeProposal(
                    probe_id=probe_id,
                    purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
                    priority=1.0,
                    estimated_cost_ms=capabilities[probe_id].cost_ms,
                    resource_class=capabilities[probe_id].resource_class,
                    dedupe_key=f"fixture:deep:{probe_id}",
                )
                for probe_id in (f"deep{index}.snapshot" for index in range(4))
                if probe_id not in request.completed_probe_ids
            )
            return ReasoningResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                status=ReasoningStatus.UNRESOLVED,
                summary="Four deep tests distinguish the remaining explanations.",
                distinguishing_probes=proposals,
            )

    definitions = (
        probe_definition("start"),
        *(probe_definition(f"fast{index}") for index in range(4)),
        *(probe_definition(f"deep{index}") for index in range(4)),
    )
    with SQLiteStore(tmp_path / "batch-cap.db") as store:
        app = investigator(
            store,
            definitions=definitions,
            decision=FourWayDecision(),
            reasoning=FourWayReasoner(),
        )
        case = app.create(
            objective="unknown intermittent symptom", budget_ms=5000, max_rounds=2, max_probes=12
        )

        result = app.run(str(case.case_id))

        assert result.completed_probe_ids == (
            "start.snapshot",
            *(f"deep{index}.snapshot" for index in range(4)),
        )
        assert store.probe_execution_count(case_id=str(case.case_id)) == 5


def test_batch_cap_admits_deep_dependency_bundle_before_fast_fill(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "dependency-batch.db") as store:
        app = investigator(
            store,
            definitions=(
                probe_definition("deep_child"),
                probe_definition("deep_parent"),
                probe_definition("fast"),
            ),
        )
        case = app.create(objective="unknown intermittent symptom", max_probes=8)
        known = {p.probe_id: p for p in app.capabilities}

        def proposal(probe_id: str, *, depends_on: tuple[str, ...] = ()) -> ProbeProposal:
            capability = known[probe_id]
            return ProbeProposal(
                probe_id=probe_id,
                purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
                priority=1.0,
                estimated_cost_ms=capability.cost_ms,
                resource_class=capability.resource_class,
                dedupe_key=f"fixture:{probe_id}",
                depends_on=depends_on,
            )

        child = proposal("deep_child.snapshot", depends_on=("deep_parent.snapshot",))
        parent = proposal("deep_parent.snapshot")
        fast = proposal("fast.snapshot")
        selected = app._eligible(  # pyright: ignore[reportPrivateUsage]
            (child, parent, fast), case, 100, batch_limit=2
        )
        assert tuple(p.probe_id for p in selected) == (
            "deep_parent.snapshot",
            "deep_child.snapshot",
        )

        unsafe_child = child.model_copy(update={"safety_class": SafetyClass.R0})
        safe_fill = app._eligible(  # pyright: ignore[reportPrivateUsage]
            (unsafe_child, parent, fast), case, 100, batch_limit=2
        )
        assert tuple(p.probe_id for p in safe_fill) == ("deep_parent.snapshot", "fast.snapshot")


def test_stale_deep_dependency_does_not_shadow_fast_same_probe_on_resume(
    tmp_path: Path,
) -> None:
    class FastChildDecision:
        @property
        def identity(self) -> ProviderIdentity:
            return ProviderIdentity(
                provider_id="fixture-fast-child", provider_version="1", role="fast_decision"
            )

        def decide(self, request: DecisionRequest) -> DecisionResponse:
            child = next(p for p in request.available_probes if p.probe_id == "child.snapshot")
            return DecisionResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                proposals=(
                    ProbeProposal(
                        probe_id=child.probe_id,
                        purpose=DiagnosticPurpose.CHECK_COVERAGE,
                        priority=1.0,
                        estimated_cost_ms=child.cost_ms,
                        resource_class=child.resource_class,
                        dedupe_key="fixture:fast-child",
                    ),
                ),
            )

    database = tmp_path / "stale-child.db"
    definitions = (probe_definition("parent"), probe_definition("child"))
    with SQLiteStore(database) as store:
        app = investigator(store, definitions=definitions)
        case = app.create(objective="unrecognized intermittent symptom", max_probes=2)
        child = next(p for p in app.capabilities if p.probe_id == "child.snapshot")
        stale = ProbeProposal(
            probe_id=child.probe_id,
            purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
            priority=1.0,
            estimated_cost_ms=child.cost_ms,
            resource_class=child.resource_class,
            dedupe_key="fixture:stale-deep-child",
            depends_on=("parent.snapshot",),
        )
        app.repository.save(
            case.model_copy(
                update={
                    "status": InvestigationStatus.INTERRUPTED,
                    "completed_probe_ids": ("parent.snapshot",),
                    "pending_distinguishing_probes": (stale,),
                }
            ),
            expected_version=case.state_version,
            event="interrupted",
            detail="Deep request became stale after its prerequisite was attempted.",
        )

    with SQLiteStore(database) as store:
        app = investigator(store, definitions=definitions, decision=FastChildDecision())
        app.resume(str(case.case_id))
        finished = app.run(str(case.case_id))

        assert finished.completed_probe_ids == ("parent.snapshot", "child.snapshot")
        assert finished.pending_distinguishing_probes == ()


def test_cancelled_case_is_durable_and_can_resume(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "test.db") as store:
        app = investigator(store)
        initial = app.create(objective="network failure", budget_ms=2000)
        incident_window = (initial.incident_start, initial.incident_end)
        first_deadline = initial.deadline_at
        cancellation = threading.Event()
        cancellation.set()
        result = app.run(str(initial.case_id), cancel_event=cancellation)
        assert result.status is InvestigationStatus.CANCELLED
        assert (result.incident_start, result.incident_end) == incident_window
        assert store.probe_execution_count(case_id=str(initial.case_id)) == 0
        resumed = app.resume(str(initial.case_id))
        assert resumed.deadline_at > datetime.now(UTC)
        assert resumed.deadline_at > first_deadline
        assert (resumed.incident_start, resumed.incident_end) == incident_window
        final = app.run(str(initial.case_id))
        assert final.status is InvestigationStatus.COMPLETE
        assert (final.incident_start, final.incident_end) == incident_window
        assert store.probe_execution_count(case_id=str(initial.case_id)) == 3
    with SQLiteStore(tmp_path / "test.db") as store:
        persisted = InvestigationRepository(store).load(str(initial.case_id))
        assert (persisted.incident_start, persisted.incident_end) == incident_window


def test_recent_passive_history_is_explicitly_pinned_and_retrievable(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "test.db") as store:
        historical = _passive_evidence(store, captured_at=datetime.now(UTC))
        app = investigator(store)

        initial = app.create(objective="intermittent resource pressure", budget_ms=2000)
        packet = app.packet(str(initial.case_id))

        assert initial.historical_case_ids == (historical.case_id,)
        assert str(historical.evidence_id) in {str(item.evidence_id) for item in packet.evidence}
        assert any(
            "Historical observation" in limitation
            for item in app.context(str(initial.case_id))
            if item.evidence_id == historical.evidence_id
            for limitation in item.limitations
        )
        checkpoint = InvestigationRepository(store).load(str(initial.case_id))
        assert checkpoint.historical_case_ids == (historical.case_id,)


def test_recent_passive_case_excludes_observations_outside_incident_window(
    tmp_path: Path,
) -> None:
    now = datetime.now(UTC)
    with SQLiteStore(tmp_path / "test.db") as store:
        recent = _passive_evidence(store, captured_at=now, sequence=1)
        stale = _persist_evidence(
            store,
            case_id=recent.case_id,
            facts={"history_marker": 2, "age": "stale"},
            captured_at=now - timedelta(days=90),
            sequence=2,
        )
        coverage = CoverageRecord(
            evidence_id=EvidenceId.new(),
            case_id=recent.case_id,
            category="core",
            status=CoverageStatus.COVERED,
            captured_at=now,
            reason="The recent passive cycle covered core state.",
        )
        coverage_source = stable_source_id("fixture.coverage", {"case_id": str(recent.case_id)})
        with store.transaction() as transaction:
            transaction.insert_evidence(
                case_id=str(recent.case_id),
                evidence_id=str(coverage.evidence_id),
                source_id=coverage_source,
                record_json=coverage.model_dump_json(),
                captured_at=now.isoformat(),
                dedupe_key="fixture:coverage",
                time_basis="collector_captured",
                time_quality="exact",
            )
        app = investigator(store)
        initial = app.create(objective="intermittent resource pressure", budget_ms=2000)

        packet = app.packet(str(initial.case_id))

        assert str(recent.evidence_id) in {str(item.evidence_id) for item in packet.evidence}
        assert str(stale.evidence_id) not in {str(item.evidence_id) for item in packet.evidence}
        assert str(coverage.evidence_id) in {str(item.evidence_id) for item in packet.coverage}
        contexts = {str(item.evidence_id): item for item in app.context(str(initial.case_id))}
        assert contexts[str(recent.evidence_id)].case_scope == "historical"
        assert contexts[str(recent.evidence_id)].incident_relevant is True


def test_delayed_current_collection_survives_incident_window_without_expanding_history(
    tmp_path: Path,
) -> None:
    now = datetime.now(UTC)
    with SQLiteStore(tmp_path / "late.db") as store:
        history = _passive_evidence(store, captured_at=now, sequence=1)
        app = investigator(store)
        state = app.create(objective="intermittent pressure", budget_ms=600_000)
        late = state.incident_end + timedelta(minutes=10)
        current = _persist_evidence(
            store, case_id=state.case_id, facts={"sample": 1}, captured_at=late, sequence=2
        )
        foreign = _persist_evidence(
            store, case_id=history.case_id, facts={"sample": 2}, captured_at=late, sequence=3
        )
        coverage = CoverageRecord(
            evidence_id=EvidenceId.new(),
            case_id=state.case_id,
            category="network",
            status=CoverageStatus.FAILED,
            captured_at=late,
            reason="Late attempt failed.",
        )
        with store.transaction() as transaction:
            transaction.insert_evidence(
                case_id=str(state.case_id),
                evidence_id=str(coverage.evidence_id),
                source_id=stable_source_id("fixture.coverage", {"late": True}),
                record_json=coverage.model_dump_json(),
                captured_at=late.isoformat(),
            )
        strict = EvidenceRetriever(store).retrieve(
            EvidenceRetrievalQuery(
                current_case_id=state.case_id,
                observed_from=state.incident_start,
                observed_until=state.incident_end,
            )
        )
        assert not strict.evidence and not strict.coverage
        packet = app.packet(str(state.case_id))
        assert str(current.evidence_id) in {str(item.evidence_id) for item in packet.evidence}
        assert str(foreign.evidence_id) not in {str(item.evidence_id) for item in packet.evidence}
        assert str(coverage.evidence_id) in {str(item.evidence_id) for item in packet.coverage}
        contexts = {str(item.evidence_id): item for item in app.context(str(state.case_id))}
        for evidence_id in (current.evidence_id, coverage.evidence_id):
            assert contexts[str(evidence_id)].case_scope == "current_case"
            assert contexts[str(evidence_id)].incident_relevant is False
            assert any(
                "outside the incident window" in note
                for note in contexts[str(evidence_id)].limitations
            )
        assert app.repository.load(str(state.case_id)).incident_end == state.incident_end


def test_collector_explicit_facts_persist_service_process_graph_edge(tmp_path: Path) -> None:
    base = probe_definition("core")

    def collect(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        observed_at = datetime.now(UTC)
        return ProbeObservation(
            summary="Service and process ownership",
            facts={
                "processes": [{"pid": 4242, "creation_time": "2026-09-22T08:00:00+00:00"}],
                "services": [{"name": "Spooler", "process_id": 4242}],
            },
            observed_at=observed_at,
            captured_at=observed_at,
        )

    definition = replace(base, handler=collect)
    with SQLiteStore(tmp_path / "test.db") as store:
        app = investigator(store, definitions=(definition,))
        initial = app.create(objective="service failure", budget_ms=2000)

        result = app.run(str(initial.case_id))
        relations = EvidenceRelationRepository(store).relations()

        assert result.status is InvestigationStatus.COMPLETE
        edge = next(item for item in relations if item.relationship is RelationKind.RUNS_IN_PROCESS)
        assert edge.conditions == ("service process ownership explicitly reported",)
        assert len(edge.evidence_ids) == 1
        assert edge.source_ids


def test_sampled_gpu_relation_routes_registered_driver_probe(tmp_path: Path) -> None:
    from systemsense.platform.windows.deep_collectors import (
        ComponentStatus,
        NvidiaGpuTelemetry,
        NvidiaTelemetrySeries,
        NvidiaTelemetrySnapshot,
    )

    class CapturingTypedDecision(TypedFeatureDecisionProvider):
        graph_scores: list[float]

        def __init__(self) -> None:
            super().__init__()
            self.graph_scores = []

        def decide(self, request: DecisionRequest) -> DecisionResponse:
            for candidate in self.score_candidates(request):
                if candidate.probe_id == "devices.snapshot":
                    self.graph_scores.append(candidate.features.machine_graph)
            return super().decide(request)

    def collect_gpu(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        gpu = NvidiaGpuTelemetry(
            index=0, uuid="GPU-TEST-4090", name="Test GPU", driver_version="581.80"
        )
        interval_note = "nvidia-smi sample instant is unknown within the bounded query interval"
        samples: list[NvidiaTelemetrySnapshot] = []
        for _ in range(3):
            sample_started_at = datetime.now(UTC)
            time.sleep(0.02)
            samples.append(
                NvidiaTelemetrySnapshot(
                    sample_started_at=sample_started_at,
                    captured_at=datetime.now(UTC),
                    status=ComponentStatus.AVAILABLE,
                    gpus=(gpu,),
                    limitation=interval_note,
                )
            )
        now = samples[-1].captured_at
        assert samples[0].sample_started_at is not None
        series = NvidiaTelemetrySeries(
            captured_at=now,
            window_started_at=samples[0].sample_started_at,
            window_ended_at=samples[-1].captured_at,
            inter_sample_delay_seconds=0.5,
            samples=tuple(samples),
            status=ComponentStatus.AVAILABLE,
            limitations=(interval_note,),
        )
        time.sleep(0.02)
        return ProbeObservation(
            summary="Three GPU telemetry samples",
            facts={"gpu_telemetry_sample": cast("JsonValue", series.model_dump(mode="json"))},
            observed_at=now,
            captured_at=now,
            time_quality="bounded_interval",
            limitations=(interval_note,),
        )

    base = probe_definition("gpu")
    gpu_probe = replace(
        base,
        manifest=base.manifest.model_copy(
            update={
                "probe_id": "gpu.telemetry.sample",
                "implementation_id": "builtin.gpu.telemetry.sample",
            }
        ),
        handler=collect_gpu,
    )
    decision = CapturingTypedDecision()
    with SQLiteStore(tmp_path / "gpu-route.db") as store:
        app = investigator(
            store,
            definitions=(gpu_probe, probe_definition("devices")),
            decision=decision,
        )
        initial = app.create(objective="my game is at 12 FPS", budget_ms=5000, max_probes=2)

        result = app.run(str(initial.case_id))

        assert result.status is InvestigationStatus.COMPLETE
        assert result.completed_probe_ids == ("gpu.telemetry.sample", "devices.snapshot")
        assert 0.25 in decision.graph_scores
        relations = EvidenceRelationRepository(store).relations()
        assert any(
            item.relationship is RelationKind.USES_DRIVER
            and item.applicability == ("gpu.telemetry.sample",)
            for item in relations
        )


class _RevisingReasoning:
    def __init__(self) -> None:
        self.calls = 0

    @property
    def identity(self) -> ProviderIdentity:
        return ProviderIdentity(
            provider_id="fixture-revising",
            provider_version="1",
            role="reasoning",
        )

    def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
        self.calls += 1
        historical = next(
            item.evidence_id for item in request.evidence_context if "history_marker" in item.facts
        )
        current = next(
            item.evidence_id for item in request.evidence_context if "category" in item.facts
        )
        hypothesis = (
            Hypothesis(
                hypothesis_id="h_historical",
                statement="The older observation may describe the incident.",
                status=HypothesisStatus.UNRESOLVED,
                supporting_evidence_ids=(historical,),
            )
            if self.calls == 1
            else Hypothesis(
                hypothesis_id="h_historical",
                statement="The current observation contests the older explanation.",
                status=HypothesisStatus.CONTESTED,
                supporting_evidence_ids=(current,),
                contradicting_evidence_ids=(historical,),
            )
        )
        return ReasoningResponse(
            provider=self.identity,
            case_id=request.case_id,
            state_version=request.state_version,
            correlation_id=request.correlation_id,
            deadline_at=request.deadline_at,
            status=ReasoningStatus.UNRESOLVED,
            summary="Fixture hypothesis revision.",
            hypotheses=(hypothesis,),
        )


def test_hypothesis_revision_preserves_older_historical_contradiction(tmp_path: Path) -> None:
    provider = _RevisingReasoning()
    with SQLiteStore(tmp_path / "test.db") as store:
        historical = _passive_evidence(store, captured_at=datetime.now(UTC))
        app = investigator(
            store,
            definitions=(probe_definition("core"),),
            reasoning=provider,
        )
        initial = app.create(objective="intermittent slowdown", budget_ms=2000)

        final = app.run(str(initial.case_id))
        steps = InvestigationRepository(store).steps(str(initial.case_id))

        assert provider.calls == 2
        assert historical.evidence_id in final.hypotheses[0].contradicting_evidence_ids
        revisions = [
            step.hypotheses[0]
            for step in steps
            if step.hypotheses and step.hypotheses[0].hypothesis_id == "h_historical"
        ]
        assert [item.status for item in revisions] == [
            HypothesisStatus.UNRESOLVED,
            HypothesisStatus.CONTESTED,
        ]


def test_bounded_packet_omits_stale_hypothesis_references_without_crashing(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "test.db") as store:
        app = investigator(store, definitions=(probe_definition("core"),))
        initial = app.create(objective="large evidence history", budget_ms=2000)
        captured_at = datetime.now(UTC)
        records = tuple(
            _persist_evidence(
                store,
                case_id=initial.case_id,
                facts={"bulk_sequence": sequence},
                captured_at=captured_at,
                sequence=sequence,
            )
            for sequence in range(60)
        )
        packet_ids = {str(item.evidence_id) for item in app.packet(str(initial.case_id)).evidence}
        omitted = next(record for record in records if str(record.evidence_id) not in packet_ids)
        repo = InvestigationRepository(store)
        state = repo.load(str(initial.case_id))
        state = repo.save(
            state.model_copy(
                update={
                    "hypotheses": (
                        Hypothesis(
                            hypothesis_id="h_outside_packet",
                            statement="This references evidence outside the compact packet.",
                            status=HypothesisStatus.UNRESOLVED,
                            supporting_evidence_ids=(omitted.evidence_id,),
                        ),
                    )
                }
            ),
            expected_version=state.state_version,
            event="fixture",
            detail="Persist an older hypothesis before bounded retrieval.",
        )

        final = app.run(str(state.case_id))

        assert final.status is InvestigationStatus.COMPLETE
        assert any("outside this bounded evidence packet" in item for item in final.warnings)


def test_completed_investigation_cannot_be_resumed(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "test.db") as store:
        app = investigator(store)
        initial = app.create(objective="network failure", budget_ms=2000)
        final = app.run(str(initial.case_id))
        assert final.status is InvestigationStatus.COMPLETE

        with pytest.raises(ValueError, match="completed investigations are immutable"):
            app.resume(str(initial.case_id))


def test_budget_stop_without_reasoning_does_not_leave_queued_summary(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "test.db") as store:
        app = investigator(store)
        initial = app.create(objective="Why is the game slow?")

        final = app._finish(  # pyright: ignore[reportPrivateUsage]
            initial,
            InvestigationOutcome.BUDGET_EXHAUSTED,
            "The case time or probe budget is exhausted.",
        )

        assert final.status is InvestigationStatus.COMPLETE
        assert final.summary.startswith("No supported diagnosis was reached")
        assert "budget is exhausted" in final.summary


def test_terminal_stop_preserves_existing_reasoned_summary(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "test.db") as store:
        app = investigator(store)
        initial = app.create(objective="Why is the game slow?")
        reasoned = initial.model_copy(
            update={"summary": "Measured clock drop remains unexplained."}
        )

        final = app._finish(  # pyright: ignore[reportPrivateUsage]
            reasoned,
            InvestigationOutcome.BUDGET_EXHAUSTED,
            "The case time or probe budget is exhausted.",
        )

        assert final.summary == "Measured clock drop remains unexplained."


def test_rejected_reasoning_is_not_misreported_as_unconfigured(tmp_path: Path) -> None:
    class FailingReasoner(DeterministicReasoningProvider):
        def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
            del request
            raise TimeoutError("simulated provider timeout")

    with SQLiteStore(tmp_path / "test.db") as store:
        app = investigator(store, reasoning=FailingReasoner())
        initial = app.create(objective="Why is the game slow?", budget_ms=5_000, max_rounds=1)

        final = app.run(str(initial.case_id))

        assert final.reasoning_provider == "reasoning-unavailable"
        assert final.summary.startswith("Reasoning could not complete")
        assert "No reasoning provider is available" not in final.summary


def test_checkpoint_cas_rejects_stale_writer(tmp_path: Path) -> None:
    from systemsense.storage.sqlite_store import StaleCaseStateError

    with SQLiteStore(tmp_path / "test.db") as store:
        app = investigator(store)
        initial = app.create(objective="slow computer", budget_ms=2000)
        repo = InvestigationRepository(store)
        repo.save(initial, expected_version=0, event="one", detail="first writer")
        with pytest.raises(StaleCaseStateError):
            repo.save(initial, expected_version=0, event="two", detail="stale writer")


def test_explicit_error_reference_seeds_reviewed_reference_graph(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    reference = _port_error_reference()
    seen_text: list[str] = []

    def references(text: str, max_items: int = 4) -> tuple[WindowsErrorReference, ...]:
        seen_text.append(text)
        assert max_items == 4
        return (reference,)

    monkeypatch.setattr("systemsense.application.investigator.reference_for_text", references)
    with SQLiteStore(tmp_path / "test.db") as store:
        app = investigator(store)
        app.knowledge = ReferenceKnowledgeGraph.load_default()
        state = app.create(
            objective="Which process hit Win32 error 10048?",
            budget_ms=2000,
        )

        error_references = app.error_references(state)
        packets = app.reference_context(state)

    assert error_references == (reference,)
    assert seen_text == [state.objective, state.objective]
    node_ids = {
        str(node.get("node_id"))
        for packet in packets
        for node in cast(list[dict[str, JsonValue]], packet.get("nodes", []))
    }
    assert "kn_port_conflict" in node_ids


@pytest.mark.parametrize(
    "objective",
    (
        "I can't connect to WiFi",
        "No internet after joining WiFi",
        "My wireless network disconnected",
    ),
)
def test_wifi_objective_routes_to_sourced_conditional_wifi_references(
    tmp_path: Path, objective: str
) -> None:
    with SQLiteStore(tmp_path / "test.db") as store:
        app = investigator(store)
        app.knowledge = ReferenceKnowledgeGraph.load_default()
        state = app.create(objective=objective, budget_ms=2_000)

        packets = app.reference_context(state)

    assert len(packets) == 1
    packet = packets[0]
    relations = cast(list[dict[str, JsonValue]], packet["relations"])
    relation_ids = {str(relation["relation_id"]) for relation in relations}
    assert {"kr_wifi_001", "kr_wifi_002", "kr_wifi_003"} <= relation_ids
    assert all(not relation_id.startswith("kr_cuda_") for relation_id in relation_ids)
    assert any(
        "network.connectivity" in cast(list[str], relation["distinguishing_probe_ids"])
        for relation in relations
    )
    assert "ks_ms_wifi_client" in {
        str(source["source_id"]) for source in cast(list[dict[str, JsonValue]], packet["sources"])
    }


def test_mixed_wifi_and_game_symptoms_retain_both_reference_branches(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "test.db") as store:
        app = investigator(store)
        app.knowledge = ReferenceKnowledgeGraph.load_default()
        state = app.create(
            objective="WiFi disconnects and my game runs at 12 FPS",
            budget_ms=2_000,
        )

        packets = app.reference_context(state)

    assert len(packets) == 1
    relations = cast(list[dict[str, JsonValue]], packets[0]["relations"])
    relation_ids = {str(relation["relation_id"]) for relation in relations}
    assert any(relation_id.startswith("kr_wifi_") for relation_id in relation_ids)
    assert any(relation_id.startswith("kr_game_") for relation_id in relation_ids)
    assert len(relations) <= 6
    assert packets[0]["disclaimer"]


def test_wireless_peripheral_objective_does_not_seed_wifi_reference_graph(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "test.db") as store:
        app = investigator(store)
        app.knowledge = ReferenceKnowledgeGraph.load_default()
        state = app.create(objective="My wireless mouse disconnected", budget_ms=2_000)

        packets = app.reference_context(state)

    assert len(packets) == 1
    relations = cast(list[dict[str, JsonValue]], packets[0]["relations"])
    assert all(not str(relation["relation_id"]).startswith("kr_wifi_") for relation in relations)


def test_wireless_mouse_baseline_chooses_devices_not_network() -> None:
    from systemsense.application.investigator import (
        _baseline_probe_ids,  # pyright: ignore[reportPrivateUsage]
    )

    available = frozenset({"network.connectivity", "devices.snapshot", "core.system"})

    assert _baseline_probe_ids("My wireless mouse disconnected", available) == (
        "devices.snapshot",
        "core.system",
    )
