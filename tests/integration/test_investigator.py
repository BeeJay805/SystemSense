import threading
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
from systemsense.decision.contracts import ProbeCapability, ProviderIdentity
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
from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId, JsonValue, stable_source_id
from systemsense.domain.probes import (
    Privilege,
    ProbeLimits,
    ProbeManifest,
    ProbeSafety,
    SafetyClass,
    SelfWrite,
)
from systemsense.evidence.graph import RelationKind
from systemsense.evidence.retrieval import (
    EvidenceRelationRepository,
    EvidenceRetrievalQuery,
    EvidenceRetriever,
)
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
    Hypothesis,
    HypothesisStatus,
    ReasoningRequest,
    ReasoningResponse,
    ReasoningStatus,
)
from systemsense.reasoning.provider import ReasoningProvider
from systemsense.reasoning.unavailable import UnavailableReasoningProvider
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
        decision=KeywordBaselineDecisionProvider(),
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
