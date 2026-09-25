"""A PDF investigation waits for an observed process choice before target sampling."""

import json
import threading
from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import cast
from uuid import uuid4

import pytest

from systemsense.application.bootstrap import default_investigator
from systemsense.application.case_service import OpenedCase
from systemsense.application.investigation_state import (
    InvestigationOutcome,
    InvestigationState,
    InvestigationStatus,
)
from systemsense.application.investigator import Investigator
from systemsense.application.targets import ProcessTargetRepository, TargetSelectionError
from systemsense.decision.baseline import KeywordBaselineDecisionProvider
from systemsense.decision.candidates import (
    CandidateDecisionGapV1,
    CandidateDecisionRequestV1,
    CandidateDecisionResponseV1,
    CandidateProposalV1,
)
from systemsense.decision.contracts import (
    DecisionRequest,
    DecisionResponse,
    DiagnosticPurpose,
    ProbeProposal,
    ProviderIdentity,
)
from systemsense.decision.frontier_ranker import (
    FrontierRankRequestV1,
    FrontierRankResponseV1,
    MixedFrontierRanker,
)
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
from systemsense.domain.probes import MeasurementNeed, MeasurementWindow
from systemsense.domain.time import utc_now
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.inference.laya_runtime import LayaWorkerPresentation
from systemsense.knowledge.catalog import ReferenceKnowledgeGraph
from systemsense.orchestration.invocations import ObservabilityGap
from systemsense.orchestration.probes import ProbeDefinition, ProbeObservation, ProbeRunner
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.packs.runtime import NoParameters, TargetPressureParametersV1, default_probe_runner
from systemsense.storage.candidate_decision_snapshots import CandidateDecisionSnapshotRepository
from systemsense.storage.candidate_dispatch_admissions import CandidateDispatchAdmissionRepository
from systemsense.storage.case_candidates import (
    CandidateGap,
    CandidateGapReason,
    CandidateResolution,
)
from systemsense.storage.frontier_packet_receipts import FrontierPacketReceiptRepository
from systemsense.storage.search_frontier import FrontierStatus, SearchFrontierRepository
from systemsense.storage.sqlite_store import SQLiteStore


def _application_snapshot(
    store: SQLiteStore,
    case_id: CaseId,
    at: datetime,
    *,
    processes: list[dict[str, JsonValue]] | None = None,
    collector_id: str = "application.snapshot",
) -> None:
    evidence_id = EvidenceId.new()
    execution_id = ExecutionId.new()
    source_id = stable_source_id(
        "systemsense.probe", {"probe_id": collector_id, "probe_version": 1}
    )
    created = at - timedelta(minutes=1)
    facts: dict[str, JsonValue] = {
        "collection_started_at": (at - timedelta(seconds=1)).isoformat(),
        "collection_completed_at": at.isoformat(),
        "collection_status": "available",
        "omitted_counts": {"processes": 0, "services": 0, "startup": 0},
        "processes": cast(JsonValue, processes)
        if processes is not None
        else [
            {
                "pid": 4242,
                "ppid": 1,
                "name": "viewer.exe",
                "creation_time": created.isoformat(),
                "identity": f"4242@{created.isoformat()}",
            }
        ],
    }
    record = EvidenceRecord(
        evidence_id=evidence_id,
        case_id=case_id,
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=at,
        captured_at=at,
        source=EvidenceSource(
            type="systemsense.probe",
            source_id=source_id,
            locator={"probe_id": collector_id},
        ),
        collector=CollectorReference(id=collector_id, version=1, execution_id=execution_id),
        summary="Application topology",
        facts=tuple(EvidenceFact(name=name, value=value) for name, value in facts.items()),
        extraction=Extraction(confidence=1, parser="builtin.probe", parser_version=1),
        sensitivity=Sensitivity.SYSTEM_METADATA,
    )
    with store.transaction() as transaction:
        transaction.record_probe_execution(
            execution_id=str(execution_id),
            case_id=str(case_id),
            probe_id=collector_id,
            probe_version=1,
            status="ok",
            parameters_json="{}",
            started_at=(at - timedelta(seconds=1)).isoformat(),
            finished_at=at.isoformat(),
            state_version=0,
        )
        transaction.insert_evidence(
            case_id=str(case_id),
            evidence_id=str(evidence_id),
            source_id=source_id,
            record_json=record.model_dump_json(),
            observed_at=at.isoformat(),
            captured_at=at.isoformat(),
            execution_id=str(execution_id),
            dedupe_key=f"execution:{execution_id}",
            time_basis="collector_upper_bound",
            time_quality="bounded_interval",
        )


def _precollected_pdf_investigator(
    store: SQLiteStore, *, processes: list[dict[str, JsonValue]] | None = None
) -> tuple[Investigator, CaseId]:
    investigator = default_investigator(store)
    state = investigator.create(objective="This PDF viewer is slow")
    _application_snapshot(store, state.case_id, state.created_at, processes=processes)
    investigator.repository.save(
        state.model_copy(update={"completed_probe_ids": ("application.snapshot",)}),
        expected_version=state.state_version,
        event="precollected",
        detail="fixture snapshot",
    )
    return investigator, state.case_id


def _add_unfocused_stored_evidence(store: SQLiteStore, case_id: CaseId, at: datetime) -> None:
    for _ in range(50):
        _application_snapshot(store, case_id, at, collector_id="fixture.stored")


def test_pdf_run_waits_for_process_selection_and_generic_resume_cannot_bypass(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "pdf-wait.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)

        waiting = investigator.run(str(case_id))

        assert waiting.status is InvestigationStatus.AWAITING_TARGET
        assert waiting.outcome is InvestigationOutcome.AWAITING_TARGET
        assert waiting.completed_probe_ids == ("application.snapshot",)
        assert waiting.assessment is None
        assert not waiting.provider_calls
        with pytest.raises(ValueError, match="target"):
            investigator.resume(str(case_id))
        with pytest.raises(ValueError, match="binding"):
            investigator.resume_after_target(str(case_id))
        inventory = ProcessTargetRepository(store).list_process_candidates(case_id)
        assert len(inventory.candidates) == 1
        ProcessTargetRepository(store).bind_process_target(
            case_id, inventory.candidates[0].candidate_id
        )
        with pytest.raises(ValueError, match="target"):
            investigator.resume(str(case_id))

        queued = investigator.resume_after_target(str(case_id))

        assert queued.status is InvestigationStatus.QUEUED
        assert queued.outcome is InvestigationOutcome.INVESTIGATING
        assert queued.completed_probe_ids == ("application.snapshot",)


class _ChoosingCandidateDecision:
    identity = ProviderIdentity(
        provider_id="fixture-candidate-choice", provider_version="1", role="fast_decision"
    )

    def __init__(self, *, gap: bool = False) -> None:
        self.gap = gap
        self.requests: list[CandidateDecisionRequestV1] = []

    def decide(self, request: DecisionRequest) -> DecisionResponse:
        return KeywordBaselineDecisionProvider().decide(request)

    def decide_candidates(
        self, request: CandidateDecisionRequestV1
    ) -> CandidateDecisionResponseV1 | CandidateDecisionGapV1:
        self.requests.append(request)
        if self.gap:
            return CandidateDecisionGapV1(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                reason_code="ranker_unavailable",
            )
        ids = tuple(item.candidate_id for item in request.available_candidates)
        return CandidateDecisionResponseV1(
            provider=self.identity,
            case_id=request.case_id,
            state_version=request.state_version,
            correlation_id=request.correlation_id,
            deadline_at=request.deadline_at,
            ranked_candidate_ids=tuple(reversed(ids)),
            considered_candidate_ids=ids,
            proposals=(
                CandidateProposalV1(
                    candidate_id=ids[-1],
                    purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
                    priority=1.0,
                ),
            ),
        )


@pytest.mark.parametrize("selected_first", [False, True])
def test_pdf_candidate_brain_routes_second_inventory_process_without_human_binding(
    tmp_path: Path,
    selected_first: bool,
) -> None:
    with SQLiteStore(tmp_path / "pdf-candidate-route.db") as store:
        store.initialize()
        at = utc_now() - timedelta(seconds=2)
        processes: list[dict[str, JsonValue]] = [
            {
                "pid": pid,
                "ppid": 1,
                "name": f"viewer{pid}.exe",
                "creation_time": (at - timedelta(minutes=index + 2)).isoformat(),
                "identity": f"{pid}@{(at - timedelta(minutes=index + 2)).isoformat()}",
            }
            for index, pid in enumerate((4242, 5252))
        ]
        investigator, case_id = _precollected_pdf_investigator(store, processes=processes)
        state = investigator.repository.load(str(case_id))
        investigator.repository.save(
            state.model_copy(update={"max_probes": 2}),
            expected_version=state.state_version,
            event="test_budget",
            detail="one candidate run",
        )
        decision = _ChoosingCandidateDecision()
        investigator.decision = decision
        if selected_first:
            target = ProcessTargetRepository(store)
            first_id = target.list_process_candidates(case_id).candidates[0].candidate_id
            target.bind_process_target(case_id, first_id)
        manifest = default_probe_runner().manifest("application.target_pressure")
        assert manifest is not None
        calls: list[dict[str, JsonValue]] = []

        def observe(parameters: dict[str, JsonValue]) -> ProbeObservation:
            calls.append(parameters)
            stamp = utc_now()
            return ProbeObservation(
                summary="Bounded selected process pressure",
                facts={"pid": parameters["pid"]},
                observed_at=stamp,
                captured_at=stamp,
            )

        investigator.runtime._probe_runner = ProbeRunner(  # pyright: ignore[reportPrivateUsage]
            definitions=(
                ProbeDefinition(
                    manifest=manifest,
                    parameter_model=TargetPressureParametersV1,
                    handler=observe,
                    isolated=False,
                ),
            )
        )

        finished = investigator.run(str(case_id))

        assert len(decision.requests) == (0 if selected_first else 1)
        if not selected_first:
            offered = decision.requests[0].available_candidates
            assert len(offered) == 2
            assert offered[0].probe_id == offered[1].probe_id == "application.target_pressure"
            assert offered[0].candidate_id != offered[1].candidate_id
        assert len(calls) == 1
        assert calls[0]["pid"] == (4242 if selected_first else 5252)
        assert datetime.fromisoformat(str(calls[0]["creation_time"])) == datetime.fromisoformat(
            str(processes[0 if selected_first else 1]["creation_time"])
        )
        assert (
            ProcessTargetRepository(store).selected_process_target(case_id) is not None
        ) is selected_first
        assert finished.status is not InvestigationStatus.AWAITING_TARGET
        assert finished.completed_probe_ids.count("application.target_pressure") == 1
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_decision_execution_links WHERE case_id=?",
            (str(case_id),),
        ).fetchone() == ((0 if selected_first else 1),)


def test_frontier_ranked_process_candidate_uses_existing_dispatch_and_worker_claim(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "frontier-process.db") as store:
        store.initialize()
        at = utc_now() - timedelta(seconds=2)
        processes: list[dict[str, JsonValue]] = [
            {
                "pid": pid,
                "ppid": 1,
                "name": f"viewer{pid}.exe",
                "creation_time": (at - timedelta(minutes=index + 2)).isoformat(),
                "identity": f"{pid}@{(at - timedelta(minutes=index + 2)).isoformat()}",
            }
            for index, pid in enumerate((4242, 5252))
        ]
        investigator, case_id = _precollected_pdf_investigator(store, processes=processes)
        state = investigator.repository.load(str(case_id))
        investigator.repository.save(
            state.model_copy(update={"max_probes": 2}),
            expected_version=state.state_version,
            event="test_budget",
            detail="one frontier candidate run",
        )
        investigator.frontier_ranker = MixedFrontierRanker(
            ranker=None,
            provider=ProviderIdentity(
                provider_id="fixture-frontier", provider_version="1", role="fast_decision"
            ),
            model_weight_sha256="a" * 64,
        )
        investigator.knowledge = ReferenceKnowledgeGraph.load_default()
        manifest = default_probe_runner().manifest("application.target_pressure")
        assert manifest is not None
        calls: list[dict[str, JsonValue]] = []

        def observe(parameters: dict[str, JsonValue]) -> ProbeObservation:
            calls.append(parameters)
            stamp = utc_now()
            return ProbeObservation(
                summary="Bounded selected process pressure",
                facts={"pid": parameters["pid"]},
                observed_at=stamp,
                captured_at=stamp,
            )

        investigator.runtime._probe_runner = ProbeRunner(  # pyright: ignore[reportPrivateUsage]
            definitions=(
                ProbeDefinition(
                    manifest=manifest,
                    parameter_model=TargetPressureParametersV1,
                    handler=observe,
                    isolated=False,
                ),
            )
        )

        finished = investigator.run(str(case_id))

        assert calls and calls[0]["pid"] == 4242
        assert finished.completed_probe_ids.count("application.target_pressure") == 1
        assert any(
            call.role == "fast_decision"
            and call.provider_id == "fixture-frontier"
            and call.degraded
            and call.detail == "frontier_worker_unavailable"
            for call in finished.provider_calls
        )
        rows = store.connection.execute(
            "SELECT s.schema_version,a.admission_id,c.claimed_at,l.execution_id "
            "FROM candidate_decision_snapshots AS s "
            "JOIN candidate_dispatch_admissions AS a ON a.snapshot_id=s.snapshot_id "
            "JOIN candidate_dispatch_claims AS c ON c.admission_id=a.admission_id "
            "JOIN candidate_decision_execution_links AS l ON l.snapshot_id=s.snapshot_id "
            "WHERE s.case_id=?",
            (str(case_id),),
        ).fetchall()
        assert len(rows) == 1
        assert rows[0][0] == 2
        frozen = store.connection.execute(
            "SELECT s.snapshot_id,s.request_json,b.receipt_id "
            "FROM candidate_decision_snapshots AS s "
            "LEFT JOIN frontier_packet_snapshot_bindings AS b ON b.snapshot_id=s.snapshot_id "
            "WHERE s.case_id=? AND s.schema_version=2",
            (str(case_id),),
        ).fetchone()
        assert frozen is not None
        assert frozen[2] is not None
        assert FrontierPacketReceiptRepository(store).readback(str(frozen[2])).packets
        assert '"evidence_packets":[]' not in str(frozen[1])
        selected_item_id = store.connection.execute(
            "SELECT correlation_id FROM candidate_decision_snapshots "
            "WHERE case_id=? AND schema_version=2",
            (str(case_id),),
        ).fetchone()
        assert selected_item_id is not None
        assert (
            SearchFrontierRepository(store).readback(str(selected_item_id[0])).status
            is FrontierStatus.SATISFIED
        )
        original_snapshot = store.connection.execute(
            "SELECT * FROM candidate_decision_snapshots WHERE snapshot_id=?", (str(frozen[0]),)
        ).fetchone()
        assert original_snapshot is not None
        other_case_id = CaseId.new()
        store.create_case(
            case_id=str(other_case_id),
            kind="general",
            symptom="unrelated case",
            created_at=utc_now().isoformat(),
        )
        receipts = FrontierPacketReceiptRepository(store)
        for owner, expected_error in (
            (other_case_id, ValueError),
            (case_id, ValueError),
        ):
            clone = list(original_snapshot)
            clone[0] = f"frontier_decision_snapshot_{uuid4().hex}"
            clone[3] = str(owner)
            store.connection.execute(
                "INSERT INTO candidate_decision_snapshots VALUES ("
                + ",".join("?" for _ in clone)
                + ")",
                clone,
            )
            with store.transaction(), pytest.raises(expected_error):
                receipts.bind_snapshot(str(frozen[2]), str(clone[0]))


def test_frontier_linked_failed_probe_is_not_satisfied(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "frontier-failed-probe.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        investigator.frontier_ranker = MixedFrontierRanker(
            ranker=None,
            provider=ProviderIdentity(
                provider_id="fixture-frontier", provider_version="1", role="fast_decision"
            ),
            model_weight_sha256="a" * 64,
        )
        investigator.knowledge = ReferenceKnowledgeGraph.load_default()
        manifest = default_probe_runner().manifest("application.target_pressure")
        assert manifest is not None

        def fail(_parameters: dict[str, JsonValue]) -> ProbeObservation:
            raise RuntimeError("read-only collector unavailable")

        investigator.runtime._probe_runner = ProbeRunner(  # pyright: ignore[reportPrivateUsage]
            definitions=(
                ProbeDefinition(
                    manifest=manifest,
                    parameter_model=TargetPressureParametersV1,
                    handler=fail,
                    isolated=False,
                ),
            )
        )

        finished = investigator.run(str(case_id))

        assert "application.target_pressure" in finished.interrupted_probe_ids
        assert store.connection.execute(
            "SELECT p.status FROM probe_executions AS p "
            "JOIN candidate_decision_execution_links AS l ON l.execution_id=p.execution_id "
            "WHERE l.case_id=?",
            (str(case_id),),
        ).fetchone() == ("failed",)
        selected_item_id = store.connection.execute(
            "SELECT correlation_id FROM candidate_decision_snapshots "
            "WHERE case_id=? AND schema_version=2",
            (str(case_id),),
        ).fetchone()
        assert selected_item_id is not None
        assert (
            SearchFrontierRepository(store).readback(str(selected_item_id[0])).status
            is FrontierStatus.FAILED
        )


def test_frontier_post_dispatch_failure_is_uncertain_and_never_falls_back(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "frontier-post-dispatch.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        investigator.frontier_ranker = MixedFrontierRanker(
            ranker=None,
            provider=ProviderIdentity(
                provider_id="fixture-frontier", provider_version="1", role="fast_decision"
            ),
            model_weight_sha256="a" * 64,
        )
        investigator.knowledge = ReferenceKnowledgeGraph.load_default()
        manifest = default_probe_runner().manifest("application.target_pressure")
        assert manifest is not None
        calls: list[dict[str, JsonValue]] = []

        def observe(parameters: dict[str, JsonValue]) -> ProbeObservation:
            calls.append(parameters)
            stamp = utc_now()
            return ProbeObservation(
                summary="Bounded selected process pressure",
                facts={"pid": parameters["pid"]},
                observed_at=stamp,
                captured_at=stamp,
            )

        investigator.runtime._probe_runner = ProbeRunner(  # pyright: ignore[reportPrivateUsage]
            definitions=(
                ProbeDefinition(
                    manifest=manifest,
                    parameter_model=TargetPressureParametersV1,
                    handler=observe,
                    isolated=False,
                ),
            )
        )
        original = investigator.runtime.execute_candidate_measurement

        def fail_after_execution(*args: object, **kwargs: object) -> None:
            original(*args, **kwargs)  # type: ignore[arg-type]
            raise RuntimeError("injected after dispatch")

        investigator.runtime.execute_candidate_measurement = fail_after_execution  # type: ignore[method-assign]

        finished = investigator.run(str(case_id))

        assert len(calls) == 1
        assert "application.target_pressure" in finished.interrupted_probe_ids
        assert any("outcome is uncertain" in warning for warning in finished.warnings)
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_dispatch_admissions WHERE case_id=?",
            (str(case_id),),
        ).fetchone() == (1,)


def test_process_frontier_catalog_rejects_window_without_issuing_candidate(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "frontier-window-gap.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        state = investigator.repository.load(str(case_id))
        state = investigator._save(  # pyright: ignore[reportPrivateUsage]
            state.model_copy(update={"status": InvestigationStatus.RUNNING}),
            "test_running",
            "fixture enters collection epoch",
        )
        registry, needs = investigator.runtime.candidate_catalog(case_id)
        assert len(needs) == 1
        windowed = needs[0].model_copy(
            update={
                "window": MeasurementWindow(
                    start=utc_now() - timedelta(minutes=2),
                    end=utc_now() - timedelta(minutes=1),
                )
            }
        )
        result = registry.issue(case_id, state.state_version, windowed)
        assert isinstance(result, CandidateGap)
        assert result.reason is CandidateGapReason.WINDOW_INELIGIBLE
        assert registry.readback(case_id, state.state_version) == ()


def test_frontier_cancellation_after_rank_prevents_candidate_admission(tmp_path: Path) -> None:
    cancellation = threading.Event()

    class CancellingRanker(MixedFrontierRanker):
        def rank(
            self,
            request: FrontierRankRequestV1,
            *,
            capture_worker_batch: Callable[
                [str, int, dict[str, object], LayaWorkerPresentation], None
            ]
            | None = None,
        ) -> FrontierRankResponseV1:
            response = super().rank(request, capture_worker_batch=capture_worker_batch)
            cancellation.set()
            return response

    with SQLiteStore(tmp_path / "frontier-cancel.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        investigator.frontier_ranker = CancellingRanker(
            ranker=None,
            provider=ProviderIdentity(
                provider_id="fixture-frontier", provider_version="1", role="fast_decision"
            ),
            model_weight_sha256="a" * 64,
        )
        investigator.knowledge = ReferenceKnowledgeGraph.load_default()

        finished = investigator.run(str(case_id), cancel_event=cancellation)

        assert cancellation.is_set()
        assert "application.target_pressure" not in finished.completed_probe_ids
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_dispatch_admissions WHERE case_id=?",
            (str(case_id),),
        ).fetchone() == (0,)


def test_frontier_packet_receipt_freezes_exact_current_case_source_before_rank(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "frontier-packet-receipt.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        state = investigator.repository.load(str(case_id))
        source_id = investigator.context(str(case_id))[0].evidence_id
        generation = store.connection.execute(
            "SELECT generation FROM evidence_case_generations WHERE case_id=?", (str(case_id),)
        ).fetchone()[0]

        receipt = FrontierPacketReceiptRepository(store).freeze(
            case_id=case_id,
            epoch_state_version=state.state_version,
            evidence_ids=(source_id,),
            expected_generation=int(generation),
        )

        assert receipt.packets
        assert all(item.evidence_id == str(source_id) for item in receipt.packets)
        bounded = json.loads(receipt.packets[0].description)
        assert "bounded_interval" in bounded["limitations"][0]
        assert "collector_upper_bound" in bounded["limitations"][0]
        assert FrontierPacketReceiptRepository(store).readback(receipt.receipt_id) == receipt
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_decision_snapshots WHERE case_id=?",
            (str(case_id),),
        ).fetchone() == (0,)


def test_pdf_frontier_ranks_stored_retrieval_against_registry_measurement(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "mixed-pdf-retrieval.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        state = investigator.repository.load(str(case_id))
        _add_unfocused_stored_evidence(store, case_id, state.created_at)
        state = investigator._save(  # pyright: ignore[reportPrivateUsage]
            state.model_copy(update={"status": InvestigationStatus.RUNNING, "max_probes": 64}),
            "test_running",
            "fixture enters collection epoch",
        )

        class CapturingRanker(MixedFrontierRanker):
            request: FrontierRankRequestV1 | None = None

            def rank(
                self,
                request: FrontierRankRequestV1,
                *,
                capture_worker_batch: Callable[
                    [str, int, dict[str, object], LayaWorkerPresentation], None
                ]
                | None = None,
            ) -> FrontierRankResponseV1:
                self.request = request
                response = super().rank(request, capture_worker_batch=capture_worker_batch)
                ordered = tuple(
                    item.item_id
                    for item in request.items
                    if item.reference.kind == "retrieve_evidence"
                ) + tuple(
                    item.item_id for item in request.items if item.reference.kind == "measure"
                )
                return response.model_copy(
                    update={
                        "ranked_item_ids": ordered,
                        "considered_item_ids": tuple(item.item_id for item in request.items),
                        "ranking_source": "laya",
                        "model_abstained": False,
                        "coverage_complete": True,
                        "degraded_reason": None,
                    }
                )

        ranker = CapturingRanker(
            ranker=None,
            provider=ProviderIdentity(
                provider_id="fixture-frontier", provider_version="1", role="fast_decision"
            ),
            model_weight_sha256="a" * 64,
        )
        investigator.frontier_ranker = ranker
        investigator.knowledge = ReferenceKnowledgeGraph.load_default()
        result, routed = investigator._route_frontier_pdf_candidate(  # pyright: ignore[reportPrivateUsage]
            state, None
        )

        assert ranker.request is not None, (result.warnings, routed)
        assert routed
        assert {item.reference.kind for item in ranker.request.items} == {
            "retrieve_evidence",
            "measure",
        }
        selected = result.fast_catalog_selected_ids
        assert selected
        assert str(selected[0]) in {
            str(item.evidence_id) for item in investigator.context(str(case_id), state=result)
        }
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_dispatch_admissions WHERE case_id=?", (str(case_id),)
        ).fetchone() == (0,)


def test_pdf_mixed_measurement_keeps_receipt_and_rejects_mutated_source(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "mixed-pdf-measure.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        state = investigator.repository.load(str(case_id))
        _add_unfocused_stored_evidence(store, case_id, state.created_at)
        state = investigator._save(  # pyright: ignore[reportPrivateUsage]
            state.model_copy(update={"status": InvestigationStatus.RUNNING, "max_probes": 64}),
            "test_running",
            "fixture enters collection epoch",
        )

        class MeasurementRanker(MixedFrontierRanker):
            def rank(
                self,
                request: FrontierRankRequestV1,
                *,
                capture_worker_batch: Callable[
                    [str, int, dict[str, object], LayaWorkerPresentation], None
                ]
                | None = None,
            ) -> FrontierRankResponseV1:
                response = super().rank(request, capture_worker_batch=capture_worker_batch)
                assert {item.reference.kind for item in request.items} == {
                    "retrieve_evidence",
                    "measure",
                }
                ordered = tuple(
                    item.item_id for item in request.items if item.reference.kind == "measure"
                ) + tuple(
                    item.item_id for item in request.items if item.reference.kind != "measure"
                )
                return response.model_copy(
                    update={
                        "ranked_item_ids": ordered,
                        "considered_item_ids": tuple(item.item_id for item in request.items),
                        "ranking_source": "laya",
                        "model_abstained": False,
                        "coverage_complete": True,
                        "degraded_reason": None,
                    }
                )

        investigator.frontier_ranker = MeasurementRanker(
            ranker=None,
            provider=ProviderIdentity(
                provider_id="fixture-frontier", provider_version="1", role="fast_decision"
            ),
            model_weight_sha256="a" * 64,
        )
        investigator.knowledge = ReferenceKnowledgeGraph.load_default()
        result, routed = investigator._route_frontier_pdf_candidate(  # pyright: ignore[reportPrivateUsage]
            state, None
        )

        assert routed
        assert "application.target_pressure" in result.completed_probe_ids, result.warnings
        row = store.connection.execute(
            "SELECT s.snapshot_id,s.request_json,b.receipt_id "
            "FROM candidate_decision_snapshots AS s "
            "JOIN frontier_packet_snapshot_bindings AS b ON b.snapshot_id=s.snapshot_id "
            "WHERE s.case_id=? AND s.schema_version=2",
            (str(case_id),),
        ).fetchone()
        assert row is not None
        snapshot = CandidateDecisionSnapshotRepository(store).readback_frontier(str(row[0]))
        assert {item.reference.kind for item in snapshot.request.items} == {
            "retrieve_evidence",
            "measure",
        }
        assert (
            snapshot.request.evidence_packets
            == FrontierPacketReceiptRepository(store).readback(str(row[2])).packets
        )
        source_id = snapshot.request.evidence_packets[0].evidence_id
        source = store.evidence(case_id=str(case_id), evidence_id=source_id)
        assert source is not None
        record = EvidenceRecord.model_validate_json(source.record_json)
        store.connection.execute(
            "UPDATE evidence SET record_json=? WHERE evidence_id=?",
            (
                record.model_copy(update={"summary": "altered after dispatch"}).model_dump_json(),
                source_id,
            ),
        )
        with pytest.raises(ValueError):
            CandidateDecisionSnapshotRepository(store).readback_frontier(str(row[0]))


def test_pdf_mixed_retrieval_is_delivered_with_eight_requested_ids_before_target(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "mixed-pdf-priority.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        state = investigator.repository.load(str(case_id))
        _add_unfocused_stored_evidence(store, case_id, state.created_at)
        requested_ids = tuple(item.evidence_id for item in investigator.context(str(case_id)))[:8]
        assert len(requested_ids) == 8
        investigator.repository.save(
            state.model_copy(
                update={
                    "max_probes": 64,
                    "requested_evidence_ids": requested_ids,
                }
            ),
            expected_version=state.state_version,
            event="test_priority_slots",
            detail="eight existing evidence requests occupy priority slots",
        )

        class RetrievalRanker(MixedFrontierRanker):
            selected_item_id: str | None = None
            selected_evidence_id: EvidenceId | None = None

            def rank(
                self,
                request: FrontierRankRequestV1,
                *,
                capture_worker_batch: Callable[
                    [str, int, dict[str, object], LayaWorkerPresentation], None
                ]
                | None = None,
            ) -> FrontierRankResponseV1:
                response = super().rank(request, capture_worker_batch=capture_worker_batch)
                retrieval = next(
                    item for item in request.items if item.reference.kind == "retrieve_evidence"
                )
                self.selected_item_id = retrieval.item_id
                self.selected_evidence_id = retrieval.reference.evidence_id
                ordered = (
                    retrieval.item_id,
                    *(item.item_id for item in request.items if item.item_id != retrieval.item_id),
                )
                return response.model_copy(
                    update={
                        "ranked_item_ids": ordered,
                        "considered_item_ids": tuple(item.item_id for item in request.items),
                        "ranking_source": "laya",
                        "model_abstained": False,
                        "coverage_complete": True,
                        "degraded_reason": None,
                    }
                )

        ranker = RetrievalRanker(
            ranker=None,
            provider=ProviderIdentity(
                provider_id="fixture-frontier", provider_version="1", role="fast_decision"
            ),
            model_weight_sha256="a" * 64,
        )
        investigator.frontier_ranker = ranker
        investigator.knowledge = ReferenceKnowledgeGraph.load_default()

        waiting = investigator.run(str(case_id))

        assert waiting.status is InvestigationStatus.AWAITING_TARGET
        assert ranker.selected_item_id is not None
        assert ranker.selected_evidence_id is not None
        assert (
            SearchFrontierRepository(store).readback(ranker.selected_item_id).status
            is FrontierStatus.SATISFIED
        )
        assert ranker.selected_evidence_id in waiting.fast_catalog_selected_ids
        assert str(ranker.selected_evidence_id) in {
            str(item.evidence_id) for item in investigator.context(str(case_id), state=waiting)
        }
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_dispatch_admissions WHERE case_id=?", (str(case_id),)
        ).fetchone() == (0,)


def test_pdf_packet_keeps_deep_request_when_eight_fast_selections_fill_priority(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "pdf-priority-fairness.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        state = investigator.repository.load(str(case_id))
        _add_unfocused_stored_evidence(store, case_id, state.created_at)
        base = investigator.packet(str(case_id), state=state)
        fast_ids = tuple(item.evidence_id for item in base.evidence[:8])
        assert len(fast_ids) == 8
        visible_ids = {str(item.evidence_id) for item in base.evidence}
        stored_ids = store.connection.execute(
            "SELECT evidence_id FROM evidence WHERE case_id=?", (str(case_id),)
        ).fetchall()
        deep_id = next(
            EvidenceId(root=str(row[0])) for row in stored_ids if str(row[0]) not in visible_ids
        )
        requested = state.model_copy(
            update={
                "fast_catalog_selected_ids": fast_ids,
                "requested_evidence_ids": (deep_id,),
            }
        )

        delivered_ids = {
            str(item.evidence_id)
            for item in investigator.packet(str(case_id), state=requested).evidence
        }

        assert str(fast_ids[0]) in delivered_ids
        assert str(deep_id) in delivered_ids


def test_pdf_mixed_retrieval_delivery_failure_does_not_satisfy_frontier(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "mixed-pdf-delivery-failure.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        state = investigator.repository.load(str(case_id))
        _add_unfocused_stored_evidence(store, case_id, state.created_at)
        state = investigator._save(  # pyright: ignore[reportPrivateUsage]
            state.model_copy(update={"status": InvestigationStatus.RUNNING, "max_probes": 64}),
            "test_running",
            "fixture enters collection epoch",
        )

        class RetrievalRanker(MixedFrontierRanker):
            selected_item_id: str | None = None

            def rank(
                self,
                request: FrontierRankRequestV1,
                *,
                capture_worker_batch: Callable[
                    [str, int, dict[str, object], LayaWorkerPresentation], None
                ]
                | None = None,
            ) -> FrontierRankResponseV1:
                response = super().rank(request, capture_worker_batch=capture_worker_batch)
                retrieval = next(
                    item for item in request.items if item.reference.kind == "retrieve_evidence"
                )
                self.selected_item_id = retrieval.item_id
                return response.model_copy(
                    update={
                        "ranked_item_ids": (
                            retrieval.item_id,
                            *(
                                item.item_id
                                for item in request.items
                                if item.item_id != retrieval.item_id
                            ),
                        ),
                        "considered_item_ids": tuple(item.item_id for item in request.items),
                        "ranking_source": "laya",
                        "model_abstained": False,
                        "coverage_complete": True,
                        "degraded_reason": None,
                    }
                )

        ranker = RetrievalRanker(
            ranker=None,
            provider=ProviderIdentity(
                provider_id="fixture-frontier", provider_version="1", role="fast_decision"
            ),
            model_weight_sha256="a" * 64,
        )
        investigator.frontier_ranker = ranker
        investigator.knowledge = ReferenceKnowledgeGraph.load_default()
        original_context = investigator.context

        def omit_selected(
            case: str, *, state: InvestigationState | None = None
        ) -> tuple[EvidenceContext, ...]:
            context = original_context(case, state=state)
            if state is not None and state.fast_catalog_selected_ids:
                return tuple(
                    item
                    for item in context
                    if item.evidence_id not in state.fast_catalog_selected_ids
                )
            return context

        monkeypatch.setattr(investigator, "context", omit_selected)
        result, routed = investigator._route_frontier_pdf_candidate(  # pyright: ignore[reportPrivateUsage]
            state, None
        )

        assert routed
        assert ranker.selected_item_id is not None
        assert (
            SearchFrontierRepository(store).readback(ranker.selected_item_id).status
            is FrontierStatus.OBSOLETE
        )
        assert not result.fast_catalog_selected_ids
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_dispatch_admissions WHERE case_id=?", (str(case_id),)
        ).fetchone() == (0,)


def test_frontier_packet_unknown_source_time_does_not_claim_incident_relevance(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "frontier-packet-unknown-time.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        state = investigator.repository.load(str(case_id))
        source_id = investigator.context(str(case_id))[0].evidence_id
        store.connection.execute(
            "UPDATE evidence SET time_quality='unknown', time_basis='legacy_capture' "
            "WHERE evidence_id=?",
            (str(source_id),),
        )
        generation = store.connection.execute(
            "SELECT generation FROM evidence_case_generations WHERE case_id=?", (str(case_id),)
        ).fetchone()[0]

        receipt = FrontierPacketReceiptRepository(store).freeze(
            case_id=case_id,
            epoch_state_version=state.state_version,
            evidence_ids=(source_id,),
            expected_generation=int(generation),
        )

        packet = json.loads(receipt.packets[0].description)
        assert packet["incident_relevant"] is None
        assert "unknown" in packet["limitations"][0]
        assert "legacy_capture" in packet["limitations"][0]


def test_frontier_packet_receipt_projects_typed_denied_coverage(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "frontier-packet-coverage.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        state = investigator.repository.load(str(case_id))
        evidence_id = EvidenceId.new()
        stamp = utc_now()
        coverage = CoverageRecord(
            evidence_id=evidence_id,
            case_id=case_id,
            category="fixture.coverage",
            status=CoverageStatus.DENIED,
            captured_at=stamp,
            reason="Read-only source denied access",
        )
        with store.transaction() as transaction:
            transaction.insert_evidence(
                case_id=str(case_id),
                evidence_id=str(evidence_id),
                source_id=stable_source_id("test.coverage", {"id": str(evidence_id)}),
                record_json=coverage.model_dump_json(),
                observed_at=stamp.isoformat(),
                captured_at=stamp.isoformat(),
                execution_id=None,
                dedupe_key=str(evidence_id),
                time_basis="probe_attempt_finish",
                time_quality="exact",
            )
        generation = store.connection.execute(
            "SELECT generation FROM evidence_case_generations WHERE case_id=?", (str(case_id),)
        ).fetchone()[0]

        receipt = FrontierPacketReceiptRepository(store).freeze(
            case_id=case_id,
            epoch_state_version=state.state_version,
            evidence_ids=(evidence_id,),
            expected_generation=int(generation),
        )

        packet = json.loads(receipt.packets[0].description)
        assert packet["packet_kind"] == "status"
        assert packet["status"] == "denied"
        assert receipt.sources[0].scope == "current_case"


def test_frontier_packet_receipt_rejects_missing_and_foreign_source_ids(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "frontier-packet-foreign.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        other, other_case_id = _precollected_pdf_investigator(store)
        state = investigator.repository.load(str(case_id))
        generation = store.connection.execute(
            "SELECT generation FROM evidence_case_generations WHERE case_id=?", (str(case_id),)
        ).fetchone()[0]
        receipts = FrontierPacketReceiptRepository(store)
        for source_id in (
            EvidenceId(root="ev_" + "f" * 32),
            other.context(str(other_case_id))[0].evidence_id,
        ):
            with pytest.raises(ValueError, match=r"missing|outside authorized"):
                receipts.freeze(
                    case_id=case_id,
                    epoch_state_version=state.state_version,
                    evidence_ids=(source_id,),
                    expected_generation=int(generation),
                )


def test_frontier_packet_receipt_detects_changed_source_but_not_unrelated_append(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "frontier-packet-change.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        state = investigator.repository.load(str(case_id))
        source_id = investigator.context(str(case_id))[0].evidence_id
        generation = store.connection.execute(
            "SELECT generation FROM evidence_case_generations WHERE case_id=?", (str(case_id),)
        ).fetchone()[0]
        receipts = FrontierPacketReceiptRepository(store)
        receipt = receipts.freeze(
            case_id=case_id,
            epoch_state_version=state.state_version,
            evidence_ids=(source_id,),
            expected_generation=int(generation),
        )
        _application_snapshot(store, case_id, utc_now())
        assert receipts.readback(receipt.receipt_id) == receipt
        with pytest.raises(ValueError, match="generation changed before freeze"):
            receipts.freeze(
                case_id=case_id,
                epoch_state_version=state.state_version,
                evidence_ids=(source_id,),
                expected_generation=int(generation),
            )
        row = store.connection.execute(
            "SELECT record_json FROM evidence WHERE evidence_id=?", (str(source_id),)
        ).fetchone()
        assert row is not None
        changed = EvidenceRecord.model_validate_json(str(row[0])).model_copy(
            update={"summary": "Altered source fact"}
        )
        store.connection.execute(
            "UPDATE evidence SET record_json=? WHERE evidence_id=?",
            (changed.model_dump_json(), str(source_id)),
        )
        with pytest.raises(ValueError, match="source projection changed"):
            receipts.readback(receipt.receipt_id)


def test_frontier_packet_receipt_preserves_explicit_passive_history_scope(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "frontier-packet-history.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        historical_id = CaseId.new()
        store.create_case(
            case_id=str(historical_id),
            kind="passive",
            symptom="historical telemetry",
            created_at=(utc_now() - timedelta(days=2)).isoformat(),
            status="ready",
        )
        _application_snapshot(store, historical_id, utc_now() - timedelta(days=1))
        historical_source = EvidenceId(
            root=str(
                store.connection.execute(
                    "SELECT evidence_id FROM evidence WHERE case_id=?", (str(historical_id),)
                ).fetchone()[0]
            )
        )
        state = investigator.repository.load(str(case_id))
        state = investigator.repository.save(
            state.model_copy(update={"historical_case_ids": (historical_id,)}),
            expected_version=state.state_version,
            event="history_opt_in",
            detail="explicit passive history",
        )
        generation = store.connection.execute(
            "SELECT generation FROM evidence_case_generations WHERE case_id=?", (str(case_id),)
        ).fetchone()[0]
        receipt = FrontierPacketReceiptRepository(store).freeze(
            case_id=case_id,
            epoch_state_version=state.state_version,
            evidence_ids=(historical_source,),
            expected_generation=int(generation),
        )

        assert receipt.sources[0].scope == "historical"
        assert receipt.sources[0].owner_case_id == historical_id
        assert receipt.source_projection == "frontier_typed_row_context_v1_p24"
        assert receipt.redactor_version == "systemsense_redactor_v1"
        assert receipt.max_packets == 24
        assert all('"case_scope":"historical"' in item.description for item in receipt.packets)


def test_frontier_source_change_during_rank_cannot_capture_or_admit(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "frontier-rank-source-race.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        source_id = investigator.context(str(case_id))[0].evidence_id

        class MutatingRanker(MixedFrontierRanker):
            def rank(
                self,
                request: FrontierRankRequestV1,
                *,
                capture_worker_batch: Callable[
                    [str, int, dict[str, object], LayaWorkerPresentation], None
                ]
                | None = None,
            ) -> FrontierRankResponseV1:
                response = super().rank(request, capture_worker_batch=capture_worker_batch)
                row = store.connection.execute(
                    "SELECT record_json FROM evidence WHERE evidence_id=?", (str(source_id),)
                ).fetchone()
                assert row is not None
                changed = EvidenceRecord.model_validate_json(str(row[0])).model_copy(
                    update={"summary": "Changed after model saw the old packet"}
                )
                store.connection.execute(
                    "UPDATE evidence SET record_json=? WHERE evidence_id=?",
                    (changed.model_dump_json(), str(source_id)),
                )
                return response

        investigator.frontier_ranker = MutatingRanker(
            ranker=None,
            provider=ProviderIdentity(
                provider_id="fixture-frontier", provider_version="1", role="fast_decision"
            ),
            model_weight_sha256="a" * 64,
        )
        investigator.knowledge = ReferenceKnowledgeGraph.load_default()

        finished = investigator.run(str(case_id))

        assert "application.target_pressure" not in finished.completed_probe_ids
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_dispatch_admissions WHERE case_id=?",
            (str(case_id),),
        ).fetchone() == (0,)
        assert store.connection.execute(
            "SELECT COUNT(*) FROM frontier_packet_receipts WHERE case_id=?", (str(case_id),)
        ).fetchone() == (1,)


def test_frontier_admission_rechecks_packet_source_before_host_sampling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "frontier-admission-source-race.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        source_id = investigator.context(str(case_id))[0].evidence_id
        investigator.frontier_ranker = MixedFrontierRanker(
            ranker=None,
            provider=ProviderIdentity(
                provider_id="fixture-frontier", provider_version="1", role="fast_decision"
            ),
            model_weight_sha256="a" * 64,
        )
        investigator.knowledge = ReferenceKnowledgeGraph.load_default()
        manifest = default_probe_runner().manifest("application.target_pressure")
        assert manifest is not None
        calls: list[dict[str, JsonValue]] = []

        def observe(parameters: dict[str, JsonValue]) -> ProbeObservation:
            calls.append(parameters)
            stamp = utc_now()
            return ProbeObservation(
                summary="Should not run", facts={}, observed_at=stamp, captured_at=stamp
            )

        investigator.runtime._probe_runner = ProbeRunner(  # pyright: ignore[reportPrivateUsage]
            definitions=(
                ProbeDefinition(
                    manifest=manifest,
                    parameter_model=TargetPressureParametersV1,
                    handler=observe,
                    isolated=False,
                ),
            )
        )
        original_admit = CandidateDispatchAdmissionRepository.admit

        def changed_before_admit(
            repository: CandidateDispatchAdmissionRepository, **kwargs: object
        ) -> object:
            row = store.connection.execute(
                "SELECT record_json FROM evidence WHERE evidence_id=?", (str(source_id),)
            ).fetchone()
            assert row is not None
            changed = EvidenceRecord.model_validate_json(str(row[0])).model_copy(
                update={"summary": "Changed before admission"}
            )
            store.connection.execute(
                "UPDATE evidence SET record_json=? WHERE evidence_id=?",
                (changed.model_dump_json(), str(source_id)),
            )
            return original_admit(repository, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(CandidateDispatchAdmissionRepository, "admit", changed_before_admit)
        finished = investigator.run(str(case_id))

        assert not calls
        assert "application.target_pressure" not in finished.completed_probe_ids
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_dispatch_admissions WHERE case_id=?",
            (str(case_id),),
        ).fetchone() == (0,)


def test_frontier_worker_claim_rechecks_packet_source_before_host_sampling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "frontier-claim-source-race.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        source_id = investigator.context(str(case_id))[0].evidence_id
        investigator.frontier_ranker = MixedFrontierRanker(
            ranker=None,
            provider=ProviderIdentity(
                provider_id="fixture-frontier", provider_version="1", role="fast_decision"
            ),
            model_weight_sha256="a" * 64,
        )
        investigator.knowledge = ReferenceKnowledgeGraph.load_default()
        manifest = default_probe_runner().manifest("application.target_pressure")
        assert manifest is not None
        calls: list[dict[str, JsonValue]] = []

        def observe(parameters: dict[str, JsonValue]) -> ProbeObservation:
            calls.append(parameters)
            stamp = utc_now()
            return ProbeObservation(
                summary="Should not run", facts={}, observed_at=stamp, captured_at=stamp
            )

        investigator.runtime._probe_runner = ProbeRunner(  # pyright: ignore[reportPrivateUsage]
            definitions=(
                ProbeDefinition(
                    manifest=manifest,
                    parameter_model=TargetPressureParametersV1,
                    handler=observe,
                    isolated=False,
                ),
            )
        )
        original_claim = CandidateDispatchAdmissionRepository.claim_for_worker

        def changed_before_claim(
            repository: CandidateDispatchAdmissionRepository, *args: object, **kwargs: object
        ) -> object:
            worker_store = repository._store  # pyright: ignore[reportPrivateUsage]
            row = worker_store.connection.execute(
                "SELECT record_json FROM evidence WHERE evidence_id=?", (str(source_id),)
            ).fetchone()
            assert row is not None
            changed = EvidenceRecord.model_validate_json(str(row[0])).model_copy(
                update={"summary": "Changed before worker claim"}
            )
            worker_store.connection.execute(
                "UPDATE evidence SET record_json=? WHERE evidence_id=?",
                (changed.model_dump_json(), str(source_id)),
            )
            return original_claim(repository, *args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(
            CandidateDispatchAdmissionRepository, "claim_for_worker", changed_before_claim
        )
        investigator.run(str(case_id))

        assert not calls
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_dispatch_admissions WHERE case_id=?",
            (str(case_id),),
        ).fetchone() == (1,)
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_dispatch_claims WHERE case_id=?",
            (str(case_id),),
        ).fetchone() == (0,)


def test_frontier_unrelated_evidence_append_keeps_unchanged_packet_receipt_valid(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "frontier-unrelated-append.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)

        class AppendingRanker(MixedFrontierRanker):
            def rank(
                self,
                request: FrontierRankRequestV1,
                *,
                capture_worker_batch: Callable[
                    [str, int, dict[str, object], LayaWorkerPresentation], None
                ]
                | None = None,
            ) -> FrontierRankResponseV1:
                response = super().rank(request, capture_worker_batch=capture_worker_batch)
                observed_at = utc_now()
                evidence_id = EvidenceId.new()
                execution_id = ExecutionId.new()
                source_id = stable_source_id(
                    "test.unrelated", {"case_id": str(case_id), "id": str(evidence_id)}
                )
                record = EvidenceRecord(
                    evidence_id=evidence_id,
                    case_id=case_id,
                    statement_kind=StatementKind.OBSERVED_FACT,
                    observed_at=observed_at,
                    captured_at=observed_at,
                    source=EvidenceSource(type="test.unrelated", source_id=source_id, locator={}),
                    collector=CollectorReference(
                        id="fixture.unrelated", version=1, execution_id=execution_id
                    ),
                    summary="Unrelated read-only fixture observation",
                    facts=(EvidenceFact(name="fixture.count", value=1),),
                    extraction=Extraction(confidence=1, parser="test.fixture", parser_version=1),
                    sensitivity=Sensitivity.SYSTEM_METADATA,
                )
                with store.transaction() as transaction:
                    transaction.record_probe_execution(
                        execution_id=str(execution_id),
                        case_id=str(case_id),
                        probe_id="fixture.unrelated",
                        probe_version=1,
                        status="ok",
                        parameters_json="{}",
                        started_at=observed_at.isoformat(),
                        finished_at=observed_at.isoformat(),
                        state_version=0,
                    )
                    transaction.insert_evidence(
                        case_id=str(case_id),
                        evidence_id=str(evidence_id),
                        source_id=source_id,
                        record_json=record.model_dump_json(),
                        observed_at=observed_at.isoformat(),
                        captured_at=observed_at.isoformat(),
                        execution_id=str(execution_id),
                        dedupe_key=f"execution:{execution_id}",
                        time_basis="source_observed",
                        time_quality="exact",
                    )
                return response

        investigator.frontier_ranker = AppendingRanker(
            ranker=None,
            provider=ProviderIdentity(
                provider_id="fixture-frontier", provider_version="1", role="fast_decision"
            ),
            model_weight_sha256="a" * 64,
        )
        investigator.knowledge = ReferenceKnowledgeGraph.load_default()
        manifest = default_probe_runner().manifest("application.target_pressure")
        assert manifest is not None
        calls: list[dict[str, JsonValue]] = []

        def observe(parameters: dict[str, JsonValue]) -> ProbeObservation:
            calls.append(parameters)
            stamp = utc_now()
            return ProbeObservation(
                summary="Bounded selected process pressure",
                facts={"pid": parameters["pid"]},
                observed_at=stamp,
                captured_at=stamp,
            )

        investigator.runtime._probe_runner = ProbeRunner(  # pyright: ignore[reportPrivateUsage]
            definitions=(
                ProbeDefinition(
                    manifest=manifest,
                    parameter_model=TargetPressureParametersV1,
                    handler=observe,
                    isolated=False,
                ),
            )
        )

        finished = investigator.run(str(case_id))

        assert calls
        assert "application.target_pressure" in finished.completed_probe_ids
        row = store.connection.execute(
            "SELECT s.correlation_id,s.request_json,b.receipt_id "
            "FROM candidate_decision_snapshots AS s "
            "JOIN frontier_packet_snapshot_bindings AS b ON b.snapshot_id=s.snapshot_id "
            "WHERE s.case_id=?",
            (str(case_id),),
        ).fetchone()
        assert row is not None
        receipt = FrontierPacketReceiptRepository(store).readback(str(row[2]))
        current_generation = store.connection.execute(
            "SELECT generation FROM evidence_case_generations WHERE case_id=?", (str(case_id),)
        ).fetchone()[0]
        assert int(current_generation) > receipt.case_generation
        assert (
            SearchFrontierRepository(store).readback(str(row[0])).status is FrontierStatus.SATISFIED
        )


def test_frontier_changed_graph_before_dispatch_closes_claim(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "frontier-graph-changed.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)

        class ChangingGraphRanker(MixedFrontierRanker):
            def rank(
                self,
                request: FrontierRankRequestV1,
                *,
                capture_worker_batch: Callable[
                    [str, int, dict[str, object], LayaWorkerPresentation], None
                ]
                | None = None,
            ) -> FrontierRankResponseV1:
                response = super().rank(request, capture_worker_batch=capture_worker_batch)
                assert investigator.knowledge is not None
                pack = investigator.knowledge.pack
                investigator.knowledge.pack = pack.model_copy(update={"version": pack.version + 1})
                return response

        investigator.frontier_ranker = ChangingGraphRanker(
            ranker=None,
            provider=ProviderIdentity(
                provider_id="fixture-frontier", provider_version="1", role="fast_decision"
            ),
            model_weight_sha256="a" * 64,
        )
        investigator.knowledge = ReferenceKnowledgeGraph.load_default()

        investigator.run(str(case_id))

        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_dispatch_admissions WHERE case_id=?",
            (str(case_id),),
        ).fetchone() == (0,)
        selected = store.connection.execute(
            "SELECT correlation_id FROM candidate_decision_snapshots "
            "WHERE case_id=? AND schema_version=2",
            (str(case_id),),
        ).fetchone()
        assert selected is not None
        assert (
            SearchFrontierRepository(store).readback(str(selected[0])).status
            is FrontierStatus.OBSOLETE
        )


def test_pdf_candidate_brain_gap_keeps_legacy_selection_fallback(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "pdf-candidate-gap.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        decision = _ChoosingCandidateDecision(gap=True)
        investigator.decision = decision

        waiting = investigator.run(str(case_id))

        assert len(decision.requests) == 1
        assert waiting.status is InvestigationStatus.AWAITING_TARGET
        assert waiting.outcome is InvestigationOutcome.AWAITING_TARGET
        assert "application.target_pressure" not in waiting.completed_probe_ids
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_dispatch_admissions WHERE case_id=?",
            (str(case_id),),
        ).fetchone() == (0,)


def test_pdf_candidate_route_defers_when_budget_expires_during_context(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "pdf-deadline-race.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        decision = _ChoosingCandidateDecision()
        investigator.decision = decision
        state = investigator.repository.load(str(case_id))
        remaining = iter((10_000, 0))

        def declining_budget(_state: InvestigationState) -> int:
            return next(remaining)

        monkeypatch.setattr(investigator, "_remaining_ms", declining_budget)
        result = investigator._route_pdf_candidate(state, None)  # pyright: ignore[reportPrivateUsage]

        assert result == state
        assert decision.requests == []
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_decision_snapshots WHERE case_id=?",
            (str(case_id),),
        ).fetchone() == (0,)


def test_pdf_candidate_provider_timeout_falls_back_without_dispatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    release = threading.Event()

    class BlockingCandidateDecision(_ChoosingCandidateDecision):
        def decide_candidates(
            self, request: CandidateDecisionRequestV1
        ) -> CandidateDecisionResponseV1 | CandidateDecisionGapV1:
            release.wait(timeout=5)
            return super().decide_candidates(request)

    with SQLiteStore(tmp_path / "pdf-provider-timeout.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        investigator.decision = BlockingCandidateDecision()

        def short_deadline(_state: InvestigationState) -> datetime:
            return utc_now() + timedelta(milliseconds=75)

        monkeypatch.setattr(investigator, "_decision_deadline", short_deadline)
        try:
            waiting = investigator.run(str(case_id))
            assert waiting.status is InvestigationStatus.AWAITING_TARGET
            assert store.connection.execute(
                "SELECT COUNT(*) FROM candidate_dispatch_admissions WHERE case_id=?",
                (str(case_id),),
            ).fetchone() == (0,)
            assert any("Candidate decision unavailable" in item for item in waiting.warnings)
        finally:
            release.set()


def test_pdf_candidate_admission_crash_is_not_replayed_after_resume(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "pdf-candidate-crash.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        state = investigator.repository.load(str(case_id))
        investigator.repository.save(
            state.model_copy(update={"max_probes": 2}),
            expected_version=state.state_version,
            event="test_budget",
            detail="one candidate attempt",
        )
        investigator.decision = _ChoosingCandidateDecision()

        def admit_then_crash(
            opened: OpenedCase,
            candidate_id: str,
            snapshot_id: str,
            *,
            cancel_event: object = None,
        ) -> object:
            registry, _ = investigator.runtime.candidate_catalog(case_id)
            resolved = registry.resolve(case_id, opened.case.state_version, candidate_id)
            assert isinstance(resolved, CandidateResolution)
            CandidateDispatchAdmissionRepository(store, registry=registry).admit(
                snapshot_id=snapshot_id,
                candidate_id=candidate_id,
                case_id=case_id,
                epoch_state_version=opened.case.state_version,
                task_id=f"probe-0-{opened.plan.probes[0].plan_instance_id}",
                invocation_sha256=resolved.candidate.invocation_sha256,
                cost_ms=resolved.candidate.cost_ms,
            )
            raise RuntimeError("simulated process crash before worker claim")

        investigator.runtime.execute_candidate_measurement = admit_then_crash  # type: ignore[method-assign]
        with pytest.raises(RuntimeError, match="simulated process crash"):
            investigator.run(str(case_id))
        running = investigator.repository.load(str(case_id))
        interrupted = investigator.repository.save(
            running.model_copy(update={"status": InvestigationStatus.INTERRUPTED}),
            expected_version=running.state_version,
            event="test_crash",
            detail="service recovered interrupted worker",
        )
        assert interrupted.spent_cost_ms == 0
        queued = investigator.resume(str(case_id))
        assert queued.spent_cost_ms == 0
        assert investigator._remaining_ms(queued) <= queued.budget_ms - 10_000  # pyright: ignore[reportPrivateUsage]

        def must_not_replay(*_args: object, **_kwargs: object) -> object:
            raise AssertionError("unlinked candidate admission must not be replayed")

        investigator.runtime.execute_candidate_measurement = must_not_replay  # type: ignore[method-assign]
        finished = investigator.run(str(case_id))

        assert "application.target_pressure" in finished.completed_probe_ids
        assert "application.target_pressure" in finished.interrupted_probe_ids
        assert any("Candidate dispatch custody is uncertain" in item for item in finished.warnings)
        assert store.connection.execute(
            "SELECT COUNT(*) FROM probe_executions WHERE case_id=? "
            "AND probe_id='application.target_pressure'",
            (str(case_id),),
        ).fetchone() == (0,)


def _waiting_with_binding(investigator: Investigator, case_id: CaseId) -> None:
    waiting = investigator.run(str(case_id))
    assert waiting.status is InvestigationStatus.AWAITING_TARGET
    targets = ProcessTargetRepository(investigator.store)
    inventory = targets.list_process_candidates(case_id)
    targets.bind_process_target(case_id, inventory.candidates[0].candidate_id)
    investigator.resume_after_target(str(case_id))


def test_resumed_pdf_samples_only_bound_target_and_failure_is_not_diagnosis(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with SQLiteStore(tmp_path / "pdf-failed-probe.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        state = investigator.repository.load(str(case_id))
        investigator.repository.save(
            state.model_copy(update={"max_probes": 2}),
            expected_version=state.state_version,
            event="test_budget",
            detail="one baseline and one selected target",
        )
        _waiting_with_binding(investigator, case_id)
        manifest = default_probe_runner().manifest("application.target_pressure")
        assert manifest is not None
        calls: list[dict[str, JsonValue]] = []

        def unavailable(parameters: dict[str, JsonValue]):
            calls.append(parameters)
            raise RuntimeError("counter unavailable")

        monkeypatch.setattr(
            investigator.runtime,
            "_probe_runner",
            ProbeRunner(
                definitions=(
                    ProbeDefinition(
                        manifest=manifest,
                        parameter_model=TargetPressureParametersV1,
                        handler=unavailable,
                        isolated=False,
                    ),
                )
            ),
        )

        finished = investigator.run(str(case_id))

        assert len(calls) == 1
        assert calls[0]["pid"] == 4242
        assert finished.completed_probe_ids == (
            "application.snapshot",
            "application.target_pressure",
        )
        assert not finished.pending_probe_ids
        assert finished.assessment is None
        assert finished.outcome is not InvestigationOutcome.SUPPORTED_EXPLANATION
        context = investigator.context(str(case_id))
        assert any(
            item.probe_id == "performance.coverage" and item.status is EvidenceContextStatus.FAILED
            for item in context
        ), [(item.probe_id, item.status) for item in context]
        completed_version = finished.state_version
        with pytest.raises(ValueError, match="not awaiting"):
            investigator.resume_after_target(str(case_id))
        assert investigator.repository.load(str(case_id)).state_version == completed_version


def test_pdf_fast_brain_selects_exact_bound_process_measurement(tmp_path: Path) -> None:
    class TargetSelectingDecision:
        identity = ProviderIdentity(
            provider_id="test-target-selection", provider_version="1", role="fast_decision"
        )

        def __init__(self) -> None:
            self.seen: list[DecisionRequest] = []

        def decide(self, request: DecisionRequest) -> DecisionResponse:
            self.seen.append(request)
            capabilities = [
                item
                for item in request.available_probes
                if item.probe_id == "application.target_pressure"
            ]
            assert len(capabilities) == 1
            capability = capabilities[0]
            assert capability.observable_ids == ("application.target_pressure",)
            assert len(capability.target_handles) == 1
            proposal = ProbeProposal(
                schema_version=2,
                probe_id=capability.probe_id,
                purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
                priority=1.0,
                estimated_cost_ms=capability.cost_ms,
                resource_class=ResourceClass.PROCESS,
                dedupe_key="bound-pdf:fast",
                measurement_need=MeasurementNeed(
                    capability_id=capability.probe_id,
                    observable=capability.observable_ids[0],
                    target_handle=capability.target_handles[0],
                ),
            )
            return DecisionResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                proposals=(proposal,),
            ).validate_against(request)

    with SQLiteStore(tmp_path / "pdf-fast-route.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        state = investigator.repository.load(str(case_id))
        investigator.repository.save(
            state.model_copy(update={"max_probes": 2}),
            expected_version=state.state_version,
            event="test_budget",
            detail="one snapshot and one selected process measurement",
        )
        _waiting_with_binding(investigator, case_id)
        decision = TargetSelectingDecision()
        investigator.decision = decision
        selected = ProcessTargetRepository(store).selected_process_target(case_id)
        assert selected is not None
        observed: list[dict[str, JsonValue]] = []
        manifest = default_probe_runner().manifest("application.target_pressure")
        assert manifest is not None

        def collect(parameters: dict[str, JsonValue]) -> ProbeObservation:
            observed.append(parameters)
            at = utc_now()
            return ProbeObservation(
                summary="Selected process pressure",
                facts={"pid": parameters["pid"]},
                observed_at=at,
                captured_at=at,
            )

        investigator.runtime._probe_runner = ProbeRunner(  # pyright: ignore[reportPrivateUsage]
            definitions=(
                ProbeDefinition(
                    manifest=manifest,
                    parameter_model=TargetPressureParametersV1,
                    handler=collect,
                    isolated=False,
                ),
            )
        )

        finished = investigator.run(str(case_id))

        assert decision.seen
        assert decision.seen[0].available_probes[-1].target_handles == (selected.candidate_id,)
        assert len(observed) == 1
        assert observed[0]["pid"] == selected.pid
        target_audit = [
            item
            for item in store.audit_entries(case_id=str(case_id))
            if item.probe_id == "application.target_pressure"
        ]
        assert len(target_audit) == 1
        assert target_audit[0].parameters["measurement_invocation_id"]
        assert (
            store.connection.execute(
                "SELECT COUNT(*) FROM decision_execution_links AS link "
                "JOIN probe_executions AS execution ON execution.execution_id = link.execution_id "
                "WHERE link.case_id = ? AND execution.probe_id = ?",
                (str(case_id), "application.target_pressure"),
            ).fetchone()[0]
            == 1
        )
        assert finished.completed_probe_ids.count("application.target_pressure") == 1


def test_untyped_target_proposal_cannot_execute_and_typed_gap_is_durable(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class UntypedDecision:
        identity = ProviderIdentity(
            provider_id="test-untyped-target", provider_version="1", role="fast_decision"
        )

        def decide(self, request: DecisionRequest) -> DecisionResponse:
            capability = next(
                item
                for item in request.available_probes
                if item.probe_id == "application.target_pressure"
            )
            return DecisionResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                proposals=(
                    ProbeProposal(
                        probe_id=capability.probe_id,
                        purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
                        priority=1.0,
                        estimated_cost_ms=capability.cost_ms,
                        resource_class=capability.resource_class,
                        dedupe_key="untyped-model-target",
                    ),
                ),
            ).validate_against(request)

    with SQLiteStore(tmp_path / "pdf-untyped-gap.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        state = investigator.repository.load(str(case_id))
        investigator.repository.save(
            state.model_copy(update={"max_probes": 2, "max_rounds": 1}),
            expected_version=state.state_version,
            event="test_budget",
            detail="one baseline and one selected target",
        )
        _waiting_with_binding(investigator, case_id)
        investigator.decision = UntypedDecision()
        selected = ProcessTargetRepository(store).selected_process_target(case_id)
        assert selected is not None
        routed: list[MeasurementNeed] = []

        def refuse_generic(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("untyped target must not reach generic plan execution")

        def typed_gap(
            opened: OpenedCase, need: MeasurementNeed, **_kwargs: object
        ) -> ObservabilityGap:
            assert opened.plan.probes[0].reason == DiagnosticPurpose.REFRESH_EVIDENCE.value
            routed.append(need)
            return ObservabilityGap(
                need=need, reason="selected process target changed before execution"
            )

        monkeypatch.setattr(investigator.runtime, "execute_plan", refuse_generic)
        monkeypatch.setattr(investigator.runtime, "execute_measurement_need", typed_gap)

        finished = investigator.run(str(case_id))

        assert len(routed) == 1
        assert routed[0].target_handle == selected.candidate_id
        assert (
            store.connection.execute(
                "SELECT COUNT(*) FROM probe_executions WHERE case_id = ? AND probe_id = ?",
                (str(case_id), "application.target_pressure"),
            ).fetchone()[0]
            == 0
        )
        assert finished.completed_probe_ids.count("application.target_pressure") == 0
        assert len(finished.measurement_gaps) == 1
        assert finished.measurement_gaps[0].need == routed[0]
        assert investigator.repository.load(str(case_id)).schema_version == 5
        assert any("selected process target changed" in warning for warning in finished.warnings)
        assert any(
            step.event == "measurement_gap" for step in investigator.repository.steps(str(case_id))
        )


def test_pdf_typed_gap_is_not_reexecuted_or_counted_as_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class RepeatingDecision:
        identity = ProviderIdentity(
            provider_id="test-repeated-target", provider_version="1", role="fast_decision"
        )

        def __init__(self) -> None:
            self.calls = 0

        def decide(self, request: DecisionRequest) -> DecisionResponse:
            self.calls += 1
            capability = next(
                (
                    item
                    for item in request.available_probes
                    if item.probe_id == "application.target_pressure"
                ),
                None,
            )
            proposals = (
                ()
                if capability is None
                else (
                    ProbeProposal(
                        schema_version=2,
                        probe_id=capability.probe_id,
                        purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
                        priority=1.0,
                        estimated_cost_ms=capability.cost_ms,
                        resource_class=capability.resource_class,
                        dedupe_key="repeat-target",
                        measurement_need=MeasurementNeed(
                            capability_id=capability.probe_id,
                            observable=capability.observable_ids[0],
                            target_handle=capability.target_handles[0],
                        ),
                    ),
                )
            )
            return DecisionResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                proposals=proposals,
            ).validate_against(request)

    with SQLiteStore(tmp_path / "pdf-gap-repeat.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        state = investigator.repository.load(str(case_id))
        investigator.repository.save(
            state.model_copy(update={"max_probes": 4, "max_rounds": 3}),
            expected_version=state.state_version,
            event="test_budget",
            detail="gap must not consume a probe or loop",
        )
        _waiting_with_binding(investigator, case_id)
        investigator.capabilities = tuple(
            capability
            for capability in investigator.capabilities
            if capability.probe_id == "application.snapshot"
        )
        decision = RepeatingDecision()
        investigator.decision = decision
        executions: list[MeasurementNeed] = []

        def no_execution(
            _opened: OpenedCase, need: MeasurementNeed, **_kwargs: object
        ) -> ObservabilityGap:
            executions.append(need)
            return ObservabilityGap(
                need=need, reason="selected process target changed before execution"
            )

        monkeypatch.setattr(investigator.runtime, "execute_measurement_need", no_execution)

        finished = investigator.run(str(case_id))

        assert len(executions) == 1
        assert decision.calls <= 3
        assert finished.completed_probe_ids == ("application.snapshot",)
        assert len(finished.measurement_gaps) == 1
        assert investigator._attempts_consumed(finished) == 1  # pyright: ignore[reportPrivateUsage]
        assert (
            investigator.repository.load(str(case_id)).measurement_gaps == finished.measurement_gaps
        )
        assert (
            store.connection.execute(
                "SELECT COUNT(*) FROM probe_executions WHERE case_id = ? AND probe_id = ?",
                (str(case_id), "application.target_pressure"),
            ).fetchone()[0]
            == 0
        )
        assert finished.status is InvestigationStatus.COMPLETE


def test_stale_immutable_pdf_binding_surfaces_new_case_requirement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "pdf-stale-selection.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        _waiting_with_binding(investigator, case_id)
        queued = investigator.repository.load(str(case_id))
        investigator.repository.save(
            queued.model_copy(update={"max_probes": 1}),
            expected_version=queued.state_version,
            event="test_budget",
            detail="no generic probe after stale binding",
        )

        def stale(_targets: ProcessTargetRepository, _case_id: CaseId):
            raise TargetSelectionError("snapshot is stale")

        monkeypatch.setattr(ProcessTargetRepository, "resolve_process_target_for_sampling", stale)
        finished = investigator.run(str(case_id))

        assert any("new case" in warning.lower() for warning in finished.warnings)
        assert len(finished.measurement_gaps) == 1
        assert finished.measurement_gaps[0].reason.startswith("selected process binding")
        assert "application.target_pressure" not in finished.completed_probe_ids
        assert not store.connection.execute(
            "SELECT 1 FROM probe_executions WHERE case_id = ? AND probe_id = ?",
            (str(case_id), "application.target_pressure"),
        ).fetchone()


def test_pdf_catalog_does_not_advertise_incompatible_target_registration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "pdf-incompatible-registration.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        _waiting_with_binding(investigator, case_id)
        state = investigator.repository.load(str(case_id))
        original = investigator.runtime.probe_manifest
        manifest = original("application.target_pressure")
        assert manifest is not None

        def incompatible(probe_id: str):
            if probe_id == "application.target_pressure":
                return manifest.model_copy(update={"input_model": "NoParameters"})
            return original(probe_id)

        monkeypatch.setattr(investigator.runtime, "probe_manifest", incompatible)
        assert "application.target_pressure" not in {
            item.probe_id
            for item in investigator._case_capabilities(state)  # pyright: ignore[reportPrivateUsage]
        }


def test_queued_v4_checkpoint_upgrades_to_v5_on_resume(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "pdf-v4-upgrade.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        _waiting_with_binding(investigator, case_id)
        queued = investigator.repository.load(str(case_id))
        legacy = queued.model_copy(
            update={"schema_version": 4, "max_probes": 1, "measurement_gaps": ()}
        )
        with store.transaction():
            store.connection.execute(
                "UPDATE investigation_checkpoints SET record_json = ? WHERE case_id = ?",
                (legacy.model_dump_json(), str(case_id)),
            )

        finished = investigator.run(str(case_id))

        assert finished.schema_version == 5
        assert investigator.repository.load(str(case_id)).schema_version == 5


def test_pdf_model_can_choose_other_probe_before_selected_target(tmp_path: Path) -> None:
    class OtherFirstDecision:
        identity = ProviderIdentity(
            provider_id="test-other-first", provider_version="1", role="fast_decision"
        )

        def __init__(self) -> None:
            self.calls = 0

        def decide(self, request: DecisionRequest) -> DecisionResponse:
            self.calls += 1
            selected_id = "core.resources" if self.calls == 1 else "application.target_pressure"
            capability = next(
                item for item in request.available_probes if item.probe_id == selected_id
            )
            need = (
                MeasurementNeed(
                    capability_id=capability.probe_id,
                    observable=capability.observable_ids[0],
                    target_handle=capability.target_handles[0],
                )
                if capability.target_handles
                else None
            )
            return DecisionResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                proposals=(
                    ProbeProposal(
                        schema_version=2 if need is not None else 1,
                        probe_id=capability.probe_id,
                        purpose=DiagnosticPurpose.DISTINGUISH_HYPOTHESES,
                        priority=1.0,
                        estimated_cost_ms=capability.cost_ms,
                        resource_class=capability.resource_class,
                        dedupe_key=f"test-choice:{self.calls}",
                        measurement_need=need,
                    ),
                ),
            ).validate_against(request)

    with SQLiteStore(tmp_path / "pdf-other-first.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        state = investigator.repository.load(str(case_id))
        investigator.repository.save(
            state.model_copy(update={"max_probes": 3}),
            expected_version=state.state_version,
            event="test_budget",
            detail="snapshot, one model choice, then selected process",
        )
        _waiting_with_binding(investigator, case_id)
        decision = OtherFirstDecision()
        investigator.decision = decision
        calls: list[str] = []
        runner = default_probe_runner()
        core_manifest = runner.manifest("core.resources")
        target_manifest = runner.manifest("application.target_pressure")
        assert core_manifest is not None and target_manifest is not None

        def collect_core(_parameters: dict[str, JsonValue]) -> ProbeObservation:
            calls.append("core.resources")
            at = utc_now()
            return ProbeObservation(
                summary="Resource sample", facts={"cpu_percent": 5}, observed_at=at, captured_at=at
            )

        def collect_target(_parameters: dict[str, JsonValue]) -> ProbeObservation:
            calls.append("application.target_pressure")
            at = utc_now()
            return ProbeObservation(
                summary="Target sample", facts={"cpu_percent": 5}, observed_at=at, captured_at=at
            )

        investigator.runtime._probe_runner = ProbeRunner(  # pyright: ignore[reportPrivateUsage]
            definitions=(
                ProbeDefinition(
                    manifest=core_manifest,
                    parameter_model=NoParameters,
                    handler=collect_core,
                    isolated=False,
                ),
                ProbeDefinition(
                    manifest=target_manifest,
                    parameter_model=TargetPressureParametersV1,
                    handler=collect_target,
                    isolated=False,
                ),
            )
        )

        finished = investigator.run(str(case_id))

        assert decision.calls >= 2
        assert calls == ["core.resources", "application.target_pressure"]
        assert finished.completed_probe_ids.count("application.target_pressure") == 1


def test_interrupted_pending_target_is_not_replayed(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "pdf-interrupted.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        state = investigator.repository.load(str(case_id))
        investigator.repository.save(
            state.model_copy(update={"max_probes": 2}),
            expected_version=state.state_version,
            event="test_budget",
            detail="one baseline and one selected target",
        )
        _waiting_with_binding(investigator, case_id)
        queued = investigator.repository.load(str(case_id))
        investigator.repository.save(
            queued.model_copy(update={"pending_probe_ids": ("application.target_pressure",)}),
            expected_version=queued.state_version,
            event="test_crash",
            detail="target may have been observed before worker crashed",
        )

        def must_not_replay(*_args: object, **_kwargs: object) -> None:
            raise AssertionError("uncertain prior target attempt must not repeat")

        investigator.runtime.execute_measurement_need = must_not_replay  # type: ignore[method-assign]
        finished = investigator.run(str(case_id))

        assert "application.target_pressure" in finished.completed_probe_ids
        assert not finished.pending_probe_ids
        assert any("not automatically repeated" in warning for warning in finished.warnings)
        assert finished.assessment is None
        assert finished.outcome is not InvestigationOutcome.SUPPORTED_EXPLANATION


def test_pdf_case_with_too_small_budget_does_not_await_unrunnable_target(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "pdf-low-budget.db") as store:
        store.initialize()
        investigator, case_id = _precollected_pdf_investigator(store)
        state = investigator.repository.load(str(case_id))
        limited = investigator.repository.save(
            state.model_copy(
                update={
                    "budget_ms": 5_000,
                    "deadline_at": utc_now() + timedelta(milliseconds=1),
                }
            ),
            expected_version=state.state_version,
            event="test_budget",
            detail="target collection cost exceeds configured case budget",
        )

        finished = investigator.run(str(case_id))

        assert limited.completed_probe_ids == ("application.snapshot",)
        assert finished.status is not InvestigationStatus.AWAITING_TARGET
        assert finished.outcome is not InvestigationOutcome.AWAITING_TARGET
        assert any("10-second case budget" in warning for warning in finished.warnings)
        assert "application.target_pressure" not in finished.completed_probe_ids
