"""The ordinary investigator owns bounded, durable attention to source events."""

import threading
import time
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

from systemsense.application.candidate_catalog import (
    _current_general_source,  # pyright: ignore[reportPrivateUsage]
)
from systemsense.application.case_service import CaseService
from systemsense.application.investigation_state import InvestigationOutcome, InvestigationStatus
from systemsense.application.investigator import InvestigationState, Investigator
from systemsense.application.runtime import DiagnosticRuntime
from systemsense.decision.contracts import EvidenceContext, ProviderIdentity
from systemsense.decision.frontier_ranker import (
    FrontierRankRequestV1,
    FrontierRankResponseV1,
    MixedFrontierRanker,
)
from systemsense.domain.evidence import EvidenceRecord
from systemsense.domain.ids import CaseId, EvidenceId
from systemsense.domain.time import utc_now
from systemsense.inference.laya_runtime import LayaWorkerPresentation
from systemsense.knowledge.catalog import ReferenceKnowledgeGraph
from systemsense.orchestration.planner import DeterministicPlanner
from systemsense.packs.runtime import default_probe_runner
from systemsense.storage.candidate_dispatch_admissions import CandidateDispatchAdmissionRepository
from systemsense.storage.case_candidates import CandidateGap
from systemsense.storage.frontier_packet_receipts import FrontierPacketReceiptRepository
from systemsense.storage.search_frontier import (
    FrontierEventV1,
    FrontierInvestigatorTurnV3,
    FrontierReferenceV1,
    FrontierStatus,
    RelevantVersionsV1,
    SearchFrontierRepository,
)
from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration.test_catalog_attention_loop import (
    _fill_case,  # pyright: ignore[reportPrivateUsage]
)
from tests.integration.test_investigator import investigator
from tests.unit.application import test_general_candidate_catalog as catalog_fixtures
from tests.unit.application.test_general_candidate_catalog import (
    _gpu_source,  # pyright: ignore[reportPrivateUsage]
    _source,  # pyright: ignore[reportPrivateUsage]
)
from tests.unit.evidence.test_retrieval import _insert_record  # pyright: ignore[reportPrivateUsage]


@pytest.fixture(autouse=True)
def _refresh_imported_catalog_clock(monkeypatch: pytest.MonkeyPatch) -> None:  # pyright: ignore[reportUnusedFunction]
    # Imported fixture helpers do not inherit their defining module's autouse fixture.
    monkeypatch.setattr(catalog_fixtures, "NOW", utc_now())


class RecordingRanker(MixedFrontierRanker):
    def __init__(self, *, fail: bool = False) -> None:
        super().__init__(
            ranker=None,
            provider=ProviderIdentity(
                provider_id="test-event-frontier",
                provider_version="1",
                role="fast_decision",
            ),
            model_weight_sha256="a" * 64,
        )
        self.fail = fail
        self.requests: list[FrontierRankRequestV1] = []

    def rank(
        self,
        request: FrontierRankRequestV1,
        *,
        capture_worker_batch: Callable[[str, int, dict[str, object], LayaWorkerPresentation], None]
        | None = None,
    ) -> FrontierRankResponseV1:
        self.requests.append(request)
        if self.fail:
            raise RuntimeError("provider unavailable")
        selected = next(
            item for item in request.items if item.reference.kind == "retrieve_evidence"
        )
        fallback = super().rank(request, capture_worker_batch=capture_worker_batch)
        offered = tuple(item.item_id for item in request.items)
        return fallback.model_copy(
            update={
                "ranked_item_ids": (
                    selected.item_id,
                    *(item for item in offered if item != selected.item_id),
                ),
                "considered_item_ids": offered,
                "ranking_source": "laya",
                "model_abstained": False,
                "coverage_complete": True,
                "degraded_reason": None,
            }
        ).validate_against(request)


class MeasurementFirstRanker(RecordingRanker):
    def __init__(self, *, prefer_measure: bool = True) -> None:
        super().__init__()
        self.prefer_measure = prefer_measure

    def rank(
        self,
        request: FrontierRankRequestV1,
        *,
        capture_worker_batch: Callable[[str, int, dict[str, object], LayaWorkerPresentation], None]
        | None = None,
    ) -> FrontierRankResponseV1:
        self.requests.append(request)
        preferred_kind = "measure" if self.prefer_measure else "retrieve_evidence"
        selected = next(
            (item for item in request.items if item.reference.kind == preferred_kind),
            request.items[0],
        )
        offered = tuple(item.item_id for item in request.items)
        return (
            MixedFrontierRanker.rank(self, request, capture_worker_batch=capture_worker_batch)
            .model_copy(
                update={
                    "ranked_item_ids": (
                        selected.item_id,
                        *(item for item in offered if item != selected.item_id),
                    ),
                    "considered_item_ids": offered,
                    "ranking_source": "laya",
                    "model_abstained": False,
                    "coverage_complete": True,
                    "degraded_reason": None,
                }
            )
            .validate_against(request)
        )


class GPUFirstRanker(MeasurementFirstRanker):
    def __init__(self, candidate_id: str) -> None:
        super().__init__()
        self.candidate_id = candidate_id

    def rank(
        self,
        request: FrontierRankRequestV1,
        *,
        capture_worker_batch: Callable[[str, int, dict[str, object], LayaWorkerPresentation], None]
        | None = None,
    ) -> FrontierRankResponseV1:
        self.requests.append(request)
        selected = next(
            item
            for item in request.items
            if item.reference.kind == "measure" and item.reference.candidate_id == self.candidate_id
        )
        offered = tuple(item.item_id for item in request.items)
        return (
            MixedFrontierRanker.rank(self, request, capture_worker_batch=capture_worker_batch)
            .model_copy(
                update={
                    "ranked_item_ids": (
                        selected.item_id,
                        *(item for item in offered if item != selected.item_id),
                    ),
                    "considered_item_ids": offered,
                    "ranking_source": "laya",
                    "model_abstained": False,
                    "coverage_complete": True,
                    "degraded_reason": None,
                }
            )
            .validate_against(request)
        )


def _app(store: SQLiteStore, ranker: RecordingRanker) -> Investigator:
    base = investigator(store)
    return Investigator(
        store=store,
        runtime=base.runtime,
        capabilities=base.capabilities,
        decision=base.decision,
        reasoning=base.reasoning,
        knowledge=ReferenceKnowledgeGraph.load_default(),
        frontier_ranker=ranker,
    )


def _app_with_registered_host_probes(store: SQLiteStore, ranker: RecordingRanker) -> Investigator:
    base = _app(store, ranker)
    return Investigator(
        store=store,
        runtime=DiagnosticRuntime(
            store=store,
            case_service=CaseService(store, DeterministicPlanner(candidates=())),
            probe_runner=default_probe_runner(),
        ),
        capabilities=base.capabilities,
        decision=base.decision,
        reasoning=base.reasoning,
        knowledge=base.knowledge,
        frontier_ranker=ranker,
    )


def _started_with_event(
    app: Investigator, store: SQLiteStore, *, count: int, budget_ms: int = 10_000
) -> tuple[InvestigationState, FrontierEventV1, EvidenceId]:
    state = app.create(objective="Investigate a recent disk observation", budget_ms=budget_ms)
    target = _fill_case(store, str(state.case_id), count=count, target_index=1)
    generation = store.connection.execute(
        "SELECT generation FROM evidence_case_generations WHERE case_id=?",
        (str(state.case_id),),
    ).fetchone()
    assert generation is not None
    frontier = SearchFrontierRepository(store)
    with store.transaction():
        event = frontier.append_result_event(
            state.case_id,
            source_evidence_id=target,
            source_execution_id=None,
            versions=RelevantVersionsV1(objective=1, evidence=int(generation[0])),
        )
    assert isinstance(event, FrontierEventV1)
    state = app._save(  # pyright: ignore[reportPrivateUsage]
        state.model_copy(update={"status": InvestigationStatus.RUNNING}),
        "started",
        "Read-only investigator started.",
    )
    return state, event, target


def _omit_until_selected(
    app: Investigator,
    case_id: str,
    target: EvidenceId,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[EvidenceContext, ...]:
    """Simulate one bounded focus packet that has omitted an exact stored row."""

    original = app.context

    def focused(
        case_id: str, *, state: InvestigationState | None = None
    ) -> tuple[EvidenceContext, ...]:
        packet = original(case_id, state=state)
        if state is not None and target in state.fast_catalog_selected_ids:
            return packet
        return tuple(item for item in packet if item.evidence_id != target)

    monkeypatch.setattr(app, "context", focused)
    return app.context(case_id)


def _empty_context(
    _case_id: str, *, state: InvestigationState | None = None
) -> tuple[EvidenceContext, ...]:
    return ()


def _bind_fixture_execution(store: SQLiteStore, case_id: CaseId, evidence_id: EvidenceId) -> None:
    """Align synthetic row metadata with its typed collector ID for receipt projection."""
    row = store.evidence(case_id=str(case_id), evidence_id=str(evidence_id))
    assert row is not None
    record = EvidenceRecord.model_validate_json(row.record_json)
    execution_id = record.collector.execution_id
    with store.transaction():
        store.connection.execute(
            "UPDATE evidence SET execution_id=?,time_basis='collector_observed',"
            "time_quality='exact' WHERE case_id=? AND evidence_id=?",
            (str(execution_id), str(case_id), str(evidence_id)),
        )


def test_source_event_turn_delivers_exact_omitted_record_and_commits_closure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "event-focused.db") as store:
        ranker = RecordingRanker()
        app = _app(store, ranker)
        state, event, target = _started_with_event(app, store, count=1)
        before = _omit_until_selected(app, str(state.case_id), target, monkeypatch)
        assert str(target) not in {str(item.evidence_id) for item in before}

        updated, after, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, before, state.state_version
        )

        frontier = SearchFrontierRepository(store)
        turns = frontier.investigator_turns(state.case_id, event.event_id)
        assert handled is True
        assert len(turns) == 1
        assert len(ranker.requests) == 1
        assert str(target) in {str(item.evidence_id) for item in after}
        assert any(
            item.evidence_id == target and item.facts.get("exact_marker") == "persisted_truth"
            for item in after
        )
        assert target in updated.fast_catalog_selected_ids
        outcome = frontier.read_investigator_turn_outcome(turns[0].turn_id)
        assert outcome is not None and outcome.outcome == "focused_delivery"
        assert outcome.resulting_checkpoint_version == updated.state_version
        assert len(outcome.frontier_item_ids) == 1
        assert frontier.readback(outcome.frontier_item_ids[0]).status is FrontierStatus.SATISFIED
        closure = frontier.read_investigator_turn_closure(event.event_id)
        assert closure is not None and closure.outcome == "focused_delivery"
        assert frontier.active_investigator_session(state.case_id) is None
        assert store.connection.execute("SELECT COUNT(*) FROM probe_executions").fetchone()[0] == 0


def test_general_event_mixes_fresh_registered_measurement_with_retrieval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with SQLiteStore(tmp_path / "event-mixed.db") as store:
        ranker = MeasurementFirstRanker()
        app = _app_with_registered_host_probes(store, ranker)
        state, event, target = _started_with_event(app, store, count=1, budget_ms=30_000)
        _source(store, state.case_id, age_seconds=5, epoch=state.state_version)
        _omit_until_selected(app, str(state.case_id), target, monkeypatch)
        assert _current_general_source(store, state.case_id, utc_now()) is not None
        registry, needs = app.runtime.general_candidate_catalog(state.case_id)
        assert needs
        assert not isinstance(
            registry.issue(state.case_id, state.state_version, needs[0]), CandidateGap
        )
        assert app._remaining_ms(state) >= 10_000  # pyright: ignore[reportPrivateUsage]

        updated, _, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, app.context(str(state.case_id), state=state), state.state_version
        )

        frontier = SearchFrontierRepository(store)
        turns = frontier.investigator_turns(state.case_id, event.event_id)
        assert handled and len(turns) == 1
        assert isinstance(turns[0], FrontierInvestigatorTurnV3)
        assert {item.reference.kind for item in ranker.requests[0].items} == {
            "retrieve_evidence",
            "measure",
        }
        outcome = frontier.read_investigator_turn_outcome(turns[0].turn_id)
        assert outcome is not None and outcome.outcome == "measurement_admitted"
        assert outcome.resulting_checkpoint_version is not None
        assert outcome.resulting_checkpoint_version <= updated.state_version
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_dispatch_admissions WHERE case_id=?",
            (str(state.case_id),),
        ).fetchone() == (1,)
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_launch_consumptions WHERE case_id=?",
            (str(state.case_id),),
        ).fetchone() == (1,)
        assert store.connection.execute(
            "SELECT COUNT(*) FROM probe_executions "
            "WHERE case_id=? AND probe_id='pressure.sample' AND status='ok'",
            (str(state.case_id),),
        ).fetchone() == (1,)
        admission_row = store.connection.execute(
            "SELECT admission_id FROM candidate_dispatch_admissions WHERE case_id=?",
            (str(state.case_id),),
        ).fetchone()
        assert admission_row is not None
        assert (
            CandidateDispatchAdmissionRepository(store)
            .readback(str(admission_row[0]))
            .outcome_status
            == "linked"
        )

        next_state, next_context, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            updated, app.context(str(state.case_id), state=updated), state.state_version
        )
        next_turn = frontier.investigator_turns(state.case_id, event.event_id)[1]
        next_outcome = frontier.read_investigator_turn_outcome(next_turn.turn_id)
        assert handled and isinstance(next_turn, FrontierInvestigatorTurnV3)
        assert next_outcome is not None and next_outcome.outcome == "focused_delivery"
        assert target in next_state.fast_catalog_selected_ids
        assert str(target) in {str(item.evidence_id) for item in next_context}


def test_mixed_receipt_includes_focused_non_candidate_evidence(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with SQLiteStore(tmp_path / "event-focused-receipt.db") as store:
        ranker = MeasurementFirstRanker()
        app = _app_with_registered_host_probes(store, ranker)
        state, event, target = _started_with_event(app, store, count=2, budget_ms=30_000)
        _bind_fixture_execution(store, state.case_id, EvidenceId(root=f"ev_{2:032x}"))
        source = _source(store, state.case_id, age_seconds=5, epoch=state.state_version)
        before = _omit_until_selected(app, str(state.case_id), target, monkeypatch)
        non_candidate = EvidenceId(root=f"ev_{2:032x}")
        assert str(non_candidate) in {str(item.evidence_id) for item in before}

        _, _, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, before, state.state_version
        )

        assert handled and ranker.requests
        packet_ids = {item.evidence_id for item in ranker.requests[0].evidence_packets}
        assert str(source) in packet_ids
        assert str(non_candidate) in packet_ids
        turn = SearchFrontierRepository(store).investigator_turns(state.case_id, event.event_id)[0]
        assert isinstance(turn, FrontierInvestigatorTurnV3)
        assert turn.packet_receipt_id is not None
        receipt = FrontierPacketReceiptRepository(store).readback(turn.packet_receipt_id)
        assert ranker.requests[0].evidence_packets == receipt.packets
        assert {str(item.evidence_id) for item in receipt.sources} >= {
            str(source),
            str(non_candidate),
        }


def test_mixed_receipt_rejects_context_row_from_another_case(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with SQLiteStore(tmp_path / "event-foreign-receipt.db") as store:
        ranker = MeasurementFirstRanker()
        app = _app_with_registered_host_probes(store, ranker)
        state, event, target = _started_with_event(app, store, count=1, budget_ms=30_000)
        _source(store, state.case_id, age_seconds=5, epoch=state.state_version)
        other = app.create(objective="Unrelated case", budget_ms=10_000)
        foreign_id = EvidenceId.new()
        _insert_record(
            store,
            case_id=str(other.case_id),
            evidence_id=str(foreign_id),
            collector_id="disk.health",
            summary="foreign observation",
            observed_at=utc_now() - timedelta(seconds=1),
        )
        before = _omit_until_selected(app, str(state.case_id), target, monkeypatch)
        assert before
        forged = before[0].model_copy(
            update={"evidence_id": foreign_id, "case_scope": "current_case"}
        )

        _, _, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, (*before, forged), state.state_version
        )

        assert handled
        assert ranker.requests == []
        turn = SearchFrontierRepository(store).investigator_turns(state.case_id, event.event_id)[0]
        outcome = SearchFrontierRepository(store).read_investigator_turn_outcome(turn.turn_id)
        assert outcome is not None and outcome.outcome == "gap"
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_dispatch_admissions WHERE case_id=?",
            (str(state.case_id),),
        ).fetchone() == (0,)


def test_mixed_receipt_omits_nonprojectable_optional_time_metadata(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with SQLiteStore(tmp_path / "event-bad-optional-time.db") as store:
        ranker = RecordingRanker()
        app = _app_with_registered_host_probes(store, ranker)
        state, _, target = _started_with_event(app, store, count=2, budget_ms=30_000)
        optional_id = EvidenceId(root=f"ev_{2:032x}")
        _bind_fixture_execution(store, state.case_id, optional_id)
        with store.transaction():
            store.connection.execute(
                "UPDATE evidence SET time_basis='invalid provenance' WHERE evidence_id=?",
                (str(optional_id),),
            )
        source = _source(store, state.case_id, age_seconds=5, epoch=state.state_version)
        before = _omit_until_selected(app, str(state.case_id), target, monkeypatch)
        assert str(optional_id) in {str(item.evidence_id) for item in before}
        receipts = FrontierPacketReceiptRepository(store)
        assert receipts.projectable_optional_sources(
            case_id=state.case_id,
            epoch_state_version=state.state_version,
            evidence_ids=(optional_id, source, optional_id),
        ) == (source,)
        with pytest.raises(ValueError, match="epoch is stale"):
            receipts.projectable_optional_sources(
                case_id=state.case_id,
                epoch_state_version=state.state_version + 1,
                evidence_ids=(optional_id,),
            )
        generation = store.connection.execute(
            "SELECT generation FROM evidence_case_generations WHERE case_id=?",
            (str(state.case_id),),
        ).fetchone()
        assert generation is not None
        with pytest.raises(ValueError, match="time metadata is invalid"):
            receipts.freeze(
                case_id=state.case_id,
                epoch_state_version=state.state_version,
                evidence_ids=(optional_id,),
                expected_generation=int(generation[0]),
            )

        updated, _, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, before, state.state_version
        )

        assert handled and ranker.requests
        packet_ids = {item.evidence_id for item in ranker.requests[0].evidence_packets}
        assert str(source) in packet_ids
        assert str(optional_id) not in packet_ids
        assert any("excluded" in warning for warning in updated.warnings)
        assert not any("attention limit" in warning for warning in updated.warnings)


def test_mixed_receipt_keeps_both_candidate_sources_when_context_overflows(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with SQLiteStore(tmp_path / "event-receipt-overflow.db") as store:
        ranker = RecordingRanker()
        app = _app_with_registered_host_probes(store, ranker)
        state, _, target = _started_with_event(app, store, count=20, budget_ms=30_000)
        for index in range(1, 21):
            _bind_fixture_execution(store, state.case_id, EvidenceId(root=f"ev_{index:032x}"))
        time.sleep(0.7)
        monkeypatch.setattr(catalog_fixtures, "NOW", utc_now())
        pressure_source = _source(store, state.case_id, age_seconds=0, epoch=state.state_version)
        gpu_source = _gpu_source(store, state.case_id, age_seconds=0.5, epoch=state.state_version)
        before = _omit_until_selected(app, str(state.case_id), target, monkeypatch)
        assert len(before) > 8

        updated, _, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, before, state.state_version
        )

        assert handled and ranker.requests
        packet_ids = {item.evidence_id for item in ranker.requests[0].evidence_packets}
        assert {str(pressure_source), str(gpu_source)} <= packet_ids
        assert len(packet_ids) > 2
        assert len(packet_ids) <= 8
        assert any(
            "omitted" in warning and "attention limit" in warning for warning in updated.warnings
        )


def test_general_event_chooses_gpu_from_two_registered_measurements_and_retrieval(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with SQLiteStore(tmp_path / "event-gpu-choice.db") as store:
        ranker = GPUFirstRanker("pending")
        app = _app_with_registered_host_probes(store, ranker)
        state, event, target = _started_with_event(app, store, count=1, budget_ms=30_000)
        time.sleep(0.7)
        monkeypatch.setattr(catalog_fixtures, "NOW", utc_now())
        _source(store, state.case_id, age_seconds=0, epoch=state.state_version)
        _gpu_source(store, state.case_id, age_seconds=0.5, epoch=state.state_version)
        _omit_until_selected(app, str(state.case_id), target, monkeypatch)
        registry, needs = app.runtime.general_candidate_catalog(state.case_id)
        issued = {
            need.capability_id: registry.issue(state.case_id, state.state_version, need)
            for need in needs
        }
        assert {"pressure.sample", "gpu.telemetry.sample"} <= set(issued)
        gpu = issued["gpu.telemetry.sample"]
        assert not isinstance(gpu, CandidateGap)
        ranker.candidate_id = gpu.candidate_id

        updated, _, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, app.context(str(state.case_id), state=state), state.state_version
        )

        assert handled and ranker.requests
        request = ranker.requests[0]
        measure_ids = {
            item.reference.candidate_id
            for item in request.items
            if item.reference.kind == "measure"
        }
        assert measure_ids == {issued["pressure.sample"].candidate_id, gpu.candidate_id}
        assert any(item.reference.kind == "retrieve_evidence" for item in request.items)
        frontier = SearchFrontierRepository(store)
        turn = frontier.investigator_turns(state.case_id, event.event_id)[0]
        outcome = frontier.read_investigator_turn_outcome(turn.turn_id)
        assert outcome is not None and outcome.outcome == "measurement_admitted"
        assert store.connection.execute(
            "SELECT COUNT(*) FROM probe_executions WHERE case_id=? "
            "AND probe_id='gpu.telemetry.sample'",
            (str(state.case_id),),
        ).fetchone() == (1,)
        assert store.connection.execute(
            "SELECT COUNT(*) FROM probe_executions WHERE case_id=? AND probe_id='pressure.sample'",
            (str(state.case_id),),
        ).fetchone() == (0,)
        assert any(
            frontier.readback(item_id).reference.kind == "measure"
            for item_id in outcome.remaining_item_ids
        )
        assert updated.state_version > state.state_version


def test_two_pending_measurements_reissue_by_binding_after_reversed_catalog_order(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with SQLiteStore(tmp_path / "event-two-reissues.db") as store:
        ranker = MeasurementFirstRanker(prefer_measure=False)
        app = _app_with_registered_host_probes(store, ranker)
        state, event, target = _started_with_event(app, store, count=1, budget_ms=30_000)
        time.sleep(0.7)
        monkeypatch.setattr(catalog_fixtures, "NOW", utc_now())
        _source(store, state.case_id, age_seconds=0, epoch=state.state_version)
        _gpu_source(store, state.case_id, age_seconds=0.5, epoch=state.state_version)
        _omit_until_selected(app, str(state.case_id), target, monkeypatch)

        first, first_context, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, app.context(str(state.case_id), state=state), state.state_version
        )
        frontier = SearchFrontierRepository(store)
        first_turn = frontier.investigator_turns(state.case_id, event.event_id)[0]
        first_outcome = frontier.read_investigator_turn_outcome(first_turn.turn_id)
        assert handled and first_outcome is not None
        assert first_outcome.outcome == "focused_delivery"
        predecessors = first_outcome.remaining_item_ids
        assert len(predecessors) == 2
        assert all(frontier.readback(item).reference.kind == "measure" for item in predecessors)

        original_catalog = app.runtime.general_candidate_catalog

        def reversed_catalog(case_id: CaseId) -> tuple[Any, tuple[Any, ...]]:
            registry, needs = original_catalog(case_id)
            return registry, tuple(reversed(needs))

        monkeypatch.setattr(app.runtime, "general_candidate_catalog", reversed_catalog)
        second, _, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            first, first_context, state.state_version
        )
        second_turn = frontier.investigator_turns(state.case_id, event.event_id)[1]
        second_outcome = frontier.read_investigator_turn_outcome(second_turn.turn_id)
        assert handled and isinstance(second_turn, FrontierInvestigatorTurnV3)
        assert len(second_turn.reissue_lineage) == 2
        assert (
            tuple(link.predecessor_item_id for link in second_turn.reissue_lineage) == predecessors
        )
        for link in second_turn.reissue_lineage:
            old_candidate = frontier.readback(link.predecessor_item_id).reference.candidate_id
            new_candidate = frontier.readback(link.successor_item_id).reference.candidate_id
            assert old_candidate is not None and new_candidate is not None
            rows = store.connection.execute(
                "SELECT probe_id,source_evidence_id,invocation_sha256 "
                "FROM case_measurement_candidates WHERE candidate_id IN (?,?) "
                "ORDER BY candidate_id",
                (old_candidate, new_candidate),
            ).fetchall()
            assert len(rows) == 2 and rows[0] == rows[1]
        assert second_outcome is not None and second_outcome.outcome == "measurement_admitted"
        assert second.state_version > first.state_version


def test_one_stale_measurement_retains_entire_pending_tail_as_gap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with SQLiteStore(tmp_path / "event-stale-sibling.db") as store:
        ranker = MeasurementFirstRanker(prefer_measure=False)
        app = _app_with_registered_host_probes(store, ranker)
        state, event, target = _started_with_event(app, store, count=1, budget_ms=30_000)
        time.sleep(0.7)
        monkeypatch.setattr(catalog_fixtures, "NOW", utc_now())
        _source(store, state.case_id, age_seconds=0, epoch=state.state_version)
        _gpu_source(store, state.case_id, age_seconds=0.5, epoch=state.state_version)
        _omit_until_selected(app, str(state.case_id), target, monkeypatch)
        first, first_context, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, app.context(str(state.case_id), state=state), state.state_version
        )
        frontier = SearchFrontierRepository(store)
        first_turn = frontier.investigator_turns(state.case_id, event.event_id)[0]
        first_outcome = frontier.read_investigator_turn_outcome(first_turn.turn_id)
        assert handled and first_outcome is not None
        assert len(first_outcome.remaining_item_ids) == 2
        original_catalog = app.runtime.general_candidate_catalog

        def missing_gpu(case_id: CaseId) -> tuple[Any, tuple[Any, ...]]:
            registry, needs = original_catalog(case_id)
            return registry, tuple(
                need for need in needs if need.capability_id != "gpu.telemetry.sample"
            )

        monkeypatch.setattr(app.runtime, "general_candidate_catalog", missing_gpu)
        _, _, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            first, first_context, state.state_version
        )

        second_turn = frontier.investigator_turns(state.case_id, event.event_id)[1]
        second_outcome = frontier.read_investigator_turn_outcome(second_turn.turn_id)
        assert handled and isinstance(second_turn, FrontierInvestigatorTurnV3)
        assert second_turn.stale_pending_gap
        assert second_outcome is not None and second_outcome.outcome == "gap"
        assert second_outcome.remaining_item_ids == first_outcome.remaining_item_ids
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_dispatch_admissions WHERE case_id=?",
            (str(state.case_id),),
        ).fetchone() == (0,)


def test_mixed_event_reissues_unadmitted_measurement_after_retrieval_checkpoint(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with SQLiteStore(tmp_path / "event-mixed-reissue.db") as store:
        ranker = MeasurementFirstRanker(prefer_measure=False)
        app = _app_with_registered_host_probes(store, ranker)
        state, event, target = _started_with_event(app, store, count=1, budget_ms=30_000)
        _source(store, state.case_id, age_seconds=5, epoch=state.state_version)
        _omit_until_selected(app, str(state.case_id), target, monkeypatch)

        first, first_context, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, app.context(str(state.case_id), state=state), state.state_version
        )
        frontier = SearchFrontierRepository(store)
        first_turn = frontier.investigator_turns(state.case_id, event.event_id)[0]
        first_outcome = frontier.read_investigator_turn_outcome(first_turn.turn_id)
        assert handled and isinstance(first_turn, FrontierInvestigatorTurnV3)
        assert first_outcome is not None and first_outcome.outcome == "focused_delivery"
        assert len(first_outcome.remaining_item_ids) == 1
        predecessor = first_outcome.remaining_item_ids[0]
        assert frontier.readback(predecessor).reference.kind == "measure"
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_dispatch_admissions WHERE case_id=?",
            (str(state.case_id),),
        ).fetchone() == (0,)

        registry, needs = app.runtime.general_candidate_catalog(state.case_id)
        assert needs
        record = registry.issue(state.case_id, first.state_version, needs[0])
        assert not isinstance(record, CandidateGap), record

        second, _, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            first, first_context, state.state_version
        )
        second_turn = frontier.investigator_turns(state.case_id, event.event_id)[1]
        second_outcome = frontier.read_investigator_turn_outcome(second_turn.turn_id)
        assert handled and isinstance(second_turn, FrontierInvestigatorTurnV3)
        assert len(second_turn.reissue_lineage) == 1
        assert second_turn.reissue_lineage[0].predecessor_item_id == predecessor
        assert frontier.readback(predecessor).status is FrontierStatus.OBSOLETE
        assert second_outcome is not None and second_outcome.outcome == "measurement_admitted"
        assert second.state_version > first.state_version
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_dispatch_admissions WHERE case_id=?",
            (str(state.case_id),),
        ).fetchone() == (1,)


def test_measurement_on_last_event_turn_closes_budgeted_session(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with SQLiteStore(tmp_path / "event-mixed-budget.db") as store:
        ranker = MeasurementFirstRanker()
        app = _app_with_registered_host_probes(store, ranker)
        state, event, target = _started_with_event(app, store, count=1, budget_ms=30_000)
        _source(store, state.case_id, age_seconds=5, epoch=state.state_version)
        _omit_until_selected(app, str(state.case_id), target, monkeypatch)
        frontier = SearchFrontierRepository(store)
        frontier.intake_investigator_event(state.case_id, event.event_id)
        frontier.start_investigator_session(state.case_id, event.event_id, decision_budget=1)

        _, _, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, app.context(str(state.case_id), state=state), state.state_version
        )

        assert handled
        turns = frontier.investigator_turns(state.case_id, event.event_id)
        assert len(turns) == 1
        outcome = frontier.read_investigator_turn_outcome(turns[0].turn_id)
        assert outcome is not None and outcome.outcome == "measurement_admitted"
        closure = frontier.read_investigator_turn_closure(event.event_id)
        assert closure is not None and closure.reason_code == "budget_exhausted"
        assert frontier.active_investigator_session(state.case_id) is None


def test_admitted_event_measurement_worker_error_is_uncertain_not_replayed(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with SQLiteStore(tmp_path / "event-mixed-worker-error.db") as store:
        ranker = MeasurementFirstRanker()
        app = _app_with_registered_host_probes(store, ranker)
        state, event, _ = _started_with_event(app, store, count=1, budget_ms=30_000)
        _source(store, state.case_id, age_seconds=5, epoch=state.state_version)

        def worker_unavailable(*_args: object, **_kwargs: object) -> None:
            raise RuntimeError("worker unavailable after admission")

        monkeypatch.setattr(app.runtime, "execute_candidate_measurement", worker_unavailable)
        updated, _, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, app.context(str(state.case_id), state=state), state.state_version
        )

        frontier = SearchFrontierRepository(store)
        turn = frontier.investigator_turns(state.case_id, event.event_id)[0]
        outcome = frontier.read_investigator_turn_outcome(turn.turn_id)
        assert handled and outcome is not None and outcome.outcome == "measurement_admitted"
        assert frontier.readback(outcome.frontier_item_ids[0]).status is FrontierStatus.INTERRUPTED
        assert any("worker interrupted" in warning for warning in updated.warnings)
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_dispatch_admissions WHERE case_id=?",
            (str(state.case_id),),
        ).fetchone() == (1,)
        assert app.runtime.general_candidate_catalog(state.case_id)[1] == ()


def test_pending_measurement_without_fresh_candidate_closes_explicit_gap(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with SQLiteStore(tmp_path / "event-mixed-stale-pending.db") as store:
        ranker = MeasurementFirstRanker(prefer_measure=False)
        app = _app_with_registered_host_probes(store, ranker)
        state, event, target = _started_with_event(app, store, count=1, budget_ms=30_000)
        _source(store, state.case_id, age_seconds=5, epoch=state.state_version)
        _omit_until_selected(app, str(state.case_id), target, monkeypatch)
        first, first_context, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, app.context(str(state.case_id), state=state), state.state_version
        )
        assert handled
        frontier = SearchFrontierRepository(store)
        first_turn = frontier.investigator_turns(state.case_id, event.event_id)[0]
        first_outcome = frontier.read_investigator_turn_outcome(first_turn.turn_id)
        assert first_outcome is not None and first_outcome.outcome == "focused_delivery"
        assert len(first_outcome.remaining_item_ids) == 1
        registry, _ = app.runtime.general_candidate_catalog(state.case_id)

        def unavailable_candidate_catalog(_case_id: CaseId) -> tuple[object, tuple[()]]:
            return registry, ()

        monkeypatch.setattr(app.runtime, "general_candidate_catalog", unavailable_candidate_catalog)

        _, _, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            first, first_context, state.state_version
        )

        second_turn = frontier.investigator_turns(state.case_id, event.event_id)[1]
        second_outcome = frontier.read_investigator_turn_outcome(second_turn.turn_id)
        assert handled and isinstance(second_turn, FrontierInvestigatorTurnV3)
        assert second_turn.stale_pending_gap
        assert second_outcome is not None and second_outcome.outcome == "gap"
        assert second_outcome.reason_code == "stale_context"
        assert second_outcome.remaining_item_ids == first_outcome.remaining_item_ids
        assert frontier.read_investigator_turn_closure(event.event_id) is not None
        assert len(ranker.requests) == 1
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_dispatch_admissions WHERE case_id=?",
            (str(state.case_id),),
        ).fetchone() == (0,)


def test_provider_failure_records_gap_and_preserves_entire_offered_tail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "event-provider-gap.db") as store:
        ranker = RecordingRanker(fail=True)
        app = _app(store, ranker)
        state, event, target = _started_with_event(app, store, count=2)
        _omit_until_selected(app, str(state.case_id), target, monkeypatch)
        monkeypatch.setattr(app, "context", _empty_context)

        _, _, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, (), state.state_version
        )

        frontier = SearchFrontierRepository(store)
        turns = frontier.investigator_turns(state.case_id, event.event_id)
        assert handled is True
        assert len(turns) == 1
        assert len(ranker.requests) == 1
        assert len(turns[0].offered_item_ids) == 2
        outcome = frontier.read_investigator_turn_outcome(turns[0].turn_id)
        assert outcome is not None and outcome.outcome == "gap"
        assert set(outcome.remaining_item_ids) == set(turns[0].offered_item_ids)
        assert outcome.frontier_item_ids == ()
        assert frontier.read_investigator_turn_closure(event.event_id) is not None
        assert frontier.active_investigator_session(state.case_id) is None
        assert (
            store.connection.execute(
                "SELECT COUNT(*) FROM search_frontier_transitions WHERE to_status=?",
                (FrontierStatus.SATISFIED.value,),
            ).fetchone()[0]
            == 0
        )


def test_retained_page_is_consumed_fifo_before_closing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "event-tail.db") as store:
        ranker = RecordingRanker()
        app = _app(store, ranker)
        state, event, _ = _started_with_event(app, store, count=3)
        original_context = app.context

        def focused(
            case_id: str, *, state: InvestigationState | None = None
        ) -> tuple[EvidenceContext, ...]:
            packet = original_context(case_id, state=state)
            selected = () if state is None else state.fast_catalog_selected_ids
            return tuple(item for item in packet if item.evidence_id in selected)

        monkeypatch.setattr(app, "context", focused)
        first, first_context, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, app.context(str(state.case_id)), state.state_version
        )
        frontier = SearchFrontierRepository(store)
        first_turn = frontier.investigator_turns(state.case_id, event.event_id)[0]
        first_outcome = frontier.read_investigator_turn_outcome(first_turn.turn_id)
        assert handled and first_outcome is not None
        assert first_outcome.outcome == "focused_delivery"
        assert len(first_outcome.remaining_item_ids) == 2
        assert frontier.active_investigator_session(state.case_id) is not None

        second, second_context, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            first, first_context, state.state_version
        )
        turns = frontier.investigator_turns(state.case_id, event.event_id)
        second_outcome = frontier.read_investigator_turn_outcome(turns[1].turn_id)
        assert handled and second_outcome is not None
        assert turns[1].pending_item_ids == first_outcome.remaining_item_ids
        assert turns[1].offered_item_ids == ()
        assert len(ranker.requests[1].items) == 1
        assert ranker.requests[1].items[0].item_id == first_outcome.remaining_item_ids[0]
        assert second_outcome.outcome == "focused_delivery"
        assert len(second_outcome.remaining_item_ids) == 1
        assert len(second_context) == 2
        assert len(second.fast_catalog_selected_ids) == 2

        third, third_context, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            second, second_context, state.state_version
        )
        third_turn = frontier.investigator_turns(state.case_id, event.event_id)[2]
        third_outcome = frontier.read_investigator_turn_outcome(third_turn.turn_id)
        assert handled and third_outcome is not None
        assert third_outcome.outcome == "focused_delivery"
        assert third_outcome.remaining_item_ids == ()
        assert len(third_context) == 3
        assert len(third.fast_catalog_selected_ids) == 3
        assert frontier.read_investigator_turn_closure(event.event_id) is not None
        assert frontier.active_investigator_session(state.case_id) is None
        assert store.connection.execute("SELECT COUNT(*) FROM probe_executions").fetchone()[0] == 0


def test_terminal_eligible_item_records_gap_without_provider_or_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "event-terminal.db") as store:
        ranker = RecordingRanker()
        app = _app(store, ranker)
        state, event, target = _started_with_event(app, store, count=1)
        before = _omit_until_selected(app, str(state.case_id), target, monkeypatch)
        frontier = SearchFrontierRepository(store)
        item = frontier.upsert_item(
            state.case_id,
            FrontierReferenceV1(kind="retrieve_evidence", evidence_id=target),
            RelevantVersionsV1(
                objective=1,
                evidence=event.versions.evidence,
                graph=app.knowledge.pack.version,  # type: ignore[union-attr]
            ),
        )
        frontier.transition(
            item.item_id, FrontierStatus.REQUESTED, FrontierStatus.OBSOLETE, "prior_terminal"
        )

        _, _, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, before, state.state_version
        )

        turns = frontier.investigator_turns(state.case_id, event.event_id)
        assert handled is True
        assert len(turns) == 1
        assert ranker.requests == []
        outcome = frontier.read_investigator_turn_outcome(turns[0].turn_id)
        assert outcome is not None and outcome.outcome == "gap"
        assert frontier.readback(item.item_id).status is FrontierStatus.OBSOLETE
        assert frontier.read_investigator_turn_closure(event.event_id) is not None
        assert store.connection.execute("SELECT COUNT(*) FROM probe_executions").fetchone()[0] == 0


def test_case_stop_closes_unresolved_turn_with_terminal_event_receipt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "event-case-stop.db") as store:
        ranker = RecordingRanker()
        app = _app(store, ranker)
        state, event, _ = _started_with_event(app, store, count=2)
        original_context = app.context

        def focused(
            case_id: str, *, state: InvestigationState | None = None
        ) -> tuple[EvidenceContext, ...]:
            packet = original_context(case_id, state=state)
            selected = () if state is None else state.fast_catalog_selected_ids
            return tuple(item for item in packet if item.evidence_id in selected)

        monkeypatch.setattr(app, "context", focused)
        first, _, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, (), state.state_version
        )
        assert handled
        frontier = SearchFrontierRepository(store)
        first_turn = frontier.investigator_turns(state.case_id, event.event_id)[0]
        first_outcome = frontier.read_investigator_turn_outcome(first_turn.turn_id)
        assert first_outcome is not None and first_outcome.remaining_item_ids
        assert frontier.active_investigator_session(state.case_id) is not None

        stopped = app._finish(  # pyright: ignore[reportPrivateUsage]
            first, InvestigationOutcome.BUDGET_EXHAUSTED, "Round budget ended."
        )

        closure = frontier.read_investigator_turn_closure(event.event_id)
        assert stopped.status is InvestigationStatus.COMPLETE
        assert closure is not None and closure.reason_code == "case_stopped"
        assert closure.terminal_checkpoint_version == stopped.state_version
        assert frontier.active_investigator_session(state.case_id) is None


def test_case_stop_closes_session_started_without_turn(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "event-no-turn-stop.db") as store:
        app = _app(store, RecordingRanker())
        state, event, _ = _started_with_event(app, store, count=1)
        frontier = SearchFrontierRepository(store)
        frontier.intake_investigator_event(state.case_id, event.event_id)
        frontier.start_investigator_session(state.case_id, event.event_id, decision_budget=8)

        stopped = app._finish(  # pyright: ignore[reportPrivateUsage]
            state, InvestigationOutcome.BUDGET_EXHAUSTED, "Round budget ended."
        )

        terminal = frontier.read_investigator_terminal(event.event_id)
        assert stopped.status is InvestigationStatus.COMPLETE
        assert terminal is not None and terminal.outcome == "gap"
        assert frontier.active_investigator_session(state.case_id) is None


def test_case_stop_after_source_loss_commits_terminal_checkpoint_and_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "event-source-stop.db") as store:
        app = _app(store, RecordingRanker())
        state, event, source_id = _started_with_event(app, store, count=2)
        original_context = app.context

        def focused(
            case_id: str, *, state: InvestigationState | None = None
        ) -> tuple[EvidenceContext, ...]:
            packet = original_context(case_id, state=state)
            selected = () if state is None else state.fast_catalog_selected_ids
            return tuple(item for item in packet if item.evidence_id in selected)

        monkeypatch.setattr(app, "context", focused)
        first, _, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, (), state.state_version
        )
        assert handled
        store.connection.execute("DELETE FROM evidence WHERE evidence_id=?", (str(source_id),))

        stopped = app._finish(  # pyright: ignore[reportPrivateUsage]
            first, InvestigationOutcome.BUDGET_EXHAUSTED, "Round budget ended."
        )

        frontier = SearchFrontierRepository(store)
        closure = frontier.read_investigator_turn_closure(event.event_id)
        assert stopped.status is InvestigationStatus.COMPLETE
        assert closure is not None and closure.reason_code == "source_unverifiable"
        assert frontier.active_investigator_session(state.case_id) is None


def test_catalog_generation_change_before_reservation_yields_without_dropping_event(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "event-discovery-race.db") as store:
        app = _app(store, RecordingRanker())
        state, event, _ = _started_with_event(app, store, count=1)
        monkeypatch.setattr(app, "context", _empty_context)
        from systemsense.application import investigator as investigator_module

        original_discover = investigator_module.discover_retrieval_page

        def racing_discover(**kwargs: Any):
            _insert_record(
                store,
                case_id=str(state.case_id),
                evidence_id=f"ev_{9991:032x}",
                collector_id="disk.health",
                summary="concurrent stored observation",
                observed_at=utc_now(),
            )
            return original_discover(**kwargs)

        monkeypatch.setattr(investigator_module, "discover_retrieval_page", racing_discover)
        unchanged, _, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, (), state.state_version
        )
        frontier = SearchFrontierRepository(store)
        assert handled and unchanged.state_version == state.state_version
        assert frontier.investigator_turns(state.case_id, event.event_id) == ()
        assert frontier.active_investigator_session(state.case_id) is not None


def test_deadline_crossing_at_reservation_yields_without_unowned_turn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "event-reserve-deadline.db") as store:
        ranker = RecordingRanker()
        app = _app(store, ranker)
        state, event, _ = _started_with_event(app, store, count=1)
        frontier = SearchFrontierRepository(store)
        original_reserve = SearchFrontierRepository.reserve_investigator_turn

        def racing_reserve(self: SearchFrontierRepository, *args: Any, **kwargs: Any):
            expired_at = kwargs["turn_deadline_at"] + timedelta(milliseconds=1)
            monkeypatch.setattr("systemsense.storage.search_frontier.utc_now", lambda: expired_at)
            return original_reserve(self, *args, **kwargs)

        monkeypatch.setattr(SearchFrontierRepository, "reserve_investigator_turn", racing_reserve)
        unchanged, _, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, app.context(str(state.case_id)), state.state_version
        )

        assert handled and unchanged.state_version == state.state_version
        assert frontier.investigator_turns(state.case_id, event.event_id) == ()
        assert frontier.active_investigator_session(state.case_id) is not None
        assert ranker.requests == []


def test_missing_source_before_first_turn_is_explicit_gap_without_model_call(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "event-source-missing.db") as store:
        ranker = RecordingRanker()
        app = _app(store, ranker)
        state, event, target = _started_with_event(app, store, count=1)
        store.connection.execute("DELETE FROM evidence WHERE evidence_id=?", (str(target),))

        updated, _, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, (), state.state_version
        )

        frontier = SearchFrontierRepository(store)
        terminal = frontier.read_investigator_terminal(event.event_id)
        assert handled and updated.state_version == state.state_version + 1
        assert terminal is not None and terminal.reason_code == "source_unverifiable"
        assert frontier.investigator_turns(state.case_id, event.event_id) == ()
        assert frontier.active_investigator_session(state.case_id) is None
        assert ranker.requests == []


def test_missing_source_after_completed_turn_closes_unresolved_tail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "event-source-after-turn.db") as store:
        ranker = RecordingRanker()
        app = _app(store, ranker)
        state, event, source_id = _started_with_event(app, store, count=2)
        original_context = app.context

        def focused(
            case_id: str, *, state: InvestigationState | None = None
        ) -> tuple[EvidenceContext, ...]:
            packet = original_context(case_id, state=state)
            selected = () if state is None else state.fast_catalog_selected_ids
            return tuple(item for item in packet if item.evidence_id in selected)

        monkeypatch.setattr(app, "context", focused)
        first, first_context, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, app.context(str(state.case_id)), state.state_version
        )
        frontier = SearchFrontierRepository(store)
        first_turn = frontier.investigator_turns(state.case_id, event.event_id)[0]
        first_outcome = frontier.read_investigator_turn_outcome(first_turn.turn_id)
        assert handled and first_outcome is not None and first_outcome.remaining_item_ids
        store.connection.execute("DELETE FROM evidence WHERE evidence_id=?", (str(source_id),))

        updated, _, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            first, first_context, state.state_version
        )

        closure = frontier.read_investigator_turn_closure(event.event_id)
        assert handled and updated.state_version == first.state_version + 1
        assert closure is not None and closure.reason_code == "source_unverifiable"
        assert frontier.active_investigator_session(state.case_id) is None
        assert len(ranker.requests) == 1


def test_missing_pending_catalog_row_records_stale_gap_without_replaying_model(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "event-pending-missing.db") as store:
        ranker = RecordingRanker()
        app = _app(store, ranker)
        state, event, source_id = _started_with_event(app, store, count=3)
        original_context = app.context

        def focused(
            case_id: str, *, state: InvestigationState | None = None
        ) -> tuple[EvidenceContext, ...]:
            packet = original_context(case_id, state=state)
            selected = () if state is None else state.fast_catalog_selected_ids
            return tuple(item for item in packet if item.evidence_id in selected)

        monkeypatch.setattr(app, "context", focused)
        first, first_context, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, (), state.state_version
        )
        frontier = SearchFrontierRepository(store)
        first_turn = frontier.investigator_turns(state.case_id, event.event_id)[0]
        first_outcome = frontier.read_investigator_turn_outcome(first_turn.turn_id)
        assert handled and first_outcome is not None and first_outcome.remaining_item_ids
        missing_id = next(
            frontier.readback(item_id).reference.evidence_id
            for item_id in first_outcome.remaining_item_ids
            if frontier.readback(item_id).reference.evidence_id != source_id
        )
        assert missing_id is not None
        store.connection.execute("DELETE FROM evidence WHERE evidence_id=?", (str(missing_id),))

        updated, _, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            first, first_context, state.state_version
        )

        turns = frontier.investigator_turns(state.case_id, event.event_id)
        outcome = frontier.read_investigator_turn_outcome(turns[-1].turn_id)
        assert handled and updated.state_version == first.state_version + 1
        assert len(turns) == 2 and outcome is not None
        assert outcome.outcome == "gap" and outcome.reason_code == "stale_context"
        assert outcome.remaining_item_ids == first_outcome.remaining_item_ids
        assert frontier.read_investigator_turn_closure(event.event_id) is not None
        assert len(ranker.requests) == 1


def test_source_lost_during_ranking_is_not_reported_as_provider_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "event-source-rank-race.db") as store:
        ranker = RecordingRanker()
        app = _app(store, ranker)
        state, event, source_id = _started_with_event(app, store, count=1)
        monkeypatch.setattr(app, "context", _empty_context)
        original_rank = ranker.rank

        def rank_then_lose_source(request: FrontierRankRequestV1) -> FrontierRankResponseV1:
            result = original_rank(request)
            store.connection.execute("DELETE FROM evidence WHERE evidence_id=?", (str(source_id),))
            return result

        monkeypatch.setattr(ranker, "rank", rank_then_lose_source)
        updated, _, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, (), state.state_version
        )

        frontier = SearchFrontierRepository(store)
        turn = frontier.investigator_turns(state.case_id, event.event_id)[0]
        outcome = frontier.read_investigator_turn_outcome(turn.turn_id)
        assert handled and updated.state_version == state.state_version + 1
        assert outcome is not None and outcome.outcome == "gap"
        assert outcome.reason_code == "source_unverifiable"
        assert outcome.remaining_item_ids == turn.offered_item_ids
        assert frontier.active_investigator_session(state.case_id) is None


def test_source_lost_at_checkpoint_rolls_back_focused_delivery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "event-source-save-race.db") as store:
        app = _app(store, RecordingRanker())
        state, event, source_id = _started_with_event(app, store, count=1)
        original_context = app.context

        def focused(
            case_id: str, *, state: InvestigationState | None = None
        ) -> tuple[EvidenceContext, ...]:
            packet = original_context(case_id, state=state)
            selected = () if state is None else state.fast_catalog_selected_ids
            return tuple(item for item in packet if item.evidence_id in selected)

        monkeypatch.setattr(app, "context", focused)
        original_save = app._save  # pyright: ignore[reportPrivateUsage]
        raced = False

        def racing_save(*args: Any, **kwargs: Any) -> InvestigationState:
            nonlocal raced
            completion = kwargs.get("frontier_turn_completion")
            if completion is not None and completion.outcome == "focused_delivery" and not raced:
                raced = True
                store.connection.execute(
                    "DELETE FROM evidence WHERE evidence_id=?", (str(source_id),)
                )
            return original_save(*args, **kwargs)

        monkeypatch.setattr(app, "_save", racing_save)
        updated, _, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, app.context(str(state.case_id)), state.state_version
        )

        frontier = SearchFrontierRepository(store)
        turn = frontier.investigator_turns(state.case_id, event.event_id)[0]
        outcome = frontier.read_investigator_turn_outcome(turn.turn_id)
        assert handled and raced and outcome is not None
        assert outcome.outcome == "gap" and outcome.reason_code == "source_unverifiable"
        assert outcome.remaining_item_ids == turn.offered_item_ids
        assert updated.fast_catalog_selected_ids == ()
        assert frontier.readback(turn.offered_item_ids[0]).status is FrontierStatus.OBSOLETE
        assert frontier.active_investigator_session(state.case_id) is None


def test_generation_change_at_checkpoint_rolls_back_success_and_records_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "event-save-race.db") as store:
        app = _app(store, RecordingRanker())
        state, event, _ = _started_with_event(app, store, count=1)
        original_context = app.context

        def focused(
            case_id: str, *, state: InvestigationState | None = None
        ) -> tuple[EvidenceContext, ...]:
            packet = original_context(case_id, state=state)
            selected = () if state is None else state.fast_catalog_selected_ids
            return tuple(item for item in packet if item.evidence_id in selected)

        monkeypatch.setattr(app, "context", focused)
        original_save = app._save  # pyright: ignore[reportPrivateUsage]
        raced = False

        def racing_save(*args: Any, **kwargs: Any) -> InvestigationState:
            nonlocal raced
            completion = kwargs.get("frontier_turn_completion")
            if completion is not None and completion.outcome == "focused_delivery" and not raced:
                raced = True
                _insert_record(
                    store,
                    case_id=str(state.case_id),
                    evidence_id=f"ev_{9992:032x}",
                    collector_id="disk.health",
                    summary="late stored observation",
                    observed_at=utc_now(),
                )
            return original_save(*args, **kwargs)

        monkeypatch.setattr(app, "_save", racing_save)
        updated, _, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, app.context(str(state.case_id)), state.state_version
        )

        frontier = SearchFrontierRepository(store)
        turn = frontier.investigator_turns(state.case_id, event.event_id)[0]
        outcome = frontier.read_investigator_turn_outcome(turn.turn_id)
        assert handled and raced
        assert outcome is not None and outcome.outcome == "gap"
        assert outcome.reason_code == "stale_context"
        assert outcome.remaining_item_ids == turn.offered_item_ids
        assert updated.fast_catalog_selected_ids == ()
        assert frontier.readback(turn.offered_item_ids[0]).status is FrontierStatus.OBSOLETE
        assert frontier.read_investigator_turn_closure(event.event_id) is not None


def test_expired_session_with_retained_tail_releases_active_slot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "event-session-expiry.db") as store:
        app = _app(store, RecordingRanker())
        state, event, _ = _started_with_event(app, store, count=2)
        original_context = app.context

        def focused(
            case_id: str, *, state: InvestigationState | None = None
        ) -> tuple[EvidenceContext, ...]:
            packet = original_context(case_id, state=state)
            selected = () if state is None else state.fast_catalog_selected_ids
            return tuple(item for item in packet if item.evidence_id in selected)

        monkeypatch.setattr(app, "context", focused)
        first, first_context, _ = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, app.context(str(state.case_id)), state.state_version
        )
        frontier = SearchFrontierRepository(store)
        active = frontier.active_investigator_session(state.case_id)
        assert active is not None
        expired_at = active.deadline_at + timedelta(seconds=1)
        monkeypatch.setattr("systemsense.application.investigator.utc_now", lambda: expired_at)
        monkeypatch.setattr("systemsense.storage.search_frontier.utc_now", lambda: expired_at)

        updated, _, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            first, first_context, state.state_version
        )

        closure = frontier.read_investigator_turn_closure(event.event_id)
        assert handled and updated.state_version == first.state_version + 1
        assert closure is not None and closure.reason_code == "deadline_expired"
        assert frontier.active_investigator_session(state.case_id) is None


def test_expiry_after_source_loss_records_source_gap_and_releases_slot(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "event-source-expiry.db") as store:
        app = _app(store, RecordingRanker())
        state, event, source_id = _started_with_event(app, store, count=2)
        original_context = app.context

        def focused(
            case_id: str, *, state: InvestigationState | None = None
        ) -> tuple[EvidenceContext, ...]:
            packet = original_context(case_id, state=state)
            selected = () if state is None else state.fast_catalog_selected_ids
            return tuple(item for item in packet if item.evidence_id in selected)

        monkeypatch.setattr(app, "context", focused)
        first, _, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, (), state.state_version
        )
        assert handled
        frontier = SearchFrontierRepository(store)
        active = frontier.active_investigator_session(state.case_id)
        assert active is not None
        store.connection.execute("DELETE FROM evidence WHERE evidence_id=?", (str(source_id),))
        expired_at = active.deadline_at + timedelta(seconds=1)
        monkeypatch.setattr("systemsense.application.investigator.utc_now", lambda: expired_at)
        monkeypatch.setattr("systemsense.storage.search_frontier.utc_now", lambda: expired_at)

        updated = app._expire_event_frontier_session(  # pyright: ignore[reportPrivateUsage]
            first, frontier, event.event_id
        )

        closure = frontier.read_investigator_turn_closure(event.event_id)
        assert updated.state_version == first.state_version + 1
        assert closure is not None and closure.reason_code == "source_unverifiable"
        assert frontier.active_investigator_session(state.case_id) is None


def test_owner_recovery_after_source_loss_closes_uncertain_turn_as_gap(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "event-source-recovery.db") as store:
        app = _app(store, RecordingRanker())
        state, event, source_id = _started_with_event(app, store, count=1)
        frontier = SearchFrontierRepository(store)
        frontier.intake_investigator_event(state.case_id, event.event_id)
        session = frontier.start_investigator_session(
            state.case_id, event.event_id, decision_budget=8
        )
        generation_row = store.connection.execute(
            "SELECT generation FROM evidence_case_generations WHERE case_id=?",
            (str(state.case_id),),
        ).fetchone()
        assert generation_row is not None
        turn = frontier.reserve_investigator_turn(
            state.case_id,
            event.event_id,
            owner_started_version=state.state_version,
            expected_checkpoint_version=state.state_version,
            current_versions=RelevantVersionsV1(
                objective=1,
                evidence=int(generation_row[0]),
                graph=app.knowledge.pack.version if app.knowledge is not None else None,
            ),
            focused_context_sha256="a" * 64,
            catalog_generation=int(generation_row[0]),
            cursor_before=None,
            cursor_after=None,
            offered_refs=(),
            pending_tail=(),
            offered_item_ids=(),
            pending_item_ids=(),
            eligible_evidence_ids=(),
            turn_deadline_at=min(state.deadline_at, session.deadline_at),
        )
        app._save(  # pyright: ignore[reportPrivateUsage]
            state.model_copy(update={"status": InvestigationStatus.QUEUED}),
            "interrupted",
            "Previous owner ended before attention completed.",
        )
        store.connection.execute("DELETE FROM evidence WHERE evidence_id=?", (str(source_id),))
        cancelled = threading.Event()
        cancelled.set()

        app.run(str(state.case_id), cancel_event=cancelled)

        outcome = frontier.read_investigator_turn_outcome(turn.turn_id)
        closure = frontier.read_investigator_turn_closure(event.event_id)
        assert outcome is not None and outcome.outcome == "interrupted"
        assert closure is not None and closure.reason_code == "source_unverifiable"
        assert frontier.active_investigator_session(state.case_id) is None


def test_deadline_crossed_during_checkpoint_save_records_gap_not_success(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "event-save-deadline.db") as store:
        app = _app(store, RecordingRanker())
        state, event, _ = _started_with_event(app, store, count=1)
        original_context = app.context

        def focused(
            case_id: str, *, state: InvestigationState | None = None
        ) -> tuple[EvidenceContext, ...]:
            packet = original_context(case_id, state=state)
            selected = () if state is None else state.fast_catalog_selected_ids
            return tuple(item for item in packet if item.evidence_id in selected)

        monkeypatch.setattr(app, "context", focused)
        original_save = app._save  # pyright: ignore[reportPrivateUsage]
        frontier = SearchFrontierRepository(store)
        delayed = False

        def delayed_save(*args: Any, **kwargs: Any) -> InvestigationState:
            nonlocal delayed
            completion = kwargs.get("frontier_turn_completion")
            if completion is not None and completion.outcome == "focused_delivery" and not delayed:
                delayed = True
                turn = frontier.read_investigator_turn(completion.turn_id)
                expired_at = turn.deadline_at + timedelta(milliseconds=1)
                monkeypatch.setattr(
                    "systemsense.storage.search_frontier.utc_now", lambda: expired_at
                )
            return original_save(*args, **kwargs)

        monkeypatch.setattr(app, "_save", delayed_save)
        updated, _, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, app.context(str(state.case_id)), state.state_version
        )

        turn = frontier.investigator_turns(state.case_id, event.event_id)[0]
        outcome = frontier.read_investigator_turn_outcome(turn.turn_id)
        assert handled and delayed
        assert outcome is not None and outcome.reason_code == "deadline_expired"
        assert outcome.outcome == "gap" and outcome.frontier_item_ids == ()
        assert updated.fast_catalog_selected_ids == ()
        assert frontier.readback(turn.offered_item_ids[0]).status is FrontierStatus.OBSOLETE
        assert frontier.read_investigator_turn_closure(event.event_id) is not None


def test_new_event_at_case_turn_cap_gets_explicit_no_turn_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "event-case-cap.db") as store:
        app = _app(store, RecordingRanker())
        state, event, _ = _started_with_event(app, store, count=1)
        monkeypatch.setattr("systemsense.storage.search_frontier._INVESTIGATOR_CASE_TURN_LIMIT", 0)

        updated, _, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, app.context(str(state.case_id)), state.state_version
        )

        frontier = SearchFrontierRepository(store)
        terminal = frontier.read_investigator_terminal(event.event_id)
        assert handled and updated.state_version == state.state_version + 1
        assert terminal is not None and terminal.reason_code == "budget_exhausted"
        assert frontier.investigator_turns(state.case_id, event.event_id) == ()
        assert frontier.active_investigator_session(state.case_id) is None


def test_generation_change_with_unresolved_cursor_closes_stale_gap(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "event-cursor-stale.db") as store:
        app = _app(store, RecordingRanker())
        state, event, _ = _started_with_event(app, store, count=9)
        initial_context = app.context(str(state.case_id))
        first, _, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, initial_context, state.state_version
        )
        frontier = SearchFrontierRepository(store)
        first_turn = frontier.investigator_turns(state.case_id, event.event_id)[0]
        first_outcome = frontier.read_investigator_turn_outcome(first_turn.turn_id)
        assert handled and first_outcome is not None
        assert first_outcome.outcome == "no_new_fact"
        assert first_outcome.cursor_after is not None

        _insert_record(
            store,
            case_id=str(state.case_id),
            evidence_id=f"ev_{9993:032x}",
            collector_id="disk.health",
            summary="new generation before cursor continuation",
            observed_at=utc_now(),
        )
        _, _, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            first, initial_context, state.state_version
        )

        second_turn = frontier.investigator_turns(state.case_id, event.event_id)[1]
        second_outcome = frontier.read_investigator_turn_outcome(second_turn.turn_id)
        assert handled and second_turn.stale_pending_only
        assert second_outcome is not None and second_outcome.outcome == "gap"
        assert second_outcome.reason_code == "stale_context"
        assert frontier.read_investigator_turn_closure(event.event_id) is not None
        assert frontier.active_investigator_session(state.case_id) is None


def test_refreshed_pending_tail_restarts_catalog_at_head_after_drain(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "event-refresh-restart.db") as store:
        ranker = RecordingRanker()
        app = _app(store, ranker)
        state, event, _ = _started_with_event(app, store, count=9)
        originally_visible = {f"ev_{index:032x}" for index in range(1, 7)}
        original_context = app.context

        def focused(
            case_id: str, *, state: InvestigationState | None = None
        ) -> tuple[EvidenceContext, ...]:
            packet = original_context(case_id, state=state)
            selected = () if state is None else state.fast_catalog_selected_ids
            return tuple(
                item
                for item in packet
                if str(item.evidence_id) in originally_visible or item.evidence_id in selected
            )

        monkeypatch.setattr(app, "context", focused)
        first, context, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, app.context(str(state.case_id)), state.state_version
        )
        frontier = SearchFrontierRepository(store)
        turns = frontier.investigator_turns(state.case_id, event.event_id)
        first_outcome = frontier.read_investigator_turn_outcome(turns[0].turn_id)
        assert handled and first_outcome is not None
        assert first_outcome.outcome == "focused_delivery"
        assert len(first_outcome.remaining_item_ids) == 1
        assert first_outcome.cursor_after is not None

        inserted = EvidenceId(root=f"ev_{9993:032x}")
        _insert_record(
            store,
            case_id=str(state.case_id),
            evidence_id=str(inserted),
            collector_id="disk.health",
            summary="new record ahead of prior cursor",
            observed_at=utc_now(),
        )
        second, context, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            first, context, state.state_version
        )
        turns = frontier.investigator_turns(state.case_id, event.event_id)
        second_outcome = frontier.read_investigator_turn_outcome(turns[1].turn_id)
        assert handled and second_outcome is not None
        assert turns[1].schema_version == 2
        assert second_outcome.outcome == "focused_delivery"
        assert second_outcome.remaining_item_ids == ()
        assert second_outcome.cursor_after is None
        assert frontier.active_investigator_session(state.case_id) is not None

        third, context, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            second, context, state.state_version
        )
        turns = frontier.investigator_turns(state.case_id, event.event_id)
        third_outcome = frontier.read_investigator_turn_outcome(turns[2].turn_id)
        assert handled and third_outcome is not None
        assert turns[2].cursor_before is None
        assert third_outcome.outcome == "focused_delivery"
        assert inserted in third.fast_catalog_selected_ids
        assert str(inserted) in {str(item.evidence_id) for item in context}


def test_pending_refresh_capacity_records_gap_without_obsoleting_old_tail(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "event-refresh-capacity.db") as store:
        ranker = RecordingRanker()
        app = _app(store, ranker)
        state, event, _ = _started_with_event(app, store, count=3)
        original_context = app.context

        def focused(
            case_id: str, *, state: InvestigationState | None = None
        ) -> tuple[EvidenceContext, ...]:
            packet = original_context(case_id, state=state)
            selected = () if state is None else state.fast_catalog_selected_ids
            return tuple(item for item in packet if item.evidence_id in selected)

        monkeypatch.setattr(app, "context", focused)
        first, context, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, app.context(str(state.case_id)), state.state_version
        )
        frontier = SearchFrontierRepository(store)
        first_turn = frontier.investigator_turns(state.case_id, event.event_id)[0]
        first_outcome = frontier.read_investigator_turn_outcome(first_turn.turn_id)
        assert handled and first_outcome is not None
        assert len(first_outcome.remaining_item_ids) == 2
        _insert_record(
            store,
            case_id=str(state.case_id),
            evidence_id=f"ev_{9994:032x}",
            collector_id="disk.health",
            summary="new generation before refresh capacity",
            observed_at=utc_now(),
        )
        reference = frontier.readback(first_outcome.remaining_item_ids[0]).reference
        next_objective = 2
        while True:
            count = store.connection.execute(
                "SELECT COUNT(*) FROM search_frontier_items WHERE case_id=?",
                (str(state.case_id),),
            ).fetchone()
            assert count is not None
            if int(count[0]) == 128:
                break
            frontier.upsert_item(
                state.case_id,
                reference,
                RelevantVersionsV1(objective=next_objective, evidence=1),
            )
            next_objective += 1

        updated, _, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            first, context, state.state_version
        )
        turns = frontier.investigator_turns(state.case_id, event.event_id)
        outcome = frontier.read_investigator_turn_outcome(turns[1].turn_id)
        assert handled and outcome is not None and outcome.outcome == "gap"
        assert outcome.reason_code == "stale_context"
        assert outcome.remaining_item_ids == first_outcome.remaining_item_ids
        assert all(
            frontier.readback(item_id).status is FrontierStatus.REQUESTED
            for item_id in first_outcome.remaining_item_ids
        )
        assert any("lacked item capacity" in warning for warning in updated.warnings)
        assert len(ranker.requests) == 1


def test_failed_focused_readback_obsoletes_item_and_records_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "event-focus-gap.db") as store:
        ranker = RecordingRanker()
        app = _app(store, ranker)
        state, event, target = _started_with_event(app, store, count=1)
        before = _omit_until_selected(app, str(state.case_id), target, monkeypatch)
        monkeypatch.setattr(app, "context", _empty_context)

        updated, after, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, before, state.state_version
        )

        frontier = SearchFrontierRepository(store)
        turn = frontier.investigator_turns(state.case_id, event.event_id)[0]
        outcome = frontier.read_investigator_turn_outcome(turn.turn_id)
        assert handled is True
        assert after == before
        assert target not in updated.fast_catalog_selected_ids
        assert outcome is not None and outcome.outcome == "gap"
        assert len(turn.offered_item_ids) == 1
        assert frontier.readback(turn.offered_item_ids[0]).status is FrontierStatus.OBSOLETE
        assert frontier.read_investigator_turn_closure(event.event_id) is not None


def test_page_capacity_short_by_one_never_partially_persists_or_advances_cursor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "event-capacity.db") as store:
        ranker = RecordingRanker()
        app = _app(store, ranker)
        state, event, _ = _started_with_event(app, store, count=2)
        monkeypatch.setattr(app, "context", _empty_context)
        monkeypatch.setattr("systemsense.storage.search_frontier._ITEM_LIMIT", 1)

        _, _, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
            state, (), state.state_version
        )

        frontier = SearchFrontierRepository(store)
        turns = frontier.investigator_turns(state.case_id, event.event_id)
        assert handled is True
        assert len(turns) == 1
        assert turns[0].cursor_before is None
        assert turns[0].cursor_after is None
        outcome = frontier.read_investigator_turn_outcome(turns[0].turn_id)
        assert outcome is not None and outcome.outcome == "gap"
        assert frontier.read_investigator_turn_closure(event.event_id) is not None
        assert ranker.requests == []
        assert (
            store.connection.execute("SELECT COUNT(*) FROM search_frontier_items").fetchone()[0]
            == 0
        )


def test_ordinary_run_mounts_one_event_turn_per_attention_iteration(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "event-run.db") as store:
        ranker = RecordingRanker()
        app = _app(store, ranker)
        state = app.create(
            objective="Investigate a recent disk observation",
            budget_ms=10_000,
            max_rounds=1,
        )
        target = _fill_case(store, str(state.case_id), count=1, target_index=1)
        generation = store.connection.execute(
            "SELECT generation FROM evidence_case_generations WHERE case_id=?",
            (str(state.case_id),),
        ).fetchone()
        assert generation is not None
        frontier = SearchFrontierRepository(store)
        with store.transaction():
            event = frontier.append_result_event(
                state.case_id,
                source_evidence_id=target,
                source_execution_id=None,
                versions=RelevantVersionsV1(objective=1, evidence=int(generation[0])),
            )
        assert isinstance(event, FrontierEventV1)

        app.run(str(state.case_id))

        turns = frontier.investigator_turns(state.case_id, event.event_id)
        assert len(turns) == 1
        assert frontier.read_investigator_turn_outcome(turns[0].turn_id) is not None
        assert frontier.read_investigator_turn_closure(event.event_id) is not None


def test_event_attention_is_off_without_opt_in_ranker(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "event-default-off.db") as store:
        app = investigator(store)
        state = app.create(objective="Investigate a recent disk observation", budget_ms=10_000)
        target = _fill_case(store, str(state.case_id), count=1, target_index=1)
        generation = store.connection.execute(
            "SELECT generation FROM evidence_case_generations WHERE case_id=?",
            (str(state.case_id),),
        ).fetchone()
        assert generation is not None
        frontier = SearchFrontierRepository(store)
        with store.transaction():
            event = frontier.append_result_event(
                state.case_id,
                source_evidence_id=target,
                source_execution_id=None,
                versions=RelevantVersionsV1(objective=1, evidence=int(generation[0])),
            )
        assert isinstance(event, FrontierEventV1)

        app.run(str(state.case_id))

        assert app.frontier_ranker is None
        assert frontier.pending_investigator_events(state.case_id)
        assert frontier.pending_investigator_triggers(state.case_id) == ()
        assert frontier.active_investigator_session(state.case_id) is None
