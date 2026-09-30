"""Synthetic source-custody tests for generic exact-process Laya selection."""

from collections.abc import Callable
from datetime import datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from systemsense.application.bootstrap import default_investigator
from systemsense.application.investigation_state import InvestigationState, InvestigationStatus
from systemsense.application.investigator import Investigator
from systemsense.application.runtime import PersistedProbeResult
from systemsense.application.targets import ProcessTargetRepository
from systemsense.decision.contracts import ProbeProposal, ProviderIdentity
from systemsense.decision.frontier_ranker import (
    FrontierRankRequestV1,
    FrontierRankResponseV1,
    MixedFrontierRanker,
)
from systemsense.decision.laya import LayaDecisionProvider
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
from systemsense.domain.time import utc_now
from systemsense.inference.laya_runtime import (
    LayaAttentionResult,
    LayaRanker,
    LayaWorkerPresentation,
)
from systemsense.knowledge.catalog import ReferenceKnowledgeGraph
from systemsense.orchestration.probes import ProbeDefinition, ProbeObservation, ProbeRunner
from systemsense.packs.runtime import TargetPressureParametersV1, default_probe_runner
from systemsense.storage.candidate_decision_snapshots import CandidateDecisionSnapshotRepository
from systemsense.storage.followup_admissions import FollowupAdmissionRepository
from systemsense.storage.sqlite_store import SQLiteStore


def _application_snapshot(
    store: SQLiteStore,
    case_id: CaseId,
    at: datetime,
    *,
    processes: list[dict[str, JsonValue]],
) -> None:
    evidence_id = EvidenceId.new()
    execution_id = ExecutionId.new()
    source_id = stable_source_id(
        "systemsense.probe", {"probe_id": "application.snapshot", "probe_version": 1}
    )
    facts: dict[str, JsonValue] = {
        "collection_started_at": (at - timedelta(seconds=1)).isoformat(),
        "collection_completed_at": at.isoformat(),
        "collection_status": "available",
        "omitted_counts": {"processes": 0, "services": 0, "startup": 0},
        "processes": cast(JsonValue, processes),
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
            locator={"probe_id": "application.snapshot"},
        ),
        collector=CollectorReference(
            id="application.snapshot", version=1, execution_id=execution_id
        ),
        summary="Synthetic application inventory",
        facts=tuple(EvidenceFact(name=name, value=value) for name, value in facts.items()),
        extraction=Extraction(confidence=1, parser="builtin.probe", parser_version=1),
        sensitivity=Sensitivity.SYSTEM_METADATA,
    )
    with store.transaction() as transaction:
        transaction.record_probe_execution(
            execution_id=str(execution_id),
            case_id=str(case_id),
            probe_id="application.snapshot",
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


class _UnusedLayaProbeRanker:
    def attend(
        self,
        *,
        state: dict[str, object],
        evidence: tuple[dict[str, str], ...],
        candidates: tuple[dict[str, str], ...],
        timeout_seconds: float,
    ) -> LayaAttentionResult:
        raise AssertionError("main Laya probe route should be owned by mixed frontier")


class _SyntheticFrontierRanker(MixedFrontierRanker):
    request: FrontierRankRequestV1 | None = None
    requests: list[FrontierRankRequestV1]
    select_pressure: bool

    def __init__(self, *, select_pressure: bool) -> None:
        super().__init__(
            ranker=None,
            provider=ProviderIdentity(
                provider_id="synthetic-frontier", provider_version="1", role="fast_decision"
            ),
            model_weight_sha256="a" * 64,
        )
        self.select_pressure = select_pressure
        self.requests = []

    def rank(
        self,
        request: FrontierRankRequestV1,
        *,
        capture_worker_batch: Callable[[str, int, dict[str, object], LayaWorkerPresentation], None]
        | None = None,
    ) -> FrontierRankResponseV1:
        self.request = request
        self.requests.append(request)
        fallback = super().rank(request, capture_worker_batch=capture_worker_batch)
        if not self.select_pressure:
            return fallback
        ids = tuple(
            item.item_id for item in request.items if item.reference.kind == "measure"
        ) + tuple(item.item_id for item in request.items if item.reference.kind != "measure")
        return fallback.model_copy(
            update={
                "ranked_item_ids": ids,
                "considered_item_ids": tuple(item.item_id for item in request.items),
                "ranking_source": "laya",
                "model_abstained": False,
                "coverage_complete": True,
                "degraded_reason": None,
            }
        )


def _generic_case(
    store: SQLiteStore,
    *,
    max_probes: int,
    objective: str = "Is viewer.exe monopolizing a core during a short sample?",
    processes: list[dict[str, JsonValue]] | None = None,
) -> tuple[Investigator, InvestigationState]:
    app = default_investigator(store)
    state = app.create(objective=objective)
    at = state.created_at
    created = (at - timedelta(minutes=1)).isoformat()
    _application_snapshot(
        store,
        state.case_id,
        at,
        processes=processes
        or [
            {
                "pid": 4242,
                "ppid": 1,
                "name": "viewer.exe",
                "creation_time": created,
                "identity": f"4242@{created}",
            }
        ],
    )
    state = app.repository.save(
        state.model_copy(
            update={"completed_probe_ids": ("application.snapshot",), "max_probes": max_probes}
        ),
        expected_version=state.state_version,
        event="synthetic_inventory_ready",
        detail="One synthetic exact-name process inventory is available.",
    )
    return app, state


def _large_target_inventory(at: datetime) -> list[dict[str, JsonValue]]:
    created = (at - timedelta(minutes=2)).isoformat()
    processes: list[dict[str, JsonValue]] = [
        {
            "pid": pid,
            "ppid": 1,
            "name": f"worker-{pid}.exe",
            "creation_time": created,
            "identity": f"{pid}@{created}",
        }
        for pid in range(1, 101)
    ]
    target_birth = (at - timedelta(hours=2)).isoformat()
    processes.append(
        {
            "pid": 57_900,
            "ppid": 1,
            "name": "viewer.exe",
            "creation_time": target_birth,
            "identity": f"57900@{target_birth}",
        }
    )
    return processes


@pytest.mark.parametrize(
    ("objective", "expected"),
    (
        ("Is viewer.exe monopolizing a core?", "viewer.exe"),
        ("Is viewer.exe using CPU while the PDF is slow?", "viewer.exe"),
        ("Is viewer.exe slow in the PDF viewer?", None),
        ("Is viewer.exe running?", None),
    ),
    ids=("generic-pressure", "explicit-cpu-over-pdf", "broad-pdf", "pure-liveness"),
)
def test_shared_exact_streaming_eligibility_preserves_question_precedence(
    objective: str, expected: str | None
) -> None:
    from systemsense.application.exact_process_sampling import exact_process_streaming_name

    assert exact_process_streaming_name(objective) == expected


@pytest.mark.parametrize(
    "objective",
    (
        "Is viewer.exe monopolizing a core during a short sample?",
        "Is viewer.exe using CPU while the PDF is slow?",
    ),
    ids=("generic-pressure", "explicit-cpu-over-pdf"),
)
def test_prebound_frontier_dispatch_uses_unique_target_beyond_display_menu(
    tmp_path: Path, objective: str
) -> None:
    with SQLiteStore(tmp_path / "prebound-beyond-display-menu.db") as store:
        store.initialize()
        app, state = _generic_case(
            store,
            max_probes=2,
            objective=objective,
            processes=_large_target_inventory(utc_now()),
        )
        calls: list[dict[str, JsonValue]] = []
        _install_pressure_runner(app, calls)
        ranker = _set_frontier_owner(app, select_pressure=True)

        finished = app.run(str(state.case_id))

        assert ranker.request is not None
        measure_items = [item for item in ranker.request.items if item.reference.kind == "measure"]
        assert len(measure_items) == 1
        target = ProcessTargetRepository(store).selected_process_target(state.case_id)
        assert target is not None and target.name == "viewer.exe"
        assert target.pid == 57_900
        assert calls == [
            {
                "pid": 57_900,
                "creation_time": target.creation_time.isoformat().replace("+00:00", "Z"),
            }
        ]
        assert finished.completed_probe_ids.count("application.target_pressure") == 1


def test_prebound_frontier_decline_does_not_force_target_beyond_display_menu(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "prebound-beyond-display-menu-declined.db") as store:
        store.initialize()
        app, state = _generic_case(
            store,
            max_probes=2,
            processes=_large_target_inventory(utc_now()),
        )
        calls: list[dict[str, JsonValue]] = []
        _install_pressure_runner(app, calls)
        ranker = _set_frontier_owner(app, select_pressure=False)

        def no_main_proposals(
            _proposals: tuple[ProbeProposal, ...],
            _state: InvestigationState,
            _remaining: int,
            *,
            batch_limit: int | None = None,
        ) -> tuple[ProbeProposal, ...]:
            return ()

        monkeypatch.setattr(app, "_eligible", no_main_proposals)
        finished = app.run(str(state.case_id))

        assert ranker.request is not None
        assert any(
            item.reference.kind == "measure"
            for request in ranker.requests
            for item in request.items
        )
        assert not calls
        assert "application.target_pressure" not in finished.completed_probe_ids
        assert store.connection.execute(
            "SELECT COUNT(*) FROM probe_executions WHERE case_id=? "
            "AND probe_id='application.target_pressure'",
            (str(state.case_id),),
        ).fetchone() == (0,)


def _install_pressure_runner(app: Investigator, calls: list[dict[str, JsonValue]]) -> None:
    manifest = default_probe_runner().manifest("application.target_pressure")
    assert manifest is not None

    def observe(parameters: dict[str, JsonValue]) -> ProbeObservation:
        calls.append(parameters)
        now = utc_now()
        return ProbeObservation(
            summary="Synthetic bounded identity-bound pressure sample",
            facts={"pid": parameters["pid"], "logical_cores": 0.0},
            observed_at=now,
            captured_at=now,
        )

    app.runtime._probe_runner = ProbeRunner(  # pyright: ignore[reportPrivateUsage]
        definitions=(
            ProbeDefinition(
                manifest=manifest,
                parameter_model=TargetPressureParametersV1,
                handler=observe,
                isolated=False,
            ),
        )
    )


def _set_frontier_owner(app: Investigator, *, select_pressure: bool) -> _SyntheticFrontierRanker:
    app.decision = LayaDecisionProvider(ranker=cast(LayaRanker, _UnusedLayaProbeRanker()))
    ranker = _SyntheticFrontierRanker(select_pressure=select_pressure)
    app.frontier_ranker = ranker
    app.knowledge = ReferenceKnowledgeGraph.load_default()
    return ranker


def test_laya_frontier_exact_process_candidate_is_source_frozen_and_linked(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "generic-frontier-selected.db") as store:
        store.initialize()
        app, state = _generic_case(store, max_probes=2)
        calls: list[dict[str, JsonValue]] = []
        _install_pressure_runner(app, calls)
        ranker = _set_frontier_owner(app, select_pressure=True)

        finished = app.run(str(state.case_id))

        assert ranker.request is not None
        measure_ids = tuple(
            item.reference.candidate_id
            for item in ranker.request.items
            if item.reference.kind == "measure"
        )
        assert len(measure_ids) == 1
        selected_binding = ProcessTargetRepository(store).selected_process_target(state.case_id)
        assert selected_binding is not None
        assert store.connection.execute(
            "SELECT target_handle FROM case_measurement_candidates WHERE candidate_id=?",
            (measure_ids[0],),
        ).fetchone() == (selected_binding.candidate_id,)
        assert calls and calls[0]["pid"] == 4242
        row = store.connection.execute(
            "SELECT s.snapshot_id FROM candidate_decision_execution_links AS l "
            "JOIN candidate_decision_snapshots AS s ON s.snapshot_id=l.snapshot_id "
            "JOIN probe_executions AS e ON e.execution_id=l.execution_id "
            "WHERE l.case_id=? AND e.probe_id='application.target_pressure'",
            (str(state.case_id),),
        ).fetchone()
        assert row is not None
        snapshot = CandidateDecisionSnapshotRepository(store).readback_frontier(str(row[0]))
        assert snapshot.response.ranking_source == "laya"
        assert snapshot.selected_kind == "measure"
        assert finished.completed_probe_ids.count("application.target_pressure") == 1


def test_frontier_abstention_does_not_force_generic_pressure_and_main_menu_is_scoped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "generic-frontier-declined.db") as store:
        store.initialize()
        app, state = _generic_case(store, max_probes=2)
        calls: list[dict[str, JsonValue]] = []
        _install_pressure_runner(app, calls)
        ranker = _set_frontier_owner(app, select_pressure=False)

        def no_main_proposals(
            _proposals: tuple[ProbeProposal, ...],
            _state: InvestigationState,
            _remaining: int,
            *,
            batch_limit: int | None = None,
        ) -> tuple[ProbeProposal, ...]:
            return ()

        monkeypatch.setattr(app, "_eligible", no_main_proposals)
        ProcessTargetRepository(store).bind_exact_process_name(state.case_id, "viewer.exe")

        # The selected process capability exists for the source-frozen frontier,
        # while the keyword-only main fallback is given a request without it.
        menu_state = state.model_copy(update={"max_probes": 2})
        caps = app._case_capabilities(menu_state)  # pyright: ignore[reportPrivateUsage]
        main_caps = app._main_routing_capabilities(  # pyright: ignore[reportPrivateUsage]
            menu_state, caps
        )
        assert any(item.probe_id == "application.target_pressure" for item in caps)
        assert all(item.probe_id != "application.target_pressure" for item in main_caps)

        finished = app.run(str(state.case_id))

        assert ranker.request is not None
        assert not calls
        assert "application.target_pressure" not in finished.completed_probe_ids
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_decision_execution_links AS l "
            "JOIN probe_executions AS e ON e.execution_id=l.execution_id "
            "WHERE l.case_id=? AND e.probe_id='application.target_pressure'",
            (str(state.case_id),),
        ).fetchone() == (0,)


def test_streaming_fallback_does_not_dispatch_generic_pressure(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "generic-streaming-fallback.db") as store:
        store.initialize()
        app = default_investigator(store)
        state = app.create(
            objective="Is viewer.exe using an unusual amount of resources right now?",
            budget_ms=20_000,
        )
        state = state.model_copy(update={"status": InvestigationStatus.RUNNING})
        now = utc_now()
        _application_snapshot(
            store,
            state.case_id,
            now,
            processes=[
                {
                    "pid": 4242,
                    "ppid": 1,
                    "name": "viewer.exe",
                    "creation_time": (now - timedelta(minutes=1)).isoformat(),
                    "identity": f"4242@{(now - timedelta(minutes=1)).isoformat()}",
                }
            ],
        )
        with store.transaction():
            store.connection.execute(
                "UPDATE cases SET status='collecting' WHERE case_id=?", (str(state.case_id),)
            )
            store.connection.execute(
                "UPDATE investigation_checkpoints SET record_json=? WHERE case_id=?",
                (state.model_dump_json(), str(state.case_id)),
            )
        row = store.connection.execute(
            "SELECT execution_id FROM evidence WHERE case_id=? "
            "AND json_extract(record_json, '$.collector.id')='application.snapshot'",
            (str(state.case_id),),
        ).fetchone()
        assert row is not None
        execution_id = ExecutionId(root=str(row[0]))
        digest = FollowupAdmissionRepository(store).parent_evidence_digest(
            str(state.case_id), str(execution_id)
        )
        parent = PersistedProbeResult(
            task_id="parent",
            case_id=str(state.case_id),
            epoch_state_version=state.state_version,
            probe_id="application.snapshot",
            execution_id=execution_id,
            evidence_generation=1,
            trigger_evidence_sha256=digest,
        )
        ranker = _set_frontier_owner(app, select_pressure=False)
        gaps: list[str] = []

        handled, selection, delivery = app._offer_streaming_mixed_frontier(  # pyright: ignore[reportPrivateUsage]
            state, parent, app, store, None, gaps
        )

        assert handled and selection is None and delivery is None
        assert ranker.request is not None
        assert any(
            item.reference.kind == "measure"
            and semantic.measurement is not None
            and semantic.measurement.probe_id == "application.target_pressure"
            for item, semantic in zip(
                ranker.request.items, ranker.request.item_semantics, strict=True
            )
        )
        assert store.connection.execute(
            "SELECT COUNT(*) FROM probe_executions WHERE case_id=? "
            "AND probe_id='application.target_pressure'",
            (str(state.case_id),),
        ).fetchone() == (0,)


def test_basic_keeps_common_exact_process_pressure_capability(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "generic-basic-capability.db") as store:
        store.initialize()
        app, state = _generic_case(store, max_probes=2)
        binding = ProcessTargetRepository(store).bind_exact_process_name(
            state.case_id, "viewer.exe"
        )

        pressure = next(
            item
            for item in app._case_capabilities(state)  # pyright: ignore[reportPrivateUsage]
            if item.probe_id == "application.target_pressure"
        )

        assert pressure.common
        assert pressure.target_handles == (binding.candidate_id,)
        assert app._main_routing_capabilities(  # pyright: ignore[reportPrivateUsage]
            state, (pressure,)
        ) == (pressure,)


def test_valid_unlinked_pressure_admission_holds_only_its_epoch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "generic-pressure-admission-pending.db") as store:
        store.initialize()
        app, state = _generic_case(store, max_probes=2)
        calls: list[dict[str, JsonValue]] = []
        _install_pressure_runner(app, calls)
        ranker = _set_frontier_owner(app, select_pressure=True)
        binding = ProcessTargetRepository(store).bind_exact_process_name(
            state.case_id, "viewer.exe"
        )

        # Binding alone does not force a pressure sample or block deep review.
        assert not app._generic_exact_pressure_pending(state)  # pyright: ignore[reportPrivateUsage]
        assert app._offer_deep_during_collection(state)  # pyright: ignore[reportPrivateUsage]

        from systemsense.storage.candidate_dispatch_admissions import (
            CandidateDispatchAdmission,
            CandidateDispatchAdmissionRepository,
        )

        registry, _ = app.runtime.candidate_catalog(state.case_id)
        with pytest.raises(ValueError):
            CandidateDispatchAdmissionRepository(store, registry=registry).admit(
                snapshot_id="frontier_decision_snapshot_" + "0" * 32,
                candidate_id="cand_v1_" + "0" * 32,
                case_id=state.case_id,
                epoch_state_version=state.state_version,
                task_id="probe-0-rejected-fixture",
                invocation_sha256="0" * 64,
                cost_ms=1,
            )
        assert not app._generic_exact_pressure_pending(state)  # pyright: ignore[reportPrivateUsage]
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_dispatch_admissions WHERE case_id=?",
            (str(state.case_id),),
        ).fetchone() == (0,)

        original_execute_plan = app.runtime._execute_plan  # pyright: ignore[reportPrivateUsage]
        observations: list[tuple[bool, bool]] = []

        def inspect_admitted_plan(*args: object, **kwargs: object) -> object:
            admission = kwargs.get("candidate_admission")
            if admission is not None:
                assert isinstance(admission, CandidateDispatchAdmission)
                live = app.repository.load(str(state.case_id))
                assert live is not None
                assert admission.outcome_status == "unclaimed"
                assert not app._offer_deep_during_collection(live)  # pyright: ignore[reportPrivateUsage]
                stale = live.model_copy(update={"state_version": live.state_version + 1})
                assert not app._generic_exact_pressure_pending(stale)  # pyright: ignore[reportPrivateUsage]
                observations.append((True, True))
            return original_execute_plan(*args, **kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(app.runtime, "_execute_plan", inspect_admitted_plan)
        finished = app.run(str(state.case_id))

        assert observations == [(True, True)]
        assert ranker.request is not None
        assert calls and calls[0]["pid"] == binding.pid
        assert finished.completed_probe_ids.count("application.target_pressure") == 1
