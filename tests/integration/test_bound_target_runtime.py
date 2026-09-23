"""The target probe receives parameters only from a revalidated case binding."""

import hashlib
import json
import threading
from collections.abc import Callable, Sequence
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from systemsense.application import runtime as runtime_module
from systemsense.application.case_service import CaseService
from systemsense.application.runtime import DiagnosticRuntime
from systemsense.application.targets import ProcessTargetBinding, TargetSelectionError
from systemsense.domain.cases import CaseKind
from systemsense.domain.ids import EvidenceId, JsonValue
from systemsense.domain.probes import MeasurementNeed, MeasurementWindow, Privilege, ProbeManifest
from systemsense.domain.time import utc_now
from systemsense.orchestration.invocations import ObservabilityGap
from systemsense.orchestration.planner import DeterministicPlanner, ProbeCandidate
from systemsense.orchestration.probes import ProbeDefinition, ProbeObservation, ProbeRunner
from systemsense.orchestration.scheduler import (
    BoundedScheduler,
    StateVersion,
    Task,
    TaskGraph,
    TaskResult,
    TaskStatus,
)
from systemsense.packs.runtime import TargetPressureParametersV1, default_probe_runner
from systemsense.storage.sqlite_store import SQLiteStore


def _runtime(
    store: SQLiteStore,
    captured: list[dict[str, JsonValue]],
    *,
    scheduler: BoundedScheduler | None = None,
) -> tuple[DiagnosticRuntime, CaseService]:
    manifest = default_probe_runner().manifest("application.target_pressure")
    assert manifest is not None

    def collect(parameters: dict[str, JsonValue]) -> ProbeObservation:
        captured.append(parameters)
        sampled_at = utc_now()
        return ProbeObservation(
            summary="Selected process sampled",
            facts={"target_pid": parameters["pid"]},
            observed_at=sampled_at,
            captured_at=sampled_at,
        )

    runner = ProbeRunner(
        definitions=(
            ProbeDefinition(
                manifest=manifest,
                parameter_model=TargetPressureParametersV1,
                handler=collect,
                isolated=False,
            ),
        )
    )
    service = CaseService(
        store,
        DeterministicPlanner(
            candidates=(
                ProbeCandidate(
                    probe_id="application.target_pressure",
                    cost_ms=100,
                    value=1.0,
                    common=True,
                ),
            )
        ),
    )
    return DiagnosticRuntime(
        store=store, case_service=service, probe_runner=runner, scheduler=scheduler
    ), service


class CapturingScheduler(BoundedScheduler):
    def __init__(self, *, before_run: Callable[[], None] | None = None) -> None:
        super().__init__()
        self.scheduled: tuple[Task, ...] = ()
        self.before_run = before_run

    def run_blocking(
        self,
        tasks: TaskGraph | Sequence[Task],
        *,
        case_deadline_at: datetime | None = None,
        cancel_event: threading.Event | None = None,
        state_version: StateVersion = 0,
        on_result: Callable[[TaskResult], None] | None = None,
    ) -> tuple[TaskResult, ...]:
        self.scheduled = tasks.tasks if isinstance(tasks, TaskGraph) else tuple(tasks)
        if self.before_run is not None:
            self.before_run()
        return super().run_blocking(
            tasks,
            case_deadline_at=case_deadline_at,
            cancel_event=cancel_event,
            state_version=state_version,
            on_result=on_result,
        )


def test_bound_target_runtime_persists_exact_parameters_and_audit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        captured: list[dict[str, JsonValue]] = []
        runtime, service = _runtime(store, captured)
        now = utc_now()
        opened = service.open_case(
            kind=CaseKind.GENERAL,
            symptom="PDF viewer stalls",
            target_traits=frozenset(),
            created_at=now,
            budget_ms=5000,
            max_probes=1,
        )
        assert tuple(item.probe_id for item in opened.plan.probes) == (
            "application.target_pressure",
        )
        binding = ProcessTargetBinding(
            candidate_id="proc_" + "a" * 32,
            case_id=opened.case.case_id,
            case_state_version=opened.case.state_version,
            evidence_id=EvidenceId.new(),
            evidence_sha256="b" * 64,
            pid=4242,
            creation_time=now - timedelta(minutes=1),
            name="viewer.exe",
            collection_started_at=now - timedelta(seconds=2),
            collection_completed_at=now - timedelta(seconds=1),
            omitted_process_count=0,
            selected_at=now,
        )

        def resolve(_repository: object, case_id: object) -> ProcessTargetBinding:
            assert case_id == opened.case.case_id
            return binding

        monkeypatch.setattr(
            runtime_module.ProcessTargetRepository,
            "resolve_process_target_for_sampling",
            resolve,
        )
        runtime.execute_bound_target_pressure(opened)

        assert len(captured) == 1
        assert captured[0]["pid"] == 4242
        assert datetime.fromisoformat(str(captured[0]["creation_time"])) == (binding.creation_time)
        execution = store.connection.execute(
            "SELECT status, parameters_json FROM probe_executions WHERE case_id = ?",
            (str(opened.case.case_id),),
        ).fetchone()
        assert execution is not None
        assert execution[0] == "ok"
        assert json.loads(str(execution[1])) == {
            "pid": 4242,
            "creation_time": binding.creation_time.isoformat().replace("+00:00", "Z"),
        }
        audit = store.audit_entries(case_id=str(opened.case.case_id))
        assert len(audit) == 1
        assert audit[0].parameters["target_candidate_id"] == binding.candidate_id
        assert audit[0].parameters["target_evidence_id"] == str(binding.evidence_id)
        assert audit[0].parameters["target_evidence_sha256"] == binding.evidence_sha256
        assert (
            audit[0].parameters["parameters_sha256"]
            == hashlib.sha256(str(execution[1]).encode("utf-8")).hexdigest()
        )
        assert store.evidence_page(case_id=str(opened.case.case_id), offset=0, limit=10)


def test_general_plan_cannot_supply_target_parameters(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        captured: list[dict[str, JsonValue]] = []
        runtime, service = _runtime(store, captured)
        opened = service.open_case(
            kind=CaseKind.GENERAL,
            symptom="PDF viewer stalls",
            target_traits=frozenset(),
            created_at=utc_now(),
            budget_ms=5000,
            max_probes=1,
        )
        runtime.execute_plan(opened)
        assert captured == []
        row = store.connection.execute(
            "SELECT status, parameters_json FROM probe_executions WHERE case_id = ?",
            (str(opened.case.case_id),),
        ).fetchone()
        assert row == ("denied", "{}")


def test_stale_case_version_is_rejected_before_bound_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        captured: list[dict[str, JsonValue]] = []
        runtime, service = _runtime(store, captured)
        opened = service.open_case(
            kind=CaseKind.GENERAL,
            symptom="PDF viewer stalls",
            target_traits=frozenset(),
            created_at=utc_now(),
            budget_ms=5000,
            max_probes=1,
        )
        store.connection.execute(
            "UPDATE cases SET state_version = 1 WHERE case_id = ?",
            (str(opened.case.case_id),),
        )

        def should_not_resolve(_repository: object, _case_id: object) -> None:
            raise AssertionError("stale plan must not resolve or sample a target")

        monkeypatch.setattr(
            runtime_module.ProcessTargetRepository,
            "resolve_process_target_for_sampling",
            should_not_resolve,
        )
        with pytest.raises(ValueError, match="no longer collecting"):
            runtime.execute_bound_target_pressure(opened)
        assert captured == []


def test_expired_binding_records_coverage_without_sampling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        captured: list[dict[str, JsonValue]] = []
        runtime, service = _runtime(store, captured)
        opened = service.open_case(
            kind=CaseKind.GENERAL,
            symptom="PDF viewer stalls",
            target_traits=frozenset(),
            created_at=utc_now(),
            budget_ms=5000,
            max_probes=1,
        )

        def expired(_repository: object, _case_id: object) -> None:
            raise TargetSelectionError("application snapshot is stale")

        monkeypatch.setattr(
            runtime_module.ProcessTargetRepository,
            "resolve_process_target_for_sampling",
            expired,
        )
        runtime.execute_bound_target_pressure(opened)
        assert captured == []
        row = store.connection.execute(
            "SELECT status, parameters_json FROM probe_executions WHERE case_id = ?",
            (str(opened.case.case_id),),
        ).fetchone()
        assert row == ("unavailable", "{}")
        assert store.coverage_page(case_id=str(opened.case.case_id), offset=0, limit=10)
        audit = store.audit_entries(case_id=str(opened.case.case_id))
        assert audit[0].parameters["target_binding_status"] == "unavailable"
        assert audit[0].outcome == "unavailable"


def test_typed_need_executes_only_revalidated_selected_process(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        captured: list[dict[str, JsonValue]] = []
        scheduler = CapturingScheduler()
        runtime, service = _runtime(store, captured, scheduler=scheduler)
        now = utc_now()
        opened = service.open_case(
            kind=CaseKind.GENERAL,
            symptom="PDF viewer stalls",
            target_traits=frozenset(),
            created_at=now,
            budget_ms=5000,
            max_probes=1,
        )
        binding = ProcessTargetBinding(
            candidate_id="proc_" + "a" * 32,
            case_id=opened.case.case_id,
            case_state_version=opened.case.state_version,
            evidence_id=EvidenceId.new(),
            evidence_sha256="b" * 64,
            pid=4242,
            creation_time=now - timedelta(minutes=1),
            name="viewer.exe",
            collection_started_at=now - timedelta(seconds=2),
            collection_completed_at=now - timedelta(seconds=1),
            omitted_process_count=0,
            selected_at=now,
        )

        def resolve(_repository: object, _case_id: object) -> ProcessTargetBinding:
            return binding

        monkeypatch.setattr(
            runtime_module.ProcessTargetRepository,
            "resolve_process_target_for_sampling",
            resolve,
        )
        need = MeasurementNeed(
            capability_id="application.target_pressure",
            observable="application.target_pressure",
            target_handle=binding.candidate_id,
        )

        result = runtime.execute_measurement_need(opened, need)

        assert not isinstance(result, ObservabilityGap)
        assert len(captured) == 1
        assert captured[0]["pid"] == 4242
        audit = store.audit_entries(case_id=str(opened.case.case_id))
        invocation_id = audit[0].parameters["measurement_invocation_id"]
        assert isinstance(invocation_id, str)
        assert invocation_id.startswith("probe-invocation:")
        assert len(scheduler.scheduled) == 1
        assert scheduler.scheduled[0].invocation is not None
        assert scheduler.scheduled[0].invocation.target_handle == binding.candidate_id
        assert scheduler.scheduled[0].dedupe_key == invocation_id


def test_typed_need_reports_gap_without_substituting_broad_probe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        captured: list[dict[str, JsonValue]] = []
        runtime, service = _runtime(store, captured)
        now = utc_now()
        opened = service.open_case(
            kind=CaseKind.GENERAL,
            symptom="PDF viewer stalls",
            target_traits=frozenset(),
            created_at=now,
            budget_ms=5000,
            max_probes=1,
        )
        binding = ProcessTargetBinding(
            candidate_id="proc_" + "a" * 32,
            case_id=opened.case.case_id,
            case_state_version=opened.case.state_version,
            evidence_id=EvidenceId.new(),
            evidence_sha256="b" * 64,
            pid=4242,
            creation_time=now - timedelta(minutes=1),
            name="viewer.exe",
            collection_started_at=now - timedelta(seconds=2),
            collection_completed_at=now - timedelta(seconds=1),
            omitted_process_count=0,
            selected_at=now,
        )

        def resolve(_repository: object, _case_id: object) -> ProcessTargetBinding:
            return binding

        monkeypatch.setattr(
            runtime_module.ProcessTargetRepository,
            "resolve_process_target_for_sampling",
            resolve,
        )
        wrong_target = MeasurementNeed(
            capability_id="application.target_pressure",
            observable="application.target_pressure",
            target_handle="proc_" + "c" * 32,
        )
        unsupported_window = wrong_target.model_copy(
            update={
                "target_handle": binding.candidate_id,
                "window": MeasurementWindow(start=now, end=now + timedelta(seconds=1)),
            }
        )

        assert isinstance(runtime.execute_measurement_need(opened, wrong_target), ObservabilityGap)
        assert isinstance(
            runtime.execute_measurement_need(opened, unsupported_window), ObservabilityGap
        )
        assert captured == []
        assert store.connection.execute("SELECT count(*) FROM probe_executions").fetchone() == (0,)


@pytest.mark.parametrize("manifest_defect", ["elevated", "wrong_input_model"])
def test_typed_need_reports_gap_for_changed_invalid_registration(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, manifest_defect: str
) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        captured: list[dict[str, JsonValue]] = []
        runtime, service = _runtime(store, captured)
        now = utc_now()
        opened = service.open_case(
            kind=CaseKind.GENERAL,
            symptom="PDF viewer stalls",
            target_traits=frozenset(),
            created_at=now,
            budget_ms=5000,
            max_probes=1,
        )
        binding = ProcessTargetBinding(
            candidate_id="proc_" + "a" * 32,
            case_id=opened.case.case_id,
            case_state_version=opened.case.state_version,
            evidence_id=EvidenceId.new(),
            evidence_sha256="b" * 64,
            pid=4242,
            creation_time=now - timedelta(minutes=1),
            name="viewer.exe",
            collection_started_at=now - timedelta(seconds=2),
            collection_completed_at=now - timedelta(seconds=1),
            omitted_process_count=0,
            selected_at=now,
        )

        def resolve(_repository: object, _case_id: object) -> ProcessTargetBinding:
            return binding

        monkeypatch.setattr(
            runtime_module.ProcessTargetRepository,
            "resolve_process_target_for_sampling",
            resolve,
        )
        original_manifest = runtime.probe_manifest("application.target_pressure")
        assert original_manifest is not None
        if manifest_defect == "elevated":
            changed = original_manifest.model_copy(
                update={
                    "safety": original_manifest.safety.model_copy(
                        update={"privilege": Privilege.ELEVATED}
                    )
                }
            )
        else:
            changed = original_manifest.model_copy(update={"input_model": "UnexpectedV1"})

        def changed_manifest(_probe_id: str) -> ProbeManifest:
            return changed

        monkeypatch.setattr(
            runtime._probe_runner,  # pyright: ignore[reportPrivateUsage]
            "manifest",
            changed_manifest,
        )
        need = MeasurementNeed(
            capability_id="application.target_pressure",
            observable="application.target_pressure",
            target_handle=binding.candidate_id,
        )

        result = runtime.execute_measurement_need(opened, need)

        assert isinstance(result, ObservabilityGap)
        assert result.need == need
        assert "registration" in result.reason
        assert captured == []
        assert store.connection.execute("SELECT count(*) FROM probe_executions").fetchone() == (0,)


def test_typed_need_rechecks_binding_before_scheduling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        captured: list[dict[str, JsonValue]] = []
        scheduler = CapturingScheduler()
        runtime, service = _runtime(store, captured, scheduler=scheduler)
        now = utc_now()
        opened = service.open_case(
            kind=CaseKind.GENERAL,
            symptom="PDF viewer stalls",
            target_traits=frozenset(),
            created_at=now,
            budget_ms=5000,
            max_probes=1,
        )
        original = ProcessTargetBinding(
            candidate_id="proc_" + "a" * 32,
            case_id=opened.case.case_id,
            case_state_version=opened.case.state_version,
            evidence_id=EvidenceId.new(),
            evidence_sha256="b" * 64,
            pid=4242,
            creation_time=now - timedelta(minutes=1),
            name="viewer.exe",
            collection_started_at=now - timedelta(seconds=2),
            collection_completed_at=now - timedelta(seconds=1),
            omitted_process_count=0,
            selected_at=now,
        )
        changed = original.model_copy(update={"pid": 4243})
        calls = 0

        def resolve(_repository: object, _case_id: object) -> ProcessTargetBinding:
            nonlocal calls
            calls += 1
            return original if calls == 1 else changed

        monkeypatch.setattr(
            runtime_module.ProcessTargetRepository,
            "resolve_process_target_for_sampling",
            resolve,
        )
        need = MeasurementNeed(
            capability_id="application.target_pressure",
            observable="application.target_pressure",
            target_handle=original.candidate_id,
        )

        result = runtime.execute_measurement_need(opened, need)

        assert isinstance(result, ObservabilityGap)
        assert calls >= 2
        assert scheduler.scheduled == ()
        assert captured == []


def test_typed_need_rechecks_binding_in_queued_worker_before_sampling(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    queued = False

    def begin_queue() -> None:
        nonlocal queued
        queued = True

    with SQLiteStore(tmp_path / "cases.db") as store:
        captured: list[dict[str, JsonValue]] = []
        scheduler = CapturingScheduler(before_run=begin_queue)
        runtime, service = _runtime(store, captured, scheduler=scheduler)
        now = utc_now()
        opened = service.open_case(
            kind=CaseKind.GENERAL,
            symptom="PDF viewer stalls",
            target_traits=frozenset(),
            created_at=now,
            budget_ms=5000,
            max_probes=1,
        )
        original = ProcessTargetBinding(
            candidate_id="proc_" + "a" * 32,
            case_id=opened.case.case_id,
            case_state_version=opened.case.state_version,
            evidence_id=EvidenceId.new(),
            evidence_sha256="b" * 64,
            pid=4242,
            creation_time=now - timedelta(minutes=1),
            name="viewer.exe",
            collection_started_at=now - timedelta(seconds=2),
            collection_completed_at=now - timedelta(seconds=1),
            omitted_process_count=0,
            selected_at=now,
        )
        changed = original.model_copy(update={"pid": 4243})
        worker_rechecks: list[str] = []

        def resolve(_repository: object, _case_id: object) -> ProcessTargetBinding:
            if queued:
                worker_rechecks.append(threading.current_thread().name)
                return changed
            return original

        monkeypatch.setattr(
            runtime_module.ProcessTargetRepository,
            "resolve_process_target_for_sampling",
            resolve,
        )
        need = MeasurementNeed(
            capability_id="application.target_pressure",
            observable="application.target_pressure",
            target_handle=original.candidate_id,
        )

        result = runtime.execute_measurement_need(opened, need)

        assert not isinstance(result, ObservabilityGap)
        assert result[0].status is TaskStatus.FAILED
        assert worker_rechecks and all(
            name.startswith("systemsense-probe") for name in worker_rechecks
        )
        assert captured == []
        assert store.connection.execute(
            "SELECT status FROM probe_executions WHERE case_id = ?",
            (str(opened.case.case_id),),
        ).fetchone() == ("unavailable",)


def test_typed_need_reports_worker_store_failure_separately_from_stale_target(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        captured: list[dict[str, JsonValue]] = []
        runtime, service = _runtime(store, captured)
        now = utc_now()
        opened = service.open_case(
            kind=CaseKind.GENERAL,
            symptom="PDF viewer stalls",
            target_traits=frozenset(),
            created_at=now,
            budget_ms=5000,
            max_probes=1,
        )
        binding = ProcessTargetBinding(
            candidate_id="proc_" + "a" * 32,
            case_id=opened.case.case_id,
            case_state_version=opened.case.state_version,
            evidence_id=EvidenceId.new(),
            evidence_sha256="b" * 64,
            pid=4242,
            creation_time=now - timedelta(minutes=1),
            name="viewer.exe",
            collection_started_at=now - timedelta(seconds=2),
            collection_completed_at=now - timedelta(seconds=1),
            omitted_process_count=0,
            selected_at=now,
        )

        def resolve(_repository: object, _case_id: object) -> ProcessTargetBinding:
            return binding

        monkeypatch.setattr(
            runtime_module.ProcessTargetRepository,
            "resolve_process_target_for_sampling",
            resolve,
        )

        class BrokenWorkerStore:
            def __init__(self, _path: Path) -> None:
                pass

            def __enter__(self) -> "BrokenWorkerStore":
                raise RuntimeError("private database location must not be echoed")

            def __exit__(self, *_args: object) -> None:
                pass

        monkeypatch.setattr(runtime_module, "SQLiteStore", BrokenWorkerStore)
        need = MeasurementNeed(
            capability_id="application.target_pressure",
            observable="application.target_pressure",
            target_handle=binding.candidate_id,
        )

        result = runtime.execute_measurement_need(opened, need)

        assert not isinstance(result, ObservabilityGap)
        assert result[0].status is TaskStatus.FAILED
        assert captured == []
        row = store.connection.execute(
            "SELECT status FROM probe_executions WHERE case_id = ?",
            (str(opened.case.case_id),),
        ).fetchone()
        assert row == ("failed",)
        assert isinstance(result[0].value, runtime_module.ProbeRun)
        assert "private database location" not in str(result[0].value.error)
