"""A persisted observation can admit one bounded read-only follow-up in flight."""

import sqlite3
import threading
import warnings
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast

import pytest

from systemsense.application.bootstrap import default_capabilities
from systemsense.application.case_service import CaseService, OpenedCase
from systemsense.application.investigation_state import InvestigationStatus
from systemsense.application.investigator import Investigator
from systemsense.application.runtime import (
    DiagnosticRuntime,
    FollowupSelection,
    PersistedProbeResult,
)
from systemsense.decision.baseline import KeywordBaselineDecisionProvider
from systemsense.decision.contracts import DecisionRequest, ProbeCapability
from systemsense.domain.cases import (
    CaseKind,
    CaseStatus,
    CaseTimeWindow,
    CaseTimeWindowBasis,
    DiagnosticCase,
)
from systemsense.domain.ids import ExecutionId, JsonValue
from systemsense.domain.probes import ProbeInvocation
from systemsense.domain.time import utc_now
from systemsense.orchestration.planner import (
    CasePlan,
    DeterministicPlanner,
    PlannedProbe,
    ProbeCandidate,
)
from systemsense.orchestration.probes import (
    ProbeDefinition,
    ProbeObservation,
    ProbeRun,
    ProbeRunner,
    ProbeRunStatus,
)
from systemsense.orchestration.scheduler import (
    BoundedScheduler,
    ResourceBudget,
    TaskStatus,
)
from systemsense.packs.runtime import NoParameters, default_probe_runner
from systemsense.reasoning.deterministic import DeterministicReasoningProvider
from systemsense.storage.decision_snapshots import DecisionSnapshotRepository, ProbeManifestRef
from systemsense.storage.followup_admissions import (
    FollowupAdmission,
    FollowupAdmissionRepository,
)
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.sqlite_store import SQLiteStore


def _opened_case(
    store: SQLiteStore, *, budget_ms: int = 20_000, include_slow: bool = True, max_probes: int = 3
) -> OpenedCase:
    service = CaseService(
        store,
        DeterministicPlanner(
            candidates=(ProbeCandidate(probe_id="core.system", cost_ms=100, value=1.0),)
        ),
    )

    placeholder_runtime = DiagnosticRuntime(
        store=store,
        case_service=service,
        probe_runner=default_probe_runner(),
    )
    investigator = Investigator(
        store=store,
        runtime=placeholder_runtime,
        capabilities=default_capabilities(),
        decision=KeywordBaselineDecisionProvider(),
        reasoning=DeterministicReasoningProvider(),
    )
    queued = investigator.create(
        objective="Network and host diagnostics", budget_ms=budget_ms, max_probes=max_probes
    )
    initial_probe_ids = ("core.system", "storage.snapshot") if include_slow else ("core.system",)
    running = InvestigationRepository(store).save(
        queued.model_copy(
            update={
                "status": InvestigationStatus.RUNNING,
                "pending_probe_ids": initial_probe_ids,
                "spent_cost_ms": 100 * len(initial_probe_ids),
            }
        ),
        expected_version=queued.state_version,
        event="test_collecting",
        detail="initial read-only probes",
    )
    return OpenedCase(
        case=DiagnosticCase(
            case_id=running.case_id,
            kind=CaseKind.GENERAL,
            status=CaseStatus.COLLECTING,
            symptom=running.objective,
            created_at=running.created_at,
            time_window=CaseTimeWindow(
                start=running.incident_start,
                end=running.incident_end,
                basis=CaseTimeWindowBasis.CASE_OPEN_DERIVED,
            ),
            state_version=running.state_version,
        ),
        deadline_at=running.deadline_at,
        plan=CasePlan(
            probes=tuple(
                PlannedProbe(probe_id=probe_id, cost_ms=100, value=1.0, reason="baseline")
                for probe_id in initial_probe_ids
            ),
            total_cost_ms=100 * len(initial_probe_ids),
            skipped_fresh=(),
            skipped_budget=(),
            skipped_low_value=(),
        ),
    )


def _single_parent_runtime(
    store: SQLiteStore,
    *,
    parent_handler: Callable[[dict[str, JsonValue]], ProbeObservation],
    child_handler: Callable[[dict[str, JsonValue]], ProbeObservation],
    max_probes: int = 3,
    runner_capture: list[ProbeRunner] | None = None,
) -> tuple[DiagnosticRuntime, OpenedCase]:
    opened = _opened_case(store, include_slow=False, max_probes=max_probes)
    original = default_probe_runner()
    parent_manifest = original.manifest("core.system")
    child_manifest = original.manifest("network.snapshot")
    assert parent_manifest and child_manifest
    runner = ProbeRunner(
        definitions=(
            ProbeDefinition(
                manifest=parent_manifest,
                parameter_model=NoParameters,
                handler=parent_handler,
                isolated=False,
            ),
            ProbeDefinition(
                manifest=child_manifest,
                parameter_model=NoParameters,
                handler=child_handler,
                isolated=False,
            ),
        )
    )
    if runner_capture is not None:
        runner_capture.append(runner)
    runtime = DiagnosticRuntime(
        store=store,
        case_service=CaseService(
            store,
            DeterministicPlanner(
                candidates=(ProbeCandidate(probe_id="core.system", cost_ms=100, value=1.0),)
            ),
        ),
        probe_runner=runner,
    )
    return runtime, opened


def _sample(name: str) -> ProbeObservation:
    at = utc_now()
    return ProbeObservation(summary=name, facts={"source": name}, observed_at=at, captured_at=at)


def _capability(probe_id: str) -> ProbeCapability:
    return next(item for item in default_capabilities() if item.probe_id == probe_id)


def test_persisted_parent_admits_child_while_unrelated_probe_is_running(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "followup.db") as store:
        store.initialize()
        opened = _opened_case(store)
        original = default_probe_runner()
        parent_manifest = original.manifest("core.system")
        slow_manifest = original.manifest("storage.snapshot")
        child_manifest = original.manifest("network.snapshot")
        assert parent_manifest and slow_manifest and child_manifest
        slow_started = threading.Event()
        slow_finished = threading.Event()
        child_started = threading.Event()
        calls: list[str] = []

        def observation(name: str) -> ProbeObservation:
            at = utc_now()
            return ProbeObservation(
                summary=name, facts={"source": name}, observed_at=at, captured_at=at
            )

        def parent(_parameters: dict[str, JsonValue]) -> ProbeObservation:
            assert slow_started.wait(10)
            calls.append("parent")
            return observation("parent")

        def slow(_parameters: dict[str, JsonValue]) -> ProbeObservation:
            slow_started.set()
            assert child_started.wait(10)
            calls.append("slow")
            slow_finished.set()
            return observation("slow")

        def child(_parameters: dict[str, JsonValue]) -> ProbeObservation:
            assert not slow_finished.is_set()
            with SQLiteStore(store.path) as worker_store:
                assert (
                    worker_store.connection.execute(
                        "SELECT COUNT(*) FROM collection_followup_admissions WHERE case_id=?",
                        (str(opened.case.case_id),),
                    ).fetchone()[0]
                    == 1
                )
            calls.append("child")
            child_started.set()
            return observation("child")

        runner = ProbeRunner(
            definitions=(
                ProbeDefinition(
                    manifest=parent_manifest,
                    parameter_model=NoParameters,
                    handler=parent,
                    isolated=False,
                ),
                ProbeDefinition(
                    manifest=slow_manifest,
                    parameter_model=NoParameters,
                    handler=slow,
                    isolated=False,
                ),
                ProbeDefinition(
                    manifest=child_manifest,
                    parameter_model=NoParameters,
                    handler=child,
                    isolated=False,
                ),
            )
        )
        runtime = DiagnosticRuntime(
            store=store,
            case_service=CaseService(
                store,
                DeterministicPlanner(
                    candidates=(ProbeCandidate(probe_id="core.system", cost_ms=100, value=1.0),)
                ),
            ),
            probe_runner=runner,
            scheduler=BoundedScheduler(budget=ResourceBudget(global_limit=2)),
        )
        child_capability = next(
            item for item in default_capabilities() if item.probe_id == "network.snapshot"
        )
        parents: list[PersistedProbeResult] = []

        def choose(event: PersistedProbeResult) -> FollowupSelection | None:
            if event.probe_id != "core.system":
                return None
            parents.append(event)
            assert store.probe_execution(str(event.execution_id)) is not None
            assert (
                store.connection.execute(
                    "SELECT COUNT(*) FROM evidence WHERE case_id=? AND execution_id=?",
                    (str(opened.case.case_id), str(event.execution_id)),
                ).fetchone()[0]
                == 1
            )
            return FollowupSelection(probe_id="network.snapshot")

        results = runtime.execute_plan(
            opened,
            followup_capabilities=(child_capability,),
            offer_followup=choose,
        )

        assert len(parents) == 1
        assert {result.status for result in results} == {TaskStatus.SUCCEEDED}
        assert len(results) == 3
        assert calls.index("child") < calls.index("slow")
        admissions = FollowupAdmissionRepository(store).readback(
            case_id=str(opened.case.case_id), epoch_state_version=opened.case.state_version
        )
        assert len(admissions) == 1
        assert admissions[0].trigger_execution_id == str(parents[0].execution_id)
        assert admissions[0].execution_id is not None
        assert admissions[0].outcome_status == "ok"


def test_ok_without_observation_cannot_trigger_a_followup(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "no-observation.db") as store:
        store.initialize()
        runners: list[ProbeRunner] = []
        runtime, opened = _single_parent_runtime(
            store,
            parent_handler=lambda _parameters: _sample("unused"),
            child_handler=lambda _parameters: _sample("child"),
            runner_capture=runners,
        )
        observed = utc_now()
        no_observation = ProbeRun(
            execution_id=ExecutionId.new(),
            probe_id="core.system",
            status=ProbeRunStatus.OK,
            started_at=observed,
            finished_at=observed,
            elapsed_ms=0,
            observation=None,
        )
        probe_runner = runners[0]
        original_run = probe_runner.run_invocation

        def run(invocation: ProbeInvocation, **kwargs: Any) -> ProbeRun:
            return (
                no_observation
                if invocation.probe_id == "core.system"
                else original_run(invocation, **kwargs)
            )

        monkeypatch.setattr(probe_runner, "run_invocation", run)
        choices: list[PersistedProbeResult] = []
        results = runtime.execute_plan(
            opened,
            followup_capabilities=(_capability("network.snapshot"),),
            offer_followup=lambda event: (
                choices.append(event) or FollowupSelection(probe_id="network.snapshot")
            ),
        )
        assert len(results) == 1
        assert results[0].status is TaskStatus.FAILED
        assert choices == []
        assert (
            FollowupAdmissionRepository(store).readback(
                case_id=str(opened.case.case_id), epoch_state_version=opened.case.state_version
            )
            == ()
        )


def test_followup_ok_without_observation_is_failed_not_a_successful_measurement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "child-no-observation.db") as store:
        store.initialize()
        runners: list[ProbeRunner] = []
        runtime, opened = _single_parent_runtime(
            store,
            parent_handler=lambda _parameters: _sample("parent"),
            child_handler=lambda _parameters: _sample("unused"),
            runner_capture=runners,
        )
        probe_runner = runners[0]
        original_run = probe_runner.run_invocation

        def run(invocation: ProbeInvocation, **kwargs: Any) -> ProbeRun:
            if invocation.probe_id == "network.snapshot":
                observed = utc_now()
                return ProbeRun(
                    execution_id=ExecutionId.new(),
                    probe_id=invocation.probe_id,
                    status=ProbeRunStatus.OK,
                    started_at=observed,
                    finished_at=observed,
                    elapsed_ms=0,
                    observation=None,
                )
            return original_run(invocation, **kwargs)

        monkeypatch.setattr(probe_runner, "run_invocation", run)
        results = runtime.execute_plan(
            opened,
            followup_capabilities=(_capability("network.snapshot"),),
            offer_followup=lambda _event: FollowupSelection(probe_id="network.snapshot"),
        )
        assert [item.status for item in results] == [TaskStatus.SUCCEEDED, TaskStatus.FAILED]
        admission = FollowupAdmissionRepository(store).readback(
            case_id=str(opened.case.case_id), epoch_state_version=opened.case.state_version
        )[0]
        assert admission.outcome_status == "failed"
        assert admission.execution_id is not None
        persisted = store.probe_execution(admission.execution_id)
        assert persisted is not None
        assert persisted.status == "failed"


def test_admission_writer_lock_rejects_child_without_losing_parallel_baseline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "busy-followup.db", busy_timeout_ms=10) as store:
        store.initialize()
        opened = _opened_case(store)
        original_runner = default_probe_runner()
        parent_manifest = original_runner.manifest("core.system")
        slow_manifest = original_runner.manifest("storage.snapshot")
        child_manifest = original_runner.manifest("network.snapshot")
        assert parent_manifest and slow_manifest and child_manifest
        slow_started = threading.Event()
        writer_ready = threading.Event()
        release_writer = threading.Event()
        writer_closed = threading.Event()
        writer_errors: list[Exception] = []

        def hold_write_lock() -> None:
            try:
                connection = sqlite3.connect(store.path, timeout=0.01, isolation_level=None)
                try:
                    connection.execute("BEGIN IMMEDIATE")
                    writer_ready.set()
                    assert release_writer.wait(10)
                    connection.rollback()
                finally:
                    connection.close()
            except Exception as error:
                writer_errors.append(error)
                writer_ready.set()
            finally:
                writer_closed.set()

        writer = threading.Thread(target=hold_write_lock, daemon=True)

        def parent(_parameters: dict[str, JsonValue]) -> ProbeObservation:
            assert slow_started.wait(10)
            return _sample("parent")

        def slow(_parameters: dict[str, JsonValue]) -> ProbeObservation:
            slow_started.set()
            assert writer_closed.wait(10)
            return _sample("slow")

        runner = ProbeRunner(
            definitions=(
                ProbeDefinition(parent_manifest, NoParameters, parent, isolated=False),
                ProbeDefinition(slow_manifest, NoParameters, slow, isolated=False),
                ProbeDefinition(
                    child_manifest,
                    NoParameters,
                    lambda _parameters: _sample("child"),
                    isolated=False,
                ),
            )
        )
        runtime = DiagnosticRuntime(
            store=store,
            case_service=CaseService(
                store,
                DeterministicPlanner(
                    candidates=(ProbeCandidate(probe_id="core.system", cost_ms=100, value=1.0),)
                ),
            ),
            probe_runner=runner,
            scheduler=BoundedScheduler(budget=ResourceBudget(global_limit=2)),
        )
        original_warn = warnings.warn

        def release_on_delayed_audit(message: str, *args: Any, **kwargs: Any) -> None:
            if "audit delayed" in message:
                release_writer.set()
            original_warn(message, *args, **kwargs)

        monkeypatch.setattr(warnings, "warn", release_on_delayed_audit)

        def choose(_event: PersistedProbeResult) -> FollowupSelection:
            writer.start()
            assert writer_ready.wait(10)
            assert writer_errors == []
            return FollowupSelection(probe_id="network.snapshot")

        try:
            with pytest.warns(RuntimeWarning, match="audit delayed"):
                results = runtime.execute_plan(
                    opened,
                    followup_capabilities=(_capability("network.snapshot"),),
                    offer_followup=choose,
                )
        finally:
            release_writer.set()
            if writer.ident is not None:
                writer.join(timeout=10)

        assert not writer.is_alive()
        assert writer_errors == []
        assert len(results) == 2
        assert all(item.status is TaskStatus.SUCCEEDED for item in results)
        assert (
            store.connection.execute(
                "SELECT COUNT(*) FROM probe_executions WHERE case_id=?",
                (str(opened.case.case_id),),
            ).fetchone()[0]
            == 2
        )
        assert (
            store.connection.execute(
                "SELECT COUNT(*) FROM evidence WHERE case_id=?",
                (str(opened.case.case_id),),
            ).fetchone()[0]
            == 2
        )
        assert (
            FollowupAdmissionRepository(store).readback(
                case_id=str(opened.case.case_id), epoch_state_version=opened.case.state_version
            )
            == ()
        )
        assert any(
            entry.probe_id == "systemsense.followup"
            and entry.parameters["reason_code"] == "admission_busy"
            for entry in store.audit_entries(case_id=str(opened.case.case_id))
        )


def test_same_epoch_decision_snapshot_binds_child_via_admission_not_legacy_link(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "snapshot.db") as store:
        store.initialize()
        runtime, opened = _single_parent_runtime(
            store,
            parent_handler=lambda _parameters: _sample("parent"),
            child_handler=lambda _parameters: _sample("child"),
        )
        capability = _capability("network.snapshot")
        manifest = runtime.probe_manifest(capability.probe_id)
        assert manifest is not None
        snapshot_ids: list[str] = []

        def choose(event: PersistedProbeResult) -> FollowupSelection:
            request = DecisionRequest(
                schema_version=2,
                case_id=opened.case.case_id,
                state_version=event.epoch_state_version,
                correlation_id="test-followup-snapshot",
                deadline_at=opened.deadline_at,
                symptom=opened.case.symptom,
                available_probes=(capability,),
                budget_ms=capability.cost_ms,
                max_probes=1,
            )
            snapshot = DecisionSnapshotRepository(store).capture(
                request,
                probe_manifest_refs=(
                    ProbeManifestRef.from_manifest(capability.probe_id, manifest),
                ),
                request_frozen_at=utc_now(),
            )
            snapshot_ids.append(snapshot.snapshot_id)
            return FollowupSelection(
                probe_id=capability.probe_id,
                decision_snapshot_id=snapshot.snapshot_id,
            )

        results = runtime.execute_plan(
            opened,
            followup_capabilities=(capability,),
            offer_followup=choose,
        )

        assert len(results) == 2
        assert all(item.status is TaskStatus.SUCCEEDED for item in results)
        assert len(snapshot_ids) == 1
        admission = FollowupAdmissionRepository(store).readback(
            case_id=str(opened.case.case_id), epoch_state_version=opened.case.state_version
        )[0]
        assert admission.decision_snapshot_id == snapshot_ids[0]
        assert admission.outcome_status == "ok"
        assert admission.execution_id is not None
        assert (
            store.connection.execute(
                "SELECT COUNT(*) FROM decision_execution_links WHERE execution_id=?",
                (admission.execution_id,),
            ).fetchone()[0]
            == 0
        )


def test_frozen_manifest_mismatch_rejects_followup_without_host_collection(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "manifest-mismatch.db") as store:
        store.initialize()
        child_calls: list[str] = []
        runtime, opened = _single_parent_runtime(
            store,
            parent_handler=lambda _parameters: _sample("parent"),
            child_handler=lambda _parameters: (child_calls.append("child"), _sample("child"))[1],
        )
        capability = _capability("network.snapshot")
        manifest = runtime.probe_manifest(capability.probe_id)
        assert manifest is not None

        def choose(event: PersistedProbeResult) -> FollowupSelection:
            snapshot = DecisionSnapshotRepository(store).capture(
                DecisionRequest(
                    schema_version=2,
                    case_id=opened.case.case_id,
                    state_version=event.epoch_state_version,
                    correlation_id="test-stale-manifest",
                    deadline_at=opened.deadline_at,
                    symptom=opened.case.symptom,
                    available_probes=(capability,),
                    budget_ms=capability.cost_ms,
                    max_probes=1,
                ),
                probe_manifest_refs=(
                    ProbeManifestRef.from_manifest(
                        capability.probe_id,
                        manifest.model_copy(update={"version": manifest.version + 1}),
                    ),
                ),
                request_frozen_at=utc_now(),
            )
            return FollowupSelection(
                probe_id=capability.probe_id,
                decision_snapshot_id=snapshot.snapshot_id,
            )

        results = runtime.execute_plan(
            opened,
            followup_capabilities=(capability,),
            offer_followup=choose,
        )
        assert len(results) == 1
        assert results[0].status is TaskStatus.SUCCEEDED
        assert child_calls == []
        assert (
            FollowupAdmissionRepository(store).readback(
                case_id=str(opened.case.case_id), epoch_state_version=opened.case.state_version
            )
            == ()
        )
        assert any(
            entry.probe_id == "systemsense.followup"
            and entry.parameters["reason_code"] == "invalid_snapshot"
            for entry in store.audit_entries(case_id=str(opened.case.case_id))
        )


@pytest.mark.parametrize("mode", ("invalid", "malformed", "raises", "graph_limit"))
def test_bad_advisory_followup_preserves_unrelated_running_evidence(
    tmp_path: Path, mode: str
) -> None:
    with SQLiteStore(tmp_path / f"bad-{mode}.db") as store:
        store.initialize()
        opened = _opened_case(store)
        original = default_probe_runner()
        parent_manifest = original.manifest("core.system")
        slow_manifest = original.manifest("storage.snapshot")
        child_manifest = original.manifest("network.snapshot")
        assert parent_manifest and slow_manifest and child_manifest
        slow_started = threading.Event()
        selection_done = threading.Event()

        def parent(_parameters: dict[str, JsonValue]) -> ProbeObservation:
            assert slow_started.wait(10)
            return _sample("parent")

        def slow(_parameters: dict[str, JsonValue]) -> ProbeObservation:
            slow_started.set()
            assert selection_done.wait(10)
            return _sample("slow")

        runner = ProbeRunner(
            definitions=(
                ProbeDefinition(parent_manifest, NoParameters, parent, isolated=False),
                ProbeDefinition(slow_manifest, NoParameters, slow, isolated=False),
                ProbeDefinition(
                    child_manifest,
                    NoParameters,
                    lambda _parameters: _sample("child"),
                    isolated=False,
                ),
            )
        )
        runtime = DiagnosticRuntime(
            store=store,
            case_service=CaseService(
                store,
                DeterministicPlanner(
                    candidates=(ProbeCandidate(probe_id="core.system", cost_ms=100, value=1.0),)
                ),
            ),
            probe_runner=runner,
            scheduler=BoundedScheduler(budget=ResourceBudget(global_limit=2, max_tasks=2)),
        )

        def choose(_event: PersistedProbeResult) -> FollowupSelection:
            selection_done.set()
            if mode == "raises":
                raise RuntimeError("untrusted advisory failure")
            if mode == "malformed":
                return cast("FollowupSelection", "malformed")
            if mode == "graph_limit":
                return FollowupSelection(probe_id="network.snapshot")
            return FollowupSelection(probe_id="unknown.probe")

        results = runtime.execute_plan(
            opened,
            followup_capabilities=(_capability("network.snapshot"),),
            offer_followup=choose,
        )

        assert len(results) == 2
        assert all(item.status is TaskStatus.SUCCEEDED for item in results)
        assert (
            store.connection.execute(
                "SELECT COUNT(*) FROM probe_executions WHERE case_id=?",
                (str(opened.case.case_id),),
            ).fetchone()[0]
            == 2
        )
        assert (
            store.connection.execute(
                "SELECT COUNT(*) FROM evidence WHERE case_id=?",
                (str(opened.case.case_id),),
            ).fetchone()[0]
            == 2
        )
        assert (
            FollowupAdmissionRepository(store).readback(
                case_id=str(opened.case.case_id), epoch_state_version=opened.case.state_version
            )
            == ()
        )
        rejection = [
            entry
            for entry in store.audit_entries(case_id=str(opened.case.case_id))
            if entry.probe_id == "systemsense.followup"
        ]
        assert len(rejection) == 1
        assert rejection[0].parameters["reason_code"] == (
            "provider_error"
            if mode == "raises"
            else "graph_limit"
            if mode == "graph_limit"
            else "invalid_selection"
        )


def test_committed_admission_without_child_result_is_uncertain_not_replayed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "crash.db") as store:
        store.initialize()
        child_calls: list[str] = []
        runtime, opened = _single_parent_runtime(
            store,
            parent_handler=lambda _parameters: _sample("parent"),
            child_handler=lambda _parameters: (child_calls.append("child"), _sample("child"))[1],
        )
        original = FollowupAdmissionRepository.admit

        def commit_then_crash(
            self: FollowupAdmissionRepository, **kwargs: Any
        ) -> FollowupAdmission:
            original(self, **kwargs)
            raise RuntimeError("simulated crash after admission commit")

        monkeypatch.setattr(FollowupAdmissionRepository, "admit", commit_then_crash)
        with pytest.raises(RuntimeError, match="simulated crash"):
            runtime.execute_plan(
                opened,
                followup_capabilities=(_capability("network.snapshot"),),
                offer_followup=lambda _event: FollowupSelection(probe_id="network.snapshot"),
            )

        assert child_calls == []
        admissions = FollowupAdmissionRepository(store).readback(
            case_id=str(opened.case.case_id), epoch_state_version=opened.case.state_version
        )
        assert len(admissions) == 1
        assert admissions[0].outcome_status == "uncertain"
        assert admissions[0].execution_id is None
        assert not admissions[0].replay_allowed


def test_stale_epoch_blocks_admitted_child_without_old_case_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "stale.db") as store:
        store.initialize()
        child_calls: list[str] = []
        runtime, opened = _single_parent_runtime(
            store,
            parent_handler=lambda _parameters: _sample("parent"),
            child_handler=lambda _parameters: (child_calls.append("child"), _sample("child"))[1],
        )
        original = FollowupAdmissionRepository.admit

        def stale_after_admit(
            self: FollowupAdmissionRepository, **kwargs: Any
        ) -> FollowupAdmission:
            admission = original(self, **kwargs)
            with store.transaction() as transaction:
                transaction.transition_case(
                    case_id=str(opened.case.case_id),
                    expected_state_version=opened.case.state_version,
                    status=CaseStatus.READY.value,
                )
            return admission

        monkeypatch.setattr(FollowupAdmissionRepository, "admit", stale_after_admit)
        results = runtime.execute_plan(
            opened,
            followup_capabilities=(_capability("network.snapshot"),),
            offer_followup=lambda _event: FollowupSelection(probe_id="network.snapshot"),
        )

        assert child_calls == []
        assert results[-1].status is TaskStatus.STALE
        admission = FollowupAdmissionRepository(store).readback(
            case_id=str(opened.case.case_id), epoch_state_version=opened.case.state_version
        )[0]
        assert admission.outcome_status == "uncertain"
        assert (
            store.connection.execute(
                "SELECT COUNT(*) FROM probe_executions WHERE case_id=? AND probe_id=?",
                (str(opened.case.case_id), "network.snapshot"),
            ).fetchone()[0]
            == 0
        )


def test_cancellation_after_admission_links_nonexecuted_child_result(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "cancel.db") as store:
        store.initialize()
        cancelled = threading.Event()
        child_calls: list[str] = []
        runtime, opened = _single_parent_runtime(
            store,
            parent_handler=lambda _parameters: _sample("parent"),
            child_handler=lambda _parameters: (child_calls.append("child"), _sample("child"))[1],
        )
        original = FollowupAdmissionRepository.admit

        def cancel_after_admit(
            self: FollowupAdmissionRepository, **kwargs: Any
        ) -> FollowupAdmission:
            admission = original(self, **kwargs)
            cancelled.set()
            return admission

        monkeypatch.setattr(FollowupAdmissionRepository, "admit", cancel_after_admit)
        results = runtime.execute_plan(
            opened,
            cancel_event=cancelled,
            followup_capabilities=(_capability("network.snapshot"),),
            offer_followup=lambda _event: FollowupSelection(probe_id="network.snapshot"),
        )

        assert child_calls == []
        assert results[-1].status is TaskStatus.CANCELLED
        admission = FollowupAdmissionRepository(store).readback(
            case_id=str(opened.case.case_id), epoch_state_version=opened.case.state_version
        )[0]
        assert admission.outcome_status == "cancelled"
        assert admission.execution_id is not None


def test_failed_parent_does_not_offer_and_duplicate_or_overbudget_child_is_rejected(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "failed.db") as store:
        store.initialize()

        def fail(_parameters: dict[str, JsonValue]) -> ProbeObservation:
            raise RuntimeError("collector failed")

        runtime, opened = _single_parent_runtime(
            store, parent_handler=fail, child_handler=lambda _parameters: _sample("child")
        )
        offered: list[PersistedProbeResult] = []
        results = runtime.execute_plan(
            opened,
            followup_capabilities=(_capability("network.snapshot"),),
            offer_followup=lambda event: (
                offered.append(event) or FollowupSelection(probe_id="network.snapshot")
            ),
        )
        assert results[0].status is TaskStatus.FAILED
        assert offered == []
        assert (
            FollowupAdmissionRepository(store).readback(
                case_id=str(opened.case.case_id), epoch_state_version=opened.case.state_version
            )
            == ()
        )

    with SQLiteStore(tmp_path / "budget.db") as store:
        store.initialize()
        runtime, opened = _single_parent_runtime(
            store,
            parent_handler=lambda _parameters: _sample("parent"),
            child_handler=lambda _parameters: _sample("child"),
            max_probes=1,
        )
        results = runtime.execute_plan(
            opened,
            followup_capabilities=(_capability("network.snapshot"),),
            offer_followup=lambda _event: FollowupSelection(probe_id="network.snapshot"),
        )
        assert len(results) == 1
        assert results[0].status is TaskStatus.SUCCEEDED
        assert (
            FollowupAdmissionRepository(store).readback(
                case_id=str(opened.case.case_id), epoch_state_version=opened.case.state_version
            )
            == ()
        )

    with SQLiteStore(tmp_path / "duplicate.db") as store:
        store.initialize()
        runtime, opened = _single_parent_runtime(
            store,
            parent_handler=lambda _parameters: _sample("parent"),
            child_handler=lambda _parameters: _sample("child"),
        )
        results = runtime.execute_plan(
            opened,
            followup_capabilities=(_capability("core.system"),),
            offer_followup=lambda _event: FollowupSelection(probe_id="core.system"),
        )
        assert len(results) == 1
        assert results[0].status is TaskStatus.SUCCEEDED
        assert (
            FollowupAdmissionRepository(store).readback(
                case_id=str(opened.case.case_id), epoch_state_version=opened.case.state_version
            )
            == ()
        )
