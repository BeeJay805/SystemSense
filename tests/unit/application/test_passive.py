import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from systemsense.application import passive
from systemsense.application.passive import PassiveRecorder, PassiveRecorderConfig
from systemsense.audit import AuditChain
from systemsense.domain.coverage import CoverageRecord, CoverageStatus
from systemsense.domain.evidence import EvidenceRecord
from systemsense.domain.ids import ExecutionId, JsonValue
from systemsense.domain.time import UtcDateTime
from systemsense.orchestration.executor import CancellationSignal
from systemsense.orchestration.probe_capacity_ledger import (
    DurableProbeLedger,
    LedgerBudget,
    LedgerUnavailable,
)
from systemsense.orchestration.probes import ProbeObservation, ProbeRun, ProbeRunStatus
from systemsense.orchestration.scheduler import (
    HostWorkArbiter,
    HostWorkSlot,
    ResourceBudget,
    ResourceClass,
)
from systemsense.platform.windows.eventlog import EventQuery, QueryStatus, WindowsEvent
from systemsense.storage.sqlite_store import SQLiteStore

_NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)


class _Manifest:
    version = 1


class _Runner:
    def __init__(self, statuses: dict[str, ProbeRunStatus] | None = None) -> None:
        self.calls: list[str] = []
        self._statuses = statuses or {}
        self._run_count = 0

    def manifest(self, probe_id: str) -> _Manifest | None:
        del probe_id
        return _Manifest()

    def run(
        self,
        probe_id: str,
        parameters: dict[str, JsonValue],
        *,
        deadline_at: UtcDateTime | None = None,
        cancellation: CancellationSignal | None = None,
        host_slot: HostWorkSlot | None = None,
    ) -> ProbeRun:
        del parameters
        assert deadline_at is not None
        assert cancellation is not None
        if host_slot is not None:
            assert isinstance(host_slot, HostWorkSlot)
        self.calls.append(probe_id)
        self._run_count += 1
        status = self._statuses.get(probe_id, ProbeRunStatus.OK)
        observation = None
        error = None
        if status is ProbeRunStatus.OK:
            observation = ProbeObservation(
                summary=f"{probe_id} passive sample",
                facts={"sample": {"probe_id": probe_id}},
                observed_at=_NOW,
                captured_at=_NOW,
            )
        else:
            error = f"{probe_id} unavailable"
        return ProbeRun(
            execution_id=ExecutionId(root=f"exec_{self._run_count:032x}"),
            probe_id=probe_id,
            status=status,
            started_at=_NOW,
            finished_at=_NOW + timedelta(milliseconds=1),
            elapsed_ms=1,
            observation=observation,
            error=error,
        )


class _EventLog:
    def __init__(self, results: tuple[EventQuery, ...]) -> None:
        self._results = list(results)
        self.after_record_ids: list[int | None] = []

    def query(
        self,
        channel: str,
        *,
        after_record_id: int | None,
        limit: int,
        deadline_at: UtcDateTime | None = None,
        cancellation: CancellationSignal | None = None,
    ) -> EventQuery:
        del channel
        assert limit <= 10
        assert deadline_at is not None
        assert cancellation is not None
        self.after_record_ids.append(after_record_id)
        return self._results.pop(0)


def _event(record_id: int) -> WindowsEvent:
    return WindowsEvent(
        channel="Application",
        provider="FixtureProvider",
        event_id=1000,
        record_id=record_id,
        level=2,
        observed_at=_NOW,
        computer="fixture-host",
        event_data={"Name": "fixture"},
        rendered_message="fixture event",
        source_id=f"src_{record_id:064x}",
    )


def _config(**updates: object) -> PassiveRecorderConfig:
    return PassiveRecorderConfig.model_validate(
        {
            "interval_seconds": 5,
            "event_channels": ("Application",),
            "event_limit": 10,
            "max_passive_cases": 10,
            "max_case_age_days": 7,
            **updates,
        }
    )


def test_passive_interval_has_a_five_second_floor() -> None:
    with pytest.raises(ValidationError, match="greater than or equal to 5"):
        _config(interval_seconds=4)


def test_capture_uses_fixed_cheap_probes_persists_marker_and_event_bookmark(
    tmp_path: Path,
) -> None:
    runner = _Runner()
    event_log = _EventLog(
        (
            EventQuery(status=QueryStatus.OK, events=(_event(10),)),
            EventQuery(status=QueryStatus.OK, events=(_event(11),)),
        )
    )
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        recorder = PassiveRecorder(
            store=store,
            runner=runner,
            event_log=event_log,
            config=_config(),
            now=lambda: _NOW,
        )

        first = recorder.capture_once()
        second = recorder.capture_once()

        assert runner.calls == [
            "core.system",
            "core.resources",
            "core.system",
            "core.resources",
        ]
        assert first.active_observer is True
        assert first.evidence_persisted == 3
        assert first.coverage_persisted == 3
        assert first.failure_count == 0
        assert store.probe_execution_count(case_id=str(first.case_id)) == 3
        audit_entries = store.audit_entries(case_id=str(first.case_id))
        assert len(audit_entries) == 3
        assert AuditChain.verify(
            audit_entries,
            checkpoint=store.audit_checkpoint(case_id=str(first.case_id)),
        ).valid
        assert event_log.after_record_ids == [None, 10]
        assert store.bookmark("passive.eventlog:Application") == "11"
        case = store.case(str(second.case_id))
        assert case is not None
        assert case.kind == "passive"
        assert case.status == "complete"
        records = tuple(
            EvidenceRecord.model_validate_json(row.record_json)
            for row in store.evidence_page(
                case_id=str(first.case_id),
                offset=0,
                limit=10,
            )
        )
        assert records
        assert all(
            any("passive observer" in limitation for limitation in record.limitations)
            for record in records
        )
        execution_ids = {
            str(record.collector.execution_id)
            for record in records
            if record.collector.execution_id
        }
        assert all(
            store.probe_execution(execution_id) is not None for execution_id in execution_ids
        )
        persisted_execution_ids = {
            str(row[0])
            for row in store.connection.execute(
                "SELECT DISTINCT execution_id FROM evidence "
                "WHERE case_id = ? AND execution_id IS NOT NULL",
                (str(first.case_id),),
            )
        }
        assert all(
            store.probe_execution(execution_id) is not None
            for execution_id in persisted_execution_ids
        )


def test_failed_probe_and_denied_event_query_are_explicit_coverage(tmp_path: Path) -> None:
    runner = _Runner(
        {
            "core.system": ProbeRunStatus.FAILED,
            "core.resources": ProbeRunStatus.TRUNCATED,
        }
    )
    event_log = _EventLog((EventQuery(status=QueryStatus.DENIED, reason="denied"),))
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        cycle = PassiveRecorder(
            store=store,
            runner=runner,
            event_log=event_log,
            config=_config(),
            now=lambda: _NOW,
        ).capture_once()

        coverage = tuple(
            CoverageRecord.model_validate_json(row.record_json)
            for row in store.coverage_page(case_id=str(cycle.case_id), offset=0, limit=10)
        )

        assert cycle.evidence_persisted == 0
        assert cycle.coverage_persisted == 3
        assert cycle.failure_count == 3
        assert {item.status for item in coverage} == {
            CoverageStatus.FAILED,
            CoverageStatus.TRUNCATED,
            CoverageStatus.DENIED,
        }


def test_passive_fixed_probes_acquire_and_release_host_capacity(tmp_path: Path) -> None:
    class RecordingArbiter(HostWorkArbiter):
        def __init__(self) -> None:
            super().__init__(ResourceBudget(global_limit=1))
            self.admissions: list[tuple[str, str, ResourceClass, bool]] = []

        def try_acquire(
            self,
            run_id: str,
            task_id: str,
            resource: ResourceClass,
            priority: int,
            *,
            isolated_probe: bool = False,
        ) -> HostWorkSlot | None:
            self.admissions.append((run_id, task_id, resource, isolated_probe))
            return super().try_acquire(
                run_id, task_id, resource, priority, isolated_probe=isolated_probe
            )

    arbiter = RecordingArbiter()

    class SlotRunner(_Runner):
        def run(
            self,
            probe_id: str,
            parameters: dict[str, JsonValue],
            *,
            deadline_at: UtcDateTime | None = None,
            cancellation: CancellationSignal | None = None,
            host_slot: HostWorkSlot | None = None,
        ) -> ProbeRun:
            assert host_slot is not None
            assert arbiter.try_acquire("other", "task", ResourceClass.CPU, 0) is None
            arbiter.forget("other", "task")
            return super().run(
                probe_id,
                parameters,
                deadline_at=deadline_at,
                cancellation=cancellation,
                host_slot=host_slot,
            )

    runner = SlotRunner()
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        result = PassiveRecorder(
            store=store,
            runner=runner,
            event_log=_EventLog((EventQuery(status=QueryStatus.OK),)),
            config=_config(),
            now=lambda: _NOW,
            host_arbiter=arbiter,
        ).capture_once()
        assert result.failure_count == 0
        assert runner.calls == ["core.system", "core.resources"]
        passive_admissions = [item for item in arbiter.admissions if item[0].startswith("passive:")]
        assert [item[1:] for item in passive_admissions] == [
            ("core.system", ResourceClass.CPU, True),
            ("core.resources", ResourceClass.CPU, True),
        ]
        assert all(str(result.case_id) in item[0] for item in passive_admissions)
        assert arbiter.pending_count == 0
        acquired = arbiter.try_acquire("later", "task", ResourceClass.CPU, 0)
        assert acquired is not None
        acquired.release()


def test_passive_queue_full_persists_blocked_coverage_without_probe_run(tmp_path: Path) -> None:
    arbiter = HostWorkArbiter(ResourceBudget(global_limit=1, max_tasks=1))
    owner = arbiter.try_acquire("owner", "task", ResourceClass.CPU, 0)
    assert owner is not None
    assert arbiter.try_acquire("waiting", "task", ResourceClass.CPU, 0) is None
    runner = _Runner()
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        cycle = PassiveRecorder(
            store=store,
            runner=runner,
            event_log=_EventLog((EventQuery(status=QueryStatus.OK),)),
            config=_config(),
            now=lambda: _NOW,
            host_arbiter=arbiter,
        ).capture_once()
        coverage = tuple(
            CoverageRecord.model_validate_json(row.record_json)
            for row in store.coverage_page(case_id=str(cycle.case_id), offset=0, limit=10)
        )
        assert runner.calls == []
        assert [row.status for row in coverage].count(CoverageStatus.UNAVAILABLE) == 2
        assert any("queue" in (row.reason or "") for row in coverage)
        for entry in store.audit_entries(case_id=str(cycle.case_id)):
            if entry.probe_id not in ("core.system", "core.resources"):
                continue
            assert entry.parameters["tree_exit_status"] == "not_tracked"
            execution = store.probe_execution(entry.event_id.removeprefix("probe_"))
            assert execution is not None
            assert execution.tree_exit_status == "not_tracked"
    arbiter.forget("waiting", "task")
    owner.release()


def test_passive_ledger_unavailable_persists_blocked_coverage(tmp_path: Path) -> None:
    class BrokenArbiter(HostWorkArbiter):
        def try_acquire(
            self,
            run_id: str,
            task_id: str,
            resource: ResourceClass,
            priority: int,
            *,
            isolated_probe: bool = False,
        ) -> HostWorkSlot | None:
            del run_id, task_id, resource, priority, isolated_probe
            raise LedgerUnavailable("secret=unavailable")

    runner = _Runner()
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        cycle = PassiveRecorder(
            store=store,
            runner=runner,
            event_log=_EventLog((EventQuery(status=QueryStatus.OK),)),
            config=_config(),
            now=lambda: _NOW,
            host_arbiter=BrokenArbiter(ResourceBudget(global_limit=1)),
        ).capture_once()
        coverage = tuple(
            CoverageRecord.model_validate_json(row.record_json)
            for row in store.coverage_page(case_id=str(cycle.case_id), offset=0, limit=10)
        )
        assert runner.calls == []
        assert [row.status for row in coverage].count(CoverageStatus.UNAVAILABLE) == 2
        assert all("secret" not in (row.reason or "") for row in coverage)


def test_passive_core_probe_admission_releases_durable_reservations(tmp_path: Path) -> None:
    ledger_path = tmp_path / "capacity.db"
    ledger = DurableProbeLedger(
        ledger_path, LedgerBudget(global_limit=1, max_pending=2), schema_hash="passive-test-v1"
    )
    arbiter = HostWorkArbiter(ResourceBudget(global_limit=1, max_tasks=2), ledger=ledger)
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        cycle = PassiveRecorder(
            store=store,
            runner=_Runner(),
            event_log=_EventLog((EventQuery(status=QueryStatus.OK),)),
            config=_config(),
            now=lambda: _NOW,
            host_arbiter=arbiter,
        ).capture_once()
        assert cycle.failure_count == 0
    with sqlite3.connect(ledger_path) as db:
        rows = db.execute("SELECT case_id, task_id, resource, state FROM work").fetchall()
    assert sorted((task_id, resource, state) for _, task_id, resource, state in rows) == [
        ("core.resources", "cpu", "released"),
        ("core.system", "cpu", "released"),
    ]
    assert all(str(cycle.case_id) in run_id for run_id, *_ in rows)


def test_passive_persists_real_worker_tree_exit_status_in_execution_and_audit(
    tmp_path: Path,
) -> None:
    class TreeExitRunner(_Runner):
        def run(
            self,
            probe_id: str,
            parameters: dict[str, JsonValue],
            *,
            deadline_at: UtcDateTime | None = None,
            cancellation: CancellationSignal | None = None,
            host_slot: HostWorkSlot | None = None,
        ) -> ProbeRun:
            result = super().run(
                probe_id,
                parameters,
                deadline_at=deadline_at,
                cancellation=cancellation,
                host_slot=host_slot,
            )
            exit_status = "verified_empty" if probe_id == "core.system" else "unknown"
            return result.model_copy(update={"tree_exit_status": exit_status})

    with SQLiteStore(tmp_path / "systemsense.db") as store:
        cycle = PassiveRecorder(
            store=store,
            runner=TreeExitRunner(),
            event_log=_EventLog((EventQuery(status=QueryStatus.OK),)),
            config=_config(),
            now=lambda: _NOW,
        ).capture_once()
        entries = store.audit_entries(case_id=str(cycle.case_id))
        by_probe = {entry.probe_id: entry for entry in entries}
        for probe_id, expected in (
            ("core.system", "verified_empty"),
            ("core.resources", "unknown"),
        ):
            entry = by_probe[probe_id]
            assert entry.parameters["tree_exit_status"] == expected
            execution_id = entry.event_id.removeprefix("probe_")
            execution = store.probe_execution(execution_id)
            assert execution is not None
            assert execution.tree_exit_status == expected


def test_passive_admission_deadline_persists_blocked_coverage(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    ticks = iter((0.0, 5.0, 6.0, 7.0))
    monkeypatch.setattr(passive, "monotonic", lambda: next(ticks))
    runner = _Runner()
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        cycle = PassiveRecorder(
            store=store,
            runner=runner,
            event_log=_EventLog((EventQuery(status=QueryStatus.OK),)),
            config=_config(),
            now=lambda: _NOW,
            host_arbiter=HostWorkArbiter(ResourceBudget(global_limit=1)),
        ).capture_once()
        coverage = tuple(
            CoverageRecord.model_validate_json(row.record_json)
            for row in store.coverage_page(case_id=str(cycle.case_id), offset=0, limit=10)
        )
        assert runner.calls == []
        assert [row.status for row in coverage].count(CoverageStatus.UNAVAILABLE) == 2
        assert all(
            "deadline" in (row.reason or "")
            for row in coverage
            if row.status is CoverageStatus.UNAVAILABLE
        )


def test_passive_cancelled_admission_does_not_launch_probe(tmp_path: Path) -> None:
    class Cancelled:
        @property
        def cancelled(self) -> bool:
            return True

    runner = _Runner()
    arbiter = HostWorkArbiter(ResourceBudget(global_limit=1))
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        cycle = PassiveRecorder(
            store=store,
            runner=runner,
            event_log=_EventLog((EventQuery(status=QueryStatus.OK),)),
            config=_config(),
            now=lambda: _NOW,
            host_arbiter=arbiter,
        ).capture_once(cancellation=Cancelled())
        coverage = tuple(
            CoverageRecord.model_validate_json(row.record_json)
            for row in store.coverage_page(case_id=str(cycle.case_id), offset=0, limit=10)
        )
        assert runner.calls == []
        assert arbiter.pending_count == 0
        assert [row.status for row in coverage].count(CoverageStatus.UNAVAILABLE) == 2
        assert all(
            "cancelled" in (row.reason or "")
            for row in coverage
            if row.status is CoverageStatus.UNAVAILABLE
        )


def test_cancelled_probe_is_explicitly_unavailable(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        cycle = PassiveRecorder(
            store=store,
            runner=_Runner({"core.system": ProbeRunStatus.CANCELLED}),
            event_log=_EventLog((EventQuery(status=QueryStatus.OK),)),
            config=_config(),
            now=lambda: _NOW,
        ).capture_once()

        coverage = tuple(
            CoverageRecord.model_validate_json(row.record_json)
            for row in store.coverage_page(case_id=str(cycle.case_id), offset=0, limit=10)
        )
        assert CoverageStatus.UNAVAILABLE in {item.status for item in coverage}
        assert cycle.failure_count == 1


class _ExplodingEventLog:
    def query(
        self,
        channel: str,
        *,
        after_record_id: int | None,
        limit: int,
        deadline_at: UtcDateTime | None = None,
        cancellation: CancellationSignal | None = None,
    ) -> EventQuery:
        del channel, after_record_id, limit, deadline_at, cancellation
        raise OSError("token=very-secret-value event log backend failed")


def test_event_backend_exception_becomes_failed_coverage(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        cycle = PassiveRecorder(
            store=store,
            runner=_Runner(),
            event_log=_ExplodingEventLog(),
            config=_config(),
            now=lambda: _NOW,
        ).capture_once()

        coverage = tuple(
            CoverageRecord.model_validate_json(row.record_json)
            for row in store.coverage_page(case_id=str(cycle.case_id), offset=0, limit=10)
        )
        event_coverage = next(item for item in coverage if item.category.startswith("eventlog"))
        assert event_coverage.status is CoverageStatus.FAILED
        assert "OSError" in (event_coverage.reason or "")
        assert "very-secret-value" not in (event_coverage.reason or "")
        assert "<redacted-error-detail>" in (event_coverage.reason or "")
        assert cycle.failure_count == 1


def test_capture_timestamps_each_completed_operation_and_cycle_finish(tmp_path: Path) -> None:
    instants = tuple(_NOW + timedelta(seconds=index) for index in range(6))
    clock = iter(instants)
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        cycle = PassiveRecorder(
            store=store,
            runner=_Runner(),
            event_log=_EventLog((EventQuery(status=QueryStatus.OK),)),
            config=_config(),
            now=lambda: next(clock),
        ).capture_once()

        evidence = tuple(
            EvidenceRecord.model_validate_json(row.record_json)
            for row in store.evidence_page(case_id=str(cycle.case_id), offset=0, limit=10)
        )
        coverage = tuple(
            CoverageRecord.model_validate_json(row.record_json)
            for row in store.coverage_page(case_id=str(cycle.case_id), offset=0, limit=10)
        )

        assert {record.captured_at for record in evidence} == {instants[1], instants[2]}
        assert {record.captured_at for record in coverage} == {
            instants[1],
            instants[2],
            instants[4],
        }
        assert cycle.started_at == instants[0]
        assert cycle.finished_at == instants[5]


def test_retention_prunes_only_old_or_excess_passive_cases(tmp_path: Path) -> None:
    event_log = _EventLog(tuple(EventQuery(status=QueryStatus.OK) for _ in range(3)))
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        store.create_case(
            case_id="case_ffffffffffffffffffffffffffffffff",
            kind="general",
            symptom="real incident",
            created_at=(_NOW - timedelta(days=30)).isoformat(),
        )
        clock = iter(
            _NOW + timedelta(minutes=cycle, seconds=step) for cycle in range(3) for step in range(6)
        )
        recorder = PassiveRecorder(
            store=store,
            runner=_Runner(),
            event_log=event_log,
            config=_config(max_passive_cases=2),
            now=lambda: next(clock),
        )

        results = tuple(recorder.capture_once() for _ in range(3))

        assert results[-1].passive_cases_pruned == 1
        assert store.case("case_ffffffffffffffffffffffffffffffff") is not None
        passive = store.cases(kinds=("passive",), limit=10)
        assert len(passive) == 2


def test_retention_preserves_passive_cases_pinned_by_checkpoint_history(tmp_path: Path) -> None:
    event_log = _EventLog(tuple(EventQuery(status=QueryStatus.OK) for _ in range(3)))
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        clock = iter(
            _NOW + timedelta(minutes=cycle, seconds=step) for cycle in range(3) for step in range(6)
        )
        recorder = PassiveRecorder(
            store=store,
            runner=_Runner(),
            event_log=event_log,
            config=_config(max_passive_cases=2),
            now=lambda: next(clock),
        )
        pinned = recorder.capture_once()
        active_case = "case_ffffffffffffffffffffffffffffffff"
        store.create_case(
            case_id=active_case,
            kind="general",
            symptom="references passive history",
            created_at=_NOW.isoformat(),
        )
        store.connection.execute(
            "INSERT INTO investigation_checkpoints (case_id, record_json) VALUES (?, ?)",
            (
                active_case,
                '{"historical_case_ids":["' + str(pinned.case_id) + '"]}',
            ),
        )

        recorder.capture_once()
        result = recorder.capture_once()

        assert result.passive_cases_pruned == 0
        assert result.pinned_cases_preserved == 1
        assert store.case(str(pinned.case_id)) is not None
        assert len(store.cases(kinds=("passive",), limit=10)) == 3


class _CancelAfterWait:
    def __init__(self) -> None:
        self.waits: list[float] = []

    def is_set(self) -> bool:
        return False

    def wait(self, seconds: float) -> bool:
        self.waits.append(seconds)
        return True


class _NeverCancel:
    def __init__(self) -> None:
        self.wait_count = 0

    def is_set(self) -> bool:
        return False

    def wait(self, _seconds: float) -> bool:
        self.wait_count += 1
        return False


class _BrokenRunner(_Runner):
    def manifest(self, probe_id: str) -> _Manifest:
        del probe_id
        raise RuntimeError("broken fixture")


class _MissingManifestRunner(_Runner):
    def manifest(self, probe_id: str) -> None:
        del probe_id
        return None


def test_missing_passive_probe_is_journaled_and_audited(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        cycle = PassiveRecorder(
            store=store,
            runner=_MissingManifestRunner(),
            event_log=_EventLog((EventQuery(status=QueryStatus.OK),)),
            config=_config(),
            now=lambda: _NOW,
        ).capture_once()

        assert store.probe_execution_count(case_id=str(cycle.case_id)) == 3
        entries = store.audit_entries(case_id=str(cycle.case_id))
        assert [entry.outcome.value for entry in entries] == ["failed", "failed", "allowed"]
        assert AuditChain.verify(
            entries,
            checkpoint=store.audit_checkpoint(case_id=str(cycle.case_id)),
        ).valid


def test_failed_cycle_attempts_still_count_toward_max_cycles(tmp_path: Path) -> None:
    cancel = _NeverCancel()
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        status = PassiveRecorder(
            store=store,
            runner=_BrokenRunner(),
            event_log=_EventLog(()),
            config=_config(),
            now=lambda: _NOW,
        ).run(cancel, max_cycles=2)  # type: ignore[arg-type]

        assert cancel.wait_count == 1
        assert status.cycles_completed == 0
        assert status.dropped_cycles == 2


def test_run_wait_is_cancellable_and_reports_final_counters(tmp_path: Path) -> None:
    cancel = _CancelAfterWait()
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        recorder = PassiveRecorder(
            store=store,
            runner=_Runner(),
            event_log=_EventLog((EventQuery(status=QueryStatus.OK),)),
            config=_config(),
            now=lambda: _NOW,
        )

        status = recorder.run(cancel, max_cycles=5)  # type: ignore[arg-type]

        assert cancel.waits == [5]
        assert status.active is False
        assert status.cycles_completed == 1
        assert status.evidence_persisted == 2
        assert status.coverage_persisted == 3
