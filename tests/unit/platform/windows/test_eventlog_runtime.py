import sqlite3
import threading
from datetime import timedelta
from pathlib import Path
from typing import cast

import pytest
from pydantic import ValidationError

from systemsense.domain.time import utc_now
from systemsense.orchestration.executor import (
    ProbeLaunchLifecycle,
    WorkerExecution,
    WorkerExecutionStatus,
    WorkerTreeExitStatus,
)
from systemsense.orchestration.probe_capacity_ledger import DurableProbeLedger, LedgerBudget
from systemsense.orchestration.scheduler import (
    BlockingCancellationToken,
    HostWorkArbiter,
    ResourceBudget,
    ResourceClass,
)
from systemsense.platform.windows.eventlog import QueryStatus
from systemsense.platform.windows.eventlog_runtime import IsolatedEventLogAdapter


def test_eventlog_worker_rejects_free_form_channels_before_execution() -> None:
    with pytest.raises(ValidationError):
        IsolatedEventLogAdapter().query("System; arbitrary", after_record_id=None, limit=3)


def test_eventlog_worker_honors_expired_deadline_and_cancellation() -> None:
    adapter = IsolatedEventLogAdapter()
    expired = adapter.query(
        "Application",
        after_record_id=None,
        limit=3,
        deadline_at=utc_now() - timedelta(seconds=1),
    )
    assert expired.status is QueryStatus.FAILED
    assert expired.reason is not None and "deadline" in expired.reason
    event = threading.Event()
    event.set()
    cancelled = adapter.query(
        "System",
        after_record_id=None,
        limit=3,
        cancellation=BlockingCancellationToken(event),
    )
    assert cancelled.status is QueryStatus.FAILED
    assert cancelled.reason is not None and "cancel" in cancelled.reason


def test_managed_eventlog_passes_custody_and_quarantines_unknown_tree(tmp_path: Path) -> None:
    class Executor:
        def __init__(self) -> None:
            self.custody: object | None = None

        def execute(self, *_args: object, **kwargs: object) -> WorkerExecution:
            self.custody = kwargs.get("custody")
            cast("ProbeLaunchLifecycle", self.custody).record_launch_intent()
            return WorkerExecution(
                status=WorkerExecutionStatus.TIMED_OUT,
                tree_exit=WorkerTreeExitStatus.UNKNOWN,
                error="probe exceeded deadline",
            )

    executor = Executor()
    ledger_path = tmp_path / "capacity.sqlite3"
    ledger = DurableProbeLedger(
        ledger_path, LedgerBudget(global_limit=1, max_pending=2), schema_hash="eventlog-test-v1"
    )
    arbiter = HostWorkArbiter(ResourceBudget(global_limit=1), ledger=ledger)
    slot = arbiter.try_acquire(
        "passive:case", "eventlog.System", ResourceClass.DISK, 0, isolated_probe=True
    )
    assert slot is not None
    assert slot.custody is not None
    adapter = IsolatedEventLogAdapter(executor=executor, managed=True)  # type: ignore[arg-type]
    result = adapter.query("System", after_record_id=None, limit=3, host_slot=slot)
    slot.release()

    assert result.status is QueryStatus.FAILED
    assert executor.custody is slot.custody
    assert arbiter.quarantined_count == 1
    with sqlite3.connect(ledger_path) as connection:
        assert connection.execute("SELECT state FROM work").fetchone() == ("quarantined",)


def test_managed_eventlog_quarantines_when_executor_raises() -> None:
    class RaisingExecutor:
        def execute(self, *_args: object, **_kwargs: object) -> WorkerExecution:
            raise RuntimeError("worker outcome unknown")

    arbiter = HostWorkArbiter(ResourceBudget(global_limit=1))
    slot = arbiter.try_acquire(
        "passive:case", "eventlog.System", ResourceClass.DISK, 0, isolated_probe=True
    )
    assert slot is not None
    adapter = IsolatedEventLogAdapter(executor=RaisingExecutor(), managed=True)  # type: ignore[arg-type]
    with pytest.raises(RuntimeError):
        adapter.query("System", after_record_id=None, limit=3, host_slot=slot)
    slot.release()
    assert arbiter.quarantined_count == 1
