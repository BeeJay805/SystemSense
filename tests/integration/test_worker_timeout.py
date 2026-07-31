import time

from systemsense.orchestration.executor import ProbeExecutor, WorkerExecutionStatus


def test_timeout_terminates_only_worker_and_preserves_partial_evidence() -> None:
    started = time.monotonic()

    result = ProbeExecutor().execute(
        "fixture.partial_then_sleep",
        {"delay_ms": 5000},
        timeout_ms=1000,
    )
    elapsed = time.monotonic() - started

    assert result.status is WorkerExecutionStatus.TIMED_OUT
    assert result.evidence == ({"stage": "started"},)
    assert elapsed < 3.0
