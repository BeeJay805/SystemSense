import threading
import time

from systemsense.orchestration.executor import (
    ProbeExecutor,
    WorkerExecution,
    WorkerExecutionStatus,
)
from systemsense.orchestration.scheduler import BlockingCancellationToken


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


def test_cancellation_terminates_the_owned_worker_with_a_true_wall_bound() -> None:
    token = BlockingCancellationToken(threading.Event())
    results: list[WorkerExecution] = []
    started = time.monotonic()
    thread = threading.Thread(
        target=lambda: results.append(
            ProbeExecutor().execute(
                "fixture.partial_then_sleep",
                {"delay_ms": 5000},
                timeout_ms=10_000,
                cancellation=token,
            )
        )
    )
    thread.start()
    time.sleep(0.2)
    token.cancel()
    thread.join(timeout=1.5)

    assert not thread.is_alive()
    assert len(results) == 1
    result = results[0]
    assert result.status is WorkerExecutionStatus.CANCELLED
    assert time.monotonic() - started < 1.5


def test_nonzero_worker_exit_cannot_report_success() -> None:
    result = ProbeExecutor().execute("fixture.false_success", {}, timeout_ms=1000)

    assert result.status is WorkerExecutionStatus.FAILED
    assert result.error == "worker exited with code 7"


def test_output_limit_stops_worker_without_buffering_unbounded_data() -> None:
    started = time.monotonic()
    result = ProbeExecutor().execute(
        "fixture.unbounded_output",
        {"size": 2_000_000},
        timeout_ms=5000,
    )

    assert result.status is WorkerExecutionStatus.FAILED
    assert result.error == "worker output exceeded limit"
    assert time.monotonic() - started < 1.5


def test_non_object_worker_messages_are_ignored_as_bounded_failure() -> None:
    evidence, status, error = ProbeExecutor._parse_output(  # pyright: ignore[reportPrivateUsage]
        '[]\n1\nnull\n"text"'
    )

    assert evidence == ()
    assert status is WorkerExecutionStatus.FAILED
    assert error is None
