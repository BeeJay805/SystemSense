import asyncio
import socket
import threading
import time
from collections.abc import Callable, Coroutine
from datetime import UTC, datetime, timedelta
from functools import wraps
from typing import Any, cast

import pytest

from systemsense.orchestration.scheduler import (
    BoundedScheduler,
    ResourceBudget,
    ResourceClass,
    Task,
    TaskGraph,
    TaskGraphError,
    TaskResult,
    TaskStatus,
)


async def _noop(_context: object) -> str:
    return "ok"


def _async_test(function: Callable[..., Coroutine[Any, Any, None]]) -> Callable[..., None]:
    @wraps(function)
    def wrapper(*args: Any, **kwargs: Any) -> None:
        asyncio.run(function(*args, **kwargs))

    return wrapper


def _task(
    task_id: str,
    *,
    dependencies: tuple[str, ...] = (),
    resource: ResourceClass = ResourceClass.CPU,
    dedupe_key: str | None = None,
    priority: int = 0,
    state_version: int = 0,
    timeout_seconds: float | None = None,
    action: Callable[[object], Any] = _noop,
) -> Task:
    return Task(
        task_id=task_id,
        action=action,
        dependencies=dependencies,
        resource=resource,
        dedupe_key=dedupe_key,
        priority=priority,
        state_version=state_version,
        timeout_seconds=timeout_seconds,
    )


def test_task_graph_rejects_duplicate_and_missing_dependencies() -> None:
    with pytest.raises(TaskGraphError, match="duplicate task ID"):
        TaskGraph((_task("same"), _task("same")))

    with pytest.raises(TaskGraphError, match="missing dependency"):
        TaskGraph((_task("child", dependencies=("missing",)),))


def test_task_graph_rejects_cycles() -> None:
    with pytest.raises(TaskGraphError, match="cycle"):
        TaskGraph((_task("a", dependencies=("b",)), _task("b", dependencies=("a",))))


def test_scheduler_rejects_task_graphs_over_the_admission_bound() -> None:
    graph = TaskGraph(tuple(_task(f"task-{index}") for index in range(3)))

    with pytest.raises(TaskGraphError, match="max_tasks"):
        asyncio.run(BoundedScheduler(budget=ResourceBudget(max_tasks=2)).run(graph))


def test_blocking_scheduler_never_creates_network_sockets() -> None:
    original_socketpair = socket.socketpair

    def fail_socketpair(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("blocking scheduler must not create socketpairs")

    socket.socketpair = fail_socketpair  # type: ignore[assignment]
    try:
        results = BoundedScheduler().run_blocking((_task("one", action=lambda _context: "ok"),))
    finally:
        socket.socketpair = original_socketpair

    assert results[0].status is TaskStatus.SUCCEEDED


def test_blocking_scheduler_overlaps_tasks_and_preserves_declaration_order() -> None:
    entered = [threading.Event(), threading.Event()]
    release = threading.Event()
    active = 0
    maximum = 0
    lock = threading.Lock()

    def collect(context: object) -> str:
        nonlocal active, maximum
        task_id = cast("Any", context).task_id
        index = 0 if task_id == "first" else 1
        with lock:
            active += 1
            maximum = max(maximum, active)
        entered[index].set()
        release.wait(timeout=1)
        with lock:
            active -= 1
        return task_id

    run = threading.Thread(
        target=lambda: results.extend(
            BoundedScheduler(budget=ResourceBudget(global_limit=2)).run_blocking(
                (_task("second", action=collect), _task("first", action=collect))
            )
        )
    )
    results: list[Any] = []
    run.start()
    assert entered[0].wait(0.5)
    assert entered[1].wait(0.5)
    release.set()
    run.join(timeout=1)

    assert maximum == 2
    assert [result.task_id for result in results] == ["second", "first"]
    assert all(result.status is TaskStatus.SUCCEEDED for result in results)


def test_blocking_scheduler_enforces_resource_caps_and_dependencies() -> None:
    order: list[str] = []
    active_disk = 0
    maximum_disk = 0
    lock = threading.Lock()

    def collect(context: object) -> str:
        nonlocal active_disk, maximum_disk
        task_id = cast("Any", context).task_id
        order.append(task_id)
        if task_id.startswith("disk"):
            with lock:
                active_disk += 1
                maximum_disk = max(maximum_disk, active_disk)
            time.sleep(0.01)
            with lock:
                active_disk -= 1
        return task_id

    results = BoundedScheduler(
        budget=ResourceBudget(global_limit=3, per_resource={ResourceClass.DISK: 1})
    ).run_blocking(
        (
            _task("dependent", dependencies=("disk-0",), action=collect),
            _task("disk-0", resource=ResourceClass.DISK, action=collect),
            _task("disk-1", resource=ResourceClass.DISK, action=collect),
        )
    )

    assert maximum_disk == 1
    assert order.index("disk-0") < order.index("dependent")
    assert all(result.status is TaskStatus.SUCCEEDED for result in results)


def test_blocking_scheduler_rejects_async_actions_as_typed_failures() -> None:
    async def collect(_context: object) -> str:
        return "not supported"

    result = BoundedScheduler().run_blocking((_task("async", action=collect),))[0]

    assert result.status is TaskStatus.FAILED
    assert result.error == "TypeError: run_blocking does not accept async task actions"


def test_blocking_scheduler_drains_timed_out_work_before_releasing_capacity() -> None:
    first_started = threading.Event()
    release_first = threading.Event()
    second_started = threading.Event()

    def collect(context: object) -> None:
        if cast("Any", context).task_id == "first":
            first_started.set()
            release_first.wait(timeout=1)
        else:
            second_started.set()

    results: list[Any] = []
    run = threading.Thread(
        target=lambda: results.extend(
            BoundedScheduler(budget=ResourceBudget(global_limit=1)).run_blocking(
                (
                    _task("first", timeout_seconds=0.01, action=collect),
                    _task("second", action=collect),
                )
            )
        )
    )
    run.start()
    assert first_started.wait(0.5)
    time.sleep(0.03)
    assert not second_started.is_set()
    release_first.set()
    run.join(timeout=1)

    assert results[0].status is TaskStatus.TIMED_OUT
    assert results[1].status is TaskStatus.SUCCEEDED


def test_blocking_scheduler_supports_cooperative_external_cancellation() -> None:
    cancellation = threading.Event()
    started = threading.Event()

    def collect(context: object) -> str:
        started.set()
        token = cast("Any", context).cancellation
        while not token.cancelled:
            time.sleep(0.001)
        return "stopped"

    results: list[Any] = []
    run = threading.Thread(
        target=lambda: results.extend(
            BoundedScheduler().run_blocking(
                (_task("first", action=collect),), cancel_event=cancellation
            )
        )
    )
    run.start()
    assert started.wait(0.5)
    cancellation.set()
    run.join(timeout=1)

    assert results[0].status is TaskStatus.CANCELLED


@_async_test
async def test_independent_tasks_overlap_and_results_follow_declared_order() -> None:
    entered = [asyncio.Event(), asyncio.Event()]
    release = asyncio.Event()

    async def collect(context: object) -> str:
        task_id = cast("Any", context).task_id
        index = 0 if task_id == "first" else 1
        entered[index].set()
        await release.wait()
        return task_id

    async def wait_for_both() -> None:
        await asyncio.gather(*(event.wait() for event in entered))
        release.set()

    tasks = (_task("second", action=collect), _task("first", action=collect))
    run = asyncio.create_task(BoundedScheduler().run(tasks))
    await wait_for_both()
    results = await run

    assert [result.task_id for result in results] == ["second", "first"]
    assert all(result.status is TaskStatus.SUCCEEDED for result in results)


@_async_test
async def test_ready_tasks_are_admitted_by_priority_not_declaration_order() -> None:
    order: list[str] = []

    async def collect(context: object) -> None:
        order.append(cast("Any", context).task_id)

    results = await BoundedScheduler(budget=ResourceBudget(global_limit=1)).run(
        (
            _task("low", priority=1, action=collect),
            _task("high", priority=10, action=collect),
        )
    )

    assert order == ["high", "low"]
    assert [result.task_id for result in results] == ["low", "high"]


@_async_test
async def test_dependencies_wait_and_failed_prerequisite_blocks_dependent() -> None:
    order: list[str] = []

    async def fail(context: object) -> None:
        order.append(cast("Any", context).task_id)
        raise RuntimeError("source unavailable")

    async def should_not_run(context: object) -> None:
        order.append(cast("Any", context).task_id)

    results = await BoundedScheduler().run(
        (
            _task("dependent", dependencies=("source",), action=should_not_run),
            _task("source", action=fail),
        )
    )

    assert order == ["source"]
    assert results[0].status is TaskStatus.BLOCKED
    assert results[1].status is TaskStatus.FAILED
    assert "source unavailable" in (results[1].error or "")


@_async_test
async def test_global_and_per_resource_limits_are_enforced() -> None:
    active = 0
    maximum = 0
    lock = asyncio.Lock()

    async def collect(_context: object) -> None:
        nonlocal active, maximum
        async with lock:
            active += 1
            maximum = max(maximum, active)
        await asyncio.sleep(0.01)
        async with lock:
            active -= 1

    results = await BoundedScheduler(
        budget=ResourceBudget(
            global_limit=3,
            per_resource={ResourceClass.DISK: 1, ResourceClass.CPU: 2},
        )
    ).run(
        tuple(
            _task(f"disk-{index}", resource=ResourceClass.DISK, action=collect)
            for index in range(3)
        )
        + tuple(
            _task(f"cpu-{index}", resource=ResourceClass.CPU, action=collect) for index in range(3)
        )
    )

    assert all(result.status is TaskStatus.SUCCEEDED for result in results)
    assert maximum <= 3


@_async_test
async def test_duplicate_dedupe_keys_execute_once_and_followers_are_marked() -> None:
    calls = 0

    async def collect(_context: object) -> str:
        nonlocal calls
        calls += 1
        return "shared"

    results = await BoundedScheduler().run(
        (
            _task("leader", dedupe_key="same", action=collect),
            _task("follower", dedupe_key="same", action=collect),
        )
    )

    assert calls == 1
    assert results[0].status is TaskStatus.SUCCEEDED
    assert results[1].status is TaskStatus.DEDUPLICATED
    assert results[1].deduplicated_from == "leader"


@_async_test
async def test_state_version_is_checked_before_and_after_execution() -> None:
    current = [2]
    started = [0]

    async def collect(_context: object) -> str:
        started[0] += 1
        return "value"

    stale_before = await BoundedScheduler().run(
        (_task("old", state_version=1, action=collect),),
        state_version=lambda: current[0],
    )
    assert stale_before[0].status is TaskStatus.STALE
    assert started == [0]

    current[0] = 1

    async def update(_context: object) -> str:
        current[0] = 2
        return "value"

    stale_after = await BoundedScheduler().run(
        (_task("changes", state_version=1, action=update),),
        state_version=lambda: current[0],
    )
    assert stale_after[0].status is TaskStatus.STALE


@_async_test
async def test_task_and_case_deadlines_are_explicit_timeouts() -> None:
    async def slow(_context: object) -> None:
        await asyncio.sleep(0.05)

    task_timeout = await BoundedScheduler().run(
        (_task("slow", timeout_seconds=0.001, action=slow),)
    )
    assert task_timeout[0].status is TaskStatus.TIMED_OUT

    case_timeout = await BoundedScheduler().run(
        (_task("queued", action=slow),),
        case_deadline_at=datetime.now(UTC) + timedelta(milliseconds=1),
    )
    assert case_timeout[0].status is TaskStatus.TIMED_OUT


@_async_test
async def test_timed_out_sync_action_is_drained_before_next_admission() -> None:
    first_started = threading.Event()
    release_first = threading.Event()
    second_started = threading.Event()
    active = 0
    maximum = 0
    lock = threading.Lock()

    def collect(context: object) -> None:
        nonlocal active, maximum
        task_id = cast("Any", context).task_id
        with lock:
            active += 1
            maximum = max(maximum, active)
        if task_id == "first":
            first_started.set()
            release_first.wait(timeout=1)
        else:
            second_started.set()
            time.sleep(0.005)
        with lock:
            active -= 1

    run = asyncio.create_task(
        BoundedScheduler(budget=ResourceBudget(global_limit=1)).run(
            (
                _task("first", timeout_seconds=0.01, action=collect),
                _task("second", action=collect),
            )
        )
    )
    assert await asyncio.to_thread(first_started.wait, 0.2)
    await asyncio.sleep(0.02)
    assert not second_started.is_set()
    release_first.set()

    results = await run
    assert results[0].status is TaskStatus.TIMED_OUT
    assert results[1].status is TaskStatus.SUCCEEDED
    assert maximum == 1


@_async_test
async def test_queued_cancellation_yields_cancelled_without_starting_task() -> None:
    cancellation = asyncio.Event()
    first_started = asyncio.Event()
    started = [0]

    async def hold(context: object) -> None:
        started[0] += 1
        if cast("Any", context).task_id == "first":
            first_started.set()
        await asyncio.sleep(0.05)

    async def cancel() -> None:
        await first_started.wait()
        cancellation.set()

    cancellation_task = asyncio.create_task(cancel())
    results = await BoundedScheduler(budget=ResourceBudget(global_limit=1)).run(
        (_task("first", action=hold), _task("queued", action=hold)),
        cancel_event=cancellation,
    )
    await cancellation_task

    assert results[1].status is TaskStatus.CANCELLED
    assert started[0] == 1


@_async_test
async def test_worker_exception_becomes_typed_failure_with_utc_provenance() -> None:
    async def fail(_context: object) -> None:
        raise ValueError("bad probe")

    result = (await BoundedScheduler().run((_task("bad", action=fail),)))[0]

    assert result.status is TaskStatus.FAILED
    assert result.error == "ValueError: bad probe"
    assert result.started_at is not None and result.started_at.tzinfo is UTC
    assert result.finished_at is not None and result.finished_at.tzinfo is UTC
    assert result.duration_ms >= 0


def test_blocking_scheduler_publishes_results_before_later_probe_finishes() -> None:
    import threading

    published = threading.Event()

    def slow(_context: object) -> str:
        if not published.wait(timeout=1):
            raise RuntimeError("fast completion was not published while another probe ran")
        return "slow"

    def on_result(result: TaskResult) -> None:
        if result.task_id == "fast":
            published.set()

    result = BoundedScheduler().run_blocking(
        (Task(task_id="fast", action=lambda _context: "fast"), Task(task_id="slow", action=slow)),
        on_result=on_result,
    )
    assert all(item.status is TaskStatus.SUCCEEDED for item in result)


def test_blocking_scheduler_blocks_dependents_when_result_is_semantically_failed() -> None:
    published: list[TaskResult] = []
    dependent_calls = 0
    failed_value = {"status": "failed", "execution_id": "exec_preserved"}

    def dependent(_context: object) -> str:
        nonlocal dependent_calls
        dependent_calls += 1
        return "must not run"

    results = BoundedScheduler().run_blocking(
        (
            Task(
                task_id="probe",
                action=lambda _context: failed_value,
                accept_result=lambda value: cast("dict[str, str]", value)["status"] == "ok",
            ),
            Task(task_id="dependent", action=dependent, dependencies=("probe",)),
        ),
        on_result=published.append,
    )

    assert results[0].status is TaskStatus.FAILED
    assert results[0].value is failed_value
    assert results[1].status is TaskStatus.BLOCKED
    assert dependent_calls == 0
    assert {item.task_id for item in published} == {"probe", "dependent"}
