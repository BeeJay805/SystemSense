"""Bounded dependency-aware scheduling for read-only diagnostic work."""

from __future__ import annotations

import asyncio
import inspect
import threading
import time
from collections.abc import Awaitable, Callable, Mapping, Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import Any


class ResourceClass(StrEnum):
    CPU = "cpu"
    DISK = "disk"
    GPU = "gpu"
    NETWORK = "network"
    PROCESS = "process"
    INFERENCE = "inference"


_EMPTY_RESOURCE_LIMITS: Mapping[ResourceClass, int] = MappingProxyType({})


@dataclass(frozen=True, slots=True)
class ResourceBudget:
    """Global, per-resource, and graph admission limits.

    ``max_tasks`` is an input/backpressure bound, not a concurrency limit. It
    prevents an untrusted or model-generated plan from creating an unbounded
    scheduler queue before the global and per-resource limits can take effect.
    """

    global_limit: int = 4
    per_resource: Mapping[ResourceClass, int] = _EMPTY_RESOURCE_LIMITS
    max_tasks: int = 256

    def __post_init__(self) -> None:
        if self.global_limit < 1:
            raise ValueError("global_limit must be positive")
        if self.max_tasks < 1:
            raise ValueError("max_tasks must be positive")
        normalized = {ResourceClass(key): value for key, value in self.per_resource.items()}
        if any(value < 1 for value in normalized.values()):
            raise ValueError("per-resource limits must be positive")
        object.__setattr__(self, "per_resource", MappingProxyType(normalized))

    def limit_for(self, resource: ResourceClass) -> int:
        return min(self.global_limit, self.per_resource.get(resource, self.global_limit))


ResourceBudgets = ResourceBudget


class TaskStatus(StrEnum):
    SUCCEEDED = "succeeded"
    SUCCESS = "succeeded"
    FAILED = "failed"
    BLOCKED = "blocked"
    DEDUPLICATED = "deduplicated"
    STALE = "stale"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"


@dataclass(frozen=True, slots=True)
class CancellationToken:
    """Cooperative cancellation state exposed to a read-only probe."""

    _event: asyncio.Event = field(compare=False, repr=False)

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def cancel(self) -> None:
        self._event.set()

    async def wait(self) -> None:
        await self._event.wait()


@dataclass(frozen=True, slots=True)
class BlockingCancellationToken:
    """Cooperative cancellation state for synchronous collectors."""

    _event: threading.Event = field(compare=False, repr=False)

    @property
    def cancelled(self) -> bool:
        return self._event.is_set()

    def cancel(self) -> None:
        self._event.set()

    def wait(self, timeout: float | None = None) -> bool:
        return self._event.wait(timeout)


@dataclass(frozen=True, slots=True)
class TaskContext:
    task_id: str
    expected_state_version: int
    deadline_at: datetime | None
    cancellation: CancellationToken | BlockingCancellationToken


TaskAction = Callable[[TaskContext], Awaitable[Any] | Any]
StateVersion = int | Callable[[], int]


@dataclass(frozen=True, slots=True)
class Task:
    """A typed, read-only unit of work in an executable DAG."""

    task_id: str
    action: TaskAction
    dependencies: tuple[str, ...] = ()
    resource: ResourceClass = ResourceClass.CPU
    priority: int = 0
    dedupe_key: str | None = None
    state_version: int = 0
    timeout_seconds: float | None = None
    deadline_at: datetime | None = None
    accept_result: Callable[[Any], bool] | None = field(default=None, compare=False, repr=False)

    def __post_init__(self) -> None:
        if not self.task_id:
            raise ValueError("task_id must not be empty")
        if len(set(self.dependencies)) != len(self.dependencies):
            raise ValueError("task dependencies must be unique")
        if self.task_id in self.dependencies:
            raise ValueError("task cannot depend on itself")
        if self.dedupe_key == "":
            raise ValueError("dedupe_key must not be empty")
        if self.timeout_seconds is not None and self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if self.deadline_at is not None and self.deadline_at.tzinfo is None:
            raise ValueError("deadline_at must be timezone-aware")
        object.__setattr__(self, "dependencies", tuple(self.dependencies))


class TaskGraphError(ValueError):
    """The proposed execution graph cannot be scheduled safely."""


@dataclass(frozen=True, slots=True)
class TaskGraph:
    tasks: tuple[Task, ...]

    def __post_init__(self) -> None:
        tasks = tuple(self.tasks)
        object.__setattr__(self, "tasks", tasks)
        ids = [task.task_id for task in tasks]
        if len(ids) != len(set(ids)):
            raise TaskGraphError("duplicate task ID")
        task_ids = set(ids)
        for task in tasks:
            missing = sorted(set(task.dependencies) - task_ids)
            if missing:
                raise TaskGraphError(f"missing dependency for {task.task_id}: {', '.join(missing)}")
        visiting: set[str] = set()
        visited: set[str] = set()
        by_id = {task.task_id: task for task in tasks}

        def visit(task_id: str) -> None:
            if task_id in visiting:
                raise TaskGraphError("cycle in task dependencies")
            if task_id in visited:
                return
            visiting.add(task_id)
            for dependency in by_id[task_id].dependencies:
                visit(dependency)
            visiting.remove(task_id)
            visited.add(task_id)

        for task_id in ids:
            visit(task_id)


@dataclass(frozen=True, slots=True)
class TaskResult:
    task_id: str
    status: TaskStatus
    value: Any = None
    error: str | None = None
    deduplicated_from: str | None = None
    underlying_status: TaskStatus | None = None
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_ms: float = 0.0
    state_version: int | None = None

    @property
    def satisfies_dependency(self) -> bool:
        return self.status is TaskStatus.SUCCEEDED or (
            self.status is TaskStatus.DEDUPLICATED
            and self.underlying_status is TaskStatus.SUCCEEDED
        )


class BoundedScheduler:
    """Run independent read-only tasks concurrently within explicit budgets."""

    def __init__(self, *, budget: ResourceBudget | None = None) -> None:
        self._budget = budget or ResourceBudget()

    async def run(
        self,
        tasks: TaskGraph | Sequence[Task],
        *,
        case_deadline_at: datetime | None = None,
        cancel_event: asyncio.Event | None = None,
        state_version: StateVersion = 0,
    ) -> tuple[TaskResult, ...]:
        graph = tasks if isinstance(tasks, TaskGraph) else TaskGraph(tuple(tasks))
        if case_deadline_at is not None and case_deadline_at.tzinfo is None:
            raise ValueError("case_deadline_at must be timezone-aware")
        state_provider = state_version if callable(state_version) else lambda: state_version
        declaration_order = {task.task_id: index for index, task in enumerate(graph.tasks)}
        by_id = {task.task_id: task for task in graph.tasks}
        if len(graph.tasks) > self._budget.max_tasks:
            raise TaskGraphError(f"task graph exceeds max_tasks ({self._budget.max_tasks})")
        pending = set(by_id)
        results: dict[str, TaskResult] = {}
        running: dict[str, asyncio.Task[TaskResult]] = {}
        dedupe_leaders: dict[str, str] = {}
        admitted_global = 0
        admitted_resources: dict[ResourceClass, int] = dict.fromkeys(ResourceClass, 0)
        semaphores = {
            resource: asyncio.Semaphore(self._budget.limit_for(resource))
            for resource in ResourceClass
        }
        global_semaphore = asyncio.Semaphore(self._budget.global_limit)

        while pending or running:
            now = _utc_now()
            if cancel_event is not None and cancel_event.is_set():
                for task_id in tuple(pending):
                    results[task_id] = _queued_result(task_id, TaskStatus.CANCELLED)
                    pending.remove(task_id)
                for worker in running.values():
                    worker.cancel()
                if running:
                    await asyncio.gather(*running.values(), return_exceptions=True)
                    for task_id, _worker in running.items():
                        if task_id not in results:
                            results[task_id] = _queued_result(task_id, TaskStatus.CANCELLED)
                    running.clear()
                break
            if case_deadline_at is not None and now >= case_deadline_at:
                for task_id in tuple(pending):
                    results[task_id] = _queued_result(task_id, TaskStatus.TIMED_OUT)
                    pending.remove(task_id)
                for worker in running.values():
                    worker.cancel()
                if running:
                    await asyncio.gather(*running.values(), return_exceptions=True)
                    for task_id in tuple(running):
                        if task_id not in results:
                            results[task_id] = _queued_result(task_id, TaskStatus.TIMED_OUT)
                    running.clear()
                break

            progress = True
            while progress:
                progress = False
                for task_id in sorted(
                    pending,
                    key=lambda item: (-by_id[item].priority, declaration_order[item]),
                ):
                    task = by_id[task_id]
                    dependency_results = [results.get(item) for item in task.dependencies]
                    if not all(item is not None for item in dependency_results):
                        continue
                    if any(not item.satisfies_dependency for item in dependency_results if item):
                        results[task_id] = _queued_result(
                            task_id,
                            TaskStatus.BLOCKED,
                            error="a prerequisite did not succeed",
                        )
                        pending.remove(task_id)
                        progress = True
                        continue
                    current_version = state_provider()
                    if current_version != task.state_version:
                        results[task_id] = _queued_result(
                            task_id,
                            TaskStatus.STALE,
                            error="task state version is stale",
                            state_version=current_version,
                        )
                        pending.remove(task_id)
                        progress = True
                        continue
                    if task.dedupe_key is not None and task.dedupe_key in dedupe_leaders:
                        leader_id = dedupe_leaders[task.dedupe_key]
                        leader_result = results.get(leader_id)
                        if leader_result is None:
                            continue
                        results[task_id] = _deduplicated_result(task_id, leader_result)
                        pending.remove(task_id)
                        progress = True
                        continue
                    if admitted_global >= self._budget.global_limit or admitted_resources[
                        task.resource
                    ] >= self._budget.limit_for(task.resource):
                        continue
                    if task.dedupe_key is not None:
                        dedupe_leaders[task.dedupe_key] = task_id
                    pending.remove(task_id)
                    admitted_global += 1
                    admitted_resources[task.resource] += 1
                    running[task_id] = asyncio.create_task(
                        self._execute(
                            task,
                            global_semaphore=global_semaphore,
                            resource_semaphore=semaphores[task.resource],
                            case_deadline_at=case_deadline_at,
                            cancel_event=cancel_event,
                            state_provider=state_provider,
                        )
                    )
                    progress = True

            if not running:
                if pending:
                    raise RuntimeError("scheduler made no progress on a validated task graph")
                continue
            done, _ = await asyncio.wait(
                tuple(running.values()), return_when=asyncio.FIRST_COMPLETED
            )
            for task_id, worker in tuple(running.items()):
                if worker not in done:
                    continue
                try:
                    results[task_id] = worker.result()
                except asyncio.CancelledError:
                    results[task_id] = _queued_result(task_id, TaskStatus.CANCELLED)
                running.pop(task_id)
                admitted_global -= 1
                admitted_resources[by_id[task_id].resource] -= 1

        return tuple(results[task.task_id] for task in graph.tasks)

    def run_blocking(
        self,
        tasks: TaskGraph | Sequence[Task],
        *,
        case_deadline_at: datetime | None = None,
        cancel_event: threading.Event | None = None,
        state_version: StateVersion = 0,
        on_result: Callable[[TaskResult], None] | None = None,
    ) -> tuple[TaskResult, ...]:
        """Run synchronous collectors without creating an asyncio event loop.

        Windows' default asyncio event loop creates a socketpair for wakeups.
        The core investigator is intentionally socket-free, so this path uses
        a bounded thread pool and polls only threading primitives.  A thread
        cannot be killed safely: a timed-out or cancelled collector is marked
        immediately, but its worker remains admitted until it returns.  This
        prevents capacity from being released while non-killable read-only
        work is still touching the host.
        """

        graph = tasks if isinstance(tasks, TaskGraph) else TaskGraph(tuple(tasks))
        if case_deadline_at is not None and case_deadline_at.tzinfo is None:
            raise ValueError("case_deadline_at must be timezone-aware")
        if len(graph.tasks) > self._budget.max_tasks:
            raise TaskGraphError(f"task graph exceeds max_tasks ({self._budget.max_tasks})")

        state_provider = state_version if callable(state_version) else lambda: state_version
        declaration_order = {task.task_id: index for index, task in enumerate(graph.tasks)}
        by_id = {task.task_id: task for task in graph.tasks}
        pending = set(by_id)
        results: dict[str, TaskResult] = {}
        published: set[str] = set()
        running: dict[str, _BlockingWorker] = {}
        dedupe_leaders: dict[str, str] = {}
        stop_status: TaskStatus | None = None

        executor = ThreadPoolExecutor(
            max_workers=self._budget.global_limit,
            thread_name_prefix="systemsense-probe",
        )
        try:
            while pending or running:
                now = time.monotonic()
                if cancel_event is not None and cancel_event.is_set():
                    stop_status = TaskStatus.CANCELLED
                elif case_deadline_at is not None and _utc_now() >= case_deadline_at:
                    stop_status = TaskStatus.TIMED_OUT

                if stop_status is not None:
                    for task_id in tuple(pending):
                        results[task_id] = _queued_result(
                            task_id,
                            stop_status,
                            error=(
                                "task cancelled"
                                if stop_status is TaskStatus.CANCELLED
                                else "task deadline exceeded"
                            ),
                        )
                        pending.remove(task_id)
                    for worker in running.values():
                        if worker.terminal_status is None:
                            worker.terminal_status = stop_status
                            worker.token.cancel()

                progress = True
                while progress and stop_status is None:
                    progress = False
                    for task_id in sorted(
                        pending,
                        key=lambda item: (-by_id[item].priority, declaration_order[item]),
                    ):
                        task = by_id[task_id]
                        dependency_results = [results.get(item) for item in task.dependencies]
                        if not all(item is not None for item in dependency_results):
                            continue
                        if any(
                            not item.satisfies_dependency for item in dependency_results if item
                        ):
                            results[task_id] = _queued_result(
                                task_id,
                                TaskStatus.BLOCKED,
                                error="a prerequisite did not succeed",
                            )
                            pending.remove(task_id)
                            progress = True
                            continue
                        current_version = state_provider()
                        if current_version != task.state_version:
                            results[task_id] = _queued_result(
                                task_id,
                                TaskStatus.STALE,
                                error="task state version is stale",
                                state_version=current_version,
                            )
                            pending.remove(task_id)
                            progress = True
                            continue
                        if task.dedupe_key is not None and task.dedupe_key in dedupe_leaders:
                            leader_id = dedupe_leaders[task.dedupe_key]
                            leader_result = results.get(leader_id)
                            if leader_result is None:
                                continue
                            results[task_id] = _deduplicated_result(task_id, leader_result)
                            pending.remove(task_id)
                            progress = True
                            continue
                        if len(running) >= self._budget.global_limit:
                            continue
                        resource_count = sum(
                            worker.task.resource == task.resource for worker in running.values()
                        )
                        if resource_count >= self._budget.limit_for(task.resource):
                            continue

                        effective_deadline = _earliest_deadline(task.deadline_at, case_deadline_at)
                        deadline_mono = _monotonic_deadline(
                            effective_deadline,
                            task.timeout_seconds,
                        )
                        if deadline_mono is not None and deadline_mono <= now:
                            results[task_id] = _queued_result(
                                task_id,
                                TaskStatus.TIMED_OUT,
                                error="task deadline exceeded",
                                state_version=current_version,
                            )
                            pending.remove(task_id)
                            progress = True
                            continue

                        pending.remove(task_id)
                        if task.dedupe_key is not None:
                            dedupe_leaders[task.dedupe_key] = task_id
                        started_at = _utc_now()
                        started_mono = time.monotonic()
                        token = BlockingCancellationToken(threading.Event())
                        context = TaskContext(
                            task_id=task.task_id,
                            expected_state_version=task.state_version,
                            deadline_at=effective_deadline,
                            cancellation=token,
                        )
                        if inspect.iscoroutinefunction(task.action):
                            results[task_id] = _result(
                                task.task_id,
                                TaskStatus.FAILED,
                                started_at=started_at,
                                started_mono=started_mono,
                                error="TypeError: run_blocking does not accept async task actions",
                                state_version=current_version,
                            )
                            progress = True
                            continue
                        future = executor.submit(_invoke_blocking, task.action, context)
                        running[task_id] = _BlockingWorker(
                            task=task,
                            future=future,
                            token=token,
                            started_at=started_at,
                            started_mono=started_mono,
                            deadline_mono=deadline_mono,
                        )
                        progress = True

                now = time.monotonic()
                for worker in running.values():
                    if worker.terminal_status is None and (
                        worker.deadline_mono is not None and now >= worker.deadline_mono
                    ):
                        worker.terminal_status = TaskStatus.TIMED_OUT
                        worker.token.cancel()

                completed = [task_id for task_id, worker in running.items() if worker.future.done()]
                for task_id in completed:
                    worker = running.pop(task_id)
                    results[task_id] = _blocking_result(worker, state_provider)

                if on_result is not None:
                    for task_id, result in tuple(results.items()):
                        if task_id not in published:
                            on_result(result)
                            published.add(task_id)

                if not running:
                    if pending:
                        if stop_status is not None or completed:
                            continue
                        raise RuntimeError("scheduler made no progress on a validated task graph")
                    continue

                if not completed:
                    time.sleep(0.001)

            return tuple(results[task.task_id] for task in graph.tasks)
        finally:
            # ``wait=True`` is deliberate: a timed-out synchronous collector is
            # non-killable and must drain before its capacity can be reused.
            executor.shutdown(wait=True, cancel_futures=True)

    async def _execute(
        self,
        task: Task,
        *,
        global_semaphore: asyncio.Semaphore,
        resource_semaphore: asyncio.Semaphore,
        case_deadline_at: datetime | None,
        cancel_event: asyncio.Event | None,
        state_provider: Callable[[], int],
    ) -> TaskResult:
        effective_deadline = _earliest_deadline(task.deadline_at, case_deadline_at)
        mono_deadline = _monotonic_deadline(effective_deadline, task.timeout_seconds)
        acquired: list[asyncio.Semaphore] = []
        started_at: datetime | None = None
        started_mono: float | None = None
        action: asyncio.Task[Any] | None = None
        try:
            for semaphore in (global_semaphore, resource_semaphore):
                outcome = await _acquire(
                    semaphore,
                    mono_deadline=mono_deadline,
                    cancel_event=cancel_event,
                )
                if outcome is not None:
                    return _queued_result(task.task_id, outcome, state_version=state_provider())
                acquired.append(semaphore)
            started_at = _utc_now()
            started_mono = time.monotonic()
            current_version = state_provider()
            if current_version != task.state_version:
                return _result(
                    task.task_id,
                    TaskStatus.STALE,
                    started_at=started_at,
                    started_mono=started_mono,
                    error="task state version is stale",
                    state_version=current_version,
                )
            token_event = cancel_event or asyncio.Event()
            context = TaskContext(
                task_id=task.task_id,
                expected_state_version=task.state_version,
                deadline_at=effective_deadline,
                cancellation=CancellationToken(token_event),
            )
            action = asyncio.create_task(_invoke(task.action, context))
            cancel_wait: asyncio.Task[Any] | None = None
            if cancel_event is not None:
                cancel_wait = asyncio.create_task(cancel_event.wait())
            timeout_wait: asyncio.Task[Any] | None = None
            if mono_deadline is not None:
                timeout_wait = asyncio.create_task(
                    asyncio.sleep(max(0.0, mono_deadline - time.monotonic()))
                )
            waiters: list[asyncio.Task[Any]] = [action]
            if cancel_wait is not None:
                waiters.append(cancel_wait)
            if timeout_wait is not None:
                waiters.append(timeout_wait)
            done, _ = await asyncio.wait(waiters, return_when=asyncio.FIRST_COMPLETED)
            try:
                if (
                    action in done
                    and (cancel_wait is None or cancel_wait not in done)
                    and (timeout_wait is None or timeout_wait not in done)
                ):
                    value = action.result()
                elif cancel_wait is not None and cancel_wait in done:
                    action.cancel()
                    await asyncio.gather(action, return_exceptions=True)
                    return _result(
                        task.task_id,
                        TaskStatus.CANCELLED,
                        started_at=started_at,
                        started_mono=started_mono,
                        error="task cancelled",
                        state_version=current_version,
                    )
                else:
                    action.cancel()
                    await asyncio.gather(action, return_exceptions=True)
                    return _result(
                        task.task_id,
                        TaskStatus.TIMED_OUT,
                        started_at=started_at,
                        started_mono=started_mono,
                        error="task deadline exceeded",
                        state_version=current_version,
                    )
            finally:
                for waiter in (cancel_wait, timeout_wait):
                    if waiter is not None and not waiter.done():
                        waiter.cancel()
                await asyncio.gather(
                    *(waiter for waiter in (cancel_wait, timeout_wait) if waiter is not None),
                    return_exceptions=True,
                )
            final_version = state_provider()
            if final_version != task.state_version:
                return _result(
                    task.task_id,
                    TaskStatus.STALE,
                    started_at=started_at,
                    started_mono=started_mono,
                    value=value,
                    error="task state version changed during execution",
                    state_version=final_version,
                )
            acceptance_error = _acceptance_error(task, value)
            if acceptance_error is not None:
                return _result(
                    task.task_id,
                    TaskStatus.FAILED,
                    started_at=started_at,
                    started_mono=started_mono,
                    value=value,
                    error=acceptance_error,
                    state_version=final_version,
                )
            return _result(
                task.task_id,
                TaskStatus.SUCCEEDED,
                started_at=started_at,
                started_mono=started_mono,
                value=value,
                state_version=final_version,
            )
        except asyncio.CancelledError:
            if action is not None and not action.done():
                action.cancel()
                await asyncio.gather(action, return_exceptions=True)
            return _result(
                task.task_id,
                TaskStatus.CANCELLED,
                started_at=started_at,
                started_mono=started_mono,
                state_version=state_provider(),
            )
        except Exception as error:
            return _result(
                task.task_id,
                TaskStatus.FAILED,
                started_at=started_at,
                started_mono=started_mono,
                error=f"{type(error).__name__}: {error}",
                state_version=state_provider(),
            )
        finally:
            for semaphore in reversed(acquired):
                semaphore.release()


@dataclass(slots=True)
class _BlockingWorker:
    task: Task
    future: Future[Any]
    token: BlockingCancellationToken
    started_at: datetime
    started_mono: float
    deadline_mono: float | None
    terminal_status: TaskStatus | None = None


def _invoke_blocking(action: TaskAction, context: TaskContext) -> Any:
    result = action(context)
    if inspect.isawaitable(result):
        close = getattr(result, "close", None)
        if callable(close):
            close()
        raise TypeError("run_blocking does not accept async task actions")
    return result


def _blocking_result(
    worker: _BlockingWorker,
    state_provider: Callable[[], int],
) -> TaskResult:
    terminal_status = worker.terminal_status
    try:
        value = worker.future.result()
    except Exception as error:
        if terminal_status is None:
            return _result(
                worker.task.task_id,
                TaskStatus.FAILED,
                started_at=worker.started_at,
                started_mono=worker.started_mono,
                error=f"{type(error).__name__}: {error}",
                state_version=state_provider(),
            )
        value = None

    if terminal_status is not None:
        return _result(
            worker.task.task_id,
            terminal_status,
            started_at=worker.started_at,
            started_mono=worker.started_mono,
            value=value,
            error=(
                "task cancelled"
                if terminal_status is TaskStatus.CANCELLED
                else "task deadline exceeded"
            ),
            state_version=state_provider(),
        )

    final_version = state_provider()
    if final_version != worker.task.state_version:
        return _result(
            worker.task.task_id,
            TaskStatus.STALE,
            started_at=worker.started_at,
            started_mono=worker.started_mono,
            value=value,
            error="task state version changed during execution",
            state_version=final_version,
        )
    acceptance_error = _acceptance_error(worker.task, value)
    if acceptance_error is not None:
        return _result(
            worker.task.task_id,
            TaskStatus.FAILED,
            started_at=worker.started_at,
            started_mono=worker.started_mono,
            value=value,
            error=acceptance_error,
            state_version=final_version,
        )
    return _result(
        worker.task.task_id,
        TaskStatus.SUCCEEDED,
        started_at=worker.started_at,
        started_mono=worker.started_mono,
        value=value,
        state_version=final_version,
    )


def _acceptance_error(task: Task, value: Any) -> str | None:
    if task.accept_result is None:
        return None
    try:
        accepted = task.accept_result(value)
    except Exception as error:
        return f"result acceptance failed: {type(error).__name__}: {error}"
    return None if accepted else "task result did not satisfy success predicate"


async def _invoke(action: TaskAction, context: TaskContext) -> Any:
    # Shield the executor future so cancelling the scheduler task cannot leave
    # a synchronous collector running after its resource slot is released.
    executor_future = asyncio.get_running_loop().run_in_executor(None, action, context)
    try:
        result = await asyncio.shield(executor_future)
    except asyncio.CancelledError:
        if not executor_future.done():
            await asyncio.shield(executor_future)
        raise
    if inspect.isawaitable(result):
        return await result
    return result


async def _acquire(
    semaphore: asyncio.Semaphore,
    *,
    mono_deadline: float | None,
    cancel_event: asyncio.Event | None,
) -> TaskStatus | None:
    acquire_task = asyncio.create_task(semaphore.acquire())
    cancel_task: asyncio.Task[Any] | None = None
    if cancel_event is not None:
        cancel_task = asyncio.create_task(cancel_event.wait())
    timeout_task: asyncio.Task[Any] | None = None
    if mono_deadline is not None:
        timeout_task = asyncio.create_task(
            asyncio.sleep(max(0.0, mono_deadline - time.monotonic()))
        )
    waiters: list[asyncio.Task[Any]] = [acquire_task]
    if cancel_task is not None:
        waiters.append(cancel_task)
    if timeout_task is not None:
        waiters.append(timeout_task)
    done, _ = await asyncio.wait(waiters, return_when=asyncio.FIRST_COMPLETED)
    try:
        acquired = (
            acquire_task in done
            and not acquire_task.cancelled()
            and acquire_task.exception() is None
            and acquire_task.result()
        )
        if acquired:
            if cancel_task is not None and cancel_task in done:
                semaphore.release()
                return TaskStatus.CANCELLED
            if timeout_task is not None and timeout_task in done:
                semaphore.release()
                return TaskStatus.TIMED_OUT
            return None
        acquire_task.cancel()
        await asyncio.gather(acquire_task, return_exceptions=True)
        if cancel_task is not None and cancel_task in done:
            return TaskStatus.CANCELLED
        return TaskStatus.TIMED_OUT
    finally:
        for waiter in (cancel_task, timeout_task):
            if waiter is not None and not waiter.done():
                waiter.cancel()
        await asyncio.gather(
            *(waiter for waiter in (cancel_task, timeout_task) if waiter is not None),
            return_exceptions=True,
        )


def _earliest_deadline(first: datetime | None, second: datetime | None) -> datetime | None:
    if first is None:
        return second
    if second is None:
        return first
    return min(first, second)


def _monotonic_deadline(deadline: datetime | None, timeout_seconds: float | None) -> float | None:
    candidates: list[float] = []
    if deadline is not None:
        candidates.append(max(0.0, (deadline - _utc_now()).total_seconds()))
    if timeout_seconds is not None:
        candidates.append(timeout_seconds)
    return None if not candidates else time.monotonic() + min(candidates)


def _queued_result(
    task_id: str,
    status: TaskStatus,
    *,
    error: str | None = None,
    state_version: int | None = None,
) -> TaskResult:
    return TaskResult(
        task_id=task_id,
        status=status,
        error=error,
        finished_at=_utc_now(),
        state_version=state_version,
    )


def _deduplicated_result(task_id: str, leader: TaskResult) -> TaskResult:
    return TaskResult(
        task_id=task_id,
        status=TaskStatus.DEDUPLICATED,
        value=leader.value,
        error=leader.error,
        deduplicated_from=leader.task_id,
        underlying_status=leader.status,
        started_at=leader.started_at,
        finished_at=leader.finished_at,
        duration_ms=leader.duration_ms,
        state_version=leader.state_version,
    )


def _result(
    task_id: str,
    status: TaskStatus,
    *,
    started_at: datetime | None = None,
    started_mono: float | None = None,
    value: Any = None,
    error: str | None = None,
    state_version: int | None = None,
) -> TaskResult:
    finished_at = _utc_now()
    duration_ms = (
        0.0 if started_mono is None else max(0.0, (time.monotonic() - started_mono) * 1000)
    )
    return TaskResult(
        task_id=task_id,
        status=status,
        value=value,
        error=error,
        started_at=started_at,
        finished_at=finished_at,
        duration_ms=duration_ms,
        state_version=state_version,
    )


def _utc_now() -> datetime:
    return datetime.now(UTC)
