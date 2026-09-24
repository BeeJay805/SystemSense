"""Bounded dependency-aware scheduling for read-only diagnostic work."""

from __future__ import annotations

import asyncio
import inspect
import threading
import time
import uuid
from collections import deque
from collections.abc import Awaitable, Callable, Mapping, Sequence
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from types import MappingProxyType
from typing import TYPE_CHECKING, Any

from systemsense.domain.probes import ProbeInvocation
from systemsense.orchestration.probe_capacity_ledger import (
    DurableProbeLedger,
    LedgerUnavailable,
    QueueFull,
    Ticket,
)

if TYPE_CHECKING:
    from systemsense.orchestration.probe_capacity_custody import ProbeCapacityCustody


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


class HostQueueFull(RuntimeError):
    """The shared admission queue cannot accept more read-only work."""


@dataclass(frozen=True, slots=True)
class _HostTicket:
    run_id: str
    task_id: str
    resource: ResourceClass
    priority: int
    sequence: int


class HostWorkSlot:
    """A host slot held until the underlying worker actually exits."""

    def __init__(
        self, arbiter: HostWorkArbiter, slot_id: str, custody: ProbeCapacityCustody | None = None
    ) -> None:
        self._arbiter = arbiter
        self._slot_id = slot_id
        self.custody = custody
        self._released = False
        self._quarantined = False
        self._lock = threading.Lock()

    def release(self) -> None:
        with self._lock:
            if self._released or self._quarantined:
                return
            if self.custody is not None:
                try:
                    released = self.custody.release_or_quarantine()
                except Exception:
                    released = False
                if not released:
                    self._arbiter.quarantine_slot(self._slot_id, "durable custody unverified")
                    self._quarantined = True
                    return
            self._released = True
        self._arbiter.release_slot(self._slot_id)

    def quarantine(self, reason: str) -> None:
        """Keep capacity occupied when an isolated child tree may still run."""

        if not reason or len(reason) > 128:
            raise ValueError("slot quarantine reason must be bounded")
        with self._lock:
            if self._released:
                raise RuntimeError("released capacity cannot be quarantined")
            if self._quarantined:
                return
            if self.custody is not None:
                try:
                    self.custody.quarantine(reason)
                except Exception:
                    # The local slot still must remain occupied when durable
                    # custody cannot be confirmed.
                    pass
            self._arbiter.quarantine_slot(self._slot_id, reason)
            self._quarantined = True


class HostWorkArbiter:
    """Fair in-process admission shared by independent case schedulers.

    An optional durable ledger also arbitrates isolated probes across processes.
    Callers must keep a slot until the worker finishes, including after a reported timeout.
    Cases with less recent grants get the next available turn; task priority
    breaks ties only within one case so one busy case cannot starve another.
    """

    def __init__(self, budget: ResourceBudget, *, ledger: DurableProbeLedger | None = None) -> None:
        self._budget = budget
        self._ledger = ledger
        self._ledger_failed = False
        self._condition = threading.Condition()
        self._pending: dict[tuple[str, str], _HostTicket] = {}
        self._durable_pending: dict[tuple[str, str], Ticket] = {}
        self._durable_blocked_until: dict[tuple[str, str], float] = {}
        self._active: dict[str, tuple[str, ResourceClass]] = {}
        self._quarantined: dict[str, str] = {}
        self._served: dict[str, int] = {}
        self._completed: set[str] = set()
        self._sequence = 0
        self._turn = 0

    @property
    def pending_count(self) -> int:
        with self._condition:
            return len(self._pending)

    @property
    def quarantined_count(self) -> int:
        with self._condition:
            return len(self._quarantined)

    def try_acquire(
        self,
        run_id: str,
        task_id: str,
        resource: ResourceClass,
        priority: int,
        *,
        isolated_probe: bool = False,
    ) -> HostWorkSlot | None:
        key = (run_id, task_id)
        with self._condition:
            ticket = self._pending.get(key)
            if ticket is None:
                same_resource = sum(
                    item.run_id == run_id and item.resource == resource
                    for item in self._pending.values()
                )
                if same_resource >= self._budget.limit_for(resource):
                    # Temporary backpressure, not a failed measurement. Keep
                    # other resource classes eligible in this case.
                    return None
                if len(self._pending) >= self._budget.max_tasks:
                    raise HostQueueFull("shared host work queue is full")
                self._sequence += 1
                ticket = _HostTicket(run_id, task_id, resource, priority, self._sequence)
                self._pending[key] = ticket
            elif ticket.resource != resource or ticket.priority != priority:
                raise ValueError("host ticket identity changed while queued")
            if self._durable_blocked_until.get(key, 0.0) > time.monotonic():
                return None
            if len(self._active) >= self._budget.global_limit:
                return None
            resource_used = sum(item[1] == resource for item in self._active.values())
            if resource_used >= self._budget.limit_for(resource):
                return None
            eligible: dict[str, list[_HostTicket]] = {}
            for item in self._pending.values():
                if (
                    self._durable_blocked_until.get((item.run_id, item.task_id), 0.0)
                    > time.monotonic()
                ):
                    continue
                used = sum(active[1] == item.resource for active in self._active.values())
                if used < self._budget.limit_for(item.resource):
                    eligible.setdefault(item.run_id, []).append(item)
            if not eligible:
                return None
            winning_run = min(
                eligible,
                key=lambda candidate: (
                    self._served.get(candidate, 0),
                    min(item.sequence for item in eligible[candidate]),
                ),
            )
            winner = min(eligible[winning_run], key=lambda item: (-item.priority, item.sequence))
            if winner != ticket:
                return None
            custody: ProbeCapacityCustody | None = None
            if isolated_probe and self._ledger is not None:
                if self._ledger_failed:
                    raise LedgerUnavailable("probe capacity ledger unavailable")
                try:
                    durable_ticket = self._durable_pending.get(key)
                    if durable_ticket is None:
                        durable_ticket = self._ledger.enqueue(
                            run_id, task_id, resource.value, priority
                        )
                        self._durable_pending[key] = durable_ticket
                    reservation = self._ledger.try_reserve(durable_ticket)
                    if reservation is None:
                        # This local winner cannot use durable capacity now.
                        # Give another eligible resource a turn this poll.
                        self._durable_blocked_until[key] = time.monotonic() + 0.01
                        return None
                    from systemsense.orchestration.probe_capacity_custody import (
                        ProbeCapacityCustody,
                    )

                    custody = ProbeCapacityCustody(self._ledger, reservation)
                    self._durable_pending.pop(key, None)
                    self._durable_blocked_until.pop(key, None)
                except QueueFull as error:
                    raise HostQueueFull("durable probe capacity queue is full") from error
                except LedgerUnavailable:
                    self._ledger_failed = True
                    raise
            del self._pending[key]
            self._turn += 1
            self._served[run_id] = self._turn
            slot_id = uuid.uuid4().hex
            self._active[slot_id] = (run_id, resource)
            self._condition.notify_all()
            return HostWorkSlot(self, slot_id, custody)

    def _cancel_durable_pending(self, key: tuple[str, str]) -> None:
        self._durable_blocked_until.pop(key, None)
        ticket = self._durable_pending.pop(key, None)
        if ticket is not None and self._ledger is not None:
            try:
                self._ledger.cancel_pending(ticket)
            except LedgerUnavailable:
                # No further isolated admission is safe until the ledger is available.
                self._ledger_failed = True

    def forget(self, run_id: str, task_id: str) -> None:
        with self._condition:
            key = (run_id, task_id)
            self._pending.pop(key, None)
            self._cancel_durable_pending(key)
            self._prune(run_id)
            self._condition.notify_all()

    def forget_run(self, run_id: str) -> None:
        with self._condition:
            for key in tuple(self._pending):
                if key[0] == run_id:
                    del self._pending[key]
                    self._cancel_durable_pending(key)
            for key in tuple(self._durable_pending):
                if key[0] == run_id:
                    self._cancel_durable_pending(key)
            self._completed.add(run_id)
            self._prune(run_id)
            self._condition.notify_all()

    def wait_for_change(self, timeout: float) -> None:
        with self._condition:
            self._condition.wait(timeout)

    def release_slot(self, slot_id: str) -> None:
        with self._condition:
            if slot_id in self._quarantined:
                return
            run_id, _resource = self._active.pop(slot_id)
            self._prune(run_id)
            self._condition.notify_all()

    def quarantine_slot(self, slot_id: str, reason: str) -> None:
        with self._condition:
            if slot_id not in self._active:
                raise ValueError("host slot is no longer active")
            self._quarantined[slot_id] = reason
            self._condition.notify_all()

    def _prune(self, run_id: str) -> None:
        if (
            run_id in self._completed
            and not any(key[0] == run_id for key in self._pending)
            and not any(item[0] == run_id for item in self._active.values())
        ):
            self._served.pop(run_id, None)
            self._completed.discard(run_id)


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
    host_slot: HostWorkSlot | None = None


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
    invocation: ProbeInvocation | None = None
    state_version: int = 0
    timeout_seconds: float | None = None
    deadline_at: datetime | None = None
    isolated_probe: bool = False
    accept_result: Callable[[Any], bool] | None = field(default=None, compare=False, repr=False)

    def __post_init__(self) -> None:
        if not self.task_id:
            raise ValueError("task_id must not be empty")
        object.__setattr__(self, "resource", ResourceClass(self.resource))
        if len(set(self.dependencies)) != len(self.dependencies):
            raise ValueError("task dependencies must be unique")
        if self.task_id in self.dependencies:
            raise ValueError("task cannot depend on itself")
        if self.dedupe_key == "":
            raise ValueError("dedupe_key must not be empty")
        if self.invocation is not None:
            invocation_key = self.invocation.dedupe_key
            if self.dedupe_key is not None and self.dedupe_key != invocation_key:
                raise ValueError("task dedupe key must match its probe invocation")
            object.__setattr__(self, "dedupe_key", invocation_key)
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


class BlockingTaskOfferQueue:
    """Bounded cross-thread delivery of immutable task offers to the scheduler owner.

    An offer is not an admission. The owner still validates the entire graph and
    calls its durable admission hook before dispatching any offered task.
    """

    def __init__(self, *, max_pending: int = 16) -> None:
        if not 1 <= max_pending <= 256:
            raise ValueError("max_pending must be between 1 and 256")
        self._max_pending = max_pending
        self._pending: deque[Callable[[], tuple[Task, ...]]] = deque()
        self._closed = False
        self._condition = threading.Condition()

    def offer(self, tasks: Sequence[Task]) -> bool:
        offered = tuple(tasks)
        if not offered:
            raise ValueError("external offer must contain at least one task")
        return self.offer_factory(lambda: offered)

    def offer_factory(self, factory: Callable[[], tuple[Task, ...]]) -> bool:
        """Queue owner-thread task preparation; never run it on the producer thread."""

        with self._condition:
            if self._closed or len(self._pending) >= self._max_pending:
                return False
            self._pending.append(factory)
            self._condition.notify_all()
            return True

    def close(self) -> None:
        with self._condition:
            self._closed = True
            self._condition.notify_all()

    @property
    def closed_and_empty(self) -> bool:
        with self._condition:
            return self._closed and not self._pending

    def drain(self) -> tuple[Callable[[], tuple[Task, ...]], ...]:
        with self._condition:
            offers = tuple(self._pending)
            self._pending.clear()
            self._condition.notify_all()
            return offers

    def wait(self, timeout: float) -> None:
        with self._condition:
            if not self._pending and not self._closed:
                self._condition.wait(timeout)


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

    def __init__(
        self,
        *,
        budget: ResourceBudget | None = None,
        host_arbiter: HostWorkArbiter | None = None,
    ) -> None:
        self._budget = budget or ResourceBudget()
        self._host_arbiter = host_arbiter

    @property
    def max_tasks(self) -> int:
        """Configured graph bound for owner-thread follow-up preflight."""

        return self._budget.max_tasks

    async def run(
        self,
        tasks: TaskGraph | Sequence[Task],
        *,
        case_deadline_at: datetime | None = None,
        cancel_event: asyncio.Event | None = None,
        state_version: StateVersion = 0,
    ) -> tuple[TaskResult, ...]:
        graph = tasks if isinstance(tasks, TaskGraph) else TaskGraph(tuple(tasks))
        run_id = uuid.uuid4().hex
        try:
            return await self._run_async(
                graph,
                run_id=run_id,
                case_deadline_at=case_deadline_at,
                cancel_event=cancel_event,
                state_version=state_version,
            )
        finally:
            if self._host_arbiter is not None:
                self._host_arbiter.forget_run(run_id)

    async def _run_async(
        self,
        graph: TaskGraph,
        *,
        run_id: str,
        case_deadline_at: datetime | None,
        cancel_event: asyncio.Event | None,
        state_version: StateVersion,
    ) -> tuple[TaskResult, ...]:
        if case_deadline_at is not None and case_deadline_at.tzinfo is None:
            raise ValueError("case_deadline_at must be timezone-aware")
        state_provider = state_version if callable(state_version) else lambda: state_version
        declaration_order = {task.task_id: index for index, task in enumerate(graph.tasks)}
        by_id = {task.task_id: task for task in graph.tasks}
        if len(graph.tasks) > self._budget.max_tasks:
            raise TaskGraphError(f"task graph exceeds max_tasks ({self._budget.max_tasks})")
        pending = set(by_id)

        def retire(task_id: str) -> None:
            pending.remove(task_id)
            if self._host_arbiter is not None:
                self._host_arbiter.forget(run_id, task_id)

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
                    retire(task_id)
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
                    retire(task_id)
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
                        retire(task_id)
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
                        retire(task_id)
                        progress = True
                        continue
                    if task.dedupe_key is not None and task.dedupe_key in dedupe_leaders:
                        leader_id = dedupe_leaders[task.dedupe_key]
                        leader_result = results.get(leader_id)
                        if leader_result is None:
                            continue
                        results[task_id] = _deduplicated_result(task_id, leader_result)
                        retire(task_id)
                        progress = True
                        continue
                    if admitted_global >= self._budget.global_limit or admitted_resources[
                        task.resource
                    ] >= self._budget.limit_for(task.resource):
                        continue
                    effective_deadline = _earliest_deadline(task.deadline_at, case_deadline_at)
                    if effective_deadline is not None and _utc_now() >= effective_deadline:
                        results[task_id] = _queued_result(
                            task_id,
                            TaskStatus.TIMED_OUT,
                            error="task deadline exceeded",
                            state_version=current_version,
                        )
                        retire(task_id)
                        progress = True
                        continue
                    host_slot: HostWorkSlot | None = None
                    if self._host_arbiter is not None:
                        try:
                            host_slot = self._host_arbiter.try_acquire(
                                run_id,
                                task_id,
                                task.resource,
                                task.priority,
                                isolated_probe=task.isolated_probe,
                            )
                        except (HostQueueFull, LedgerUnavailable) as error:
                            results[task_id] = _queued_result(
                                task_id,
                                TaskStatus.BLOCKED,
                                error=str(error),
                                state_version=current_version,
                            )
                            retire(task_id)
                            progress = True
                            continue
                        if host_slot is None:
                            continue
                    if task.dedupe_key is not None:
                        dedupe_leaders[task.dedupe_key] = task_id
                    retire(task_id)
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
                            host_slot=host_slot,
                        )
                    )
                    progress = True

            if not running:
                if pending:
                    if self._host_arbiter is None:
                        raise RuntimeError("scheduler made no progress on a validated task graph")
                    await asyncio.sleep(0.01)
                    continue
                continue
            done, _ = await asyncio.wait(
                tuple(running.values()),
                return_when=asyncio.FIRST_COMPLETED,
                timeout=0.01 if self._host_arbiter is not None and pending else None,
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
        offer_after_result: Callable[[TaskResult], Sequence[Task]] | None = None,
        external_offers: BlockingTaskOfferQueue | None = None,
        on_admitted: Callable[[tuple[Task, ...]], bool | None] | None = None,
        on_offer_error: Callable[[Exception], None] | None = None,
    ) -> tuple[TaskResult, ...]:
        """Run synchronous collectors without creating an asyncio event loop.

        Windows' default asyncio event loop creates a socketpair for wakeups.
        The core investigator is intentionally socket-free, so this path uses
        a bounded thread pool and polls only threading primitives.  A thread
        cannot be killed safely: a timed-out or cancelled collector is marked
        immediately, but its worker remains admitted until it returns.  This
        prevents capacity from being released while non-killable read-only
        work is still touching the host.

        ``offer_after_result`` is opt-in and runs on the calling thread only
        after ``on_result`` returns. The callback may use persisted outcomes to
        offer more typed tasks; offered tasks are validated against the entire
        admitted graph before any worker can execute them. ``on_admitted`` runs
        after validation, before an offer enters the runnable queue, so callers
        can persist an admission intent without creating phantom work. Returning
        ``False`` rejects only that offer; ``None`` or ``True`` accepts it.
        ``external_offers`` allows a separate policy worker to submit bounded
        offers without running inference on the persistence owner thread.
        ``on_offer_error`` isolates a failed external factory when the caller
        can record its degraded/uncertain outcome. Without it, the error raises.
        """

        graph = tasks if isinstance(tasks, TaskGraph) else TaskGraph(tuple(tasks))
        run_id = uuid.uuid4().hex
        if (offer_after_result is not None or external_offers is not None) and on_result is None:
            raise ValueError("dynamic admission requires on_result persistence")
        if external_offers is not None and (on_admitted is None or case_deadline_at is None):
            raise ValueError("external offers require durable admission and a case deadline")
        if case_deadline_at is not None and case_deadline_at.tzinfo is None:
            raise ValueError("case_deadline_at must be timezone-aware")
        if len(graph.tasks) > self._budget.max_tasks:
            raise TaskGraphError(f"task graph exceeds max_tasks ({self._budget.max_tasks})")

        state_provider = state_version if callable(state_version) else lambda: state_version
        ordered_tasks = list(graph.tasks)
        declaration_order = {task.task_id: index for index, task in enumerate(graph.tasks)}
        by_id = {task.task_id: task for task in graph.tasks}
        pending = set(by_id)

        def retire(task_id: str) -> None:
            pending.remove(task_id)
            if self._host_arbiter is not None:
                self._host_arbiter.forget(run_id, task_id)

        results: dict[str, TaskResult] = {}
        published: set[str] = set()
        running: dict[str, _BlockingWorker] = {}
        dedupe_leaders: dict[str, str] = {}
        stop_status: TaskStatus | None = None

        def admit_offer(offered: tuple[Task, ...]) -> bool:
            if len(ordered_tasks) + len(offered) > self._budget.max_tasks:
                raise TaskGraphError("dynamic task graph exceeds max_tasks")
            try:
                TaskGraph((*ordered_tasks, *offered))
            except (AttributeError, TypeError) as error:
                raise TaskGraphError("dynamic offer must contain Task objects") from error
            if (cancel_event is not None and cancel_event.is_set()) or (
                case_deadline_at is not None and _utc_now() >= case_deadline_at
            ):
                return False
            if on_admitted is not None and on_admitted(offered) is False:
                return False
            for task in offered:
                declaration_order[task.task_id] = len(ordered_tasks)
                ordered_tasks.append(task)
                by_id[task.task_id] = task
                pending.add(task.task_id)
            return True

        executor = ThreadPoolExecutor(
            max_workers=self._budget.global_limit,
            thread_name_prefix="systemsense-probe",
        )
        try:
            while (
                pending
                or running
                or (
                    external_offers is not None
                    and not external_offers.closed_and_empty
                    and stop_status is None
                )
            ):
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
                        retire(task_id)
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
                            retire(task_id)
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
                            retire(task_id)
                            progress = True
                            continue
                        if task.dedupe_key is not None and task.dedupe_key in dedupe_leaders:
                            leader_id = dedupe_leaders[task.dedupe_key]
                            leader_result = results.get(leader_id)
                            if leader_result is None:
                                continue
                            results[task_id] = _deduplicated_result(task_id, leader_result)
                            retire(task_id)
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
                            retire(task_id)
                            progress = True
                            continue

                        host_slot: HostWorkSlot | None = None
                        if self._host_arbiter is not None:
                            try:
                                host_slot = self._host_arbiter.try_acquire(
                                    run_id,
                                    task_id,
                                    task.resource,
                                    task.priority,
                                    isolated_probe=task.isolated_probe,
                                )
                            except (HostQueueFull, LedgerUnavailable) as error:
                                results[task_id] = _queued_result(
                                    task_id,
                                    TaskStatus.BLOCKED,
                                    error=str(error),
                                    state_version=current_version,
                                )
                                retire(task_id)
                                progress = True
                                continue
                            if host_slot is None:
                                continue

                        retire(task_id)
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
                            host_slot=host_slot,
                        )
                        if inspect.iscoroutinefunction(task.action):
                            if host_slot is not None:
                                host_slot.release()
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
                        try:
                            future = executor.submit(
                                _invoke_blocking_with_slot, task.action, context, host_slot
                            )
                            if host_slot is not None:
                                future.add_done_callback(
                                    lambda _finished, slot=host_slot: slot.release()
                                )
                        except Exception:
                            if host_slot is not None:
                                host_slot.release()
                            raise
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
                            if (
                                offer_after_result is not None
                                and stop_status is None
                                and (cancel_event is None or not cancel_event.is_set())
                                and (case_deadline_at is None or _utc_now() < case_deadline_at)
                            ):
                                offered = tuple(offer_after_result(result))
                                if offered:
                                    admit_offer(offered)

                admitted_external = False
                if external_offers is not None and stop_status is None:
                    for prepare in external_offers.drain():
                        try:
                            offered = prepare()
                        except Exception as error:
                            if on_offer_error is None:
                                raise
                            on_offer_error(error)
                            continue
                        if offered:
                            try:
                                admitted_external = admit_offer(offered) or admitted_external
                            except Exception as error:
                                # A failed/ambiguous durable admission cannot
                                # dispatch, but unrelated collector results must
                                # still be persisted. The owner records the gap.
                                if on_offer_error is None:
                                    raise
                                on_offer_error(error)

                if not running:
                    if pending:
                        if stop_status is not None or completed or admitted_external:
                            continue
                        if self._host_arbiter is None:
                            raise RuntimeError(
                                "scheduler made no progress on a validated task graph"
                            )
                        self._host_arbiter.wait_for_change(0.01)
                        continue
                    if external_offers is not None and not external_offers.closed_and_empty:
                        external_offers.wait(0.01)
                    continue

                if not completed:
                    time.sleep(0.001)

            return tuple(results[task.task_id] for task in ordered_tasks)
        finally:
            # ``wait=True`` is deliberate: a timed-out synchronous collector is
            # non-killable and must drain before its capacity can be reused.
            executor.shutdown(wait=True, cancel_futures=True)
            if self._host_arbiter is not None:
                self._host_arbiter.forget_run(run_id)

    async def _execute(
        self,
        task: Task,
        *,
        global_semaphore: asyncio.Semaphore,
        resource_semaphore: asyncio.Semaphore,
        case_deadline_at: datetime | None,
        cancel_event: asyncio.Event | None,
        state_provider: Callable[[], int],
        host_slot: HostWorkSlot | None,
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
                host_slot=host_slot,
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
            if host_slot is not None:
                host_slot.release()


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


def _invoke_blocking_with_slot(
    action: TaskAction, context: TaskContext, slot: HostWorkSlot | None
) -> Any:
    try:
        return _invoke_blocking(action, context)
    finally:
        if slot is not None:
            slot.release()


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
