import asyncio
import socket
import threading
import time
from collections.abc import Callable, Coroutine
from concurrent.futures import Future
from datetime import UTC, datetime, timedelta
from functools import wraps
from typing import Any, cast

import pytest

import systemsense.orchestration.scheduler as scheduler_module
from systemsense.orchestration.scheduler import (
    BlockingTaskOfferQueue,
    BoundedScheduler,
    HostWorkArbiter,
    ResourceBudget,
    ResourceClass,
    Task,
    TaskContext,
    TaskGraph,
    TaskGraphError,
    TaskResult,
    TaskStatus,
)


def test_shared_host_arbiter_caps_concurrent_cases_and_serves_waiting_case() -> None:
    arbiter = HostWorkArbiter(ResourceBudget(global_limit=2, per_resource={ResourceClass.DISK: 1}))
    first_started = threading.Event()
    release_first = threading.Event()
    order: list[str] = []
    lock = threading.Lock()
    results: dict[str, tuple[TaskResult, ...]] = {}

    def action(name: str) -> Callable[[object], str]:
        def run(_context: object) -> str:
            with lock:
                order.append(name)
            if name == "a1":
                first_started.set()
                assert release_first.wait(3)
            return name

        return run

    def run_case(name: str, tasks: tuple[Task, ...]) -> None:
        results[name] = BoundedScheduler(
            budget=ResourceBudget(global_limit=2), host_arbiter=arbiter
        ).run_blocking(tasks, case_deadline_at=datetime.now(UTC) + timedelta(seconds=4))

    a = threading.Thread(
        target=run_case,
        args=(
            "a",
            (
                Task("a1", action("a1"), resource=ResourceClass.DISK),
                Task("a2", action("a2"), resource=ResourceClass.DISK),
            ),
        ),
        daemon=True,
    )
    b = threading.Thread(
        target=run_case,
        args=("b", (Task("b1", action("b1"), resource=ResourceClass.DISK),)),
        daemon=True,
    )
    a.start()
    assert first_started.wait(2)
    b.start()
    deadline = time.monotonic() + 2
    while arbiter.pending_count < 2 and time.monotonic() < deadline:
        time.sleep(0.005)
    assert arbiter.pending_count == 2
    release_first.set()
    a.join(3)
    b.join(3)
    assert not a.is_alive() and not b.is_alive()
    assert order == ["a1", "b1", "a2"]
    assert all(
        result.status is TaskStatus.SUCCEEDED for case in results.values() for result in case
    )
    assert arbiter.pending_count == 0


def test_uncertain_child_exit_quarantines_probe_capacity_after_action_return() -> None:
    arbiter = HostWorkArbiter(ResourceBudget(global_limit=1))
    slot = arbiter.try_acquire("first", "probe", ResourceClass.CPU, 0)
    assert slot is not None
    slot.quarantine("child_tree_exit_unverified")
    slot.release()
    arbiter.forget_run("first")

    assert arbiter.quarantined_count == 1
    assert arbiter.try_acquire("second", "probe", ResourceClass.CPU, 0) is None


def test_running_task_can_quarantine_its_own_host_slot() -> None:
    arbiter = HostWorkArbiter(ResourceBudget(global_limit=1))

    def uncertain(context: TaskContext) -> str:
        assert context.host_slot is not None
        context.host_slot.quarantine("child_tree_exit_unverified")
        return "probe failed"

    first = BoundedScheduler(host_arbiter=arbiter).run_blocking((Task("first", uncertain),))
    assert first[0].status is TaskStatus.SUCCEEDED
    assert arbiter.quarantined_count == 1
    second = BoundedScheduler(host_arbiter=arbiter).run_blocking(
        (Task("second", lambda _context: "must not run"),),
        case_deadline_at=datetime.now(UTC) + timedelta(milliseconds=100),
    )
    assert second[0].status is TaskStatus.TIMED_OUT


def test_shared_host_arbiter_cancelled_waiter_never_dispatches() -> None:
    arbiter = HostWorkArbiter(ResourceBudget(global_limit=1))
    owner_started = threading.Event()
    owner_release = threading.Event()
    waiter_cancel = threading.Event()
    waiter_ran = threading.Event()
    results: dict[str, tuple[TaskResult, ...]] = {}

    def owner(_context: object) -> None:
        owner_started.set()
        assert owner_release.wait(3)

    def run_owner() -> None:
        results["owner"] = BoundedScheduler(host_arbiter=arbiter).run_blocking(
            (Task("owner", owner),),
            case_deadline_at=datetime.now(UTC) + timedelta(seconds=4),
        )

    def run_waiter() -> None:
        results["waiter"] = BoundedScheduler(host_arbiter=arbiter).run_blocking(
            (Task("waiter", lambda _context: waiter_ran.set()),),
            case_deadline_at=datetime.now(UTC) + timedelta(seconds=4),
            cancel_event=waiter_cancel,
        )

    first = threading.Thread(target=run_owner, daemon=True)
    second = threading.Thread(target=run_waiter, daemon=True)
    first.start()
    assert owner_started.wait(2)
    second.start()
    deadline = time.monotonic() + 2
    while arbiter.pending_count != 1 and time.monotonic() < deadline:
        time.sleep(0.005)
    assert arbiter.pending_count == 1
    waiter_cancel.set()
    second.join(2)
    assert not second.is_alive()
    assert results["waiter"][0].status is TaskStatus.CANCELLED
    assert not waiter_ran.is_set()
    assert arbiter.pending_count == 0
    owner_release.set()
    first.join(2)
    assert not first.is_alive()


def test_shared_host_slot_stays_held_until_timed_out_worker_exits() -> None:
    arbiter = HostWorkArbiter(ResourceBudget(global_limit=1))
    first_started = threading.Event()
    first_release = threading.Event()
    second_started = threading.Event()
    results: dict[str, tuple[TaskResult, ...]] = {}

    def slow(_context: object) -> None:
        first_started.set()
        assert first_release.wait(3)

    def run_first() -> None:
        results["first"] = BoundedScheduler(host_arbiter=arbiter).run_blocking(
            (Task("slow", slow, timeout_seconds=0.03),)
        )

    def run_second() -> None:
        results["second"] = BoundedScheduler(host_arbiter=arbiter).run_blocking(
            (Task("next", lambda _context: second_started.set()),),
            case_deadline_at=datetime.now(UTC) + timedelta(seconds=3),
        )

    first = threading.Thread(target=run_first, daemon=True)
    second = threading.Thread(target=run_second, daemon=True)
    first.start()
    assert first_started.wait(2)
    second.start()
    deadline = time.monotonic() + 2
    while arbiter.pending_count != 1 and time.monotonic() < deadline:
        time.sleep(0.005)
    assert arbiter.pending_count == 1
    time.sleep(0.06)
    assert not second_started.is_set()
    first_release.set()
    first.join(2)
    second.join(2)
    assert not first.is_alive() and not second.is_alive()
    assert results["first"][0].status is TaskStatus.TIMED_OUT
    assert results["second"][0].status is TaskStatus.SUCCEEDED


def test_shared_host_queued_task_deadline_cancels_its_ticket() -> None:
    arbiter = HostWorkArbiter(ResourceBudget(global_limit=1))
    first_started = threading.Event()
    first_release = threading.Event()
    second_started = threading.Event()
    results: dict[str, tuple[TaskResult, ...]] = {}

    def run_first() -> None:
        def slow(_context: object) -> None:
            first_started.set()
            assert first_release.wait(3)

        results["first"] = BoundedScheduler(host_arbiter=arbiter).run_blocking(
            (Task("slow", slow),)
        )

    def run_second() -> None:
        results["second"] = BoundedScheduler(host_arbiter=arbiter).run_blocking(
            (
                Task(
                    "expired",
                    lambda _context: second_started.set(),
                    deadline_at=datetime.now(UTC) + timedelta(milliseconds=50),
                ),
            )
        )

    first = threading.Thread(target=run_first, daemon=True)
    second = threading.Thread(target=run_second, daemon=True)
    first.start()
    assert first_started.wait(2)
    second.start()
    second.join(2)
    assert not second.is_alive()
    assert results["second"][0].status is TaskStatus.TIMED_OUT
    assert not second_started.is_set()
    assert arbiter.pending_count == 0
    first_release.set()
    first.join(2)
    assert not first.is_alive()


def test_stale_host_ticket_does_not_block_another_case_while_first_case_drains() -> None:
    arbiter = HostWorkArbiter(ResourceBudget(global_limit=2, per_resource={ResourceClass.DISK: 1}))

    def queued() -> int:
        return arbiter.pending_count

    disk_started = threading.Event()
    disk_release = threading.Event()
    cpu_started = threading.Event()
    cpu_release = threading.Event()
    other_started = threading.Event()
    version = [0]
    outcomes: dict[str, tuple[TaskResult, ...]] = {}

    def held(started: threading.Event, release: threading.Event) -> Callable[[object], None]:
        def collect(_context: object) -> None:
            started.set()
            assert release.wait(3)

        return collect

    def run_disk() -> None:
        outcomes["disk"] = BoundedScheduler(host_arbiter=arbiter).run_blocking(
            (Task("disk-owner", held(disk_started, disk_release), resource=ResourceClass.DISK),)
        )

    def run_stale() -> None:
        outcomes["stale"] = BoundedScheduler(
            budget=ResourceBudget(global_limit=2), host_arbiter=arbiter
        ).run_blocking(
            (
                Task("cpu-owner", held(cpu_started, cpu_release)),
                Task("stale-disk", lambda _context: None, resource=ResourceClass.DISK),
            ),
            state_version=lambda: version[0],
        )

    def run_other() -> None:
        outcomes["other"] = BoundedScheduler(host_arbiter=arbiter).run_blocking(
            (
                Task(
                    "other-disk", lambda _context: other_started.set(), resource=ResourceClass.DISK
                ),
            ),
            case_deadline_at=datetime.now(UTC) + timedelta(seconds=3),
        )

    disk = threading.Thread(target=run_disk, daemon=True)
    stale = threading.Thread(target=run_stale, daemon=True)
    other = threading.Thread(target=run_other, daemon=True)
    disk.start()
    assert disk_started.wait(2)
    stale.start()
    assert cpu_started.wait(2)
    deadline = time.monotonic() + 2
    while queued() != 1 and time.monotonic() < deadline:
        time.sleep(0.005)
    assert queued() == 1
    version[0] = 1
    deadline = time.monotonic() + 2
    while queued() != 0 and time.monotonic() < deadline:
        time.sleep(0.005)
    assert queued() == 0
    other.start()
    disk_release.set()
    assert other_started.wait(2), "a stale ticket held the newly available DISK slot"
    assert not cpu_release.is_set(), "the stale case should still be draining"
    cpu_release.set()
    for worker in (disk, stale, other):
        worker.join(2)
        assert not worker.is_alive()
    assert outcomes["stale"][1].status is TaskStatus.STALE
    assert outcomes["other"][0].status is TaskStatus.SUCCEEDED


def test_host_arbiter_keeps_case_turn_between_dependent_tasks() -> None:
    arbiter = HostWorkArbiter(ResourceBudget(global_limit=1))
    b1 = arbiter.try_acquire("b", "b1", ResourceClass.CPU, 0)
    assert b1 is not None
    assert arbiter.try_acquire("a", "a1", ResourceClass.CPU, 0) is None
    assert arbiter.try_acquire("b", "b2", ResourceClass.CPU, 0) is None
    b1.release()
    a1 = arbiter.try_acquire("a", "a1", ResourceClass.CPU, 0)
    assert a1 is not None
    a1.release()
    assert arbiter.try_acquire("a", "a2", ResourceClass.CPU, 0) is None
    b2 = arbiter.try_acquire("b", "b2", ResourceClass.CPU, 0)
    assert b2 is not None
    b2.release()
    a2 = arbiter.try_acquire("a", "a2", ResourceClass.CPU, 0)
    assert a2 is not None
    a2.release()
    arbiter.forget_run("a")
    arbiter.forget_run("b")
    assert arbiter.pending_count == 0


def test_host_arbiter_favors_older_case_over_new_high_priority_case() -> None:
    arbiter = HostWorkArbiter(ResourceBudget(global_limit=1))
    owner = arbiter.try_acquire("owner", "held", ResourceClass.CPU, 0)
    assert owner is not None
    assert arbiter.try_acquire("older", "low", ResourceClass.CPU, 0) is None
    assert arbiter.try_acquire("newer", "high", ResourceClass.CPU, 100) is None
    owner.release()
    assert arbiter.try_acquire("newer", "high", ResourceClass.CPU, 100) is None
    older = arbiter.try_acquire("older", "low", ResourceClass.CPU, 0)
    assert older is not None
    older.release()
    newer = arbiter.try_acquire("newer", "high", ResourceClass.CPU, 100)
    assert newer is not None
    newer.release()
    for run_id in ("owner", "older", "newer"):
        arbiter.forget_run(run_id)


def test_host_queue_defers_same_case_flood_for_another_case() -> None:
    arbiter = HostWorkArbiter(ResourceBudget(global_limit=1, max_tasks=2))
    owner = arbiter.try_acquire("owner", "held", ResourceClass.CPU, 0)
    assert owner is not None
    assert arbiter.try_acquire("flood", "first", ResourceClass.CPU, 0) is None
    assert arbiter.try_acquire("flood", "second", ResourceClass.CPU, 0) is None
    assert arbiter.try_acquire("other", "first", ResourceClass.CPU, 0) is None
    assert arbiter.pending_count == 2
    owner.release()
    first = arbiter.try_acquire("flood", "first", ResourceClass.CPU, 0)
    assert first is not None
    first.release()
    second = arbiter.try_acquire("other", "first", ResourceClass.CPU, 0)
    assert second is not None
    second.release()
    for run_id in ("owner", "flood", "other"):
        arbiter.forget_run(run_id)


def test_disk_ticket_flood_does_not_block_free_cpu_capacity() -> None:
    arbiter = HostWorkArbiter(ResourceBudget(global_limit=4, per_resource={ResourceClass.DISK: 1}))
    disk_started = threading.Event()
    disk_release = threading.Event()
    cpu_started = threading.Event()
    outcomes: dict[str, tuple[TaskResult, ...]] = {}

    def held_disk(_context: object) -> None:
        disk_started.set()
        assert disk_release.wait(3)

    def owner() -> None:
        outcomes["owner"] = BoundedScheduler(host_arbiter=arbiter).run_blocking(
            (Task("held-disk", held_disk, resource=ResourceClass.DISK),)
        )

    def flooded_case() -> None:
        disk_tasks = tuple(
            Task(
                f"disk-{index}",
                lambda _context: None,
                resource=ResourceClass.DISK,
                priority=10,
            )
            for index in range(4)
        )
        outcomes["flooded"] = BoundedScheduler(host_arbiter=arbiter).run_blocking(
            (*disk_tasks, Task("cpu", lambda _context: cpu_started.set())),
            case_deadline_at=datetime.now(UTC) + timedelta(seconds=3),
        )

    first = threading.Thread(target=owner, daemon=True)
    second = threading.Thread(target=flooded_case, daemon=True)
    first.start()
    assert disk_started.wait(2)
    second.start()
    assert cpu_started.wait(2), "same-resource queue quota discarded eligible CPU work"
    assert not disk_release.is_set()
    disk_release.set()
    first.join(2)
    second.join(2)
    assert not first.is_alive() and not second.is_alive()
    assert all(result.status is TaskStatus.SUCCEEDED for result in outcomes["flooded"])


def test_cancelled_before_start_future_releases_host_slot(monkeypatch: pytest.MonkeyPatch) -> None:
    class FakeExecutor:
        def __init__(self, *, max_workers: int, thread_name_prefix: str) -> None:
            self.futures: list[Future[object]] = []

        def submit(self, _action: object, *_args: object) -> Future[object]:
            future: Future[object] = Future()
            self.futures.append(future)
            if len(self.futures) == 1:
                future.set_result("first")
            return future

        def shutdown(self, *, wait: bool, cancel_futures: bool) -> None:
            assert wait and cancel_futures
            for future in self.futures:
                if not future.done():
                    future.cancel()

    monkeypatch.setattr(scheduler_module, "ThreadPoolExecutor", FakeExecutor)
    arbiter = HostWorkArbiter(ResourceBudget(global_limit=2))

    def fail_persistence(_result: TaskResult) -> None:
        raise RuntimeError("simulated persistence failure")

    with pytest.raises(RuntimeError, match="simulated persistence failure"):
        BoundedScheduler(host_arbiter=arbiter).run_blocking(
            (Task("first", lambda _context: "first"), Task("queued", lambda _context: "queued")),
            on_result=fail_persistence,
        )
    first = arbiter.try_acquire("after", "first", ResourceClass.CPU, 0)
    second = arbiter.try_acquire("after", "second", ResourceClass.CPU, 0)
    assert first is not None and second is not None
    first.release()
    second.release()
    arbiter.forget_run("after")


def test_task_resource_strings_are_normalized_before_host_admission() -> None:
    task = Task("disk", lambda _context: None, resource="disk")  # type: ignore[arg-type]
    assert task.resource is ResourceClass.DISK


def test_blocking_scheduler_accepts_external_offers_without_waiting_for_slow_result() -> None:
    offers = BlockingTaskOfferQueue(max_pending=2)
    slow_started = threading.Event()
    child_finished = threading.Event()
    persisted: list[str] = []
    provider_started = threading.Event()
    provider_release = threading.Event()

    def slow(_context: object) -> str:
        slow_started.set()
        assert child_finished.wait(2), "external child waited for unrelated slow result"
        return "slow"

    def fast(_context: object) -> str:
        assert slow_started.wait(2)
        return "fast"

    def child(_context: object) -> str:
        child_finished.set()
        return "child"

    def policy() -> None:
        assert provider_started.wait(2)
        assert provider_release.wait(2)
        assert offers.offer((Task(task_id="child", action=child, dependencies=("fast",)),))
        offers.close()

    worker = threading.Thread(target=policy, daemon=True)
    worker.start()

    def persist(result: TaskResult) -> None:
        persisted.append(result.task_id)
        if result.task_id == "fast":
            provider_started.set()
            provider_release.set()

    results = BoundedScheduler(budget=ResourceBudget(global_limit=2)).run_blocking(
        (Task(task_id="slow", action=slow), Task(task_id="fast", action=fast)),
        case_deadline_at=datetime.now(UTC) + timedelta(seconds=3),
        on_result=persist,
        external_offers=offers,
        on_admitted=lambda tasks: persisted.append(f"admitted:{tasks[0].task_id}"),
    )
    worker.join(2)
    assert not worker.is_alive()
    assert tuple(result.status for result in results) == (TaskStatus.SUCCEEDED,) * 3
    assert persisted.index("fast") < persisted.index("admitted:child")
    assert persisted.index("admitted:child") < persisted.index("child")


def test_blocking_scheduler_waits_for_two_external_offers() -> None:
    offers = BlockingTaskOfferQueue(max_pending=2)
    first_ready = threading.Event()
    second_ready = threading.Event()
    ran: list[str] = []

    def first(_context: object) -> str:
        first_ready.set()
        return "first"

    def second(_context: object) -> str:
        second_ready.set()
        return "second"

    def policy() -> None:
        assert first_ready.wait(2)
        assert offers.offer((Task(task_id="child-a", action=lambda _context: ran.append("a")),))
        assert second_ready.wait(2)
        assert offers.offer((Task(task_id="child-b", action=lambda _context: ran.append("b")),))
        offers.close()

    worker = threading.Thread(target=policy, daemon=True)
    worker.start()
    results = BoundedScheduler(budget=ResourceBudget(global_limit=2)).run_blocking(
        (Task(task_id="first", action=first), Task(task_id="second", action=second)),
        case_deadline_at=datetime.now(UTC) + timedelta(seconds=3),
        on_result=lambda _result: None,
        external_offers=offers,
        on_admitted=lambda _tasks: True,
    )
    worker.join(2)
    assert not worker.is_alive()
    assert {item.task_id for item in results} == {"first", "second", "child-a", "child-b"}
    assert all(item.status is TaskStatus.SUCCEEDED for item in results)
    assert sorted(ran) == ["a", "b"]


def test_blocking_scheduler_external_offer_queue_is_bounded_and_closed() -> None:
    offers = BlockingTaskOfferQueue(max_pending=1)
    assert offers.offer((Task(task_id="one", action=lambda _context: None),))
    assert not offers.offer((Task(task_id="two", action=lambda _context: None),))
    offers.close()
    assert not offers.offer((Task(task_id="three", action=lambda _context: None),))


def test_blocking_scheduler_prepares_external_offer_only_on_owner_thread() -> None:
    offers = BlockingTaskOfferQueue(max_pending=1)
    owner = threading.get_ident()
    prepared: list[int] = []

    def prepare() -> tuple[Task, ...]:
        prepared.append(threading.get_ident())
        return (Task(task_id="child", action=lambda _context: "child"),)

    producer = threading.Thread(target=lambda: (offers.offer_factory(prepare), offers.close()))
    producer.start()
    producer.join(2)
    results = BoundedScheduler().run_blocking(
        (Task(task_id="root", action=lambda _context: "root"),),
        case_deadline_at=datetime.now(UTC) + timedelta(seconds=1),
        on_result=lambda _result: None,
        external_offers=offers,
        on_admitted=lambda _tasks: True,
    )
    assert prepared == [owner]
    assert tuple(item.status for item in results) == (TaskStatus.SUCCEEDED,) * 2


def test_blocking_scheduler_external_offer_wait_is_deadline_bounded() -> None:
    offers = BlockingTaskOfferQueue(max_pending=1)
    started = time.monotonic()
    results = BoundedScheduler().run_blocking(
        (Task(task_id="root", action=lambda _context: "root"),),
        case_deadline_at=datetime.now(UTC) + timedelta(milliseconds=100),
        on_result=lambda _result: None,
        external_offers=offers,
        on_admitted=lambda _tasks: True,
    )
    assert time.monotonic() - started < 1
    assert tuple(item.task_id for item in results) == ("root",)
    assert results[0].status is TaskStatus.SUCCEEDED


def test_blocking_scheduler_external_policy_delay_does_not_block_result_persistence() -> None:
    offers = BlockingTaskOfferQueue(max_pending=1)
    first_persisted = threading.Event()
    persisted_at: dict[str, float] = {}

    def policy() -> None:
        assert first_persisted.wait(2)
        time.sleep(0.25)
        offers.close()

    worker = threading.Thread(target=policy, daemon=True)
    worker.start()

    def persist(result: TaskResult) -> None:
        persisted_at[result.task_id] = time.monotonic()
        if result.task_id == "first":
            first_persisted.set()

    def second(_context: object) -> str:
        time.sleep(0.02)
        return "second"

    results = BoundedScheduler(budget=ResourceBudget(global_limit=2)).run_blocking(
        (
            Task(task_id="first", action=lambda _context: "first"),
            Task(task_id="second", action=second),
        ),
        case_deadline_at=datetime.now(UTC) + timedelta(seconds=2),
        on_result=persist,
        external_offers=offers,
        on_admitted=lambda _tasks: True,
    )
    worker.join(2)
    assert all(item.status is TaskStatus.SUCCEEDED for item in results)
    assert persisted_at["second"] - persisted_at["first"] < 0.15


def test_blocking_scheduler_external_rejected_admission_never_dispatches() -> None:
    offers = BlockingTaskOfferQueue(max_pending=1)
    child_ran = False

    def child(_context: object) -> str:
        nonlocal child_ran
        child_ran = True
        return "child"

    assert offers.offer((Task(task_id="child", action=child),))
    offers.close()
    results = BoundedScheduler().run_blocking(
        (Task(task_id="root", action=lambda _context: "root"),),
        case_deadline_at=datetime.now(UTC) + timedelta(seconds=1),
        on_result=lambda _result: None,
        external_offers=offers,
        on_admitted=lambda _tasks: False,
    )
    assert tuple(item.task_id for item in results) == ("root",)
    assert not child_ran


def test_blocking_scheduler_dispatches_prequeued_offer_without_initial_tasks() -> None:
    offers = BlockingTaskOfferQueue(max_pending=1)
    assert offers.offer((Task(task_id="child", action=lambda _context: "done"),))
    offers.close()
    results = BoundedScheduler().run_blocking(
        (),
        case_deadline_at=datetime.now(UTC) + timedelta(seconds=1),
        on_result=lambda _result: None,
        external_offers=offers,
        on_admitted=lambda _tasks: True,
    )
    assert tuple(item.status for item in results) == (TaskStatus.SUCCEEDED,)


def test_external_factory_failure_does_not_drop_unrelated_result_when_reported() -> None:
    offers = BlockingTaskOfferQueue(max_pending=1)
    assert offers.offer_factory(lambda: (_ for _ in ()).throw(ValueError("stale snapshot")))
    offers.close()
    persisted: list[str] = []
    failures: list[str] = []
    results = BoundedScheduler().run_blocking(
        (Task(task_id="root", action=lambda _context: "root"),),
        case_deadline_at=datetime.now(UTC) + timedelta(seconds=1),
        on_result=lambda result: persisted.append(result.task_id),
        external_offers=offers,
        on_admitted=lambda _tasks: True,
        on_offer_error=lambda error: failures.append(str(error)),
    )
    assert tuple(item.status for item in results) == (TaskStatus.SUCCEEDED,)
    assert persisted == ["root"]
    assert failures == ["stale snapshot"]


def test_external_admission_failure_does_not_drop_unrelated_result_when_reported() -> None:
    offers = BlockingTaskOfferQueue(max_pending=1)
    assert offers.offer((Task(task_id="child", action=lambda _context: "unsafe"),))
    offers.close()
    persisted: list[str] = []
    failures: list[str] = []

    def reject(_tasks: tuple[Task, ...]) -> bool:
        raise RuntimeError("admission outcome uncertain")

    results = BoundedScheduler().run_blocking(
        (Task(task_id="root", action=lambda _context: "root"),),
        case_deadline_at=datetime.now(UTC) + timedelta(seconds=1),
        on_result=lambda result: persisted.append(result.task_id),
        external_offers=offers,
        on_admitted=reject,
        on_offer_error=lambda error: failures.append(str(error)),
    )
    assert tuple(item.task_id for item in results) == ("root",)
    assert persisted == ["root"]
    assert failures == ["admission outcome uncertain"]


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
async def test_shared_host_arbiter_fairly_schedules_async_cases() -> None:
    arbiter = HostWorkArbiter(ResourceBudget(global_limit=1))
    first_started = asyncio.Event()
    first_release = asyncio.Event()
    order: list[str] = []

    async def collect(context: object) -> str:
        task_id = cast("Any", context).task_id
        order.append(task_id)
        if task_id == "a1":
            first_started.set()
            await first_release.wait()
        return task_id

    first = asyncio.create_task(
        BoundedScheduler(host_arbiter=arbiter).run(
            (_task("a1", action=collect), _task("a2", action=collect))
        )
    )
    await asyncio.wait_for(first_started.wait(), 1)
    second = asyncio.create_task(
        BoundedScheduler(host_arbiter=arbiter).run((_task("b1", action=collect),))
    )
    deadline = time.monotonic() + 1
    while arbiter.pending_count < 2 and time.monotonic() < deadline:
        await asyncio.sleep(0.005)
    assert arbiter.pending_count == 2
    first_release.set()
    left, right = await asyncio.wait_for(asyncio.gather(first, second), 2)
    assert order == ["a1", "b1", "a2"]
    assert all(result.status is TaskStatus.SUCCEEDED for result in (*left, *right))
    assert arbiter.pending_count == 0


@_async_test
async def test_async_case_dispatches_external_slot_release_before_local_slow_task() -> None:
    arbiter = HostWorkArbiter(ResourceBudget(global_limit=2, per_resource={ResourceClass.DISK: 1}))
    disk_started = asyncio.Event()
    disk_release = asyncio.Event()
    slow_started = asyncio.Event()
    slow_release = asyncio.Event()
    next_disk_started = asyncio.Event()

    async def held_disk(_context: object) -> None:
        disk_started.set()
        await disk_release.wait()

    async def held_cpu(_context: object) -> None:
        slow_started.set()
        await slow_release.wait()

    async def next_disk(_context: object) -> None:
        next_disk_started.set()

    first = asyncio.create_task(
        BoundedScheduler(host_arbiter=arbiter).run(
            (Task("disk-owner", held_disk, resource=ResourceClass.DISK),)
        )
    )
    await asyncio.wait_for(disk_started.wait(), 1)
    second = asyncio.create_task(
        BoundedScheduler(host_arbiter=arbiter).run(
            (
                Task("slow-cpu", held_cpu),
                Task("next-disk", next_disk, resource=ResourceClass.DISK),
            )
        )
    )
    await asyncio.wait_for(slow_started.wait(), 1)
    deadline = time.monotonic() + 1
    while arbiter.pending_count != 1 and time.monotonic() < deadline:
        await asyncio.sleep(0.005)
    assert arbiter.pending_count == 1
    disk_release.set()
    await asyncio.wait_for(next_disk_started.wait(), 1)
    assert not slow_release.is_set()
    slow_release.set()
    left, right = await asyncio.wait_for(asyncio.gather(first, second), 2)
    assert all(result.status is TaskStatus.SUCCEEDED for result in (*left, *right))


@_async_test
async def test_async_disk_ticket_flood_does_not_block_free_cpu_capacity() -> None:
    arbiter = HostWorkArbiter(ResourceBudget(global_limit=4, per_resource={ResourceClass.DISK: 1}))
    disk_started = asyncio.Event()
    disk_release = asyncio.Event()
    cpu_started = asyncio.Event()

    async def held_disk(_context: object) -> None:
        disk_started.set()
        await disk_release.wait()

    async def disk_probe(_context: object) -> None:
        return None

    async def cpu_probe(_context: object) -> None:
        cpu_started.set()

    owner = asyncio.create_task(
        BoundedScheduler(host_arbiter=arbiter).run(
            (Task("held-disk", held_disk, resource=ResourceClass.DISK),)
        )
    )
    await asyncio.wait_for(disk_started.wait(), 1)
    tasks = tuple(
        Task(f"disk-{index}", disk_probe, resource=ResourceClass.DISK, priority=10)
        for index in range(4)
    )
    flooded = asyncio.create_task(
        BoundedScheduler(host_arbiter=arbiter).run((*tasks, Task("cpu", cpu_probe)))
    )
    await asyncio.wait_for(cpu_started.wait(), 1)
    assert not disk_release.is_set()
    disk_release.set()
    left, right = await asyncio.wait_for(asyncio.gather(owner, flooded), 2)
    assert all(result.status is TaskStatus.SUCCEEDED for result in (*left, *right))


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


def test_blocking_scheduler_admits_child_after_persisted_result_while_unrelated_work_runs() -> None:
    owner_thread = threading.get_ident()
    persisted: set[str] = set()
    child_finished = threading.Event()
    slow_started = threading.Event()
    offered: list[str] = []

    def slow(_context: object) -> str:
        slow_started.set()
        assert child_finished.wait(timeout=2), "dynamic child did not overlap unrelated work"
        return "slow"

    def fast(_context: object) -> str:
        assert slow_started.wait(timeout=2)
        return "fast"

    def child(_context: object) -> str:
        child_finished.set()
        return "child"

    def persist(result: TaskResult) -> None:
        assert threading.get_ident() == owner_thread
        persisted.add(result.task_id)

    def offer(result: TaskResult) -> tuple[Task, ...]:
        assert threading.get_ident() == owner_thread
        assert result.task_id in persisted
        offered.append(result.task_id)
        return (
            (Task(task_id="child", action=child, dependencies=("fast",)),)
            if result.task_id == "fast"
            else ()
        )

    results = BoundedScheduler(budget=ResourceBudget(global_limit=2)).run_blocking(
        (Task(task_id="slow", action=slow), Task(task_id="fast", action=fast)),
        on_result=persist,
        offer_after_result=offer,
    )

    assert tuple(item.task_id for item in results) == ("slow", "fast", "child")
    assert all(item.status is TaskStatus.SUCCEEDED for item in results)
    assert persisted == {"slow", "fast", "child"}
    assert offered == ["fast", "slow", "child"] or offered == ["fast", "child", "slow"]


@pytest.mark.parametrize("defect", ["duplicate", "missing", "cycle"])
def test_blocking_scheduler_rejects_malformed_dynamic_offer(defect: str) -> None:
    def offer(_result: TaskResult) -> tuple[Task, ...]:
        if defect == "duplicate":
            return (Task(task_id="root", action=lambda _context: None),)
        if defect == "missing":
            return (Task(task_id="child", action=lambda _context: None, dependencies=("absent",)),)
        return (
            Task(task_id="left", action=lambda _context: None, dependencies=("right",)),
            Task(task_id="right", action=lambda _context: None, dependencies=("left",)),
        )

    with pytest.raises(TaskGraphError):
        BoundedScheduler().run_blocking(
            (Task(task_id="root", action=lambda _context: "persisted"),),
            on_result=lambda _result: None,
            offer_after_result=offer,
        )


def test_blocking_scheduler_dynamic_offer_respects_total_capacity() -> None:
    child_ran = False

    def child(_context: object) -> None:
        nonlocal child_ran
        child_ran = True

    with pytest.raises(TaskGraphError, match="max_tasks"):
        BoundedScheduler(budget=ResourceBudget(max_tasks=1)).run_blocking(
            (Task(task_id="root", action=lambda _context: "done"),),
            on_result=lambda _result: None,
            offer_after_result=lambda _result: (Task(task_id="child", action=child),),
        )
    assert not child_ran


def test_blocking_scheduler_dynamic_child_waits_for_resource_capacity() -> None:
    disk_started = threading.Event()
    release_disk = threading.Event()
    disk_finished = threading.Event()

    def disk_hold(_context: object) -> str:
        disk_started.set()
        assert release_disk.wait(timeout=2)
        time.sleep(0.03)
        disk_finished.set()
        return "disk"

    def fast(_context: object) -> str:
        assert disk_started.wait(timeout=2)
        return "fast"

    def child(_context: object) -> str:
        assert disk_finished.is_set(), "per-resource capacity was released too early"
        return "child"

    def offer(result: TaskResult) -> tuple[Task, ...]:
        if result.task_id != "fast":
            return ()
        release_disk.set()
        return (Task(task_id="child", action=child, resource=ResourceClass.DISK),)

    results = BoundedScheduler(
        budget=ResourceBudget(global_limit=2, per_resource={ResourceClass.DISK: 1})
    ).run_blocking(
        (
            Task(task_id="disk", action=disk_hold, resource=ResourceClass.DISK),
            Task(task_id="fast", action=fast, resource=ResourceClass.CPU),
        ),
        on_result=lambda _result: None,
        offer_after_result=offer,
    )

    assert tuple(item.status for item in results) == (TaskStatus.SUCCEEDED,) * 3


def test_blocking_scheduler_dynamic_offer_requires_persist_callback() -> None:
    with pytest.raises(ValueError, match="on_result"):
        BoundedScheduler().run_blocking(
            (Task(task_id="root", action=lambda _context: "root"),),
            offer_after_result=lambda _result: (),
        )


def test_blocking_scheduler_commits_validated_offer_before_child_dispatch() -> None:
    owner_thread = threading.get_ident()
    events: list[str] = []
    admitted = threading.Event()

    def persist(result: TaskResult) -> None:
        events.append(f"persist:{result.task_id}")

    def offer(result: TaskResult) -> tuple[Task, ...]:
        events.append(f"offer:{result.task_id}")
        return (
            (Task(task_id="child", action=child, dependencies=("root",)),)
            if result.task_id == "root"
            else ()
        )

    def commit(tasks: tuple[Task, ...]) -> None:
        assert threading.get_ident() == owner_thread
        assert events[:2] == ["persist:root", "offer:root"]
        assert tuple(task.task_id for task in tasks) == ("child",)
        events.append("admitted:child")
        admitted.set()

    def child(_context: object) -> str:
        assert admitted.is_set()
        events.append("run:child")
        return "child"

    results = BoundedScheduler().run_blocking(
        (Task(task_id="root", action=lambda _context: "root"),),
        on_result=persist,
        offer_after_result=offer,
        on_admitted=commit,
    )

    assert tuple(item.status for item in results) == (TaskStatus.SUCCEEDED,) * 2
    assert events.index("admitted:child") < events.index("run:child")


def test_blocking_scheduler_does_not_commit_malformed_offer() -> None:
    committed = False

    def commit(_tasks: tuple[Task, ...]) -> None:
        nonlocal committed
        committed = True

    with pytest.raises(TaskGraphError, match="missing dependency"):
        BoundedScheduler().run_blocking(
            (Task(task_id="root", action=lambda _context: "root"),),
            on_result=lambda _result: None,
            offer_after_result=lambda _result: (
                Task(task_id="child", action=lambda _context: None, dependencies=("missing",)),
            ),
            on_admitted=commit,
        )
    assert not committed


def test_blocking_scheduler_failed_admission_commit_does_not_dispatch_offer() -> None:
    slow_started = threading.Event()
    release_slow = threading.Event()
    slow_finished = threading.Event()
    child_ran = False

    def slow(_context: object) -> str:
        slow_started.set()
        assert release_slow.wait(timeout=2)
        slow_finished.set()
        return "slow"

    def fast(_context: object) -> str:
        assert slow_started.wait(timeout=2)
        return "fast"

    def child(_context: object) -> str:
        nonlocal child_ran
        child_ran = True
        return "child"

    def offer(result: TaskResult) -> tuple[Task, ...]:
        return (Task(task_id="child", action=child),) if result.task_id == "fast" else ()

    def failed_commit(_tasks: tuple[Task, ...]) -> None:
        release_slow.set()
        raise RuntimeError("admission persistence failed")

    with pytest.raises(RuntimeError, match="admission persistence failed"):
        BoundedScheduler(budget=ResourceBudget(global_limit=2)).run_blocking(
            (Task(task_id="slow", action=slow), Task(task_id="fast", action=fast)),
            on_result=lambda _result: None,
            offer_after_result=offer,
            on_admitted=failed_commit,
        )
    assert slow_finished.is_set()
    assert not child_ran


def test_blocking_scheduler_rejected_offer_keeps_unrelated_result_persistence() -> None:
    slow_started = threading.Event()
    release_slow = threading.Event()
    persisted: list[str] = []
    child_ran = False

    def slow(_context: object) -> str:
        slow_started.set()
        assert release_slow.wait(timeout=2)
        return "slow"

    def fast(_context: object) -> str:
        assert slow_started.wait(timeout=2)
        return "fast"

    def child(_context: object) -> str:
        nonlocal child_ran
        child_ran = True
        return "child"

    def offer(result: TaskResult) -> tuple[Task, ...]:
        return (Task(task_id="child", action=child),) if result.task_id == "fast" else ()

    def reject(_tasks: tuple[Task, ...]) -> bool:
        release_slow.set()
        return False

    results = BoundedScheduler(budget=ResourceBudget(global_limit=2)).run_blocking(
        (Task(task_id="slow", action=slow), Task(task_id="fast", action=fast)),
        on_result=lambda result: persisted.append(result.task_id),
        offer_after_result=offer,
        on_admitted=reject,
    )

    assert tuple(item.task_id for item in results) == ("slow", "fast")
    assert all(item.status is TaskStatus.SUCCEEDED for item in results)
    assert set(persisted) == {"slow", "fast"}
    assert not child_ran


def test_blocking_scheduler_does_not_offer_after_cancel_or_case_deadline() -> None:
    def check_stop(stop: str) -> None:
        cancellation = threading.Event()
        offered = False

        def persist(_result: TaskResult) -> None:
            if stop == "cancel":
                cancellation.set()
            else:
                time.sleep(0.03)

        def offer(_result: TaskResult) -> tuple[Task, ...]:
            nonlocal offered
            offered = True
            return (Task(task_id="child", action=lambda _context: "child"),)

        results = BoundedScheduler().run_blocking(
            (Task(task_id="root", action=lambda _context: "root"),),
            case_deadline_at=(
                datetime.now(UTC) + timedelta(milliseconds=10) if stop == "deadline" else None
            ),
            cancel_event=cancellation,
            on_result=persist,
            offer_after_result=offer,
        )
        assert not offered
        assert tuple(item.task_id for item in results) == ("root",)

    check_stop("cancel")
    check_stop("deadline")


def test_blocking_scheduler_dynamic_child_preserves_dedupe_and_state_version() -> None:
    version = 1
    child_calls = 0

    def child(_context: object) -> str:
        nonlocal child_calls
        child_calls += 1
        return "child"

    def offer(result: TaskResult) -> tuple[Task, ...]:
        if result.task_id != "root":
            return ()
        return (
            Task(task_id="duplicate", action=child, dedupe_key="same", state_version=1),
            Task(task_id="stale", action=child, state_version=0),
        )

    results = BoundedScheduler().run_blocking(
        (Task(task_id="root", action=lambda _context: "root", dedupe_key="same", state_version=1),),
        state_version=lambda: version,
        on_result=lambda _result: None,
        offer_after_result=offer,
    )

    assert tuple(item.status for item in results) == (
        TaskStatus.SUCCEEDED,
        TaskStatus.DEDUPLICATED,
        TaskStatus.STALE,
    )
    assert child_calls == 0
