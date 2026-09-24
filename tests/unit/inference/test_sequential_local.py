from __future__ import annotations

import threading
import time
from collections.abc import Callable

import pytest

from systemsense.inference.sequential_local import (
    SequentialLocalCancelled,
    SequentialLocalCoordinator,
    SequentialLocalDeadline,
    SequentialLocalQuarantined,
)


class FakeSession:
    def __init__(self, role: str, events: list[str], *, verified: bool = True) -> None:
        self.role = role
        self.events = events
        self.verified = verified

    def start(self) -> None:
        self.events.append(f"start:{self.role}")

    def close_verified(self) -> bool:
        self.events.append(f"close:{self.role}")
        return self.verified


def _coordinator(
    events: list[str], *, fast_verified: bool = True
) -> SequentialLocalCoordinator[FakeSession]:
    return SequentialLocalCoordinator(
        fast_factory=lambda: FakeSession("fast", events, verified=fast_verified),
        deep_factory=lambda: FakeSession("deep", events),
    )


def _call(session: FakeSession, _deadline: float, _cancelled: Callable[[], bool]) -> str:
    session.events.append(f"call:{session.role}")
    return session.role


def _deadline() -> float:
    return time.monotonic() + 3


def test_reuses_one_role_and_closes_verified_tree_before_starting_other() -> None:
    events: list[str] = []
    coordinator = _coordinator(events)

    assert coordinator.run("fast", _call, deadline_at=_deadline()) == "fast"
    assert coordinator.run("fast", _call, deadline_at=_deadline()) == "fast"
    assert coordinator.run("deep", _call, deadline_at=_deadline()) == "deep"
    assert coordinator.run("fast", _call, deadline_at=_deadline()) == "fast"
    assert coordinator.close(deadline_at=_deadline())
    assert coordinator.close(deadline_at=_deadline())

    assert events == [
        "start:fast",
        "call:fast",
        "call:fast",
        "close:fast",
        "start:deep",
        "call:deep",
        "close:deep",
        "start:fast",
        "call:fast",
        "close:fast",
    ]


def test_unverified_close_quarantines_and_never_starts_other_role() -> None:
    events: list[str] = []
    coordinator = _coordinator(events, fast_verified=False)
    coordinator.run("fast", _call, deadline_at=_deadline())

    with pytest.raises(SequentialLocalQuarantined, match="close_unverified"):
        coordinator.run("deep", _call, deadline_at=_deadline())
    with pytest.raises(SequentialLocalQuarantined):
        coordinator.run("fast", _call, deadline_at=_deadline())

    assert events == ["start:fast", "call:fast", "close:fast"]
    assert coordinator.status.quarantined_reason == "close_unverified"


def test_waiting_deep_gets_turn_before_new_fast_call() -> None:
    events: list[str] = []
    coordinator = _coordinator(events)
    entered = threading.Event()
    release = threading.Event()
    outcomes: list[str] = []

    def blocked(session: FakeSession, deadline: float, cancelled: Callable[[], bool]) -> str:
        entered.set()
        assert release.wait(2)
        return _call(session, deadline, cancelled)

    first = threading.Thread(
        target=lambda: outcomes.append(coordinator.run("fast", blocked, deadline_at=_deadline()))
    )
    deep = threading.Thread(
        target=lambda: outcomes.append(coordinator.run("deep", _call, deadline_at=_deadline()))
    )
    later_fast = threading.Thread(
        target=lambda: outcomes.append(coordinator.run("fast", _call, deadline_at=_deadline()))
    )
    first.start()
    assert entered.wait(1)
    deep.start()
    later_fast.start()
    until = time.monotonic() + 1
    while coordinator.status.queued_fast != 1 or coordinator.status.queued_deep != 1:
        assert time.monotonic() < until
        time.sleep(0.005)
    release.set()
    for thread in (first, deep, later_fast):
        thread.join(2)
        assert not thread.is_alive()

    assert outcomes == ["fast", "deep", "fast"]
    assert events.index("start:deep") < events.index("call:fast", 2)
    assert coordinator.close(deadline_at=_deadline())


def test_queued_cancellation_and_deadline_never_start_model() -> None:
    events: list[str] = []
    coordinator = _coordinator(events)
    entered = threading.Event()
    release = threading.Event()

    def blocked(session: FakeSession, deadline: float, cancelled: Callable[[], bool]) -> str:
        entered.set()
        assert release.wait(2)
        return _call(session, deadline, cancelled)

    active = threading.Thread(
        target=lambda: coordinator.run("fast", blocked, deadline_at=_deadline())
    )
    active.start()
    assert entered.wait(1)
    cancel = threading.Event()
    cancel.set()
    with pytest.raises(SequentialLocalCancelled):
        coordinator.run("deep", _call, deadline_at=_deadline(), cancelled=cancel.is_set)
    with pytest.raises(SequentialLocalDeadline):
        coordinator.run("deep", _call, deadline_at=time.monotonic() - 1)
    release.set()
    active.join(2)
    assert not active.is_alive()
    assert "start:deep" not in events
    assert coordinator.close(deadline_at=_deadline())


def test_late_cancelled_result_is_rejected_and_owned_session_retired() -> None:
    events: list[str] = []
    coordinator = _coordinator(events)
    cancel = threading.Event()

    def late(session: FakeSession, _deadline: float, _cancelled: Callable[[], bool]) -> str:
        cancel.set()
        return session.role

    with pytest.raises(SequentialLocalCancelled):
        coordinator.run("deep", late, deadline_at=_deadline(), cancelled=cancel.is_set)

    assert events == ["start:deep", "close:deep"]
    assert coordinator.status.active_role is None
    assert coordinator.close(deadline_at=_deadline())


def test_start_failure_closes_partial_session_before_any_retry() -> None:
    events: list[str] = []

    class BadSession(FakeSession):
        def start(self) -> None:
            super().start()
            raise RuntimeError("start failed")

    coordinator: SequentialLocalCoordinator[FakeSession] = SequentialLocalCoordinator(
        fast_factory=lambda: BadSession("fast", events),
        deep_factory=lambda: FakeSession("deep", events),
    )
    with pytest.raises(RuntimeError, match="start failed"):
        coordinator.run("fast", _call, deadline_at=_deadline())
    assert events == ["start:fast", "close:fast"]
    assert coordinator.run("deep", _call, deadline_at=_deadline()) == "deep"
    assert coordinator.close(deadline_at=_deadline())
