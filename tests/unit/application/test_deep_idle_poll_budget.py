"""Idle deep work stays responsive without repeatedly scanning unchanged custody."""

import threading
from types import SimpleNamespace
from typing import Any, cast

import pytest

from systemsense.application import investigator as module
from systemsense.application.deep_worker import DeepWorkerLane


@pytest.mark.parametrize("signal", ["completion", "cancellation", "evidence"])
def test_idle_polling_bounds_custody_work_and_detects_changes(
    monkeypatch: pytest.MonkeyPatch, signal: str
) -> None:
    elapsed = 0.0
    signal_at = 0.203
    generation = 1
    drains = 0
    cancellation = threading.Event()

    class Lane:
        occupied = True

        def wait(self, timeout: float) -> bool:
            nonlocal elapsed, generation
            assert 0 <= timeout <= 0.05
            elapsed += timeout
            if elapsed >= signal_at:
                if signal == "completion":
                    # Completion wakes the Event immediately, before its timeout.
                    elapsed = signal_at
                    self.occupied = False
                elif signal == "cancellation":
                    cancellation.set()
                else:
                    generation += 1
            return not self.occupied

    lane = Lane()
    state = SimpleNamespace(case_id="test-case")

    def drain(value: object) -> object:
        nonlocal drains
        drains += 1
        return value

    def remaining_ms(_: object) -> float:
        return 1000 - elapsed * 1000

    def capture(*_: object) -> SimpleNamespace:
        return SimpleNamespace(case_generation=generation)

    owner = SimpleNamespace(
        store=object(),
        _deep_task=object(),
        _deep_lane=lane,
        _remaining_ms=remaining_ms,
        _drain_deep=drain,
        _has_deep_work=lambda: lane.occupied,
    )
    monkeypatch.setattr(module, "current_cancellation", lambda: cancellation)
    monkeypatch.setattr(
        module,
        "capture_presented_read_set",
        capture,
    )
    result = module.Investigator._await_deep_when_idle(  # pyright: ignore[reportPrivateUsage]
        cast(Any, owner), cast(Any, state)
    )
    assert result is state
    assert signal_at <= elapsed <= signal_at + 0.05
    # Includes the final drain. A 10-ms polling loop unnecessarily performs >20.
    assert drains <= 7


def test_completed_deep_event_does_not_wait_for_poll_interval() -> None:
    lane = DeepWorkerLane()
    lane._done.set()  # pyright: ignore[reportPrivateUsage]
    assert lane.wait(0.05)
