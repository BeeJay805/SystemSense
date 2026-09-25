"""The warm profile keeps its fast worker callable during deep reasoning."""

from __future__ import annotations

import threading
import time
from typing import Any

import pytest

from systemsense.inference.independent_providers import IndependentAdvisoryRuntime
from systemsense.inference.laya_runtime import LayaRuntimeError
from systemsense.inference.settings import LocalInferenceConfig


class _Session:
    def __init__(
        self, role: str, events: list[str], entered: threading.Event, release: threading.Event
    ) -> None:
        self.role = role
        self.events = events
        self.entered = entered
        self.release = release
        self.open = False

    def start(self) -> None:
        self.open = True
        self.events.append(f"start:{self.role}")

    def is_usable(self) -> bool:
        return self.open

    def close_verified(self) -> bool:
        self.open = False
        self.events.append(f"close:{self.role}")
        return True

    def rank(self, **_kwargs: Any) -> tuple[str, ...]:
        self.events.append("rank")
        return ("probe",)

    def complete(self, **_kwargs: Any) -> dict[str, str]:
        self.entered.set()
        assert self.release.wait(3)
        self.events.append("complete")
        return {"answer": "done"}


def test_warm_laya_ranks_repeatedly_while_deep_call_is_active() -> None:
    events: list[str] = []
    entered = threading.Event()
    release = threading.Event()
    runtime = IndependentAdvisoryRuntime(
        fast_factory=lambda: _Session("fast", events, entered, release),
        deep_factory=lambda: _Session("deep", events, entered, release),
        reasoning_config=LocalInferenceConfig(),
    )
    assert runtime.ranker.rank(state={}, candidates=(), timeout_seconds=1) == ("probe",)
    thread = threading.Thread(
        target=lambda: runtime.client.complete(
            model="local", prompt="x", schema={}, timeout_seconds=3
        )
    )
    thread.start()
    assert entered.wait(1)
    assert runtime.active_calls() == {"fast": 0, "deep": 1}
    started = time.monotonic()
    assert runtime.ranker.rank(state={}, candidates=(), timeout_seconds=1) == ("probe",)
    assert runtime.ranker.rank(state={}, candidates=(), timeout_seconds=1) == ("probe",)
    assert time.monotonic() - started < 0.5
    assert thread.is_alive()
    release.set()
    thread.join(3)
    assert not thread.is_alive()
    assert events.count("start:fast") == 1
    assert events.count("rank") == 3
    assert runtime.successful_calls() == {"fast": 3, "deep": 1}
    assert runtime.close(deadline_at=time.monotonic() + 2)


def test_failed_fast_role_is_quarantined_without_retiring_deep_role() -> None:
    events: list[str] = []
    entered = threading.Event()
    release = threading.Event()
    release.set()

    class FailedFast(_Session):
        def rank(self, **_kwargs: Any) -> tuple[str, ...]:
            raise RuntimeError("model_failed")

    runtime = IndependentAdvisoryRuntime(
        fast_factory=lambda: FailedFast("fast", events, entered, release),
        deep_factory=lambda: _Session("deep", events, entered, release),
        reasoning_config=LocalInferenceConfig(),
    )
    with pytest.raises(RuntimeError, match="model_failed"):
        runtime.ranker.rank(state={}, candidates=(), timeout_seconds=1)
    with pytest.raises(LayaRuntimeError, match="role_quarantined"):
        runtime.ranker.rank(state={}, candidates=(), timeout_seconds=1)
    assert runtime.client.complete(model="local", prompt="x", schema={}, timeout_seconds=1) == {
        "answer": "done"
    }
    assert events.count("start:fast") == 1
    assert runtime.role_status("fast")[0] == "quarantined"
    assert runtime.close(deadline_at=time.monotonic() + 1)
