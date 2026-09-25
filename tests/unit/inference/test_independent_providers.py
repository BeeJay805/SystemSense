"""The warm profile keeps its fast worker callable during deep reasoning."""

from __future__ import annotations

import threading
import time
from typing import Any

import pytest

from systemsense.inference import independent_providers
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


def test_failed_fast_role_restarts_after_verified_close_without_retiring_deep_role() -> None:
    events: list[str] = []
    entered = threading.Event()
    release = threading.Event()
    release.set()

    class FailedFast(_Session):
        def rank(self, **_kwargs: Any) -> tuple[str, ...]:
            raise RuntimeError("model_failed")

    fast_sessions: list[_Session] = []

    def fast_factory() -> _Session:
        session: _Session = (
            FailedFast("fast", events, entered, release)
            if not fast_sessions
            else _Session("fast", events, entered, release)
        )
        fast_sessions.append(session)
        return session

    runtime = IndependentAdvisoryRuntime(
        fast_factory=fast_factory,
        deep_factory=lambda: _Session("deep", events, entered, release),
        reasoning_config=LocalInferenceConfig(),
    )
    with pytest.raises(RuntimeError, match="model_failed"):
        runtime.ranker.rank(state={}, candidates=(), timeout_seconds=1)
    assert runtime.role_status("fast") == ("recovering", "call_RuntimeError;retry_1_of_2")
    assert runtime.ranker.rank(state={}, candidates=(), timeout_seconds=1) == ("probe",)
    assert runtime.client.complete(model="local", prompt="x", schema={}, timeout_seconds=1) == {
        "answer": "done"
    }
    assert events.count("start:fast") == 2
    assert runtime.role_status("fast") == ("active", "session_status;last=call_RuntimeError")
    assert runtime.close(deadline_at=time.monotonic() + 1)


def test_input_fit_rejection_does_not_retire_a_healthy_fast_role() -> None:
    events: list[str] = []
    release = threading.Event()
    release.set()

    class RejectOnce(_Session):
        def rank(self, **_kwargs: Any) -> tuple[str, ...]:
            self.events.append("rank")
            if self.events.count("rank") == 1:
                raise LayaRuntimeError(
                    "Laya worker rejected its bounded request",
                    failure_code="instruction_fit_limit",
                )
            return ("probe",)

    runtime = IndependentAdvisoryRuntime(
        fast_factory=lambda: RejectOnce("fast", events, threading.Event(), release),
        deep_factory=lambda: _Session("deep", events, threading.Event(), release),
        reasoning_config=LocalInferenceConfig(),
    )
    with pytest.raises(LayaRuntimeError) as failure:
        runtime.ranker.rank(state={}, candidates=(), timeout_seconds=1)
    assert failure.value.failure_code == "instruction_fit_limit"
    assert runtime.ranker.rank(state={}, candidates=(), timeout_seconds=1) == ("probe",)
    assert events.count("start:fast") == 1
    assert "close:fast" not in events
    assert runtime.close(deadline_at=time.monotonic() + 1)


def test_fast_role_quarantines_after_bounded_verified_failures() -> None:
    events: list[str] = []
    release = threading.Event()
    release.set()

    class FailedFast(_Session):
        def rank(self, **_kwargs: Any) -> tuple[str, ...]:
            raise RuntimeError("model_failed")

    runtime = IndependentAdvisoryRuntime(
        fast_factory=lambda: FailedFast("fast", events, threading.Event(), release),
        deep_factory=lambda: _Session("deep", events, threading.Event(), release),
        reasoning_config=LocalInferenceConfig(),
    )
    for _ in range(3):
        with pytest.raises(RuntimeError, match="model_failed"):
            runtime.ranker.rank(state={}, candidates=(), timeout_seconds=1)
    assert runtime.role_status("fast") == ("quarantined", "call_RuntimeError;retry_exhausted")
    with pytest.raises(LayaRuntimeError, match="role_quarantined"):
        runtime.ranker.rank(state={}, candidates=(), timeout_seconds=1)
    assert events.count("start:fast") == events.count("close:fast") == 3
    assert runtime.close(deadline_at=time.monotonic() + 1)


def test_fast_role_keeps_quarantine_if_close_is_unverified() -> None:
    events: list[str] = []
    release = threading.Event()

    class UnverifiedFast(_Session):
        def rank(self, **_kwargs: Any) -> tuple[str, ...]:
            raise RuntimeError("model_failed")

        def close_verified(self) -> bool:
            self.events.append("close_unverified:fast")
            return False

    runtime = IndependentAdvisoryRuntime(
        fast_factory=lambda: UnverifiedFast("fast", events, threading.Event(), release),
        deep_factory=lambda: _Session("deep", events, threading.Event(), release),
        reasoning_config=LocalInferenceConfig(),
    )
    with pytest.raises(LayaRuntimeError, match="close_unverified"):
        runtime.ranker.rank(state={}, candidates=(), timeout_seconds=1)
    assert runtime.role_status("fast") == ("quarantined", "call_RuntimeError;close_unverified")
    with pytest.raises(LayaRuntimeError, match="role_quarantined"):
        runtime.ranker.rank(state={}, candidates=(), timeout_seconds=1)
    assert events.count("start:fast") == 1


def test_recoverable_role_respects_retry_backoff_and_caller_deadline(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(independent_providers, "_RESTART_BACKOFF_SECONDS", (0.04, 0.04))
    events: list[str] = []
    release = threading.Event()
    sessions: list[_Session] = []

    class FailedFast(_Session):
        def rank(self, **_kwargs: Any) -> tuple[str, ...]:
            raise RuntimeError("one_bad_call")

    def fast_factory() -> _Session:
        session: _Session = (
            FailedFast("fast", events, threading.Event(), release)
            if not sessions
            else _Session("fast", events, threading.Event(), release)
        )
        sessions.append(session)
        return session

    runtime = IndependentAdvisoryRuntime(
        fast_factory=fast_factory,
        deep_factory=lambda: _Session("deep", events, threading.Event(), release),
        reasoning_config=LocalInferenceConfig(),
    )
    with pytest.raises(RuntimeError, match="one_bad_call"):
        runtime.ranker.rank(state={}, candidates=(), timeout_seconds=1)
    with pytest.raises(LayaRuntimeError, match="call_deadline_elapsed"):
        runtime.ranker.rank(state={}, candidates=(), timeout_seconds=0.005)
    assert len(sessions) == 1
    assert runtime.ranker.rank(state={}, candidates=(), timeout_seconds=1) == ("probe",)
    assert len(sessions) == 2
    assert runtime.close(deadline_at=time.monotonic() + 1)


def test_role_status_retains_bounded_known_failure_without_leaking_arbitrary_text() -> None:
    class FailedFast(_Session):
        def rank(self, **_kwargs: Any) -> tuple[str, ...]:
            raise LayaRuntimeError("Laya worker call admission denied")

    runtime = IndependentAdvisoryRuntime(
        fast_factory=lambda: FailedFast("fast", [], threading.Event(), threading.Event()),
        deep_factory=lambda: _Session("deep", [], threading.Event(), threading.Event()),
        reasoning_config=LocalInferenceConfig(),
    )
    with pytest.raises(LayaRuntimeError, match="call admission denied"):
        runtime.ranker.rank(state={}, candidates=(), timeout_seconds=1)
    assert runtime.role_status("fast") == (
        "recovering",
        "call_LayaRuntimeError:call_admission_denied;retry_1_of_2",
    )
    assert runtime.close(deadline_at=time.monotonic() + 1)
