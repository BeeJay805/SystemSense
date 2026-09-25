"""Independent warm managed roles for the explicit local development profile."""

from __future__ import annotations

import re
import threading
import time
from collections.abc import Callable
from typing import TypeVar

from systemsense.inference.laya_runtime import LayaRuntimeError
from systemsense.inference.sequential_local import OwnedLocalSession, SequentialLocalUnavailable
from systemsense.inference.sequential_providers import (
    ManagedSessionOllamaClient,
    SequentialLayaRanker,
)
from systemsense.inference.settings import LocalInferenceConfig

ResultT = TypeVar("ResultT")
_MAX_ROLE_RESTARTS = 2
_RESTART_BACKOFF_SECONDS = (0.05, 0.2)
_KNOWN_FAILURE_CODES = {
    "Laya worker request was cancelled": "worker_cancelled",
    "Laya worker exceeded its request deadline": "worker_deadline",
    "Laya worker call admission denied": "call_admission_denied",
    "Laya worker call admission exceeded its deadline": "call_admission_deadline",
    "Laya worker returned an invalid response": "invalid_worker_response",
    "Laya attention deadline expired before full coverage": "attention_deadline",
    "session_retired": "session_retired",
}


def _bounded_kind(error: Exception) -> str:
    name = type(error).__name__
    kind = name if re.fullmatch(r"[A-Za-z][A-Za-z0-9_]{0,63}", name) else "UnknownError"
    detail = _KNOWN_FAILURE_CODES.get(str(error))
    return f"{kind}:{detail}" if detail is not None else kind


class _Role:
    def __init__(self, factory: Callable[[], OwnedLocalSession]) -> None:
        self.factory = factory
        self.lock = threading.Lock()
        self.session: OwnedLocalSession | None = None
        self.failed = False
        self.failure_reason: str | None = None
        self.failure_count = 0
        self.next_retry_at = 0.0
        self.active = 0
        self.successful = 0


class _IndependentCoordinator:
    """One owned session per role; only same-role calls contend."""

    def __init__(
        self,
        fast_factory: Callable[[], OwnedLocalSession],
        deep_factory: Callable[[], OwnedLocalSession],
    ) -> None:
        self._roles = {"fast": _Role(fast_factory), "deep": _Role(deep_factory)}
        self._closing = threading.Event()
        self._metrics_lock = threading.Lock()

    def run(
        self,
        role: str,
        call: Callable[[OwnedLocalSession, float, Callable[[], bool]], ResultT],
        *,
        deadline_at: float,
        cancelled: Callable[[], bool],
    ) -> ResultT:
        slot = self._roles[role]
        while not slot.lock.acquire(timeout=min(0.05, max(0, deadline_at - time.monotonic()))):
            if cancelled() or self._closing.is_set():
                raise SequentialLocalUnavailable("call_cancelled")
            if time.monotonic() >= deadline_at:
                raise SequentialLocalUnavailable("call_deadline_elapsed")
        try:
            if cancelled() or self._closing.is_set():
                raise SequentialLocalUnavailable("call_cancelled")
            if time.monotonic() >= deadline_at:
                raise SequentialLocalUnavailable("call_deadline_elapsed")
            if slot.failed:
                raise SequentialLocalUnavailable("role_quarantined")
            while slot.session is None and time.monotonic() < slot.next_retry_at:
                if cancelled() or self._closing.is_set():
                    raise SequentialLocalUnavailable("call_cancelled")
                remaining = deadline_at - time.monotonic()
                if remaining <= 0:
                    raise SequentialLocalUnavailable("call_deadline_elapsed")
                time.sleep(max(0.0, min(0.02, remaining, slot.next_retry_at - time.monotonic())))
            if slot.session is None:
                if cancelled() or self._closing.is_set():
                    raise SequentialLocalUnavailable("call_cancelled")
                if time.monotonic() >= deadline_at:
                    raise SequentialLocalUnavailable("call_deadline_elapsed")
                try:
                    slot.session = slot.factory()
                except Exception as error:
                    # Session factories must be inert. Without a returned owner,
                    # no process-tree close proof can be obtained.
                    slot.failed = True
                    slot.failure_reason = f"factory_{_bounded_kind(error)};owner_unverified"
                    raise
                try:
                    slot.session.start()
                except Exception as error:
                    self._retire_failed_session(slot, error, stage="start")
                    raise
            assert slot.session is not None
            try:
                with self._metrics_lock:
                    slot.active += 1
                result = call(slot.session, deadline_at, cancelled)
                if not slot.session.is_usable():
                    raise SequentialLocalUnavailable("session_retired")
                with self._metrics_lock:
                    slot.successful += 1
                return result
            except Exception as error:
                try:
                    session_usable = slot.session.is_usable()
                except Exception:
                    session_usable = False
                if not (
                    role == "fast"
                    and isinstance(error, LayaRuntimeError)
                    and error.failure_code
                    in {"state_fit_limit", "instruction_fit_limit", "question_expansion_limit"}
                    and session_usable
                ):
                    self._retire_failed_session(slot, error, stage="call")
                raise
            finally:
                with self._metrics_lock:
                    slot.active -= 1
        finally:
            slot.lock.release()

    def role_status(self, role: str) -> tuple[str, str]:
        slot = self._roles[role]
        if slot.failed:
            return "quarantined", slot.failure_reason or "role_failed"
        if slot.session is None:
            if slot.failure_reason is not None:
                return (
                    "recovering",
                    f"{slot.failure_reason};retry_{slot.failure_count}_of_{_MAX_ROLE_RESTARTS}",
                )
            return "not_started", "not_started"
        admission = getattr(slot.session, "admission", None)
        if admission is not None:
            status = admission.status
            reason = status.reason
            if slot.failure_reason is not None:
                reason = f"{reason};last={slot.failure_reason}"
            return status.phase, reason[:120]
        reason = "session_status"
        if slot.failure_reason is not None:
            reason = f"{reason};last={slot.failure_reason}"
        return ("active" if slot.session.is_usable() else "degraded"), reason

    @staticmethod
    def _retire_failed_session(slot: _Role, error: Exception, *, stage: str) -> None:
        assert slot.session is not None
        slot.failure_reason = f"{stage}_{_bounded_kind(error)}"
        try:
            verified = slot.session.close_verified()
        except Exception:
            verified = False
        if not verified:
            slot.failed = True
            slot.failure_reason += ";close_unverified"
            raise SequentialLocalUnavailable("close_unverified") from None
        slot.session = None
        slot.failure_count += 1
        if slot.failure_count > _MAX_ROLE_RESTARTS:
            slot.failed = True
            slot.failure_reason += ";retry_exhausted"
            return
        slot.next_retry_at = time.monotonic() + _RESTART_BACKOFF_SECONDS[slot.failure_count - 1]

    def close(self, *, deadline_at: float) -> bool:
        self._closing.set()
        verified = True
        for slot in self._roles.values():
            if not slot.lock.acquire(timeout=max(0, deadline_at - time.monotonic())):
                verified = False
                continue
            try:
                if slot.session is not None and not slot.session.close_verified():
                    verified = False
            finally:
                slot.lock.release()
        return verified

    def active_calls(self) -> dict[str, int]:
        with self._metrics_lock:
            return {role: slot.active for role, slot in self._roles.items()}

    def successful_calls(self) -> dict[str, int]:
        with self._metrics_lock:
            return {role: slot.successful for role, slot in self._roles.items()}


class IndependentAdvisoryRuntime:
    """The existing managed adapters over two independently admitted workers."""

    def __init__(
        self,
        *,
        fast_factory: Callable[[], OwnedLocalSession],
        deep_factory: Callable[[], OwnedLocalSession],
        reasoning_config: LocalInferenceConfig,
    ) -> None:
        self.coordinator = _IndependentCoordinator(fast_factory, deep_factory)
        self.ranker = SequentialLayaRanker(self)  # type: ignore[arg-type]
        self.client = ManagedSessionOllamaClient(self, reasoning_config)  # type: ignore[arg-type]

    def role_status(self, role: str) -> tuple[str, str]:
        return self.coordinator.role_status(role)

    def close(self, *, deadline_at: float) -> bool:
        return self.coordinator.close(deadline_at=deadline_at)

    def active_calls(self) -> dict[str, int]:
        return self.coordinator.active_calls()

    def successful_calls(self) -> dict[str, int]:
        return self.coordinator.successful_calls()
