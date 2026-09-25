"""Independent warm managed roles for the explicit local development profile."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable
from typing import TypeVar

from systemsense.inference.sequential_local import OwnedLocalSession, SequentialLocalUnavailable
from systemsense.inference.sequential_providers import (
    ManagedSessionOllamaClient,
    SequentialLayaRanker,
)
from systemsense.inference.settings import LocalInferenceConfig

ResultT = TypeVar("ResultT")


class _Role:
    def __init__(self, factory: Callable[[], OwnedLocalSession]) -> None:
        self.factory = factory
        self.lock = threading.Lock()
        self.session: OwnedLocalSession | None = None
        self.failed = False
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
            if slot.session is None:
                slot.session = slot.factory()
                try:
                    slot.session.start()
                except Exception:
                    slot.failed = True
                    if not slot.session.close_verified():
                        raise SequentialLocalUnavailable("close_unverified") from None
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
            except Exception:
                slot.failed = True
                if not slot.session.close_verified():
                    raise SequentialLocalUnavailable("close_unverified") from None
                raise
            finally:
                with self._metrics_lock:
                    slot.active -= 1
        finally:
            slot.lock.release()

    def role_status(self, role: str) -> tuple[str, str]:
        slot = self._roles[role]
        if slot.failed:
            return "quarantined", "role_failed"
        if slot.session is None:
            return "not_started", "not_started"
        admission = getattr(slot.session, "admission", None)
        if admission is not None:
            status = admission.status
            return status.phase, status.reason
        return ("active" if slot.session.is_usable() else "degraded"), "session_status"

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
