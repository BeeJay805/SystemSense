"""Serialize two owned local model roles without granting either OS authority.

Factories must be side-effect-free until their returned session's ``start`` is
called. A session owns its complete process tree and lifetime lease. Its
``close_verified`` must return true only after the whole tree exited and the
exact lease was released. The coordinator cannot interrupt a hung callback:
each role adapter must enforce its deadline and retire its owned tree on cancel.
"""

from __future__ import annotations

import math
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal, Protocol, TypeVar

Role = Literal["fast", "deep"]


class OwnedLocalSession(Protocol):
    def start(self) -> None: ...

    def is_usable(self) -> bool: ...

    def close_verified(self) -> bool: ...


SessionT = TypeVar("SessionT", bound=OwnedLocalSession)
ResultT = TypeVar("ResultT")


class SequentialLocalUnavailable(RuntimeError):
    """The owner was closed or could not admit a new call."""


class SequentialLocalDeadline(SequentialLocalUnavailable):
    """The call deadline elapsed before a usable result was accepted."""


class SequentialLocalCancelled(SequentialLocalUnavailable):
    """The caller cancelled before a usable result was accepted."""


class SequentialLocalQuarantined(SequentialLocalUnavailable):
    """Owned tree or lease release was unverified; no other role may start."""


@dataclass(frozen=True, slots=True)
class SequentialLocalStatus:
    active_role: Role | None
    busy: bool
    queued_fast: int
    queued_deep: int
    quarantined_reason: str | None
    closed: bool


def _not_cancelled() -> bool:
    return False


class SequentialLocalCoordinator[SessionT: OwnedLocalSession]:
    """One resident role, one call at a time, with fair handoff when both wait.

    Opposite-role waiters take the next turn. Same-role calls reuse residency
    while no opposite role waits. Every switch verifies full prior-role release.
    """

    def __init__(
        self,
        *,
        fast_factory: Callable[[], SessionT],
        deep_factory: Callable[[], SessionT],
    ) -> None:
        self._factories: dict[Role, Callable[[], SessionT]] = {
            "fast": fast_factory,
            "deep": deep_factory,
        }
        self._condition = threading.Condition()
        self._session: SessionT | None = None
        self._role: Role | None = None
        self._last_served: Role | None = None
        self._queued: dict[Role, list[object]] = {"fast": [], "deep": []}
        self._busy = False
        self._quarantined_reason: str | None = None
        self._closed = False

    @property
    def status(self) -> SequentialLocalStatus:
        with self._condition:
            return SequentialLocalStatus(
                active_role=self._role,
                busy=self._busy,
                queued_fast=len(self._queued["fast"]),
                queued_deep=len(self._queued["deep"]),
                quarantined_reason=self._quarantined_reason,
                closed=self._closed,
            )

    def run(
        self,
        role: Role,
        call: Callable[[SessionT, float, Callable[[], bool]], ResultT],
        *,
        deadline_at: float,
        cancelled: Callable[[], bool] = _not_cancelled,
    ) -> ResultT:
        if role not in self._factories or not math.isfinite(deadline_at):
            raise ValueError("role and monotonic deadline must be valid")
        ticket = object()
        with self._condition:
            self._queued[role].append(ticket)
            try:
                while True:
                    self._check_window(deadline_at, cancelled)
                    if self._quarantined_reason is not None:
                        raise SequentialLocalQuarantined(self._quarantined_reason)
                    if self._closed:
                        raise SequentialLocalUnavailable("coordinator_closed")
                    if (
                        not self._busy
                        and self._next_role() == role
                        and self._queued[role][0] is ticket
                    ):
                        self._queued[role].pop(0)
                        self._busy = True
                        self._last_served = role
                        break
                    self._condition.wait(
                        timeout=min(0.05, max(0.0, deadline_at - time.monotonic()))
                    )
            except BaseException:
                if ticket in self._queued[role]:
                    self._queued[role].remove(ticket)
                self._condition.notify_all()
                raise

        try:
            session = self._prepare(role, deadline_at, cancelled)
            try:
                result = call(session, deadline_at, cancelled)
                self._check_window(deadline_at, cancelled)
                return result
            except BaseException:
                self._retire(session)
                raise
        finally:
            with self._condition:
                self._busy = False
                self._condition.notify_all()

    def close(self, *, deadline_at: float) -> bool:
        """Drain an active call, then verify release; false means no release proof."""

        if not math.isfinite(deadline_at):
            raise ValueError("monotonic deadline must be finite")
        with self._condition:
            self._closed = True
            self._condition.notify_all()
            while self._busy:
                remaining = deadline_at - time.monotonic()
                if remaining <= 0:
                    return False
                self._condition.wait(timeout=remaining)
            if self._quarantined_reason is not None:
                return False
            session = self._session
            if session is None:
                return True
            self._busy = True
        try:
            self._retire(session)
            return True
        except SequentialLocalQuarantined:
            return False
        finally:
            with self._condition:
                self._busy = False
                self._condition.notify_all()

    def _next_role(self) -> Role | None:
        fast = bool(self._queued["fast"])
        deep = bool(self._queued["deep"])
        if fast and deep:
            return "deep" if self._last_served == "fast" else "fast"
        if fast:
            return "fast"
        if deep:
            return "deep"
        return None

    def _prepare(self, role: Role, deadline_at: float, cancelled: Callable[[], bool]) -> SessionT:
        session = self._session
        if session is not None:
            try:
                reusable = session.is_usable()
            except Exception:
                reusable = False
            if self._role != role or not reusable:
                self._retire(session)
                session = None
        self._check_window(deadline_at, cancelled)
        if session is not None:
            return session
        session = self._factories[role]()
        try:
            self._check_window(deadline_at, cancelled)
            session.start()
            self._check_window(deadline_at, cancelled)
        except BaseException:
            self._retire(session)
            raise
        with self._condition:
            self._session = session
            self._role = role
        return session

    def _retire(self, session: SessionT) -> None:
        try:
            verified = session.close_verified()
        except BaseException:
            verified = False
        with self._condition:
            if not verified:
                self._quarantined_reason = "close_unverified"
                self._condition.notify_all()
                raise SequentialLocalQuarantined("close_unverified")
            if self._session is session:
                self._session = None
                self._role = None
            self._condition.notify_all()

    @staticmethod
    def _check_window(deadline_at: float, cancelled: Callable[[], bool]) -> None:
        try:
            is_cancelled = cancelled()
        except Exception:
            is_cancelled = True
        if is_cancelled:
            raise SequentialLocalCancelled("call_cancelled")
        if time.monotonic() >= deadline_at:
            raise SequentialLocalDeadline("call_deadline_elapsed")
