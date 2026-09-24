"""Bounded in-process fair turns for advisory model callbacks.

The gate coordinates *turns*, not providers, workers, or GPU memory. It grants
one registered case at a time and never revokes a running callback on timeout
or cancellation. The caller must hold its lease until that callback exits.
"""

from __future__ import annotations

import re
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal

TurnStatus = Literal["acquired", "expired", "cancelled", "closed"]
_RUN_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}")


@dataclass(frozen=True, slots=True)
class ModelTurnAttempt:
    """A typed outcome; only ``acquired`` carries a lease."""

    status: TurnStatus
    lease: ModelTurnLease | None = None


class ModelTurnLease:
    """Idempotent worker-owned turn; release only after the callback exits."""

    def __init__(self, gate: FairModelTurns, run_id: str) -> None:
        self._gate = gate
        self._run_id = run_id
        self._released = False
        self._lock = threading.Lock()

    def __enter__(self) -> ModelTurnLease:
        return self

    def __exit__(self, *_unused: object) -> None:
        self.release()

    def release(self) -> None:
        with self._lock:
            if self._released:
                return
            self._released = True
        self._gate._release(self._run_id)  # pyright: ignore[reportPrivateUsage]


class ModelTurnRegistration:
    """One worker's bounded case reservation, including its queued turns."""

    def __init__(self, gate: FairModelTurns, run_id: str) -> None:
        self._gate = gate
        self._run_id = run_id

    def __enter__(self) -> ModelTurnRegistration:
        return self

    def __exit__(self, *_unused: object) -> None:
        self.close()

    def acquire(
        self, *, deadline_at: datetime, cancel_event: threading.Event | None = None
    ) -> ModelTurnAttempt:
        """Wait off the persistence owner thread for one fair model turn."""

        return self._gate._acquire(  # pyright: ignore[reportPrivateUsage]
            self._run_id, deadline_at, cancel_event
        )

    def close(self) -> None:
        """Unregister on worker exit or failed thread start, without revoking work."""

        self._gate._unregister(self._run_id)  # pyright: ignore[reportPrivateUsage]


class FairModelTurns:
    """FIFO turn admission across a bounded number of local case workers.

    A separate worker/provider belongs to each case. Register nonblocking on
    the owner thread; only worker threads call ``registration.acquire``. The
    registry bound also caps the number of workers allowed to wait here.
    """

    def __init__(self, *, max_registered: int = 16, poll_seconds: float = 0.05) -> None:
        if not 1 <= max_registered <= 256:
            raise ValueError("max_registered must be between 1 and 256")
        if not 0.001 <= poll_seconds <= 1:
            raise ValueError("poll_seconds must be between 0.001 and 1")
        self._max_registered = max_registered
        self._poll_seconds = poll_seconds
        self._condition = threading.Condition()
        self._registered: set[str] = set()
        self._closing: set[str] = set()
        self._pending: dict[str, int] = {}
        self._active: str | None = None
        self._sequence = 0

    @property
    def registered_count(self) -> int:
        with self._condition:
            return len(self._registered)

    @property
    def pending_count(self) -> int:
        with self._condition:
            return len(self._pending)

    def register(self, run_id: str) -> ModelTurnRegistration | None:
        """Reserve one bounded worker without blocking result persistence."""

        if _RUN_ID.fullmatch(run_id) is None:
            raise ValueError("model turn run ID is invalid")
        with self._condition:
            if run_id in self._registered:
                raise ValueError("model turn run is already registered")
            if len(self._registered) >= self._max_registered:
                return None
            self._registered.add(run_id)
            return ModelTurnRegistration(self, run_id)

    def _acquire(
        self,
        run_id: str,
        deadline_at: datetime,
        cancel_event: threading.Event | None,
    ) -> ModelTurnAttempt:
        if deadline_at.tzinfo is None:
            raise ValueError("model turn deadline must be timezone-aware")
        remaining = (deadline_at - datetime.now(UTC)).total_seconds()
        monotonic_deadline = time.monotonic() + max(0.0, remaining)
        with self._condition:
            if run_id not in self._registered or run_id in self._closing:
                return ModelTurnAttempt("closed")
            if run_id == self._active or run_id in self._pending:
                raise RuntimeError("case already has a model turn")
            if cancel_event is not None and cancel_event.is_set():
                return ModelTurnAttempt("cancelled")
            if remaining <= 0:
                return ModelTurnAttempt("expired")
            self._sequence += 1
            self._pending[run_id] = self._sequence
            try:
                while True:
                    if run_id in self._closing or run_id not in self._registered:
                        return ModelTurnAttempt("closed")
                    if cancel_event is not None and cancel_event.is_set():
                        return ModelTurnAttempt("cancelled")
                    remaining = min(
                        monotonic_deadline - time.monotonic(),
                        (deadline_at - datetime.now(UTC)).total_seconds(),
                    )
                    if remaining <= 0:
                        return ModelTurnAttempt("expired")
                    if self._active is None:
                        winner = min(self._pending, key=self._pending.__getitem__)
                        if winner == run_id:
                            del self._pending[run_id]
                            self._active = run_id
                            self._condition.notify_all()
                            return ModelTurnAttempt("acquired", ModelTurnLease(self, run_id))
                    self._condition.wait(min(self._poll_seconds, remaining))
            finally:
                if self._pending.pop(run_id, None) is not None:
                    self._condition.notify_all()

    def _release(self, run_id: str) -> None:
        with self._condition:
            if self._active != run_id:
                raise RuntimeError("model turn is not owned by this run")
            self._active = None
            self._prune(run_id)
            self._condition.notify_all()

    def _unregister(self, run_id: str) -> None:
        with self._condition:
            if run_id not in self._registered:
                return
            self._closing.add(run_id)
            self._pending.pop(run_id, None)
            self._prune(run_id)
            self._condition.notify_all()

    def _prune(self, run_id: str) -> None:
        if run_id in self._closing and self._active != run_id:
            self._closing.discard(run_id)
            self._registered.discard(run_id)
