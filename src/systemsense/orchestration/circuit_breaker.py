"""Cooldown circuit for repeatedly failing evidence sources."""

from datetime import datetime, timedelta
from enum import StrEnum

from systemsense.domain.time import UtcDateTime, ensure_utc


class CircuitState(StrEnum):
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreaker:
    def __init__(self, *, failure_threshold: int, cooldown: timedelta) -> None:
        if failure_threshold < 1:
            raise ValueError("failure_threshold must be positive")
        if cooldown <= timedelta(0):
            raise ValueError("cooldown must be positive")
        self._failure_threshold = failure_threshold
        self._cooldown = cooldown
        self._failure_count = 0
        self._state = CircuitState.CLOSED
        self._opened_until: datetime | None = None

    @property
    def state(self) -> CircuitState:
        return self._state

    def allow(self, *, at: UtcDateTime) -> bool:
        checked_at = ensure_utc(at)
        if self._state is CircuitState.CLOSED:
            return True
        if self._state is CircuitState.HALF_OPEN:
            return False
        assert self._opened_until is not None
        if checked_at < self._opened_until:
            return False
        self._state = CircuitState.HALF_OPEN
        return True

    def record_failure(self, *, at: UtcDateTime) -> None:
        failed_at = ensure_utc(at)
        self._failure_count += 1
        if self._state is CircuitState.HALF_OPEN or self._failure_count >= self._failure_threshold:
            self._state = CircuitState.OPEN
            self._opened_until = failed_at + self._cooldown

    def record_success(self) -> None:
        self._failure_count = 0
        self._state = CircuitState.CLOSED
        self._opened_until = None
