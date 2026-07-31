"""Freshness assessment and targeted passive invalidation."""

from datetime import datetime, timedelta
from enum import StrEnum

from pydantic import Field

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.time import UtcDateTime, ensure_utc


class FreshnessReason(StrEnum):
    FRESH = "fresh"
    TTL_EXPIRED = "ttl_expired"
    INVALIDATED = "invalidated"


class Freshness(FrozenModel):
    age_seconds: float = Field(ge=0)
    stale: bool
    reason: FreshnessReason


class InvalidationSignal(StrEnum):
    DRIVER_CHANGE = "driver_change"
    NETWORK_CHANGE = "network_change"
    UPDATE_CHANGE = "update_change"
    BOOT = "boot"
    PROCESS_CHANGE = "process_change"


_SIGNAL_CATEGORIES: dict[InvalidationSignal, frozenset[str]] = {
    InvalidationSignal.DRIVER_CHANGE: frozenset({"devices", "drivers", "audio", "gpu"}),
    InvalidationSignal.NETWORK_CHANGE: frozenset({"network"}),
    InvalidationSignal.UPDATE_CHANGE: frozenset({"servicing"}),
    InvalidationSignal.BOOT: frozenset({"system", "resources", "processes", "services"}),
    InvalidationSignal.PROCESS_CHANGE: frozenset({"processes", "ports", "resources"}),
}


def categories_for_signal(signal: InvalidationSignal) -> frozenset[str]:
    return _SIGNAL_CATEGORIES[signal]


def assess_freshness(
    *,
    observed_at: UtcDateTime,
    ttl_seconds: int,
    invalidated_at: UtcDateTime | None,
    at: datetime,
) -> Freshness:
    if ttl_seconds < 1:
        raise ValueError("ttl_seconds must be positive")
    checked_at = ensure_utc(at)
    age_seconds = max(0.0, (checked_at - observed_at).total_seconds())
    if invalidated_at is not None and checked_at >= invalidated_at:
        return Freshness(
            age_seconds=age_seconds,
            stale=True,
            reason=FreshnessReason.INVALIDATED,
        )
    if checked_at > observed_at + timedelta(seconds=ttl_seconds):
        return Freshness(
            age_seconds=age_seconds,
            stale=True,
            reason=FreshnessReason.TTL_EXPIRED,
        )
    return Freshness(
        age_seconds=age_seconds,
        stale=False,
        reason=FreshnessReason.FRESH,
    )
