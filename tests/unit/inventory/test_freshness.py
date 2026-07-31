from datetime import UTC, datetime, timedelta

from systemsense.inventory.freshness import (
    FreshnessReason,
    InvalidationSignal,
    assess_freshness,
    categories_for_signal,
)

_OBSERVED = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)


def test_freshness_reports_age_and_inclusive_ttl_boundary() -> None:
    result = assess_freshness(
        observed_at=_OBSERVED,
        ttl_seconds=60,
        invalidated_at=None,
        at=_OBSERVED + timedelta(seconds=60),
    )

    assert result.age_seconds == 60
    assert not result.stale
    assert result.reason is FreshnessReason.FRESH


def test_ttl_expiry_and_invalidation_have_explicit_reasons() -> None:
    expired = assess_freshness(
        observed_at=_OBSERVED,
        ttl_seconds=60,
        invalidated_at=None,
        at=_OBSERVED + timedelta(seconds=61),
    )
    invalidated = assess_freshness(
        observed_at=_OBSERVED,
        ttl_seconds=3600,
        invalidated_at=_OBSERVED + timedelta(seconds=10),
        at=_OBSERVED + timedelta(seconds=11),
    )

    assert expired.stale and expired.reason is FreshnessReason.TTL_EXPIRED
    assert invalidated.stale and invalidated.reason is FreshnessReason.INVALIDATED


def test_invalidation_signals_target_related_categories_only() -> None:
    assert categories_for_signal(InvalidationSignal.DRIVER_CHANGE) == frozenset(
        {"devices", "drivers", "audio", "gpu"}
    )
    assert "network" not in categories_for_signal(InvalidationSignal.DRIVER_CHANGE)
