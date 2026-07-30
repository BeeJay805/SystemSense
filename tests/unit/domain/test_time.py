from datetime import UTC, datetime, timedelta, timezone

import pytest
from pydantic import BaseModel, ValidationError

from systemsense.domain.time import UtcDateTime, ensure_utc, utc_now


def test_ensure_utc_rejects_naive_datetime() -> None:
    with pytest.raises(ValueError, match="timezone"):
        ensure_utc(datetime(2026, 7, 30, 12, 0))


def test_ensure_utc_converts_aware_datetime() -> None:
    mountain = timezone(-timedelta(hours=6))

    result = ensure_utc(datetime(2026, 7, 30, 12, 0, tzinfo=mountain))

    assert result == datetime(2026, 7, 30, 18, 0, tzinfo=UTC)
    assert result.tzinfo is UTC


def test_utc_now_is_timezone_aware() -> None:
    result = utc_now()

    assert result.tzinfo is UTC


def test_utc_datetime_validates_and_serializes_as_utc() -> None:
    class Observation(BaseModel):
        observed_at: UtcDateTime

    observation = Observation.model_validate({"observed_at": "2026-07-30T12:00:00-06:00"})

    assert observation.observed_at == datetime(2026, 7, 30, 18, 0, tzinfo=UTC)
    assert observation.model_dump(mode="json") == {"observed_at": "2026-07-30T18:00:00Z"}


def test_utc_datetime_rejects_naive_input() -> None:
    class Observation(BaseModel):
        observed_at: UtcDateTime

    with pytest.raises(ValidationError):
        Observation.model_validate({"observed_at": "2026-07-30T12:00:00"})
