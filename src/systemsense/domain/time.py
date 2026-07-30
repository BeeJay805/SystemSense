"""UTC-only time handling for evidence provenance."""

from datetime import UTC, datetime
from typing import Annotated

from pydantic import AfterValidator


def ensure_utc(value: datetime) -> datetime:
    """Reject naive datetimes and normalize aware values to UTC."""

    if value.tzinfo is None or value.utcoffset() is None:
        raise ValueError("timestamp must include a timezone")
    return value.astimezone(UTC)


UtcDateTime = Annotated[datetime, AfterValidator(ensure_utc)]


def utc_now() -> datetime:
    """Return the current timezone-aware UTC time."""

    return datetime.now(UTC)
