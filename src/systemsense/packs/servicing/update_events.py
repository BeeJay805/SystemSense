"""Structured Windows Update event facts."""

from collections.abc import Mapping

from pydantic import Field

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.time import UtcDateTime


class UpdateEvent(FrozenModel):
    event_id: int = Field(ge=0)
    observed_at: UtcDateTime
    title: str | None = Field(default=None, max_length=1024)
    error_code: str | None = Field(default=None, max_length=255)
    operation: str | None = Field(default=None, max_length=255)


def parse_update_event(
    *,
    event_id: int,
    observed_at: UtcDateTime,
    fields: Mapping[str, str],
) -> UpdateEvent:
    return UpdateEvent(
        event_id=event_id,
        observed_at=observed_at,
        title=fields.get("updateTitle"),
        error_code=fields.get("errorCode"),
        operation=fields.get("operation"),
    )
