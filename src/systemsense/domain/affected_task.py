"""User-reported affected task; a report never counts as observed evidence."""

from enum import StrEnum
from typing import Literal

from pydantic import Field

from systemsense.domain.evidence import FrozenModel


class AffectedTaskKind(StrEnum):
    BROWSER_NAVIGATION = "browser_navigation"
    APPLICATION_OPERATION = "application_operation"
    NETWORK_CONNECTION = "network_connection"
    DEVICE_OPERATION = "device_operation"
    OTHER = "other"


class ReportedAffectedTaskV1(FrozenModel):
    """Bounded intake context, without target-selection or outcome authority."""

    schema_version: Literal[1] = 1
    kind: AffectedTaskKind
    action: str = Field(min_length=1, max_length=240)
    target_hint: str | None = Field(default=None, min_length=1, max_length=240)
    expected_outcome: str | None = Field(default=None, min_length=1, max_length=500)
    reported_outcome: str = Field(min_length=1, max_length=500)
    source: Literal["user_report"] = "user_report"
    verification: Literal["unverified"] = "unverified"
