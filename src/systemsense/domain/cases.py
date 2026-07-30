"""Case-focused diagnostic workspace contracts."""

from enum import StrEnum
from typing import Literal

from pydantic import Field, field_validator, model_validator

from systemsense.domain.coverage import CoverageRecord
from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import CaseId, TargetId
from systemsense.domain.time import UtcDateTime


class CaseKind(StrEnum):
    GENERAL = "general"
    APPLICATION = "application"
    DEVICES_AUDIO = "devices_audio"
    NETWORK = "network"
    SERVICING = "servicing"
    LOCAL_AI = "local_ai"


class CaseStatus(StrEnum):
    OPEN = "open"
    COLLECTING = "collecting"
    READY = "ready"
    COMPLETE = "complete"
    ARCHIVED = "archived"


class TargetType(StrEnum):
    HOST = "host"
    APPLICATION = "application"
    DEVICE = "device"
    SERVICE = "service"
    REPOSITORY = "repository"


class CaseTarget(FrozenModel):
    target_id: TargetId
    type: TargetType
    display_name: str = Field(min_length=1, max_length=260)


class CaseTimeWindow(FrozenModel):
    start: UtcDateTime
    failure_start: UtcDateTime | None = None
    failure_end: UtcDateTime | None = None
    end: UtcDateTime

    @model_validator(mode="after")
    def validate_order(self) -> "CaseTimeWindow":
        points = [self.start]
        if self.failure_start is not None:
            points.append(self.failure_start)
        if self.failure_end is not None:
            points.append(self.failure_end)
        points.append(self.end)
        if points != sorted(points):
            raise ValueError("case time window must be chronologically ordered")
        return self


class DiagnosticCase(FrozenModel):
    schema_version: Literal[1] = 1
    case_id: CaseId
    kind: CaseKind
    status: CaseStatus
    symptom: str = Field(min_length=1, max_length=2000)
    created_at: UtcDateTime
    time_window: CaseTimeWindow
    targets: tuple[CaseTarget, ...] = ()
    coverage: tuple[CoverageRecord, ...] = ()

    @field_validator("symptom")
    @classmethod
    def symptom_must_not_be_blank(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("symptom must not be blank")
        return normalized
