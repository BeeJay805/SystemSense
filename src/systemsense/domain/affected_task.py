"""User-reported affected task; a report never counts as observed evidence."""

from __future__ import annotations

from datetime import timedelta
from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId
from systemsense.domain.time import UtcDateTime


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


class TaskObservationFactPathsV1(FrozenModel):
    """Exact source fact names selected by a trusted fixture binder."""

    schema_version: Literal[1] = 1
    target_handle: str = Field(min_length=1, max_length=120)
    action: str = Field(min_length=1, max_length=120)
    expected: str = Field(min_length=1, max_length=120)
    observed: str = Field(min_length=1, max_length=120)
    window_start: str = Field(min_length=1, max_length=120)
    window_end: str = Field(min_length=1, max_length=120)
    window_ms: str = Field(min_length=1, max_length=120)

    @model_validator(mode="after")
    def unique_paths(self) -> TaskObservationFactPathsV1:
        paths = (
            self.target_handle,
            self.action,
            self.expected,
            self.observed,
            self.window_start,
            self.window_end,
            self.window_ms,
        )
        if len(set(paths)) != len(paths):
            raise ValueError("task observation fact paths must be unique")
        if any(
            not all(character.isalnum() or character in "_.-" for character in path)
            for path in paths
        ):
            raise ValueError("task observation fact paths contain unsupported characters")
        return self


class TaskObservationReferenceV1(FrozenModel):
    """A fixture-only pointer; it never verifies the user's reported task."""

    schema_version: Literal[1] = 1
    case_id: CaseId
    evidence_id: EvidenceId
    source_id: str = Field(pattern=r"^src_[0-9a-f]{64}$")
    collector_id: str = Field(min_length=1, max_length=120)
    collector_version: int = Field(ge=1)
    execution_id: ExecutionId
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    fact_paths: TaskObservationFactPathsV1
    scope: Literal["synthetic_fixture"] = "synthetic_fixture"


class TaskObservationContextV1(FrozenModel):
    """A complete source-bound synthetic task packet for advisory search."""

    schema_version: Literal[1] = 1
    case_id: CaseId
    evidence_id: EvidenceId
    source_id: str = Field(pattern=r"^src_[0-9a-f]{64}$")
    collector_id: str = Field(min_length=1, max_length=120)
    collector_version: int = Field(ge=1)
    execution_id: ExecutionId
    record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    target_handle: str = Field(min_length=1, max_length=120)
    action: str = Field(min_length=1, max_length=160)
    expected: str = Field(min_length=1, max_length=120)
    observed: str = Field(min_length=1, max_length=120)
    window_start: UtcDateTime
    window_end: UtcDateTime
    sample_window_ms: int = Field(ge=1, le=600_000)
    observed_at: UtcDateTime
    captured_at: UtcDateTime
    limitation: str = Field(min_length=1, max_length=160)
    scope: Literal["synthetic_fixture"] = "synthetic_fixture"

    @model_validator(mode="after")
    def validate_window(self) -> TaskObservationContextV1:
        if not self.window_start <= self.window_end <= self.observed_at <= self.captured_at:
            raise ValueError("task observation times are inconsistent")
        if (
            self.window_end - self.window_start != timedelta(milliseconds=self.sample_window_ms)
            or self.window_end != self.observed_at
        ):
            raise ValueError("task observation duration conflicts with exact source times")
        return self

    def model_visible(self) -> dict[str, str | int]:
        """Keep source custody and limits, omitting the private content hash."""

        return {
            "kind": "synthetic_task_observation_v1",
            "case_id": str(self.case_id),
            "evidence_id": str(self.evidence_id),
            "source_id": self.source_id,
            "collector_id": self.collector_id,
            "collector_version": self.collector_version,
            "execution_id": str(self.execution_id),
            "target_handle": self.target_handle,
            "action": self.action,
            "expected": self.expected,
            "observed": self.observed,
            "window_start": self.window_start.isoformat(),
            "window_end": self.window_end.isoformat(),
            "sample_window_ms": self.sample_window_ms,
            "observed_at": self.observed_at.isoformat(),
            "captured_at": self.captured_at.isoformat(),
            "time_quality": "exact",
            "status": "observed",
            "scope": self.scope,
            "limitation": self.limitation,
        }
