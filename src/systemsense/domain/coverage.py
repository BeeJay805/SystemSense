"""Explicit evidence coverage states."""

from enum import StrEnum
from typing import Literal

from pydantic import Field

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId
from systemsense.domain.time import UtcDateTime


class CoverageStatus(StrEnum):
    COVERED = "covered"
    PARTIAL = "partial"
    MISSING = "missing"
    UNAVAILABLE = "unavailable"
    DENIED = "denied"
    FAILED = "failed"
    TRUNCATED = "truncated"
    STALE = "stale"
    UNSUPPORTED = "unsupported"


class CoverageRecord(FrozenModel):
    schema_version: Literal[1] = 1
    evidence_id: EvidenceId
    case_id: CaseId
    category: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_.-]*$")
    status: CoverageStatus
    captured_at: UtcDateTime
    reason: str | None = Field(default=None, max_length=1000)
    execution_id: ExecutionId | None = None
    limitations: tuple[str, ...] = ()
