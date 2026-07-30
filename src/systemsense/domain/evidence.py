"""Normalized evidence contracts with provenance and no diagnostic claims."""

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId, JsonValue
from systemsense.domain.time import UtcDateTime


class FrozenModel(BaseModel):
    """Strict immutable base for persisted domain records."""

    model_config = ConfigDict(extra="forbid", frozen=True)


class StatementKind(StrEnum):
    OBSERVED_FACT = "observed_fact"
    CHANGE = "change"
    CORRELATION = "correlation"
    CONTRADICTION = "contradiction"
    MISSING = "missing"
    UNAVAILABLE = "unavailable"


class Sensitivity(StrEnum):
    PUBLIC = "public"
    SYSTEM_METADATA = "system_metadata"
    PERSONAL = "personal"
    SENSITIVE = "sensitive"


class EvidenceSource(FrozenModel):
    type: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_.-]*$")
    source_id: str = Field(pattern=r"^src_[0-9a-f]{64}$")
    locator: dict[str, JsonValue]


class CollectorReference(FrozenModel):
    id: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_.-]*$")
    version: int = Field(ge=1)
    execution_id: ExecutionId


class EvidenceFact(FrozenModel):
    name: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_.-]*$")
    value: JsonValue
    unit: str | None = None


class Extraction(FrozenModel):
    confidence: float = Field(ge=0.0, le=1.0)
    parser: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_.-]*$")
    parser_version: int = Field(ge=1)


class EvidenceRecord(FrozenModel):
    schema_version: Literal[1] = 1
    evidence_id: EvidenceId
    case_id: CaseId
    statement_kind: StatementKind
    observed_at: UtcDateTime
    captured_at: UtcDateTime
    source: EvidenceSource
    collector: CollectorReference
    summary: str = Field(min_length=1, max_length=1000)
    facts: tuple[EvidenceFact, ...] = ()
    extraction: Extraction
    limitations: tuple[str, ...] = ()
    sensitivity: Sensitivity
