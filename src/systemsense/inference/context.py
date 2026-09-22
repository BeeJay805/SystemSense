"""Compact, already-redacted evidence supplied to advisory providers."""

from __future__ import annotations

import json
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field, field_validator, model_validator

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import EvidenceId, JsonValue
from systemsense.domain.time import UtcDateTime


class EvidenceContextStatus(StrEnum):
    """Collection state is evidence, including every non-success outcome."""

    OBSERVED = "observed"
    PARTIAL = "partial"
    MISSING = "missing"
    UNAVAILABLE = "unavailable"
    DENIED = "denied"
    STALE = "stale"
    TRUNCATED = "truncated"
    FAILED = "failed"
    UNSUPPORTED = "unsupported"


Limitation = Annotated[str, Field(min_length=1, max_length=240)]


class EvidenceContext(FrozenModel):
    """A bounded observation excerpt, never raw or unredacted source data."""

    evidence_id: EvidenceId
    observed_at: UtcDateTime
    captured_at: UtcDateTime
    probe_id: str = Field(min_length=1, max_length=120, pattern=r"^[a-z][a-z0-9_.-]*$")
    summary: str = Field(min_length=1, max_length=1000)
    facts: dict[str, JsonValue] = Field(default_factory=dict, max_length=32)
    status: EvidenceContextStatus
    limitations: tuple[Limitation, ...] = Field(default=(), max_length=16)
    redaction_applied: Literal[True] = True

    @field_validator("facts")
    @classmethod
    def validate_fact_names(cls, facts: dict[str, JsonValue]) -> dict[str, JsonValue]:
        for name in facts:
            if not name or len(name) > 120:
                raise ValueError("facts keys must contain 1 to 120 characters")
            if not all(character.isalnum() or character in "_.-" for character in name):
                raise ValueError("facts keys contain unsupported characters")
        if len(json.dumps(facts, separators=(",", ":")).encode("utf-8")) > 8192:
            raise ValueError("facts content exceeds 8192 bytes")
        return facts

    @model_validator(mode="after")
    def annotate_temporal_order(self) -> EvidenceContext:
        limitation = "source_clock_after_capture"
        if self.captured_at < self.observed_at and limitation not in self.limitations:
            retained = self.limitations[:15]
            object.__setattr__(self, "limitations", (*retained, limitation))
        return self
