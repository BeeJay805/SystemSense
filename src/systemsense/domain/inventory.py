"""Timestamped current-state inventory contracts."""

from datetime import datetime, timedelta
from typing import Literal

from pydantic import Field, model_validator

from systemsense.domain.evidence import (
    CollectorReference,
    EvidenceSource,
    Extraction,
    FrozenModel,
    Sensitivity,
)
from systemsense.domain.ids import EntityId, JsonValue
from systemsense.domain.time import UtcDateTime, ensure_utc


class InventoryFact(FrozenModel):
    schema_version: Literal[1] = 1
    entity_id: EntityId
    category: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_.-]*$")
    name: str = Field(min_length=1, pattern=r"^[a-z][a-z0-9_.-]*$")
    value: JsonValue
    source: EvidenceSource
    collector: CollectorReference
    observed_at: UtcDateTime
    captured_at: UtcDateTime
    extraction: Extraction
    freshness_ttl_seconds: int = Field(gt=0)
    invalidated_at: UtcDateTime | None = None
    sensitivity: Sensitivity
    limitations: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_invalidation(self) -> "InventoryFact":
        if self.invalidated_at is not None and self.invalidated_at < self.observed_at:
            raise ValueError("invalidation cannot precede observation")
        return self

    def is_stale(self, at: datetime) -> bool:
        checked_at = ensure_utc(at)
        if self.invalidated_at is not None and checked_at >= self.invalidated_at:
            return True
        fresh_until = self.observed_at + timedelta(seconds=self.freshness_ttl_seconds)
        return checked_at > fresh_until
