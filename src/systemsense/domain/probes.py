"""Declarative contracts for trusted diagnostic probes."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Literal

from pydantic import Field, model_validator

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import JsonValue
from systemsense.domain.time import UtcDateTime


class SafetyClass(StrEnum):
    R0 = "R0"
    R1 = "R1"
    R2 = "R2"
    R3 = "R3"


class Privilege(StrEnum):
    STANDARD = "standard"
    ELEVATED = "elevated"


class SelfWrite(StrEnum):
    AUDIT_RECORD = "audit_record"
    EVIDENCE_RECORD = "evidence_record"
    ARTIFACT_RECORD = "artifact_record"
    TEMP_ARTIFACT = "temp_artifact"


class ProbeSafety(FrozenModel):
    safety_class: SafetyClass
    privilege: Privilege
    target_state_effect: Literal["none"]
    outbound_network: Literal[False] = False
    self_writes: tuple[SelfWrite, ...] = ()


class ProbeLimits(FrozenModel):
    timeout_ms: int = Field(ge=1, le=120_000)
    max_output_bytes: int = Field(ge=1, le=10_485_760)
    max_records: int = Field(ge=1, le=100_000)


class ProbeManifest(FrozenModel):
    schema_version: Literal[1] = 1
    probe_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$")
    version: int = Field(ge=1)
    implementation_id: str = Field(pattern=r"^builtin\.[a-z][a-z0-9_.-]*$")
    question: str = Field(min_length=1, max_length=1000)
    safety: ProbeSafety
    input_model: str = Field(pattern=r"^[A-Z][A-Za-z0-9]*V[0-9]+$")
    limits: ProbeLimits
    category: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$")


class MeasurementWindow(FrozenModel):
    start: UtcDateTime
    end: UtcDateTime

    @model_validator(mode="after")
    def bounded_window(self) -> MeasurementWindow:
        if self.end <= self.start:
            raise ValueError("measurement window end must follow start")
        if (self.end - self.start).total_seconds() > 86_400:
            raise ValueError("measurement window cannot exceed one day")
        return self


class MeasurementNeed(FrozenModel):
    """Desired observable, without authority to choose an executable operation."""

    capability_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$", max_length=120)
    observable: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$", max_length=120)
    target_handle: str | None = Field(default=None, min_length=1, max_length=120)
    window: MeasurementWindow | None = None


class ProbeInvocation(FrozenModel):
    """Registered local resolution of one read-only measurement need."""

    probe_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$", max_length=120)
    probe_version: int = Field(ge=1)
    observable: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$", max_length=120)
    target_handle: str | None = Field(default=None, min_length=1, max_length=120)
    parameters: dict[str, JsonValue]
    window: MeasurementWindow | None = None

    @property
    def dedupe_key(self) -> str:
        canonical = json.dumps(
            self.model_dump(mode="json"),
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        return f"probe-invocation:{hashlib.sha256(canonical).hexdigest()}"
