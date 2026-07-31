"""Typed inputs and outputs for reproducible diagnostic comparisons."""

from enum import StrEnum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class BenchmarkModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class BenchmarkFamily(StrEnum):
    CORE = "core"
    APPLICATION = "application"
    DEVICES_AUDIO = "devices_audio"
    NETWORK = "network"
    SERVICING = "servicing"
    LOCAL_AI = "local_ai"


class MeasurementSource(StrEnum):
    ENGINEERING_FIXTURE = "engineering_fixture"
    RECORDED_MODEL_RUN = "recorded_model_run"


class ArmMeasurement(BenchmarkModel):
    input_chars: int = Field(ge=0)
    input_tokens: int | None = Field(default=None, ge=1)
    elapsed_ms: int = Field(ge=0)
    tool_calls: int = Field(ge=0)
    evidence_ids: tuple[str, ...]
    diagnosis_codes: tuple[str, ...]


class BenchmarkScenario(BenchmarkModel):
    schema_version: Literal[1] = 1
    scenario_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$")
    family: BenchmarkFamily
    symptom: str = Field(min_length=1, max_length=2000)
    measurement_source: MeasurementSource
    baseline: ArmMeasurement
    systemsense: ArmMeasurement
    systemsense_overhead_ms: int = Field(ge=0)


class GroundTruth(BenchmarkModel):
    schema_version: Literal[1] = 1
    scenario_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$")
    required_evidence_ids: tuple[str, ...] = Field(min_length=1)
    accepted_diagnosis_codes: tuple[str, ...] = Field(min_length=1)


class CaseMetrics(BenchmarkModel):
    scenario_id: str
    family: BenchmarkFamily
    measurement_source: MeasurementSource
    baseline_quality: float = Field(ge=0.0, le=1.0)
    systemsense_quality: float = Field(ge=0.0, le=1.0)
    context_char_savings_pct: float
    token_savings_pct: float | None
    time_savings_pct: float
    tool_call_savings_pct: float
    systemsense_overhead_ms: int
    savings_valid: bool
    invalid_reason: str | None = None


class Distribution(BenchmarkModel):
    count: int = Field(ge=1)
    minimum: float
    median: float
    p95: float
    maximum: float
    mean: float


class AggregateMetrics(BenchmarkModel):
    case_count: int = Field(ge=1)
    valid_case_count: int = Field(ge=0)
    invalid_case_ids: tuple[str, ...]
    context_char_savings_pct: Distribution | None
    token_savings_pct: Distribution | None
    time_savings_pct: Distribution | None
    tool_call_savings_pct: Distribution | None


class BenchmarkReport(BenchmarkModel):
    schema_version: Literal[1] = 1
    measurement_sources: tuple[MeasurementSource, ...]
    cases: tuple[CaseMetrics, ...]
    aggregate: AggregateMetrics
