"""Versioned measured-investigation artifacts without fabricated quality claims."""

from __future__ import annotations

import hashlib
import json
import math
from enum import StrEnum
from typing import Literal

from pydantic import Field, field_validator, model_validator

from systemsense.application.investigation_state import (
    InvestigationOutcome,
    InvestigationStatus,
)
from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import CaseId
from systemsense.domain.time import UtcDateTime
from systemsense.orchestration.probes import ProbeRunStatus


class MeasurementSource(StrEnum):
    SIMULATION = "simulation"
    LIVE = "live"


class EvaluationMode(StrEnum):
    KEYWORD_BASELINE_DETERMINISTIC = "keyword_baseline_deterministic"
    CONFIGURED_PROVIDERS = "configured_providers"


class QualityLabel(StrEnum):
    UNKNOWN = "unknown"
    PASS = "pass"
    FAIL = "fail"
    INCONCLUSIVE = "inconclusive"


class EpisodeSpec(FrozenModel):
    schema_version: Literal[1] = 1
    scenario_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$")
    objective: str = Field(min_length=1, max_length=2000)
    measurement_source: MeasurementSource
    synthetic: bool
    mode: EvaluationMode
    budget_ms: int = Field(ge=100, le=600_000)
    max_rounds: int = Field(ge=1, le=12)
    max_probes: int = Field(ge=1, le=64)

    @model_validator(mode="after")
    def simulation_is_explicit(self) -> EpisodeSpec:
        if self.measurement_source is MeasurementSource.SIMULATION and not self.synthetic:
            raise ValueError("simulation measurements must be labeled synthetic")
        return self


class FailureCount(FrozenModel):
    failures: int = Field(ge=0)
    total: int = Field(ge=0)

    @model_validator(mode="after")
    def failures_fit_denominator(self) -> FailureCount:
        if self.failures > self.total:
            raise ValueError("failures cannot exceed the denominator")
        return self


class ProviderMeasurement(FrozenModel):
    role: Literal["decision", "reasoning", "catalog_attention"]
    provider_id: str = Field(min_length=1, max_length=80)
    effective_provider_id: str | None = Field(default=None, min_length=1, max_length=80)
    model_id: str | None = Field(default=None, min_length=1, max_length=120)
    calls: int = Field(ge=0)
    failures: int = Field(ge=0)

    @model_validator(mode="after")
    def failures_fit_calls(self) -> ProviderMeasurement:
        if self.failures > self.calls:
            raise ValueError("provider failures cannot exceed calls")
        return self


class EpisodeReview(FrozenModel):
    quality_label: QualityLabel = QualityLabel.UNKNOWN
    reviewer: str | None = Field(default=None, min_length=1, max_length=120)
    notes: str | None = Field(default=None, max_length=1000)

    @model_validator(mode="after")
    def reviewed_labels_are_explicit(self) -> EpisodeReview:
        if self.quality_label is QualityLabel.UNKNOWN and self.reviewer is not None:
            raise ValueError("unknown quality must not name a reviewer")
        if self.quality_label is not QualityLabel.UNKNOWN and self.reviewer is None:
            raise ValueError("a reviewed quality label requires a reviewer")
        return self


class EpisodeArtifact(FrozenModel):
    schema_version: Literal[1, 2] = 1
    scenario_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$")
    measurement_source: MeasurementSource
    synthetic: bool
    mode: EvaluationMode
    case_id: CaseId
    objective: str = Field(min_length=1, max_length=2000)
    budget_ms: int = Field(ge=100, le=600_000)
    max_rounds: int = Field(ge=1, le=12)
    max_probes: int = Field(ge=1, le=64)
    started_at: UtcDateTime
    finished_at: UtcDateTime
    elapsed_ms: float = Field(ge=0)
    attempted_probe_ids: tuple[str, ...] = Field(default=(), max_length=128)
    skipped_probe_ids: tuple[str, ...] = Field(default=(), max_length=128)
    probe_attempts: FailureCount
    probe_status_counts: dict[ProbeRunStatus, int] = Field(max_length=7)
    evidence_count: int = Field(ge=0)
    coverage_count: int = Field(ge=0)
    decision: ProviderMeasurement
    reasoning: ProviderMeasurement
    catalog_attention: ProviderMeasurement | None = Field(
        default=None, exclude_if=lambda value: value is None
    )
    terminal_status: InvestigationStatus
    terminal_outcome: InvestigationOutcome
    warnings: tuple[str, ...] = Field(default=(), max_length=64)
    review: EpisodeReview = EpisodeReview()

    @field_validator("elapsed_ms")
    @classmethod
    def finite_elapsed(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("elapsed_ms must be finite")
        return value

    @model_validator(mode="after")
    def validate_measurement(self) -> EpisodeArtifact:
        if self.catalog_attention is not None and self.schema_version < 2:
            raise ValueError("catalog attention measurement requires episode version 2")
        if (
            self.catalog_attention is not None
            and self.catalog_attention.role != "catalog_attention"
        ):
            raise ValueError("catalog attention measurement has the wrong role")
        if self.finished_at < self.started_at:
            raise ValueError("episode timestamps must be ordered")
        if any(count < 0 for count in self.probe_status_counts.values()):
            raise ValueError("probe status counts cannot be negative")
        if sum(self.probe_status_counts.values()) != self.probe_attempts.total:
            raise ValueError("probe status counts must equal the attempt denominator")
        status_failures = sum(
            count
            for status, count in self.probe_status_counts.items()
            if status is not ProbeRunStatus.OK
        )
        if status_failures != self.probe_attempts.failures:
            raise ValueError("probe status counts must equal the failure numerator")
        if len(self.skipped_probe_ids) != len(set(self.skipped_probe_ids)):
            raise ValueError("skipped probe IDs must be unique")
        if set(self.skipped_probe_ids) & set(self.attempted_probe_ids):
            raise ValueError("a probe cannot be both attempted and skipped")
        if self.measurement_source is MeasurementSource.SIMULATION and not self.synthetic:
            raise ValueError("simulation measurements must be labeled synthetic")
        return self

    def outcome_fingerprint(self) -> str:
        """Stable outcome identity excluding clocks and opaque run-generated IDs."""

        payload = {
            "schema_version": self.schema_version,
            "scenario_id": self.scenario_id,
            "measurement_source": self.measurement_source.value,
            "synthetic": self.synthetic,
            "mode": self.mode.value,
            "objective": self.objective,
            "budget_ms": self.budget_ms,
            "max_rounds": self.max_rounds,
            "max_probes": self.max_probes,
            "attempted_probe_ids": self.attempted_probe_ids,
            "skipped_probe_ids": self.skipped_probe_ids,
            "probe_attempts": self.probe_attempts.model_dump(mode="json"),
            "probe_status_counts": {
                status.value: count for status, count in self.probe_status_counts.items()
            },
            "evidence_count": self.evidence_count,
            "coverage_count": self.coverage_count,
            "decision": self.decision.model_dump(mode="json"),
            "reasoning": self.reasoning.model_dump(mode="json"),
            "terminal_status": self.terminal_status.value,
            "terminal_outcome": self.terminal_outcome.value,
            "warnings": self.warnings,
            "review": self.review.model_dump(mode="json"),
        }
        if self.catalog_attention is not None:
            payload["catalog_attention"] = self.catalog_attention.model_dump(mode="json")
        return _sha256(payload)

    def integrity_sha256(self) -> str:
        """Hash the complete serialized artifact, including measured clocks."""

        return _sha256(self.model_dump(mode="json"))


class EvaluationSuite(FrozenModel):
    schema_version: Literal[1] = 1
    episodes: tuple[EpisodeArtifact, ...] = Field(min_length=1, max_length=1000)

    def integrity_sha256(self) -> str:
        return _sha256(self.model_dump(mode="json"))


def _sha256(payload: object) -> str:
    canonical = json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()
