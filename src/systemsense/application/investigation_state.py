"""Durable case progress, budgets, and explicit investigation outcomes."""

from enum import StrEnum
from typing import Literal

from pydantic import Field

from systemsense.application.assessment import AssessmentDecision
from systemsense.decision.contracts import ProbeProposal
from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import CaseId, EvidenceId
from systemsense.domain.time import UtcDateTime
from systemsense.evidence.retrieval import EvidenceCatalogCursor
from systemsense.inference.context import EvidenceContext
from systemsense.reasoning.contracts import EvidenceDetailRequest, Hypothesis


class InvestigationStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    AWAITING_TARGET = "awaiting_target"
    COMPLETE = "complete"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"
    FAILED = "failed"


class InvestigationOutcome(StrEnum):
    INVESTIGATING = "investigating"
    AWAITING_TARGET = "awaiting_target"
    SUPPORTED_EXPLANATION = "supported_explanation"
    INSUFFICIENT_OBSERVABILITY = "insufficient_observability"
    NO_PROGRESS = "no_progress"
    BUDGET_EXHAUSTED = "budget_exhausted"
    AWAITING_RECURRENCE = "awaiting_recurrence"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"
    FAILED = "failed"


class ProviderCall(FrozenModel):
    role: Literal["fast_decision", "reasoning"]
    provider_id: str = Field(max_length=80)
    provider_version: str = Field(max_length=40)
    state_version: int = Field(ge=0)
    started_at: UtcDateTime
    elapsed_ms: float = Field(ge=0)
    degraded: bool
    detail: str | None = Field(default=None, max_length=120)


class InvestigationState(FrozenModel):
    schema_version: Literal[1, 2, 3] = 3
    case_id: CaseId
    objective: str = Field(min_length=1, max_length=2000)
    state_version: int = Field(default=0, ge=0)
    status: InvestigationStatus = InvestigationStatus.QUEUED
    outcome: InvestigationOutcome = InvestigationOutcome.INVESTIGATING
    created_at: UtcDateTime
    updated_at: UtcDateTime
    deadline_at: UtcDateTime
    incident_start: UtcDateTime
    incident_end: UtcDateTime
    budget_ms: int = Field(ge=100, le=600_000)
    max_rounds: int = Field(default=4, ge=1, le=12)
    max_probes: int = Field(default=16, ge=1, le=64)
    round_count: int = Field(default=0, ge=0, le=120)
    run_start_round: int = Field(default=0, ge=0)
    spent_cost_ms: int = Field(default=0, ge=0)
    completed_probe_ids: tuple[str, ...] = Field(default=(), max_length=128)
    pending_probe_ids: tuple[str, ...] = Field(default=(), max_length=128)
    interrupted_probe_ids: tuple[str, ...] = Field(default=(), max_length=128)
    unrecorded_attempt_count: int = Field(default=0, ge=0, le=128)
    # Validated advisory requests belong to this case checkpoint, not to a
    # process-local variable that disappears between investigation runs.
    pending_distinguishing_probes: tuple[ProbeProposal, ...] = Field(default=(), max_length=32)
    historical_case_ids: tuple[CaseId, ...] = Field(default=(), max_length=32)
    hypotheses: tuple[Hypothesis, ...] = Field(default=(), max_length=16)
    assessment: AssessmentDecision | None = None
    summary: str = Field(default="Queued for read-only investigation.", max_length=4000)
    warnings: tuple[str, ...] = Field(default=(), max_length=64)
    evidence_fingerprint: str = ""
    stagnant_rounds: int = Field(default=0, ge=0)
    decision_provider: str = ""
    reasoning_provider: str = ""
    provider_calls: tuple[ProviderCall, ...] = Field(default=(), max_length=128)
    ranked_evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=64)
    ranked_attention_page_ids: tuple[str, ...] = Field(default=(), max_length=64)
    focused_evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=64)
    assessed_context: tuple[EvidenceContext, ...] = Field(default=(), max_length=64)
    requested_evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=8)
    completed_evidence_requests: tuple[EvidenceId, ...] = Field(default=(), max_length=128)
    requested_details: tuple[EvidenceDetailRequest, ...] = Field(default=(), max_length=4)
    completed_detail_requests: tuple[EvidenceDetailRequest, ...] = Field(default=(), max_length=32)
    evidence_catalog_cursor: EvidenceCatalogCursor | None = None
    evidence_catalog_generation: int | None = Field(default=None, ge=0)
    evidence_catalog_limit: int = Field(default=64, ge=1, le=64)
    evidence_catalog_followup_pending: bool = False
    attention_notes: tuple[str, ...] = Field(default=(), max_length=16)
    considered_evidence_count: int = Field(default=0, ge=0, le=64)
    stop_reason: str | None = Field(default=None, max_length=1000)


class InvestigationStep(FrozenModel):
    case_id: CaseId
    state_version: int = Field(ge=0)
    occurred_at: UtcDateTime
    event: str = Field(min_length=1, max_length=80)
    detail: str = Field(max_length=4000)
    hypotheses: tuple[Hypothesis, ...] = ()
    probe_ids: tuple[str, ...] = ()
