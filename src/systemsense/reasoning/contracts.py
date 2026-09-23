"""Bounded reasoning requests, hypothesis ledgers, and advisory proposals."""

from __future__ import annotations

from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field, StrictBool, field_validator, model_validator

from systemsense.decision.contracts import (
    DecisionRequest,
    DecisionResponse,
    FastSignalKind,
    ProbeCapability,
    ProbeProposal,
    ProviderIdentity,
    ResponseValidationError,
)
from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import CaseId, EvidenceId, JsonValue
from systemsense.domain.time import UtcDateTime
from systemsense.evidence.graph import EvidenceRelation
from systemsense.inference.context import EvidenceContext
from systemsense.knowledge.windows_errors import WindowsErrorReference


class HypothesisStatus(StrEnum):
    SUPPORTED = "supported"
    CONTESTED = "contested"
    UNRESOLVED = "unresolved"


class ReasoningStatus(StrEnum):
    SUPPORTED = "supported"
    UNRESOLVED = "unresolved"
    INSUFFICIENT_OBSERVABILITY = "insufficient_observability"
    UNAVAILABLE = "unavailable"


class ExpectedFact(FrozenModel):
    """A testable categorical prediction, not an observed measurement.

    Free-form strings are excluded so model-echoed user content cannot become
    durable prediction state. Numeric and boolean values still require redaction
    review at the application boundary.
    """

    probe_id: str = Field(min_length=1, max_length=120, pattern=r"^[a-z][a-z0-9_.-]*$")
    fact_name: str = Field(min_length=1, max_length=120, pattern=r"^[a-z][a-z0-9_.-]*$")
    expected_value: (
        StrictBool
        | Annotated[int, Field(strict=True, ge=0, le=255)]
        | Annotated[
            str,
            Field(
                max_length=12,
                pattern=(
                    r"^(enabled|disabled|running|stopped|failed|available|unavailable|"
                    r"connected|disconnected|online|offline|ok|error)$"
                ),
            ),
        ]
    )


class Hypothesis(FrozenModel):
    hypothesis_id: str = Field(min_length=1, max_length=100, pattern=r"^[a-z][a-z0-9_.-]*$")
    statement: str = Field(min_length=1, max_length=1200)
    status: HypothesisStatus
    supporting_evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=64)
    contradicting_evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=64)
    missing_evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=64)
    distinguishing_probe_ids: tuple[str, ...] = Field(default=(), max_length=16)
    expected_facts: tuple[ExpectedFact, ...] = Field(default=(), max_length=4)
    # Set by the deterministic coordinator when the prediction is accepted.
    expected_facts_observed_after: UtcDateTime | None = None

    @model_validator(mode="after")
    def unique_expected_facts(self) -> Hypothesis:
        keys = [(item.probe_id, item.fact_name) for item in self.expected_facts]
        if len(keys) != len(set(keys)):
            raise ValueError("expected facts must not repeat a probe/fact pair")
        return self


class EvidenceDetailRequest(FrozenModel):
    """A bounded literal search inside one already admitted local observation."""

    evidence_id: EvidenceId
    match_literals: tuple[Annotated[str, Field(min_length=1, max_length=80)], ...] = Field(
        min_length=1, max_length=3
    )

    @field_validator("match_literals")
    @classmethod
    def validate_literals(cls, values: tuple[str, ...]) -> tuple[str, ...]:
        if any(
            not value.strip() or len(value) > 80 or any(ord(c) < 32 for c in value)
            for value in values
        ):
            raise ValueError("detail literals must be 1 to 80 printable characters")
        return tuple(dict.fromkeys(value.strip() for value in values))

    def key(self) -> str:
        import hashlib
        import json

        content = (str(self.evidence_id), sorted(value.casefold() for value in self.match_literals))
        return hashlib.sha256(json.dumps(content).encode()).hexdigest()


class FastAttentionConcern(FrozenModel):
    """What the fast brain wants checked, not a verified contradiction or cause."""

    kind: FastSignalKind
    evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=8)
    hypothesis_brief: str | None = Field(default=None, min_length=1, max_length=400)

    @model_validator(mode="after")
    def contradiction_has_references(self) -> FastAttentionConcern:
        if self.kind is FastSignalKind.CONTRADICTION_SUSPECTED and (
            not self.evidence_ids or self.hypothesis_brief is None
        ):
            raise ValueError("suspected contradiction needs evidence and hypothesis brief")
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("fast concern repeats evidence")
        return self


class ReasoningRequest(FrozenModel):
    schema_version: Literal[1, 2, 3] = 2
    case_id: CaseId
    state_version: int = Field(ge=0)
    correlation_id: str = Field(min_length=1, max_length=120)
    deadline_at: UtcDateTime
    objective: str = Field(min_length=1, max_length=2000)
    observer_context: tuple[str, ...] = Field(default=(), max_length=4)
    fast_concerns: tuple[FastAttentionConcern, ...] = Field(default=(), max_length=8)
    evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=256)
    evidence_context: tuple[EvidenceContext, ...] = Field(default=(), max_length=64)
    relationships: tuple[EvidenceRelation, ...] = Field(default=(), max_length=64)
    previous_hypotheses: tuple[Hypothesis, ...] = Field(default=(), max_length=16)
    available_probes: tuple[ProbeCapability, ...] = Field(min_length=1, max_length=128)
    completed_probe_ids: frozenset[str] = frozenset()
    satisfied_probe_ids: frozenset[str] = frozenset()
    pending_probe_ids: tuple[str, ...] = Field(default=(), max_length=32)
    reference_context: tuple[dict[str, JsonValue], ...] = Field(default=(), max_length=32)
    error_references: tuple[WindowsErrorReference, ...] = Field(default=(), max_length=4)
    evidence_catalog: tuple[dict[str, JsonValue], ...] = Field(default=(), max_length=64)
    catalog_has_more: bool = False
    priority_evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=64)
    completed_evidence_requests: tuple[EvidenceId, ...] = Field(default=(), max_length=64)
    completed_detail_requests: tuple[EvidenceDetailRequest, ...] = Field(default=(), max_length=32)
    budget_ms: int = Field(gt=0, le=600_000)
    max_probes: int = Field(gt=0, le=128)

    @model_validator(mode="after")
    def validate_references(self) -> ReasoningRequest:
        known_evidence = set(self.evidence_ids)
        context_ids = [context.evidence_id for context in self.evidence_context]
        if len(context_ids) != len(set(context_ids)):
            raise ValueError("evidence context must have unique IDs")
        if not set(context_ids).issubset(known_evidence):
            raise ValueError("evidence context references unknown evidence")
        if self.fast_concerns and self.schema_version == 1:
            raise ValueError("fast concerns require reasoning request version 2")
        if self.catalog_has_more and self.schema_version != 3:
            raise ValueError("catalog pagination requires reasoning request version 3")
        for concern in self.fast_concerns:
            if not set(concern.evidence_ids).issubset(known_evidence):
                raise ValueError("fast concern references unknown evidence")
            if not set(concern.evidence_ids).issubset(set(context_ids)):
                raise ValueError("fast concern evidence is absent from focused packet")
        for label, evidence_ids in (
            ("priority evidence IDs", self.priority_evidence_ids),
            ("completed evidence requests", self.completed_evidence_requests),
        ):
            if len(evidence_ids) != len({str(item) for item in evidence_ids}):
                raise ValueError(f"{label} must be unique")
            if not set(evidence_ids).issubset(known_evidence):
                raise ValueError(f"{label} must reference known evidence")
        relation_keys = [
            (relation.relation_id, relation.relation_version) for relation in self.relationships
        ]
        if len(relation_keys) != len(set(relation_keys)):
            raise ValueError("relationships must have unique identity and version")
        for relation in self.relationships:
            if not relation.evidence_ids:
                raise ValueError("relationship must be grounded by request evidence")
            if not set(relation.evidence_ids).issubset(known_evidence):
                raise ValueError("relationship references unknown evidence")
        known_probes = {probe.probe_id for probe in self.available_probes}
        if not self.completed_probe_ids.issubset(known_probes):
            raise ValueError("completed probe IDs must reference available probes")
        if not self.satisfied_probe_ids.issubset(self.completed_probe_ids):
            raise ValueError("satisfied probes must be completed")
        if not set(self.pending_probe_ids).issubset(known_probes):
            raise ValueError("pending probe IDs must reference available probes")
        if len(set(self.pending_probe_ids)) != len(self.pending_probe_ids):
            raise ValueError("pending probe IDs must be unique")
        hypothesis_ids = [hypothesis.hypothesis_id for hypothesis in self.previous_hypotheses]
        if len(hypothesis_ids) != len(set(hypothesis_ids)):
            raise ValueError("previous hypotheses must have unique IDs")
        for hypothesis in self.previous_hypotheses:
            references = (
                *hypothesis.supporting_evidence_ids,
                *hypothesis.contradicting_evidence_ids,
                *hypothesis.missing_evidence_ids,
            )
            if any(evidence_id not in known_evidence for evidence_id in references):
                raise ValueError("previous hypothesis references unknown evidence")
            if any(
                probe_id not in known_probes for probe_id in hypothesis.distinguishing_probe_ids
            ):
                raise ValueError("previous hypothesis references unknown probe")
        return self


class ReasoningValidationError(ResponseValidationError):
    """A reasoning response references invalid or unsafe case state."""


class ReasoningResponse(FrozenModel):
    schema_version: Literal[1, 2, 3] = 1
    provider: ProviderIdentity
    case_id: CaseId
    state_version: int = Field(ge=0)
    correlation_id: str = Field(min_length=1, max_length=120)
    deadline_at: UtcDateTime
    status: ReasoningStatus
    summary: str = Field(min_length=1, max_length=2000)
    hypotheses: tuple[Hypothesis, ...] = Field(default=(), max_length=16)
    distinguishing_probes: tuple[ProbeProposal, ...] = Field(default=(), max_length=32)
    cancelled_probe_ids: tuple[str, ...] = Field(default=(), max_length=32)
    request_next_catalog_page: bool = False
    catalog_page_truncated: bool = False
    degraded: bool = False
    requested_evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=8)
    requested_details: tuple[EvidenceDetailRequest, ...] = Field(default=(), max_length=4)
    considered_evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=64)
    context_notes: tuple[str, ...] = Field(default=(), max_length=8)

    def validate_against(self, request: ReasoningRequest) -> ReasoningResponse:
        if self.provider.role != "reasoning":
            raise ReasoningValidationError("provider role does not match reasoning response")
        if self.case_id != request.case_id:
            raise ReasoningValidationError("case_id does not match request")
        if self.state_version != request.state_version:
            raise ReasoningValidationError("state_version is stale")
        if self.correlation_id != request.correlation_id:
            raise ReasoningValidationError("correlation_id does not match request")
        if self.deadline_at != request.deadline_at:
            raise ReasoningValidationError("deadline_at does not match request")
        if self.cancelled_probe_ids:
            if self.schema_version == 1:
                raise ReasoningValidationError("probe cancellation requires response schema v2")
            if len(set(self.cancelled_probe_ids)) != len(self.cancelled_probe_ids):
                raise ReasoningValidationError("cancelled probe IDs must be unique")
            if not set(self.cancelled_probe_ids).issubset(request.pending_probe_ids):
                raise ReasoningValidationError("cancelled probe was not pending")
            if set(self.cancelled_probe_ids).intersection(
                proposal.probe_id for proposal in self.distinguishing_probes
            ):
                raise ReasoningValidationError("probe cannot be cancelled and proposed")
        if self.request_next_catalog_page:
            if self.schema_version != 3 or not request.catalog_has_more:
                raise ReasoningValidationError("next catalog page is unavailable")
            if self.degraded:
                raise ReasoningValidationError("degraded reasoning cannot request a catalog page")
            if self.catalog_page_truncated:
                raise ReasoningValidationError("truncated catalog page cannot be advanced")
        if self.catalog_page_truncated and self.schema_version != 3:
            raise ReasoningValidationError("catalog truncation requires response schema v3")
        if self.status is ReasoningStatus.SUPPORTED and not self.hypotheses:
            raise ReasoningValidationError("supported response requires a hypothesis")
        if self.status is ReasoningStatus.SUPPORTED and not any(
            hypothesis.status is HypothesisStatus.SUPPORTED for hypothesis in self.hypotheses
        ):
            raise ReasoningValidationError("supported response requires a supported hypothesis")

        known_evidence = set(request.evidence_ids)
        if not set(self.considered_evidence_ids).issubset(known_evidence):
            raise ReasoningValidationError("considered context references unknown evidence")
        if request.schema_version == 3 and not set(self.considered_evidence_ids).issubset(
            item.evidence_id for item in request.evidence_context
        ):
            raise ReasoningValidationError("catalog-only evidence was not considered as facts")
        if not set(self.requested_evidence_ids).issubset(known_evidence):
            raise ReasoningValidationError("requested detail references unknown evidence")
        if any(item.evidence_id not in known_evidence for item in self.requested_details):
            raise ReasoningValidationError("detail search references unknown evidence")
        citation_evidence = (
            set(item.evidence_id for item in request.evidence_context)
            if request.evidence_catalog or request.schema_version == 3
            else known_evidence
        )
        known_probes = {probe.probe_id: probe for probe in request.available_probes}
        for hypothesis in self.hypotheses:
            if hypothesis.expected_facts_observed_after is not None:
                raise ReasoningValidationError(
                    "expected fact observation boundary is coordinator-owned"
                )
            support = set(hypothesis.supporting_evidence_ids)
            contradiction = set(hypothesis.contradicting_evidence_ids)
            if not support.isdisjoint(contradiction):
                raise ReasoningValidationError(
                    "the same evidence cannot support and contradict a hypothesis"
                )
            if hypothesis.status is HypothesisStatus.SUPPORTED:
                if not support:
                    raise ReasoningValidationError(
                        "supported hypothesis requires supporting evidence"
                    )
                if contradiction:
                    raise ReasoningValidationError(
                        "supported hypothesis cannot have contradicting evidence"
                    )
            for evidence_id in (
                *hypothesis.supporting_evidence_ids,
                *hypothesis.contradicting_evidence_ids,
                *hypothesis.missing_evidence_ids,
            ):
                if evidence_id not in citation_evidence:
                    raise ReasoningValidationError("hypothesis references unknown evidence")
            for probe_id in hypothesis.distinguishing_probe_ids:
                if probe_id not in known_probes:
                    raise ReasoningValidationError("hypothesis references unknown probe")
            for expected in hypothesis.expected_facts:
                if expected.probe_id not in known_probes:
                    raise ReasoningValidationError("expected fact references unknown probe")

        decision_request = DecisionRequest(
            schema_version=2,
            case_id=request.case_id,
            state_version=request.state_version,
            correlation_id=request.correlation_id,
            deadline_at=request.deadline_at,
            symptom=request.objective,
            evidence_ids=request.evidence_ids,
            evidence_context=request.evidence_context,
            relationships=request.relationships,
            fresh_probe_ids=frozenset(),
            completed_probe_ids=request.completed_probe_ids,
            satisfied_probe_ids=request.satisfied_probe_ids,
            available_probes=request.available_probes,
            budget_ms=request.budget_ms,
            max_probes=request.max_probes,
        )
        decision = DecisionResponse(
            provider=ProviderIdentity(
                provider_id="reasoning-proposal-validator",
                provider_version="1",
                role="fast_decision",
            ),
            case_id=self.case_id,
            state_version=self.state_version,
            correlation_id=self.correlation_id,
            deadline_at=self.deadline_at,
            proposals=self.distinguishing_probes,
            degraded=self.degraded,
        )
        try:
            decision.validate_against(decision_request)
        except ResponseValidationError as error:
            raise ReasoningValidationError(str(error)) from error
        return self
