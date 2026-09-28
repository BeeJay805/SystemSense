"""Bounded reasoning requests, hypothesis ledgers, and advisory proposals."""

from __future__ import annotations

import hashlib
import json
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
from systemsense.domain.affected_task import (
    ReportedAffectedTaskV1,
    SourceTaskRelationV1,
    TaskObservationContextV1,
)
from systemsense.domain.diagnostic_progress import DiagnosticProgressContextV1
from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import CaseId, EvidenceId, JsonValue
from systemsense.domain.time import UtcDateTime
from systemsense.evidence.graph import EvidenceRelation
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
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
    # Added only by the coordinator after accepting a version-6 prediction.
    probe_version: int | None = Field(default=None, ge=1, exclude_if=lambda value: value is None)


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


def is_unavailable_observation(context: EvidenceContext) -> bool:
    """Recognize an exact projected absence, never infer absence from prose."""
    if set(context.facts) - {"collection_status"}:
        return False
    if context.status in {
        EvidenceContextStatus.MISSING,
        EvidenceContextStatus.UNAVAILABLE,
        EvidenceContextStatus.DENIED,
        EvidenceContextStatus.FAILED,
        EvidenceContextStatus.UNSUPPORTED,
    }:
        return True
    status = context.facts.get("collection_status")
    return (
        set(context.facts) == {"collection_status"}
        and isinstance(status, str)
        and status
        in {"unsupported", "permission_denied", "denied", "failed", "unavailable", "missing"}
    )


class NoncausalObservationReviewV1(FrozenModel):
    """Advisory account of an observation's limit for the affected outcome."""

    schema_version: Literal[1] = 1
    evidence_id: EvidenceId
    disposition: Literal["unavailable", "target_unbound", "time_unbound", "unrelated"]
    explanation: str = Field(min_length=12, max_length=240)

    @field_validator("explanation")
    @classmethod
    def meaningful_explanation(cls, value: str) -> str:
        stripped = value.strip()
        if len(stripped) < 12 or any(ord(character) < 32 for character in stripped):
            raise ValueError("noncausal review needs a bounded printable explanation")
        return stripped


def hypothesis_revision_sha256(hypothesis: Hypothesis) -> str:
    """Bind one complete prior advisory row, including its prediction boundary."""
    payload = json.dumps(
        hypothesis.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class PriorHypothesisRevisionRefV1(FrozenModel):
    schema_version: Literal[1] = 1
    hypothesis_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$", max_length=100)
    hypothesis_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class HypothesisRevisionIntentV1(FrozenModel):
    schema_version: Literal[1] = 1
    hypothesis_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$", max_length=100)
    prior_hypothesis_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    retired_supporting_evidence_ids: tuple[EvidenceId, ...] = Field(min_length=1, max_length=64)

    @field_validator("retired_supporting_evidence_ids")
    @classmethod
    def unique_retirements(cls, ids: tuple[EvidenceId, ...]) -> tuple[EvidenceId, ...]:
        if len(ids) != len(set(ids)):
            raise ValueError("retired support IDs must be unique")
        return ids


class HypothesisRevisionLinkV1(FrozenModel):
    schema_version: Literal[1] = 1
    hypothesis_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$", max_length=100)
    prior_hypothesis_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    revised_hypothesis_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    retired_supporting_evidence_ids: tuple[EvidenceId, ...] = Field(min_length=1, max_length=64)
    source_request_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


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


class SelectedSourceContextV1(FrozenModel):
    """Receipt-backed focus, with fixture coverage kept separate from causality."""

    schema_version: Literal[1] = 1
    item_id: str = Field(pattern=r"^fr_v1_[0-9a-f]{64}$")
    evidence_id: EvidenceId
    source_record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    source_task_relation: SourceTaskRelationV1 | None = None


class ReasoningRequest(FrozenModel):
    schema_version: Literal[1, 2, 3, 4, 5, 6, 7] = 2
    case_id: CaseId
    state_version: int = Field(ge=0)
    correlation_id: str = Field(min_length=1, max_length=120)
    deadline_at: UtcDateTime
    objective: str = Field(min_length=1, max_length=2000)
    reported_task: ReportedAffectedTaskV1 | None = None
    task_observation: TaskObservationContextV1 | None = None
    selected_sources: tuple[SelectedSourceContextV1, ...] = Field(default=(), max_length=8)
    observer_context: tuple[str, ...] = Field(default=(), max_length=4)
    fast_concerns: tuple[FastAttentionConcern, ...] = Field(default=(), max_length=8)
    diagnostic_progress: tuple[DiagnosticProgressContextV1, ...] = Field(default=(), max_length=8)
    evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=256)
    evidence_context: tuple[EvidenceContext, ...] = Field(default=(), max_length=64)
    relationships: tuple[EvidenceRelation, ...] = Field(default=(), max_length=64)
    previous_hypotheses: tuple[Hypothesis, ...] = Field(default=(), max_length=16)
    prior_hypothesis_revision_refs: tuple[PriorHypothesisRevisionRefV1, ...] = Field(
        default=(), max_length=16, exclude_if=lambda value: not value
    )
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
        if self.schema_version >= 6:
            outputs = tuple(
                output for probe in self.available_probes for output in probe.prediction_outputs
            )
            if len(outputs) > 16 or sum(len(item.allowed_values) for item in outputs) > 64:
                raise ValueError("prediction output contracts exceed bounded request limits")
        if self.reported_task is not None and self.schema_version < 4:
            raise ValueError("reported affected task requires reasoning request version 4")
        if (self.task_observation is not None or self.selected_sources) and self.schema_version < 5:
            raise ValueError("task observation and selected sources require request version 5")
        if self.selected_sources and self.task_observation is None:
            raise ValueError("selected sources require the bound task observation")
        known_evidence = set(self.evidence_ids)
        context_ids = [context.evidence_id for context in self.evidence_context]
        focused_current = {
            str(item.evidence_id)
            for item in self.evidence_context
            if item.case_scope == "current_case"
        }
        if self.task_observation is not None and (
            self.task_observation.case_id != self.case_id
            or str(self.task_observation.evidence_id) not in focused_current
        ):
            raise ValueError("task observation must be focused current-case evidence")
        selected_ids = [str(item.evidence_id) for item in self.selected_sources]
        if len(selected_ids) != len(set(selected_ids)):
            raise ValueError("selected sources must have unique evidence IDs")
        for item in self.selected_sources:
            if str(item.evidence_id) not in focused_current:
                raise ValueError("selected source must be focused current-case evidence")
            relation = item.source_task_relation
            if relation is not None and (
                self.task_observation is None
                or relation.case_id != self.case_id
                or relation.source_evidence_id != item.evidence_id
                or relation.task_evidence_id != self.task_observation.evidence_id
                or relation.task_record_sha256 != self.task_observation.record_sha256
            ):
                raise ValueError("selected source task relation differs from bound task")
        if len(context_ids) != len(set(context_ids)):
            raise ValueError("evidence context must have unique IDs")
        if not set(context_ids).issubset(known_evidence):
            raise ValueError("evidence context references unknown evidence")
        if self.fast_concerns and self.schema_version == 1:
            raise ValueError("fast concerns require reasoning request version 2")
        if self.catalog_has_more and self.schema_version < 3:
            raise ValueError("catalog pagination requires reasoning request version 3")
        if self.diagnostic_progress:
            if self.schema_version < 4:
                raise ValueError("diagnostic progress requires request schema version 4")
            if any(item.scope.case_id != self.case_id for item in self.diagnostic_progress):
                raise ValueError("diagnostic progress must belong to request case")
            if len({item.question_id for item in self.diagnostic_progress}) != len(
                self.diagnostic_progress
            ):
                raise ValueError("diagnostic progress question IDs must be unique")
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
        if self.prior_hypothesis_revision_refs:
            expected_refs = {
                hypothesis.hypothesis_id: hypothesis_revision_sha256(hypothesis)
                for hypothesis in self.previous_hypotheses
            }
            actual_refs = {
                item.hypothesis_id: item.hypothesis_sha256
                for item in self.prior_hypothesis_revision_refs
            }
            if (
                self.schema_version < 7
                or actual_refs != expected_refs
                or len(actual_refs) != len(self.prior_hypothesis_revision_refs)
            ):
                raise ValueError("prior hypothesis revision refs differ from coordinator basis")
        elif self.schema_version >= 7 and self.previous_hypotheses:
            raise ValueError("version 7 prior hypotheses require coordinator revision refs")
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
    schema_version: Literal[1, 2, 3, 4, 5] = 1
    provider: ProviderIdentity
    case_id: CaseId
    state_version: int = Field(ge=0)
    correlation_id: str = Field(min_length=1, max_length=120)
    deadline_at: UtcDateTime
    status: ReasoningStatus
    summary: str = Field(min_length=1, max_length=2000)
    hypotheses: tuple[Hypothesis, ...] = Field(default=(), max_length=16)
    hypothesis_revision_intents: tuple[HypothesisRevisionIntentV1, ...] = Field(
        default=(), max_length=16, exclude_if=lambda value: not value
    )
    presented_prior_hypothesis_ids: tuple[str, ...] = Field(
        default=(), max_length=16, exclude_if=lambda value: not value
    )
    noncausal_observation_reviews: tuple[NoncausalObservationReviewV1, ...] = Field(
        default=(), max_length=2, exclude_if=lambda value: not value
    )
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
            if self.schema_version < 3 or not request.catalog_has_more:
                raise ReasoningValidationError("next catalog page is unavailable")
            if self.degraded:
                raise ReasoningValidationError("degraded reasoning cannot request a catalog page")
            if self.catalog_page_truncated:
                raise ReasoningValidationError("truncated catalog page cannot be advanced")
        if self.catalog_page_truncated and self.schema_version < 3:
            raise ReasoningValidationError("catalog truncation requires response schema v3")
        if self.status is ReasoningStatus.SUPPORTED and not self.hypotheses:
            raise ReasoningValidationError("supported response requires a hypothesis")
        if self.status is ReasoningStatus.SUPPORTED and not any(
            hypothesis.status is HypothesisStatus.SUPPORTED for hypothesis in self.hypotheses
        ):
            raise ReasoningValidationError("supported response requires a supported hypothesis")
        hypothesis_ids = [hypothesis.hypothesis_id for hypothesis in self.hypotheses]
        if len(hypothesis_ids) != len(set(hypothesis_ids)):
            raise ReasoningValidationError("hypotheses must have unique IDs")
        if self.hypothesis_revision_intents:
            if self.schema_version < 4 or request.schema_version < 7 or self.degraded:
                raise ReasoningValidationError(
                    "revision intents require nondegraded version 4 advice and version 7 request"
                )
        if self.noncausal_observation_reviews and (self.schema_version < 5 or self.degraded):
            raise ReasoningValidationError("noncausal reviews require nondegraded response v5")
        prior = {item.hypothesis_id: item for item in request.previous_hypotheses}
        if self.hypothesis_revision_intents or self.noncausal_observation_reviews:
            if len(self.presented_prior_hypothesis_ids) != len(
                set(self.presented_prior_hypothesis_ids)
            ) or not set(self.presented_prior_hypothesis_ids) <= set(prior):
                raise ReasoningValidationError("presented prior hypotheses are invalid")
        if self.hypothesis_revision_intents:
            refs = {
                item.hypothesis_id: item.hypothesis_sha256
                for item in request.prior_hypothesis_revision_refs
            }
            intent_ids = [item.hypothesis_id for item in self.hypothesis_revision_intents]
            if len(intent_ids) != len(set(intent_ids)):
                raise ReasoningValidationError("revision intents must have unique hypothesis IDs")
            for intent in self.hypothesis_revision_intents:
                if (
                    intent.hypothesis_id not in hypothesis_ids
                    or refs.get(intent.hypothesis_id) != intent.prior_hypothesis_sha256
                ):
                    raise ReasoningValidationError(
                        "revision intent differs from frozen prior basis"
                    )
                if intent.hypothesis_id not in self.presented_prior_hypothesis_ids:
                    raise ReasoningValidationError(
                        "revision intent prior hypothesis was not presented"
                    )
                if not set(intent.retired_supporting_evidence_ids) <= set(
                    prior[intent.hypothesis_id].supporting_evidence_ids
                ):
                    raise ReasoningValidationError("revision intent retires unknown prior support")

        if self.noncausal_observation_reviews:
            if not self.presented_prior_hypothesis_ids:
                raise ReasoningValidationError("noncausal review has no presented prior basis")
            reviewed_ids = [str(item.evidence_id) for item in self.noncausal_observation_reviews]
            if len(reviewed_ids) != len(set(reviewed_ids)):
                raise ReasoningValidationError("noncausal reviews repeat an observation")
            context = {str(item.evidence_id): item for item in request.evidence_context}
            prior_citations = {
                str(evidence_id)
                for prior_id in self.presented_prior_hypothesis_ids
                for evidence_id in (
                    *prior[prior_id].supporting_evidence_ids,
                    *prior[prior_id].contradicting_evidence_ids,
                    *prior[prior_id].missing_evidence_ids,
                )
            }
            cited_context = [context[eid] for eid in prior_citations if eid in context]
            if not cited_context:
                raise ReasoningValidationError("noncausal review has no prior focused basis")
            latest_prior_at = max(item.observed_at for item in cited_context)
            considered = {str(item) for item in self.considered_evidence_ids}
            for review in self.noncausal_observation_reviews:
                evidence_id = str(review.evidence_id)
                observation = context.get(evidence_id)
                if (
                    observation is None
                    or evidence_id not in considered
                    or evidence_id in prior_citations
                    or observation.case_scope != "current_case"
                    or observation.status is not EvidenceContextStatus.OBSERVED
                    or observation.observed_at <= latest_prior_at
                ):
                    raise ReasoningValidationError("noncausal review is not a recent focused fact")
                if review.disposition == "unavailable" and not is_unavailable_observation(
                    observation
                ):
                    raise ReasoningValidationError(
                        "noncausal review availability differs from fact"
                    )

        known_evidence = set(request.evidence_ids)
        if not set(self.considered_evidence_ids).issubset(known_evidence):
            raise ReasoningValidationError("considered context references unknown evidence")
        if request.schema_version >= 3 and not set(self.considered_evidence_ids).issubset(
            item.evidence_id for item in request.evidence_context
        ):
            raise ReasoningValidationError("catalog-only evidence was not considered as facts")
        if not set(self.requested_evidence_ids).issubset(known_evidence):
            raise ReasoningValidationError("requested detail references unknown evidence")
        if any(item.evidence_id not in known_evidence for item in self.requested_details):
            raise ReasoningValidationError("detail search references unknown evidence")
        citation_evidence = (
            set(item.evidence_id for item in request.evidence_context)
            if request.evidence_catalog or request.schema_version >= 3
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
                if expected.probe_version is not None:
                    raise ReasoningValidationError("prediction probe version is coordinator-owned")
                if expected.probe_id not in known_probes:
                    raise ReasoningValidationError("expected fact references unknown probe")
                if request.schema_version >= 6:
                    if expected.probe_id in request.completed_probe_ids:
                        raise ReasoningValidationError(
                            "expected fact has no future eligible probe execution"
                        )
                    capability = known_probes[expected.probe_id]
                    if capability.probe_version is None or not any(
                        output.name == expected.fact_name
                        and any(
                            type(value) is type(expected.expected_value)
                            and value == expected.expected_value
                            for value in output.allowed_values
                        )
                        for output in capability.prediction_outputs
                    ):
                        raise ReasoningValidationError(
                            "expected fact is outside the registered probe output contract"
                        )

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
