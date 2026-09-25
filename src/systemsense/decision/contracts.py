"""Bounded, versioned contracts for fast diagnostic decisions."""

from __future__ import annotations

import hashlib
import json
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import Field, StrictBool, StrictInt, field_validator, model_validator

from systemsense.domain.diagnostic_progress import DiagnosticProgressContextV1
from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import CaseId, EntityId, EvidenceId, JsonValue
from systemsense.domain.probes import MeasurementNeed, SafetyClass
from systemsense.domain.time import UtcDateTime
from systemsense.evidence.graph import EvidenceRelation
from systemsense.inference.context import EvidenceContext
from systemsense.orchestration.scheduler import ResourceClass


class PermissionClass(StrEnum):
    READ_ONLY = "read_only"


class DiagnosticPurpose(StrEnum):
    REFRESH_EVIDENCE = "refresh_evidence"
    DISTINGUISH_HYPOTHESES = "distinguish_hypotheses"
    CHECK_COVERAGE = "check_coverage"


class FastSignalKind(StrEnum):
    """Advisory reasons to ask the deep brain to reconsider the current branch."""

    CONTRADICTION_SUSPECTED = "contradiction_suspected"
    NO_PROGRESS_SUSPECTED = "no_progress_suspected"
    COVERAGE_GAP = "coverage_gap"


class FastSignal(FrozenModel):
    """A bounded attention signal, never a diagnosis or permission grant."""

    kind: FastSignalKind
    evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=8)
    hypothesis_index: int | None = Field(default=None, ge=0, le=15)

    @model_validator(mode="after")
    def require_contradiction_references(self) -> FastSignal:
        if self.kind is FastSignalKind.CONTRADICTION_SUSPECTED and (
            not self.evidence_ids or self.hypothesis_index is None
        ):
            raise ValueError("suspected contradiction needs evidence and a hypothesis")
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("fast signal repeats evidence")
        return self


class ProviderIdentity(FrozenModel):
    provider_id: str = Field(min_length=1, max_length=80, pattern=r"^[a-z][a-z0-9_.-]*$")
    provider_version: str = Field(min_length=1, max_length=40)
    role: Literal["fast_decision", "reasoning"]


class ProbeCapability(FrozenModel):
    """A catalog-owned read-only probe that a provider may reference."""

    probe_id: str = Field(min_length=1, max_length=120, pattern=r"^[a-z][a-z0-9_.-]*$")
    description: str = Field(min_length=1, max_length=240)
    keywords: frozenset[str] = frozenset()
    target_traits: frozenset[str] = frozenset()
    # Entities behind independently validated machine edges. This broad probe
    # may supply related coverage; it is NOT guaranteed to inspect these IDs.
    related_entity_hint_ids: tuple[EntityId, ...] = Field(default=(), max_length=64)
    # These are admitted local handles and observables, not model-authored
    # operating-system selectors. A request still needs local revalidation.
    observable_ids: tuple[
        Annotated[str, Field(min_length=1, max_length=120, pattern=r"^[a-z][a-z0-9_.-]*$")],
        ...,
    ] = Field(default=(), max_length=16)
    target_handles: tuple[
        Annotated[str, Field(min_length=1, max_length=120, pattern=r"^[a-z][a-z0-9_.:-]*$")],
        ...,
    ] = Field(default=(), max_length=64)
    supports_window: bool = False
    common: bool = False
    baseline_priority: float = Field(default=0.5, ge=0, le=1)
    cost_ms: int = Field(gt=0, le=120_000)
    resource_class: ResourceClass
    permission_class: PermissionClass = PermissionClass.READ_ONLY
    safety_class: SafetyClass = SafetyClass.R1
    target_state_effect: Literal["none"] = "none"
    outbound_network: Literal[False] = False

    @field_validator("keywords", "target_traits")
    @classmethod
    def normalize_terms(cls, values: frozenset[str]) -> frozenset[str]:
        return frozenset(value.casefold().strip() for value in values if value.strip())

    @model_validator(mode="after")
    def read_only_safety_only(self) -> ProbeCapability:
        if self.safety_class not in {SafetyClass.R0, SafetyClass.R1}:
            raise ValueError("decision capabilities must use safety class R0 or R1")
        if len({str(item) for item in self.related_entity_hint_ids}) != len(
            self.related_entity_hint_ids
        ):
            raise ValueError("related entity hint IDs must be unique")
        if len(set(self.observable_ids)) != len(self.observable_ids):
            raise ValueError("observable IDs must be unique")
        if len(set(self.target_handles)) != len(self.target_handles):
            raise ValueError("target handles must be unique")
        return self


class ProbeProposal(FrozenModel):
    """A bounded reference to a catalog probe, never an executable operation."""

    schema_version: Literal[1, 2] = 1
    probe_id: str = Field(min_length=1, max_length=120, pattern=r"^[a-z][a-z0-9_.-]*$")
    purpose: DiagnosticPurpose
    priority: float = Field(ge=0, le=1)
    estimated_cost_ms: int = Field(gt=0, le=120_000)
    resource_class: ResourceClass
    dedupe_key: str = Field(min_length=1, max_length=160, pattern=r"^[a-zA-Z0-9_.:/-]+$")
    permission_class: PermissionClass = PermissionClass.READ_ONLY
    safety_class: SafetyClass = SafetyClass.R1
    depends_on: tuple[str, ...] = Field(default=(), max_length=16)
    measurement_need: MeasurementNeed | None = None

    @model_validator(mode="after")
    def typed_need_requires_version_two(self) -> ProbeProposal:
        if self.measurement_need is not None and self.schema_version != 2:
            raise ValueError("measurement need requires proposal schema version 2")
        return self


class FastHypothesisCheck(FrozenModel):
    """A deep-brain expectation for one exact, later observed categorical fact.

    A mismatch is only a reason to revisit a hypothesis, never proof of cause.
    Approximate numeric thresholds and missing values are deliberately excluded.
    """

    hypothesis_index: int = Field(ge=0, le=15)
    probe_id: str = Field(min_length=1, max_length=120, pattern=r"^[a-z][a-z0-9_.-]*$")
    fact_name: str = Field(min_length=1, max_length=120, pattern=r"^[a-z][a-z0-9_.-]*$")
    expected_value: StrictBool | StrictInt | Annotated[str, Field(max_length=160)]
    observed_after: UtcDateTime


class DecisionRequest(FrozenModel):
    schema_version: Literal[1, 2, 3, 4] = 1
    case_id: CaseId
    state_version: int = Field(ge=0)
    correlation_id: str = Field(min_length=1, max_length=120, pattern=r"^[a-zA-Z0-9_.:-]+$")
    deadline_at: UtcDateTime
    symptom: str = Field(min_length=1, max_length=2000)
    target_traits: frozenset[str] = frozenset()
    evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=256)
    evidence_context: tuple[EvidenceContext, ...] = Field(default=(), max_length=64)
    attention_context: tuple[EvidenceContext, ...] = Field(default=(), max_length=256)
    attention_only: bool = False
    relationships: tuple[EvidenceRelation, ...] = Field(default=(), max_length=64)
    fresh_probe_ids: frozenset[str] = frozenset()
    completed_probe_ids: frozenset[str] = frozenset()
    satisfied_probe_ids: frozenset[str] = frozenset()
    retryable_probe_ids: frozenset[str] = frozenset()
    preferred_probe_ids: tuple[str, ...] = Field(default=(), max_length=32)
    hypothesis_briefs: tuple[str, ...] = Field(default=(), max_length=16)
    hypothesis_checks: tuple[FastHypothesisCheck, ...] = Field(default=(), max_length=8)
    diagnostic_progress: tuple[DiagnosticProgressContextV1, ...] = Field(default=(), max_length=8)
    # Deterministic coordinator progress, not a model-derived causal score.
    stagnant_rounds: int = Field(default=0, ge=0, le=120)
    reference_context: tuple[dict[str, JsonValue], ...] = Field(default=(), max_length=32)
    available_probes: tuple[ProbeCapability, ...] = Field(min_length=1, max_length=128)
    budget_ms: int = Field(gt=0, le=600_000)
    max_probes: int = Field(gt=0, le=128)

    @field_validator("target_traits")
    @classmethod
    def normalize_target_traits(cls, values: frozenset[str]) -> frozenset[str]:
        return frozenset(value.casefold().strip() for value in values if value.strip())

    @model_validator(mode="after")
    def unique_probe_capabilities(self) -> DecisionRequest:
        ids = [probe.probe_id for probe in self.available_probes]
        if len(ids) != len(set(ids)):
            raise ValueError("probe capabilities must have unique IDs")
        context_ids = [context.evidence_id for context in self.evidence_context]
        if not {str(item.evidence_id) for item in self.attention_context}.issubset(
            map(str, self.evidence_ids)
        ):
            raise ValueError("attention pages reference unknown evidence")
        if len(context_ids) != len(set(context_ids)):
            raise ValueError("evidence context must have unique IDs")
        if not set(context_ids).issubset(self.evidence_ids):
            raise ValueError("evidence context references unknown evidence")
        relation_keys = [
            (relation.relation_id, relation.relation_version) for relation in self.relationships
        ]
        if len(relation_keys) != len(set(relation_keys)):
            raise ValueError("relationships must have unique identity and version")
        for relation in self.relationships:
            if not relation.evidence_ids:
                raise ValueError("relationship must be grounded by request evidence")
            if not set(relation.evidence_ids).issubset(self.evidence_ids):
                raise ValueError("relationship references unknown evidence")
        if not self.completed_probe_ids.issubset(ids):
            raise ValueError("completed probe IDs must reference available probes")
        if self.satisfied_probe_ids:
            if self.schema_version < 2:
                raise ValueError("satisfied probes require request schema version 2")
            if not self.satisfied_probe_ids.issubset(self.completed_probe_ids):
                raise ValueError("satisfied probes must be completed")
        if self.retryable_probe_ids:
            if self.schema_version < 2:
                raise ValueError("retryable probes require request schema version 2")
            if not self.retryable_probe_ids.issubset(ids):
                raise ValueError("retryable probe IDs must reference available probes")
            if not self.retryable_probe_ids.isdisjoint(self.completed_probe_ids):
                raise ValueError("retryable and completed probe IDs must be disjoint")
        if not set(self.preferred_probe_ids).issubset(ids):
            raise ValueError("preferred probe IDs must reference available probes")
        if any(len(brief) > 1200 for brief in self.hypothesis_briefs):
            raise ValueError("hypothesis briefs must be bounded")
        if self.hypothesis_checks:
            if self.schema_version < 3:
                raise ValueError("hypothesis checks require request schema version 3")
            for check in self.hypothesis_checks:
                if check.hypothesis_index >= len(self.hypothesis_briefs):
                    raise ValueError("hypothesis check references unknown hypothesis")
                if check.probe_id not in ids:
                    raise ValueError("hypothesis check references unknown probe")
            if len(
                {
                    (item.hypothesis_index, item.probe_id, item.fact_name, item.observed_after)
                    for item in self.hypothesis_checks
                }
            ) != len(self.hypothesis_checks):
                raise ValueError("hypothesis checks must be unique")
        if self.stagnant_rounds and self.schema_version < 3:
            raise ValueError("stagnant rounds require request schema version 3")
        if self.diagnostic_progress:
            if self.schema_version < 4:
                raise ValueError("diagnostic progress requires request schema version 4")
            if any(item.scope.case_id != self.case_id for item in self.diagnostic_progress):
                raise ValueError("diagnostic progress must belong to request case")
            if len({item.question_id for item in self.diagnostic_progress}) != len(
                self.diagnostic_progress
            ):
                raise ValueError("diagnostic progress question IDs must be unique")
        return self


class ResponseValidationError(ValueError):
    """A provider response cannot be safely applied to a decision request."""


def presentation_payload_sha256(payload: dict[str, JsonValue]) -> str:
    """Canonical checksum of hash-only provider presentation metadata."""

    canonical = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class DecisionPresentationTrace(FrozenModel):
    """Worker-reported construction hashes, not proof of actual token tensors.

    Training admission requires a separate pinned implementation parity gate.
    """

    schema_version: Literal[1] = 1
    provider: ProviderIdentity
    format_id: str = Field(min_length=1, max_length=80, pattern=r"^[a-z][a-z0-9_.-]*$")
    payload: dict[str, JsonValue]
    payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def verify_checksum_and_bound(self) -> DecisionPresentationTrace:
        encoded = json.dumps(
            self.payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        )
        if len(encoded.encode("utf-8")) > 1_048_576:
            raise ValueError("presentation trace exceeds size bound")
        if hashlib.sha256(encoded.encode("utf-8")).hexdigest() != self.payload_sha256:
            raise ValueError("presentation trace payload digest mismatch")
        return self


class DecisionResponse(FrozenModel):
    schema_version: Literal[1, 2] = 2
    provider: ProviderIdentity
    case_id: CaseId
    state_version: int = Field(ge=0)
    correlation_id: str = Field(min_length=1, max_length=120)
    deadline_at: UtcDateTime
    proposals: tuple[ProbeProposal, ...] = Field(default=(), max_length=128)
    requires_reasoning: bool = False
    stop_reason: str | None = Field(default=None, max_length=120)
    degraded: bool = False
    ranked_evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=64)
    ranked_attention_page_ids: tuple[str, ...] = Field(default=(), max_length=64)
    attention_notes: tuple[str, ...] = Field(default=(), max_length=16)
    considered_evidence_count: int = Field(default=0, ge=0, le=64)
    considered_evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=256)
    signals: tuple[FastSignal, ...] = Field(default=(), max_length=8)
    presentation_trace: DecisionPresentationTrace | None = None

    def validate_against(self, request: DecisionRequest) -> DecisionResponse:
        if self.provider.role != "fast_decision":
            raise ResponseValidationError("provider role does not match fast decision response")
        if self.case_id != request.case_id:
            raise ResponseValidationError("case_id does not match request")
        if self.state_version != request.state_version:
            raise ResponseValidationError("state_version is stale")
        if self.correlation_id != request.correlation_id:
            raise ResponseValidationError("correlation_id does not match request")
        if self.deadline_at != request.deadline_at:
            raise ResponseValidationError("deadline_at does not match request")
        if not set(self.ranked_evidence_ids).issubset(request.evidence_ids):
            raise ResponseValidationError("attention references unknown evidence")
        if len(set(self.ranked_evidence_ids)) != len(self.ranked_evidence_ids):
            raise ResponseValidationError("attention repeats evidence")
        pages = request.attention_context or request.evidence_context
        page_ids = {f"{item.evidence_id}:{index}" for index, item in enumerate(pages)}
        if not set(self.ranked_attention_page_ids).issubset(page_ids):
            raise ResponseValidationError("attention references unknown page")
        if self.considered_evidence_count > len({str(item.evidence_id) for item in pages}):
            raise ResponseValidationError("attention count exceeds supplied evidence")
        if any(len(note) > 400 for note in self.attention_notes):
            raise ResponseValidationError("attention notes exceed the size bound")
        if self.signals and self.schema_version == 1:
            raise ResponseValidationError("fast signals require response schema version 2")
        if self.requires_reasoning and (self.schema_version == 1 or not self.signals):
            raise ResponseValidationError("fast escalation requires a typed fast signal in v2")
        if self.signals and not self.requires_reasoning:
            raise ResponseValidationError("fast escalation requires reasoning")
        visible_ids = {
            str(item.evidence_id)
            for item in (*request.evidence_context, *request.attention_context)
        }
        for signal in self.signals:
            if not set(signal.evidence_ids).issubset(request.evidence_ids):
                raise ResponseValidationError("fast signal references unknown evidence")
            if not {str(item) for item in signal.evidence_ids}.issubset(visible_ids):
                raise ResponseValidationError("fast signal evidence was not visible to the model")
            if not set(signal.evidence_ids).issubset(self.considered_evidence_ids):
                raise ResponseValidationError(
                    "fast signal evidence was not considered by the model"
                )
            if signal.hypothesis_index is not None and signal.hypothesis_index >= len(
                request.hypothesis_briefs
            ):
                raise ResponseValidationError("fast signal references unknown hypothesis")
        if len(set(self.considered_evidence_ids)) != len(self.considered_evidence_ids):
            raise ResponseValidationError("considered evidence IDs must be unique")
        if not {str(item) for item in self.considered_evidence_ids}.issubset(visible_ids):
            raise ResponseValidationError("considered evidence was not visible to the model")
        if self.presentation_trace is not None:
            if self.presentation_trace.provider != self.provider:
                raise ResponseValidationError("presentation trace provider mismatch")
            trace_format = self.presentation_trace.format_id
            if trace_format not in {"laya-worker-attention-v1", "laya-worker-attention-v2"}:
                raise ResponseValidationError("presentation trace format unsupported")
            # This format contains only typed hashes, counts and catalog-owned
            # IDs. It cannot smuggle model-visible case text into the trace.
            from systemsense.inference.laya_runtime import LayaAttentionMicrobatch

            payload = self.presentation_trace.payload
            raw = payload.get("microbatches")
            expected_keys = (
                {"microbatches"}
                if trace_format == "laya-worker-attention-v1"
                else {"evidence_serializer", "ordered_fragments", "ordered_probes", "microbatches"}
            )
            if set(payload) != expected_keys or not isinstance(raw, list) or not raw:
                raise ResponseValidationError("presentation trace payload invalid")
            try:
                batches = tuple(LayaAttentionMicrobatch.model_validate(item) for item in raw)
            except ValueError as error:
                raise ResponseValidationError("presentation trace microbatch invalid") from error
            if len(batches) > 32:
                raise ResponseValidationError("presentation trace has too many microbatches")
            if [item.model_dump(mode="json") for item in batches] != raw:
                raise ResponseValidationError("presentation trace contains noncanonical fields")
            if trace_format == "laya-worker-attention-v2":
                from systemsense.decision.laya import eligible_laya_candidates
                from systemsense.decision.semantic_packets import (
                    SERIALIZER_ID,
                    generic_decision_evidence_packets,
                )

                projected = generic_decision_evidence_packets(
                    request.attention_context or request.evidence_context,
                    candidate_count=(
                        0 if request.attention_only else len(eligible_laya_candidates(request))
                    ),
                    relationships=request.relationships,
                    priority_paths=tuple(check.fact_name for check in request.hypothesis_checks),
                )
                expected_fragments = [
                    {
                        "fragment_id": item["fragment_id"],
                        "description_sha256": hashlib.sha256(
                            item["description"].encode("utf-8")
                        ).hexdigest(),
                    }
                    for item in projected
                ]
                expected_probes = (
                    []
                    if request.attention_only
                    else [
                        {
                            "probe_id": item.probe_id,
                            "description_sha256": hashlib.sha256(
                                item.description.encode("utf-8")
                            ).hexdigest(),
                        }
                        for item in eligible_laya_candidates(request)
                    ]
                )
                if (
                    payload.get("evidence_serializer") != SERIALIZER_ID
                    or payload.get("ordered_fragments") != expected_fragments
                    or payload.get("ordered_probes") != expected_probes
                ):
                    raise ResponseValidationError("semantic packet trace request binding mismatch")
                evidence_batches = tuple(batch for batch in batches if batch.phase == "evidence")
                probe_batches = tuple(batch for batch in batches if batch.phase == "probe")
                seen_evidence = [item for batch in evidence_batches for item in batch.candidate_ids]
                seen_probes = [item for batch in probe_batches for item in batch.candidate_ids]
                if (
                    tuple(batch.batch_index for batch in evidence_batches)
                    != tuple(range(len(evidence_batches)))
                    or tuple(batch.batch_index for batch in probe_batches)
                    != tuple(range(len(probe_batches)))
                    or any(batch.phase == "evidence" for batch in batches[len(evidence_batches) :])
                    or seen_evidence
                    != [item["fragment_id"] for item in expected_fragments[: len(seen_evidence)]]
                    or seen_probes != [item["probe_id"] for item in expected_probes]
                    or any(
                        origin.presentation_sha256 is None
                        for batch in batches
                        for origin in batch.cached_origins
                    )
                ):
                    raise ResponseValidationError("semantic packet trace worker coverage mismatch")

        capabilities = {probe.probe_id: probe for probe in request.available_probes}
        proposal_ids = [proposal.probe_id for proposal in self.proposals]
        if len(proposal_ids) != len(set(proposal_ids)):
            raise ResponseValidationError("duplicate probe proposal")
        dedupe_keys = [proposal.dedupe_key for proposal in self.proposals]
        if len(dedupe_keys) != len(set(dedupe_keys)):
            raise ResponseValidationError("duplicate dedupe key")
        if len(self.proposals) > request.max_probes:
            raise ResponseValidationError("proposal count exceeds budget")

        proposal_id_set = set(proposal_ids)
        for proposal in self.proposals:
            if any(
                dependency not in proposal_id_set and dependency not in request.satisfied_probe_ids
                for dependency in proposal.depends_on
            ):
                raise ResponseValidationError("proposal dependency is not selected or completed")

        dependencies = {
            proposal.probe_id: set(proposal.depends_on).intersection(proposal_id_set)
            for proposal in self.proposals
        }
        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(probe_id: str) -> None:
            if probe_id in visiting:
                raise ResponseValidationError("proposal dependencies contain a cycle")
            if probe_id in visited:
                return
            visiting.add(probe_id)
            for dependency in dependencies[probe_id]:
                visit(dependency)
            visiting.remove(probe_id)
            visited.add(probe_id)

        for probe_id in dependencies:
            visit(probe_id)

        total_cost = 0
        for proposal in self.proposals:
            capability = capabilities.get(proposal.probe_id)
            if capability is None:
                raise ResponseValidationError(f"unknown probe: {proposal.probe_id}")
            if proposal.resource_class is not capability.resource_class:
                raise ResponseValidationError("resource_class does not match capability")
            if proposal.permission_class is not capability.permission_class:
                raise ResponseValidationError("unsupported permission class")
            if proposal.safety_class is not capability.safety_class:
                raise ResponseValidationError("unsupported safety class")
            if proposal.permission_class is not PermissionClass.READ_ONLY:
                raise ResponseValidationError("only read_only proposals are supported")
            if proposal.estimated_cost_ms != capability.cost_ms:
                raise ResponseValidationError("proposal cost does not match catalog cost")
            if any(dependency not in capabilities for dependency in proposal.depends_on):
                raise ResponseValidationError("proposal dependency is unknown")
            need = proposal.measurement_need
            if need is not None:
                if need.capability_id != proposal.probe_id:
                    raise ResponseValidationError("measurement capability does not match probe")
                if need.observable not in capability.observable_ids:
                    raise ResponseValidationError("measurement observable is not registered")
                if capability.target_handles:
                    if need.target_handle not in capability.target_handles:
                        raise ResponseValidationError("measurement target handle is not registered")
                elif need.target_handle is not None:
                    raise ResponseValidationError("measurement target handle is not registered")
                if need.window is not None and not capability.supports_window:
                    raise ResponseValidationError("measurement window is unsupported")
            total_cost += capability.cost_ms
        if total_cost > request.budget_ms:
            raise ResponseValidationError("proposal cost exceeds budget")
        return self
