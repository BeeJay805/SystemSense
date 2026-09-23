"""Bounded, versioned contracts for fast diagnostic decisions."""

from __future__ import annotations

from enum import StrEnum
from typing import Literal

from pydantic import Field, field_validator, model_validator

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import CaseId, EntityId, EvidenceId, JsonValue
from systemsense.domain.probes import SafetyClass
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
        return self


class ProbeProposal(FrozenModel):
    """A bounded reference to a catalog probe, never an executable operation."""

    probe_id: str = Field(min_length=1, max_length=120, pattern=r"^[a-z][a-z0-9_.-]*$")
    purpose: DiagnosticPurpose
    priority: float = Field(ge=0, le=1)
    estimated_cost_ms: int = Field(gt=0, le=120_000)
    resource_class: ResourceClass
    dedupe_key: str = Field(min_length=1, max_length=160, pattern=r"^[a-zA-Z0-9_.:/-]+$")
    permission_class: PermissionClass = PermissionClass.READ_ONLY
    safety_class: SafetyClass = SafetyClass.R1
    depends_on: tuple[str, ...] = Field(default=(), max_length=16)


class DecisionRequest(FrozenModel):
    schema_version: Literal[1] = 1
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
    preferred_probe_ids: tuple[str, ...] = Field(default=(), max_length=32)
    hypothesis_briefs: tuple[str, ...] = Field(default=(), max_length=16)
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
        if not set(self.preferred_probe_ids).issubset(ids):
            raise ValueError("preferred probe IDs must reference available probes")
        if any(len(brief) > 1200 for brief in self.hypothesis_briefs):
            raise ValueError("hypothesis briefs must be bounded")
        return self


class ResponseValidationError(ValueError):
    """A provider response cannot be safely applied to a decision request."""


class DecisionResponse(FrozenModel):
    schema_version: Literal[1] = 1
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
            if any(dependency not in proposal_id_set for dependency in proposal.depends_on):
                raise ResponseValidationError("proposal dependency is not selected")

        dependencies = {proposal.probe_id: set(proposal.depends_on) for proposal in self.proposals}
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
            total_cost += capability.cost_ms
        if total_cost > request.budget_ms:
            raise ResponseValidationError("proposal cost exceeds budget")
        return self
