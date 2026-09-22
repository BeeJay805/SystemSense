"""Bounded case planning and the keyword baseline implementation.

The planner owns the translation between the case-facing planning contract and
the provider-facing decision contract.  Providers can propose only registered,
read-only capabilities; they never receive an executable operation.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Protocol
from uuid import uuid4

from pydantic import Field, model_validator

from systemsense.decision.contracts import (
    DecisionRequest,
    PermissionClass,
    ProbeCapability,
    ProviderIdentity,
    ResponseValidationError,
)
from systemsense.decision.provider import FastDecisionProvider
from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import CaseId
from systemsense.domain.probes import SafetyClass
from systemsense.domain.time import UtcDateTime, utc_now
from systemsense.orchestration.scheduler import ResourceClass


class ProbeCandidate(FrozenModel):
    probe_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$")
    cost_ms: int = Field(gt=0, le=120_000)
    value: float = Field(ge=0, le=1)
    common: bool = False
    symptom_terms: frozenset[str] = frozenset()
    target_traits: frozenset[str] = frozenset()
    description: str = "registered read-only diagnostic probe"
    resource_class: ResourceClass = ResourceClass.CPU
    permission_class: PermissionClass = PermissionClass.READ_ONLY
    safety_class: SafetyClass = SafetyClass.R1

    @model_validator(mode="after")
    def read_only_candidate(self) -> ProbeCandidate:
        if self.permission_class is not PermissionClass.READ_ONLY:
            raise ValueError("planner candidates must be read-only")
        if self.safety_class not in {SafetyClass.R0, SafetyClass.R1}:
            raise ValueError("planner candidates must use safety class R0 or R1")
        return self


class CasePlanningRequest(FrozenModel):
    symptom: str = Field(min_length=1, max_length=2000)
    target_traits: frozenset[str]
    fresh_probe_ids: frozenset[str]
    budget_ms: int = Field(gt=0, le=600_000)
    max_probes: int = Field(gt=0, le=128)
    # These defaults preserve the old case-service call shape while making the
    # provider request fully typed.  New callers should pass the real case and
    # correlation context explicitly.
    case_id: CaseId = Field(default_factory=CaseId.new)
    state_version: int = Field(default=0, ge=0)
    correlation_id: str = Field(
        default_factory=lambda: f"planning:{uuid4().hex}",
        min_length=1,
        max_length=120,
        pattern=r"^[a-zA-Z0-9_.:-]+$",
    )
    deadline_at: UtcDateTime = Field(default_factory=lambda: utc_now() + timedelta(seconds=30))


class PlannedProbe(FrozenModel):
    probe_id: str
    cost_ms: int
    value: float
    reason: str
    depends_on: tuple[str, ...] = ()


class CasePlan(FrozenModel):
    probes: tuple[PlannedProbe, ...]
    total_cost_ms: int = Field(ge=0)
    skipped_fresh: tuple[str, ...]
    skipped_budget: tuple[str, ...]
    skipped_low_value: tuple[str, ...]

    @property
    def probe_ids(self) -> tuple[str, ...]:
        return tuple(probe.probe_id for probe in self.probes)


class CasePlanner(Protocol):
    """Case-facing planner contract consumed by the application service."""

    def plan(self, request: CasePlanningRequest) -> CasePlan: ...


class KeywordBaselinePlanner:
    """Legacy deterministic planner retained as an explicit fallback."""

    def __init__(
        self,
        *,
        candidates: tuple[ProbeCandidate, ...],
        minimum_value: float = 0.0,
    ) -> None:
        if not 0 <= minimum_value <= 1:
            raise ValueError("minimum_value must be between 0 and 1")
        ids = [candidate.probe_id for candidate in candidates]
        if len(ids) != len(set(ids)):
            raise ValueError("probe candidates must have unique IDs")
        self._candidates = candidates
        self._minimum_value = minimum_value

    def plan(self, request: CasePlanningRequest) -> CasePlan:
        symptom = request.symptom.casefold()
        common = sorted(
            (candidate for candidate in self._candidates if candidate.common),
            key=lambda candidate: candidate.probe_id,
        )
        relevant = sorted(
            (
                candidate
                for candidate in self._candidates
                if not candidate.common
                and (
                    any(term.casefold() in symptom for term in candidate.symptom_terms)
                    or bool(candidate.target_traits & request.target_traits)
                )
            ),
            key=lambda candidate: (-candidate.value, candidate.cost_ms, candidate.probe_id),
        )

        selected: list[PlannedProbe] = []
        total_cost = 0
        skipped_fresh: list[str] = []
        skipped_budget: list[str] = []
        skipped_low_value: list[str] = []
        for candidate in (*common, *relevant):
            if not candidate.common and candidate.probe_id in request.fresh_probe_ids:
                skipped_fresh.append(candidate.probe_id)
                continue
            if not candidate.common and candidate.value < self._minimum_value:
                skipped_low_value.append(candidate.probe_id)
                continue
            if (
                total_cost + candidate.cost_ms > request.budget_ms
                or len(selected) == request.max_probes
            ):
                skipped_budget.append(candidate.probe_id)
                continue
            selected.append(
                PlannedProbe(
                    probe_id=candidate.probe_id,
                    cost_ms=candidate.cost_ms,
                    value=candidate.value,
                    reason="common bundle" if candidate.common else "symptom or target match",
                )
            )
            total_cost += candidate.cost_ms

        return CasePlan(
            probes=tuple(selected),
            total_cost_ms=total_cost,
            skipped_fresh=tuple(skipped_fresh),
            skipped_budget=tuple(skipped_budget),
            skipped_low_value=tuple(skipped_low_value),
        )


class ProviderBackedPlanner(KeywordBaselinePlanner):
    """Apply a bounded decision provider to the registered probe catalog."""

    def __init__(
        self,
        *,
        candidates: tuple[ProbeCandidate, ...],
        provider: FastDecisionProvider,
        minimum_value: float = 0.0,
    ) -> None:
        if not 0 <= minimum_value <= 1:
            raise ValueError("minimum_value must be between 0 and 1")
        ids = [candidate.probe_id for candidate in candidates]
        if len(ids) != len(set(ids)):
            raise ValueError("probe candidates must have unique IDs")
        self._candidates = candidates
        self._candidate_by_id = {candidate.probe_id: candidate for candidate in candidates}
        self._provider = provider
        self._minimum_value = minimum_value

    @property
    def provider_identity(self) -> ProviderIdentity:
        return self._provider.identity

    def plan(self, request: CasePlanningRequest) -> CasePlan:
        decision_request = DecisionRequest(
            case_id=request.case_id,
            state_version=request.state_version,
            correlation_id=request.correlation_id,
            deadline_at=request.deadline_at,
            symptom=request.symptom,
            target_traits=request.target_traits,
            fresh_probe_ids=request.fresh_probe_ids,
            available_probes=tuple(self._capability(candidate) for candidate in self._candidates),
            budget_ms=request.budget_ms,
            max_probes=request.max_probes,
        )
        if decision_request.deadline_at <= utc_now():
            raise ResponseValidationError("decision request deadline has expired")

        response = self._provider.decide(decision_request)
        response.validate_against(decision_request)
        if response.deadline_at <= utc_now():
            raise ResponseValidationError("decision response deadline has expired")

        selected: list[PlannedProbe] = []
        selected_ids: set[str] = set()
        total_cost = 0
        for proposal in response.proposals:
            candidate = self._candidate_by_id.get(proposal.probe_id)
            if candidate is None:  # defensive even though response validation checks it
                raise ResponseValidationError(f"unknown probe: {proposal.probe_id}")
            if proposal.probe_id in request.fresh_probe_ids and not candidate.common:
                raise ResponseValidationError("provider selected fresh probe")
            if proposal.priority < self._minimum_value:
                continue
            if proposal.probe_id in selected_ids:
                raise ResponseValidationError("provider selected duplicate probe")
            selected_ids.add(proposal.probe_id)
            total_cost += candidate.cost_ms
            selected.append(
                PlannedProbe(
                    probe_id=proposal.probe_id,
                    cost_ms=candidate.cost_ms,
                    value=proposal.priority,
                    reason=f"{response.provider.provider_id}: {proposal.purpose.value}",
                    depends_on=proposal.depends_on,
                )
            )

        selected_set = set(selected_ids)
        skipped_fresh = tuple(
            candidate.probe_id
            for candidate in self._candidates
            if not candidate.common
            and candidate.probe_id in request.fresh_probe_ids
            and candidate.probe_id not in selected_set
        )
        skipped_low_value = tuple(
            candidate.probe_id
            for candidate in self._candidates
            if not candidate.common
            and candidate.probe_id not in selected_set
            and candidate.probe_id not in request.fresh_probe_ids
            and candidate.value < self._minimum_value
        )
        proposed_ids = {proposal.probe_id for proposal in response.proposals}
        skipped_budget = tuple(
            candidate.probe_id
            for candidate in self._candidates
            if candidate.probe_id not in selected_set
            and candidate.probe_id not in request.fresh_probe_ids
            and candidate.probe_id not in proposed_ids
            and candidate.value >= self._minimum_value
        )
        return CasePlan(
            probes=tuple(selected),
            total_cost_ms=total_cost,
            skipped_fresh=skipped_fresh,
            skipped_budget=skipped_budget,
            skipped_low_value=skipped_low_value,
        )

    @staticmethod
    def _capability(candidate: ProbeCandidate) -> ProbeCapability:
        return ProbeCapability(
            probe_id=candidate.probe_id,
            description=candidate.description,
            keywords=candidate.symptom_terms,
            target_traits=candidate.target_traits,
            common=candidate.common,
            baseline_priority=candidate.value,
            cost_ms=candidate.cost_ms,
            resource_class=candidate.resource_class,
            permission_class=candidate.permission_class,
            safety_class=candidate.safety_class,
        )


# Compatibility name for callers that explicitly selected the old deterministic
# implementation.  Defaults use ProviderBackedPlanner instead.
DeterministicPlanner = KeywordBaselinePlanner
