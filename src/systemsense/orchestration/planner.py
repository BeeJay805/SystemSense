"""Deterministic budgeted selection from registered probe candidates."""

from pydantic import Field

from systemsense.domain.evidence import FrozenModel


class ProbeCandidate(FrozenModel):
    probe_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$")
    cost_ms: int = Field(gt=0, le=120_000)
    value: float = Field(ge=0, le=1)
    common: bool = False
    symptom_terms: frozenset[str] = frozenset()
    target_traits: frozenset[str] = frozenset()


class CasePlanningRequest(FrozenModel):
    symptom: str = Field(min_length=1, max_length=2000)
    target_traits: frozenset[str]
    fresh_probe_ids: frozenset[str]
    budget_ms: int = Field(gt=0, le=600_000)
    max_probes: int = Field(gt=0, le=128)


class PlannedProbe(FrozenModel):
    probe_id: str
    cost_ms: int
    value: float
    reason: str


class CasePlan(FrozenModel):
    probes: tuple[PlannedProbe, ...]
    total_cost_ms: int = Field(ge=0)
    skipped_fresh: tuple[str, ...]
    skipped_budget: tuple[str, ...]
    skipped_low_value: tuple[str, ...]

    @property
    def probe_ids(self) -> tuple[str, ...]:
        return tuple(probe.probe_id for probe in self.probes)


class DeterministicPlanner:
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
            if candidate.probe_id in request.fresh_probe_ids:
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
