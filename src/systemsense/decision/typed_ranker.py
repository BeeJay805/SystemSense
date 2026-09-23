"""CPU-only, typed-feature fast-decision challenger.

This is an auditable routing heuristic, not a diagnosis model or product default.
Sourced reference mechanisms can suggest registered probes, never establish a
cause. Machine edges can suggest a different broad registered read-only probe;
the resulting hint does not guarantee that probe will inspect the entity.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import cast

from systemsense.decision.contracts import (
    DecisionRequest,
    DecisionResponse,
    DiagnosticPurpose,
    PermissionClass,
    ProbeCapability,
    ProbeProposal,
    ProviderIdentity,
)
from systemsense.domain.probes import SafetyClass
from systemsense.evidence.graph import AssertionStatus, MemoryLayer, RelationKind
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus

_TERMS = re.compile(r"[a-z0-9]+")
_ALARM_FIELD = re.compile(
    r"error|fail|denied|timeout|disconnect|problem|offline|corrupt|warning|critical", re.I
)
_STOP_WORDS = frozenset({"a", "an", "and", "is", "the", "to", "with", "or", "of"})
_NO_PROGRESS = frozenset(
    {
        EvidenceContextStatus.FAILED,
        EvidenceContextStatus.DENIED,
        EvidenceContextStatus.UNAVAILABLE,
        EvidenceContextStatus.UNSUPPORTED,
        EvidenceContextStatus.MISSING,
    }
)
_TRAVERSABLE_MACHINE_RELATIONS = frozenset(
    {
        RelationKind.DEPENDS_ON,
        RelationKind.RUNS_IN_PROCESS,
        RelationKind.STORED_ON,
        RelationKind.USES_DRIVER,
    }
)
_BROAD_GRAPH_HINT_STRENGTH = 0.25
_MAX_GRAPH_SOURCE_AGE = timedelta(minutes=5)


@dataclass(frozen=True, slots=True)
class FeatureContributions:
    """Normalized routing inputs; these are not probabilities of a root cause."""

    symptom: float
    trait: float
    freshness: float
    status: float
    coverage_gap: float
    machine_graph: float
    reference_graph: float
    cost: float
    revisit_penalty: float


@dataclass(frozen=True, slots=True)
class CandidateScore:
    probe_id: str
    score: float
    features: FeatureContributions


class TypedFeatureDecisionProvider:
    """Pure in-process challenger over bounded, catalog-owned request data."""

    def __init__(self, *, clock: Callable[[], datetime] | None = None) -> None:
        self._clock = clock or (lambda: datetime.now(UTC))

    @property
    def identity(self) -> ProviderIdentity:
        return ProviderIdentity(
            provider_id="typed-feature-challenger",
            provider_version="3",
            role="fast_decision",
        )

    def score_candidates(self, request: DecisionRequest) -> tuple[CandidateScore, ...]:
        """Return eligible scores with fixed, inspectable feature contributions."""

        return self._score_candidates(request, self._clock())

    def _score_candidates(
        self, request: DecisionRequest, now: datetime
    ) -> tuple[CandidateScore, ...]:

        remaining_ms = int((request.deadline_at - now).total_seconds() * 1000)
        if request.attention_only or remaining_ms <= 0:
            return ()
        usable_budget = min(request.budget_ms, remaining_ms)
        symptom_terms = _terms(request.symptom)
        by_probe: dict[str, list[EvidenceContext]] = {}
        for evidence in request.evidence_context:
            by_probe.setdefault(evidence.probe_id, []).append(evidence)
        grounded_reference = _reference_probe_ids(request, symptom_terms)
        grounded_machine = _machine_probe_ids(request, now)
        scores: list[CandidateScore] = []
        for capability in request.available_probes:
            if not _eligible(capability, request, usable_budget):
                continue
            symptom = _overlap(symptom_terms, _terms(" ".join(capability.keywords)))
            trait = _overlap(request.target_traits, capability.target_traits)
            reference_graph = float(capability.probe_id in grounded_reference)
            machine_graph = (
                _BROAD_GRAPH_HINT_STRENGTH if capability.probe_id in grounded_machine else 0.0
            )
            preferred = capability.probe_id in request.preferred_probe_ids
            # Common probes are not a reason to scan an unrelated subsystem.
            if not (symptom or trait or reference_graph or machine_graph or preferred):
                continue
            history = sorted(
                by_probe.get(capability.probe_id, ()), key=lambda item: item.observed_at
            )
            latest = history[-1] if history else None
            freshness, status, coverage_gap = _evidence_quality(latest, now)
            no_progress = sum(item.status in _NO_PROGRESS for item in history)
            revisit = min(1.0, 0.25 * max(0, len(history) - 1) + 0.35 * no_progress)
            features = FeatureContributions(
                symptom=symptom,
                trait=trait,
                freshness=freshness,
                status=status,
                coverage_gap=coverage_gap,
                machine_graph=machine_graph,
                reference_graph=reference_graph,
                cost=max(0.0, 1.0 - capability.cost_ms / usable_budget),
                revisit_penalty=revisit,
            )
            raw = (
                0.30 * symptom
                + 0.22 * trait
                + 0.16 * reference_graph
                + 0.16 * machine_graph
                + 0.08 * freshness
                + 0.06 * status
                + 0.16 * coverage_gap
                + 0.06 * features.cost
                + 0.04 * float(preferred)
                - 0.18 * revisit
            )
            scores.append(
                CandidateScore(
                    probe_id=capability.probe_id,
                    score=round(max(0.0, min(1.0, raw)), 6),
                    features=features,
                )
            )
        return tuple(sorted(scores, key=lambda item: (-item.score, item.probe_id)))

    def decide(self, request: DecisionRequest) -> DecisionResponse:
        now = self._clock()
        ranked = self._score_candidates(request, now)
        capabilities = {item.probe_id: item for item in request.available_probes}
        remaining_ms = max(0, int((request.deadline_at - now).total_seconds() * 1000))
        budget = min(request.budget_ms, remaining_ms)
        proposals: list[ProbeProposal] = []
        total_cost = 0
        observed_probe_ids = {item.probe_id for item in request.evidence_context}
        for candidate in ranked:
            capability = capabilities[candidate.probe_id]
            if len(proposals) >= request.max_probes:
                break
            if total_cost + capability.cost_ms > budget:
                continue
            purpose = (
                DiagnosticPurpose.CHECK_COVERAGE
                if candidate.features.machine_graph
                or candidate.probe_id not in observed_probe_ids
                or candidate.features.coverage_gap >= 0.5
                else DiagnosticPurpose.DISTINGUISH_HYPOTHESES
                if candidate.features.reference_graph
                else DiagnosticPurpose.REFRESH_EVIDENCE
            )
            proposals.append(
                ProbeProposal(
                    probe_id=candidate.probe_id,
                    purpose=purpose,
                    priority=candidate.score,
                    estimated_cost_ms=capability.cost_ms,
                    resource_class=capability.resource_class,
                    dedupe_key=f"{candidate.probe_id}:typed-feature-v3",
                    permission_class=capability.permission_class,
                    safety_class=capability.safety_class,
                )
            )
            total_cost += capability.cost_ms

        contexts = request.attention_context or request.evidence_context
        ordered_pages = sorted(
            enumerate(contexts),
            key=lambda pair: _attention_key(pair[0], pair[1], now),
        )[:64]
        evidence_ids = tuple(dict.fromkeys(item.evidence_id for _, item in ordered_pages))
        result = DecisionResponse(
            provider=self.identity,
            case_id=request.case_id,
            state_version=request.state_version,
            correlation_id=request.correlation_id,
            deadline_at=request.deadline_at,
            proposals=tuple(proposals),
            stop_reason="deadline_elapsed" if remaining_ms <= 0 else None,
            ranked_evidence_ids=evidence_ids,
            ranked_attention_page_ids=tuple(
                f"{item.evidence_id}:{index}" for index, item in ordered_pages
            ),
            considered_evidence_count=len(evidence_ids),
        )
        return result.validate_against(request)


def _eligible(capability: ProbeCapability, request: DecisionRequest, budget_ms: int) -> bool:
    return (
        capability.permission_class is PermissionClass.READ_ONLY
        and capability.safety_class in {SafetyClass.R0, SafetyClass.R1}
        and capability.target_state_effect == "none"
        and not capability.outbound_network
        and capability.probe_id not in request.completed_probe_ids
        and capability.probe_id not in request.fresh_probe_ids
        and capability.cost_ms <= budget_ms
    )


def _machine_probe_ids(request: DecisionRequest, now: datetime) -> frozenset[str]:
    """Use validated source→target edges as weak broad-probe coverage hints.

    This is attention routing, not causal inference or a guarantee that the
    hinted probe will actually enumerate the related entity.
    """

    targets: dict[str, set[str]] = {}
    for capability in request.available_probes:
        for entity_id in capability.related_entity_hint_ids:
            targets.setdefault(str(entity_id), set()).add(capability.probe_id)
    if not targets:
        return frozenset()
    observed = {
        context.evidence_id: context
        for context in request.evidence_context
        if context.status is EvidenceContextStatus.OBSERVED
        and context.case_scope == "current_case"
        and context.incident_relevant is True
        and context.observed_at <= context.captured_at <= now
        and now - context.captured_at <= _MAX_GRAPH_SOURCE_AGE
    }
    registered = {capability.probe_id for capability in request.available_probes}
    routed: set[str] = set()
    for relation in request.relationships:
        if (
            relation.memory_layer is not MemoryLayer.MACHINE
            or relation.assertion_status is not AssertionStatus.OBSERVED
            or relation.relationship not in _TRAVERSABLE_MACHINE_RELATIONS
        ):
            continue
        target_probe_ids = targets.get(str(relation.target_entity_id))
        if not target_probe_ids:
            continue
        if not any(
            (context := observed.get(evidence_id)) is not None
            and relation.is_valid_at(context.observed_at)
            for evidence_id in relation.evidence_ids
        ):
            continue
        for target_probe_id in target_probe_ids:
            if any(
                source_probe_id in registered
                and source_probe_id in request.completed_probe_ids
                and source_probe_id != target_probe_id
                for source_probe_id in relation.applicability
            ):
                routed.add(target_probe_id)
    return frozenset(routed)


def _terms(text: str) -> frozenset[str]:
    return frozenset(_TERMS.findall(text.casefold())) - _STOP_WORDS


def _overlap(left: frozenset[str], right: frozenset[str]) -> float:
    return len(left & right) / max(1, len(right))


def _evidence_quality(
    evidence: EvidenceContext | None, now: datetime
) -> tuple[float, float, float]:
    if evidence is None:
        return 0.4, 0.0, 1.0  # unexplored, never healthy
    if (
        evidence.observed_at > now
        or evidence.captured_at > now
        or evidence.observed_at > evidence.captured_at
    ):
        return 0.0, 0.0, 1.0
    age_seconds = max(0.0, (now - evidence.observed_at).total_seconds())
    freshness = (
        1.0
        if age_seconds <= 300
        else 0.6
        if age_seconds <= 1800
        else 0.2
        if age_seconds <= 7200
        else 0.0
    )
    if evidence.status is EvidenceContextStatus.STALE:
        freshness = 0.0
    status = (
        1.0
        if evidence.status is EvidenceContextStatus.OBSERVED
        else 0.35
        if evidence.status is EvidenceContextStatus.PARTIAL
        else 0.0
    )
    omitted = evidence.facts.get("omitted_count")
    collection_status = evidence.facts.get("collection_status")
    coverage_gap = 1.0 - status
    if (isinstance(omitted, int) and not isinstance(omitted, bool) and omitted > 0) or (
        isinstance(collection_status, str) and collection_status != "available"
    ):
        coverage_gap = max(coverage_gap, 0.5)
    if evidence.limitations or evidence.status is EvidenceContextStatus.TRUNCATED:
        coverage_gap = max(coverage_gap, 0.5)
    return freshness, status, coverage_gap


def _attention_key(index: int, item: EvidenceContext, now: datetime) -> tuple[int, float, str, int]:
    plausible_time = (
        item.observed_at <= item.captured_at and item.observed_at <= now and item.captured_at <= now
    )
    if not plausible_time:
        tier = 5
    elif item.status is EvidenceContextStatus.OBSERVED:
        tier = 0 if _has_alarm_fact(item) else 1
    elif item.status is EvidenceContextStatus.PARTIAL:
        tier = 2 if _has_alarm_fact(item) else 3
    else:
        tier = 4
    return tier, -item.observed_at.timestamp(), str(item.evidence_id), index


def _has_alarm_fact(item: EvidenceContext) -> bool:
    for name, value in item.facts.items():
        if not _ALARM_FIELD.search(name):
            continue
        if isinstance(value, bool):
            if value:
                return True
        elif isinstance(value, (int, float)):
            if value > 0:
                return True
        elif isinstance(value, str):
            if value.strip().casefold() not in {"", "0", "false", "none", "ok", "healthy"}:
                return True
        elif value:
            return True
    return False


def _reference_probe_ids(request: DecisionRequest, symptom_terms: frozenset[str]) -> frozenset[str]:
    """Only sourced, coherent reference edges can suggest a registered probe."""

    known_probes = {item.probe_id for item in request.available_probes}
    relevant: set[str] = set()
    for packet in request.reference_context:
        nodes_raw, sources_raw, relations_raw = (
            packet.get("nodes"),
            packet.get("sources"),
            packet.get("relations"),
        )
        if not all(
            isinstance(value, (list, tuple)) for value in (nodes_raw, sources_raw, relations_raw)
        ):
            continue
        nodes: dict[str, frozenset[str]] = {}
        for raw in cast(list[object] | tuple[object, ...], nodes_raw):
            if not isinstance(raw, dict):
                continue
            node = cast(dict[str, object], raw)
            node_id = node.get("node_id", node.get("id"))
            label = node.get("label")
            if isinstance(node_id, str) and isinstance(label, str) and node_id.startswith("kn_"):
                nodes[node_id] = _terms(label)
        sources: set[str] = set()
        for raw in cast(list[object] | tuple[object, ...], sources_raw):
            if not isinstance(raw, dict):
                continue
            source = cast(dict[str, object], raw)
            source_id = source.get("source_id")
            if isinstance(source_id, str) and source_id.startswith("ks_"):
                sources.add(source_id)
        for raw in cast(list[object] | tuple[object, ...], relations_raw):
            if not isinstance(raw, dict):
                continue
            relation = cast(dict[str, object], raw)
            source_node = relation.get("source_node_id", relation.get("from"))
            target_node = relation.get("target_node_id", relation.get("to"))
            mechanism = relation.get("mechanism")
            conditions = relation.get("conditions", relation.get("when"))
            relation_sources = _string_items(relation.get("source_ids", relation.get("sources")))
            probe_ids = _string_items(
                relation.get("distinguishing_probe_ids", relation.get("probes"))
            )
            if not (
                isinstance(source_node, str)
                and isinstance(target_node, str)
                and source_node in nodes
                and target_node in nodes
                and isinstance(mechanism, str)
                and mechanism.strip()
                and _string_items(conditions)
                and relation_sources
                and all(source_id in sources for source_id in relation_sources)
                and probe_ids
            ):
                continue
            symptoms = " ".join(_string_items(relation.get("symptoms")))
            reference_terms = nodes[source_node] | nodes[target_node] | _terms(symptoms)
            if not (reference_terms & symptom_terms):
                continue
            relevant.update(probe_id for probe_id in probe_ids if probe_id in known_probes)
    return frozenset(relevant)


def _string_items(value: object) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        return ()
    items = cast(list[object] | tuple[object, ...], value)
    if any(not isinstance(item, str) or not item.strip() for item in items):
        return ()
    return tuple(cast(str, item) for item in items)
