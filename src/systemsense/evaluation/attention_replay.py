"""Deterministic held-out replay for registered next-probe providers.

This module scores only independently reviewed, real expert labels. It does not
fit a ranker, generate labels, or claim diagnostic performance from fixtures.
Version 2 hashes check internal consistency only; they do not authenticate a label.
Matched recorded outcome time describes the expert-labeled observation, not a
provider's counterfactual time-to-evidence. Recall uses only explicitly labeled
useful probes. Adjudication coverage gives observed outcomes over all registered
candidates; candidates without labels or outcomes remain unknown, not negative.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Literal, Protocol

from pydantic import Field

from systemsense.decision.contracts import DecisionRequest, DecisionResponse, ProviderIdentity
from systemsense.domain.evidence import FrozenModel
from systemsense.domain.probes import ProbeManifest
from systemsense.evaluation.attention_labels import (
    ExpertAttentionLabel,
    RegisteredProbe,
    validate_group_splits,
)
from systemsense.evaluation.attention_labels import (
    candidate_catalog_sha256 as _candidate_catalog_sha256,
)


class ReplayProvider(Protocol):
    """The provider surface needed for a decision replay."""

    @property
    def identity(self) -> ProviderIdentity: ...

    def decide(self, request: DecisionRequest) -> DecisionResponse: ...


class ProviderReplayMetrics(FrozenModel):
    cases: int = Field(ge=1)
    unsupported_suggestions: int = Field(ge=0)
    labeled_useful_probe_recall_at_k: float = Field(
        ge=0,
        le=1,
        description=(
            "Recall over labeled useful probes only; not all potentially useful candidates."
        ),
    )
    labeled_useful_probe_hits: int = Field(ge=0)
    labeled_useful_probe_opportunities: int = Field(ge=0)
    negative_top_k_suggestions: int = Field(ge=0)
    negative_probe_opportunities: int = Field(ge=0)
    matched_recorded_outcome_seconds: float | None = Field(default=None, ge=0)
    matched_recorded_outcome_cases: int = Field(ge=0)


class CaseCandidateAdjudication(FrozenModel):
    label_id: str
    registered_candidate_count: int = Field(ge=1)
    observed_outcome_count: int = Field(ge=0)
    observed_outcome_fraction: float = Field(ge=0, le=1)
    labeled_useful_candidate_count: int = Field(ge=0)
    labeled_negative_candidate_count: int = Field(ge=0)
    unadjudicated_candidate_count: int = Field(ge=0)


class CandidateAdjudicationSummary(FrozenModel):
    cases: int = Field(ge=1)
    registered_candidate_count: int = Field(ge=1)
    observed_outcome_count: int = Field(
        ge=0, description="Registered candidates with a recorded probe outcome."
    )
    observed_outcome_fraction: float = Field(
        ge=0,
        le=1,
        description="Observed outcomes divided by every registered candidate, including unknowns.",
    )
    labeled_useful_candidate_count: int = Field(ge=0)
    labeled_negative_candidate_count: int = Field(ge=0)
    unadjudicated_candidate_count: int = Field(ge=0)
    per_case: tuple[CaseCandidateAdjudication, ...] = Field(min_length=1)


class AttentionReplayResult(FrozenModel):
    schema_version: int = 1
    split: str
    k: int = Field(ge=1)
    synthetic: bool = False
    label_hash_validation: Literal["consistency_only"] = "consistency_only"
    label_authenticity: Literal["not_verified"] = "not_verified"
    candidate_adjudication: CandidateAdjudicationSummary
    metrics: dict[str, ProviderReplayMetrics]


def candidate_catalog_sha256(candidates: Sequence[RegisteredProbe]) -> str:
    """Public canonical digest helper for the complete frozen candidate set."""

    return _candidate_catalog_sha256(candidates)


def candidate_context_sha256(request: DecisionRequest) -> str:
    """Hash the exact capability catalog visible in a frozen provider request."""

    payload = [
        item.model_dump(mode="json")
        for item in sorted(request.available_probes, key=lambda item: item.probe_id)
    ]
    canonical = json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def visible_evidence_sha256(request: DecisionRequest) -> str:
    """Hash the exact evidence and contextual material exposed to a decision provider."""

    payload = {
        "symptom": request.symptom,
        "target_traits": sorted(request.target_traits),
        "evidence_ids": [str(item) for item in request.evidence_ids],
        "evidence_context": [item.model_dump(mode="json") for item in request.evidence_context],
        "attention_context": [item.model_dump(mode="json") for item in request.attention_context],
        "relationships": [item.model_dump(mode="json") for item in request.relationships],
        "fresh_probe_ids": sorted(request.fresh_probe_ids),
        "completed_probe_ids": sorted(request.completed_probe_ids),
        "preferred_probe_ids": list(request.preferred_probe_ids),
        "hypothesis_briefs": list(request.hypothesis_briefs),
        "reference_context": list(request.reference_context),
    }
    canonical = json.dumps(
        payload,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def evaluate_attention_replay(
    *,
    splits: Mapping[str, Sequence[ExpertAttentionLabel]],
    requests: Mapping[str, DecisionRequest],
    manifests: Mapping[str, ProbeManifest],
    providers: Mapping[str, ReplayProvider],
    k: int,
    heldout_split: str = "heldout",
) -> AttentionReplayResult:
    """Compare providers over identical frozen requests in a validated held-out split.

    All candidate manifests and label split groups are validated before any provider
    runs. Provider responses must preserve the complete request correlation envelope.
    Proposal IDs absent from the catalog are counted as unsupported suggestions.
    """

    if k < 1:
        raise ValueError("k must be positive")
    if not providers or any(not name for name in providers):
        raise ValueError("at least one named provider is required")
    if heldout_split not in splits or not splits[heldout_split]:
        raise ValueError("held-out split must contain at least one expert label")

    validate_group_splits(splits, manifests)
    labels = tuple(splits[heldout_split])
    if len({label.label_id for label in labels}) != len(labels):
        raise ValueError("held-out labels must have unique IDs")
    if set(requests) != {label.label_id for group in splits.values() for label in group}:
        raise ValueError("requests must bind exactly one frozen request to every split label")

    for label in labels:
        if (
            label.label_origin != "human_expert"
            or label.synthetic
            or label.source_kind not in {"live", "recorded"}
        ):
            raise ValueError(
                "only real human expert labels are admissible; synthetic labels are refused"
            )
        request = requests[label.label_id]
        _validate_snapshot_binding(label, request, manifests)

    per_case_adjudication = tuple(_case_adjudication(label) for label in labels)
    registered_total = sum(item.registered_candidate_count for item in per_case_adjudication)
    observed_total = sum(item.observed_outcome_count for item in per_case_adjudication)
    adjudication = CandidateAdjudicationSummary(
        cases=len(per_case_adjudication),
        registered_candidate_count=registered_total,
        observed_outcome_count=observed_total,
        observed_outcome_fraction=observed_total / registered_total,
        labeled_useful_candidate_count=sum(
            item.labeled_useful_candidate_count for item in per_case_adjudication
        ),
        labeled_negative_candidate_count=sum(
            item.labeled_negative_candidate_count for item in per_case_adjudication
        ),
        unadjudicated_candidate_count=sum(
            item.unadjudicated_candidate_count for item in per_case_adjudication
        ),
        per_case=per_case_adjudication,
    )

    accumulated: dict[str, dict[str, float]] = {
        name: {
            "unsupported": 0,
            "hits": 0,
            "opportunities": 0,
            "negative_top_k": 0,
            "negative_opportunities": 0,
            "matched_outcome_seconds": 0,
            "matched_outcome_cases": 0,
        }
        for name in providers
    }

    for label in labels:
        request = requests[label.label_id]
        for name, provider in providers.items():
            response = provider.decide(request)
            _validate_response_binding(response, request)
            candidate_ids = {candidate.probe_id for candidate in label.snapshot.candidate_probes}
            proposal_ids = [proposal.probe_id for proposal in response.proposals]
            unsupported = sum(probe_id not in candidate_ids for probe_id in proposal_ids)
            # Output positions consume K even when a suggestion is unsupported.
            top_k_ids = proposal_ids[:k]
            selected = set(top_k_ids) & candidate_ids
            useful = set(label.useful_probe_ids)
            item = accumulated[name]
            item["unsupported"] += unsupported
            item["hits"] += len(selected & useful)
            item["opportunities"] += len(useful)
            negatives = set(label.negative_probe_ids)
            item["negative_top_k"] += len(set(top_k_ids) & negatives)
            item["negative_opportunities"] += len(negatives)

            # This is matched recorded label timing, not counterfactual provider latency.
            decisive = [
                outcome.finished_at
                for outcome in label.outcomes
                if outcome.probe_id in selected
                and outcome.probe_id in useful
                and outcome.result == "informative"
            ]
            if decisive:
                elapsed = (min(decisive) - label.snapshot.captured_at).total_seconds()
                item["matched_outcome_seconds"] += elapsed
                item["matched_outcome_cases"] += 1

    metrics: dict[str, ProviderReplayMetrics] = {}
    for name, item in accumulated.items():
        opportunities = int(item["opportunities"])
        matched_cases = int(item["matched_outcome_cases"])
        metrics[name] = ProviderReplayMetrics(
            cases=len(labels),
            unsupported_suggestions=int(item["unsupported"]),
            labeled_useful_probe_recall_at_k=(
                int(item["hits"]) / opportunities if opportunities else 0.0
            ),
            labeled_useful_probe_hits=int(item["hits"]),
            labeled_useful_probe_opportunities=opportunities,
            negative_top_k_suggestions=int(item["negative_top_k"]),
            negative_probe_opportunities=int(item["negative_opportunities"]),
            matched_recorded_outcome_seconds=(
                item["matched_outcome_seconds"] / matched_cases if matched_cases else None
            ),
            matched_recorded_outcome_cases=matched_cases,
        )
    return AttentionReplayResult(
        split=heldout_split,
        k=k,
        candidate_adjudication=adjudication,
        metrics=metrics,
    )


def _case_adjudication(label: ExpertAttentionLabel) -> CaseCandidateAdjudication:
    candidates = {item.probe_id for item in label.snapshot.candidate_probes}
    outcomes = {item.probe_id for item in label.outcomes}
    useful = set(label.useful_probe_ids)
    negative = set(label.negative_probe_ids)
    count = len(candidates)
    observed = len(outcomes)
    adjudicated = outcomes | useful | negative
    return CaseCandidateAdjudication(
        label_id=label.label_id,
        registered_candidate_count=count,
        observed_outcome_count=observed,
        observed_outcome_fraction=observed / count,
        labeled_useful_candidate_count=len(useful),
        labeled_negative_candidate_count=len(negative),
        unadjudicated_candidate_count=len(candidates - adjudicated),
    )


def _validate_snapshot_binding(
    label: ExpertAttentionLabel,
    request: DecisionRequest,
    manifests: Mapping[str, ProbeManifest],
) -> None:
    if label.schema_version == 1:
        raise ValueError("version 1 labels are protocol-only and unscorable")
    if label.schema_version != 2:
        raise ValueError("unsupported expert label version")
    snapshot = label.snapshot
    if request.case_id != label.split_keys.case_id:
        raise ValueError("request case does not match label snapshot")
    if request.state_version != snapshot.state_version:
        raise ValueError("request state does not match label snapshot")
    if set(request.evidence_ids) != set(snapshot.evidence_ids):
        raise ValueError("request visible evidence does not match label snapshot")
    if snapshot.visible_evidence_sha256 != visible_evidence_sha256(request):
        raise ValueError("request visible evidence content digest does not match label snapshot")
    if snapshot.candidate_catalog_sha256 != candidate_catalog_sha256(snapshot.candidate_probes):
        raise ValueError("candidate catalog digest does not match frozen candidate references")
    if snapshot.candidate_context_sha256 != candidate_context_sha256(request):
        raise ValueError("request candidate context digest does not match label snapshot")
    candidate_ids = {candidate.probe_id for candidate in snapshot.candidate_probes}
    if {probe.probe_id for probe in request.available_probes} != candidate_ids:
        raise ValueError("request candidates do not exactly match label snapshot")
    label.validate_against_catalog(manifests)
    for candidate in snapshot.candidate_probes:
        capability = next(
            probe for probe in request.available_probes if probe.probe_id == candidate.probe_id
        )
        manifest = manifests[candidate.probe_id]
        if candidate != RegisteredProbe.from_manifest(manifest):
            raise ValueError("candidate version or catalog digest does not match trusted catalog")
        if capability.safety_class != manifest.safety.safety_class:
            raise ValueError("request candidate safety class does not match catalog")


def _validate_response_binding(response: DecisionResponse, request: DecisionRequest) -> None:
    if response.provider.role != "fast_decision":
        raise ValueError("provider response role is not fast decision")
    if (
        response.case_id != request.case_id
        or response.state_version != request.state_version
        or response.correlation_id != request.correlation_id
        or response.deadline_at != request.deadline_at
    ):
        raise ValueError("provider response does not match frozen request envelope")
    if len({proposal.dedupe_key for proposal in response.proposals}) != len(response.proposals):
        raise ValueError("provider response contains duplicate proposal keys")
    if len({proposal.probe_id for proposal in response.proposals}) != len(response.proposals):
        raise ValueError("provider response contains duplicate candidate IDs")
    if len(response.proposals) > request.max_probes:
        raise ValueError("provider response exceeds the frozen probe-count budget")
    capabilities = {probe.probe_id: probe for probe in request.available_probes}
    total_cost = 0
    for proposal in response.proposals:
        capability = capabilities.get(proposal.probe_id)
        if capability is None:
            continue
        if (
            proposal.estimated_cost_ms != capability.cost_ms
            or proposal.resource_class != capability.resource_class
            or proposal.safety_class != capability.safety_class
            or proposal.permission_class != capability.permission_class
        ):
            raise ValueError("provider proposal does not match frozen candidate capability")
        total_cost += capability.cost_ms
    if total_cost > request.budget_ms:
        raise ValueError("provider response exceeds the frozen time budget")
