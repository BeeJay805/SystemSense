"""Additive model-facing references to locally admitted measurement candidates.

These IDs are lookup keys, never executable selectors or permission grants. The
private candidate registry owns invocation details and dispatch revalidation.
Legacy probe-ID decisions use their original contract and serializer unchanged.
"""

from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import Field, model_validator

from systemsense.decision.contracts import (
    DecisionPresentationTrace,
    DiagnosticPurpose,
    PermissionClass,
    ProviderIdentity,
    ResponseValidationError,
)
from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import CaseId, EvidenceId, JsonValue
from systemsense.domain.probes import SafetyClass
from systemsense.domain.time import UtcDateTime
from systemsense.evidence.graph import EvidenceRelation
from systemsense.inference.context import EvidenceContext
from systemsense.inference.laya_runtime import LayaAttentionMicrobatch
from systemsense.orchestration.scheduler import ResourceClass

_CANDIDATE_ID = r"^cand_v1_[0-9a-f]{32}$"
_SHA256 = r"^[0-9a-f]{64}$"


class AdmittedCandidateRefV1(FrozenModel):
    """Privacy-projected identity issued by the local registry, not the model."""

    candidate_id: str = Field(pattern=_CANDIDATE_ID)
    probe_id: str = Field(min_length=1, max_length=120, pattern=r"^[a-z][a-z0-9_.-]*$")
    description: str = Field(min_length=1, max_length=240)
    manifest_sha256: str = Field(pattern=_SHA256)
    invocation_sha256: str = Field(pattern=_SHA256)
    cost_ms: int = Field(gt=0, le=120_000)
    resource_class: ResourceClass
    safety_class: SafetyClass
    permission_class: Literal[PermissionClass.READ_ONLY] = PermissionClass.READ_ONLY

    @model_validator(mode="after")
    def require_read_only_safety(self) -> AdmittedCandidateRefV1:
        if self.safety_class not in {SafetyClass.R0, SafetyClass.R1}:
            raise ValueError("candidate is not read-only safe")
        return self


class CandidateDecisionRequestV1(FrozenModel):
    """One frozen, ordered set of case/epoch-scoped candidate references."""

    schema_version: Literal[1] = 1
    request_kind: Literal["candidate_decision_v1"] = "candidate_decision_v1"
    case_id: CaseId
    state_version: int = Field(ge=0)
    correlation_id: str = Field(min_length=1, max_length=120, pattern=r"^[a-zA-Z0-9_.:-]+$")
    deadline_at: UtcDateTime
    symptom: str = Field(min_length=1, max_length=2000)
    evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=256)
    evidence_context: tuple[EvidenceContext, ...] = Field(default=(), max_length=64)
    attention_context: tuple[EvidenceContext, ...] = Field(default=(), max_length=256)
    relationships: tuple[EvidenceRelation, ...] = Field(default=(), max_length=64)
    reference_context: tuple[dict[str, JsonValue], ...] = Field(default=(), max_length=32)
    hypothesis_briefs: tuple[str, ...] = Field(default=(), max_length=16)
    available_candidates: tuple[AdmittedCandidateRefV1, ...] = Field(min_length=1, max_length=128)
    budget_ms: int = Field(gt=0, le=600_000)
    max_candidates: int = Field(gt=0, le=128)

    @model_validator(mode="after")
    def verify_frozen_scope(self) -> CandidateDecisionRequestV1:
        ids = tuple(item.candidate_id for item in self.available_candidates)
        if len(set(ids)) != len(ids):
            raise ValueError("candidate IDs must be unique")
        evidence_ids = {str(item) for item in self.evidence_ids}
        contexts = (*self.evidence_context, *self.attention_context)
        if len({str(item.evidence_id) for item in self.evidence_context}) != len(
            self.evidence_context
        ):
            raise ValueError("evidence context repeats an ID")
        if any(str(item.evidence_id) not in evidence_ids for item in contexts):
            raise ValueError("candidate decision context references unknown evidence")
        if any(
            not {str(evidence_id) for evidence_id in item.evidence_ids}.issubset(evidence_ids)
            for item in self.relationships
        ):
            raise ValueError("candidate decision relationship is not grounded")
        return self

    @property
    def candidate_manifest_sha256(self) -> str:
        """Order-sensitive content digest for snapshot and cache namespace binding."""

        encoded = json.dumps(
            [item.model_dump(mode="json") for item in self.available_candidates],
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


class CandidateProposalV1(FrozenModel):
    """An advisory choice of one offered ID; no invocation fields are accepted."""

    candidate_id: str = Field(pattern=_CANDIDATE_ID)
    purpose: DiagnosticPurpose
    priority: float = Field(ge=0, le=1)


class CandidateDecisionResponseV1(FrozenModel):
    schema_version: Literal[1] = 1
    response_kind: Literal["candidate_decision_v1"] = "candidate_decision_v1"
    provider: ProviderIdentity
    case_id: CaseId
    state_version: int = Field(ge=0)
    correlation_id: str = Field(min_length=1, max_length=120)
    deadline_at: UtcDateTime
    ranked_candidate_ids: tuple[str, ...] = Field(min_length=1, max_length=128)
    considered_candidate_ids: tuple[str, ...] = Field(min_length=1, max_length=128)
    proposals: tuple[CandidateProposalV1, ...] = Field(default=(), max_length=128)
    ranked_evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=64)
    considered_evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=256)
    degraded: bool = False
    stop_reason: str | None = Field(default=None, max_length=120)
    presentation_trace: DecisionPresentationTrace | None = None

    def validate_against(self, request: CandidateDecisionRequestV1) -> CandidateDecisionResponseV1:
        if (
            self.provider.role != "fast_decision"
            or self.case_id != request.case_id
            or self.state_version != request.state_version
            or self.correlation_id != request.correlation_id
            or self.deadline_at != request.deadline_at
        ):
            raise ResponseValidationError("candidate decision binding mismatch")
        offered = tuple(item.candidate_id for item in request.available_candidates)
        ranked = self.ranked_candidate_ids
        if (
            len(ranked) != len(offered)
            or len(set(ranked)) != len(ranked)
            or set(ranked) != set(offered)
            or self.considered_candidate_ids != offered
        ):
            raise ResponseValidationError("candidate ranking or coverage is incomplete")
        by_id = {item.candidate_id: item for item in request.available_candidates}
        affordable: list[str] = []
        remaining = request.budget_ms
        for candidate_id in ranked:
            cost = by_id[candidate_id].cost_ms
            if len(affordable) < request.max_candidates and cost <= remaining:
                affordable.append(candidate_id)
                remaining -= cost
        proposed = tuple(item.candidate_id for item in self.proposals)
        if proposed != tuple(affordable[: len(proposed)]):
            raise ResponseValidationError("candidate proposals violate trusted rank or budget")
        if not set(self.ranked_evidence_ids).issubset(request.evidence_ids) or not set(
            self.considered_evidence_ids
        ).issubset(request.evidence_ids):
            raise ResponseValidationError("candidate response references unknown evidence")
        if self.presentation_trace is not None:
            expected_order = [
                {
                    "candidate_id": item.candidate_id,
                    "description_sha256": hashlib.sha256(
                        item.description.encode("utf-8")
                    ).hexdigest(),
                }
                for item in request.available_candidates
            ]
            trace = self.presentation_trace
            if trace.format_id == "laya-worker-candidate-attention-v2":
                from systemsense.decision.semantic_packets import SERIALIZER_ID, evidence_packets

                projected = evidence_packets(
                    request.attention_context or request.evidence_context,
                    relationships=request.relationships,
                )
                if (
                    set(trace.payload)
                    != {
                        "candidate_manifest_sha256",
                        "evidence_serializer",
                        "ordered_candidates",
                        "evidence_fragments",
                        "evidence_packet_sha256",
                        "microbatches",
                    }
                    or trace.payload.get("evidence_serializer") != SERIALIZER_ID
                    or trace.payload.get("evidence_packet_sha256")
                    != [
                        hashlib.sha256(item["description"].encode("utf-8")).hexdigest()
                        for item in projected
                    ]
                ):
                    raise ResponseValidationError(
                        "candidate semantic packet trace binding mismatch"
                    )
                expected_evidence_ids = tuple(item["fragment_id"] for item in projected)
            elif trace.format_id == "laya-worker-candidate-attention-v1":
                expected_evidence_ids = candidate_evidence_fragment_ids(request)
            else:
                raise ResponseValidationError("candidate worker trace format unsupported")
            if (
                trace.provider != self.provider
                or trace.payload.get("candidate_manifest_sha256")
                != request.candidate_manifest_sha256
                or trace.payload.get("ordered_candidates") != expected_order
                or trace.payload.get("evidence_fragments") != list(expected_evidence_ids)
            ):
                raise ResponseValidationError("candidate worker trace binding mismatch")
            raw_batches = trace.payload.get("microbatches")
            if not isinstance(raw_batches, list) or not 1 <= len(raw_batches) <= 32:
                raise ResponseValidationError("candidate worker trace batches invalid")
            try:
                batches = tuple(
                    LayaAttentionMicrobatch.model_validate(item) for item in raw_batches
                )
            except ValueError as error:
                raise ResponseValidationError("candidate worker trace batch invalid") from error
            if [item.model_dump(mode="json") for item in batches] != raw_batches:
                raise ResponseValidationError("candidate worker trace batch fields invalid")
            evidence_batches = tuple(item for item in batches if item.phase == "evidence")
            probe_batches = tuple(item for item in batches if item.phase == "probe")
            if (
                tuple(item.batch_index for item in evidence_batches)
                != tuple(range(len(evidence_batches)))
                or tuple(item.batch_index for item in probe_batches)
                != tuple(range(len(probe_batches)))
                or any(item.phase == "evidence" for item in batches[len(evidence_batches) :])
                or tuple(
                    candidate_id for item in evidence_batches for candidate_id in item.candidate_ids
                )
                != expected_evidence_ids
                or tuple(
                    candidate_id for item in probe_batches for candidate_id in item.candidate_ids
                )
                != offered
                or any(item.inference_ids and item.worker_presentation is None for item in batches)
                or any(
                    origin.presentation_sha256 is None
                    for item in batches
                    for origin in item.cached_origins
                )
            ):
                raise ResponseValidationError("candidate worker trace coverage invalid")
        return self


class CandidateDecisionGapV1(FrozenModel):
    """No usable candidate ranking; no executable choice is implied."""

    schema_version: Literal[1] = 1
    response_kind: Literal["candidate_decision_gap_v1"] = "candidate_decision_gap_v1"
    provider: ProviderIdentity
    case_id: CaseId
    state_version: int = Field(ge=0)
    correlation_id: str = Field(min_length=1, max_length=120)
    deadline_at: UtcDateTime
    reason_code: Literal[
        "deadline_unavailable", "ranker_unavailable", "invalid_result", "presentation_mismatch"
    ]

    def validate_against(self, request: CandidateDecisionRequestV1) -> CandidateDecisionGapV1:
        if (
            self.provider.role != "fast_decision"
            or self.case_id != request.case_id
            or self.state_version != request.state_version
            or self.correlation_id != request.correlation_id
            or self.deadline_at != request.deadline_at
        ):
            raise ResponseValidationError("candidate decision gap binding mismatch")
        return self


def candidate_decision_request_json(request: CandidateDecisionRequestV1) -> str:
    """Canonical case/epoch/order-bound replay input, separate from legacy JSON."""

    return json.dumps(
        request.model_dump(mode="json"),
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def candidate_decision_request_sha256(request: CandidateDecisionRequestV1) -> str:
    return hashlib.sha256(candidate_decision_request_json(request).encode("utf-8")).hexdigest()


def candidate_evidence_order(request: CandidateDecisionRequestV1) -> tuple[int, ...]:
    """Frozen context index order for the candidate worker projection."""

    contexts = request.attention_context or request.evidence_context
    first_batch = min(20, len(contexts))
    sampled = (
        [index * (len(contexts) - 1) // (first_batch - 1) for index in range(first_batch)]
        if first_batch > 1
        else list(range(first_batch))
    )
    sampled_set = set(sampled)
    return (*sampled, *(index for index in range(len(contexts)) if index not in sampled_set))


def candidate_evidence_fragment_ids(request: CandidateDecisionRequestV1) -> tuple[str, ...]:
    contexts = request.attention_context or request.evidence_context
    return tuple(
        f"{contexts[index].evidence_id}:{index}:preview:0"
        for index in candidate_evidence_order(request)
    )
