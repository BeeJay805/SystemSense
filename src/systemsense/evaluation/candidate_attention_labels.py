"""Non-admitting candidate-ID review records for a future investigation dataset.

These are local review claims, not authenticated labels or training examples.
Historical probe-ID labels must never be silently reinterpreted as candidates.
"""

from __future__ import annotations

import hashlib
import json
from typing import Literal

from pydantic import Field, model_validator

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId
from systemsense.domain.time import UtcDateTime
from systemsense.evaluation.attention_labels import SplitKeys

_DIGEST = r"^[0-9a-f]{64}$"
_CANDIDATE_ID = r"^cand_v1_[0-9a-f]{32}$"
_SNAPSHOT_ID = r"^decision_snapshot_[0-9a-f]{32}$"


class FrozenCandidateRef(FrozenModel):
    """Hash-only reference to one locally admitted choice, not an authority token."""

    candidate_id: str = Field(pattern=_CANDIDATE_ID)
    probe_id: str = Field(min_length=1, max_length=120, pattern=r"^[a-z][a-z0-9_.-]*$")
    manifest_sha256: str = Field(pattern=_DIGEST)
    invocation_sha256: str = Field(pattern=_DIGEST)
    registry_entry_sha256: str = Field(pattern=_DIGEST)
    description_sha256: str = Field(pattern=_DIGEST)
    target_binding_sha256: str | None = Field(default=None, pattern=_DIGEST)
    window_binding_sha256: str | None = Field(default=None, pattern=_DIGEST)


def candidate_reference_manifest_sha256(candidates: tuple[FrozenCandidateRef, ...]) -> str:
    """Digest ordered hash-only refs, distinct from the model-visible manifest."""

    canonical = json.dumps(
        [item.model_dump(mode="json") for item in candidates],
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


class FrozenCandidateSnapshot(FrozenModel):
    """Claim about one versioned decision presentation, pending storage readback."""

    schema_version: Literal[1] = 1
    snapshot_id: str = Field(pattern=_SNAPSHOT_ID)
    case_id: CaseId
    state_version: int = Field(ge=0)
    captured_at: UtcDateTime
    request_sha256: str = Field(pattern=_DIGEST)
    request_candidate_manifest_sha256: str = Field(pattern=_DIGEST)
    reference_manifest_sha256: str = Field(pattern=_DIGEST)
    candidates: tuple[FrozenCandidateRef, ...] = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def exact_unique_manifest(self) -> FrozenCandidateSnapshot:
        ids = [item.candidate_id for item in self.candidates]
        if len(ids) != len(set(ids)):
            raise ValueError("candidate IDs must be unique")
        if self.reference_manifest_sha256 != candidate_reference_manifest_sha256(self.candidates):
            raise ValueError("ordered candidate reference manifest digest mismatch")
        return self


class ObservedCandidateOutcome(FrozenModel):
    """An outcome claim that later admission must verify against durable execution."""

    case_id: CaseId
    snapshot_id: str = Field(pattern=_SNAPSHOT_ID)
    candidate_id: str = Field(pattern=_CANDIDATE_ID)
    execution_id: ExecutionId
    started_at: UtcDateTime
    finished_at: UtcDateTime
    result: Literal["informative", "uninformative", "inconclusive", "failed"]
    evidence_ids: tuple[EvidenceId, ...] = Field(default=(), max_length=256)
    limitation_codes: tuple[str, ...] = Field(default=(), max_length=16)

    @model_validator(mode="after")
    def coherent_observation(self) -> ObservedCandidateOutcome:
        if self.started_at > self.finished_at:
            raise ValueError("outcome timestamps are reversed")
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("outcome evidence IDs must be unique")
        if self.result in {"informative", "uninformative"} and not self.evidence_ids:
            raise ValueError("observed utility requires evidence references")
        if self.result in {"inconclusive", "failed"} and not self.limitation_codes:
            raise ValueError("inconclusive or failed outcome needs a limitation")
        return self


class CandidateAdjudication(FrozenModel):
    """Unknown is not a negative; a negative needs an observed uninformative run."""

    candidate_id: str = Field(pattern=_CANDIDATE_ID)
    utility: Literal["useful", "negative", "unknown"]
    outcome: ObservedCandidateOutcome | None = None

    @model_validator(mode="after")
    def utility_requires_observation(self) -> CandidateAdjudication:
        if self.outcome is None:
            if self.utility != "unknown":
                raise ValueError("useful or negative utility requires an observed outcome")
            return self
        if self.outcome.candidate_id != self.candidate_id:
            raise ValueError("outcome candidate identity mismatch")
        expected = {
            "informative": "useful",
            "uninformative": "negative",
            "inconclusive": "unknown",
            "failed": "unknown",
        }[self.outcome.result]
        if self.utility != expected:
            raise ValueError("unknown or selected utility contradicts observed result")
        return self


class ReviewerConsentClaim(FrozenModel):
    """Receipt digests are references only; no authorizer has verified them here."""

    reviewer_id: str = Field(min_length=1, max_length=120, pattern=r"^[a-z][a-z0-9_.-]*$")
    reviewed_at: UtcDateTime
    reviewer_receipt_sha256: str | None = Field(default=None, pattern=_DIGEST)
    consent_receipt_sha256: str | None = Field(default=None, pattern=_DIGEST)
    authenticity: Literal["unverified"] = "unverified"


class ExpertCandidateLabel(FrozenModel):
    """Pre-result question plus case-scoped outcomes, never training admission."""

    schema_version: Literal[3] = 3
    label_id: str = Field(pattern=r"^label_[0-9a-f]{32}$")
    split_keys: SplitKeys
    snapshot: FrozenCandidateSnapshot
    discriminating_question: str = Field(min_length=1, max_length=1000)
    question_frozen_at: UtcDateTime
    adjudications: tuple[CandidateAdjudication, ...] = Field(min_length=1, max_length=128)
    abstain: bool
    reviewer_claim: ReviewerConsentClaim
    label_origin: Literal["human_expert_claimed"] = "human_expert_claimed"
    source_kind: Literal["live", "recorded"]
    synthetic: Literal[False] = False
    trainable: Literal[False] = False

    @model_validator(mode="after")
    def internally_consistent_review(self) -> ExpertCandidateLabel:
        if self.split_keys.case_id != self.snapshot.case_id:
            raise ValueError("split case does not match candidate snapshot case")
        if self.question_frozen_at < self.snapshot.captured_at:
            raise ValueError("discriminating question predates frozen snapshot")
        ids = tuple(item.candidate_id for item in self.adjudications)
        if ids != tuple(item.candidate_id for item in self.snapshot.candidates):
            raise ValueError("adjudications must match ordered snapshot candidate IDs")
        if self.abstain and any(item.utility != "unknown" for item in self.adjudications):
            raise ValueError("abstain cannot select useful or negative utility")
        if self.reviewer_claim.reviewed_at < self.question_frozen_at:
            raise ValueError("review precedes discriminating question")
        for item in self.adjudications:
            outcome = item.outcome
            if outcome is None:
                continue
            if outcome.case_id != self.snapshot.case_id:
                raise ValueError("outcome case does not match snapshot case")
            if outcome.snapshot_id != self.snapshot.snapshot_id:
                raise ValueError("outcome snapshot identity mismatch")
            if not (
                self.question_frozen_at
                <= outcome.started_at
                <= outcome.finished_at
                <= self.reviewer_claim.reviewed_at
            ):
                raise ValueError("question must precede observed result and review")
        return self
