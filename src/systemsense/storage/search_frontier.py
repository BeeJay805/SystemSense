"""Bounded, append-only advisory search work and persisted-result outbox.

This repository never executes a probe. A measurement reference is an opaque
candidate minted by the local capability registry, not an executable selector.
Model inference must run outside every transaction in this module.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Literal, cast

from pydantic import Field, model_validator

from systemsense.application.investigation_state import (
    InvestigationState,
    InvestigationStatus,
    InvestigationStep,
)
from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId
from systemsense.domain.probes import MeasurementWindow
from systemsense.domain.time import UtcDateTime, utc_now
from systemsense.evidence.graph import EvidenceRelation
from systemsense.evidence.retrieval import EvidenceCatalogCursor, EvidenceRelationRepository
from systemsense.storage.sqlite_store import SQLiteStore

_ITEM_LIMIT = 128
_EVENT_LIMIT = 2048
_INVESTIGATOR_PENDING_LIMIT = 32
_INVESTIGATOR_CASE_TURN_LIMIT = 32
_ID = re.compile(r"fr_v1_[0-9a-f]{64}\Z")


class FrontierItemCapacityError(ValueError):
    """The bounded frontier cannot admit another item; no partial page was stored."""

    code = "item_capacity"


class FrontierStatus(StrEnum):
    REQUESTED = "requested"
    CLAIMED = "claimed"
    ADMITTED = "admitted"
    RUNNING = "running"
    SATISFIED = "satisfied"
    FAILED = "failed"
    OBSOLETE = "obsolete"
    CANCELLED = "cancelled"
    INTERRUPTED = "interrupted"


_NEXT: dict[FrontierStatus, frozenset[FrontierStatus]] = {
    FrontierStatus.REQUESTED: frozenset(
        {FrontierStatus.CLAIMED, FrontierStatus.OBSOLETE, FrontierStatus.CANCELLED}
    ),
    FrontierStatus.CLAIMED: frozenset(
        {
            FrontierStatus.ADMITTED,
            FrontierStatus.OBSOLETE,
            FrontierStatus.CANCELLED,
            FrontierStatus.INTERRUPTED,
        }
    ),
    FrontierStatus.ADMITTED: frozenset(
        {
            FrontierStatus.RUNNING,
            FrontierStatus.OBSOLETE,
            FrontierStatus.CANCELLED,
            FrontierStatus.INTERRUPTED,
        }
    ),
    FrontierStatus.RUNNING: frozenset(
        {
            FrontierStatus.SATISFIED,
            FrontierStatus.FAILED,
            FrontierStatus.OBSOLETE,
            FrontierStatus.CANCELLED,
            FrontierStatus.INTERRUPTED,
        }
    ),
}


class FrontierReferenceV1(FrozenModel):
    """Small typed references, never paths, URLs, commands or probe arguments."""

    schema_version: Literal[1] = 1
    kind: Literal["retrieve_evidence", "measure", "review_branch", "consult_deep"]
    evidence_id: EvidenceId | None = None
    candidate_id: str | None = Field(default=None, pattern=r"^cand_v1_[0-9a-f]{32}$")
    question_id: str | None = Field(default=None, pattern=r"^question_v1_[0-9a-f]{32}$")
    branch_id: str | None = Field(default=None, pattern=r"^branch_v1_[0-9a-f]{32}$")
    window: MeasurementWindow | None = None

    @model_validator(mode="after")
    def match_kind(self) -> FrontierReferenceV1:
        fields = {
            "retrieve_evidence": (
                self.evidence_id,
                self.candidate_id,
                self.question_id,
                self.branch_id,
                self.window,
            ),
            "measure": (self.candidate_id, self.evidence_id, self.question_id, self.branch_id),
            "review_branch": (
                self.branch_id,
                self.evidence_id,
                self.candidate_id,
                self.question_id,
                self.window,
            ),
            "consult_deep": (
                self.question_id,
                self.evidence_id,
                self.candidate_id,
                self.branch_id,
                self.window,
            ),
        }[self.kind]
        if fields[0] is None or any(value is not None for value in fields[1:]):
            raise ValueError("frontier reference fields do not match kind")
        return self


class FrontierBranchReferenceV2(FrozenModel):
    """Exact immutable relation version, not a pointer to the newest edge."""

    schema_version: Literal[2] = 2
    kind: Literal["review_branch"] = "review_branch"
    branch_id: str = Field(pattern=r"^branch_v2_[0-9a-f]{32}$")
    relation_id: str = Field(pattern=r"^rel_[0-9a-f]{32}$")
    relation_version: int = Field(ge=1)
    relation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    evidence_id: None = None
    candidate_id: None = None
    question_id: None = None
    window: None = None

    @model_validator(mode="after")
    def bind_branch_identity(self) -> FrontierBranchReferenceV2:
        digest = hashlib.sha256(
            f"{self.relation_id}:{self.relation_version}:{self.relation_sha256}".encode()
        ).hexdigest()[:32]
        if self.branch_id != f"branch_v2_{digest}":
            raise ValueError("branch ID does not bind relation version and content")
        return self

    @classmethod
    def from_relation(cls, relation: EvidenceRelation) -> FrontierBranchReferenceV2:
        content_sha = hashlib.sha256(
            _canonical(relation.model_dump(mode="json")).encode()
        ).hexdigest()
        digest = hashlib.sha256(
            f"{relation.relation_id}:{relation.relation_version}:{content_sha}".encode()
        ).hexdigest()[:32]
        return cls(
            branch_id=f"branch_v2_{digest}",
            relation_id=relation.relation_id,
            relation_version=relation.relation_version,
            relation_sha256=content_sha,
        )


type FrontierReference = FrontierReferenceV1 | FrontierBranchReferenceV2


class RelevantVersionsV1(FrozenModel):
    """Only relevant dependencies are populated; unrelated changes do not stale work."""

    schema_version: Literal[1] = 1
    objective: int = Field(ge=0)
    evidence: int | None = Field(default=None, ge=0)
    graph: int | None = Field(default=None, ge=0)
    hypotheses: int | None = Field(default=None, ge=0)
    target: int | None = Field(default=None, ge=0)
    capabilities: int | None = Field(default=None, ge=0)
    serializer: int = Field(default=1, ge=1)


class FrontierItemV1(FrozenModel):
    schema_version: Literal[1] = 1
    item_id: str = Field(pattern=r"^fr_v1_[0-9a-f]{64}$")
    case_id: CaseId
    reference: FrontierReference
    versions: RelevantVersionsV1
    prerequisite_ids: tuple[str, ...] = Field(default=(), max_length=16)
    cost_ms: int = Field(default=0, ge=0, le=120_000)
    status: FrontierStatus
    created_at: UtcDateTime


class FocusDeliveryReceiptV1(FrozenModel):
    """Exact owner-confirmed focus, durable before the next case checkpoint."""

    schema_version: Literal[1] = 1
    item_id: str = Field(pattern=r"^fr_v1_[0-9a-f]{64}$")
    case_id: CaseId
    evidence_id: EvidenceId
    epoch_state_version: int = Field(ge=0)
    evidence_generation: int = Field(ge=0)
    source_record_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


class FrontierEventV1(FrozenModel):
    schema_version: Literal[1] = 1
    event_id: str = Field(pattern=r"^fre_v1_[0-9a-f]{64}$")
    case_id: CaseId
    kind: Literal["observation_added", "task_completed"]
    source_evidence_id: EvidenceId | None = None
    source_execution_id: ExecutionId | None = None
    source_record_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    source_state: Literal["present", "missing_unverifiable", "not_applicable"]
    versions: RelevantVersionsV1
    persisted_at: UtcDateTime


class FrontierOutboxGapV1(FrozenModel):
    """Exact event capacity ended; the next consumer must rescan case evidence."""

    schema_version: Literal[1] = 1
    case_id: CaseId
    reason: Literal["capacity_requires_catalog_rescan"] = "capacity_requires_catalog_rescan"
    triggered_by_evidence_id: EvidenceId | None = None
    triggered_by_execution_id: ExecutionId | None = None
    versions: RelevantVersionsV1
    marked_at: UtcDateTime


class FrontierInvestigatorTriggerV1(FrozenModel):
    """Durable investigator work reference; it confers no execution authority."""

    schema_version: Literal[1] = 1
    event_id: str = Field(pattern=r"^fre_v1_[0-9a-f]{64}$")
    case_id: CaseId
    queued_at: UtcDateTime


class FrontierInvestigatorIntakeV1(FrozenModel):
    schema_version: Literal[1] = 1
    event_id: str = Field(pattern=r"^fre_v1_[0-9a-f]{64}$")
    case_id: CaseId
    status: Literal["queued", "already_active", "already_terminal", "backpressured"]
    trigger: FrontierInvestigatorTriggerV1 | None = None


class FrontierInvestigatorSessionV1(FrozenModel):
    """One frozen, bounded reconsideration of a durable source event."""

    schema_version: Literal[1] = 1
    event_id: str = Field(pattern=r"^fre_v1_[0-9a-f]{64}$")
    case_id: CaseId
    versions: RelevantVersionsV1
    source_record_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    catalog_generation: int | None = Field(default=None, ge=0)
    catalog_cursor: None = None
    decision_budget: int = Field(ge=1, le=8)
    deadline_at: UtcDateTime
    started_at: UtcDateTime


class FrontierInvestigatorTerminalV1(FrozenModel):
    """Explicit reconsideration result, not a diagnostic or causal conclusion."""

    schema_version: Literal[1] = 1
    event_id: str = Field(pattern=r"^fre_v1_[0-9a-f]{64}$")
    case_id: CaseId
    outcome: Literal["frontier_work_recorded", "no_new_fact", "gap"]
    reason_code: Literal[
        "frontier_item_persisted",
        "all_facts_already_visible",
        "source_unverifiable",
        "budget_exhausted",
        "policy_unavailable",
        "deadline_expired",
        "stale_snapshot",
    ]
    frontier_item_ids: tuple[str, ...] = Field(default=(), max_length=8)
    source_record_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    terminal_at: UtcDateTime

    @model_validator(mode="after")
    def match_outcome(self) -> FrontierInvestigatorTerminalV1:
        valid_reasons = {
            "frontier_work_recorded": {"frontier_item_persisted"},
            "no_new_fact": {"all_facts_already_visible"},
            "gap": {
                "source_unverifiable",
                "budget_exhausted",
                "policy_unavailable",
                "deadline_expired",
                "stale_snapshot",
            },
        }
        if self.reason_code not in valid_reasons[self.outcome] or (
            self.outcome == "frontier_work_recorded"
        ) != bool(self.frontier_item_ids):
            raise ValueError("investigator terminal outcome and reason do not match")
        return self


class FrontierInvestigatorTurnV1(FrozenModel):
    """One consumed decision slot, frozen before any provider work."""

    schema_version: Literal[1] = 1
    turn_id: str = Field(pattern=r"^frit_v1_[0-9a-f]{64}$")
    event_id: str = Field(pattern=r"^fre_v1_[0-9a-f]{64}$")
    case_id: CaseId
    ordinal: int = Field(ge=1, le=8)
    owner_started_version: int = Field(ge=1)
    expected_checkpoint_version: int = Field(ge=1)
    current_versions: RelevantVersionsV1
    focused_context_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    catalog_generation: int = Field(ge=0)
    cursor_before: EvidenceCatalogCursor | None = None
    cursor_after: EvidenceCatalogCursor | None = None
    offered_refs: tuple[FrontierReference, ...] = Field(max_length=8)
    pending_tail: tuple[FrontierReference, ...] = Field(max_length=8)
    offered_item_ids: tuple[str, ...] = Field(max_length=8)
    pending_item_ids: tuple[str, ...] = Field(max_length=8)
    stale_pending_only: bool = False
    eligible_evidence_ids: tuple[EvidenceId, ...] = Field(max_length=8)
    deadline_at: UtcDateTime
    reserved_at: UtcDateTime


class FrontierPendingRefreshV2(FrozenModel):
    """One ordered, exact predecessor-to-successor item mapping."""

    schema_version: Literal[2] = 2
    predecessor_item_id: str = Field(pattern=r"^fr_v1_[0-9a-f]{64}$")
    successor_item_id: str = Field(pattern=r"^fr_v1_[0-9a-f]{64}$")


class FrontierInvestigatorTurnV2(FrontierInvestigatorTurnV1):
    """A pending tail refreshed in the reservation transaction."""

    schema_version: Literal[2] = 2  # pyright: ignore[reportIncompatibleVariableOverride]
    pending_refresh_lineage: tuple[FrontierPendingRefreshV2, ...] = Field(
        min_length=1, max_length=8
    )


class FrontierPendingRefreshV3(FrozenModel):
    """Ordered replacement of one pending item after a checkpoint epoch advance."""

    schema_version: Literal[3] = 3
    predecessor_item_id: str = Field(pattern=r"^fr_v1_[0-9a-f]{64}$")
    successor_item_id: str = Field(pattern=r"^fr_v1_[0-9a-f]{64}$")


class FrontierInvestigatorTurnV3(FrontierInvestigatorTurnV1):
    """Mixed page with immutable candidate epoch and frozen packet receipt."""

    schema_version: Literal[3] = 3  # pyright: ignore[reportIncompatibleVariableOverride]
    candidate_epoch: int = Field(ge=1)
    source_record_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    packet_receipt_id: str | None = Field(
        default=None, pattern=r"^frontier_packet_receipt_[0-9a-f]{32}$"
    )
    reissue_lineage: tuple[FrontierPendingRefreshV3, ...] = Field(default=(), max_length=8)
    offered_deferral_counts: tuple[int, ...] = Field(default=(), max_length=8)
    stale_pending_gap: bool = False

    @model_validator(mode="after")
    def validate_mixed_bounds(self) -> FrontierInvestigatorTurnV3:
        if len(self.offered_deferral_counts) != len(
            (*self.pending_item_ids, *self.offered_item_ids)
        ) or any(count < 0 or count > 7 for count in self.offered_deferral_counts):
            raise ValueError("mixed turn deferral counts are invalid")
        if len({link.predecessor_item_id for link in self.reissue_lineage}) != len(
            self.reissue_lineage
        ) or len({link.successor_item_id for link in self.reissue_lineage}) != len(
            self.reissue_lineage
        ):
            raise ValueError("mixed turn reissue lineage is duplicated")
        if self.stale_pending_gap and (
            not self.stale_pending_only
            or not self.pending_item_ids
            or self.offered_item_ids
            or self.offered_refs
            or self.pending_tail
            or self.eligible_evidence_ids
            or self.reissue_lineage
            or self.packet_receipt_id is not None
            or self.cursor_after != self.cursor_before
        ):
            raise ValueError("mixed stale pending gap has active work")
        return self


type FrontierInvestigatorTurn = (
    FrontierInvestigatorTurnV1 | FrontierInvestigatorTurnV2 | FrontierInvestigatorTurnV3
)


class FrontierInvestigatorTurnCompletionV1(FrozenModel):
    """Prepared outcome for insertion with the resulting case checkpoint."""

    schema_version: Literal[1, 2] = 1
    turn_id: str = Field(pattern=r"^frit_v1_[0-9a-f]{64}$")
    case_id: CaseId
    outcome: Literal["focused_delivery", "no_new_fact", "gap", "interrupted"]
    reason_code: Literal[
        "focused_context_delivered",
        "all_facts_already_visible",
        "stale_context",
        "policy_unavailable",
        "deadline_expired",
        "owner_interrupted",
        "source_unverifiable",
    ]
    frontier_item_ids: tuple[str, ...] = Field(default=(), max_length=8)
    remaining_item_ids: tuple[str, ...] = Field(default=(), max_length=8)
    remaining_refs: tuple[FrontierReference, ...] = Field(default=(), max_length=8)
    cursor_after: EvidenceCatalogCursor | None = None
    focused_context_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def match_outcome(self) -> FrontierInvestigatorTurnCompletionV1:
        reasons = {
            "focused_delivery": "focused_context_delivered",
            "no_new_fact": "all_facts_already_visible",
            "interrupted": "owner_interrupted",
        }
        if self.outcome in reasons and self.reason_code != reasons[self.outcome]:
            raise ValueError("investigator turn outcome and reason do not match")
        if self.outcome == "gap" and self.reason_code not in {
            "stale_context",
            "policy_unavailable",
            "deadline_expired",
            "source_unverifiable",
        }:
            raise ValueError("investigator turn gap reason is invalid")
        if (self.outcome == "focused_delivery") != bool(self.frontier_item_ids):
            raise ValueError("investigator turn item references do not match outcome")
        if self.outcome == "focused_delivery" and len(self.frontier_item_ids) != 1:
            raise ValueError("focused delivery requires one selected frontier item")
        if len(set(self.frontier_item_ids)) != len(self.frontier_item_ids):
            raise ValueError("investigator turn item references are duplicated")
        return self


class FrontierInvestigatorTurnOutcomeV1(FrontierInvestigatorTurnCompletionV1):
    schema_version: Literal[1, 2] = 2
    resulting_checkpoint_version: int | None = Field(default=None, ge=1)
    completed_at: UtcDateTime
    source_state_at_completion: (
        Literal["present", "missing_unverifiable", "not_applicable"] | None
    ) = None
    source_record_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def source_receipt_version(self) -> FrontierInvestigatorTurnOutcomeV1:
        if (self.schema_version == 2) != (self.source_state_at_completion is not None):
            raise ValueError("investigator turn source receipt is invalid")
        return self


class FrontierInvestigatorTurnCompletionV3(FrozenModel):
    """Prepared v3 result; measurement admission does not assert execution."""

    schema_version: Literal[3] = 3
    turn_id: str = Field(pattern=r"^frit_v1_[0-9a-f]{64}$")
    case_id: CaseId
    outcome: Literal[
        "focused_delivery", "measurement_admitted", "no_new_fact", "gap", "interrupted"
    ]
    reason_code: Literal[
        "focused_context_delivered",
        "registered_measurement_admitted",
        "all_facts_already_visible",
        "stale_context",
        "policy_unavailable",
        "deadline_expired",
        "owner_interrupted",
        "source_unverifiable",
    ]
    frontier_item_ids: tuple[str, ...] = Field(default=(), max_length=1)
    remaining_item_ids: tuple[str, ...] = Field(default=(), max_length=8)
    remaining_refs: tuple[FrontierReference, ...] = Field(default=(), max_length=8)
    cursor_after: EvidenceCatalogCursor | None = None
    focused_context_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    candidate_snapshot_id: str | None = Field(
        default=None, pattern=r"^frontier_decision_snapshot_[0-9a-f]{32}$"
    )
    dispatch_admission_id: str | None = Field(
        default=None, pattern=r"^candidate_admission_[0-9a-f]{32}$"
    )
    launch_continuation_id: str | None = Field(
        default=None, pattern=r"^candidate_launch_v1_[0-9a-f]{32}$"
    )

    @model_validator(mode="after")
    def validate_selection(self) -> FrontierInvestigatorTurnCompletionV3:
        reasons = {
            "focused_delivery": "focused_context_delivered",
            "measurement_admitted": "registered_measurement_admitted",
            "no_new_fact": "all_facts_already_visible",
            "interrupted": "owner_interrupted",
        }
        if self.outcome in reasons and self.reason_code != reasons[self.outcome]:
            raise ValueError("mixed turn outcome and reason do not match")
        if self.outcome == "gap" and self.reason_code not in {
            "stale_context",
            "policy_unavailable",
            "deadline_expired",
            "source_unverifiable",
        }:
            raise ValueError("mixed turn gap reason is invalid")
        if (self.outcome in {"focused_delivery", "measurement_admitted"}) != (
            len(self.frontier_item_ids) == 1
        ):
            raise ValueError("mixed turn selected item does not match outcome")
        links = (
            self.candidate_snapshot_id,
            self.dispatch_admission_id,
            self.launch_continuation_id,
        )
        if (self.outcome == "measurement_admitted") != all(link is not None for link in links):
            raise ValueError("mixed turn admission snapshot or continuation is invalid")
        if self.outcome != "measurement_admitted" and any(link is not None for link in links):
            raise ValueError("mixed turn admission links require measurement outcome")
        return self


class FrontierInvestigatorTurnOutcomeV3(FrontierInvestigatorTurnCompletionV3):
    resulting_checkpoint_version: int | None = Field(default=None, ge=1)
    completed_at: UtcDateTime
    source_state_at_completion: Literal["present", "missing_unverifiable", "not_applicable"]
    source_record_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class FrontierInvestigatorItemTransitionV1(FrozenModel):
    """Prepared terminal item transition for a checkpoint-save transaction."""

    schema_version: Literal[1] = 1
    item_id: str = Field(pattern=r"^fr_v1_[0-9a-f]{64}$")
    expected_status: FrontierStatus
    terminal_status: Literal[FrontierStatus.SATISFIED, FrontierStatus.OBSOLETE]
    reason: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$", min_length=1, max_length=120)


class FrontierInvestigatorTurnClosureIntentV1(FrozenModel):
    """Typed request to end attention after a durable final turn outcome."""

    schema_version: Literal[1, 2] = 1
    event_id: str = Field(pattern=r"^fre_v1_[0-9a-f]{64}$")
    case_id: CaseId
    final_turn_id: str = Field(pattern=r"^frit_v1_[0-9a-f]{64}$")
    outcome: Literal["focused_delivery", "no_new_fact", "gap"]
    reason_code: Literal[
        "focused_context_delivered",
        "all_facts_already_visible",
        "budget_exhausted",
        "policy_unavailable",
        "stale_context",
        "deadline_expired",
        "owner_interrupted",
        "case_stopped",
        "source_unverifiable",
    ]

    @model_validator(mode="after")
    def match_reason(self) -> FrontierInvestigatorTurnClosureIntentV1:
        expected = {
            "focused_delivery": {"focused_context_delivered"},
            "no_new_fact": {"all_facts_already_visible"},
            "gap": {
                "budget_exhausted",
                "policy_unavailable",
                "stale_context",
                "deadline_expired",
                "owner_interrupted",
                "case_stopped",
                "source_unverifiable",
            },
        }
        if self.reason_code not in expected[self.outcome]:
            raise ValueError("investigator turn closure reason is invalid")
        return self


class FrontierInvestigatorTurnClosureV1(FrontierInvestigatorTurnClosureIntentV1):
    schema_version: Literal[1, 2] = 2
    case_turn_limit: int = Field(ge=1, le=32)
    case_deadline_at: UtcDateTime
    closed_at: UtcDateTime
    terminal_event_id: str | None = None
    terminal_checkpoint_version: int | None = Field(default=None, ge=1)
    terminal_event_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    terminal_status: InvestigationStatus | None = None
    terminal_outcome: str | None = None
    source_state_at_closure: Literal["present", "missing_unverifiable", "not_applicable"] | None = (
        None
    )
    source_record_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")

    @model_validator(mode="after")
    def match_terminal_receipt(self) -> FrontierInvestigatorTurnClosureV1:
        receipt = (
            self.terminal_event_id,
            self.terminal_checkpoint_version,
            self.terminal_event_sha256,
            self.terminal_status,
            self.terminal_outcome,
        )
        if (self.reason_code == "case_stopped") != all(value is not None for value in receipt):
            raise ValueError("investigator case stop terminal receipt is invalid")
        if self.reason_code != "case_stopped" and any(value is not None for value in receipt):
            raise ValueError("investigator case stop terminal receipt is invalid")
        if (self.schema_version == 2) != (self.source_state_at_closure is not None):
            raise ValueError("investigator closure source receipt is invalid")
        return self


def _canonical(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _only_evidence_generation_advanced(
    previous: RelevantVersionsV1, current: RelevantVersionsV1
) -> bool:
    return (
        previous.evidence is not None
        and current.evidence is not None
        and previous.evidence < current.evidence
        and previous.model_copy(update={"evidence": current.evidence}) == current
    )


class SearchFrontierRepository:
    """One-shot item lifecycle plus safely reprocessable result notifications."""

    def __init__(self, store: SQLiteStore) -> None:
        self._store = store

    def same_database(self, store: SQLiteStore) -> bool:
        """A source readback must be from the frontier's own durable case store."""

        return self._store.path == store.path

    def upsert_item(
        self,
        case_id: CaseId,
        reference: FrontierReference,
        versions: RelevantVersionsV1,
        prerequisite_ids: tuple[str, ...] = (),
        cost_ms: int = 0,
    ) -> FrontierItemV1:
        with self._store.transaction():
            return self._upsert_item_locked(case_id, reference, versions, prerequisite_ids, cost_ms)

    def upsert_retrieval_page(
        self,
        case_id: CaseId,
        eligible_evidence_ids: tuple[EvidenceId, ...],
        versions: RelevantVersionsV1,
        *,
        expected_generation: int,
    ) -> tuple[FrontierItemV1, ...]:
        """Admit one complete eligible page or none, with exact same-case sources."""

        if not 1 <= len(eligible_evidence_ids) <= 8 or len(
            {str(item) for item in eligible_evidence_ids}
        ) != len(eligible_evidence_ids):
            raise ValueError("retrieval page evidence IDs must be unique and bounded")
        if expected_generation < 0 or versions.evidence != expected_generation:
            raise ValueError("retrieval page generation does not match versions")
        with self._store.transaction():
            generation_row = self._store.connection.execute(
                "SELECT generation FROM evidence_case_generations WHERE case_id=?",
                (str(case_id),),
            ).fetchone()
            if generation_row is None or int(generation_row[0]) != expected_generation:
                raise ValueError("retrieval page generation is stale")
            for evidence_id in eligible_evidence_ids:
                source = self._store.connection.execute(
                    "SELECT case_id FROM evidence WHERE evidence_id=?",
                    (str(evidence_id),),
                ).fetchone()
                if source is None or str(source[0]) != str(case_id):
                    raise ValueError("retrieval page source is not bound to case")
            try:
                return tuple(
                    self._upsert_item_locked(
                        case_id,
                        FrontierReferenceV1(kind="retrieve_evidence", evidence_id=evidence_id),
                        versions,
                    )
                    for evidence_id in eligible_evidence_ids
                )
            except ValueError as error:
                if str(error) == "frontier item limit reached":
                    raise FrontierItemCapacityError("frontier item limit reached") from error
                raise

    def upsert_mixed_page(
        self,
        case_id: CaseId,
        eligible_evidence_ids: tuple[EvidenceId, ...],
        candidate_ids: tuple[str, ...],
        versions: RelevantVersionsV1,
        *,
        expected_generation: int,
        candidate_epoch: int,
    ) -> tuple[FrontierItemV1, ...]:
        """Upsert a bounded retrieval/measurement page as one all-or-nothing unit.

        Candidate rows, costs, exact source bindings, and generation are read
        from local custody. A model supplies none of these values.
        """

        if (
            not candidate_ids
            or not 1 <= len((*eligible_evidence_ids, *candidate_ids)) <= 8
            or len({str(item) for item in eligible_evidence_ids}) != len(eligible_evidence_ids)
            or len(set(candidate_ids)) != len(candidate_ids)
            or expected_generation < 0
            or versions.evidence != expected_generation
        ):
            raise ValueError("mixed page IDs or generation are invalid")
        with self._store.transaction():
            case = self._store.case(str(case_id))
            if case is None or case.status != "collecting" or case.state_version != candidate_epoch:
                raise ValueError("mixed page case epoch is stale")
            generation_row = self._store.connection.execute(
                "SELECT generation FROM evidence_case_generations WHERE case_id=?",
                (str(case_id),),
            ).fetchone()
            if generation_row is None or int(generation_row[0]) != expected_generation:
                raise ValueError("mixed page generation is stale")
            for evidence_id in eligible_evidence_ids:
                source = self._store.connection.execute(
                    "SELECT case_id FROM evidence WHERE evidence_id=?",
                    (str(evidence_id),),
                ).fetchone()
                if source is None or str(source[0]) != str(case_id):
                    raise ValueError("mixed page evidence is not bound to case")
            candidates: list[tuple[str, int]] = []
            for candidate_id in candidate_ids:
                row = self._store.connection.execute(
                    "SELECT case_id,epoch_state_version,cost_ms FROM "
                    "case_measurement_candidates WHERE candidate_id=?",
                    (candidate_id,),
                ).fetchone()
                if row is None or str(row[0]) != str(case_id) or int(row[1]) != candidate_epoch:
                    raise ValueError("mixed page candidate is not bound to case epoch")
                candidates.append((candidate_id, int(row[2])))
            try:
                items = tuple(
                    self._upsert_item_locked(
                        case_id,
                        FrontierReferenceV1(kind="retrieve_evidence", evidence_id=evidence_id),
                        versions,
                    )
                    for evidence_id in eligible_evidence_ids
                ) + tuple(
                    self._upsert_item_locked(
                        case_id,
                        FrontierReferenceV1(kind="measure", candidate_id=candidate_id),
                        versions,
                        cost_ms=cost_ms,
                    )
                    for candidate_id, cost_ms in candidates
                )
                now = utc_now()
                for item in items[len(eligible_evidence_ids) :]:
                    self._validate_mixed_candidate(item, candidate_epoch, now)
                return items
            except ValueError as error:
                if str(error) == "frontier item limit reached":
                    raise FrontierItemCapacityError("frontier item limit reached") from error
                raise

    def _upsert_item_locked(
        self,
        case_id: CaseId,
        reference: FrontierReference,
        versions: RelevantVersionsV1,
        prerequisite_ids: tuple[str, ...] = (),
        cost_ms: int = 0,
    ) -> FrontierItemV1:
        if not self._store.connection.in_transaction:
            raise ValueError("frontier item upsert requires active transaction")
        if not 0 <= cost_ms <= 120_000 or len(prerequisite_ids) > 16:
            raise ValueError("frontier item bounds exceeded")
        if len(set(prerequisite_ids)) != len(prerequisite_ids) or any(
            _ID.fullmatch(item_id) is None for item_id in prerequisite_ids
        ):
            raise ValueError("invalid prerequisite identity")
        identity = {
            "schema_version": 1,
            "case_id": str(case_id),
            "reference": reference.model_dump(mode="json"),
            "versions": versions.model_dump(mode="json"),
            "prerequisite_ids": list(prerequisite_ids),
            "cost_ms": cost_ms,
        }
        body = _canonical(identity)
        digest = _digest(body)
        item_id = f"fr_v1_{digest}"
        connection = self._store.connection
        if (
            connection.execute("SELECT 1 FROM cases WHERE case_id=?", (str(case_id),)).fetchone()
            is None
        ):
            raise ValueError("frontier case does not exist")
        existing = connection.execute(
            "SELECT 1 FROM search_frontier_items WHERE item_id=?", (item_id,)
        ).fetchone()
        if existing is None:
            count = connection.execute(
                "SELECT COUNT(*) FROM search_frontier_items WHERE case_id=?", (str(case_id),)
            ).fetchone()
            if count is None or int(count[0]) >= _ITEM_LIMIT:
                raise ValueError("frontier item limit reached")
            for dependency in prerequisite_ids:
                prior = self.readback(dependency)
                if prior.case_id != case_id:
                    raise ValueError("prerequisite belongs to another case")
            connection.execute(
                "INSERT INTO search_frontier_items "
                "(item_id,schema_version,case_id,identity_json,identity_sha256,created_at) "
                "VALUES (?,?,?,?,?,?)",
                (item_id, 1, str(case_id), body, digest, utc_now().isoformat()),
            )
        return self.readback(item_id)

    def readback(self, item_id: str) -> FrontierItemV1:
        if _ID.fullmatch(item_id) is None:
            raise ValueError("invalid frontier item ID")
        row = self._store.connection.execute(
            "SELECT case_id,identity_json,identity_sha256,created_at "
            "FROM search_frontier_items WHERE item_id=?",
            (item_id,),
        ).fetchone()
        if row is None:
            raise ValueError("frontier item does not exist")
        body, digest = str(row[1]), str(row[2])
        if digest != _digest(body) or item_id != f"fr_v1_{digest}":
            raise ValueError("frontier identity digest mismatch")
        identity = json.loads(body)
        if body != _canonical(identity) or identity.get("case_id") != str(row[0]):
            raise ValueError("frontier identity binding mismatch")
        status = FrontierStatus.REQUESTED
        previous_hash = digest
        last_ordinal = 0
        for (
            ordinal,
            from_status,
            to_status,
            reason,
            occurred_at,
            prior_hash,
            transition_hash,
        ) in self._store.connection.execute(
            "SELECT ordinal,from_status,to_status,reason,occurred_at,previous_hash,transition_hash "
            "FROM search_frontier_transitions WHERE item_id=? ORDER BY ordinal",
            (item_id,),
        ):
            step = {
                "item_id": item_id,
                "ordinal": int(ordinal),
                "from_status": str(from_status),
                "to_status": str(to_status),
                "reason": str(reason),
                "occurred_at": str(occurred_at),
                "previous_hash": str(prior_hash),
            }
            if (
                step["ordinal"] != last_ordinal + 1
                or prior_hash != previous_hash
                or from_status != status.value
                or to_status not in {value.value for value in _NEXT.get(status, frozenset())}
                or transition_hash != _digest(_canonical(step))
            ):
                raise ValueError("frontier transition chain is invalid")
            status = FrontierStatus(str(to_status))
            previous_hash = str(transition_hash)
            last_ordinal = int(ordinal)
        return FrontierItemV1(
            item_id=item_id,
            case_id=CaseId(root=str(row[0])),
            reference=(
                FrontierBranchReferenceV2.model_validate(identity["reference"])
                if identity["reference"].get("schema_version") == 2
                else FrontierReferenceV1.model_validate(identity["reference"])
            ),
            versions=RelevantVersionsV1.model_validate(identity["versions"]),
            prerequisite_ids=tuple(identity["prerequisite_ids"]),
            cost_ms=int(identity["cost_ms"]),
            status=status,
            created_at=datetime.fromisoformat(str(row[3])),
        )

    def claim_ready(self, item_id: str, expected_versions: RelevantVersionsV1) -> FrontierItemV1:
        with self._store.transaction():
            item = self.readback(item_id)
            if item.status is not FrontierStatus.REQUESTED:
                raise ValueError("frontier item is not requested")
            if item.versions != expected_versions:
                raise ValueError("frontier relevant versions changed")
            if any(
                self.readback(prerequisite).status is not FrontierStatus.SATISFIED
                for prerequisite in item.prerequisite_ids
            ):
                raise ValueError("frontier prerequisite is not satisfied")
            return self._transition_locked(item, FrontierStatus.CLAIMED, "claimed")

    def transition(
        self,
        item_id: str,
        expected_status: FrontierStatus,
        to_status: FrontierStatus,
        reason: str,
    ) -> FrontierItemV1:
        with self._store.transaction():
            item = self.readback(item_id)
            if item.status is not expected_status:
                raise ValueError("frontier status changed before transition")
            return self._transition_locked(item, to_status, reason)

    def transition_in_transaction(
        self,
        item_id: str,
        expected_status: FrontierStatus,
        to_status: FrontierStatus,
        reason: str,
    ) -> FrontierItemV1:
        """Transition only inside the caller's case-checkpoint transaction."""

        if not self._store.connection.in_transaction:
            raise ValueError("frontier transition requires caller transaction")
        item = self.readback(item_id)
        if item.status is not expected_status:
            raise ValueError("frontier status changed before transition")
        return self._transition_locked(item, to_status, reason)

    def commit_focus_delivery_in_transaction(
        self,
        item_id: str,
        case_id: CaseId,
        evidence_id: EvidenceId,
        *,
        epoch_state_version: int,
        evidence_generation: int,
    ) -> FocusDeliveryReceiptV1:
        """Commit the selected source and transition in one owner transaction.

        Branch membership is checked again against the exact relation version.
        No model-supplied source bytes are trusted here.
        """

        if not self._store.connection.in_transaction:
            raise ValueError("focus delivery requires caller transaction")
        item = self.readback(item_id)
        case = self._store.case(str(case_id))
        branch_ok = False
        if isinstance(item.reference, FrontierBranchReferenceV2):
            relations = EvidenceRelationRepository(self._store)
            relation = relations.read_version(
                item.reference.relation_id, item.reference.relation_version
            )
            branch_ok = (
                relation is not None
                and relations.read_latest(item.reference.relation_id) == relation
                and evidence_id in relation.evidence_ids
                and FrontierBranchReferenceV2.from_relation(relation) == item.reference
            )
        reference_ok = (
            item.reference.kind == "retrieve_evidence" and item.reference.evidence_id == evidence_id
        ) or branch_ok
        if (
            item.case_id != case_id
            or case is None
            or case.state_version != epoch_state_version
            or item.status is not FrontierStatus.RUNNING
            or item.versions.evidence != evidence_generation
            or epoch_state_version < 0
            or not reference_ok
        ):
            raise ValueError("focus delivery item binding changed")
        generation = self._store.connection.execute(
            "SELECT generation FROM evidence_case_generations WHERE case_id=?",
            (str(case_id),),
        ).fetchone()
        row = self._store.connection.execute(
            "SELECT record_json FROM evidence WHERE case_id=? AND evidence_id=?",
            (str(case_id), str(evidence_id)),
        ).fetchone()
        if generation is None or int(generation[0]) != evidence_generation or row is None:
            raise ValueError("focus delivery source generation changed")
        receipt = FocusDeliveryReceiptV1(
            item_id=item_id,
            case_id=case_id,
            evidence_id=evidence_id,
            epoch_state_version=epoch_state_version,
            evidence_generation=evidence_generation,
            source_record_sha256=hashlib.sha256(str(row[0]).encode("utf-8")).hexdigest(),
        )
        body = _canonical(receipt.model_dump(mode="json"))
        self._transition_locked(item, FrontierStatus.SATISFIED, "focused_delivery_confirmed")
        self._store.connection.execute(
            "INSERT INTO search_frontier_focus_delivery_receipts "
            "(item_id,case_id,schema_version,receipt_json,receipt_sha256,committed_at) "
            "VALUES (?,?,?,?,?,?)",
            (item_id, str(case_id), 1, body, _digest(body), utc_now().isoformat()),
        )
        return receipt

    def focus_delivery_receipts(self, case_id: CaseId) -> tuple[FocusDeliveryReceiptV1, ...]:
        """Read exact immutable focus custody; corruption fails closed."""

        rows = self._store.connection.execute(
            "SELECT item_id,case_id,schema_version,receipt_json,receipt_sha256 "
            "FROM search_frontier_focus_delivery_receipts WHERE case_id=? "
            "ORDER BY committed_at,item_id LIMIT 129",
            (str(case_id),),
        ).fetchall()
        if len(rows) > _ITEM_LIMIT:
            raise ValueError("focus delivery receipt limit exceeded")
        receipts: list[FocusDeliveryReceiptV1] = []
        for item_id, stored_case_id, schema_version, body, digest in rows:
            if str(digest) != _digest(str(body)) or int(schema_version) != 1:
                raise ValueError("focus delivery receipt digest or version mismatch")
            receipt = FocusDeliveryReceiptV1.model_validate_json(str(body))
            item = self.readback(str(item_id))
            evidence = self._store.connection.execute(
                "SELECT record_json FROM evidence WHERE case_id=? AND evidence_id=?",
                (str(case_id), str(receipt.evidence_id)),
            ).fetchone()
            if (
                str(body) != _canonical(receipt.model_dump(mode="json"))
                or receipt.item_id != str(item_id)
                or receipt.case_id != case_id
                or str(stored_case_id) != str(case_id)
                or item.case_id != case_id
                or item.status is not FrontierStatus.SATISFIED
                or item.versions.evidence != receipt.evidence_generation
                or (
                    not isinstance(item.reference, FrontierBranchReferenceV2)
                    and (
                        item.reference.kind != "retrieve_evidence"
                        or item.reference.evidence_id != receipt.evidence_id
                    )
                )
                or (
                    evidence is not None
                    and hashlib.sha256(str(evidence[0]).encode("utf-8")).hexdigest()
                    != receipt.source_record_sha256
                )
            ):
                raise ValueError("focus delivery receipt binding mismatch")
            receipts.append(receipt)
        return tuple(receipts)

    def interrupt_uncertain(self, case_id: CaseId) -> tuple[str, ...]:
        """Run only under an exclusive recovered-case lease, never beside live workers."""

        interrupted: list[str] = []
        with self._store.transaction():
            rows = self._store.connection.execute(
                "SELECT item_id FROM search_frontier_items "
                "WHERE case_id=? ORDER BY created_at,item_id",
                (str(case_id),),
            ).fetchall()
            for (item_id,) in rows:
                item = self.readback(str(item_id))
                if item.status in {
                    FrontierStatus.CLAIMED,
                    FrontierStatus.ADMITTED,
                    FrontierStatus.RUNNING,
                }:
                    self._transition_locked(item, FrontierStatus.INTERRUPTED, "recovery_uncertain")
                    interrupted.append(str(item_id))
        return tuple(interrupted)

    def _transition_locked(
        self, item: FrontierItemV1, to_status: FrontierStatus, reason: str
    ) -> FrontierItemV1:
        if to_status not in _NEXT.get(item.status, frozenset()):
            raise ValueError("invalid transition")
        if not 1 <= len(reason) <= 120 or re.fullmatch(r"[a-z][a-z0-9_.-]*", reason) is None:
            raise ValueError("invalid frontier transition reason code")
        last = self._store.connection.execute(
            "SELECT ordinal,transition_hash FROM search_frontier_transitions "
            "WHERE item_id=? ORDER BY ordinal DESC LIMIT 1",
            (item.item_id,),
        ).fetchone()
        ordinal = 1 if last is None else int(last[0]) + 1
        previous_hash = item.item_id.removeprefix("fr_v1_") if last is None else str(last[1])
        occurred_at = utc_now().isoformat()
        step = {
            "item_id": item.item_id,
            "ordinal": ordinal,
            "from_status": item.status.value,
            "to_status": to_status.value,
            "reason": reason,
            "occurred_at": occurred_at,
            "previous_hash": previous_hash,
        }
        self._store.connection.execute(
            "INSERT INTO search_frontier_transitions "
            "(item_id,ordinal,from_status,to_status,reason,occurred_at,"
            "previous_hash,transition_hash) "
            "VALUES (?,?,?,?,?,?,?,?)",
            (
                item.item_id,
                ordinal,
                item.status.value,
                to_status.value,
                reason,
                occurred_at,
                previous_hash,
                _digest(_canonical(step)),
            ),
        )
        return self.readback(item.item_id)

    def append_result_event(
        self,
        case_id: CaseId,
        *,
        source_evidence_id: EvidenceId | None,
        source_execution_id: ExecutionId | None,
        versions: RelevantVersionsV1,
    ) -> FrontierEventV1 | FrontierOutboxGapV1:
        connection = self._store.connection
        if not connection.in_transaction:
            raise ValueError("result event requires an active transaction")
        if source_evidence_id is None and source_execution_id is None:
            raise ValueError("result event requires a source")
        source_record_sha256: str | None = None
        if source_evidence_id is not None:
            row = connection.execute(
                "SELECT case_id,execution_id,record_json FROM evidence WHERE evidence_id=?",
                (str(source_evidence_id),),
            ).fetchone()
            if (
                row is None
                or str(row[0]) != str(case_id)
                or (source_execution_id is not None and str(row[1]) != str(source_execution_id))
            ):
                raise ValueError("result source does not match case")
            source_record_sha256 = _digest(str(row[2]))
        if source_execution_id is not None:
            row = connection.execute(
                "SELECT case_id FROM probe_executions WHERE execution_id=?",
                (str(source_execution_id),),
            ).fetchone()
            if row is None or str(row[0]) != str(case_id):
                raise ValueError("result source does not match case")
        kind: Literal["observation_added", "task_completed"] = (
            "observation_added" if source_evidence_id is not None else "task_completed"
        )
        payload = {
            "schema_version": 1,
            "case_id": str(case_id),
            "kind": kind,
            "source_evidence_id": str(source_evidence_id) if source_evidence_id else None,
            "source_execution_id": str(source_execution_id) if source_execution_id else None,
            "source_record_sha256": source_record_sha256,
            "versions": versions.model_dump(mode="json"),
        }
        body = _canonical(payload)
        digest = _digest(body)
        event_id = f"fre_v1_{digest}"
        exists = connection.execute(
            "SELECT 1 FROM search_frontier_events WHERE event_id=?", (event_id,)
        ).fetchone()
        if exists is None:
            count = connection.execute(
                "SELECT COUNT(*) FROM search_frontier_events WHERE case_id=?", (str(case_id),)
            ).fetchone()
            if count is None or int(count[0]) >= _EVENT_LIMIT:
                marker = {
                    "schema_version": 1,
                    "case_id": str(case_id),
                    "reason": "capacity_requires_catalog_rescan",
                    "triggered_by_evidence_id": payload["source_evidence_id"],
                    "triggered_by_execution_id": payload["source_execution_id"],
                    "versions": versions.model_dump(mode="json"),
                }
                marker_json = _canonical(marker)
                connection.execute(
                    "INSERT OR IGNORE INTO search_frontier_event_overflows "
                    "(case_id,marker_json,marker_sha256,marked_at) VALUES (?,?,?,?)",
                    (str(case_id), marker_json, _digest(marker_json), utc_now().isoformat()),
                )
                gap = self.outbox_gap(case_id)
                if gap is None:
                    raise ValueError("frontier overflow marker was not persisted")
                return gap
            connection.execute(
                "INSERT INTO search_frontier_events "
                "(event_id,schema_version,case_id,source_evidence_id,source_execution_id,kind,"
                "event_json,event_sha256,persisted_at) VALUES (?,?,?,?,?,?,?,?,?)",
                (
                    event_id,
                    1,
                    str(case_id),
                    payload["source_evidence_id"],
                    payload["source_execution_id"],
                    kind,
                    body,
                    digest,
                    utc_now().isoformat(),
                ),
            )
        return self.read_event(event_id)

    def outbox_gap(self, case_id: CaseId) -> FrontierOutboxGapV1 | None:
        row = self._store.connection.execute(
            "SELECT marker_json,marker_sha256,marked_at "
            "FROM search_frontier_event_overflows WHERE case_id=?",
            (str(case_id),),
        ).fetchone()
        if row is None:
            return None
        body, digest = str(row[0]), str(row[1])
        payload = json.loads(body)
        if (
            _digest(body) != digest
            or _canonical(payload) != body
            or payload.get("case_id") != str(case_id)
        ):
            raise ValueError("frontier overflow marker binding mismatch")
        return FrontierOutboxGapV1.model_validate({**payload, "marked_at": str(row[2])})

    def read_event(self, event_id: str) -> FrontierEventV1:
        row = self._store.connection.execute(
            "SELECT case_id,source_evidence_id,source_execution_id,kind,"
            "event_json,event_sha256,persisted_at "
            "FROM search_frontier_events WHERE event_id=?",
            (event_id,),
        ).fetchone()
        if row is None:
            raise ValueError("frontier event does not exist")
        body, digest = str(row[4]), str(row[5])
        payload = json.loads(body)
        if (
            event_id != f"fre_v1_{digest}"
            or digest != _digest(body)
            or body != _canonical(payload)
            or payload.get("case_id") != str(row[0])
            or payload.get("source_evidence_id") != row[1]
            or payload.get("source_execution_id") != row[2]
            or payload.get("kind") != row[3]
            or (
                payload.get("source_record_sha256") is None
                if row[1] is not None
                else payload.get("source_record_sha256") is not None
            )
        ):
            raise ValueError("frontier event binding mismatch")
        case_id = CaseId(root=str(row[0]))
        evidence_id = EvidenceId(root=str(row[1])) if row[1] is not None else None
        execution_id = ExecutionId(root=str(row[2])) if row[2] is not None else None
        source_state: Literal["present", "missing_unverifiable", "not_applicable"] = (
            "not_applicable"
        )
        if evidence_id is not None:
            source = self._store.connection.execute(
                "SELECT case_id,execution_id,record_json FROM evidence WHERE evidence_id=?",
                (str(evidence_id),),
            ).fetchone()
            if source is None:
                source_state = "missing_unverifiable"
            else:
                if (
                    str(source[0]) != str(case_id)
                    or (execution_id is not None and str(source[1]) != str(execution_id))
                    or _digest(str(source[2])) != payload.get("source_record_sha256")
                ):
                    raise ValueError("frontier event source binding mismatch")
                source_state = "present"
        if execution_id is not None:
            source = self._store.connection.execute(
                "SELECT case_id FROM probe_executions WHERE execution_id=?", (str(execution_id),)
            ).fetchone()
            if source is None or str(source[0]) != str(case_id):
                raise ValueError("frontier event source binding mismatch")
        return FrontierEventV1(
            event_id=event_id,
            case_id=case_id,
            kind=cast(Literal["observation_added", "task_completed"], str(row[3])),
            source_evidence_id=evidence_id,
            source_execution_id=execution_id,
            source_record_sha256=payload.get("source_record_sha256"),
            source_state=source_state,
            versions=RelevantVersionsV1.model_validate(payload["versions"]),
            persisted_at=datetime.fromisoformat(str(row[6])),
        )

    def pending_events(self, case_id: CaseId, *, limit: int = 32) -> tuple[FrontierEventV1, ...]:
        if not 1 <= limit <= 64:
            raise ValueError("frontier event page limit must be 1..64")
        rows = self._store.connection.execute(
            "SELECT e.event_id FROM search_frontier_events AS e "
            "LEFT JOIN search_frontier_event_acks AS a ON a.event_id=e.event_id "
            "WHERE e.case_id=? AND a.event_id IS NULL ORDER BY e.rowid LIMIT ?",
            (str(case_id), limit),
        ).fetchall()
        return tuple(self.read_event(str(row[0])) for row in rows)

    def ack_event(self, event_id: str) -> None:
        with self._store.transaction():
            self.read_event(event_id)
            self._store.connection.execute(
                "INSERT OR IGNORE INTO search_frontier_event_acks (event_id,acknowledged_at) "
                "VALUES (?,?)",
                (event_id, utc_now().isoformat()),
            )

    def pending_investigator_events(
        self, case_id: CaseId, *, limit: int = 32
    ) -> tuple[FrontierEventV1, ...]:
        """Read the investigator's independent, closed-consumer event stream."""

        if not 1 <= limit <= 64:
            raise ValueError("frontier event page limit must be 1..64")
        rows = self._store.connection.execute(
            "SELECT e.event_id FROM search_frontier_events AS e "
            "LEFT JOIN search_frontier_investigator_event_acks AS a ON a.event_id=e.event_id "
            "WHERE e.case_id=? AND a.event_id IS NULL ORDER BY e.rowid LIMIT ?",
            (str(case_id), limit),
        ).fetchall()
        return tuple(self.read_event(str(row[0])) for row in rows)

    def intake_investigator_event(
        self, case_id: CaseId, event_id: str
    ) -> FrontierInvestigatorTriggerV1:
        """Atomically queue one bounded case trigger before acknowledging its event."""

        with self._store.transaction():
            event = self.read_event(event_id)
            if event.case_id != case_id:
                raise ValueError("investigator event belongs to another case")
            trigger = self._store.connection.execute(
                "SELECT case_id,schema_version,queued_at FROM "
                "search_frontier_investigator_triggers WHERE event_id=?",
                (event_id,),
            ).fetchone()
            ack = self._store.connection.execute(
                "SELECT 1 FROM search_frontier_investigator_event_acks WHERE event_id=?",
                (event_id,),
            ).fetchone()
            if (trigger is None) != (ack is None):
                raise ValueError("investigator intake custody is incomplete")
            if trigger is not None:
                return self._read_investigator_trigger(case_id, event_id)
            count = self._store.connection.execute(
                "SELECT COUNT(*) FROM search_frontier_investigator_triggers AS t "
                "LEFT JOIN search_frontier_investigator_terminals AS x ON x.event_id=t.event_id "
                "LEFT JOIN search_frontier_investigator_turn_closures AS c "
                "ON c.event_id=t.event_id "
                "WHERE t.case_id=? AND x.event_id IS NULL AND c.event_id IS NULL",
                (str(case_id),),
            ).fetchone()
            if count is None or int(count[0]) >= _INVESTIGATOR_PENDING_LIMIT:
                raise ValueError("investigator trigger capacity reached")
            queued_at = utc_now()
            self._store.connection.execute(
                "INSERT INTO search_frontier_investigator_triggers "
                "(event_id,case_id,schema_version,queued_at) VALUES (?,?,1,?)",
                (event_id, str(case_id), queued_at.isoformat()),
            )
            self._store.connection.execute(
                "INSERT INTO search_frontier_investigator_event_acks "
                "(event_id,acknowledged_at) VALUES (?,?)",
                (event_id, utc_now().isoformat()),
            )
            return FrontierInvestigatorTriggerV1(
                event_id=event_id, case_id=case_id, queued_at=queued_at
            )

    def intake_investigator_event_status(
        self, case_id: CaseId, event_id: str
    ) -> FrontierInvestigatorIntakeV1:
        """Typed capacity result; corruption and cross-case sources still fail closed."""

        try:
            trigger = self.intake_investigator_event(case_id, event_id)
        except ValueError as error:
            if str(error) != "investigator trigger capacity reached":
                raise
            return FrontierInvestigatorIntakeV1(
                event_id=event_id, case_id=case_id, status="backpressured"
            )
        if self.read_investigator_terminal(event_id) is not None:
            status = "already_terminal"
        elif self.read_investigator_turn_closure(event_id) is not None:
            status = "already_terminal"
        elif (
            self._store.connection.execute(
                "SELECT 1 FROM search_frontier_investigator_sessions WHERE event_id=?",
                (event_id,),
            ).fetchone()
            is not None
        ):
            self._read_investigator_session(case_id, event_id)
            status = "already_active"
        else:
            status = "queued"
        return FrontierInvestigatorIntakeV1(
            event_id=event_id, case_id=case_id, status=status, trigger=trigger
        )

    def pending_investigator_triggers(
        self, case_id: CaseId, *, limit: int = 32
    ) -> tuple[FrontierEventV1, ...]:
        """Return queued trigger sources for a later case owner."""

        if not 1 <= limit <= 64:
            raise ValueError("investigator trigger page limit must be 1..64")
        rows = self._store.connection.execute(
            "SELECT t.event_id FROM search_frontier_investigator_triggers AS t "
            "LEFT JOIN search_frontier_investigator_sessions AS s ON s.event_id=t.event_id "
            "LEFT JOIN search_frontier_investigator_terminals AS x ON x.event_id=t.event_id "
            "LEFT JOIN search_frontier_investigator_turn_closures AS c "
            "ON c.event_id=t.event_id "
            "WHERE t.case_id=? AND s.event_id IS NULL AND x.event_id IS NULL "
            "AND c.event_id IS NULL "
            "ORDER BY t.rowid LIMIT ?",
            (str(case_id), limit),
        ).fetchall()
        events: list[FrontierEventV1] = []
        for row in rows:
            event_id = str(row[0])
            self._read_investigator_trigger(case_id, event_id)
            events.append(self.read_event(event_id))
        return tuple(events)

    def _read_investigator_trigger(
        self, case_id: CaseId, event_id: str
    ) -> FrontierInvestigatorTriggerV1:
        row = self._store.connection.execute(
            "SELECT case_id,schema_version,queued_at FROM "
            "search_frontier_investigator_triggers WHERE event_id=?",
            (event_id,),
        ).fetchone()
        ack = self._store.connection.execute(
            "SELECT acknowledged_at FROM search_frontier_investigator_event_acks WHERE event_id=?",
            (event_id,),
        ).fetchone()
        if row is None or ack is None or str(row[0]) != str(case_id) or int(row[1]) != 1:
            raise ValueError("investigator trigger custody is invalid")
        try:
            event = self.read_event(event_id)
        except ValueError as error:
            raise ValueError("investigator trigger source is unavailable") from error
        if event.case_id != case_id:
            raise ValueError("investigator trigger crosses cases")
        try:
            queued_at = datetime.fromisoformat(str(row[2]))
            acknowledged_at = datetime.fromisoformat(str(ack[0]))
        except ValueError as error:
            raise ValueError("investigator trigger timestamp is invalid") from error
        if any(
            value.utcoffset() != timedelta(0) or value.isoformat() != raw
            for value, raw in ((queued_at, str(row[2])), (acknowledged_at, str(ack[0])))
        ):
            raise ValueError("investigator trigger timestamp is not canonical UTC")
        return FrontierInvestigatorTriggerV1(
            event_id=event_id, case_id=case_id, queued_at=queued_at
        )

    def start_investigator_session(
        self, case_id: CaseId, event_id: str, *, decision_budget: int
    ) -> FrontierInvestigatorSessionV1:
        """Claim one trigger for bounded reconsideration, with no model call in the transaction."""

        if not 1 <= decision_budget <= 8:
            raise ValueError("investigator decision budget must be 1..8")
        with self._store.transaction():
            self._read_investigator_trigger(case_id, event_id)
            if self.read_investigator_terminal(event_id) is not None:
                raise ValueError("investigator trigger is already terminal")
            if self.read_investigator_turn_closure(event_id) is not None:
                raise ValueError("investigator trigger is already terminal")
            active = self.active_investigator_session(case_id)
            if active is not None:
                if active.event_id == event_id and active.decision_budget == decision_budget:
                    return active
                raise ValueError("another investigator session is active for case")
            if (
                self._store.connection.execute(
                    "SELECT 1 FROM search_frontier_investigator_sessions WHERE event_id=?",
                    (event_id,),
                ).fetchone()
                is not None
            ):
                raise ValueError("investigator session custody is incomplete")
            event = self.read_event(event_id)
            started = utc_now()
            session = FrontierInvestigatorSessionV1(
                event_id=event_id,
                case_id=case_id,
                versions=event.versions,
                source_record_sha256=event.source_record_sha256,
                catalog_generation=event.versions.evidence,
                decision_budget=decision_budget,
                deadline_at=started + timedelta(seconds=30),
                started_at=started,
            )
            body = _canonical(session.model_dump(mode="json"))
            self._store.connection.execute(
                "INSERT INTO search_frontier_investigator_sessions "
                "(event_id,case_id,schema_version,record_json,record_sha256,started_at) "
                "VALUES (?,?,?,?,?,?)",
                (event_id, str(case_id), 1, body, _digest(body), started.isoformat()),
            )
            self._store.connection.execute(
                "INSERT INTO search_frontier_investigator_active_sessions (case_id,event_id) "
                "VALUES (?,?)",
                (str(case_id), event_id),
            )
            return session

    def active_investigator_session(self, case_id: CaseId) -> FrontierInvestigatorSessionV1 | None:
        row = self._store.connection.execute(
            "SELECT event_id FROM search_frontier_investigator_active_sessions WHERE case_id=?",
            (str(case_id),),
        ).fetchone()
        if row is None:
            return None
        event_id = str(row[0])
        self._read_investigator_trigger(case_id, event_id)
        if self.read_investigator_terminal(event_id) is not None:
            raise ValueError("investigator active session is already terminal")
        if self.read_investigator_turn_closure(event_id) is not None:
            raise ValueError("investigator active session is already terminal")
        return self._read_investigator_session(case_id, event_id)

    def _read_investigator_session(
        self, case_id: CaseId, event_id: str
    ) -> FrontierInvestigatorSessionV1:
        row = self._store.connection.execute(
            "SELECT case_id,schema_version,record_json,record_sha256,started_at "
            "FROM search_frontier_investigator_sessions WHERE event_id=?",
            (event_id,),
        ).fetchone()
        if row is None or str(row[0]) != str(case_id) or int(row[1]) != 1:
            raise ValueError("investigator session binding is invalid")
        body, digest = str(row[2]), str(row[3])
        payload = json.loads(body)
        if _digest(body) != digest or _canonical(payload) != body:
            raise ValueError("investigator session digest is invalid")
        session = FrontierInvestigatorSessionV1.model_validate(payload)
        event = self.read_event(event_id)
        if (
            session.event_id != event_id
            or session.case_id != case_id
            or session.versions != event.versions
            or session.source_record_sha256 != event.source_record_sha256
            or session.catalog_generation != event.versions.evidence
            or session.started_at.isoformat() != str(row[4])
        ):
            raise ValueError("investigator session source binding is invalid")
        return session

    def finish_investigator_session(
        self,
        case_id: CaseId,
        event_id: str,
        *,
        outcome: Literal["frontier_work_recorded", "no_new_fact", "gap"],
        reason_code: str | None = None,
        frontier_item_ids: tuple[str, ...] = (),
    ) -> FrontierInvestigatorTerminalV1:
        """Record one typed terminal before releasing the case's active slot."""

        with self._store.transaction():
            session = self.active_investigator_session(case_id)
            if session is None or session.event_id != event_id:
                raise ValueError("investigator session is not active for case")
            terminal_at = utc_now()
            if terminal_at < session.started_at:
                raise ValueError("investigator terminal chronology is invalid")
            valid_reasons = {
                "frontier_work_recorded": {"frontier_item_persisted"},
                "no_new_fact": {"all_facts_already_visible"},
                "gap": {
                    "source_unverifiable",
                    "budget_exhausted",
                    "policy_unavailable",
                    "deadline_expired",
                    "stale_snapshot",
                },
            }
            if reason_code is None and outcome == "frontier_work_recorded":
                reason_code = "frontier_item_persisted"
            if reason_code not in valid_reasons[outcome]:
                raise ValueError("investigator terminal reason is invalid")
            source_missing = self.read_event(event_id).source_state == "missing_unverifiable"
            generation_row = self._store.connection.execute(
                "SELECT generation FROM evidence_case_generations WHERE case_id=?",
                (str(case_id),),
            ).fetchone()
            stale = session.catalog_generation is not None and (
                generation_row is None or int(generation_row[0]) != session.catalog_generation
            )
            expired = terminal_at >= session.deadline_at
            if source_missing:
                if reason_code != "source_unverifiable":
                    raise ValueError("investigator missing source requires an explicit gap")
            elif reason_code == "source_unverifiable":
                raise ValueError("investigator source is still verifiable")
            elif expired:
                if reason_code != "deadline_expired":
                    raise ValueError("investigator deadline expired before terminal")
            elif reason_code == "deadline_expired":
                raise ValueError("investigator deadline has not expired")
            elif stale != (reason_code == "stale_snapshot"):
                raise ValueError("investigator stale snapshot requires an explicit gap")
            if outcome == "frontier_work_recorded":
                if not 1 <= len(frontier_item_ids) <= 8 or len(set(frontier_item_ids)) != len(
                    frontier_item_ids
                ):
                    raise ValueError("investigator frontier item references are invalid")
                for item_id in frontier_item_ids:
                    item = self.readback(item_id)
                    if (
                        item.case_id != case_id
                        or item.versions != session.versions
                        or not session.started_at < item.created_at <= terminal_at
                    ):
                        raise ValueError("investigator frontier item is not bound to session")
            elif frontier_item_ids:
                raise ValueError("investigator terminal reason cannot carry frontier items")
            terminal = FrontierInvestigatorTerminalV1.model_validate(
                {
                    "event_id": event_id,
                    "case_id": case_id,
                    "outcome": outcome,
                    "reason_code": reason_code,
                    "frontier_item_ids": frontier_item_ids,
                    "source_record_sha256": session.source_record_sha256,
                    "terminal_at": terminal_at,
                }
            )
            body = _canonical(terminal.model_dump(mode="json"))
            self._store.connection.execute(
                "INSERT INTO search_frontier_investigator_terminals "
                "(event_id,case_id,schema_version,record_json,record_sha256,terminal_at) "
                "VALUES (?,?,?,?,?,?)",
                (event_id, str(case_id), 1, body, _digest(body), terminal.terminal_at.isoformat()),
            )
            self._store.connection.execute(
                "DELETE FROM search_frontier_investigator_active_sessions "
                "WHERE case_id=? AND event_id=?",
                (str(case_id), event_id),
            )
            return terminal

    def read_investigator_terminal(self, event_id: str) -> FrontierInvestigatorTerminalV1 | None:
        row = self._store.connection.execute(
            "SELECT case_id,schema_version,record_json,record_sha256,terminal_at "
            "FROM search_frontier_investigator_terminals WHERE event_id=?",
            (event_id,),
        ).fetchone()
        if row is None:
            return None
        body, digest = str(row[2]), str(row[3])
        payload = json.loads(body)
        if int(row[1]) != 1 or _digest(body) != digest or _canonical(payload) != body:
            raise ValueError("investigator terminal digest is invalid")
        terminal = FrontierInvestigatorTerminalV1.model_validate(payload)
        case_id = CaseId(root=str(row[0]))
        session = self._read_investigator_session(case_id, event_id)
        if (
            terminal.event_id != event_id
            or terminal.case_id != case_id
            or terminal.source_record_sha256 != session.source_record_sha256
            or terminal.terminal_at.isoformat() != str(row[4])
        ):
            raise ValueError("investigator terminal source binding is invalid")
        if terminal.terminal_at < session.started_at:
            raise ValueError("investigator terminal chronology is invalid")
        if terminal.outcome in {"frontier_work_recorded", "no_new_fact"} and (
            terminal.terminal_at >= session.deadline_at
        ):
            raise ValueError("investigator terminal deadline is invalid")
        if (
            terminal.reason_code == "deadline_expired"
            and terminal.terminal_at < session.deadline_at
        ):
            raise ValueError("investigator terminal deadline is invalid")
        if terminal.outcome == "frontier_work_recorded":
            if not 1 <= len(terminal.frontier_item_ids) <= 8 or len(
                set(terminal.frontier_item_ids)
            ) != len(terminal.frontier_item_ids):
                raise ValueError("investigator frontier item references are invalid")
            for item_id in terminal.frontier_item_ids:
                item = self.readback(item_id)
                if (
                    item.case_id != case_id
                    or item.versions != session.versions
                    or not session.started_at < item.created_at <= terminal.terminal_at
                ):
                    raise ValueError("investigator frontier item is not bound to session")
        return terminal

    def reserve_investigator_turn(
        self,
        case_id: CaseId,
        event_id: str,
        *,
        owner_started_version: int,
        expected_checkpoint_version: int,
        current_versions: RelevantVersionsV1,
        focused_context_sha256: str,
        catalog_generation: int,
        cursor_before: EvidenceCatalogCursor | None,
        cursor_after: EvidenceCatalogCursor | None,
        offered_refs: tuple[FrontierReference, ...],
        pending_tail: tuple[FrontierReference, ...],
        offered_item_ids: tuple[str, ...],
        pending_item_ids: tuple[str, ...],
        eligible_evidence_ids: tuple[EvidenceId, ...],
        turn_deadline_at: datetime,
        refresh_pending: bool = False,
        mixed_candidate_epoch: int | None = None,
        packet_receipt_id: str | None = None,
        reissue_lineage: tuple[FrontierPendingRefreshV3, ...] = (),
        offered_deferral_counts: tuple[int, ...] = (),
        auto_reissue_retrieval: bool = False,
        mixed_stale_pending_gap: bool = False,
    ) -> FrontierInvestigatorTurn:
        """Spend a bounded slot before a model call; source-session versions remain historical."""

        with self._store.transaction():
            session = self.active_investigator_session(case_id)
            if session is None or session.event_id != event_id:
                raise ValueError("investigator session is not active for case")
            if self.read_event(event_id).source_state == "missing_unverifiable":
                raise ValueError("investigator source unverifiable")
            now = utc_now()
            state = self._investigator_checkpoint(case_id)
            if (
                state.status != InvestigationStatus.RUNNING
                or state.state_version != expected_checkpoint_version
                or not 1 <= owner_started_version <= expected_checkpoint_version
            ):
                raise ValueError("investigator owner checkpoint is stale")
            mixed = mixed_candidate_epoch is not None
            if mixed and (mixed_candidate_epoch != expected_checkpoint_version or refresh_pending):
                raise ValueError("mixed turn candidate epoch is stale")
            if mixed_stale_pending_gap and (
                not mixed
                or not pending_item_ids
                or offered_item_ids
                or offered_refs
                or pending_tail
                or eligible_evidence_ids
                or packet_receipt_id is not None
                or reissue_lineage
                or auto_reissue_retrieval
                or cursor_after != cursor_before
            ):
                raise ValueError("mixed stale pending gap has active work")
            if not mixed and (
                packet_receipt_id is not None
                or reissue_lineage
                or offered_deferral_counts
                or auto_reissue_retrieval
                or mixed_stale_pending_gap
            ):
                raise ValueError("historical turn cannot carry mixed custody")
            step = self._store.connection.execute(
                "SELECT record_json FROM investigation_steps WHERE case_id=? AND state_version=?",
                (str(case_id), owner_started_version),
            ).fetchone()
            if step is None:
                raise ValueError("investigator owner started step is unavailable")
            step_body = json.loads(str(step[0]))
            newer_owner = self._store.connection.execute(
                "SELECT 1 FROM investigation_steps WHERE case_id=? AND state_version>? "
                "AND json_extract(record_json,'$.event')='started' LIMIT 1",
                (str(case_id), owner_started_version),
            ).fetchone()
            if step_body.get("event") != "started" or newer_owner is not None:
                raise ValueError("investigator owner started step is stale")
            generation_row = self._store.connection.execute(
                "SELECT generation FROM evidence_case_generations WHERE case_id=?",
                (str(case_id),),
            ).fetchone()
            generation = 0 if generation_row is None else int(generation_row[0])
            if catalog_generation != generation or current_versions.evidence != generation:
                raise ValueError("investigator catalog generation is stale")
            if auto_reissue_retrieval:
                if not mixed or not pending_item_ids:
                    raise ValueError("mixed retrieval reissue requires a prior pending tail")
                explicit = {link.predecessor_item_id: link for link in reissue_lineage}
                ordered: list[FrontierPendingRefreshV3] = []
                refreshed: list[str] = []
                for predecessor_id in pending_item_ids:
                    predecessor = self.readback(predecessor_id)
                    if predecessor.reference.kind == "retrieve_evidence" and (
                        _only_evidence_generation_advanced(predecessor.versions, current_versions)
                    ):
                        if predecessor_id in explicit:
                            raise ValueError("mixed retrieval reissue is ambiguous")
                        try:
                            successor = self._upsert_item_locked(
                                case_id,
                                predecessor.reference,
                                current_versions,
                                prerequisite_ids=predecessor.prerequisite_ids,
                                cost_ms=predecessor.cost_ms,
                            )
                        except ValueError as error:
                            if str(error) == "frontier item limit reached":
                                raise FrontierItemCapacityError(str(error)) from error
                            raise
                        ordered.append(
                            FrontierPendingRefreshV3(
                                predecessor_item_id=predecessor_id,
                                successor_item_id=successor.item_id,
                            )
                        )
                        refreshed.append(successor.item_id)
                    elif predecessor_id in explicit:
                        link = explicit.pop(predecessor_id)
                        ordered.append(link)
                        refreshed.append(link.successor_item_id)
                    else:
                        refreshed.append(predecessor_id)
                if explicit:
                    raise ValueError("mixed reissue does not belong to pending tail")
                pending_item_ids = tuple(refreshed)
                reissue_lineage = tuple(ordered)
            if (
                now >= min(state.deadline_at, session.deadline_at)
                or turn_deadline_at <= now
                or turn_deadline_at > min(state.deadline_at, session.deadline_at)
            ):
                raise ValueError("investigator turn deadline is invalid")
            if len(offered_refs) > 8 or len(pending_tail) > 8:
                raise ValueError("investigator turn references exceed bounds")
            if refresh_pending and (
                not pending_item_ids
                or offered_item_ids
                or offered_refs
                or pending_tail
                or eligible_evidence_ids
                or cursor_after is not None
            ):
                raise ValueError("investigator pending refresh requires only an exact pending tail")
            if offered_refs or pending_tail:
                raise ValueError("investigator turn requires persisted frontier item IDs")
            if (
                len(offered_item_ids) > 8
                or len(pending_item_ids) > 8
                or len(eligible_evidence_ids) > 8
            ):
                raise ValueError("investigator turn item/page references exceed bounds")
            if (
                len(offered_item_ids)
                + len(pending_item_ids)
                + len(offered_refs)
                + len(pending_tail)
                > 8
            ):
                raise ValueError("investigator turn pending tail exceeds bounds")
            if len({_canonical(ref.model_dump(mode="json")) for ref in offered_refs}) != len(
                offered_refs
            ) or len({_canonical(ref.model_dump(mode="json")) for ref in pending_tail}) != len(
                pending_tail
            ):
                raise ValueError("investigator turn references are duplicated")
            item_refs: list[FrontierReference] = []
            stale_pending_only = mixed_stale_pending_gap
            for item_id in (*offered_item_ids, *pending_item_ids):
                item = self.readback(item_id)
                if item.case_id != case_id:
                    raise ValueError("investigator turn item is not bound to current case snapshot")
                if (
                    refresh_pending
                    and item_id in pending_item_ids
                    and (
                        item.status is not FrontierStatus.REQUESTED
                        or item.reference.kind != "retrieve_evidence"
                        or item.reference.evidence_id is None
                        or not _only_evidence_generation_advanced(item.versions, current_versions)
                    )
                ):
                    raise ValueError(
                        "investigator pending refresh item is not current and retrievable"
                    )
                if item.versions != current_versions and not mixed_stale_pending_gap:
                    if item_id not in pending_item_ids or not _only_evidence_generation_advanced(
                        item.versions, current_versions
                    ):
                        raise ValueError(
                            "investigator turn item is not bound to current case snapshot"
                        )
                    stale_pending_only = True
                item_refs.append(item.reference)
            if len(set((*offered_item_ids, *pending_item_ids))) != len(
                (*offered_item_ids, *pending_item_ids)
            ):
                raise ValueError("investigator turn item IDs are duplicated")
            if mixed:
                if any(
                    self.readback(item_id).status is not FrontierStatus.REQUESTED
                    for item_id in (*offered_item_ids, *pending_item_ids)
                ):
                    raise ValueError("mixed turn item has already been selected")
                measurement_ids = tuple(
                    item_id
                    for item_id in (*offered_item_ids, *pending_item_ids)
                    if self.readback(item_id).reference.kind == "measure"
                )
                for item_id in measurement_ids:
                    if not mixed_stale_pending_gap:
                        self._validate_mixed_candidate(
                            self.readback(item_id), expected_checkpoint_version, now
                        )
                if measurement_ids and packet_receipt_id is None and not mixed_stale_pending_gap:
                    raise ValueError("mixed turn measurement requires frozen packet receipt")
                if packet_receipt_id is not None:
                    from systemsense.storage.frontier_packet_receipts import (
                        FrontierPacketReceiptRepository,
                    )

                    receipt = FrontierPacketReceiptRepository(self._store).readback(
                        packet_receipt_id
                    )
                    if (
                        receipt.case_id != case_id
                        or receipt.epoch_state_version != mixed_candidate_epoch
                        or receipt.case_generation != generation
                    ):
                        raise ValueError("mixed turn packet receipt is stale")
            represented = {
                str(ref.evidence_id)
                for ref in (*offered_refs, *pending_tail, *item_refs)
                if ref.kind == "retrieve_evidence" and ref.evidence_id is not None
            }
            eligible_ids = tuple(str(evidence_id) for evidence_id in eligible_evidence_ids)
            if len(set(eligible_ids)) != len(eligible_ids) or not set(eligible_ids) <= represented:
                raise ValueError("investigator eligible evidence is missing from frozen page")
            historical_pending_ids = {
                str(self.readback(item_id).reference.evidence_id)
                for item_id in pending_item_ids
                if self.readback(item_id).reference.kind == "retrieve_evidence"
                and self.readback(item_id).reference.evidence_id is not None
            }
            for evidence_id in represented | set(eligible_ids):
                source = self._store.connection.execute(
                    "SELECT case_id FROM evidence WHERE evidence_id=?",
                    (evidence_id,),
                ).fetchone()
                if (
                    source is None
                    and stale_pending_only
                    and not refresh_pending
                    and evidence_id in historical_pending_ids
                    and evidence_id not in eligible_ids
                    and not offered_item_ids
                ):
                    # A deleted row remains a valid historical pending reference.
                    # The stale-continuation invariant below forbids a new page;
                    # completion may only record an explicit unresolved gap.
                    continue
                if source is None or str(source[0]) != str(case_id):
                    raise ValueError("investigator evidence reference is not source-bound")
            open_turn = self._store.connection.execute(
                "SELECT t.turn_id FROM search_frontier_investigator_turns AS t "
                "LEFT JOIN search_frontier_investigator_turn_outcomes AS o ON o.turn_id=t.turn_id "
                "WHERE t.event_id=? AND o.turn_id IS NULL LIMIT 1",
                (event_id,),
            ).fetchone()
            if open_turn is not None:
                raise ValueError("investigator turn is unfinished")
            count = self._store.connection.execute(
                "SELECT COUNT(*) FROM search_frontier_investigator_turns WHERE event_id=?",
                (event_id,),
            ).fetchone()
            case_count = self._store.connection.execute(
                "SELECT COUNT(*) FROM search_frontier_investigator_turns WHERE case_id=?",
                (str(case_id),),
            ).fetchone()
            assert count is not None and case_count is not None
            ordinal = int(count[0]) + 1
            prior_turn: FrontierInvestigatorTurn | None = None
            prior_outcome: (
                FrontierInvestigatorTurnOutcomeV1 | FrontierInvestigatorTurnOutcomeV3 | None
            ) = None
            if ordinal == 1:
                if cursor_before is not None or pending_item_ids or pending_tail:
                    raise ValueError("investigator first turn must start before catalog cursor")
            else:
                prior_id = f"frit_v1_{_digest(f'{event_id}:{ordinal - 1}')}"
                prior_turn = self.read_investigator_turn(prior_id)
                prior_outcome = self.read_investigator_turn_outcome(prior_id)
                if (
                    prior_outcome is None
                    or cursor_before != prior_outcome.cursor_after
                    or (not mixed and pending_item_ids != prior_outcome.remaining_item_ids)
                    or pending_tail != prior_outcome.remaining_refs
                ):
                    raise ValueError("investigator turn catalog cursor is stale")
                if mixed:
                    predecessors = tuple(link.predecessor_item_id for link in reissue_lineage)
                    replacement = {
                        link.predecessor_item_id: link.successor_item_id for link in reissue_lineage
                    }
                    if predecessors != tuple(
                        item_id
                        for item_id in prior_outcome.remaining_item_ids
                        if item_id in replacement
                    ) or pending_item_ids != tuple(
                        replacement.get(item_id, item_id)
                        for item_id in prior_outcome.remaining_item_ids
                    ):
                        raise ValueError("mixed turn reissue continuation is invalid")
                    for link in reissue_lineage:
                        predecessor = self.readback(link.predecessor_item_id)
                        if predecessor.status is not FrontierStatus.REQUESTED:
                            raise ValueError("mixed turn reissue predecessor is not pending")
                        self._transition_locked(
                            predecessor, FrontierStatus.OBSOLETE, "mixed_reissue"
                        )
                        self._validate_mixed_reissue(link, case_id, expected_checkpoint_version)
                if (
                    prior_outcome.cursor_after is not None
                    and _only_evidence_generation_advanced(
                        prior_turn.current_versions, current_versions
                    )
                    and not refresh_pending
                    and not mixed
                ):
                    stale_pending_only = True
                if (
                    not mixed
                    and (pending_item_ids or pending_tail)
                    and (
                        offered_item_ids
                        or offered_refs
                        or eligible_evidence_ids
                        or (cursor_after != cursor_before and not refresh_pending)
                    )
                ):
                    raise ValueError("investigator pending tail must precede a new page")
            if (
                stale_pending_only
                and not refresh_pending
                and (
                    offered_item_ids
                    or offered_refs
                    or eligible_evidence_ids
                    or cursor_after != cursor_before
                )
            ):
                raise ValueError("investigator stale pending turn cannot admit a new page")
            if (
                ordinal > session.decision_budget
                or int(case_count[0]) >= _INVESTIGATOR_CASE_TURN_LIMIT
            ):
                raise ValueError("investigator turn budget exhausted")
            mixed_deferrals: tuple[int, ...] = ()
            if mixed:
                prior_counts: dict[str, int] = {}
                if ordinal > 1:
                    assert prior_turn is not None and prior_outcome is not None
                    if isinstance(prior_turn, FrontierInvestigatorTurnV3):
                        prior_counts = dict(
                            zip(
                                (*prior_turn.pending_item_ids, *prior_turn.offered_item_ids),
                                prior_turn.offered_deferral_counts,
                                strict=True,
                            )
                        )
                    else:
                        prior_counts = {item_id: 0 for item_id in prior_outcome.remaining_item_ids}
                replacement = {
                    link.successor_item_id: link.predecessor_item_id for link in reissue_lineage
                }
                mixed_deferrals = tuple(
                    prior_counts.get(replacement.get(item_id, item_id), -1)
                    + (0 if mixed_stale_pending_gap else 1)
                    if item_id in pending_item_ids
                    else 0
                    for item_id in (*pending_item_ids, *offered_item_ids)
                )
                if any(count > 7 for count in mixed_deferrals) or (
                    offered_deferral_counts and offered_deferral_counts != mixed_deferrals
                ):
                    raise ValueError("mixed turn deferral aging limit or custody is invalid")
            lineage: tuple[FrontierPendingRefreshV2, ...] = ()
            if refresh_pending:
                if ordinal == 1 or not stale_pending_only:
                    raise ValueError(
                        "investigator pending refresh requires advanced evidence generation"
                    )
                predecessor_ids = pending_item_ids
                successors: list[str] = []
                mappings: list[FrontierPendingRefreshV2] = []
                for predecessor_id in predecessor_ids:
                    predecessor = self.readback(predecessor_id)
                    try:
                        successor = self._upsert_item_locked(
                            case_id,
                            predecessor.reference,
                            current_versions,
                            prerequisite_ids=predecessor.prerequisite_ids,
                            cost_ms=predecessor.cost_ms,
                        )
                    except ValueError as error:
                        if str(error) == "frontier item limit reached":
                            raise FrontierItemCapacityError(
                                "frontier item limit reached"
                            ) from error
                        raise
                    if (
                        successor.item_id == predecessor_id
                        or successor.status is not FrontierStatus.REQUESTED
                    ):
                        raise ValueError("investigator pending refresh successor is unavailable")
                    successors.append(successor.item_id)
                    mappings.append(
                        FrontierPendingRefreshV2(
                            predecessor_item_id=predecessor_id,
                            successor_item_id=successor.item_id,
                        )
                    )
                if len(set(successors)) != len(successors):
                    raise ValueError("investigator pending refresh successor IDs are duplicated")
                for predecessor_id in predecessor_ids:
                    self._transition_locked(
                        self.readback(predecessor_id),
                        FrontierStatus.OBSOLETE,
                        "pending_tail_refreshed",
                    )
                pending_item_ids = tuple(successors)
                lineage = tuple(mappings)
                stale_pending_only = False
            turn_id = f"frit_v1_{_digest(f'{event_id}:{ordinal}')}"
            turn_data = dict(
                turn_id=turn_id,
                event_id=event_id,
                case_id=case_id,
                ordinal=ordinal,
                owner_started_version=owner_started_version,
                expected_checkpoint_version=expected_checkpoint_version,
                current_versions=current_versions,
                focused_context_sha256=focused_context_sha256,
                catalog_generation=catalog_generation,
                cursor_before=cursor_before,
                cursor_after=cursor_after,
                offered_refs=offered_refs,
                pending_tail=pending_tail,
                offered_item_ids=offered_item_ids,
                pending_item_ids=pending_item_ids,
                stale_pending_only=stale_pending_only,
                eligible_evidence_ids=eligible_evidence_ids,
                deadline_at=turn_deadline_at,
                reserved_at=now,
            )
            turn: FrontierInvestigatorTurn
            if refresh_pending:
                turn = FrontierInvestigatorTurnV2.model_validate(
                    {**turn_data, "schema_version": 2, "pending_refresh_lineage": lineage}
                )
            elif mixed:
                turn = FrontierInvestigatorTurnV3.model_validate(
                    {
                        **turn_data,
                        "schema_version": 3,
                        "candidate_epoch": mixed_candidate_epoch,
                        "source_record_sha256": self.read_event(event_id).source_record_sha256,
                        "packet_receipt_id": packet_receipt_id,
                        "reissue_lineage": reissue_lineage,
                        "offered_deferral_counts": mixed_deferrals,
                        "stale_pending_gap": mixed_stale_pending_gap,
                    }
                )
            else:
                turn = FrontierInvestigatorTurnV1.model_validate(turn_data)
            body = _canonical(turn.model_dump(mode="json"))
            self._store.connection.execute(
                "INSERT INTO search_frontier_investigator_turns "
                "(turn_id,event_id,case_id,ordinal,schema_version,"
                "record_json,record_sha256,reserved_at) "
                "VALUES (?,?,?,?,?,?,?,?)",
                (
                    turn_id,
                    event_id,
                    str(case_id),
                    ordinal,
                    turn.schema_version,
                    body,
                    _digest(body),
                    now.isoformat(),
                ),
            )
            return turn

    def investigator_turns(
        self, case_id: CaseId, event_id: str
    ) -> tuple[FrontierInvestigatorTurn, ...]:
        self._read_investigator_session(case_id, event_id)
        rows = self._store.connection.execute(
            "SELECT turn_id FROM search_frontier_investigator_turns "
            "WHERE case_id=? AND event_id=? ORDER BY ordinal",
            (str(case_id), event_id),
        ).fetchall()
        return tuple(self.read_investigator_turn(str(row[0])) for row in rows)

    def _validate_mixed_candidate(self, item: FrontierItemV1, epoch: int, now: datetime) -> None:
        candidate_id = item.reference.candidate_id
        if item.reference.kind != "measure" or candidate_id is None:
            raise ValueError("mixed turn candidate reference is invalid")
        row = self._store.connection.execute(
            "SELECT case_id,epoch_state_version,cost_ms,source_evidence_id,"
            "source_evidence_sha256,dependency_bindings_json,expires_at "
            "FROM case_measurement_candidates WHERE candidate_id=?",
            (candidate_id,),
        ).fetchone()
        if (
            row is None
            or str(row[0]) != str(item.case_id)
            or int(row[1]) != epoch
            or int(row[2]) != item.cost_ms
            or now >= datetime.fromisoformat(str(row[6]))
        ):
            raise ValueError("mixed turn candidate is unregistered or stale")
        bindings = [(str(row[3]), str(row[4]))]
        bindings.extend(
            (str(value["evidence_id"]), str(value["sha256"])) for value in json.loads(str(row[5]))
        )
        for evidence_id, digest in bindings:
            source = self._store.connection.execute(
                "SELECT record_json FROM evidence WHERE case_id=? AND evidence_id=?",
                (str(item.case_id), evidence_id),
            ).fetchone()
            if source is None or _digest(str(source[0])) != digest:
                raise ValueError("mixed turn candidate source binding changed")
        if (
            self._store.connection.execute(
                "SELECT 1 FROM candidate_dispatch_admissions WHERE candidate_id=?",
                (candidate_id,),
            ).fetchone()
            is not None
        ):
            raise ValueError("mixed turn candidate has already been admitted")

    def _validate_mixed_reissue(
        self,
        link: FrontierPendingRefreshV3,
        case_id: CaseId,
        epoch: int,
        *,
        require_requested_successor: bool = True,
    ) -> None:
        predecessor = self.readback(link.predecessor_item_id)
        successor = self.readback(link.successor_item_id)
        if (
            predecessor.case_id != case_id
            or successor.case_id != case_id
            or predecessor.status is not FrontierStatus.OBSOLETE
            or (require_requested_successor and successor.status is not FrontierStatus.REQUESTED)
            or predecessor.reference.kind != successor.reference.kind
            or predecessor.prerequisite_ids != successor.prerequisite_ids
            or predecessor.cost_ms != successor.cost_ms
        ):
            raise ValueError("mixed turn reissue item binding is invalid")
        if predecessor.reference.kind == "retrieve_evidence":
            if (
                predecessor.reference != successor.reference
                or not _only_evidence_generation_advanced(predecessor.versions, successor.versions)
            ):
                raise ValueError("mixed turn retrieval reissue binding changed")
            return
        if (
            predecessor.reference.kind != "measure"
            or predecessor.reference.candidate_id is None
            or successor.reference.candidate_id is None
            or predecessor.reference.candidate_id == successor.reference.candidate_id
        ):
            raise ValueError("mixed turn candidate reissue identity is invalid")
        rows = self._store.connection.execute(
            "SELECT candidate_id,case_id,epoch_state_version,probe_id,manifest_version,"
            "manifest_sha256,invocation_sha256,observable,target_handle,source_evidence_id,"
            "source_evidence_sha256,dependency_bindings_json,dependency_sha256,cost_ms,"
            "resource_class,safety_class,description "
            "FROM case_measurement_candidates WHERE candidate_id IN (?,?)",
            (predecessor.reference.candidate_id, successor.reference.candidate_id),
        ).fetchall()
        by_id = {str(row[0]): tuple(row) for row in rows}
        old = by_id.get(predecessor.reference.candidate_id)
        new = by_id.get(successor.reference.candidate_id)
        if (
            old is None
            or new is None
            or str(old[1]) != str(case_id)
            or str(new[1]) != str(case_id)
            or int(old[2]) >= epoch
            or int(new[2]) != epoch
            or old[3:] != new[3:]
        ):
            raise ValueError("mixed turn reissue candidate binding changed")

    def read_investigator_turn(self, turn_id: str) -> FrontierInvestigatorTurn:
        row = self._store.connection.execute(
            "SELECT event_id,case_id,ordinal,schema_version,record_json,record_sha256,reserved_at "
            "FROM search_frontier_investigator_turns WHERE turn_id=?",
            (turn_id,),
        ).fetchone()
        if row is None:
            raise ValueError("investigator turn is unavailable")
        body = str(row[4])
        payload = json.loads(body)
        if (
            int(row[3]) not in {1, 2, 3}
            or _digest(body) != str(row[5])
            or _canonical(payload) != body
        ):
            raise ValueError("investigator turn digest is invalid")
        turn: FrontierInvestigatorTurn
        if int(row[3]) == 3:
            turn = FrontierInvestigatorTurnV3.model_validate(payload)
        elif int(row[3]) == 2:
            turn = FrontierInvestigatorTurnV2.model_validate(payload)
        else:
            turn = FrontierInvestigatorTurnV1.model_validate(payload)
        session = self._read_investigator_session(CaseId(root=str(row[1])), str(row[0]))
        if (
            turn.turn_id != turn_id
            or turn.event_id != str(row[0])
            or str(turn.case_id) != str(row[1])
            or turn.ordinal != int(row[2])
            or turn.schema_version != int(row[3])
            or turn.reserved_at.isoformat() != str(row[6])
            or turn.ordinal > session.decision_budget
            or not session.started_at <= turn.reserved_at < turn.deadline_at <= session.deadline_at
            or turn_id != f"frit_v1_{_digest(f'{turn.event_id}:{turn.ordinal}')}"
        ):
            raise ValueError("investigator turn custody is invalid")
        stale_pending_only = isinstance(turn, FrontierInvestigatorTurnV3) and turn.stale_pending_gap
        for item_id in (*turn.offered_item_ids, *turn.pending_item_ids):
            item = self.readback(item_id)
            if item.case_id != turn.case_id:
                raise ValueError("investigator turn item crosses cases")
            if item.versions != turn.current_versions and not (
                isinstance(turn, FrontierInvestigatorTurnV3) and turn.stale_pending_gap
            ):
                if item_id not in turn.pending_item_ids or not _only_evidence_generation_advanced(
                    item.versions, turn.current_versions
                ):
                    raise ValueError("investigator turn item versions are invalid")
                stale_pending_only = True
        if isinstance(turn, FrontierInvestigatorTurnV2):
            if (
                turn.stale_pending_only
                or turn.cursor_after is not None
                or turn.offered_item_ids
                or turn.offered_refs
                or turn.pending_tail
                or turn.eligible_evidence_ids
                or tuple(link.successor_item_id for link in turn.pending_refresh_lineage)
                != turn.pending_item_ids
            ):
                raise ValueError("investigator pending refresh custody is invalid")
            for link in turn.pending_refresh_lineage:
                predecessor = self.readback(link.predecessor_item_id)
                successor = self.readback(link.successor_item_id)
                if (
                    predecessor.case_id != turn.case_id
                    or successor.case_id != turn.case_id
                    or predecessor.status is not FrontierStatus.OBSOLETE
                    or predecessor.reference.kind != "retrieve_evidence"
                    or predecessor.reference != successor.reference
                    or predecessor.prerequisite_ids != successor.prerequisite_ids
                    or predecessor.cost_ms != successor.cost_ms
                    or successor.versions != turn.current_versions
                    or not _only_evidence_generation_advanced(
                        predecessor.versions, successor.versions
                    )
                ):
                    raise ValueError("investigator pending refresh lineage is invalid")
        if isinstance(turn, FrontierInvestigatorTurnV3):
            source = self.read_event(turn.event_id)
            if (
                turn.candidate_epoch != turn.expected_checkpoint_version
                or turn.source_record_sha256 != source.source_record_sha256
            ):
                raise ValueError("mixed turn source or candidate epoch is invalid")
            if turn.packet_receipt_id is not None:
                from systemsense.storage.frontier_packet_receipts import (
                    FrontierPacketReceiptV1,
                )

                receipt_row = self._store.connection.execute(
                    "SELECT receipt_json,receipt_sha256 FROM frontier_packet_receipts "
                    "WHERE receipt_id=?",
                    (turn.packet_receipt_id,),
                )
                receipt_data = receipt_row.fetchone()
                if receipt_data is None:
                    raise ValueError("mixed turn receipt is unavailable")
                receipt_body = str(receipt_data[0])
                if _digest(receipt_body) != str(receipt_data[1]):
                    raise ValueError("mixed turn receipt digest is invalid")
                receipt = FrontierPacketReceiptV1.model_validate_json(receipt_body)
                if (
                    receipt.receipt_id != turn.packet_receipt_id
                    or receipt.case_id != turn.case_id
                    or receipt.epoch_state_version != turn.candidate_epoch
                    or receipt.case_generation != turn.catalog_generation
                ):
                    raise ValueError("mixed turn receipt binding is invalid")
            elif not turn.stale_pending_gap and any(
                self.readback(item_id).reference.kind == "measure"
                for item_id in (*turn.offered_item_ids, *turn.pending_item_ids)
            ):
                raise ValueError("mixed turn measurement lacks packet receipt")
            if turn.reissue_lineage:
                for link in turn.reissue_lineage:
                    self._validate_mixed_reissue(
                        link,
                        turn.case_id,
                        turn.candidate_epoch,
                        require_requested_successor=False,
                    )
        if turn.ordinal > 1:
            prior_id = f"frit_v1_{_digest(f'{turn.event_id}:{turn.ordinal - 1}')}"
            prior_turn = self.read_investigator_turn(prior_id)
            prior_outcome = self.read_investigator_turn_outcome(prior_id)
            if (
                prior_outcome is None
                or turn.cursor_before != prior_outcome.cursor_after
                or (
                    not isinstance(turn, (FrontierInvestigatorTurnV2, FrontierInvestigatorTurnV3))
                    and turn.pending_item_ids != prior_outcome.remaining_item_ids
                )
            ):
                raise ValueError("investigator turn continuation is invalid")
            if isinstance(turn, FrontierInvestigatorTurnV2) and (
                tuple(link.predecessor_item_id for link in turn.pending_refresh_lineage)
                != prior_outcome.remaining_item_ids
                or not _only_evidence_generation_advanced(
                    prior_turn.current_versions, turn.current_versions
                )
            ):
                raise ValueError("investigator pending refresh continuation is invalid")
            if isinstance(turn, FrontierInvestigatorTurnV3):
                predecessors = tuple(link.predecessor_item_id for link in turn.reissue_lineage)
                replacement = {
                    link.predecessor_item_id: link.successor_item_id
                    for link in turn.reissue_lineage
                }
                if predecessors != tuple(
                    item_id
                    for item_id in prior_outcome.remaining_item_ids
                    if item_id in replacement
                ) or turn.pending_item_ids != tuple(
                    replacement.get(item_id, item_id)
                    for item_id in prior_outcome.remaining_item_ids
                ):
                    raise ValueError("mixed turn pending continuation is invalid")
                prior_counts = (
                    dict(
                        zip(
                            (*prior_turn.pending_item_ids, *prior_turn.offered_item_ids),
                            prior_turn.offered_deferral_counts,
                            strict=True,
                        )
                    )
                    if isinstance(prior_turn, FrontierInvestigatorTurnV3)
                    else {item_id: 0 for item_id in prior_outcome.remaining_item_ids}
                )
                replacement = {
                    link.successor_item_id: link.predecessor_item_id
                    for link in turn.reissue_lineage
                }
                expected_counts = tuple(
                    prior_counts.get(replacement.get(item_id, item_id), -1)
                    + (0 if turn.stale_pending_gap else 1)
                    if item_id in turn.pending_item_ids
                    else 0
                    for item_id in (*turn.pending_item_ids, *turn.offered_item_ids)
                )
                if turn.offered_deferral_counts != expected_counts:
                    raise ValueError("mixed turn deferral custody is invalid")
            if (
                prior_outcome.cursor_after is not None
                and _only_evidence_generation_advanced(
                    prior_turn.current_versions, turn.current_versions
                )
                and not isinstance(turn, (FrontierInvestigatorTurnV2, FrontierInvestigatorTurnV3))
            ):
                stale_pending_only = True
        if stale_pending_only and (
            turn.offered_item_ids
            or turn.offered_refs
            or turn.eligible_evidence_ids
            or turn.cursor_after != turn.cursor_before
        ):
            raise ValueError("investigator stale continuation admitted a new page")
        if stale_pending_only != turn.stale_pending_only:
            raise ValueError("investigator stale pending custody is invalid")
        if (
            isinstance(turn, FrontierInvestigatorTurnV3)
            and turn.ordinal == 1
            and any(turn.offered_deferral_counts)
        ):
            raise ValueError("mixed first turn deferrals are invalid")
        return turn

    def complete_investigator_turn_in_transaction(
        self,
        prepared: FrontierInvestigatorTurnCompletionV1 | FrontierInvestigatorTurnCompletionV3,
        *,
        expected_checkpoint_version: int,
    ) -> FrontierInvestigatorTurnOutcomeV1 | FrontierInvestigatorTurnOutcomeV3:
        """Append an outcome within the caller's checkpoint-save transaction."""

        if not self._store.connection.in_transaction:
            raise ValueError("investigator turn completion requires caller transaction")
        if isinstance(prepared, FrontierInvestigatorTurnCompletionV3):
            return self._complete_mixed_turn_in_transaction(
                prepared, expected_checkpoint_version=expected_checkpoint_version
            )
        turn = self.read_investigator_turn(prepared.turn_id)
        if isinstance(turn, FrontierInvestigatorTurnV3):
            raise ValueError("mixed turn requires v3 completion")
        if prepared.case_id != turn.case_id:
            raise ValueError("investigator turn completion crosses cases")
        if self.read_investigator_turn_outcome(turn.turn_id) is not None:
            raise ValueError("investigator turn already completed")
        state = self._investigator_checkpoint(turn.case_id)
        case_row = self._store.connection.execute(
            "SELECT state_version FROM cases WHERE case_id=?",
            (str(turn.case_id),),
        ).fetchone()
        if (
            case_row is None
            or state.state_version != expected_checkpoint_version
            or int(case_row[0]) != expected_checkpoint_version
            or expected_checkpoint_version != turn.expected_checkpoint_version + 1
        ):
            raise ValueError("investigator completion checkpoint is stale")
        newer_owner = self._store.connection.execute(
            "SELECT 1 FROM investigation_steps WHERE case_id=? AND state_version>? "
            "AND json_extract(record_json,'$.event')='started' LIMIT 1",
            (str(turn.case_id), turn.owner_started_version),
        ).fetchone()
        if newer_owner is not None:
            raise ValueError("investigator completion owner is stale")
        if prepared.focused_context_sha256 != turn.focused_context_sha256:
            raise ValueError("investigator completion focused context is stale")
        source = self.read_event(turn.event_id)
        source_missing = source.source_state == "missing_unverifiable"
        if source_missing and (
            prepared.outcome != "gap" or prepared.reason_code != "source_unverifiable"
        ):
            raise ValueError("investigator source unverifiable requires explicit gap")
        if not source_missing and prepared.reason_code == "source_unverifiable":
            raise ValueError("investigator source is still verifiable")
        if turn.stale_pending_only and (
            prepared.outcome != "gap"
            or prepared.reason_code not in {"stale_context", "source_unverifiable"}
        ):
            raise ValueError("investigator stale pending turn requires explicit stale_context gap")
        if prepared.cursor_after != turn.cursor_after:
            raise ValueError("investigator completion catalog cursor is not reserved")
        if prepared.outcome == "no_new_fact" and (
            turn.pending_item_ids or turn.offered_item_ids or turn.pending_tail or turn.offered_refs
        ):
            raise ValueError("investigator no-new-fact cannot discard pending work")
        selected = set(prepared.frontier_item_ids)
        expected_items = tuple(
            item_id
            for item_id in (*turn.pending_item_ids, *turn.offered_item_ids)
            if item_id not in selected
        )
        expected_refs = (*turn.pending_tail, *turn.offered_refs)
        if (
            prepared.remaining_item_ids != expected_items
            or prepared.remaining_refs != expected_refs
        ):
            raise ValueError("investigator turn pending tail was not preserved")
        generation_row = self._store.connection.execute(
            "SELECT generation FROM evidence_case_generations WHERE case_id=?",
            (str(turn.case_id),),
        ).fetchone()
        generation = 0 if generation_row is None else int(generation_row[0])
        now = utc_now()
        if now < turn.reserved_at:
            raise ValueError("investigator completion chronology is invalid")
        if prepared.outcome in {"focused_delivery", "no_new_fact"}:
            if now >= turn.deadline_at:
                raise ValueError("investigator completion deadline expired")
            if generation != turn.catalog_generation:
                raise ValueError("investigator completion catalog generation is stale")
        if (
            prepared.reason_code == "stale_context"
            and generation == turn.catalog_generation
            and not turn.stale_pending_only
        ):
            raise ValueError("investigator completion context is not stale")
        if prepared.reason_code == "deadline_expired" and now < turn.deadline_at:
            raise ValueError("investigator completion deadline has not expired")
        outcome = FrontierInvestigatorTurnOutcomeV1.model_validate(
            {
                **prepared.model_dump(mode="json"),
                "resulting_checkpoint_version": expected_checkpoint_version,
                "completed_at": now,
                "schema_version": 2,
                "source_state_at_completion": source.source_state,
                "source_record_sha256": source.source_record_sha256,
            }
        )
        self._validate_investigator_success_custody(turn, outcome)
        self._insert_investigator_turn_outcome(turn, outcome)
        return outcome

    def _complete_mixed_turn_in_transaction(
        self,
        prepared: FrontierInvestigatorTurnCompletionV3,
        *,
        expected_checkpoint_version: int,
    ) -> FrontierInvestigatorTurnOutcomeV3:
        turn = self.read_investigator_turn(prepared.turn_id)
        if not isinstance(turn, FrontierInvestigatorTurnV3):
            raise ValueError("v3 completion requires a mixed turn")
        if prepared.case_id != turn.case_id or self.read_investigator_turn_outcome(turn.turn_id):
            raise ValueError("mixed turn completion case or single-use custody is invalid")
        state = self._investigator_checkpoint(turn.case_id)
        case_row = self._store.connection.execute(
            "SELECT state_version FROM cases WHERE case_id=?", (str(turn.case_id),)
        ).fetchone()
        if (
            case_row is None
            or state.state_version != expected_checkpoint_version
            or int(case_row[0]) != expected_checkpoint_version
            or expected_checkpoint_version != turn.expected_checkpoint_version + 1
        ):
            raise ValueError("mixed turn completion checkpoint is stale")
        newer_owner = self._store.connection.execute(
            "SELECT 1 FROM investigation_steps WHERE case_id=? AND state_version>? "
            "AND json_extract(record_json,'$.event')='started' LIMIT 1",
            (str(turn.case_id), turn.owner_started_version),
        ).fetchone()
        if newer_owner is not None:
            raise ValueError("mixed turn completion owner is stale")
        if (
            prepared.focused_context_sha256 != turn.focused_context_sha256
            or prepared.cursor_after != turn.cursor_after
        ):
            raise ValueError("mixed turn completion context is stale")
        if turn.stale_pending_gap and (
            prepared.outcome != "gap"
            or prepared.reason_code not in {"stale_context", "source_unverifiable"}
            or prepared.frontier_item_ids
        ):
            raise ValueError("mixed stale pending gap cannot select or deliver work")
        selected = set(prepared.frontier_item_ids)
        if selected and not selected <= set((*turn.pending_item_ids, *turn.offered_item_ids)):
            raise ValueError("mixed turn selected item was not offered")
        remaining = tuple(
            item_id
            for item_id in (*turn.pending_item_ids, *turn.offered_item_ids)
            if item_id not in selected
        )
        if prepared.remaining_item_ids != remaining or prepared.remaining_refs != (
            *turn.pending_tail,
            *turn.offered_refs,
        ):
            raise ValueError("mixed turn retained alternatives changed")
        source = self.read_event(turn.event_id)
        if source.source_record_sha256 != turn.source_record_sha256:
            raise ValueError("mixed turn event source changed")
        if source.source_state == "missing_unverifiable" and (
            prepared.outcome != "gap" or prepared.reason_code != "source_unverifiable"
        ):
            raise ValueError("mixed turn source is unverifiable")
        if (
            source.source_state != "missing_unverifiable"
            and prepared.reason_code == "source_unverifiable"
        ):
            raise ValueError("mixed turn source remains verifiable")
        now = utc_now()
        generation_row = self._store.connection.execute(
            "SELECT generation FROM evidence_case_generations WHERE case_id=?",
            (str(turn.case_id),),
        ).fetchone()
        generation = 0 if generation_row is None else int(generation_row[0])
        success = prepared.outcome in {"focused_delivery", "measurement_admitted", "no_new_fact"}
        if now < turn.reserved_at or (
            success and (now >= turn.deadline_at or generation != turn.catalog_generation)
        ):
            raise ValueError("mixed turn completion deadline or catalog is stale")
        if prepared.reason_code == "deadline_expired" and now < turn.deadline_at:
            raise ValueError("mixed turn deadline has not expired")
        if prepared.outcome == "no_new_fact" and (turn.pending_item_ids or turn.offered_item_ids):
            raise ValueError("mixed turn cannot discard offered work")
        if prepared.outcome == "measurement_admitted":
            self._validate_mixed_admission(
                turn, prepared, resulting_checkpoint_version=expected_checkpoint_version
            )
        elif prepared.outcome == "focused_delivery":
            item = self.readback(prepared.frontier_item_ids[0])
            if (
                item.reference.kind != "retrieve_evidence"
                or item.status is not FrontierStatus.SATISFIED
            ):
                raise ValueError("mixed turn retrieval is not satisfied")
        outcome = FrontierInvestigatorTurnOutcomeV3.model_validate(
            {
                **prepared.model_dump(mode="json"),
                "resulting_checkpoint_version": expected_checkpoint_version,
                "completed_at": now,
                "source_state_at_completion": source.source_state,
                "source_record_sha256": source.source_record_sha256,
            }
        )
        self._insert_investigator_turn_outcome(turn, outcome)
        return outcome

    def _validate_mixed_admission(
        self,
        turn: FrontierInvestigatorTurnV3,
        prepared: FrontierInvestigatorTurnCompletionV3 | FrontierInvestigatorTurnOutcomeV3,
        *,
        resulting_checkpoint_version: int,
        require_admitted_status: bool = True,
    ) -> None:
        selected_id = prepared.frontier_item_ids[0]
        item = self.readback(selected_id)
        candidate_id = item.reference.candidate_id
        if (
            item.case_id != turn.case_id
            or item.reference.kind != "measure"
            or candidate_id is None
            or item.versions != turn.current_versions
            or (require_admitted_status and item.status is not FrontierStatus.ADMITTED)
            or (
                not require_admitted_status
                and item.status
                not in {
                    FrontierStatus.ADMITTED,
                    FrontierStatus.RUNNING,
                    FrontierStatus.SATISFIED,
                    FrontierStatus.FAILED,
                    FrontierStatus.INTERRUPTED,
                    FrontierStatus.OBSOLETE,
                    FrontierStatus.CANCELLED,
                }
            )
        ):
            raise ValueError("mixed turn selected measurement is not admitted")
        admission = self._store.connection.execute(
            "SELECT snapshot_id,candidate_id,case_id,epoch_state_version,task_id,"
            "invocation_sha256,admitted_at FROM candidate_dispatch_admissions "
            "WHERE admission_id=?",
            (prepared.dispatch_admission_id,),
        ).fetchone()
        claim = self._store.connection.execute(
            "SELECT case_id,epoch_state_version,task_id,invocation_sha256,claimed_at "
            "FROM candidate_dispatch_claims WHERE admission_id=?",
            (prepared.dispatch_admission_id,),
        ).fetchone()
        snapshot = self._store.connection.execute(
            "SELECT schema_version,case_id,epoch_state_version FROM candidate_decision_snapshots "
            "WHERE snapshot_id=?",
            (prepared.candidate_snapshot_id,),
        ).fetchone()
        binding = self._store.connection.execute(
            "SELECT receipt_id FROM frontier_packet_snapshot_bindings WHERE snapshot_id=?",
            (prepared.candidate_snapshot_id,),
        ).fetchone()
        continuation = self._store.connection.execute(
            "SELECT admission_id,turn_id,case_id,epoch_state_version,"
            "resulting_checkpoint_version,owner_started_version,task_id,"
            "invocation_sha256,deadline_at,created_at "
            "FROM candidate_launch_continuations WHERE continuation_id=?",
            (prepared.launch_continuation_id,),
        ).fetchone()
        if (
            admission is None
            or claim is None
            or snapshot is None
            or binding is None
            or continuation is None
            or turn.packet_receipt_id is None
            or str(admission[0]) != prepared.candidate_snapshot_id
            or str(admission[1]) != candidate_id
            or str(admission[2]) != str(turn.case_id)
            or int(admission[3]) != turn.candidate_epoch
            or str(snapshot[0]) != "2"
            or str(snapshot[1]) != str(turn.case_id)
            or int(snapshot[2]) != turn.candidate_epoch
            or str(binding[0]) != turn.packet_receipt_id
            or str(claim[0]) != str(turn.case_id)
            or int(claim[1]) != turn.candidate_epoch
            or str(claim[2]) != str(admission[4])
            or str(claim[3]) != str(admission[5])
            or str(continuation[0]) != prepared.dispatch_admission_id
            or str(continuation[1]) != turn.turn_id
            or str(continuation[2]) != str(turn.case_id)
            or int(continuation[3]) != turn.candidate_epoch
            or int(continuation[4]) != resulting_checkpoint_version
            or int(continuation[5]) != turn.owner_started_version
            or str(continuation[6]) != str(admission[4])
            or str(continuation[7]) != str(admission[5])
            or datetime.fromisoformat(str(continuation[8])) > turn.deadline_at
            or not turn.reserved_at
            <= datetime.fromisoformat(str(admission[6]))
            <= datetime.fromisoformat(str(claim[4]))
            <= datetime.fromisoformat(str(continuation[9]))
            <= turn.deadline_at
        ):
            raise ValueError("mixed turn admission, claim, or continuation binding is invalid")
        if require_admitted_status:
            from systemsense.storage.candidate_decision_snapshots import (
                CandidateDecisionSnapshotRepository,
            )
            from systemsense.storage.candidate_dispatch_admissions import (
                CandidateDispatchAdmissionRepository,
            )

            frozen = CandidateDecisionSnapshotRepository(self._store).readback_frontier(
                prepared.candidate_snapshot_id or ""
            )
            admitted = CandidateDispatchAdmissionRepository(self._store).readback(
                prepared.dispatch_admission_id or ""
            )
            if (
                frozen.selected_item_id != selected_id
                or frozen.candidate_id != candidate_id
                or admitted.admission_id != prepared.dispatch_admission_id
                or admitted.claimed_at is None
            ):
                raise ValueError("mixed turn frozen selection or claimed admission changed")

    def recover_interrupted_investigator_turn(
        self, turn_id: str
    ) -> FrontierInvestigatorTurnOutcomeV1 | FrontierInvestigatorTurnOutcomeV3:
        """Record loss of a reservation only after its deadline or owner replacement."""

        with self._store.transaction():
            turn = self.read_investigator_turn(turn_id)
            existing = self.read_investigator_turn_outcome(turn_id)
            if existing is not None:
                return existing
            state = self._investigator_checkpoint(turn.case_id)
            newer_owner = self._store.connection.execute(
                "SELECT 1 FROM investigation_steps WHERE case_id=? AND state_version>? "
                "AND json_extract(record_json,'$.event')='started' LIMIT 1",
                (str(turn.case_id), turn.owner_started_version),
            ).fetchone()
            now = utc_now()
            if now < turn.reserved_at:
                raise ValueError("investigator recovery chronology is invalid")
            if (
                now < turn.deadline_at
                and newer_owner is None
                and state.status == InvestigationStatus.RUNNING
            ):
                raise ValueError("investigator turn is still owned")
            data = {
                "turn_id": turn_id,
                "case_id": turn.case_id,
                "outcome": "interrupted",
                "reason_code": "owner_interrupted",
                "cursor_after": turn.cursor_before,
                "focused_context_sha256": turn.focused_context_sha256,
                "remaining_item_ids": (*turn.pending_item_ids, *turn.offered_item_ids),
                "remaining_refs": (*turn.pending_tail, *turn.offered_refs),
                "resulting_checkpoint_version": None,
                "completed_at": now,
                "source_state_at_completion": self.read_event(turn.event_id).source_state,
                "source_record_sha256": self.read_event(turn.event_id).source_record_sha256,
            }
            outcome: FrontierInvestigatorTurnOutcomeV1 | FrontierInvestigatorTurnOutcomeV3
            if isinstance(turn, FrontierInvestigatorTurnV3):
                outcome = FrontierInvestigatorTurnOutcomeV3.model_validate(data)
            else:
                outcome = FrontierInvestigatorTurnOutcomeV1.model_validate(data)
            self._insert_investigator_turn_outcome(turn, outcome)
            return outcome

    def read_investigator_turn_outcome(
        self, turn_id: str
    ) -> FrontierInvestigatorTurnOutcomeV1 | FrontierInvestigatorTurnOutcomeV3 | None:
        row = self._store.connection.execute(
            "SELECT case_id,schema_version,record_json,record_sha256,completed_at "
            "FROM search_frontier_investigator_turn_outcomes WHERE turn_id=?",
            (turn_id,),
        ).fetchone()
        if row is None:
            return None
        body = str(row[2])
        payload = json.loads(body)
        if (
            int(row[1]) not in {1, 2, 3}
            or _digest(body) != str(row[3])
            or _canonical(payload) != body
        ):
            raise ValueError("investigator turn outcome digest is invalid")
        outcome: FrontierInvestigatorTurnOutcomeV1 | FrontierInvestigatorTurnOutcomeV3
        if int(row[1]) == 3:
            outcome = FrontierInvestigatorTurnOutcomeV3.model_validate(payload)
        else:
            outcome = FrontierInvestigatorTurnOutcomeV1.model_validate(payload)
        turn = self.read_investigator_turn(turn_id)
        if isinstance(turn, FrontierInvestigatorTurnV3) != isinstance(
            outcome, FrontierInvestigatorTurnOutcomeV3
        ):
            raise ValueError("mixed turn outcome version is invalid")
        if (
            outcome.turn_id != turn_id
            or outcome.case_id != turn.case_id
            or str(outcome.case_id) != str(row[0])
            or outcome.completed_at.isoformat() != str(row[4])
            or outcome.completed_at < turn.reserved_at
            or outcome.focused_context_sha256 != turn.focused_context_sha256
            or outcome.schema_version != int(row[1])
        ):
            raise ValueError("investigator turn outcome custody is invalid")
        source = self.read_event(turn.event_id)
        if outcome.schema_version in {2, 3}:
            if outcome.source_record_sha256 != source.source_record_sha256 or (
                (source.source_evidence_id is None)
                != (outcome.source_state_at_completion == "not_applicable")
            ):
                raise ValueError("investigator turn source receipt is invalid")
        elif (
            outcome.outcome in {"focused_delivery", "no_new_fact"}
            and source.source_state == "missing_unverifiable"
        ):
            raise ValueError("investigator legacy success source is unverifiable")
        if outcome.reason_code == "source_unverifiable" and (
            outcome.schema_version not in {2, 3}
            or outcome.source_state_at_completion != "missing_unverifiable"
        ):
            raise ValueError("investigator source gap receipt is invalid")
        if (
            outcome.outcome in {"focused_delivery", "no_new_fact"}
            and outcome.schema_version in {2, 3}
            and outcome.source_state_at_completion == "missing_unverifiable"
        ):
            raise ValueError("investigator success source receipt is invalid")
        if outcome.outcome == "interrupted":
            if (
                outcome.cursor_after != turn.cursor_before
                or outcome.resulting_checkpoint_version is not None
            ):
                raise ValueError("investigator interrupted turn continuation is invalid")
        elif (
            outcome.cursor_after != turn.cursor_after
            or outcome.resulting_checkpoint_version != turn.expected_checkpoint_version + 1
        ):
            raise ValueError("investigator turn continuation is invalid")
        selected = set(outcome.frontier_item_ids)
        expected_items = tuple(
            item_id
            for item_id in (*turn.pending_item_ids, *turn.offered_item_ids)
            if item_id not in selected
        )
        if (
            outcome.remaining_item_ids != expected_items
            or outcome.remaining_refs != (*turn.pending_tail, *turn.offered_refs)
            or (outcome.outcome == "no_new_fact" and (expected_items or outcome.remaining_refs))
        ):
            raise ValueError("investigator turn pending tail is invalid")
        if (
            turn.stale_pending_only
            and outcome.outcome != "interrupted"
            and (
                outcome.outcome != "gap"
                or outcome.reason_code not in {"stale_context", "source_unverifiable"}
            )
        ):
            raise ValueError("investigator stale pending outcome is invalid")
        if (
            isinstance(turn, FrontierInvestigatorTurnV3)
            and turn.stale_pending_gap
            and outcome.frontier_item_ids
        ):
            raise ValueError("mixed stale pending gap selected work")
        if isinstance(turn, FrontierInvestigatorTurnV3):
            if outcome.outcome == "measurement_admitted":
                self._validate_mixed_admission(
                    turn,
                    outcome,
                    resulting_checkpoint_version=turn.expected_checkpoint_version + 1,
                    require_admitted_status=False,
                )
            elif outcome.outcome == "focused_delivery":
                item = self.readback(outcome.frontier_item_ids[0])
                if (
                    item.reference.kind != "retrieve_evidence"
                    or item.status is not FrontierStatus.SATISFIED
                ):
                    raise ValueError("mixed turn retrieval is not satisfied")
        else:
            assert isinstance(outcome, FrontierInvestigatorTurnOutcomeV1)
            self._validate_investigator_success_custody(turn, outcome)
        return outcome

    def _validate_investigator_success_custody(
        self, turn: FrontierInvestigatorTurnV1, outcome: FrontierInvestigatorTurnOutcomeV1
    ) -> None:
        """Use only frozen turn, immutable item history, and recorded completion time."""

        if outcome.outcome not in {"focused_delivery", "no_new_fact"}:
            return
        if not turn.reserved_at <= outcome.completed_at < turn.deadline_at:
            raise ValueError("investigator success deadline or chronology is invalid")
        if outcome.outcome == "no_new_fact":
            if (
                turn.pending_item_ids
                or turn.offered_item_ids
                or turn.pending_tail
                or turn.offered_refs
            ):
                raise ValueError("investigator no-new-fact cannot discard pending work")
            return
        selected_id = outcome.frontier_item_ids[0]
        first_pending = turn.pending_item_ids[0] if turn.pending_item_ids else None
        if selected_id not in (*turn.pending_item_ids, *turn.offered_item_ids) or (
            first_pending is not None and selected_id != first_pending
        ):
            raise ValueError("investigator focused delivery selected item was not offered")
        item = self.readback(selected_id)
        if (
            item.case_id != turn.case_id
            or item.versions != turn.current_versions
            or item.reference.kind != "retrieve_evidence"
            or item.status is not FrontierStatus.SATISFIED
        ):
            raise ValueError("investigator focused delivery item is not bound or satisfied")

    def _insert_investigator_turn_outcome(
        self,
        turn: FrontierInvestigatorTurnV1,
        outcome: FrontierInvestigatorTurnOutcomeV1 | FrontierInvestigatorTurnOutcomeV3,
    ) -> None:
        body = _canonical(outcome.model_dump(mode="json"))
        self._store.connection.execute(
            "INSERT INTO search_frontier_investigator_turn_outcomes "
            "(turn_id,case_id,schema_version,record_json,record_sha256,completed_at) "
            "VALUES (?,?,?,?,?,?)",
            (
                turn.turn_id,
                str(turn.case_id),
                outcome.schema_version,
                body,
                _digest(body),
                outcome.completed_at.isoformat(),
            ),
        )

    def _investigator_checkpoint(self, case_id: CaseId) -> InvestigationState:
        row = self._store.connection.execute(
            "SELECT record_json FROM investigation_checkpoints WHERE case_id=?",
            (str(case_id),),
        ).fetchone()
        if row is None:
            raise ValueError("investigator owner checkpoint is unavailable")
        state = InvestigationState.model_validate_json(str(row[0]))
        if state.case_id != case_id:
            raise ValueError("investigator owner checkpoint crosses cases")
        return state

    def _case_turn_count_through(self, turn: FrontierInvestigatorTurnV1) -> int:
        row = self._store.connection.execute(
            "SELECT rowid FROM search_frontier_investigator_turns WHERE turn_id=?",
            (turn.turn_id,),
        ).fetchone()
        if row is None:
            raise ValueError("investigator turn is unavailable")
        count = self._store.connection.execute(
            "SELECT COUNT(*) FROM search_frontier_investigator_turns WHERE case_id=? AND rowid<=?",
            (str(turn.case_id), int(row[0])),
        ).fetchone()
        if count is None:
            raise ValueError("investigator case turn count is unavailable")
        return int(count[0])

    def investigator_case_turns_remaining(self, case_id: CaseId) -> int:
        """Return durable case-wide reservation capacity before opening attention."""

        if self._store.case(str(case_id)) is None:
            raise ValueError("investigator case is unavailable")
        row = self._store.connection.execute(
            "SELECT COUNT(*) FROM search_frontier_investigator_turns WHERE case_id=?",
            (str(case_id),),
        ).fetchone()
        if row is None:
            raise ValueError("investigator case turn count is unavailable")
        return max(0, _INVESTIGATOR_CASE_TURN_LIMIT - int(row[0]))

    def _case_stop_terminal_event(
        self, case_id: CaseId, checkpoint_version: int
    ) -> tuple[str, str, datetime, str, str]:
        """Verify immutable terminal event against its historical checkpoint step."""

        rows = self._store.connection.execute(
            "SELECT schema_version,event_id,kind,event_json,source_record_id,"
            "source_observed_at,persisted_at FROM coordinator_events "
            "WHERE case_id=? AND kind='terminal' AND source_record_id=?",
            (str(case_id), str(checkpoint_version)),
        ).fetchall()
        if len(rows) != 1:
            raise ValueError("investigator case stop terminal event is unavailable")
        schema_version, event_id, kind, body, source_id, source_at, persisted_at = rows[0]
        payload = json.loads(str(body))
        step_row = self._store.connection.execute(
            "SELECT record_json FROM investigation_steps WHERE case_id=? AND state_version=?",
            (str(case_id), checkpoint_version),
        ).fetchone()
        if step_row is None:
            raise ValueError("investigator case stop terminal step is unavailable")
        step = InvestigationStep.model_validate_json(str(step_row[0]))
        if (
            int(schema_version) != 1
            or str(kind) != "terminal"
            or str(source_id) != str(checkpoint_version)
            or _canonical(payload) != str(body)
            or payload.get("kind") != "terminal"
            or payload.get("event_id") != str(event_id)
            or payload.get("observed_at") != str(persisted_at)
            or payload.get("status")
            not in {
                status.value
                for status in (
                    InvestigationStatus.COMPLETE,
                    InvestigationStatus.CANCELLED,
                    InvestigationStatus.FAILED,
                    InvestigationStatus.INTERRUPTED,
                )
            }
            or not isinstance(payload.get("outcome"), str)
            or step.case_id != case_id
            or step.state_version != checkpoint_version
            or step.occurred_at.isoformat() != str(source_at)
        ):
            raise ValueError("investigator case stop terminal event binding is invalid")
        return (
            str(event_id),
            _digest(str(body)),
            datetime.fromisoformat(str(persisted_at)),
            str(payload["status"]),
            str(payload["outcome"]),
        )

    def close_investigator_session_in_transaction(
        self, intent: FrontierInvestigatorTurnClosureIntentV1
    ) -> FrontierInvestigatorTurnClosureV1:
        """Close bounded attention after its final durable turn, in the caller's transaction."""

        if not self._store.connection.in_transaction:
            raise ValueError("investigator turn closure requires caller transaction")
        session = self.active_investigator_session(intent.case_id)
        if session is None or session.event_id != intent.event_id:
            raise ValueError("investigator turn closure lacks active session")
        if self.read_investigator_terminal(intent.event_id) is not None:
            raise ValueError("investigator legacy terminal already exists")
        turn = self.read_investigator_turn(intent.final_turn_id)
        outcome = self.read_investigator_turn_outcome(intent.final_turn_id)
        if turn.case_id != intent.case_id or turn.event_id != intent.event_id or outcome is None:
            raise ValueError("investigator final turn is not completed for session")
        unfinished = self._store.connection.execute(
            "SELECT 1 FROM search_frontier_investigator_turns AS t "
            "LEFT JOIN search_frontier_investigator_turn_outcomes AS o ON o.turn_id=t.turn_id "
            "WHERE t.event_id=? AND o.turn_id IS NULL LIMIT 1",
            (intent.event_id,),
        ).fetchone()
        latest = self._store.connection.execute(
            "SELECT MAX(ordinal) FROM search_frontier_investigator_turns WHERE event_id=?",
            (intent.event_id,),
        ).fetchone()
        if unfinished is not None or latest is None or turn.ordinal != int(latest[0]):
            raise ValueError("investigator closure has unresolved turn")
        has_tail = bool(
            outcome.remaining_item_ids or outcome.remaining_refs or outcome.cursor_after
        )
        admitted_without_tail = (
            not has_tail
            and isinstance(turn, FrontierInvestigatorTurnV3)
            and isinstance(outcome, FrontierInvestigatorTurnOutcomeV3)
            and outcome.outcome == "measurement_admitted"
        )
        closed_at = utc_now()
        if closed_at < outcome.completed_at:
            raise ValueError("investigator closure chronology is invalid")
        case_deadline_at = self._investigator_checkpoint(intent.case_id).deadline_at
        source = self.read_event(intent.event_id)
        source_missing = source.source_state == "missing_unverifiable"
        if source_missing and intent.reason_code != "source_unverifiable":
            raise ValueError("investigator source unverifiable requires explicit closure gap")
        if not source_missing and intent.reason_code == "source_unverifiable":
            raise ValueError("investigator closure source is still verifiable")
        terminal_receipt: dict[str, object] = {}
        if intent.outcome in {"focused_delivery", "no_new_fact"}:
            if (
                intent.outcome != outcome.outcome
                or has_tail
                or intent.reason_code != outcome.reason_code
            ):
                raise ValueError("investigator successful closure has unresolved continuation")
        elif intent.reason_code == "budget_exhausted":
            if (
                turn.ordinal < session.decision_budget
                and self._case_turn_count_through(turn) < _INVESTIGATOR_CASE_TURN_LIMIT
            ) or (not has_tail and outcome.outcome in {"focused_delivery", "no_new_fact"}):
                raise ValueError("investigator budget closure is not exhausted")
        elif intent.reason_code == "deadline_expired":
            expired_turn = (
                outcome.reason_code == "deadline_expired" and closed_at >= turn.deadline_at
            )
            expired_session = (has_tail or admitted_without_tail) and closed_at >= min(
                session.deadline_at, case_deadline_at
            )
            if not (expired_turn or expired_session):
                raise ValueError("investigator deadline closure is not expired or unresolved")
        elif intent.reason_code == "case_stopped":
            state = self._investigator_checkpoint(intent.case_id)
            if not has_tail or state.status not in {
                InvestigationStatus.COMPLETE,
                InvestigationStatus.CANCELLED,
                InvestigationStatus.FAILED,
                InvestigationStatus.INTERRUPTED,
            }:
                raise ValueError("investigator case stop requires unresolved terminal event")
            event_id, event_sha, persisted_at, event_status, event_outcome = (
                self._case_stop_terminal_event(intent.case_id, state.state_version)
            )
            if (
                closed_at < persisted_at
                or event_status != state.status.value
                or event_outcome != state.outcome.value
            ):
                raise ValueError("investigator case stop closure chronology is invalid")
            terminal_receipt = {
                "terminal_event_id": event_id,
                "terminal_checkpoint_version": state.state_version,
                "terminal_event_sha256": event_sha,
                "terminal_status": state.status,
                "terminal_outcome": state.outcome.value,
            }
        elif intent.reason_code == "source_unverifiable":
            pass  # Source loss after the last completed turn is itself the gap.
        elif intent.reason_code != outcome.reason_code or outcome.outcome not in {
            "gap",
            "interrupted",
        }:
            raise ValueError("investigator gap closure does not match final outcome")
        closure = FrontierInvestigatorTurnClosureV1.model_validate(
            {
                **intent.model_dump(mode="json"),
                "case_turn_limit": _INVESTIGATOR_CASE_TURN_LIMIT,
                "case_deadline_at": case_deadline_at,
                "closed_at": closed_at,
                "schema_version": 2,
                "source_state_at_closure": source.source_state,
                "source_record_sha256": source.source_record_sha256,
                **terminal_receipt,
            }
        )
        body = _canonical(closure.model_dump(mode="json"))
        self._store.connection.execute(
            "INSERT INTO search_frontier_investigator_turn_closures "
            "(event_id,case_id,final_turn_id,schema_version,record_json,record_sha256,closed_at) "
            "VALUES (?,?,?,?,?,?,?)",
            (
                intent.event_id,
                str(intent.case_id),
                intent.final_turn_id,
                closure.schema_version,
                body,
                _digest(body),
                closure.closed_at.isoformat(),
            ),
        )
        deleted = self._store.connection.execute(
            "DELETE FROM search_frontier_investigator_active_sessions "
            "WHERE case_id=? AND event_id=?",
            (str(intent.case_id), intent.event_id),
        )
        if deleted.rowcount != 1:
            raise ValueError("investigator active session release failed")
        return closure

    def read_investigator_turn_closure(
        self, event_id: str
    ) -> FrontierInvestigatorTurnClosureV1 | None:
        row = self._store.connection.execute(
            "SELECT case_id,final_turn_id,schema_version,record_json,record_sha256,closed_at "
            "FROM search_frontier_investigator_turn_closures WHERE event_id=?",
            (event_id,),
        ).fetchone()
        if row is None:
            return None
        body = str(row[3])
        payload = json.loads(body)
        if int(row[2]) not in {1, 2} or _digest(body) != str(row[4]) or _canonical(payload) != body:
            raise ValueError("investigator turn closure digest is invalid")
        closure = FrontierInvestigatorTurnClosureV1.model_validate(payload)
        case_id = CaseId(root=str(row[0]))
        session = self._read_investigator_session(case_id, event_id)
        turn = self.read_investigator_turn(str(row[1]))
        outcome = self.read_investigator_turn_outcome(turn.turn_id)
        if (
            closure.event_id != event_id
            or closure.case_id != case_id
            or closure.final_turn_id != turn.turn_id
            or turn.event_id != session.event_id
            or outcome is None
            or closure.closed_at.isoformat() != str(row[5])
            or closure.closed_at < outcome.completed_at
            or closure.schema_version != int(row[2])
        ):
            raise ValueError("investigator turn closure source binding is invalid")
        source = self.read_event(event_id)
        if closure.schema_version == 2:
            if closure.source_record_sha256 != source.source_record_sha256 or (
                (source.source_evidence_id is None)
                != (closure.source_state_at_closure == "not_applicable")
            ):
                raise ValueError("investigator closure source receipt is invalid")
        elif (
            closure.outcome in {"focused_delivery", "no_new_fact"}
            and source.source_state == "missing_unverifiable"
        ):
            raise ValueError("investigator legacy closure source is unverifiable")
        has_tail = bool(
            outcome.remaining_item_ids or outcome.remaining_refs or outcome.cursor_after
        )
        admitted_without_tail = (
            not has_tail
            and isinstance(turn, FrontierInvestigatorTurnV3)
            and isinstance(outcome, FrontierInvestigatorTurnOutcomeV3)
            and outcome.outcome == "measurement_admitted"
        )
        if closure.outcome in {"focused_delivery", "no_new_fact"}:
            if (
                closure.outcome != outcome.outcome
                or closure.reason_code != outcome.reason_code
                or has_tail
            ):
                raise ValueError("investigator successful closure has unresolved continuation")
        elif closure.reason_code == "budget_exhausted":
            if (
                turn.ordinal < session.decision_budget
                and self._case_turn_count_through(turn) < closure.case_turn_limit
            ) or (not has_tail and outcome.outcome in {"focused_delivery", "no_new_fact"}):
                raise ValueError("investigator closure budget is invalid")
        elif closure.reason_code == "deadline_expired":
            expired_turn = (
                outcome.reason_code == "deadline_expired" and closure.closed_at >= turn.deadline_at
            )
            expired_session = (has_tail or admitted_without_tail) and closure.closed_at >= min(
                session.deadline_at, closure.case_deadline_at
            )
            if not (expired_turn or expired_session):
                raise ValueError("investigator closure deadline is invalid")
        elif closure.reason_code == "case_stopped":
            if not has_tail or closure.terminal_checkpoint_version is None:
                raise ValueError("investigator case stop has no unresolved continuation")
            event_id, event_sha, persisted_at, event_status, event_outcome = (
                self._case_stop_terminal_event(case_id, closure.terminal_checkpoint_version)
            )
            if (
                closure.terminal_event_id != event_id
                or closure.terminal_event_sha256 != event_sha
                or closure.terminal_status != event_status
                or closure.terminal_outcome != event_outcome
                or closure.closed_at < persisted_at
            ):
                raise ValueError("investigator case stop terminal receipt is invalid")
        elif closure.reason_code == "source_unverifiable":
            if (
                closure.schema_version != 2
                or closure.source_state_at_closure != "missing_unverifiable"
            ):
                raise ValueError("investigator closure source gap receipt is invalid")
        elif closure.reason_code != outcome.reason_code or outcome.outcome not in {
            "gap",
            "interrupted",
        }:
            raise ValueError("investigator closure gap is invalid")
        return closure
