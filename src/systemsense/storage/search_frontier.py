"""Bounded, append-only advisory search work and persisted-result outbox.

This repository never executes a probe. A measurement reference is an opaque
candidate minted by the local capability registry, not an executable selector.
Model inference must run outside every transaction in this module.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from enum import StrEnum
from typing import Literal, cast

from pydantic import Field, model_validator

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId
from systemsense.domain.probes import MeasurementWindow
from systemsense.domain.time import UtcDateTime, utc_now
from systemsense.evidence.graph import EvidenceRelation
from systemsense.storage.sqlite_store import SQLiteStore

_ITEM_LIMIT = 128
_EVENT_LIMIT = 2048
_ID = re.compile(r"fr_v1_[0-9a-f]{64}\Z")


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


def _canonical(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


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
        with self._store.transaction():
            connection = self._store.connection
            if (
                connection.execute(
                    "SELECT 1 FROM cases WHERE case_id=?", (str(case_id),)
                ).fetchone()
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
