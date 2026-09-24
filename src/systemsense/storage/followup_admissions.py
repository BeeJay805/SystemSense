"""Append-only provenance for read-only follow-ups admitted during a collection epoch.

Admission records are not execution claims or replay authority. The caller must
prepare the invocation through the registered probe policy before admission.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from systemsense.domain.evidence import EvidenceRecord, StatementKind
from systemsense.domain.probes import ProbeInvocation
from systemsense.domain.time import utc_now
from systemsense.storage.sqlite_store import SQLiteStore

_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_TASK_ID = re.compile(r"[a-zA-Z0-9_.:-]{1,160}\Z")
_RUN_STATUSES = frozenset(
    {"ok", "denied", "unavailable", "failed", "timed_out", "cancelled", "truncated"}
)


@dataclass(frozen=True, slots=True)
class FollowupAdmission:
    admission_id: str
    case_id: str
    epoch_state_version: int
    trigger_execution_id: str
    evidence_generation: int
    trigger_evidence_sha256: str
    decision_snapshot_id: str | None
    request_sha256: str
    invocation: ProbeInvocation
    invocation_sha256: str
    dedupe_key: str
    task_id: str
    estimated_cost_ms: int
    admitted_at: datetime
    schema_version: int = 1


@dataclass(frozen=True, slots=True)
class FollowupAdmissionReadback:
    admission_id: str
    case_id: str
    epoch_state_version: int
    task_id: str
    trigger_execution_id: str
    evidence_generation: int
    trigger_evidence_sha256: str
    request_sha256: str
    decision_snapshot_id: str | None
    invocation_sha256: str
    dedupe_key: str
    estimated_cost_ms: int
    admitted_at: datetime
    execution_id: str | None
    outcome_status: str
    replay_allowed: bool = False


def _utc(value: datetime, *, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(None):
        raise ValueError(f"{name} must be UTC")
    return value


def _parse_utc(value: object, *, name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError as error:
        raise ValueError(f"{name} is invalid") from error
    return _utc(parsed, name=name)


def _canonical(value: object) -> str:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def _sha256(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class _BudgetCheckpoint(BaseModel):
    """Only the validated checkpoint fields needed for atomic reservations."""

    model_config = ConfigDict(extra="ignore")
    case_id: str
    state_version: int = Field(ge=0, strict=True)
    status: Literal["running"]
    deadline_at: datetime
    budget_ms: int = Field(ge=100, le=600_000, strict=True)
    spent_cost_ms: int = Field(ge=0, strict=True)
    max_probes: int = Field(ge=1, le=64, strict=True)
    completed_probe_ids: tuple[str, ...]
    pending_probe_ids: tuple[str, ...]
    interrupted_probe_ids: tuple[str, ...]
    unrecorded_attempt_count: int = Field(ge=0, strict=True)


class FollowupAdmissionRepository:
    """Same-thread SQLite writer and integrity-checked readback for one case epoch."""

    def __init__(self, store: SQLiteStore, *, now: Callable[[], datetime] = utc_now) -> None:
        self.store = store
        self._now = now

    def admit(
        self,
        *,
        case_id: str,
        epoch_state_version: int,
        trigger_execution_id: str,
        expected_evidence_generation: int,
        request_sha256: str,
        decision_snapshot_id: str | None,
        invocation: ProbeInvocation,
        task_id: str,
        estimated_cost_ms: int,
    ) -> FollowupAdmission:
        """Reserve one exact invocation before dispatch, or reject without a row."""

        if (
            not case_id
            or epoch_state_version < 0
            or expected_evidence_generation < 1
            or not 1 <= estimated_cost_ms <= 120_000
            or _DIGEST.fullmatch(request_sha256) is None
            or _TASK_ID.fullmatch(task_id) is None
        ):
            raise ValueError("follow-up admission identity invalid")
        canonical_invocation = _canonical(invocation.model_dump(mode="json"))
        invocation_sha256 = _sha256(canonical_invocation)
        with self.store.transaction() as transaction:
            admitted_at = _utc(self._now(), name="admission time")
            transaction.require_case_state(
                case_id=case_id, expected_state_version=epoch_state_version
            )
            case = self.store.case(case_id)
            if case is None or case.status != "collecting":
                raise ValueError("collection epoch is not active")
            checkpoint_row = self.store.connection.execute(
                "SELECT record_json FROM investigation_checkpoints WHERE case_id=?", (case_id,)
            ).fetchone()
            if checkpoint_row is None:
                raise ValueError("collection budget checkpoint is unavailable")
            try:
                checkpoint = _BudgetCheckpoint.model_validate_json(str(checkpoint_row[0]))
            except ValueError as error:
                raise ValueError("collection budget checkpoint is invalid") from error
            if (
                checkpoint.case_id != case_id
                or checkpoint.state_version != epoch_state_version
                or admitted_at > _utc(checkpoint.deadline_at, name="case deadline")
            ):
                raise ValueError("collection epoch or deadline is stale")
            history_rows = self.store.connection.execute(
                "SELECT probe_id FROM probe_executions WHERE case_id=?", (case_id,)
            ).fetchall()
            history_ids = {str(row[0]) for row in history_rows}
            unknown_completed = set(
                (*checkpoint.completed_probe_ids, *checkpoint.pending_probe_ids)
            ).difference(history_ids, checkpoint.interrupted_probe_ids)
            unresolved_row = self.store.connection.execute(
                "SELECT COUNT(*) FROM collection_followup_admissions AS a "
                "LEFT JOIN collection_followup_execution_links AS l "
                "ON l.admission_id=a.admission_id "
                "WHERE a.case_id=? AND a.epoch_state_version=? AND l.admission_id IS NULL",
                (case_id, epoch_state_version),
            ).fetchone()
            assert unresolved_row is not None
            attempts_reserved = (
                len(history_rows)
                + len(unknown_completed)
                + checkpoint.unrecorded_attempt_count
                + int(unresolved_row[0])
            )
            if attempts_reserved + 1 > checkpoint.max_probes:
                raise ValueError("follow-up probe slot budget exhausted")
            cost_row = self.store.connection.execute(
                "SELECT COALESCE(SUM(estimated_cost_ms),0) FROM collection_followup_admissions "
                "WHERE case_id=? AND epoch_state_version=?",
                (case_id, epoch_state_version),
            ).fetchone()
            assert cost_row is not None
            if (
                checkpoint.spent_cost_ms + int(cost_row[0]) + estimated_cost_ms
                > checkpoint.budget_ms
            ):
                raise ValueError("follow-up cost budget exhausted")
            parent = self.store.connection.execute(
                "SELECT case_id,state_version,status,started_at,finished_at "
                "FROM probe_executions WHERE execution_id=?",
                (trigger_execution_id,),
            ).fetchone()
            if (
                parent is None
                or str(parent[0]) != case_id
                or int(parent[1]) != epoch_state_version
                or str(parent[2]) != "ok"
                or parent[4] is None
            ):
                raise ValueError("successful same-epoch parent execution is required")
            parent_start = _parse_utc(parent[3], name="parent start")
            parent_finished = _parse_utc(parent[4], name="parent finish")
            if not parent_start <= parent_finished <= admitted_at:
                raise ValueError("parent/admission chronology invalid")
            evidence_digest = self._parent_evidence_digest(case_id, trigger_execution_id)
            generation_row = self.store.connection.execute(
                "SELECT generation FROM evidence_case_generations WHERE case_id=?", (case_id,)
            ).fetchone()
            if generation_row is None or int(generation_row[0]) != expected_evidence_generation:
                raise ValueError("case evidence generation changed before admission")
            if decision_snapshot_id is not None:
                snapshot = self.store.connection.execute(
                    "SELECT case_id,state_version,request_sha256,candidate_probe_ids_json,"
                    "request_frozen_at,captured_at FROM decision_snapshots WHERE snapshot_id=?",
                    (decision_snapshot_id,),
                ).fetchone()
                if (
                    snapshot is None
                    or str(snapshot[0]) != case_id
                    or int(snapshot[1]) != epoch_state_version
                    or str(snapshot[2]) != request_sha256
                    or invocation.probe_id not in json.loads(str(snapshot[3]))
                    or snapshot[4] is None
                ):
                    raise ValueError("decision snapshot does not bind follow-up")
                frozen_at = _parse_utc(snapshot[4], name="request freeze time")
                captured_at = _parse_utc(snapshot[5], name="snapshot capture time")
                if not parent_finished <= frozen_at <= captured_at <= admitted_at:
                    raise ValueError("decision/admission chronology invalid")
            admission = FollowupAdmission(
                admission_id=f"followup_admission_{uuid4().hex}",
                case_id=case_id,
                epoch_state_version=epoch_state_version,
                trigger_execution_id=trigger_execution_id,
                evidence_generation=expected_evidence_generation,
                trigger_evidence_sha256=evidence_digest,
                decision_snapshot_id=decision_snapshot_id,
                request_sha256=request_sha256,
                invocation=invocation,
                invocation_sha256=invocation_sha256,
                dedupe_key=invocation.dedupe_key,
                task_id=task_id,
                estimated_cost_ms=estimated_cost_ms,
                admitted_at=admitted_at,
            )
            try:
                self.store.connection.execute(
                    "INSERT INTO collection_followup_admissions "
                    "(admission_id,schema_version,case_id,epoch_state_version,"
                    "trigger_execution_id,evidence_generation,trigger_evidence_sha256,"
                    "decision_snapshot_id,request_sha256,invocation_json,invocation_sha256,"
                    "dedupe_key,task_id,estimated_cost_ms,admitted_at) "
                    "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        admission.admission_id,
                        admission.schema_version,
                        case_id,
                        epoch_state_version,
                        trigger_execution_id,
                        expected_evidence_generation,
                        evidence_digest,
                        decision_snapshot_id,
                        request_sha256,
                        canonical_invocation,
                        invocation_sha256,
                        admission.dedupe_key,
                        task_id,
                        estimated_cost_ms,
                        admitted_at.isoformat(),
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise ValueError("duplicate or invalid follow-up admission") from error
        return admission

    def link_execution(self, *, admission_id: str, execution_id: str) -> None:
        """Call only inside the child execution/evidence/audit write transaction."""

        connection = self.store.connection
        if not connection.in_transaction:
            raise ValueError("follow-up outcome link requires an active transaction")
        row = connection.execute(
            "SELECT a.case_id,a.epoch_state_version,a.trigger_execution_id,"
            "a.invocation_json,a.invocation_sha256,a.admitted_at,"
            "e.case_id,e.state_version,e.probe_id,e.probe_version,e.parameters_json,"
            "e.started_at,e.finished_at,e.status,e.followup_admission_id "
            "FROM collection_followup_admissions AS a "
            "JOIN probe_executions AS e ON e.execution_id=? "
            "WHERE a.admission_id=?",
            (execution_id, admission_id),
        ).fetchone()
        if row is None:
            raise ValueError("follow-up admission or execution unavailable")
        case = self.store.case(str(row[0]))
        if case is None or case.status != "collecting" or case.state_version != int(row[1]):
            raise ValueError("follow-up collection epoch changed before outcome link")
        invocation_json = str(row[3])
        try:
            invocation = ProbeInvocation.model_validate_json(invocation_json)
            parameters = json.loads(str(row[10]))
        except ValueError as error:
            raise ValueError("follow-up invocation is invalid") from error
        if (
            str(row[0]) != str(row[6])
            or int(row[1]) != int(row[7])
            or str(row[2]) == execution_id
            or invocation.probe_id != str(row[8])
            or invocation.probe_version != int(row[9])
            or invocation.parameters != parameters
            or _sha256(invocation_json) != str(row[4])
            or str(row[13]) not in _RUN_STATUSES
            or row[12] is None
            or str(row[14]) != admission_id
        ):
            raise ValueError("follow-up execution admission identity or invocation mismatch")
        admitted_at = _parse_utc(row[5], name="admission time")
        started_at = _parse_utc(row[11], name="execution start")
        finished_at = _parse_utc(row[12], name="execution finish")
        if not admitted_at <= started_at <= finished_at:
            raise ValueError("follow-up execution chronology invalid")
        try:
            connection.execute(
                "INSERT INTO collection_followup_execution_links "
                "(admission_id,schema_version,execution_id,linked_at) VALUES (?,1,?,?)",
                (admission_id, execution_id, datetime.now(UTC).isoformat()),
            )
        except sqlite3.IntegrityError as error:
            raise ValueError("duplicate or invalid follow-up outcome link") from error

    def readback(
        self, *, case_id: str, epoch_state_version: int
    ) -> tuple[FollowupAdmissionReadback, ...]:
        """Return factual links; an unlinked admission is uncertain, not runnable."""

        rows = self.store.connection.execute(
            "SELECT a.admission_id,a.schema_version,a.case_id,a.epoch_state_version,"
            "a.task_id,a.trigger_execution_id,a.request_sha256,a.decision_snapshot_id,"
            "a.invocation_json,a.invocation_sha256,a.dedupe_key,"
            "l.schema_version,l.execution_id,e.case_id,e.state_version,e.probe_id,"
            "e.probe_version,e.parameters_json,e.status,a.evidence_generation,"
            "a.trigger_evidence_sha256,a.estimated_cost_ms,a.admitted_at,"
            "e.followup_admission_id,e.started_at,e.finished_at "
            "FROM collection_followup_admissions AS a "
            "LEFT JOIN collection_followup_execution_links AS l ON l.admission_id=a.admission_id "
            "LEFT JOIN probe_executions AS e ON e.execution_id=l.execution_id "
            "WHERE a.case_id=? AND a.epoch_state_version=? "
            "ORDER BY a.admitted_at,a.admission_id",
            (case_id, epoch_state_version),
        ).fetchall()
        result: list[FollowupAdmissionReadback] = []
        for row in rows:
            invocation_json = str(row[8])
            try:
                invocation = ProbeInvocation.model_validate_json(invocation_json)
                linked_parameters = None if row[17] is None else json.loads(str(row[17]))
            except ValueError as error:
                raise ValueError("follow-up admission readback is invalid") from error
            if (
                int(row[1]) != 1
                or str(row[2]) != case_id
                or int(row[3]) != epoch_state_version
                or _sha256(invocation_json) != str(row[9])
                or invocation.dedupe_key != str(row[10])
                or int(row[19]) < 1
                or _DIGEST.fullmatch(str(row[20])) is None
                or not 1 <= int(row[21]) <= 120_000
            ):
                raise ValueError("follow-up admission readback binding mismatch")
            admitted_at = _parse_utc(row[22], name="admission time")
            parent = self.store.connection.execute(
                "SELECT case_id,state_version,status,started_at,finished_at "
                "FROM probe_executions WHERE execution_id=?",
                (str(row[5]),),
            ).fetchone()
            if (
                parent is None
                or str(parent[0]) != case_id
                or int(parent[1]) != epoch_state_version
                or str(parent[2]) != "ok"
                or parent[4] is None
            ):
                raise ValueError("follow-up parent execution readback binding mismatch")
            parent_start = _parse_utc(parent[3], name="parent start")
            parent_finished = _parse_utc(parent[4], name="parent finish")
            if not parent_start <= parent_finished <= admitted_at:
                raise ValueError("follow-up parent readback chronology invalid")
            if self._parent_evidence_digest(case_id, str(row[5])) != str(row[20]):
                raise ValueError("follow-up parent evidence readback digest mismatch")
            execution_id = None if row[12] is None else str(row[12])
            status = "uncertain"
            if execution_id is not None:
                if (
                    int(row[11]) != 1
                    or str(row[13]) != case_id
                    or int(row[14]) != epoch_state_version
                    or str(row[15]) != invocation.probe_id
                    or int(row[16]) != invocation.probe_version
                    or linked_parameters != invocation.parameters
                    or str(row[18]) not in _RUN_STATUSES
                    or str(row[23]) != str(row[0])
                ):
                    raise ValueError("follow-up outcome readback binding mismatch")
                started_at = _parse_utc(row[24], name="execution start")
                finished_at = _parse_utc(row[25], name="execution finish")
                if not admitted_at <= started_at <= finished_at:
                    raise ValueError("follow-up outcome readback chronology invalid")
                status = str(row[18])
            result.append(
                FollowupAdmissionReadback(
                    admission_id=str(row[0]),
                    case_id=case_id,
                    epoch_state_version=epoch_state_version,
                    task_id=str(row[4]),
                    trigger_execution_id=str(row[5]),
                    evidence_generation=int(row[19]),
                    trigger_evidence_sha256=str(row[20]),
                    request_sha256=str(row[6]),
                    decision_snapshot_id=None if row[7] is None else str(row[7]),
                    invocation_sha256=str(row[9]),
                    dedupe_key=str(row[10]),
                    estimated_cost_ms=int(row[21]),
                    admitted_at=admitted_at,
                    execution_id=execution_id,
                    outcome_status=status,
                )
            )
        return tuple(result)

    def _parent_evidence_digest(self, case_id: str, execution_id: str) -> str:
        execution = self.store.connection.execute(
            "SELECT probe_id,probe_version FROM probe_executions "
            "WHERE case_id=? AND execution_id=?",
            (case_id, execution_id),
        ).fetchone()
        if execution is None:
            raise ValueError("successful parent execution is unavailable")
        evidence_rows = self.store.connection.execute(
            "SELECT evidence_id,source_id,record_json FROM evidence "
            "WHERE case_id=? AND execution_id=? ORDER BY evidence_id",
            (case_id, execution_id),
        ).fetchall()
        if not evidence_rows:
            raise ValueError("successful parent has no persisted evidence")
        has_observation = False
        for row in evidence_rows:
            try:
                record = EvidenceRecord.model_validate_json(str(row[2]))
            except ValueError:
                continue  # Explicit coverage and malformed rows are not observations.
            if (
                record.statement_kind is StatementKind.OBSERVED_FACT
                and str(record.evidence_id) == str(row[0])
                and str(record.case_id) == case_id
                and record.source.source_id == str(row[1])
                and record.collector.id == str(execution[0])
                and record.collector.version == int(execution[1])
                and str(record.collector.execution_id) == execution_id
            ):
                has_observation = True
        if not has_observation:
            raise ValueError("successful parent has no persisted typed observation")
        return _sha256(_canonical([(str(row[0]), _sha256(str(row[2]))) for row in evidence_rows]))
