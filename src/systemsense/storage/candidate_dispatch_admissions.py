"""One-shot, append-only budget intents for model-selected candidate measurements.

This ledger never grants OS access. The application dispatcher still owns the
registered probe policy, current manifest, live target identity, and deadline.
"""

from __future__ import annotations

import hashlib
import json
import re
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Literal, Protocol
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from systemsense.domain.ids import CaseId
from systemsense.domain.probes import ProbeInvocation
from systemsense.domain.time import ensure_utc, utc_now
from systemsense.storage.candidate_decision_snapshots import (
    CandidateDecisionSnapshotRepository,
)
from systemsense.storage.case_candidates import CandidateGap, CandidateResolution
from systemsense.storage.sqlite_store import SQLiteStore

_ADMISSION_ID = re.compile(r"candidate_admission_[0-9a-f]{32}\Z")
_TASK_ID = re.compile(r"[a-zA-Z0-9_.:-]{1,160}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")


class CandidateResolver(Protocol):
    def resolve(
        self, case_id: CaseId, epoch_state_version: int, candidate_id: str
    ) -> CandidateResolution | CandidateGap: ...


@dataclass(frozen=True, slots=True)
class CandidateDispatchAdmission:
    admission_id: str
    snapshot_id: str
    candidate_id: str
    case_id: CaseId
    epoch_state_version: int
    task_id: str
    invocation_sha256: str
    cost_ms: int
    admitted_at: datetime
    claimed_at: datetime | None
    execution_id: str | None
    outcome_status: Literal["unclaimed", "claimed_unlinked", "linked"]
    replay_allowed: Literal[False] = False
    dispatch_authorized: Literal[False] = False


class _BudgetCheckpoint(BaseModel):
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


def _utc(value: datetime, *, name: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(None):
        raise ValueError(f"{name} must be UTC")
    return ensure_utc(value)


def _parse_utc(value: object, *, name: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(str(value))
    except ValueError as error:
        raise ValueError(f"{name} is invalid") from error
    return _utc(parsed, name=name)


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


class CandidateDispatchAdmissionRepository:
    """Durably reserve before queueing; claim exactly once before host access."""

    def __init__(
        self,
        store: SQLiteStore,
        *,
        registry: CandidateResolver | None = None,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._store = store
        self._registry = registry
        self._clock = clock
        self._snapshots = CandidateDecisionSnapshotRepository(store, clock=clock)

    def admit(
        self,
        *,
        snapshot_id: str,
        candidate_id: str,
        case_id: CaseId,
        epoch_state_version: int,
        task_id: str,
        invocation_sha256: str,
        cost_ms: int,
    ) -> CandidateDispatchAdmission:
        """Atomically reserve one trusted cost and slot for an exact proposal."""

        if (
            self._registry is None
            or epoch_state_version < 0
            or _TASK_ID.fullmatch(task_id) is None
            or _DIGEST.fullmatch(invocation_sha256) is None
            or not 1 <= cost_ms <= 120_000
        ):
            raise ValueError("candidate dispatch identity is invalid")
        with self._store.transaction():
            now = _utc(self._clock(), name="admission time")
            self._snapshots.verify_selection(
                snapshot_id, case_id, epoch_state_version, candidate_id, invocation_sha256
            )
            resolved = self._registry.resolve(case_id, epoch_state_version, candidate_id)
            if isinstance(resolved, CandidateGap):
                raise ValueError(f"candidate is no longer eligible: {resolved.reason}")
            invocation_json = json.dumps(
                resolved.invocation.model_dump(mode="json"),
                sort_keys=True,
                separators=(",", ":"),
                ensure_ascii=False,
                allow_nan=False,
            )
            if (
                resolved.candidate.candidate_id != candidate_id
                or resolved.candidate.invocation_sha256 != invocation_sha256
                or _digest(invocation_json) != invocation_sha256
                or resolved.candidate.cost_ms != cost_ms
            ):
                raise ValueError("candidate invocation or cost differs from trusted registry")
            if (
                self._store.connection.execute(
                    "SELECT 1 FROM candidate_dispatch_admissions WHERE candidate_id=?",
                    (candidate_id,),
                ).fetchone()
                is not None
            ):
                raise ValueError("candidate was already admitted; replay is forbidden")
            self._require_budget(case_id, epoch_state_version, cost_ms, now)
            snapshot = self._snapshots.readback(snapshot_id)
            if not snapshot.captured_at <= now:
                raise ValueError("admission precedes frozen candidate decision")
            admission_id = f"candidate_admission_{uuid4().hex}"
            try:
                self._store.connection.execute(
                    "INSERT INTO candidate_dispatch_admissions ("
                    "admission_id,schema_version,snapshot_id,candidate_id,case_id,"
                    "epoch_state_version,task_id,invocation_sha256,cost_ms,admitted_at) "
                    "VALUES (?,1,?,?,?,?,?,?,?,?)",
                    (
                        admission_id,
                        snapshot_id,
                        candidate_id,
                        str(case_id),
                        epoch_state_version,
                        task_id,
                        invocation_sha256,
                        cost_ms,
                        now.isoformat(),
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise ValueError("candidate or task was already admitted") from error
            return self.readback(admission_id)

    def verify_admitted(
        self,
        admission_id: str,
        *,
        case_id: CaseId,
        epoch_state_version: int,
        task_id: str,
        invocation_sha256: str,
    ) -> CandidateDispatchAdmission:
        """Identity check only; this does not claim, dispatch, or authorize host access."""

        record = self.readback(admission_id)
        case = self._store.case(str(case_id))
        if (
            record.case_id != case_id
            or record.epoch_state_version != epoch_state_version
            or record.task_id != task_id
            or record.invocation_sha256 != invocation_sha256
            or case is None
            or case.status != "collecting"
            or case.state_version != epoch_state_version
        ):
            raise ValueError("candidate dispatch admission is stale or does not bind task")
        return record

    def claim_for_worker(
        self,
        admission_id: str,
        *,
        case_id: CaseId,
        epoch_state_version: int,
        task_id: str,
        invocation_sha256: str,
    ) -> CandidateDispatchAdmission:
        """One-shot claim; caller must still revalidate live target and probe policy."""

        with self._store.transaction():
            record = self.verify_admitted(
                admission_id,
                case_id=case_id,
                epoch_state_version=epoch_state_version,
                task_id=task_id,
                invocation_sha256=invocation_sha256,
            )
            if record.claimed_at is not None:
                raise ValueError("candidate dispatch is already claimed")
            now = _utc(self._clock(), name="claim time")
            self._checkpoint(case_id, epoch_state_version, now)
            candidate = self._store.connection.execute(
                "SELECT expires_at FROM case_measurement_candidates WHERE candidate_id=? "
                "AND case_id=? AND epoch_state_version=?",
                (record.candidate_id, str(case_id), epoch_state_version),
            ).fetchone()
            if candidate is None or now >= _parse_utc(candidate[0], name="candidate expiry"):
                raise ValueError("candidate expired before dispatch claim")
            if now < record.admitted_at:
                raise ValueError("claim precedes candidate admission")
            try:
                self._store.connection.execute(
                    "INSERT INTO candidate_dispatch_claims ("
                    "admission_id,case_id,epoch_state_version,task_id,"
                    "invocation_sha256,claimed_at) "
                    "VALUES (?,?,?,?,?,?)",
                    (
                        admission_id,
                        str(case_id),
                        epoch_state_version,
                        task_id,
                        invocation_sha256,
                        now.isoformat(),
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise ValueError("candidate dispatch is already claimed") from error
            return self.readback(admission_id)

    def readback(self, admission_id: str) -> CandidateDispatchAdmission:
        """Historical provenance; an unlinked admission is uncertain, never replayable."""

        if _ADMISSION_ID.fullmatch(admission_id) is None:
            raise ValueError("candidate dispatch admission ID is invalid")
        row = self._store.connection.execute(
            "SELECT schema_version,snapshot_id,candidate_id,case_id,epoch_state_version,"
            "task_id,invocation_sha256,cost_ms,admitted_at "
            "FROM candidate_dispatch_admissions WHERE admission_id=?",
            (admission_id,),
        ).fetchone()
        if row is None:
            raise ValueError("candidate dispatch admission is unavailable")
        snapshot_id, candidate_id, case_id = str(row[1]), str(row[2]), CaseId(root=str(row[3]))
        epoch, task_id, invocation_sha256 = int(row[4]), str(row[5]), str(row[6])
        cost_ms, admitted_at = int(row[7]), _parse_utc(row[8], name="admission time")
        snapshot = self._snapshots.readback(snapshot_id)
        if (
            int(row[0]) != 1
            or _TASK_ID.fullmatch(task_id) is None
            or _DIGEST.fullmatch(invocation_sha256) is None
            or snapshot.case_id != case_id
            or snapshot.epoch_state_version != epoch
            or not snapshot.captured_at <= admitted_at
        ):
            raise ValueError("candidate dispatch admission binding is invalid")
        proposed = getattr(snapshot.response, "proposals", ())
        refs = [
            item
            for item in snapshot.request.available_candidates
            if item.candidate_id == candidate_id
        ]
        if (
            len(refs) != 1
            or candidate_id not in (item.candidate_id for item in proposed)
            or refs[0].invocation_sha256 != invocation_sha256
            or refs[0].cost_ms != cost_ms
        ):
            raise ValueError("candidate dispatch admission differs from frozen proposal")
        claim = self._store.connection.execute(
            "SELECT case_id,epoch_state_version,task_id,invocation_sha256,claimed_at "
            "FROM candidate_dispatch_claims WHERE admission_id=?",
            (admission_id,),
        ).fetchone()
        claimed_at: datetime | None = None
        if claim is not None:
            claimed_at = _parse_utc(claim[4], name="claim time")
            if (
                str(claim[0]) != str(case_id)
                or int(claim[1]) != epoch
                or str(claim[2]) != task_id
                or str(claim[3]) != invocation_sha256
                or claimed_at < admitted_at
            ):
                raise ValueError("candidate dispatch claim binding is invalid")
        links = self._snapshots.execution_links(snapshot_id)
        matching = [item for item in links if item.candidate_id == candidate_id]
        if len(matching) > 1 or (matching and claimed_at is None):
            raise ValueError("candidate execution lacks a one-shot dispatch claim")
        execution_id = matching[0].execution_id if matching else None
        if execution_id is not None:
            execution = self._store.connection.execute(
                "SELECT started_at FROM probe_executions WHERE execution_id=?",
                (execution_id,),
            ).fetchone()
            if (
                execution is None
                or claimed_at is None
                or _parse_utc(execution[0], name="execution start") < claimed_at
            ):
                raise ValueError("candidate execution precedes one-shot worker claim")
        status: Literal["unclaimed", "claimed_unlinked", "linked"] = (
            "linked"
            if execution_id is not None
            else "claimed_unlinked"
            if claimed_at
            else "unclaimed"
        )
        return CandidateDispatchAdmission(
            admission_id=admission_id,
            snapshot_id=snapshot_id,
            candidate_id=candidate_id,
            case_id=case_id,
            epoch_state_version=epoch,
            task_id=task_id,
            invocation_sha256=invocation_sha256,
            cost_ms=cost_ms,
            admitted_at=admitted_at,
            claimed_at=claimed_at,
            execution_id=execution_id,
            outcome_status=status,
        )

    def link_execution(
        self,
        admission_id: str,
        execution_id: str,
        executed_invocation: ProbeInvocation,
    ) -> CandidateDispatchAdmission:
        """Bind a finished execution after a one-shot claim, in caller transaction."""

        if not self._store.connection.in_transaction:
            raise ValueError("candidate execution link requires caller-owned transaction")
        admission = self.readback(admission_id)
        if admission.claimed_at is None or admission.execution_id is not None:
            raise ValueError("candidate execution requires unused worker claim")
        invocation_json = json.dumps(
            executed_invocation.model_dump(mode="json"),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        )
        if _digest(invocation_json) != admission.invocation_sha256:
            raise ValueError("candidate execution invocation differs from admission")
        execution = self._store.connection.execute(
            "SELECT started_at,finished_at FROM probe_executions WHERE execution_id=? "
            "AND case_id=? AND state_version=?",
            (execution_id, str(admission.case_id), admission.epoch_state_version),
        ).fetchone()
        if execution is None or execution[1] is None:
            raise ValueError("candidate execution is not finished in admitted epoch")
        started = _parse_utc(execution[0], name="execution start")
        finished = _parse_utc(execution[1], name="execution finish")
        if not admission.claimed_at <= started <= finished:
            raise ValueError("candidate execution precedes one-shot worker claim")
        self._snapshots.link_execution(
            admission.snapshot_id,
            admission.candidate_id,
            execution_id,
            executed_invocation,
        )
        return self.readback(admission_id)

    def _checkpoint(self, case_id: CaseId, epoch: int, now: datetime) -> _BudgetCheckpoint:
        case = self._store.case(str(case_id))
        if case is None or case.status != "collecting" or case.state_version != epoch:
            raise ValueError("candidate dispatch case epoch is stale")
        row = self._store.connection.execute(
            "SELECT record_json FROM investigation_checkpoints WHERE case_id=?",
            (str(case_id),),
        ).fetchone()
        if row is None:
            raise ValueError("candidate dispatch budget checkpoint is missing")
        try:
            checkpoint = _BudgetCheckpoint.model_validate_json(str(row[0]))
        except ValueError as error:
            raise ValueError("candidate dispatch budget checkpoint is invalid") from error
        if (
            checkpoint.case_id != str(case_id)
            or checkpoint.state_version != epoch
            or now >= _utc(checkpoint.deadline_at, name="case deadline")
        ):
            raise ValueError("candidate dispatch case deadline is stale")
        return checkpoint

    def _require_budget(self, case_id: CaseId, epoch: int, cost_ms: int, now: datetime) -> None:
        checkpoint = self._checkpoint(case_id, epoch, now)
        history_rows = self._store.connection.execute(
            "SELECT probe_id FROM probe_executions WHERE case_id=?", (str(case_id),)
        ).fetchall()
        history_ids = {str(row[0]) for row in history_rows}
        unknown = set((*checkpoint.completed_probe_ids, *checkpoint.pending_probe_ids)).difference(
            history_ids, checkpoint.interrupted_probe_ids
        )
        followup = self._store.connection.execute(
            "SELECT COUNT(*),COALESCE(SUM(a.estimated_cost_ms),0) "
            "FROM collection_followup_admissions AS a "
            "LEFT JOIN collection_followup_execution_links AS l "
            "ON l.admission_id=a.admission_id "
            "WHERE a.case_id=? AND a.epoch_state_version=? AND l.admission_id IS NULL",
            (str(case_id), epoch),
        ).fetchone()
        candidate = self._store.connection.execute(
            "SELECT COUNT(*),COALESCE(SUM(a.cost_ms),0) "
            "FROM candidate_dispatch_admissions AS a "
            "LEFT JOIN candidate_decision_execution_links AS l "
            "ON l.snapshot_id=a.snapshot_id AND l.candidate_id=a.candidate_id "
            "WHERE a.case_id=? AND l.execution_id IS NULL",
            (str(case_id),),
        ).fetchone()
        all_candidate_cost = self._store.connection.execute(
            "SELECT COALESCE(SUM(cost_ms),0) FROM candidate_dispatch_admissions WHERE case_id=?",
            (str(case_id),),
        ).fetchone()
        assert followup is not None and candidate is not None and all_candidate_cost is not None
        slots = (
            len(history_rows)
            + len(unknown)
            + checkpoint.unrecorded_attempt_count
            + int(followup[0])
            + int(candidate[0])
        )
        cost = checkpoint.spent_cost_ms + int(followup[1]) + int(all_candidate_cost[0])
        if slots + 1 > checkpoint.max_probes:
            raise ValueError("candidate dispatch probe slot budget exhausted")
        if cost + cost_ms > checkpoint.budget_ms:
            raise ValueError("candidate dispatch cost budget exhausted")
