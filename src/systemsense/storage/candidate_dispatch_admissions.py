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
from contextlib import nullcontext
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

from systemsense.decision.candidates import CandidateDecisionResponseV1
from systemsense.domain.ids import CaseId
from systemsense.domain.probes import ProbeInvocation
from systemsense.domain.time import ensure_utc, utc_now
from systemsense.storage.candidate_decision_snapshots import (
    CandidateDecisionSnapshotRepository,
    FrontierCandidateSnapshot,
)
from systemsense.storage.case_candidates import (
    CandidateGap,
    CandidateResolution,
    CaseCandidateRegistry,
)
from systemsense.storage.followup_admissions import FollowupAdmissionRepository
from systemsense.storage.sqlite_store import SQLiteStore

_ADMISSION_ID = re.compile(r"candidate_admission_[0-9a-f]{32}\Z")
_TASK_ID = re.compile(r"[a-zA-Z0-9_.:-]{1,160}\Z")
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_CONTINUATION_ID = re.compile(r"candidate_launch_v1_[0-9a-f]{32}\Z")


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


@dataclass(frozen=True, slots=True)
class CandidateLaunchContinuation:
    continuation_id: str
    admission_id: str
    turn_id: str
    case_id: CaseId
    epoch_state_version: int
    resulting_checkpoint_version: int
    owner_started_version: int
    task_id: str
    invocation_sha256: str
    deadline_at: datetime
    created_at: datetime
    consumed_at: datetime | None


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
        transaction = (
            nullcontext() if self._store.connection.in_transaction else self._store.transaction()
        )
        with transaction:
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
            snapshot = (
                self._snapshots.readback_frontier(snapshot_id)
                if snapshot_id.startswith("frontier_decision_snapshot_")
                else self._snapshots.readback(snapshot_id)
            )
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

    def admit_after_parent(
        self,
        *,
        snapshot_id: str,
        candidate_id: str,
        case_id: CaseId,
        epoch_state_version: int,
        task_id: str,
        invocation_sha256: str,
        cost_ms: int,
        trigger_execution_id: str,
        trigger_evidence_sha256: str,
    ) -> CandidateDispatchAdmission:
        """Reserve an exact candidate and its persisted trigger in one transaction."""

        if _DIGEST.fullmatch(trigger_evidence_sha256) is None:
            raise ValueError("candidate follow-up parent digest is invalid")
        with self._store.transaction():
            parent = self._store.connection.execute(
                "SELECT case_id,state_version,status,finished_at FROM probe_executions "
                "WHERE execution_id=?",
                (trigger_execution_id,),
            ).fetchone()
            if (
                parent is None
                or str(parent[0]) != str(case_id)
                or int(parent[1]) != epoch_state_version
                or str(parent[2]) != "ok"
                or parent[3] is None
            ):
                raise ValueError("candidate follow-up parent is unavailable")
            candidate = self._store.connection.execute(
                "SELECT probe_id FROM case_measurement_candidates "
                "WHERE case_id=? AND candidate_id=?",
                (str(case_id), candidate_id),
            ).fetchone()
            expected_sources = {
                "pressure.sample": "core.resources",
                "gpu.telemetry.sample": "local_ai.snapshot",
            }
            expected_source = expected_sources.get(str(candidate[0])) if candidate else None
            if expected_source is not None:
                source = self._store.connection.execute(
                    "SELECT e.execution_id,x.probe_id "
                    "FROM case_measurement_candidates AS c "
                    "JOIN evidence AS e ON e.case_id=c.case_id "
                    "AND e.evidence_id=c.source_evidence_id "
                    "JOIN probe_executions AS x ON x.case_id=e.case_id "
                    "AND x.execution_id=e.execution_id "
                    "WHERE c.case_id=? AND c.candidate_id=?",
                    (str(case_id), candidate_id),
                ).fetchone()
                if (
                    source is None
                    or str(source[1]) != expected_source
                    or str(source[0]) != trigger_execution_id
                ):
                    raise ValueError("candidate follow-up source is not the exact parent execution")
            snapshot = (
                self._snapshots.readback_frontier(snapshot_id)
                if snapshot_id.startswith("frontier_decision_snapshot_")
                else self._snapshots.readback(snapshot_id)
            )
            if (
                snapshot.case_id != case_id
                or snapshot.epoch_state_version != epoch_state_version
                or _parse_utc(parent[3], name="parent finish") > snapshot.request_frozen_at
            ):
                raise ValueError("candidate follow-up parent/request chronology is invalid")
            self._verify_parent_digest(case_id, trigger_execution_id, trigger_evidence_sha256)
            admission = self.admit(
                snapshot_id=snapshot_id,
                candidate_id=candidate_id,
                case_id=case_id,
                epoch_state_version=epoch_state_version,
                task_id=task_id,
                invocation_sha256=invocation_sha256,
                cost_ms=cost_ms,
            )
            self._store.connection.execute(
                "INSERT INTO candidate_followup_parents "
                "(admission_id,case_id,epoch_state_version,trigger_execution_id,"
                "trigger_evidence_sha256,bound_at) VALUES (?,?,?,?,?,?)",
                (
                    admission.admission_id,
                    str(case_id),
                    epoch_state_version,
                    trigger_execution_id,
                    trigger_evidence_sha256,
                    admission.admitted_at.isoformat(),
                ),
            )
            return admission

    def parent_binding(self, admission_id: str) -> tuple[str, str] | None:
        """Read an immutable trigger binding, when this was an async candidate."""

        row = self._store.connection.execute(
            "SELECT case_id,epoch_state_version,trigger_execution_id,"
            "trigger_evidence_sha256 FROM candidate_followup_parents WHERE admission_id=?",
            (admission_id,),
        ).fetchone()
        if row is None:
            return None
        admission = self.readback(admission_id)
        if str(row[0]) != str(admission.case_id) or int(row[1]) != admission.epoch_state_version:
            raise ValueError("candidate follow-up parent identity is invalid")
        return str(row[2]), str(row[3])

    def _verify_parent_digest(
        self, case_id: CaseId, execution_id: str, expected_digest: str
    ) -> None:
        try:
            actual = FollowupAdmissionRepository(self._store).parent_evidence_digest(
                str(case_id), execution_id
            )
        except ValueError as error:
            raise ValueError("candidate follow-up parent evidence unavailable") from error
        if actual != expected_digest:
            raise ValueError("candidate follow-up parent evidence changed")

    def admit_in_transaction(
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
        if not self._store.connection.in_transaction:
            raise ValueError("candidate admission requires caller transaction")
        return self.admit(
            snapshot_id=snapshot_id,
            candidate_id=candidate_id,
            case_id=case_id,
            epoch_state_version=epoch_state_version,
            task_id=task_id,
            invocation_sha256=invocation_sha256,
            cost_ms=cost_ms,
        )

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

        transaction = (
            nullcontext() if self._store.connection.in_transaction else self._store.transaction()
        )
        with transaction:
            record = self.verify_admitted(
                admission_id,
                case_id=case_id,
                epoch_state_version=epoch_state_version,
                task_id=task_id,
                invocation_sha256=invocation_sha256,
            )
            parent_binding = self.parent_binding(admission_id)
            if parent_binding is not None:
                self._verify_parent_digest(record.case_id, *parent_binding)
            if record.claimed_at is not None:
                raise ValueError("candidate dispatch is already claimed")
            now = _utc(self._clock(), name="claim time")
            self._checkpoint(case_id, epoch_state_version, now)
            if record.snapshot_id.startswith("frontier_decision_snapshot_"):
                if not isinstance(self._registry, CaseCandidateRegistry):
                    raise ValueError("frontier worker claim requires live candidate registry")
                self._snapshots.verify_selection(
                    record.snapshot_id,
                    case_id,
                    epoch_state_version,
                    record.candidate_id,
                    invocation_sha256,
                )
                resolved = self._registry.resolve_for_claim(
                    case_id,
                    epoch_state_version,
                    record.candidate_id,
                    admission_id,
                )
                if (
                    isinstance(resolved, CandidateGap)
                    or resolved.candidate.invocation_sha256 != invocation_sha256
                    or resolved.candidate.cost_ms != record.cost_ms
                ):
                    raise ValueError("frontier worker candidate registry changed")
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

    def claim_for_worker_in_transaction(
        self,
        admission_id: str,
        *,
        case_id: CaseId,
        epoch_state_version: int,
        task_id: str,
        invocation_sha256: str,
    ) -> CandidateDispatchAdmission:
        if not self._store.connection.in_transaction:
            raise ValueError("candidate claim requires caller transaction")
        return self.claim_for_worker(
            admission_id,
            case_id=case_id,
            epoch_state_version=epoch_state_version,
            task_id=task_id,
            invocation_sha256=invocation_sha256,
        )

    def create_launch_continuation_in_transaction(
        self,
        admission_id: str,
        *,
        turn_id: str,
        owner_started_version: int,
        resulting_checkpoint_version: int,
        deadline_at: datetime,
    ) -> CandidateLaunchContinuation:
        """Bind a consumed claim to only the next owner checkpoint save.

        The caller must insert this and the turn outcome in the same transaction
        as the N→N+1 checkpoint transition. Rolling back the save rolls back
        this prospective launch permit too.
        """

        if not self._store.connection.in_transaction:
            raise ValueError("candidate continuation requires caller transaction")
        admission = self.readback(admission_id)
        now = _utc(self._clock(), name="continuation time")
        deadline = _utc(deadline_at, name="continuation deadline")
        checkpoint = self._checkpoint(admission.case_id, admission.epoch_state_version, now)
        snapshot = (
            self._snapshots.readback_frontier(admission.snapshot_id)
            if admission.snapshot_id.startswith("frontier_decision_snapshot_")
            else self._snapshots.readback(admission.snapshot_id)
        )
        if (
            admission.claimed_at is None
            or admission.execution_id is not None
            or admission.claimed_at > now
        ):
            raise ValueError("candidate continuation requires unused one-shot claim")
        if (
            resulting_checkpoint_version != admission.epoch_state_version + 1
            or owner_started_version < 1
            or owner_started_version > admission.epoch_state_version
        ):
            raise ValueError("candidate continuation checkpoint is invalid")
        if now >= deadline or deadline > min(
            checkpoint.deadline_at,
            snapshot.request.deadline_at,
            now + timedelta(seconds=2),
        ):
            raise ValueError("candidate continuation deadline is invalid")
        from systemsense.storage.search_frontier import SearchFrontierRepository

        turn = SearchFrontierRepository(self._store).read_investigator_turn(turn_id)
        if (
            turn.case_id != admission.case_id
            or turn.expected_checkpoint_version != admission.epoch_state_version
            or turn.owner_started_version != owner_started_version
            or not turn.reserved_at <= now < turn.deadline_at
            or deadline > turn.deadline_at
        ):
            raise ValueError("candidate continuation turn or owner is stale")
        newer_owner = self._store.connection.execute(
            "SELECT 1 FROM investigation_steps WHERE case_id=? AND state_version>? "
            "AND json_extract(record_json,'$.event')='started' LIMIT 1",
            (str(admission.case_id), owner_started_version),
        ).fetchone()
        if newer_owner is not None:
            raise ValueError("candidate continuation owner is stale")
        continuation_id = f"candidate_launch_v1_{uuid4().hex}"
        try:
            self._store.connection.execute(
                "INSERT INTO candidate_launch_continuations (continuation_id,schema_version,"
                "admission_id,turn_id,case_id,epoch_state_version,resulting_checkpoint_version,"
                "owner_started_version,task_id,invocation_sha256,deadline_at,created_at) "
                "VALUES (?,1,?,?,?,?,?,?,?,?,?,?)",
                (
                    continuation_id,
                    admission_id,
                    turn_id,
                    str(admission.case_id),
                    admission.epoch_state_version,
                    resulting_checkpoint_version,
                    owner_started_version,
                    admission.task_id,
                    admission.invocation_sha256,
                    deadline.isoformat(),
                    now.isoformat(),
                ),
            )
        except sqlite3.IntegrityError as error:
            raise ValueError("candidate continuation already exists") from error
        return self.readback_launch_continuation(continuation_id)

    def readback_launch_continuation(self, continuation_id: str) -> CandidateLaunchContinuation:
        if _CONTINUATION_ID.fullmatch(continuation_id) is None:
            raise ValueError("candidate continuation ID is invalid")
        row = self._store.connection.execute(
            "SELECT schema_version,admission_id,turn_id,case_id,epoch_state_version,"
            "resulting_checkpoint_version,owner_started_version,task_id,invocation_sha256,"
            "deadline_at,created_at FROM candidate_launch_continuations WHERE continuation_id=?",
            (continuation_id,),
        ).fetchone()
        if row is None:
            raise ValueError("candidate continuation is unavailable")
        consumed = self._store.connection.execute(
            "SELECT case_id,consumed_at FROM candidate_launch_consumptions WHERE continuation_id=?",
            (continuation_id,),
        ).fetchone()
        case_id = CaseId(root=str(row[3]))
        admission = self.readback(str(row[1]))
        if (
            int(row[0]) != 1
            or admission.case_id != case_id
            or admission.epoch_state_version != int(row[4])
            or int(row[5]) != int(row[4]) + 1
            or admission.task_id != str(row[7])
            or admission.invocation_sha256 != str(row[8])
            or (consumed is not None and str(consumed[0]) != str(case_id))
        ):
            raise ValueError("candidate continuation binding is invalid")
        return CandidateLaunchContinuation(
            continuation_id=continuation_id,
            admission_id=admission.admission_id,
            turn_id=str(row[2]),
            case_id=case_id,
            epoch_state_version=int(row[4]),
            resulting_checkpoint_version=int(row[5]),
            owner_started_version=int(row[6]),
            task_id=str(row[7]),
            invocation_sha256=str(row[8]),
            deadline_at=_parse_utc(row[9], name="continuation deadline"),
            created_at=_parse_utc(row[10], name="continuation time"),
            consumed_at=(
                None if consumed is None else _parse_utc(consumed[1], name="consumption time")
            ),
        )

    def consume_launch_continuation(
        self,
        continuation_id: str,
        *,
        case_id: CaseId,
        task_id: str,
        invocation_sha256: str,
    ) -> CandidateLaunchContinuation:
        """Spend the exact continuation before the worker may touch its target."""

        with self._store.transaction():
            continuation = self.readback_launch_continuation(continuation_id)
            admission = self.readback(continuation.admission_id)
            now = _utc(self._clock(), name="continuation consumption time")
            if (
                continuation.case_id != case_id
                or continuation.task_id != task_id
                or continuation.invocation_sha256 != invocation_sha256
                or continuation.consumed_at is not None
                or admission.claimed_at is None
                or admission.execution_id is not None
            ):
                raise ValueError("candidate continuation identity or one-shot claim is stale")
            if now < continuation.created_at or now >= continuation.deadline_at:
                raise ValueError("candidate continuation deadline is stale")
            try:
                checkpoint = self._checkpoint(
                    case_id, continuation.resulting_checkpoint_version, now
                )
            except ValueError as error:
                raise ValueError("candidate continuation checkpoint is stale") from error
            if checkpoint.state_version != continuation.epoch_state_version + 1:
                raise ValueError("candidate continuation checkpoint is stale")
            newer_owner = self._store.connection.execute(
                "SELECT 1 FROM investigation_steps WHERE case_id=? AND state_version>? "
                "AND json_extract(record_json,'$.event')='started' LIMIT 1",
                (str(case_id), continuation.owner_started_version),
            ).fetchone()
            if newer_owner is not None:
                raise ValueError("candidate continuation owner is stale")
            from systemsense.storage.search_frontier import (
                FrontierInvestigatorTurnOutcomeV3,
                SearchFrontierRepository,
            )

            outcome = SearchFrontierRepository(self._store).read_investigator_turn_outcome(
                continuation.turn_id
            )
            if outcome is None:
                raise ValueError("candidate continuation turn outcome is missing")
            if (
                not isinstance(outcome, FrontierInvestigatorTurnOutcomeV3)
                or outcome.outcome != "measurement_admitted"
                or outcome.case_id != case_id
                or outcome.turn_id != continuation.turn_id
                or outcome.resulting_checkpoint_version != continuation.resulting_checkpoint_version
                or outcome.dispatch_admission_id != admission.admission_id
                or outcome.launch_continuation_id != continuation_id
                or outcome.candidate_snapshot_id != admission.snapshot_id
            ):
                raise ValueError("candidate continuation turn outcome is stale")
            if not isinstance(self._registry, CaseCandidateRegistry):
                raise ValueError("candidate continuation requires a live candidate registry")
            resolved = self._registry.resolve_for_continuation(
                case_id,
                continuation.epoch_state_version,
                admission.candidate_id,
                admission.admission_id,
                continuation_id,
            )
            if (
                isinstance(resolved, CandidateGap)
                or resolved.candidate.invocation_sha256 != invocation_sha256
                or resolved.candidate.cost_ms != admission.cost_ms
            ):
                raise ValueError("candidate continuation source or manifest changed")
            try:
                self._store.connection.execute(
                    "INSERT INTO candidate_launch_consumptions "
                    "(continuation_id,case_id,consumed_at) VALUES (?,?,?)",
                    (continuation_id, str(case_id), now.isoformat()),
                )
            except sqlite3.IntegrityError as error:
                raise ValueError("candidate continuation was already consumed") from error
            return self.readback_launch_continuation(continuation_id)

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
        frontier_snapshot = snapshot_id.startswith("frontier_decision_snapshot_")
        snapshot = (
            self._snapshots.readback_frontier(snapshot_id)
            if frontier_snapshot
            else self._snapshots.readback(snapshot_id)
        )
        if (
            int(row[0]) != 1
            or _TASK_ID.fullmatch(task_id) is None
            or _DIGEST.fullmatch(invocation_sha256) is None
            or snapshot.case_id != case_id
            or snapshot.epoch_state_version != epoch
            or not snapshot.captured_at <= admitted_at
        ):
            raise ValueError("candidate dispatch admission binding is invalid")
        if isinstance(snapshot, FrontierCandidateSnapshot):
            proposed_ids = (snapshot.candidate_id,)
            candidates = snapshot.candidate_refs
        else:
            if not isinstance(snapshot.response, CandidateDecisionResponseV1):
                raise ValueError("candidate dispatch snapshot has no proposal")
            proposed_ids = tuple(item.candidate_id for item in snapshot.response.proposals)
            candidates = snapshot.request.available_candidates
        refs = [item for item in candidates if item.candidate_id == candidate_id]
        if (
            len(refs) != 1
            or candidate_id not in proposed_ids
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
