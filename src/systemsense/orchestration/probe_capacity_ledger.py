"""Cross-process capacity for registered, isolated read-only probe workers.

This ledger cannot inspect Windows Job handles. Only trusted executor code may
call ``record_tree_exit_proof`` with a verifier retaining the open Job and exact
worker handle. The verifier must observe Job ActiveProcesses == 0 and exit of
the same PID *and creation time*. A Python type is not an authority boundary.
Every launcher must persist launch intent before CreateProcess; otherwise the
prelaunch expiry rule is unsafe. A crashed custodian leaves capacity occupied.
"""

from __future__ import annotations

import hashlib
import json
import math
import secrets
import sqlite3
import time
from collections.abc import Generator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Protocol, cast

_SCHEMA_VERSION = 1
_ACTIVE = ("reserved", "intent", "bound", "assigned", "resumed", "quarantined", "verified")
# Match the scheduler's closed ResourceClass values without an import cycle.
_RESOURCE_CLASSES = frozenset(("cpu", "disk", "gpu", "network", "process", "inference"))
_STATES = frozenset((*_ACTIVE, "pending", "expired", "released", "cancelled"))
_TERMINAL = ("expired", "released", "cancelled")
_CAPACITY_STATES = (*_ACTIVE, "pending")


class LedgerUnavailable(RuntimeError):
    """Capacity cannot be safely decided; do not launch a worker."""


class QueueFull(RuntimeError):
    """The durable pending queue is at its configured limit."""


@dataclass(frozen=True, slots=True)
class LedgerBudget:
    global_limit: int
    per_resource: Mapping[str, int] | None = None
    max_pending: int = 256

    def __post_init__(self) -> None:
        if (
            type(self.global_limit) is not int
            or type(self.max_pending) is not int
            or self.global_limit < 1
            or self.max_pending < 1
        ):
            raise ValueError("capacity limits must be positive")
        limits = dict(self.per_resource or {})
        for name, limit in limits.items():
            if name not in _RESOURCE_CLASSES or type(limit) is not int or limit < 1:
                raise ValueError("resource capacity must be positive")
        object.__setattr__(self, "per_resource", MappingProxyType(limits))

    def limit_for(self, resource: str) -> int:
        return min(self.global_limit, (self.per_resource or {}).get(resource, self.global_limit))

    def fingerprint(self, schema_hash: str) -> str:
        payload = {
            "version": _SCHEMA_VERSION,
            "schema_hash": schema_hash,
            "global_limit": self.global_limit,
            "per_resource": dict(sorted((self.per_resource or {}).items())),
            "max_pending": self.max_pending,
        }
        return hashlib.sha256(json.dumps(payload, sort_keys=True).encode()).hexdigest()


@dataclass(frozen=True, slots=True)
class Ticket:
    id: str
    secret: str


@dataclass(frozen=True, slots=True)
class Reservation:
    id: str
    secret: str
    expires_at: float


@dataclass(frozen=True, slots=True)
class LaunchReceipt:
    id: str
    secret: str


@dataclass(frozen=True, slots=True)
class WorkerIdentity:
    pid: int
    creation_time_ns: int

    def __post_init__(self) -> None:
        if self.pid <= 0 or self.creation_time_ns <= 0:
            raise ValueError("worker identity must be exact and positive")


@dataclass(frozen=True, slots=True)
class WorkerReceipt:
    id: str
    secret: str
    identity: WorkerIdentity


class CustodyVerifier(Protocol):
    """Trusted executor adapter retaining an open Job and worker process handle."""

    def prove_empty_and_exited(self, identity: WorkerIdentity) -> bool: ...


class DurableProbeLedger:
    """One SQLite file shared by all investigator processes on one host.

    Each operation uses a short BEGIN IMMEDIATE transaction. No process launch
    or Job wait happens while the transaction is held. Post-intent records do
    not expire, even after a process or custodian crash.
    """

    def __init__(self, path: Path, budget: LedgerBudget, schema_hash: str) -> None:
        if not schema_hash:
            raise ValueError("schema_hash is required")
        self.path = Path(path)
        self.budget = budget
        self._fingerprint = budget.fingerprint(schema_hash)
        try:
            existed = self.path.exists()
            with self._transaction(check_meta=False) as db:
                tables = db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
                if not tables:
                    if existed:
                        raise LedgerUnavailable("existing ledger has no schema")
                    self._create_schema(db)
                self._audit_integrity(db)
                self._gc_terminal(db)
        except (OSError, sqlite3.Error) as error:
            raise LedgerUnavailable("probe capacity ledger unavailable") from error

    def _create_schema(self, db: sqlite3.Connection) -> None:
        db.execute("CREATE TABLE meta (version INTEGER NOT NULL, fingerprint TEXT NOT NULL)")
        db.execute(
            "CREATE TABLE work ("
            "id TEXT PRIMARY KEY, secret TEXT NOT NULL, case_id TEXT NOT NULL, "
            "task_id TEXT NOT NULL, resource TEXT NOT NULL, priority INTEGER NOT NULL, "
            "state TEXT NOT NULL, expires_at REAL, pid INTEGER, creation_time_ns INTEGER, "
            "reason TEXT, UNIQUE(case_id, task_id))"
        )
        db.execute("CREATE INDEX work_state_resource ON work(state, resource)")
        db.execute("CREATE TABLE served (case_id TEXT PRIMARY KEY, turn INTEGER NOT NULL)")
        db.execute("CREATE TABLE counter (value INTEGER NOT NULL)")
        db.execute("INSERT INTO counter VALUES (0)")
        db.execute("INSERT INTO meta VALUES (?, ?)", (_SCHEMA_VERSION, self._fingerprint))

    def _check_meta(self, db: sqlite3.Connection) -> None:
        """Check the persisted policy and every capacity-relevant live row."""
        rows = db.execute("SELECT version, fingerprint FROM meta").fetchall()
        if rows != [(_SCHEMA_VERSION, self._fingerprint)]:
            raise LedgerUnavailable("ledger schema or budget mismatch")
        counter = db.execute("SELECT value FROM counter").fetchall()
        if len(counter) != 1 or not isinstance(counter[0][0], int) or counter[0][0] < 0:
            raise LedgerUnavailable("ledger turn counter is invalid")
        # Unknown states could conceal occupied capacity, so they always block admission.
        unknown = db.execute(
            f"SELECT 1 FROM work WHERE state NOT IN ({','.join('?' for _ in _STATES)}) LIMIT 1",
            tuple(_STATES),
        ).fetchone()
        if unknown is not None:
            raise LedgerUnavailable("ledger contains an unknown state")
        for row in db.execute(
            f"SELECT state,resource,expires_at,pid,creation_time_ns FROM work "
            f"WHERE state IN ({','.join('?' for _ in _CAPACITY_STATES)})",
            _CAPACITY_STATES,
        ):
            self._validate_work_row(row)

    def _audit_integrity(self, db: sqlite3.Connection) -> None:
        if db.execute("PRAGMA quick_check").fetchone() != ("ok",):
            raise LedgerUnavailable("ledger integrity check failed")
        self._check_meta(db)
        counter = db.execute("SELECT value FROM counter").fetchone()[0]
        for case_id, turn in db.execute("SELECT case_id,turn FROM served"):
            if not case_id or not isinstance(turn, int) or not 0 < turn <= counter:
                raise LedgerUnavailable("ledger fairness state is invalid")
        for row in db.execute("SELECT state,resource,expires_at,pid,creation_time_ns FROM work"):
            self._validate_work_row(row)

    @staticmethod
    def _validate_work_row(row: tuple[object, ...]) -> None:
        state, resource, expires, pid, created = row
        if state not in _STATES or resource not in _RESOURCE_CLASSES:
            raise LedgerUnavailable("ledger work state or resource is invalid")
        if state in {"pending", "reserved"}:
            if not isinstance(expires, (int, float)) or not math.isfinite(expires):
                raise LedgerUnavailable("prelaunch expiry is invalid")
        elif expires is not None:
            raise LedgerUnavailable("postlaunch expiry is invalid")
        if state in {"bound", "assigned", "resumed", "verified"}:
            if not isinstance(pid, int) or not isinstance(created, int) or min(pid, created) <= 0:
                raise LedgerUnavailable("worker identity is invalid")
        elif state in {"pending", "reserved", "intent", "expired", "cancelled"}:
            if pid is not None or created is not None:
                raise LedgerUnavailable("unexpected worker identity")
        elif (pid is None) != (created is None):
            raise LedgerUnavailable("partial worker identity")

    def audit_integrity(self) -> None:
        """Run the full SQLite and historical-row audit outside the hot admission path."""
        with self._transaction() as db:
            self._audit_integrity(db)

    @contextmanager
    def _transaction(self, *, check_meta: bool = True) -> Generator[sqlite3.Connection]:
        try:
            db = sqlite3.connect(self.path, timeout=5.0, isolation_level=None)
            try:
                db.execute("BEGIN IMMEDIATE")
                if check_meta:
                    self._check_meta(db)
                yield db
                db.execute("COMMIT")
            except BaseException:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise
            finally:
                db.close()
        except sqlite3.Error as error:
            raise LedgerUnavailable("probe capacity ledger unavailable") from error

    def enqueue(
        self,
        case_id: str,
        task_id: str,
        resource: str,
        priority: int,
        *,
        pending_seconds: float = 300.0,
    ) -> Ticket:
        if not case_id or not task_id or resource not in _RESOURCE_CLASSES:
            raise ValueError("valid case, task and resource are required")
        if not math.isfinite(pending_seconds) or not 0 < pending_seconds <= 3600:
            raise ValueError("pending_seconds must be within (0, 3600]")
        with self._transaction() as db:
            self._expire(db, time.time())
            existing = db.execute(
                "SELECT id, secret, resource, priority, state FROM work "
                "WHERE case_id=? AND task_id=?",
                (case_id, task_id),
            ).fetchone()
            if existing:
                if existing[4] in {"expired", "cancelled"}:
                    if (
                        db.execute("SELECT COUNT(*) FROM work WHERE state='pending'").fetchone()[0]
                        >= self.budget.max_pending
                    ):
                        raise QueueFull("probe capacity queue is full")
                    ticket = Ticket(secrets.token_hex(16), secrets.token_hex(32))
                    db.execute(
                        "UPDATE work SET id=?,secret=?,resource=?,priority=?,state='pending',"
                        "expires_at=?,reason=NULL WHERE case_id=? AND task_id=?",
                        (
                            ticket.id,
                            ticket.secret,
                            resource,
                            priority,
                            time.time() + pending_seconds,
                            case_id,
                            task_id,
                        ),
                    )
                    return ticket
                if existing[2:4] != (resource, priority) or existing[4] != "pending":
                    raise LedgerUnavailable("task identity or state changed")
                return Ticket(existing[0], existing[1])
            if (
                db.execute("SELECT COUNT(*) FROM work WHERE state='pending'").fetchone()[0]
                >= self.budget.max_pending
            ):
                raise QueueFull("probe capacity queue is full")
            ticket = Ticket(secrets.token_hex(16), secrets.token_hex(32))
            db.execute(
                "INSERT INTO work(id,secret,case_id,task_id,resource,priority,state,expires_at) "
                "VALUES(?,?,?,?,?,?,'pending',?)",
                (
                    ticket.id,
                    ticket.secret,
                    case_id,
                    task_id,
                    resource,
                    priority,
                    time.time() + pending_seconds,
                ),
            )
            return ticket

    def try_reserve(
        self, ticket: Ticket, *, reservation_seconds: float = 30.0
    ) -> Reservation | None:
        if not math.isfinite(reservation_seconds) or not 0 < reservation_seconds <= 300:
            raise ValueError("reservation_seconds must be within (0, 300]")
        with self._transaction() as db:
            self._expire(db, time.time())
            row = self._row(db, ticket.id, ticket.secret, "pending")
            active = db.execute(
                f"SELECT resource FROM work WHERE state IN ({','.join('?' for _ in _ACTIVE)})",
                _ACTIVE,
            ).fetchall()
            used = [item[0] for item in active]
            if len(used) >= self.budget.global_limit or used.count(row[4]) >= self.budget.limit_for(
                row[4]
            ):
                return None
            pending = db.execute(
                "SELECT id,case_id,resource,priority,rowid FROM work WHERE state='pending'"
            ).fetchall()
            eligible = [
                item for item in pending if used.count(item[2]) < self.budget.limit_for(item[2])
            ]
            served = dict(db.execute("SELECT case_id,turn FROM served").fetchall())
            winning_case = min(
                {item[1] for item in eligible},
                key=lambda case: (
                    served.get(case, 0),
                    min(item[4] for item in eligible if item[1] == case),
                ),
            )
            winner = min(
                (item for item in eligible if item[1] == winning_case),
                key=lambda item: (-item[3], item[4]),
            )
            if winner[0] != ticket.id:
                return None
            expires = time.time() + reservation_seconds
            db.execute(
                "UPDATE work SET state='reserved',expires_at=? WHERE id=?", (expires, ticket.id)
            )
            db.execute("UPDATE counter SET value=value+1")
            turn = db.execute("SELECT value FROM counter").fetchone()[0]
            db.execute(
                "INSERT INTO served(case_id,turn) VALUES(?,?) "
                "ON CONFLICT(case_id) DO UPDATE SET turn=excluded.turn",
                (winning_case, turn),
            )
            return Reservation(ticket.id, ticket.secret, expires)

    def _row(
        self, db: sqlite3.Connection, id: str, secret: str, *states: str
    ) -> tuple[str, str, str, str, str, int, str, float | None, int | None, int | None, str | None]:
        row = cast(
            tuple[
                str,
                str,
                str,
                str,
                str,
                int,
                str,
                float | None,
                int | None,
                int | None,
                str | None,
            ]
            | None,
            db.execute("SELECT * FROM work WHERE id=? AND secret=?", (id, secret)).fetchone(),
        )
        if row is None or row[6] not in states:
            raise LedgerUnavailable("receipt is missing or in an invalid state")
        return row

    def _expire(self, db: sqlite3.Connection, now: float) -> None:
        pending = db.execute(
            "UPDATE work SET state='expired',expires_at=NULL "
            "WHERE state='pending' AND expires_at<=?",
            (now,),
        )
        reserved = db.execute(
            "UPDATE work SET state='expired',expires_at=NULL "
            "WHERE state='reserved' AND expires_at<=?",
            (now,),
        )
        if pending.rowcount or reserved.rowcount:
            self._prune_served(db)
            self._gc_terminal(db)

    def _gc_terminal(self, db: sqlite3.Connection) -> None:
        """Retain a small bounded diagnostic tail; never delete capacity claims."""
        keep = max(64, 4 * self.budget.max_pending)
        count = db.execute(
            "SELECT COUNT(*) FROM work WHERE state IN ('expired','released','cancelled')"
        ).fetchone()[0]
        if count > keep:
            db.execute(
                "DELETE FROM work WHERE rowid IN ("
                "SELECT rowid FROM work WHERE state IN ('expired','released','cancelled') "
                "ORDER BY rowid LIMIT ?)",
                (count - keep,),
            )

    def _prune_served(self, db: sqlite3.Connection) -> None:
        db.execute(
            "DELETE FROM served WHERE case_id NOT IN "
            "(SELECT DISTINCT case_id FROM work WHERE state IN "
            "('pending','reserved','intent','bound','assigned','resumed','quarantined','verified'))"
        )

    def expire_prelaunch(self, *, now: float | None = None) -> None:
        with self._transaction() as db:
            self._expire(db, time.time() if now is None else now)

    def release_prelaunch(self, reservation: Reservation) -> None:
        with self._transaction() as db:
            self._row(db, reservation.id, reservation.secret, "reserved")
            db.execute(
                "UPDATE work SET state='released',expires_at=NULL WHERE id=?", (reservation.id,)
            )
            self._prune_served(db)
            self._gc_terminal(db)

    def record_launch_intent(self, reservation: Reservation) -> LaunchReceipt:
        with self._transaction() as db:
            row = self._row(db, reservation.id, reservation.secret, "reserved")
            if row[7] != reservation.expires_at or time.time() >= reservation.expires_at:
                raise LedgerUnavailable("reservation expired before launch intent")
            db.execute(
                "UPDATE work SET state='intent',expires_at=NULL WHERE id=?", (reservation.id,)
            )
            return LaunchReceipt(reservation.id, reservation.secret)

    def bind_suspended_worker(
        self, receipt: LaunchReceipt, *, pid: int, creation_time_ns: int
    ) -> WorkerReceipt:
        identity = WorkerIdentity(pid, creation_time_ns)
        with self._transaction() as db:
            self._row(db, receipt.id, receipt.secret, "intent")
            db.execute(
                "UPDATE work SET state='bound',pid=?,creation_time_ns=? WHERE id=?",
                (pid, creation_time_ns, receipt.id),
            )
        return WorkerReceipt(receipt.id, receipt.secret, identity)

    def _advance(self, receipt: WorkerReceipt, before: str, after: str) -> None:
        with self._transaction() as db:
            row = self._row(db, receipt.id, receipt.secret, before)
            if (row[8], row[9]) != (receipt.identity.pid, receipt.identity.creation_time_ns):
                raise LedgerUnavailable("worker identity changed")
            db.execute("UPDATE work SET state=? WHERE id=?", (after, receipt.id))
            if after == "released":
                self._prune_served(db)
                self._gc_terminal(db)

    def confirm_job_assignment(self, receipt: WorkerReceipt) -> None:
        self._advance(receipt, "bound", "assigned")

    def confirm_resume(self, receipt: WorkerReceipt) -> None:
        self._advance(receipt, "assigned", "resumed")

    def record_tree_exit_proof(self, receipt: WorkerReceipt, verifier: CustodyVerifier) -> None:
        # This may query a Job and process handle; never hold the SQLite write lock.
        try:
            proved = verifier.prove_empty_and_exited(receipt.identity)
        except Exception as error:
            raise LedgerUnavailable("custody verification failed") from error
        if proved is not True:
            raise LedgerUnavailable("worker tree exit is unproved")
        with self._transaction() as db:
            row = self._row(
                db, receipt.id, receipt.secret, "bound", "assigned", "resumed", "quarantined"
            )
            if (row[8], row[9]) != (receipt.identity.pid, receipt.identity.creation_time_ns):
                raise LedgerUnavailable("worker identity changed")
            db.execute("UPDATE work SET state='verified' WHERE id=?", (receipt.id,))

    def release_verified(self, receipt: WorkerReceipt) -> None:
        self._advance(receipt, "verified", "released")

    def quarantine(self, receipt: LaunchReceipt | WorkerReceipt, reason: str) -> None:
        if not reason or len(reason) > 128:
            raise ValueError("quarantine reason must be bounded")
        with self._transaction() as db:
            self._row(
                db,
                receipt.id,
                receipt.secret,
                "intent",
                "bound",
                "assigned",
                "resumed",
                "quarantined",
            )
            db.execute(
                "UPDATE work SET state='quarantined',reason=? WHERE id=?", (reason, receipt.id)
            )

    def cancel_pending(self, ticket: Ticket) -> None:
        with self._transaction() as db:
            self._row(db, ticket.id, ticket.secret, "pending")
            db.execute("UPDATE work SET state='cancelled',expires_at=NULL WHERE id=?", (ticket.id,))
            self._prune_served(db)
            self._gc_terminal(db)
