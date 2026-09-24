"""Version-four host leases for one process or an owned Windows Job tree.

This module fences legacy v3 readers on the same SQLite file. Tree leases never
reclaim on PID exit, timeout, or clock reset. A lost Job handle leaves capacity
quarantined until a separate, reviewed recovery procedure exists.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import secrets
import sqlite3
import time
import uuid
import weakref
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

import psutil

from systemsense.inference.host_lease import (
    LeaseBudget,
    LeaseDecision,
    LeaseDemand,
    WorkerIdentity,
)

_REQUEST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$")
_LEASE_ID = re.compile(r"^[0-9a-f]{32}$")
_ISSUED_JOBS: weakref.WeakValueDictionary[str, JobCustody] = weakref.WeakValueDictionary()


def _observe_worker(worker: WorkerIdentity) -> str:
    try:
        started = psutil.Process(worker.pid).create_time()
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return "exited"
    except (psutil.Error, OSError):
        return "unknown"
    if not math.isfinite(started) or started <= 0:
        return "unknown"
    return "alive" if started == worker.started_at else "exited"


class JobCustody(Protocol):
    def is_assigned_worker(self, worker: Any) -> bool: ...

    def wait_until_empty(self, timeout_seconds: float) -> bool: ...


@dataclass(frozen=True, slots=True)
class TreeCustody:
    """An in-memory capability bound to a specific, still-open owned Job."""

    tree_id: str
    root: WorkerIdentity
    _job: JobCustody = field(repr=False, compare=False)
    _token: str = field(repr=False, compare=False)

    @classmethod
    def create(cls, job: JobCustody, worker: Any, root: WorkerIdentity) -> TreeCustody:
        if getattr(worker, "pid", None) != root.pid or not job.is_assigned_worker(worker):
            raise ValueError("worker must be assigned to this open Job")
        custody = cls(uuid.uuid4().hex, root, job, secrets.token_hex(32))
        _ISSUED_JOBS[custody._token] = job
        return custody

    @property
    def token_hash(self) -> str:
        return hashlib.sha256(self._token.encode("ascii")).hexdigest()

    def is_empty(self) -> bool:
        if _ISSUED_JOBS.get(self._token) is not self._job:
            return False
        try:
            return self._job.wait_until_empty(0)
        except (OSError, RuntimeError, ValueError):
            return False

    def is_open(self) -> bool:
        if _ISSUED_JOBS.get(self._token) is not self._job:
            return False
        try:
            self._job.wait_until_empty(0)
            return True
        except (OSError, RuntimeError, ValueError):
            return False


class _MigrationRequiresDrain(Exception):
    pass


class _MigrationRequired(Exception):
    pass


class _ExternalProofRequired(Exception):
    pass


class _BudgetMismatch(Exception):
    pass


class _ClockRegression(Exception):
    pass


class TreeHostInferenceLeaseLedger:
    """One shared, bounded budget across new single-process and tree leases.

    Existing v3 ledgers cannot be migrated by table emptiness alone: v3 may
    already have reclaimed a parent while a child survived. Version-four
    readers reserve capacity until verified release, even after TTL expiry.
    This is same-user coordination, not a security boundary.
    """

    def __init__(
        self,
        path: Path,
        budget: LeaseBudget,
        *,
        lease_ttl_seconds: float = 120.0,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if not path.is_absolute() or path == Path(":memory:"):
            raise ValueError("lease database requires a trusted absolute file path")
        if not math.isfinite(lease_ttl_seconds) or not 1 <= lease_ttl_seconds <= 3600:
            raise ValueError("lease TTL must be finite and bounded")
        self._path = path
        self._budget = budget
        self._ttl = lease_ttl_seconds
        self._clock = clock
        canonical = json.dumps(
            [budget.cpu_slots, budget.ram_bytes, budget.vram_bytes, budget.gpu_device_index],
            separators=(",", ":"),
        )
        self._budget_hash = hashlib.sha256(canonical.encode("ascii")).hexdigest()

    @property
    def lease_ttl_seconds(self) -> float:
        return self._ttl

    def try_acquire(
        self,
        request_id: str,
        demand: LeaseDemand,
        *,
        worker_identity: WorkerIdentity | None = None,
        custody: TreeCustody | None = None,
    ) -> LeaseDecision:
        if not _REQUEST_ID.fullmatch(request_id):
            return LeaseDecision("denied", "invalid_request_id")
        if (worker_identity is None) == (custody is None):
            return LeaseDecision("denied", "exactly_one_owner_required")
        if demand.vram_bytes and custody is None:
            return LeaseDecision("denied", "gpu_tree_custody_required")
        owner = custody.root if custody is not None else worker_identity
        assert owner is not None
        for name, required, capacity in (
            ("cpu", demand.cpu_slots, self._budget.cpu_slots),
            ("ram", demand.ram_bytes, self._budget.ram_bytes),
            ("vram", demand.vram_bytes, self._budget.vram_bytes),
        ):
            if required > capacity:
                return LeaseDecision("denied", f"demand_exceeds_{name}_budget")
        if demand.vram_bytes and demand.gpu_device_index != self._budget.gpu_device_index:
            return LeaseDecision("denied", "gpu_device_mismatch")
        if _observe_worker(owner) != "alive":
            return LeaseDecision("denied", "worker_identity_unverifiable")
        if custody is not None and not custody.is_open():
            return LeaseDecision("denied", "tree_custody_unverifiable")
        try:
            with self._connect() as conn:
                now = self._tick(conn)
                row = conn.execute(
                    "SELECT lease_id,cpu,ram,vram,gpu,root_pid,root_started,"
                    "tree_id,token_hash,state"
                    " FROM tree_leases WHERE request_id=?",
                    (request_id,),
                ).fetchone()
                owner_tuple = self._owner_tuple(owner, custody)
                demand_tuple = self._demand_tuple(demand)
                if row is not None:
                    if tuple(row[1:5]) != demand_tuple or tuple(row[5:9]) != owner_tuple:
                        return LeaseDecision("denied", "request_id_collision")
                    if row[9] != "active":
                        return LeaseDecision("denied", "lease_quarantined")
                    return LeaseDecision("acquired", "already_acquired", str(row[0]))
                rows = conn.execute("SELECT cpu,ram,vram,gpu,state FROM tree_leases").fetchall()
                for name, index, capacity in (
                    ("cpu", 0, self._budget.cpu_slots),
                    ("ram", 1, self._budget.ram_bytes),
                    ("vram", 2, self._budget.vram_bytes),
                ):
                    used = sum(int(row[index]) for row in rows)
                    active = sum(int(row[index]) for row in rows if row[4] == "active")
                    if used > capacity:
                        return LeaseDecision("denied", "ledger_corrupt")
                    required = (demand.cpu_slots, demand.ram_bytes, demand.vram_bytes)[index]
                    if required + used > capacity:
                        suffix = "_quarantined" if required + active <= capacity else ""
                        return LeaseDecision("queued", f"capacity_{name}{suffix}")
                if any(
                    row[4] not in ("active", "quarantined")
                    or row[0] < 1
                    or row[1] < 1
                    or row[2] < 0
                    or (row[2] > 0 and row[3] != self._budget.gpu_device_index)
                    for row in rows
                ):
                    return LeaseDecision("denied", "ledger_corrupt")
                lease_id = uuid.uuid4().hex
                conn.execute(
                    "INSERT INTO tree_leases(lease_id,request_id,cpu,ram,vram,gpu,expires_at,"
                    "root_pid,root_started,tree_id,token_hash,state)"
                    " VALUES(?,?,?,?,?,?,?,?,?,?,?,'active')",
                    (lease_id, request_id, *demand_tuple, now + self._ttl, *owner_tuple),
                )
                return LeaseDecision("acquired", "admitted", lease_id)
        except _MigrationRequiresDrain:
            return LeaseDecision("denied", "migration_requires_drain")
        except _MigrationRequired:
            return LeaseDecision("denied", "migration_required")
        except _BudgetMismatch:
            return LeaseDecision("denied", "budget_mismatch")
        except _ClockRegression:
            return LeaseDecision("denied", "clock_regression")
        except (OSError, sqlite3.Error, ValueError):
            return LeaseDecision("denied", "store_unavailable")

    def renew(self, lease_id: str) -> bool:
        if not _LEASE_ID.fullmatch(lease_id):
            return False
        try:
            with self._connect() as conn:
                now = self._tick(conn)
                return (
                    conn.execute(
                        "UPDATE tree_leases SET expires_at=? WHERE lease_id=? AND state='active'",
                        (now + self._ttl, lease_id),
                    ).rowcount
                    == 1
                )
        except (
            OSError,
            sqlite3.Error,
            ValueError,
            _MigrationRequiresDrain,
            _MigrationRequired,
            _BudgetMismatch,
            _ClockRegression,
        ):
            return False

    def release(
        self,
        lease_id: str,
        *,
        worker_identity: WorkerIdentity | None = None,
        custody: TreeCustody | None = None,
    ) -> bool:
        if not _LEASE_ID.fullmatch(lease_id) or (worker_identity is None) == (custody is None):
            return False
        owner = custody.root if custody is not None else worker_identity
        assert owner is not None
        try:
            with self._connect() as conn:
                self._tick(conn)
                row = conn.execute(
                    "SELECT root_pid,root_started,tree_id,token_hash FROM tree_leases"
                    " WHERE lease_id=?",
                    (lease_id,),
                ).fetchone()
                if row is None or tuple(row) != self._owner_tuple(owner, custody):
                    return False
                if custody is not None:
                    if not custody.is_empty():
                        return False
                elif _observe_worker(owner) != "exited":
                    return False
                return (
                    conn.execute("DELETE FROM tree_leases WHERE lease_id=?", (lease_id,)).rowcount
                    == 1
                )
        except (
            OSError,
            sqlite3.Error,
            ValueError,
            _MigrationRequiresDrain,
            _MigrationRequired,
            _BudgetMismatch,
            _ClockRegression,
        ):
            return False

    def migrate_from_v3(self) -> str:
        """Report whether migration is blocked; never infer external drain proof."""

        try:
            with self._connect(allow_migration=True):
                return "migrated"
        except _MigrationRequiresDrain:
            return "migration_requires_drain"
        except _ExternalProofRequired:
            return "external_proof_required"
        except _BudgetMismatch:
            return "budget_mismatch"
        except (OSError, sqlite3.Error, ValueError):
            return "store_unavailable"

    def _connect(self, *, allow_migration: bool = False) -> _Transaction:
        return _Transaction(self._path, self._budget_hash, allow_migration)

    def _tick(self, conn: sqlite3.Connection) -> float:
        now = self._clock()
        if not math.isfinite(now) or now < 0:
            raise ValueError("invalid monotonic clock")
        prior = conn.execute("SELECT value FROM meta WHERE key='v4_last_tick'").fetchone()
        if prior is not None and now < float(prior[0]):
            occupied = int(conn.execute("SELECT count(*) FROM tree_leases").fetchone()[0])
            if occupied:
                raise _ClockRegression
        conn.execute(
            "INSERT INTO meta(key,value) VALUES('v4_last_tick',?)"
            " ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (repr(now),),
        )
        conn.execute(
            "UPDATE tree_leases SET state='quarantined' WHERE expires_at<=? AND state='active'",
            (now,),
        )
        return now

    @staticmethod
    def _demand_tuple(demand: LeaseDemand) -> tuple[int, int, int, int | None]:
        return demand.cpu_slots, demand.ram_bytes, demand.vram_bytes, demand.gpu_device_index

    @staticmethod
    def _owner_tuple(
        owner: WorkerIdentity, custody: TreeCustody | None
    ) -> tuple[int, float, str | None, str | None]:
        return (
            owner.pid,
            owner.started_at,
            custody.tree_id if custody else None,
            custody.token_hash if custody else None,
        )


class _Transaction:
    def __init__(self, path: Path, budget_hash: str, allow_migration: bool) -> None:
        self._path = path
        self._budget_hash = budget_hash
        self._allow_migration = allow_migration
        self._conn: sqlite3.Connection | None = None

    def __enter__(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, timeout=1.0, isolation_level=None)
        self._conn = conn
        try:
            conn.execute("PRAGMA busy_timeout=1000")
            conn.execute("BEGIN IMMEDIATE")
            version = int(conn.execute("PRAGMA user_version").fetchone()[0])
            if version not in (0, 3, 4):
                raise sqlite3.DatabaseError("unsupported host lease schema")
            if version == 4:
                tables = {
                    row[0]
                    for row in conn.execute(
                        "SELECT name FROM sqlite_master WHERE type='table'"
                        " AND name IN ('meta','tree_leases')"
                    ).fetchall()
                }
                if tables != {"meta", "tree_leases"}:
                    raise sqlite3.DatabaseError("incomplete host lease schema")
            else:
                conn.execute(
                    "CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)"
                )
            saved = conn.execute("SELECT value FROM meta WHERE key='budget_hash'").fetchone()
            if version == 4 and saved is None:
                raise sqlite3.DatabaseError("missing host lease budget")
            if saved is not None and saved[0] != self._budget_hash:
                raise _BudgetMismatch
            if version == 3:
                if not self._allow_migration:
                    raise _MigrationRequired
                leases = int(conn.execute("SELECT count(*) FROM leases").fetchone()[0])
                pending = int(conn.execute("SELECT count(*) FROM pending").fetchone()[0])
                if leases or pending:
                    raise _MigrationRequiresDrain
                raise _ExternalProofRequired
            if saved is None:
                conn.execute(
                    "INSERT INTO meta(key,value) VALUES('budget_hash',?)", (self._budget_hash,)
                )
            if version != 4:
                conn.execute(
                    "CREATE TABLE tree_leases(lease_id TEXT PRIMARY KEY,"
                    "request_id TEXT NOT NULL UNIQUE,cpu INTEGER NOT NULL,ram INTEGER NOT NULL,"
                    "vram INTEGER NOT NULL,gpu INTEGER,expires_at REAL NOT NULL,"
                    "root_pid INTEGER NOT NULL,root_started REAL NOT NULL,"
                    "tree_id TEXT,token_hash TEXT,state TEXT NOT NULL)"
                )
                conn.execute("PRAGMA user_version=4")
            return conn
        except BaseException:
            conn.rollback()
            conn.close()
            self._conn = None
            raise

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        conn = self._conn
        if conn is None:
            return
        try:
            if exc_type is None:
                conn.commit()
            else:
                conn.rollback()
        finally:
            conn.close()
