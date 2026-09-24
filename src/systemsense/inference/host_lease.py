"""Cross-process, bounded inference leases; no model or OS execution authority.

The ledger coordinates *configured* CPU slots and peak RAM/VRAM budgets. It does
not measure free memory. A caller must validate telemetry and model footprints
separately, acquire before dispatch, renew during work, and stop work before a
lost lease can be reused. SQLite serializes admission across local processes.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import sqlite3
import time
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

import psutil

_MAX_BYTES = 512 * 1024**3
_REQUEST_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,79}$")
LeaseStatus = Literal["acquired", "queued", "denied"]
WorkerState = Literal["alive", "exited", "unknown"]
LeaseReleaseStatus = Literal[
    "released_now",
    "verified_exited_prior_reclaim",
    "still_live_or_unknown",
    "not_found",
    "identity_mismatch",
    "store_unavailable",
]
_RECLAIM_RETENTION_SECONDS = 24 * 60 * 60
_MAX_RECLAIMS = 4096


@dataclass(frozen=True, slots=True)
class LeaseBudget:
    cpu_slots: int
    ram_bytes: int
    vram_bytes: int
    gpu_device_index: int | None = None

    def __post_init__(self) -> None:
        if not 1 <= self.cpu_slots <= 64 or not 1 <= self.ram_bytes <= _MAX_BYTES:
            raise ValueError("CPU slots and RAM budget must be positive and bounded")
        if not 0 <= self.vram_bytes <= _MAX_BYTES:
            raise ValueError("VRAM budget must be bounded")
        if (self.vram_bytes > 0) != (self.gpu_device_index is not None):
            raise ValueError("positive VRAM budget requires exactly one GPU device")
        if self.gpu_device_index is not None and not 0 <= self.gpu_device_index <= 15:
            raise ValueError("GPU device index must be bounded")


@dataclass(frozen=True, slots=True)
class LeaseDemand:
    cpu_slots: int
    ram_bytes: int
    vram_bytes: int = 0
    gpu_device_index: int | None = None

    def __post_init__(self) -> None:
        if not 1 <= self.cpu_slots <= 64 or not 1 <= self.ram_bytes <= _MAX_BYTES:
            raise ValueError("CPU slots and RAM demand must be positive and bounded")
        if not 0 <= self.vram_bytes <= _MAX_BYTES:
            raise ValueError("VRAM demand must be bounded")
        if (self.vram_bytes > 0) != (self.gpu_device_index is not None):
            raise ValueError("positive VRAM demand requires exactly one GPU device")
        if self.gpu_device_index is not None and not 0 <= self.gpu_device_index <= 15:
            raise ValueError("GPU device index must be bounded")


@dataclass(frozen=True, slots=True)
class LeaseDecision:
    status: LeaseStatus
    reason: str
    lease_id: str | None = None


@dataclass(frozen=True, slots=True)
class LeaseReleaseDecision:
    status: LeaseReleaseStatus


@dataclass(frozen=True, slots=True)
class WorkerIdentity:
    """A specific process incarnation, not a reusable PID alone."""

    pid: int
    started_at: float

    def __post_init__(self) -> None:
        if (
            not 1 <= self.pid <= 2**32 - 1
            or not math.isfinite(self.started_at)
            or self.started_at <= 0
        ):
            raise ValueError("invalid worker process identity")


def capture_worker_identity(pid: int) -> WorkerIdentity:
    """Capture a running worker identity before asking the ledger for capacity."""

    return WorkerIdentity(pid, psutil.Process(pid).create_time())


def _observe_worker(worker: WorkerIdentity) -> WorkerState:
    try:
        observed = psutil.Process(worker.pid).create_time()
    except (psutil.NoSuchProcess, psutil.ZombieProcess):
        return "exited"
    except (psutil.Error, OSError):
        return "unknown"
    if not math.isfinite(observed) or observed <= 0:
        return "unknown"
    return "alive" if observed == worker.started_at else "exited"


class _BudgetMismatch(Exception):
    pass


class _ClockRegression(Exception):
    pass


class HostInferenceLeaseLedger:
    """One finite lease and FIFO queue among processes sharing a trusted SQLite file.

    Expiry quarantines capacity until a bound worker's exit can be verified.
    Unbound CPU/RAM leases require explicit unknown-exit acknowledgment after
    expiry. GPU leases require a bound worker and cannot use this acknowledgment.
    The caller must still stop work before a lost lease can be reused. This is
    resource coordination, not a security boundary against local users.
    """

    def __init__(
        self,
        path: Path,
        budget: LeaseBudget,
        *,
        lease_ttl_seconds: float = 120.0,
        request_ttl_seconds: float = 30.0,
        max_pending: int = 64,
        clock: Callable[[], float] = time.monotonic,
        boot_id: str | None = None,
    ) -> None:
        if not path.is_absolute() or path == Path(":memory:"):
            raise ValueError("lease database requires a trusted absolute file path")
        if not 1 <= lease_ttl_seconds <= 3600 or not 1 <= request_ttl_seconds <= 300:
            raise ValueError("lease and pending TTLs must be finite and bounded")
        if not 1 <= max_pending <= 1024:
            raise ValueError("pending queue bound must be finite")
        self._path = path
        self._budget = budget
        self._lease_ttl = lease_ttl_seconds
        self._request_ttl = request_ttl_seconds
        self._max_pending = max_pending
        self._clock = clock
        self._boot_id = boot_id or str(round(psutil.boot_time()))
        if not _REQUEST_ID.fullmatch(self._boot_id):
            raise ValueError("invalid host boot identity")
        canonical = json.dumps(
            [budget.cpu_slots, budget.ram_bytes, budget.vram_bytes, budget.gpu_device_index],
            separators=(",", ":"),
        )
        self._budget_hash = hashlib.sha256(canonical.encode("ascii")).hexdigest()

    @property
    def lease_ttl_seconds(self) -> float:
        return self._lease_ttl

    def try_acquire(
        self,
        request_id: str,
        demand: LeaseDemand,
        *,
        worker_identity: WorkerIdentity | None = None,
    ) -> LeaseDecision:
        if not _REQUEST_ID.fullmatch(request_id):
            return LeaseDecision("denied", "invalid_request_id")
        mismatch = self._static_denial(demand)
        if mismatch:
            return LeaseDecision("denied", mismatch)
        if demand.vram_bytes and worker_identity is None:
            return LeaseDecision("denied", "gpu_worker_identity_required")
        if worker_identity is not None and _observe_worker(worker_identity) != "alive":
            return LeaseDecision("denied", "worker_identity_unverifiable")
        try:
            with self._transaction() as conn:
                now = self._tick(conn)
                existing = conn.execute(
                    "SELECT lease_id, cpu, ram, vram, gpu, worker_pid, worker_started, state"
                    " FROM leases WHERE request_id = ?",
                    (request_id,),
                ).fetchone()
                if existing is not None:
                    if tuple(existing[1:5]) != self._demand_tuple(demand) or (
                        existing[5],
                        existing[6],
                    ) != self._worker_tuple(worker_identity):
                        return LeaseDecision("denied", "request_id_collision")
                    if existing[7] != "active":
                        return LeaseDecision("denied", "lease_quarantined")
                    return LeaseDecision("acquired", "already_acquired", str(existing[0]))
                pending = conn.execute(
                    "SELECT seq, cpu, ram, vram, gpu FROM pending WHERE request_id = ?",
                    (request_id,),
                ).fetchone()
                if pending is not None:
                    if tuple(pending[1:]) != self._demand_tuple(demand):
                        return LeaseDecision("denied", "request_id_collision")
                    conn.execute(
                        "UPDATE pending SET expires_at = ? WHERE request_id = ?",
                        (now + self._request_ttl, request_id),
                    )
                else:
                    count = int(conn.execute("SELECT count(*) FROM pending").fetchone()[0])
                    if count >= self._max_pending:
                        return LeaseDecision("denied", "pending_queue_full")
                    conn.execute(
                        "INSERT INTO pending(request_id,cpu,ram,vram,gpu,expires_at)"
                        " VALUES(?,?,?,?,?,?)",
                        (request_id, *self._demand_tuple(demand), now + self._request_ttl),
                    )
                head = conn.execute(
                    "SELECT request_id FROM pending ORDER BY seq LIMIT 1"
                ).fetchone()
                if head is None or head[0] != request_id:
                    return LeaseDecision("queued", "queued_behind_prior_request")
                used_cpu = used_ram = used_vram = 0
                active_cpu = active_ram = active_vram = 0
                for cpu, ram, vram, gpu, state in conn.execute(
                    "SELECT cpu,ram,vram,gpu,state FROM leases"
                ).fetchall():
                    if (
                        not 1 <= cpu <= self._budget.cpu_slots
                        or not 1 <= ram <= self._budget.ram_bytes
                        or not 0 <= vram <= self._budget.vram_bytes
                        or (vram > 0 and gpu != self._budget.gpu_device_index)
                        or (vram == 0 and gpu is not None)
                        or state not in ("active", "quarantined_live", "quarantined_unknown")
                    ):
                        return LeaseDecision("denied", "ledger_corrupt")
                    used_cpu += cpu
                    used_ram += ram
                    used_vram += vram
                    if state == "active":
                        active_cpu += cpu
                        active_ram += ram
                        active_vram += vram
                if (
                    used_cpu > self._budget.cpu_slots
                    or used_ram > self._budget.ram_bytes
                    or used_vram > self._budget.vram_bytes
                ):
                    return LeaseDecision("denied", "ledger_corrupt")
                for dimension, required, used, active, capacity in (
                    ("cpu", demand.cpu_slots, used_cpu, active_cpu, self._budget.cpu_slots),
                    ("ram", demand.ram_bytes, used_ram, active_ram, self._budget.ram_bytes),
                    ("vram", demand.vram_bytes, used_vram, active_vram, self._budget.vram_bytes),
                ):
                    if required + used > capacity:
                        suffix = "_quarantined" if required + active <= capacity else ""
                        return LeaseDecision("queued", f"capacity_{dimension}{suffix}")
                lease_id = uuid.uuid4().hex
                conn.execute(
                    "INSERT INTO leases(lease_id,request_id,cpu,ram,vram,gpu,expires_at,"
                    "worker_pid,worker_started,state) VALUES(?,?,?,?,?,?,?,?,?,?)",
                    (
                        lease_id,
                        request_id,
                        *self._demand_tuple(demand),
                        now + self._lease_ttl,
                        *self._worker_tuple(worker_identity),
                        "active",
                    ),
                )
                conn.execute("DELETE FROM pending WHERE request_id = ?", (request_id,))
                return LeaseDecision("acquired", "admitted", lease_id)
        except _BudgetMismatch:
            return LeaseDecision("denied", "budget_mismatch")
        except _ClockRegression:
            return LeaseDecision("denied", "clock_regression")
        except (OSError, sqlite3.Error, ValueError):
            return LeaseDecision("denied", "store_unavailable")

    def renew(self, lease_id: str) -> bool:
        if not re.fullmatch(r"[0-9a-f]{32}", lease_id):
            return False
        try:
            with self._transaction() as conn:
                now = self._tick(conn)
                cursor = conn.execute(
                    "UPDATE leases SET expires_at = ? WHERE lease_id = ? AND state = 'active'",
                    (now + self._lease_ttl, lease_id),
                )
                return cursor.rowcount == 1
        except (OSError, sqlite3.Error, ValueError, _BudgetMismatch, _ClockRegression):
            return False

    def release(self, lease_id: str, *, acknowledge_unknown_exit: bool = False) -> bool:
        if not re.fullmatch(r"[0-9a-f]{32}", lease_id):
            return False
        try:
            with self._transaction() as conn:
                self._tick(conn)
                row = conn.execute(
                    "SELECT worker_pid,worker_started,state,vram FROM leases WHERE lease_id = ?",
                    (lease_id,),
                ).fetchone()
                if row is None:
                    return False
                if (row[0] is None) != (row[1] is None):
                    return False
                if row[3] > 0 and row[0] is None:
                    return False
                if row[0] is not None and row[1] is not None:
                    if _observe_worker(WorkerIdentity(int(row[0]), float(row[1]))) != "exited":
                        return False
                elif row[2] != "active" and not acknowledge_unknown_exit:
                    return False
                cursor = conn.execute("DELETE FROM leases WHERE lease_id = ?", (lease_id,))
                return cursor.rowcount == 1
        except (OSError, sqlite3.Error, ValueError, _BudgetMismatch, _ClockRegression):
            return False

    def reconcile_release(
        self, lease_id: str, worker_identity: WorkerIdentity
    ) -> LeaseReleaseDecision:
        """Release a bound worker only after verified exit, including prior sweeps.

        A bounded exact tombstone makes crash reconciliation distinguishable from
        an arbitrary or expired lease token. Only the two verified-exit statuses
        authorize a managed caller to mark its lease closed.
        """

        if not re.fullmatch(r"[0-9a-f]{32}", lease_id):
            return LeaseReleaseDecision("not_found")
        try:
            with self._transaction() as conn:
                existing = conn.execute(
                    "SELECT worker_pid,worker_started FROM leases WHERE lease_id = ?",
                    (lease_id,),
                ).fetchone()
                now = self._tick(conn)
                if existing is not None and tuple(existing) != self._worker_tuple(worker_identity):
                    return LeaseReleaseDecision("identity_mismatch")
                tombstone = conn.execute(
                    "SELECT worker_pid,worker_started FROM lease_reclaims WHERE lease_id = ?",
                    (lease_id,),
                ).fetchone()
                if tombstone is not None:
                    if tuple(tombstone) != self._worker_tuple(worker_identity):
                        return LeaseReleaseDecision("identity_mismatch")
                    status: LeaseReleaseStatus = (
                        "released_now" if existing is not None else "verified_exited_prior_reclaim"
                    )
                    return LeaseReleaseDecision(status)
                if existing is None:
                    return LeaseReleaseDecision("not_found")
                if _observe_worker(worker_identity) != "exited":
                    return LeaseReleaseDecision("still_live_or_unknown")
                conn.execute("DELETE FROM leases WHERE lease_id = ?", (lease_id,))
                self._record_reclaim(conn, lease_id, worker_identity, now)
                return LeaseReleaseDecision("released_now")
        except (OSError, sqlite3.Error, ValueError, _BudgetMismatch, _ClockRegression):
            return LeaseReleaseDecision("store_unavailable")

    def cancel_pending(self, request_id: str) -> bool:
        if not _REQUEST_ID.fullmatch(request_id):
            return False
        try:
            with self._transaction() as conn:
                self._tick(conn)
                cursor = conn.execute("DELETE FROM pending WHERE request_id = ?", (request_id,))
                return cursor.rowcount == 1
        except (OSError, sqlite3.Error, ValueError, _BudgetMismatch, _ClockRegression):
            return False

    def _static_denial(self, demand: LeaseDemand) -> str | None:
        if demand.gpu_device_index != self._budget.gpu_device_index and demand.vram_bytes:
            return "gpu_device_mismatch"
        for name, required, capacity in (
            ("cpu", demand.cpu_slots, self._budget.cpu_slots),
            ("ram", demand.ram_bytes, self._budget.ram_bytes),
            ("vram", demand.vram_bytes, self._budget.vram_bytes),
        ):
            if required > capacity:
                return f"demand_exceeds_{name}_budget"
        return None

    @staticmethod
    def _demand_tuple(demand: LeaseDemand) -> tuple[int, int, int, int | None]:
        return demand.cpu_slots, demand.ram_bytes, demand.vram_bytes, demand.gpu_device_index

    @staticmethod
    def _worker_tuple(worker: WorkerIdentity | None) -> tuple[int | None, float | None]:
        return (worker.pid, worker.started_at) if worker is not None else (None, None)

    def _transaction(self) -> _LeaseTransaction:
        return _LeaseTransaction(self._path, self._budget_hash, self._boot_id)

    def _tick(self, conn: sqlite3.Connection) -> float:
        now = self._clock()
        if not math.isfinite(now) or now < 0:
            raise ValueError("invalid monotonic clock")
        prior = conn.execute("SELECT value FROM meta WHERE key = 'last_tick'").fetchone()
        if prior is not None and now < float(prior[0]):
            # A monotonic clock may restart after reboot. A boot-time estimate
            # is not authority to erase reservations: it can jitter between
            # processes during the same boot. Reset the clock only after every
            # bound worker is independently verified to have exited.
            previous = conn.execute(
                "SELECT lease_id,worker_pid,worker_started FROM leases"
            ).fetchall()
            reclaimable: list[tuple[str, WorkerIdentity]] = []
            for lease_id, pid, started in previous:
                if pid is None or started is None:
                    raise _ClockRegression
                try:
                    worker = WorkerIdentity(int(pid), float(started))
                except (TypeError, ValueError) as error:
                    raise _ClockRegression from error
                if _observe_worker(worker) != "exited":
                    raise _ClockRegression
                reclaimable.append((str(lease_id), worker))
            for lease_id, worker in reclaimable:
                conn.execute("DELETE FROM leases WHERE lease_id = ?", (lease_id,))
                self._record_reclaim(conn, lease_id, worker, now)
            conn.execute("DELETE FROM pending")
        conn.execute(
            "INSERT INTO meta(key,value) VALUES('last_tick',?)"
            " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (repr(now),),
        )
        for lease_id, pid, started in conn.execute(
            "SELECT lease_id,worker_pid,worker_started FROM leases"
            " WHERE expires_at <= ? OR state != 'active'",
            (now,),
        ).fetchall():
            state: WorkerState = "unknown"
            if pid is not None and started is not None:
                try:
                    state = _observe_worker(WorkerIdentity(int(pid), float(started)))
                except (TypeError, ValueError):
                    state = "unknown"
                if state == "exited":
                    conn.execute("DELETE FROM leases WHERE lease_id = ?", (lease_id,))
                    self._record_reclaim(
                        conn, lease_id, WorkerIdentity(int(pid), float(started)), now
                    )
                    continue
            state_name = "quarantined_live" if state == "alive" else "quarantined_unknown"
            conn.execute("UPDATE leases SET state = ? WHERE lease_id = ?", (state_name, lease_id))
        conn.execute("DELETE FROM pending WHERE expires_at <= ?", (now,))
        conn.execute(
            "DELETE FROM lease_reclaims WHERE reclaimed_at <= ?",
            (now - _RECLAIM_RETENTION_SECONDS,),
        )
        return now

    @staticmethod
    def _record_reclaim(
        conn: sqlite3.Connection, lease_id: str, worker: WorkerIdentity, now: float
    ) -> None:
        conn.execute(
            "INSERT INTO lease_reclaims(lease_id,worker_pid,worker_started,reclaimed_at)"
            " VALUES(?,?,?,?)",
            (lease_id, worker.pid, worker.started_at, now),
        )
        conn.execute(
            "DELETE FROM lease_reclaims WHERE lease_id IN ("
            "SELECT lease_id FROM lease_reclaims ORDER BY reclaimed_at DESC,lease_id DESC"
            " LIMIT -1 OFFSET ?)",
            (_MAX_RECLAIMS,),
        )


class _LeaseTransaction:
    def __init__(self, path: Path, budget_hash: str, boot_id: str) -> None:
        self._path = path
        self._budget_hash = budget_hash
        self._boot_id = boot_id
        self._conn: sqlite3.Connection | None = None

    def __enter__(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._path, timeout=1.0, isolation_level=None)
        self._conn = conn
        try:
            conn.execute("PRAGMA busy_timeout = 1000")
            conn.execute("BEGIN IMMEDIATE")
            version = int(conn.execute("PRAGMA user_version").fetchone()[0])
            if version not in (0, 1, 2, 3):
                raise sqlite3.DatabaseError("unsupported host lease schema")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS leases(lease_id TEXT PRIMARY KEY,"
                "request_id TEXT NOT NULL UNIQUE,cpu INTEGER NOT NULL,ram INTEGER NOT NULL,"
                "vram INTEGER NOT NULL,gpu INTEGER,expires_at REAL NOT NULL,"
                "worker_pid INTEGER,worker_started REAL,state TEXT NOT NULL DEFAULT 'active')"
            )
            if version == 1:
                conn.execute("ALTER TABLE leases ADD COLUMN worker_pid INTEGER")
                conn.execute("ALTER TABLE leases ADD COLUMN worker_started REAL")
                conn.execute("ALTER TABLE leases ADD COLUMN state TEXT NOT NULL DEFAULT 'active'")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS pending(seq INTEGER PRIMARY KEY AUTOINCREMENT,"
                "request_id TEXT NOT NULL UNIQUE,cpu INTEGER NOT NULL,ram INTEGER NOT NULL,"
                "vram INTEGER NOT NULL,gpu INTEGER,expires_at REAL NOT NULL)"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS lease_reclaims(lease_id TEXT PRIMARY KEY,"
                "worker_pid INTEGER NOT NULL,worker_started REAL NOT NULL,"
                "reclaimed_at REAL NOT NULL)"
            )
            conn.execute("PRAGMA user_version = 3")
            saved_budget = conn.execute("SELECT value FROM meta WHERE key='budget_hash'").fetchone()
            if saved_budget is not None and saved_budget[0] != self._budget_hash:
                raise _BudgetMismatch
            if saved_budget is None:
                conn.execute(
                    "INSERT INTO meta(key,value) VALUES('budget_hash',?)",
                    (self._budget_hash,),
                )
            # Boot timestamps are diagnostic only. They can drift between
            # processes in the same boot and must never release capacity.
            conn.execute(
                "INSERT INTO meta(key,value) VALUES('boot_id',?)"
                " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (self._boot_id,),
            )
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
