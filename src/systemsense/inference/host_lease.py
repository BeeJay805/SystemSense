"""Cross-process, bounded host inference leases; no model or OS execution authority.

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


class _BudgetMismatch(Exception):
    pass


class _ClockRegression(Exception):
    pass


class HostInferenceLeaseLedger:
    """One host-wide, finite lease and FIFO queue in a trusted local SQLite file.

    Leases expire after a bounded duration if an owner crashes. The caller is
    responsible for heartbeats and for terminating a call before lease expiry.
    This is resource coordination, not a security boundary against local users.
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

    def try_acquire(self, request_id: str, demand: LeaseDemand) -> LeaseDecision:
        if not _REQUEST_ID.fullmatch(request_id):
            return LeaseDecision("denied", "invalid_request_id")
        mismatch = self._static_denial(demand)
        if mismatch:
            return LeaseDecision("denied", mismatch)
        try:
            with self._transaction() as conn:
                now = self._tick(conn)
                existing = conn.execute(
                    "SELECT lease_id, cpu, ram, vram, gpu FROM leases WHERE request_id = ?",
                    (request_id,),
                ).fetchone()
                if existing is not None:
                    if tuple(existing[1:]) != self._demand_tuple(demand):
                        return LeaseDecision("denied", "request_id_collision")
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
                for cpu, ram, vram, gpu in conn.execute(
                    "SELECT cpu,ram,vram,gpu FROM leases"
                ).fetchall():
                    if (
                        not 1 <= cpu <= self._budget.cpu_slots
                        or not 1 <= ram <= self._budget.ram_bytes
                        or not 0 <= vram <= self._budget.vram_bytes
                        or (vram > 0 and gpu != self._budget.gpu_device_index)
                        or (vram == 0 and gpu is not None)
                    ):
                        return LeaseDecision("denied", "ledger_corrupt")
                    used_cpu += cpu
                    used_ram += ram
                    used_vram += vram
                if (
                    used_cpu > self._budget.cpu_slots
                    or used_ram > self._budget.ram_bytes
                    or used_vram > self._budget.vram_bytes
                ):
                    return LeaseDecision("denied", "ledger_corrupt")
                for dimension, required, used, capacity in (
                    ("cpu", demand.cpu_slots, used_cpu, self._budget.cpu_slots),
                    ("ram", demand.ram_bytes, used_ram, self._budget.ram_bytes),
                    ("vram", demand.vram_bytes, used_vram, self._budget.vram_bytes),
                ):
                    if required + used > capacity:
                        return LeaseDecision("queued", f"capacity_{dimension}")
                lease_id = uuid.uuid4().hex
                conn.execute(
                    "INSERT INTO leases(lease_id,request_id,cpu,ram,vram,gpu,expires_at)"
                    " VALUES(?,?,?,?,?,?,?)",
                    (lease_id, request_id, *self._demand_tuple(demand), now + self._lease_ttl),
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
                    "UPDATE leases SET expires_at = ? WHERE lease_id = ?",
                    (now + self._lease_ttl, lease_id),
                )
                return cursor.rowcount == 1
        except (OSError, sqlite3.Error, ValueError, _BudgetMismatch, _ClockRegression):
            return False

    def release(self, lease_id: str) -> bool:
        if not re.fullmatch(r"[0-9a-f]{32}", lease_id):
            return False
        try:
            with self._transaction() as conn:
                self._tick(conn)
                cursor = conn.execute("DELETE FROM leases WHERE lease_id = ?", (lease_id,))
                return cursor.rowcount == 1
        except (OSError, sqlite3.Error, ValueError, _BudgetMismatch, _ClockRegression):
            return False

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

    def _transaction(self) -> _LeaseTransaction:
        return _LeaseTransaction(self._path, self._budget_hash, self._boot_id)

    def _tick(self, conn: sqlite3.Connection) -> float:
        now = self._clock()
        if not math.isfinite(now) or now < 0:
            raise ValueError("invalid monotonic clock")
        prior = conn.execute("SELECT value FROM meta WHERE key = 'last_tick'").fetchone()
        if prior is not None and now < float(prior[0]):
            raise _ClockRegression
        conn.execute(
            "INSERT INTO meta(key,value) VALUES('last_tick',?)"
            " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (repr(now),),
        )
        conn.execute("DELETE FROM leases WHERE expires_at <= ?", (now,))
        conn.execute("DELETE FROM pending WHERE expires_at <= ?", (now,))
        return now


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
            if version not in (0, 1):
                raise sqlite3.DatabaseError("unsupported host lease schema")
            conn.execute(
                "CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY,value TEXT NOT NULL)"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS leases(lease_id TEXT PRIMARY KEY,"
                "request_id TEXT NOT NULL UNIQUE,cpu INTEGER NOT NULL,ram INTEGER NOT NULL,"
                "vram INTEGER NOT NULL,gpu INTEGER,expires_at REAL NOT NULL)"
            )
            conn.execute(
                "CREATE TABLE IF NOT EXISTS pending(seq INTEGER PRIMARY KEY AUTOINCREMENT,"
                "request_id TEXT NOT NULL UNIQUE,cpu INTEGER NOT NULL,ram INTEGER NOT NULL,"
                "vram INTEGER NOT NULL,gpu INTEGER,expires_at REAL NOT NULL)"
            )
            conn.execute("PRAGMA user_version = 1")
            saved_budget = conn.execute("SELECT value FROM meta WHERE key='budget_hash'").fetchone()
            if saved_budget is not None and saved_budget[0] != self._budget_hash:
                raise _BudgetMismatch
            if saved_budget is None:
                conn.execute(
                    "INSERT INTO meta(key,value) VALUES('budget_hash',?)",
                    (self._budget_hash,),
                )
            saved_boot = conn.execute("SELECT value FROM meta WHERE key='boot_id'").fetchone()
            if saved_boot is not None and saved_boot[0] != self._boot_id:
                conn.execute("DELETE FROM leases")
                conn.execute("DELETE FROM pending")
                conn.execute("DELETE FROM meta WHERE key='last_tick'")
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
