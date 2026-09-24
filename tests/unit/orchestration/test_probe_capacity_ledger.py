"""Durable probe capacity safety across independent Python processes."""

from __future__ import annotations

import multiprocessing as mp
import sqlite3
from multiprocessing.synchronize import Event as EventType
from pathlib import Path
from typing import Any

import pytest

from systemsense.orchestration.probe_capacity_ledger import (
    DurableProbeLedger,
    LedgerBudget,
    LedgerUnavailable,
    QueueFull,
    WorkerIdentity,
)


class _Verifier:
    def __init__(self) -> None:
        self.identity: WorkerIdentity | None = None

    def prove_empty_and_exited(self, identity: WorkerIdentity) -> bool:
        return identity == self.identity


def _ledger(path: Path) -> DurableProbeLedger:
    return DurableProbeLedger(
        path,
        LedgerBudget(global_limit=1, per_resource={"disk": 1}, max_pending=3),
        schema_hash="registered-probes-v1",
    )


def _contend(path: str, ready: mp.Queue[bool], go: EventType, result: mp.Queue[bool]) -> None:
    ledger = _ledger(Path(path))
    ticket = ledger.enqueue("case-b", "task-b", "disk", 0)
    ready.put(True)
    go.wait(10)
    result.put(ledger.try_reserve(ticket) is not None)


def test_two_processes_cannot_overbook(tmp_path: Path) -> None:
    path = tmp_path / "capacity.db"
    ledger = _ledger(path)
    first = ledger.enqueue("case-a", "task-a", "disk", 0)
    assert ledger.try_reserve(first) is not None
    context = mp.get_context("spawn")
    ready: mp.Queue[bool] = context.Queue()
    result: mp.Queue[bool] = context.Queue()
    go = context.Event()
    child = context.Process(target=_contend, args=(str(path), ready, go, result))
    child.start()
    assert ready.get(timeout=10)
    go.set()
    assert result.get(timeout=10) is False
    child.join(timeout=10)
    assert child.exitcode == 0


def test_eligible_case_fairness_skips_saturated_resource(tmp_path: Path) -> None:
    ledger = DurableProbeLedger(
        tmp_path / "ledger.db",
        LedgerBudget(global_limit=2, per_resource={"disk": 1, "cpu": 1}, max_pending=4),
        schema_hash="v1",
    )
    disk = ledger.enqueue("a", "disk-a", "disk", 0)
    assert ledger.try_reserve(disk) is not None
    blocked = ledger.enqueue("b", "disk-b", "disk", 0)
    eligible = ledger.enqueue("c", "cpu-c", "cpu", 0)
    assert ledger.try_reserve(blocked) is None
    assert ledger.try_reserve(eligible) is not None


def test_launch_intent_and_expiration_never_reclaim(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path / "ledger.db")
    ticket = ledger.enqueue("a", "one", "disk", 0)
    reserved = ledger.try_reserve(ticket, reservation_seconds=30)
    assert reserved is not None
    launched = ledger.record_launch_intent(reserved)
    ledger.expire_prelaunch(now=reserved.expires_at + 100)
    second = ledger.enqueue("b", "two", "disk", 0)
    assert ledger.try_reserve(second) is None
    ledger.quarantine(launched, "custodian crashed")
    assert ledger.try_reserve(second) is None


def test_exact_verified_tree_exit_required(tmp_path: Path) -> None:
    verifier = _Verifier()
    ledger = _ledger(tmp_path / "ledger.db")
    reservation = ledger.try_reserve(ledger.enqueue("a", "one", "disk", 0))
    assert reservation is not None
    intent = ledger.record_launch_intent(reservation)
    worker = ledger.bind_suspended_worker(intent, pid=1234, creation_time_ns=98765)
    ledger.confirm_job_assignment(worker)
    ledger.confirm_resume(worker)
    with pytest.raises(LedgerUnavailable):
        ledger.record_tree_exit_proof(worker, verifier)
    verifier.identity = WorkerIdentity(pid=1234, creation_time_ns=98765)
    ledger.record_tree_exit_proof(worker, verifier)
    ledger.release_verified(worker)
    assert ledger.try_reserve(ledger.enqueue("b", "two", "disk", 0)) is not None


def test_corruption_and_budget_mismatch_fail_closed(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    _ledger(path)
    with pytest.raises(LedgerUnavailable):
        DurableProbeLedger(path, LedgerBudget(global_limit=2), "registered-probes-v1")
    path.write_bytes(b"not a sqlite database")
    with pytest.raises(LedgerUnavailable):
        _ledger(path)


def test_unopenable_ledger_path_fails_closed(tmp_path: Path) -> None:
    with pytest.raises(LedgerUnavailable):
        _ledger(tmp_path)


def test_abandoned_pending_ticket_expires_and_can_requeue(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path / "ledger.db")
    old = ledger.enqueue("a", "one", "disk", 0, pending_seconds=0.001)
    ledger.expire_prelaunch(now=10**12)
    replacement = ledger.enqueue("a", "one", "disk", 0)
    assert replacement != old
    assert ledger.try_reserve(replacement) is not None
    with pytest.raises(LedgerUnavailable):
        ledger.try_reserve(old)


@pytest.mark.parametrize(
    "column,value", [("state", "impossible"), ("resource", "shell"), ("pid", 555)]
)
def test_semantic_corruption_fails_closed(tmp_path: Path, column: str, value: object) -> None:
    path = tmp_path / "ledger.db"
    ledger = _ledger(path)
    ledger.enqueue("a", "one", "disk", 0)
    with sqlite3.connect(path) as db:
        db.execute(f"UPDATE work SET {column}=? WHERE task_id='one'", (value,))
    with pytest.raises(LedgerUnavailable):
        ledger.enqueue("b", "two", "disk", 0)


def test_budget_copies_mutable_resource_limits() -> None:
    limits = {"disk": 1}
    budget = LedgerBudget(global_limit=2, per_resource=limits)
    limits["disk"] = 2
    assert budget.limit_for("disk") == 1


def test_queue_is_bounded_and_cancel_pending(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path / "ledger.db")
    tickets = [ledger.enqueue("a", str(index), "disk", 0) for index in range(3)]
    with pytest.raises(QueueFull):
        ledger.enqueue("a", "overflow", "disk", 0)
    ledger.cancel_pending(tickets[0])
    ledger.enqueue("a", "new", "disk", 0)


def test_only_prelaunch_reservation_expires(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path / "ledger.db")
    reservation = ledger.try_reserve(ledger.enqueue("a", "one", "disk", 0))
    assert reservation is not None
    ledger.expire_prelaunch(now=reservation.expires_at + 1)
    assert ledger.try_reserve(ledger.enqueue("b", "two", "disk", 0)) is not None


def test_unreadable_or_reused_worker_identity_keeps_capacity(tmp_path: Path) -> None:
    verifier = _Verifier()
    ledger = _ledger(tmp_path / "ledger.db")
    reservation = ledger.try_reserve(ledger.enqueue("a", "one", "disk", 0))
    assert reservation is not None
    worker = ledger.bind_suspended_worker(
        ledger.record_launch_intent(reservation), pid=1234, creation_time_ns=98765
    )
    verifier.identity = WorkerIdentity(pid=1234, creation_time_ns=99999)
    with pytest.raises(LedgerUnavailable):
        ledger.record_tree_exit_proof(worker, verifier)
    assert ledger.try_reserve(ledger.enqueue("b", "two", "disk", 0)) is None


def test_terminal_history_is_bounded_without_reclaiming_quarantine(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    ledger = _ledger(path)
    reservation = ledger.try_reserve(ledger.enqueue("held", "one", "disk", 0))
    assert reservation is not None
    ledger.quarantine(ledger.record_launch_intent(reservation), "unknown child state")
    for index in range(150):
        ticket = ledger.enqueue("history", str(index), "cpu", 0)
        ledger.cancel_pending(ticket)
    with sqlite3.connect(path) as db:
        terminal = db.execute(
            "SELECT COUNT(*) FROM work WHERE state IN ('released','expired','cancelled')"
        ).fetchone()[0]
        held = db.execute("SELECT state FROM work WHERE case_id='held'").fetchone()
    assert terminal <= 64
    assert held == ("quarantined",)
    assert ledger.try_reserve(ledger.enqueue("next", "disk", "disk", 0)) is None


def test_terminal_gc_preserves_intent_verified_and_quarantined(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    ledger = DurableProbeLedger(path, LedgerBudget(global_limit=3, max_pending=4), schema_hash="v1")
    first = ledger.try_reserve(ledger.enqueue("intent", "one", "cpu", 0))
    assert first is not None
    ledger.record_launch_intent(first)
    second = ledger.try_reserve(ledger.enqueue("verified", "two", "cpu", 0))
    assert second is not None
    worker = ledger.bind_suspended_worker(
        ledger.record_launch_intent(second), pid=123, creation_time_ns=456
    )
    verifier = _Verifier()
    verifier.identity = worker.identity
    ledger.record_tree_exit_proof(worker, verifier)
    third = ledger.try_reserve(ledger.enqueue("quarantined", "three", "cpu", 0))
    assert third is not None
    ledger.quarantine(ledger.record_launch_intent(third), "unknown")
    for index in range(150):
        ledger.cancel_pending(ledger.enqueue("history", str(index), "cpu", 0))
    with sqlite3.connect(path) as db:
        rows = dict(
            db.execute(
                "SELECT case_id,state FROM work "
                "WHERE case_id IN ('intent','verified','quarantined')"
            ).fetchall()
        )
    assert rows == {
        "intent": "intent",
        "verified": "verified",
        "quarantined": "quarantined",
    }


def test_full_audit_finds_terminal_row_corruption(tmp_path: Path) -> None:
    path = tmp_path / "ledger.db"
    ledger = _ledger(path)
    ledger.cancel_pending(ledger.enqueue("a", "one", "disk", 0))
    with sqlite3.connect(path) as db:
        db.execute("UPDATE work SET resource='arbitrary' WHERE task_id='one'")
    with pytest.raises(LedgerUnavailable):
        ledger.audit_integrity()


def test_hot_admission_avoids_full_sqlite_integrity_scan(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    ledger = _ledger(tmp_path / "ledger.db")
    statements: list[str] = []
    original = sqlite3.connect

    def traced_connect(database: str | Path, **kwargs: Any) -> sqlite3.Connection:
        db = original(database, **kwargs)
        db.set_trace_callback(statements.append)
        return db

    monkeypatch.setattr(sqlite3, "connect", traced_connect)
    ticket = ledger.enqueue("a", "one", "disk", 0)
    assert ledger.try_reserve(ticket) is not None
    assert not any("quick_check" in statement.lower() for statement in statements)
