"""Version-four leases keep complete owned process trees reserved."""

from __future__ import annotations

import sqlite3
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

from pytest import MonkeyPatch

from systemsense.inference import host_lease, tree_host_lease
from systemsense.inference.host_lease import (
    HostInferenceLeaseLedger,
    LeaseBudget,
    LeaseDemand,
    WorkerIdentity,
)
from systemsense.inference.tree_host_lease import TreeCustody, TreeHostInferenceLeaseLedger


def test_tree_ledger_exposes_renewal_ttl(tmp_path: Path) -> None:
    ledger = TreeHostInferenceLeaseLedger(
        tmp_path / "ttl.sqlite3", LeaseBudget(1, 1024, 0), lease_ttl_seconds=17
    )
    assert ledger.lease_ttl_seconds == 17


class FakeJob:
    def __init__(self, pid: int = 1234) -> None:
        self.pid = pid
        self.active = 2
        self.open = True

    def is_assigned_worker(self, worker: SimpleNamespace) -> bool:
        return self.open and worker.pid == self.pid

    def wait_until_empty(self, timeout_seconds: float) -> bool:
        assert timeout_seconds == 0
        if not self.open:
            raise RuntimeError("closed job")
        return self.active == 0


def test_surviving_child_quarantines_gpu_across_clients_and_clock_regression(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    root_state = ["alive"]

    def observe(worker: WorkerIdentity) -> str:
        return root_state[0] if worker.pid == 1234 else "alive"

    monkeypatch.setattr(
        tree_host_lease,
        "_observe_worker",
        observe,
    )
    clock = [100.0]
    db = tmp_path / "host.sqlite3"
    budget = LeaseBudget(1, 1024, 2048, 0)
    left = TreeHostInferenceLeaseLedger(db, budget, lease_ttl_seconds=10, clock=lambda: clock[0])
    right = TreeHostInferenceLeaseLedger(db, budget, lease_ttl_seconds=10, clock=lambda: clock[0])
    demand = LeaseDemand(1, 512, 1024, 0)
    job = FakeJob()
    custody = TreeCustody.create(job, SimpleNamespace(pid=1234), WorkerIdentity(1234, 1.0))
    second_custody = TreeCustody.create(
        FakeJob(5678), SimpleNamespace(pid=5678), WorkerIdentity(5678, 2.0)
    )
    first = left.try_acquire("first", demand, custody=custody)
    assert first.status == "acquired" and first.lease_id
    root_state[0] = "exited"
    clock[0] = 111.0
    decision = right.try_acquire("second", demand, custody=second_custody)
    assert decision.reason.endswith("_quarantined")
    clock[0] = 1.0
    assert right.try_acquire("second", demand, custody=second_custody).reason == "clock_regression"
    assert not left.release(first.lease_id, custody=custody)
    clock[0] = 112.0
    other_job = FakeJob()
    other_job.active = 0
    swapped = replace(custody, _job=other_job)
    assert not left.release(first.lease_id, custody=swapped)
    job.active = 0
    assert left.release(first.lease_id, custody=custody)
    assert right.try_acquire("second", demand, custody=second_custody).status == "acquired"


def test_v3_reader_rejects_v4_and_migration_requires_drained_ledger(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    def alive(_: WorkerIdentity) -> str:
        return "alive"

    monkeypatch.setattr(host_lease, "_observe_worker", alive)
    monkeypatch.setattr(tree_host_lease, "_observe_worker", alive)
    db = tmp_path / "host.sqlite3"
    budget = LeaseBudget(1, 1024, 2048, 0)
    legacy = HostInferenceLeaseLedger(db, budget, clock=lambda: 100.0)
    demand = LeaseDemand(1, 512)
    first = legacy.try_acquire("legacy", demand, worker_identity=WorkerIdentity(1234, 1.0))
    assert first.status == "acquired"
    upgraded = TreeHostInferenceLeaseLedger(db, budget, clock=lambda: 100.0)
    decision = upgraded.try_acquire("new", demand, worker_identity=WorkerIdentity(1234, 1.0))
    assert decision.reason == "migration_required"
    assert upgraded.migrate_from_v3() == "migration_requires_drain"
    with sqlite3.connect(db) as conn:
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 3

    def exited(_: WorkerIdentity) -> str:
        return "exited"

    monkeypatch.setattr(host_lease, "_observe_worker", exited)
    assert first.lease_id and legacy.release(first.lease_id)
    assert upgraded.migrate_from_v3() == "external_proof_required"
    decision = upgraded.try_acquire("new", demand, worker_identity=WorkerIdentity(1234, 1.0))
    assert decision.reason == "migration_required"
    assert legacy.try_acquire("legacy2", demand).status == "acquired"


def test_single_worker_release_needs_verified_exit(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    state = ["alive"]

    def observe(_: WorkerIdentity) -> str:
        return state[0]

    monkeypatch.setattr(tree_host_lease, "_observe_worker", observe)
    ledger = TreeHostInferenceLeaseLedger(tmp_path / "host.sqlite3", LeaseBudget(1, 1024, 0))
    worker = WorkerIdentity(1234, 1.0)
    first = ledger.try_acquire("laya", LeaseDemand(1, 512), worker_identity=worker)
    assert first.lease_id
    assert not ledger.release(first.lease_id, worker_identity=worker)
    state[0] = "unknown"
    assert not ledger.release(first.lease_id, worker_identity=worker)
    state[0] = "exited"
    assert ledger.release(first.lease_id, worker_identity=worker)


def test_gpu_single_pid_cannot_bypass_tree_custody(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    def alive(_: WorkerIdentity) -> str:
        return "alive"

    monkeypatch.setattr(tree_host_lease, "_observe_worker", alive)
    ledger = TreeHostInferenceLeaseLedger(tmp_path / "host.sqlite3", LeaseBudget(1, 1024, 2048, 0))
    decision = ledger.try_acquire(
        "gpu", LeaseDemand(1, 512, 1024, 0), worker_identity=WorkerIdentity(1234, 1.0)
    )
    assert decision.reason == "gpu_tree_custody_required"


def test_missing_v4_lease_table_fails_closed(tmp_path: Path, monkeypatch: MonkeyPatch) -> None:
    def alive(_: WorkerIdentity) -> str:
        return "alive"

    monkeypatch.setattr(tree_host_lease, "_observe_worker", alive)
    db = tmp_path / "host.sqlite3"
    ledger = TreeHostInferenceLeaseLedger(db, LeaseBudget(1, 1024, 0))
    first = ledger.try_acquire(
        "first", LeaseDemand(1, 512), worker_identity=WorkerIdentity(1234, 1.0)
    )
    assert first.status == "acquired"
    with sqlite3.connect(db) as conn:
        conn.execute("DROP TABLE tree_leases")
    second = ledger.try_acquire(
        "second", LeaseDemand(1, 512), worker_identity=WorkerIdentity(5678, 2.0)
    )
    assert second.reason == "store_unavailable"


def test_empty_v4_ledger_resets_clock_after_reboot(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    def exited(_: WorkerIdentity) -> str:
        return "exited"

    monkeypatch.setattr(tree_host_lease, "_observe_worker", exited)
    clock = [1000.0]
    db = tmp_path / "host.sqlite3"
    ledger = TreeHostInferenceLeaseLedger(db, LeaseBudget(1, 1024, 0), clock=lambda: clock[0])

    def alive(_: WorkerIdentity) -> str:
        return "alive"

    monkeypatch.setattr(tree_host_lease, "_observe_worker", alive)
    first = ledger.try_acquire(
        "first", LeaseDemand(1, 512), worker_identity=WorkerIdentity(1234, 1.0)
    )
    assert first.lease_id
    monkeypatch.setattr(tree_host_lease, "_observe_worker", exited)
    assert ledger.release(first.lease_id, worker_identity=WorkerIdentity(1234, 1.0))
    clock[0] = 1.0
    monkeypatch.setattr(tree_host_lease, "_observe_worker", alive)
    second = ledger.try_acquire(
        "second", LeaseDemand(1, 512), worker_identity=WorkerIdentity(5678, 2.0)
    )
    assert second.status == "acquired"
