"""Host lease admission is coordinated across independent ledger instances."""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from pytest import MonkeyPatch

from systemsense.inference import host_lease
from systemsense.inference.host_lease import (
    HostInferenceLeaseLedger,
    LeaseBudget,
    LeaseDemand,
)


def test_two_process_handles_do_not_overbook_and_fifo_waiter_wins(tmp_path: object) -> None:
    from pathlib import Path

    db = Path(str(tmp_path)) / "host-lease.sqlite3"
    now = [1000.0]
    budget = LeaseBudget(cpu_slots=1, ram_bytes=1024, vram_bytes=2048, gpu_device_index=0)
    left = HostInferenceLeaseLedger(db, budget, clock=lambda: now[0])
    right = HostInferenceLeaseLedger(db, budget, clock=lambda: now[0])
    cpu = LeaseDemand(cpu_slots=1, ram_bytes=512, vram_bytes=0)

    first = left.try_acquire("first", cpu)
    assert first.status == "acquired" and first.lease_id
    assert right.try_acquire("second", cpu).reason == "capacity_cpu"
    assert left.try_acquire("third", cpu).reason == "queued_behind_prior_request"
    assert left.release(first.lease_id)
    assert left.try_acquire("third", cpu).status == "queued"
    assert right.try_acquire("second", cpu).status == "acquired"


def test_expired_unbound_lease_is_quarantined_not_silently_reused(tmp_path: object) -> None:
    from pathlib import Path

    now = [1000.0]
    ledger = HostInferenceLeaseLedger(
        Path(str(tmp_path)) / "lease.sqlite3",
        LeaseBudget(cpu_slots=1, ram_bytes=1024, vram_bytes=0),
        lease_ttl_seconds=10,
        clock=lambda: now[0],
    )
    demand = LeaseDemand(cpu_slots=1, ram_bytes=1)
    first = ledger.try_acquire("first", demand)
    assert first.lease_id
    now[0] += 11
    assert ledger.try_acquire("second", demand).reason == "capacity_cpu_quarantined"
    assert ledger.try_acquire("first", demand).reason == "lease_quarantined"
    with sqlite3.connect(Path(str(tmp_path)) / "lease.sqlite3") as conn:
        assert conn.execute("SELECT state FROM leases WHERE request_id='first'").fetchone() == (
            "quarantined_unknown",
        )
    assert not ledger.renew(first.lease_id)
    assert not ledger.release(first.lease_id)
    assert ledger.release(first.lease_id, acknowledge_unknown_exit=True)
    assert ledger.try_acquire("second", demand).status == "acquired"


def test_expired_live_worker_remains_quarantined_until_verified_exit(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    now = [1000.0]
    worker_state: list[host_lease.WorkerState] = ["alive"]

    def observe(_: host_lease.WorkerIdentity) -> host_lease.WorkerState:
        return worker_state[0]

    monkeypatch.setattr(host_lease, "_observe_worker", observe)
    ledger = HostInferenceLeaseLedger(
        tmp_path / "lease.sqlite3",
        LeaseBudget(1, 1024, 0),
        lease_ttl_seconds=10,
        clock=lambda: now[0],
    )
    demand = LeaseDemand(1, 1)
    worker = host_lease.WorkerIdentity(pid=1234, started_at=123.0)
    first = ledger.try_acquire("first", demand, worker_identity=worker)
    assert first.lease_id
    now[0] += 11
    assert ledger.try_acquire("second", demand).reason == "capacity_cpu_quarantined"
    with sqlite3.connect(tmp_path / "lease.sqlite3") as conn:
        assert conn.execute("SELECT state FROM leases WHERE request_id='first'").fetchone() == (
            "quarantined_live",
        )
    assert not ledger.renew(first.lease_id)
    assert not ledger.release(first.lease_id)
    worker_state[0] = "exited"
    assert ledger.try_acquire("second", demand).status == "acquired"
    assert not ledger.renew(first.lease_id)


def test_reconcile_release_normal_close_and_exact_idempotent_readback(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    state: list[host_lease.WorkerState] = ["alive"]

    def observe(_: host_lease.WorkerIdentity) -> host_lease.WorkerState:
        return state[0]

    monkeypatch.setattr(host_lease, "_observe_worker", observe)
    ledger = HostInferenceLeaseLedger(tmp_path / "lease.sqlite3", LeaseBudget(1, 1024, 0))
    worker = host_lease.WorkerIdentity(1234, 123.0)
    first = ledger.try_acquire("first", LeaseDemand(1, 1), worker_identity=worker)
    assert first.lease_id
    assert ledger.reconcile_release(first.lease_id, worker).status == "still_live_or_unknown"
    state[0] = "exited"
    assert ledger.reconcile_release(first.lease_id, worker).status == "released_now"
    assert (
        ledger.reconcile_release(first.lease_id, worker).status == "verified_exited_prior_reclaim"
    )
    assert ledger.reconcile_release("f" * 32, worker).status == "not_found"


def test_reconcile_release_recognizes_prior_auto_reclaim_only_for_matching_worker(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    now = [1000.0]
    state: list[host_lease.WorkerState] = ["alive"]

    def observe(_: host_lease.WorkerIdentity) -> host_lease.WorkerState:
        return state[0]

    monkeypatch.setattr(host_lease, "_observe_worker", observe)
    ledger = HostInferenceLeaseLedger(
        tmp_path / "lease.sqlite3",
        LeaseBudget(1, 1024, 0),
        lease_ttl_seconds=10,
        clock=lambda: now[0],
    )
    worker = host_lease.WorkerIdentity(1234, 123.0)
    first = ledger.try_acquire("first", LeaseDemand(1, 1), worker_identity=worker)
    assert first.lease_id
    now[0] += 11
    state[0] = "exited"
    assert ledger.try_acquire("second", LeaseDemand(1, 1)).status == "acquired"
    wrong_incarnation = host_lease.WorkerIdentity(1234, 124.0)
    assert ledger.reconcile_release(first.lease_id, wrong_incarnation).status == "identity_mismatch"
    assert (
        ledger.reconcile_release(first.lease_id, worker).status == "verified_exited_prior_reclaim"
    )


def test_release_racing_expiry_sweep_has_only_verified_success(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    now = [1000.0]
    state: list[host_lease.WorkerState] = ["alive"]

    def observe(_: host_lease.WorkerIdentity) -> host_lease.WorkerState:
        return state[0]

    monkeypatch.setattr(host_lease, "_observe_worker", observe)
    ledger = HostInferenceLeaseLedger(
        tmp_path / "lease.sqlite3",
        LeaseBudget(1, 1024, 0),
        lease_ttl_seconds=10,
        clock=lambda: now[0],
    )
    worker = host_lease.WorkerIdentity(1234, 123.0)
    first = ledger.try_acquire("first", LeaseDemand(1, 1), worker_identity=worker)
    assert first.lease_id
    state[0] = "exited"
    now[0] += 11
    with ThreadPoolExecutor(max_workers=2) as executor:
        release_future = executor.submit(ledger.reconcile_release, first.lease_id, worker)
        contender_future = executor.submit(ledger.try_acquire, "second", LeaseDemand(1, 1))
        release = release_future.result()
        contender = contender_future.result()
    assert release.status in ("released_now", "verified_exited_prior_reclaim")
    assert contender.status == "acquired"
    assert ledger.reconcile_release(first.lease_id, worker).status == (
        "verified_exited_prior_reclaim"
    )


def test_reclaim_receipt_expires_to_not_found_without_false_success(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    now = [1000.0]
    state: list[host_lease.WorkerState] = ["alive"]

    def observe(_: host_lease.WorkerIdentity) -> host_lease.WorkerState:
        return state[0]

    monkeypatch.setattr(host_lease, "_observe_worker", observe)
    ledger = HostInferenceLeaseLedger(
        tmp_path / "lease.sqlite3",
        LeaseBudget(1, 1024, 0),
        clock=lambda: now[0],
    )
    worker = host_lease.WorkerIdentity(1234, 123.0)
    first = ledger.try_acquire("first", LeaseDemand(1, 1), worker_identity=worker)
    assert first.lease_id
    state[0] = "exited"
    assert ledger.reconcile_release(first.lease_id, worker).status == "released_now"
    now[0] += 24 * 60 * 60 + 1
    assert ledger.reconcile_release(first.lease_id, worker).status == "not_found"


def test_lease_ttl_is_public_for_managed_renewal_cadence(tmp_path: Path) -> None:
    ledger = HostInferenceLeaseLedger(
        tmp_path / "lease.sqlite3",
        LeaseBudget(1, 1024, 0),
        lease_ttl_seconds=17,
    )
    assert ledger.lease_ttl_seconds == 17


def test_process_identity_distinguishes_reused_pid(tmp_path: Path) -> None:
    identity = host_lease.capture_worker_identity(os.getpid())
    ledger = HostInferenceLeaseLedger(tmp_path / "lease.sqlite3", LeaseBudget(1, 1024, 0))
    assert (
        ledger.try_acquire("real", LeaseDemand(1, 1), worker_identity=identity).status == "acquired"
    )
    reused_pid = host_lease.WorkerIdentity(identity.pid, identity.started_at - 1)
    assert (
        ledger.try_acquire("reused", LeaseDemand(1, 1), worker_identity=reused_pid).reason
        == "worker_identity_unverifiable"
    )


def test_real_worker_exit_reconciles_expired_gpu_lease(tmp_path: Path) -> None:
    now = [1000.0]
    ledger = HostInferenceLeaseLedger(
        tmp_path / "lease.sqlite3",
        LeaseBudget(1, 1024, 2048, gpu_device_index=0),
        lease_ttl_seconds=1,
        clock=lambda: now[0],
    )
    demand = LeaseDemand(1, 1, 100, gpu_device_index=0)
    child = subprocess.Popen([sys.executable, "-c", "input()"], stdin=subprocess.PIPE, text=True)
    try:
        worker = host_lease.capture_worker_identity(child.pid)
        first = ledger.try_acquire("first", demand, worker_identity=worker)
        assert first.lease_id
        child.communicate(input="\n", timeout=5)
        assert child.returncode == 0
        now[0] += 2
        second_child = subprocess.Popen(
            [sys.executable, "-c", "input()"], stdin=subprocess.PIPE, text=True
        )
        try:
            second_worker = host_lease.capture_worker_identity(second_child.pid)
            assert (
                ledger.try_acquire("second", demand, worker_identity=second_worker).status
                == "acquired"
            )
        finally:
            second_child.communicate(input="\n", timeout=5)
    finally:
        if child.poll() is None:
            child.communicate(input="\n", timeout=5)


def test_unknown_process_status_does_not_reclaim_quarantined_lease(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    now = [1000.0]
    state: list[host_lease.WorkerState] = ["alive"]

    def observe(_: host_lease.WorkerIdentity) -> host_lease.WorkerState:
        return state[0]

    monkeypatch.setattr(host_lease, "_observe_worker", observe)
    ledger = HostInferenceLeaseLedger(
        tmp_path / "lease.sqlite3",
        LeaseBudget(1, 1024, 0),
        clock=lambda: now[0],
        lease_ttl_seconds=10,
    )
    worker = host_lease.WorkerIdentity(1234, 123.0)
    first = ledger.try_acquire("first", LeaseDemand(1, 1), worker_identity=worker)
    assert first.lease_id
    now[0] += 11
    state[0] = "unknown"
    assert ledger.try_acquire("second", LeaseDemand(1, 1)).reason == "capacity_cpu_quarantined"
    with sqlite3.connect(tmp_path / "lease.sqlite3") as conn:
        assert conn.execute("SELECT state FROM leases WHERE request_id='first'").fetchone() == (
            "quarantined_unknown",
        )
    assert not ledger.release(first.lease_id, acknowledge_unknown_exit=True)
    state[0] = "exited"
    assert ledger.try_acquire("second", LeaseDemand(1, 1)).status == "acquired"


def test_v1_lease_migrates_to_quarantine_without_inventing_worker_identity(tmp_path: Path) -> None:
    db = tmp_path / "lease.sqlite3"
    with sqlite3.connect(db) as conn:
        conn.execute(
            "CREATE TABLE leases(lease_id TEXT PRIMARY KEY,request_id TEXT NOT NULL UNIQUE,"
            "cpu INTEGER NOT NULL,ram INTEGER NOT NULL,vram INTEGER NOT NULL,"
            "gpu INTEGER,expires_at REAL NOT NULL)"
        )
        conn.execute(
            "INSERT INTO leases VALUES(?,?,?,?,?,?,?)", ("a" * 32, "old", 1, 1, 0, None, 1010.0)
        )
        conn.execute("PRAGMA user_version = 1")
    now = [1011.0]
    ledger = HostInferenceLeaseLedger(db, LeaseBudget(1, 1024, 0), clock=lambda: now[0])
    assert ledger.try_acquire("new", LeaseDemand(1, 1)).reason == "capacity_cpu_quarantined"
    with sqlite3.connect(db) as conn:
        assert conn.execute("PRAGMA user_version").fetchone() == (3,)
        assert conn.execute(
            "SELECT state,worker_pid FROM leases WHERE request_id='old'"
        ).fetchone() == (
            "quarantined_unknown",
            None,
        )


def test_incomplete_worker_identity_row_cannot_be_released_as_unbound(tmp_path: Path) -> None:
    db = tmp_path / "lease.sqlite3"
    ledger = HostInferenceLeaseLedger(db, LeaseBudget(1, 1024, 0))
    first = ledger.try_acquire("first", LeaseDemand(1, 1))
    assert first.lease_id
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE leases SET worker_pid=1234 WHERE lease_id=?", (first.lease_id,))
    assert not ledger.release(first.lease_id)


def test_unbound_gpu_lease_cannot_be_admitted_or_released_from_legacy(
    tmp_path: Path,
) -> None:
    db = tmp_path / "lease.sqlite3"
    budget = LeaseBudget(1, 1024, 2048, gpu_device_index=0)
    demand = LeaseDemand(1, 1, 100, gpu_device_index=0)
    ledger = HostInferenceLeaseLedger(db, budget)
    assert ledger.try_acquire("gpu", demand).reason == "gpu_worker_identity_required"
    initial = ledger.try_acquire("cpu", LeaseDemand(1, 1))
    assert initial.lease_id and ledger.release(initial.lease_id)

    with sqlite3.connect(db) as conn:
        conn.execute(
            "INSERT INTO leases(lease_id,request_id,cpu,ram,vram,gpu,expires_at,"
            "worker_pid,worker_started,state) VALUES(?,?,?,?,?,?,?,?,?,?)",
            ("b" * 32, "legacy-gpu", 1, 1, 100, 0, 0.0, None, None, "active"),
        )
    assert not ledger.release("b" * 32, acknowledge_unknown_exit=True)
    with sqlite3.connect(db) as conn:
        assert conn.execute(
            "SELECT state FROM leases WHERE request_id='legacy-gpu'"
        ).fetchone() == ("quarantined_unknown",)


def test_capacity_reason_blames_quarantine_only_when_it_changes_admission(tmp_path: Path) -> None:
    now = [1000.0]
    ledger = HostInferenceLeaseLedger(
        tmp_path / "lease.sqlite3",
        LeaseBudget(3, 100, 0),
        lease_ttl_seconds=10,
        clock=lambda: now[0],
    )
    assert ledger.try_acquire("old", LeaseDemand(1, 1)).status == "acquired"
    now[0] += 5
    assert ledger.try_acquire("active", LeaseDemand(1, 99)).status == "acquired"
    now[0] += 6
    assert ledger.try_acquire("new", LeaseDemand(1, 2)).reason == "capacity_ram"


def test_heartbeat_preserves_lease_and_release_is_idempotent(tmp_path: object) -> None:
    from pathlib import Path

    now = [1000.0]
    ledger = HostInferenceLeaseLedger(
        Path(str(tmp_path)) / "lease.sqlite3",
        LeaseBudget(cpu_slots=1, ram_bytes=1024, vram_bytes=0),
        lease_ttl_seconds=10,
        clock=lambda: now[0],
    )
    demand = LeaseDemand(cpu_slots=1, ram_bytes=1)
    acquired = ledger.try_acquire("owner", demand)
    assert acquired.lease_id
    now[0] += 8
    assert ledger.renew(acquired.lease_id)
    now[0] += 5
    assert ledger.try_acquire("contender", demand).status == "queued"
    assert ledger.release(acquired.lease_id)
    assert not ledger.release(acquired.lease_id)
    assert ledger.try_acquire("contender", demand).status == "acquired"


def test_vram_device_and_ram_budgets_are_independent(tmp_path: object) -> None:
    from pathlib import Path

    ledger = HostInferenceLeaseLedger(
        Path(str(tmp_path)) / "lease.sqlite3",
        LeaseBudget(cpu_slots=2, ram_bytes=1024, vram_bytes=2048, gpu_device_index=0),
    )
    gpu = LeaseDemand(cpu_slots=1, ram_bytes=100, vram_bytes=1500, gpu_device_index=0)
    worker = host_lease.capture_worker_identity(os.getpid())
    assert ledger.try_acquire("gpu", gpu, worker_identity=worker).status == "acquired"
    assert ledger.try_acquire("bad-gpu", LeaseDemand(1, 100, 1, 1)).reason == "gpu_device_mismatch"
    assert ledger.try_acquire("ram", LeaseDemand(1, 1000)).reason == "capacity_ram"


def test_incompatible_budget_and_unavailable_db_fail_closed(tmp_path: object) -> None:
    from pathlib import Path

    db = Path(str(tmp_path)) / "lease.sqlite3"
    first = HostInferenceLeaseLedger(db, LeaseBudget(cpu_slots=1, ram_bytes=1024, vram_bytes=0))
    assert first.try_acquire("one", LeaseDemand(1, 1)).status == "acquired"
    incompatible = HostInferenceLeaseLedger(
        db, LeaseBudget(cpu_slots=2, ram_bytes=1024, vram_bytes=0)
    )
    assert incompatible.try_acquire("two", LeaseDemand(1, 1)).reason == "budget_mismatch"
    missing_parent = HostInferenceLeaseLedger(
        Path(str(tmp_path)) / "missing" / "lease.sqlite3",
        LeaseBudget(cpu_slots=1, ram_bytes=1024, vram_bytes=0),
    )
    assert missing_parent.try_acquire("three", LeaseDemand(1, 1)).reason == "store_unavailable"


def test_stale_waiter_expires_and_cannot_block_next_request(tmp_path: object) -> None:
    from pathlib import Path

    now = [1000.0]
    ledger = HostInferenceLeaseLedger(
        Path(str(tmp_path)) / "lease.sqlite3",
        LeaseBudget(cpu_slots=1, ram_bytes=1024, vram_bytes=0),
        request_ttl_seconds=5,
        clock=lambda: now[0],
    )
    demand = LeaseDemand(1, 1)
    owner = ledger.try_acquire("owner", demand)
    assert owner.lease_id
    assert ledger.try_acquire("abandoned", demand).status == "queued"
    now[0] += 6
    assert ledger.release(owner.lease_id)
    assert ledger.try_acquire("new", demand).status == "acquired"


def test_simultaneous_independent_processes_admit_only_one(tmp_path: Path) -> None:
    db = tmp_path / "lease.sqlite3"
    root = Path(__file__).resolve().parents[3]
    env = dict(os.environ, PYTHONPATH=str(root / "src"))
    script = (
        "import sys; "
        "from pathlib import Path; "
        "from systemsense.inference.host_lease import "
        "HostInferenceLeaseLedger,LeaseBudget,LeaseDemand; "
        "ledger=HostInferenceLeaseLedger(Path(sys.argv[1]),LeaseBudget(1,1024,0)); "
        "print(ledger.try_acquire(sys.argv[2],LeaseDemand(1,1)).status)"
    )

    def attempt(index: int) -> str:
        child = subprocess.run(
            [sys.executable, "-c", script, str(db), f"child-{index}"],
            env=env,
            cwd=root,
            capture_output=True,
            text=True,
            timeout=10,
            check=True,
        )
        return child.stdout.strip()

    with ThreadPoolExecutor(max_workers=4) as executor:
        outcomes = list(executor.map(attempt, range(4)))
    assert sorted(outcomes) == ["acquired", "queued", "queued", "queued"]


def test_boot_id_change_never_reclaims_unverified_live_gpu_worker(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    worker = host_lease.WorkerIdentity(os.getpid(), 1234.0)

    def alive(_worker: host_lease.WorkerIdentity) -> host_lease.WorkerState:
        return "alive"

    monkeypatch.setattr(host_lease, "_observe_worker", alive)
    db = tmp_path / "lease.sqlite3"
    budget = LeaseBudget(1, 1024, 1024, gpu_device_index=0)
    first = HostInferenceLeaseLedger(db, budget, boot_id="boot-A")
    acquired = first.try_acquire("first", LeaseDemand(1, 1, 1024, 0), worker_identity=worker)
    assert acquired.status == "acquired" and acquired.lease_id
    second = HostInferenceLeaseLedger(db, budget, boot_id="boot-B")
    assert (
        second.try_acquire("second", LeaseDemand(1, 1, 1024, 0), worker_identity=worker).status
        == "queued"
    )
    assert first.renew(acquired.lease_id)


def test_clock_regression_recovers_only_after_verified_worker_exit(
    tmp_path: Path, monkeypatch: MonkeyPatch
) -> None:
    now = [1000.0]
    db = tmp_path / "lease.sqlite3"
    budget = LeaseBudget(1, 1024, 1024, gpu_device_index=0)
    worker = host_lease.WorkerIdentity(os.getpid(), 1234.0)
    state: list[host_lease.WorkerState] = ["alive"]

    def observe(_worker: host_lease.WorkerIdentity) -> host_lease.WorkerState:
        return state[0]

    monkeypatch.setattr(host_lease, "_observe_worker", observe)
    first = HostInferenceLeaseLedger(db, budget, clock=lambda: now[0], boot_id="boot-A")
    acquired = first.try_acquire("first", LeaseDemand(1, 1, 1024, 0), worker_identity=worker)
    assert acquired.status == "acquired" and acquired.lease_id
    now[0] = 900.0
    assert (
        first.try_acquire("second", LeaseDemand(1, 1, 1024, 0), worker_identity=worker).reason
        == "clock_regression"
    )
    second_boot = HostInferenceLeaseLedger(db, budget, clock=lambda: now[0], boot_id="boot-B")
    assert (
        second_boot.try_acquire("new", LeaseDemand(1, 1, 1024, 0), worker_identity=worker).reason
        == "clock_regression"
    )
    state[0] = "exited"
    assert (
        second_boot.try_acquire("new", LeaseDemand(1, 1, 1024, 0), worker_identity=worker).reason
        == "worker_identity_unverifiable"
    )
    new_worker = host_lease.WorkerIdentity(os.getpid(), 5678.0)

    def observed_exit(value: host_lease.WorkerIdentity) -> host_lease.WorkerState:
        return "exited" if value == worker else "alive"

    monkeypatch.setattr(host_lease, "_observe_worker", observed_exit)
    assert (
        second_boot.try_acquire(
            "new", LeaseDemand(1, 1, 1024, 0), worker_identity=new_worker
        ).status
        == "acquired"
    )
    assert (
        first.reconcile_release(acquired.lease_id, worker).status == "verified_exited_prior_reclaim"
    )


def test_pending_queue_and_identity_are_bounded(tmp_path: Path) -> None:
    ledger = HostInferenceLeaseLedger(
        tmp_path / "lease.sqlite3", LeaseBudget(1, 1024, 0), max_pending=1
    )
    demand = LeaseDemand(1, 1)
    assert ledger.try_acquire("active", demand).status == "acquired"
    assert ledger.try_acquire("first-waiter", demand).status == "queued"
    assert ledger.try_acquire("second-waiter", demand).reason == "pending_queue_full"
    assert ledger.try_acquire("first-waiter", LeaseDemand(1, 2)).reason == "request_id_collision"
    assert ledger.cancel_pending("first-waiter")
    assert ledger.try_acquire("second-waiter", demand).status == "queued"


def test_corrupt_resource_totals_fail_closed(tmp_path: Path) -> None:
    db = tmp_path / "lease.sqlite3"
    ledger = HostInferenceLeaseLedger(db, LeaseBudget(1, 1024, 0))
    assert ledger.try_acquire("active", LeaseDemand(1, 1)).status == "acquired"
    with sqlite3.connect(db) as conn:
        conn.execute("UPDATE leases SET cpu=-10,ram=-999 WHERE request_id='active'")
    assert ledger.try_acquire("new", LeaseDemand(1, 1)).reason == "ledger_corrupt"
