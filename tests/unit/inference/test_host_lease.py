"""Host lease admission is coordinated across independent ledger instances."""

from __future__ import annotations

import os
import sqlite3
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

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


def test_expired_crashed_owner_is_recovered_and_old_token_cannot_renew(tmp_path: object) -> None:
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
    assert ledger.try_acquire("second", demand).status == "acquired"
    assert not ledger.renew(first.lease_id)


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
    assert ledger.try_acquire("gpu", gpu).status == "acquired"
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


def test_same_boot_clock_regression_fails_closed_and_new_boot_recovers(tmp_path: Path) -> None:
    now = [1000.0]
    db = tmp_path / "lease.sqlite3"
    budget = LeaseBudget(1, 1024, 0)
    first = HostInferenceLeaseLedger(db, budget, clock=lambda: now[0], boot_id="boot-A")
    assert first.try_acquire("first", LeaseDemand(1, 1)).status == "acquired"
    now[0] = 900.0
    assert first.try_acquire("second", LeaseDemand(1, 1)).reason == "clock_regression"
    second_boot = HostInferenceLeaseLedger(db, budget, clock=lambda: now[0], boot_id="boot-B")
    assert second_boot.try_acquire("new", LeaseDemand(1, 1)).status == "acquired"


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
