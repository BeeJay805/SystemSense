"""Cold-boot migration must fence every ambiguous v3 state."""

from __future__ import annotations

import os
import sqlite3
from pathlib import Path

import psutil
import pytest

from systemsense.inference.host_lease import (
    HostInferenceLeaseLedger,
    LeaseBudget,
    LeaseDemand,
    WorkerIdentity,
)
from systemsense.inference.tree_host_lease import TreeHostInferenceLeaseLedger


class Boot:
    def __init__(self) -> None:
        self.monotonic = 500.0
        self.boot_time = 1000.0


def ledgers(
    path: Path, boot: Boot, budget: LeaseBudget | None = None
) -> tuple[HostInferenceLeaseLedger, TreeHostInferenceLeaseLedger]:
    size = budget or LeaseBudget(1, 1024, 2048, 0)
    legacy = HostInferenceLeaseLedger(path, size, clock=lambda: boot.monotonic, boot_id="1000")
    upgraded = TreeHostInferenceLeaseLedger(
        path,
        size,
        clock=lambda: boot.monotonic,
        boot_time=lambda: boot.boot_time,
    )
    assert legacy.try_acquire("seed", LeaseDemand(1, 512)).status == "acquired"
    return legacy, upgraded


def rows(path: Path) -> tuple[int, int, int]:
    with sqlite3.connect(path) as conn:
        version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        leases = int(conn.execute("SELECT count(*) FROM leases").fetchone()[0])
        reclaims = int(conn.execute("SELECT count(*) FROM lease_reclaims").fetchone()[0])
    return version, leases, reclaims


def test_cold_boot_success_preserves_v3_history_and_fences_old_reader(tmp_path: Path) -> None:
    boot = Boot()
    path = tmp_path / "lease.sqlite3"
    legacy, upgraded = ledgers(path, boot)
    assert upgraded.stage_v3_cold_boot_migration() == "migration_requires_drain"
    with sqlite3.connect(path) as conn:
        conn.execute("DELETE FROM leases")
        conn.execute("INSERT INTO lease_reclaims VALUES('historical',1234,1.0,100.0)")
    assert upgraded.stage_v3_cold_boot_migration() == "staged_for_cold_boot"
    boot.monotonic = 10.0
    boot.boot_time = 2000.0
    assert upgraded.complete_v3_cold_boot_migration() == "migrated"
    assert rows(path) == (4, 0, 1)
    assert legacy.try_acquire("old", LeaseDemand(1, 512)).reason == "store_unavailable"


@pytest.mark.parametrize(
    ("monotonic", "boot_time"),
    [(500.0, 1000.0), (600.0, 2000.0), (100.0, 1000.0)],
    ids=["same_boot", "no_monotonic_reset", "clock_jump_only"],
)
def test_cold_boot_requires_both_independent_signals(
    tmp_path: Path, monotonic: float, boot_time: float
) -> None:
    boot = Boot()
    path = tmp_path / "lease.sqlite3"
    _, upgraded = ledgers(path, boot)
    with sqlite3.connect(path) as conn:
        conn.execute("DELETE FROM leases")
    assert upgraded.stage_v3_cold_boot_migration() == "staged_for_cold_boot"
    boot.monotonic, boot.boot_time = monotonic, boot_time
    assert upgraded.complete_v3_cold_boot_migration() != "migrated"
    assert rows(path)[0] == 3


@pytest.mark.parametrize("postboot_id", ["1000", "2000"])
def test_postboot_v3_transaction_blocks_completion(tmp_path: Path, postboot_id: str) -> None:
    boot = Boot()
    path = tmp_path / "lease.sqlite3"
    _, upgraded = ledgers(path, boot)
    with sqlite3.connect(path) as conn:
        conn.execute("DELETE FROM leases")
    assert upgraded.stage_v3_cold_boot_migration() == "staged_for_cold_boot"
    boot.monotonic, boot.boot_time = 10.0, 2000.0
    postboot = HostInferenceLeaseLedger(path, LeaseBudget(1, 1024, 2048, 0), boot_id=postboot_id)
    assert postboot.try_acquire("postboot", LeaseDemand(1, 512)).status == "acquired"
    with sqlite3.connect(path) as conn:
        conn.execute("DELETE FROM leases")
    assert upgraded.complete_v3_cold_boot_migration() == "v3_activity_after_stage"
    assert rows(path)[0] == 3


@pytest.mark.parametrize("table", ["leases", "pending"])
def test_active_or_pending_blocks_completion(tmp_path: Path, table: str) -> None:
    boot = Boot()
    path = tmp_path / "lease.sqlite3"
    _, upgraded = ledgers(path, boot)
    with sqlite3.connect(path) as conn:
        conn.execute("DELETE FROM leases")
    assert upgraded.stage_v3_cold_boot_migration() == "staged_for_cold_boot"
    with sqlite3.connect(path) as conn:
        if table == "leases":
            conn.execute(
                "INSERT INTO leases(lease_id,request_id,cpu,ram,vram,gpu,expires_at,state)"
                " VALUES('active','active',1,512,0,NULL,9999,'active')"
            )
        else:
            conn.execute(
                "INSERT INTO pending(request_id,cpu,ram,vram,gpu,expires_at)"
                " VALUES('waiting',1,512,0,NULL,9999)"
            )
    boot.monotonic, boot.boot_time = 10.0, 2000.0
    assert upgraded.complete_v3_cold_boot_migration() == "migration_requires_drain"
    assert rows(path)[0] == 3


def test_budget_mismatch_blocks_completion(tmp_path: Path) -> None:
    boot = Boot()
    path = tmp_path / "lease.sqlite3"
    _, upgraded = ledgers(path, boot)
    with sqlite3.connect(path) as conn:
        conn.execute("DELETE FROM leases")
    assert upgraded.stage_v3_cold_boot_migration() == "staged_for_cold_boot"
    other = TreeHostInferenceLeaseLedger(
        path, LeaseBudget(2, 1024, 2048, 0), boot_time=lambda: 2000.0, clock=lambda: 10.0
    )
    assert other.complete_v3_cold_boot_migration() == "budget_mismatch"
    assert rows(path)[0] == 3


def test_explicit_source_to_target_budget_migrates_atomically(tmp_path: Path) -> None:
    boot = Boot()
    path = tmp_path / "lease.sqlite3"
    source = LeaseBudget(1, 1024, 2_684_354_560, 0)  # 2.5 GiB Laya reservation
    target = LeaseBudget(2, 4096, 21_474_836_480, 0)  # 20 GiB shared reservation
    _, old_budget_reader = ledgers(path, boot, source)
    with sqlite3.connect(path) as conn:
        conn.execute("DELETE FROM leases")
        conn.execute("INSERT INTO lease_reclaims VALUES('historical',1234,1.0,100.0)")
        old_hash = conn.execute("SELECT value FROM meta WHERE key='budget_hash'").fetchone()[0]
    upgraded = TreeHostInferenceLeaseLedger(
        path, target, clock=lambda: boot.monotonic, boot_time=lambda: boot.boot_time
    )
    assert upgraded.stage_v3_cold_boot_migration() == "budget_mismatch"
    assert upgraded.stage_v3_cold_boot_migration(source_budget=source) == "staged_for_cold_boot"
    boot.monotonic, boot.boot_time = 10.0, 2000.0
    assert upgraded.complete_v3_cold_boot_migration(source_budget=source) == "migrated"
    with sqlite3.connect(path) as conn:
        new_hash = conn.execute("SELECT value FROM meta WHERE key='budget_hash'").fetchone()[0]
        assert conn.execute("PRAGMA user_version").fetchone()[0] == 4
        assert conn.execute("SELECT count(*) FROM lease_reclaims").fetchone()[0] == 1
    assert new_hash != old_hash
    worker = WorkerIdentity(os.getpid(), psutil.Process().create_time())
    assert (
        old_budget_reader.try_acquire("old_v4", LeaseDemand(1, 512), worker_identity=worker).reason
        == "budget_mismatch"
    )
    assert (
        upgraded.try_acquire("new_v4", LeaseDemand(1, 512), worker_identity=worker).status
        == "acquired"
    )
    legacy = HostInferenceLeaseLedger(path, source, boot_id="2000")
    assert legacy.try_acquire("old_v3", LeaseDemand(1, 512)).reason == "store_unavailable"


def test_source_budget_mismatch_refuses_stage_and_completion(tmp_path: Path) -> None:
    boot = Boot()
    path = tmp_path / "lease.sqlite3"
    source = LeaseBudget(1, 1024, 2048, 0)
    wrong_source = LeaseBudget(1, 1024, 4096, 0)
    target = LeaseBudget(2, 4096, 24576, 0)
    ledgers(path, boot, source)
    with sqlite3.connect(path) as conn:
        conn.execute("DELETE FROM leases")
    upgraded = TreeHostInferenceLeaseLedger(
        path, target, clock=lambda: boot.monotonic, boot_time=lambda: boot.boot_time
    )
    assert upgraded.stage_v3_cold_boot_migration(source_budget=wrong_source) == "budget_mismatch"
    assert upgraded.stage_v3_cold_boot_migration(source_budget=source) == "staged_for_cold_boot"
    boot.monotonic, boot.boot_time = 10.0, 2000.0
    assert upgraded.complete_v3_cold_boot_migration(source_budget=wrong_source) == "budget_mismatch"
    assert rows(path)[0] == 3


def test_changed_target_budget_refuses_completion(tmp_path: Path) -> None:
    boot = Boot()
    path = tmp_path / "lease.sqlite3"
    source = LeaseBudget(1, 1024, 2048, 0)
    target = LeaseBudget(2, 4096, 24576, 0)
    changed_target = LeaseBudget(3, 4096, 24576, 0)
    ledgers(path, boot, source)
    with sqlite3.connect(path) as conn:
        conn.execute("DELETE FROM leases")
    staged = TreeHostInferenceLeaseLedger(
        path, target, clock=lambda: boot.monotonic, boot_time=lambda: boot.boot_time
    )
    assert staged.stage_v3_cold_boot_migration(source_budget=source) == "staged_for_cold_boot"
    boot.monotonic, boot.boot_time = 10.0, 2000.0
    changed = TreeHostInferenceLeaseLedger(
        path, changed_target, clock=lambda: boot.monotonic, boot_time=lambda: boot.boot_time
    )
    assert changed.complete_v3_cold_boot_migration(source_budget=source) == "budget_mismatch"
    assert rows(path)[0] == 3


@pytest.mark.parametrize("table", ["leases", "pending", "lease_reclaims", "meta"])
def test_transient_v3_table_write_blocks_completion(tmp_path: Path, table: str) -> None:
    boot = Boot()
    path = tmp_path / "lease.sqlite3"
    _, upgraded = ledgers(path, boot)
    with sqlite3.connect(path) as conn:
        conn.execute("DELETE FROM leases")
    assert upgraded.stage_v3_cold_boot_migration() == "staged_for_cold_boot"
    with sqlite3.connect(path) as conn:
        if table == "leases":
            conn.execute(
                "INSERT INTO leases(lease_id,request_id,cpu,ram,vram,gpu,expires_at,state)"
                " VALUES('transient','transient',1,512,0,NULL,9999,'active')"
            )
            conn.execute("DELETE FROM leases WHERE lease_id='transient'")
        elif table == "pending":
            conn.execute(
                "INSERT INTO pending(request_id,cpu,ram,vram,gpu,expires_at)"
                " VALUES('transient',1,512,0,NULL,9999)"
            )
            conn.execute("DELETE FROM pending WHERE request_id='transient'")
        elif table == "lease_reclaims":
            conn.execute("INSERT INTO lease_reclaims VALUES('transient',1234,1.0,100.0)")
            conn.execute("DELETE FROM lease_reclaims WHERE lease_id='transient'")
        else:
            conn.execute("DELETE FROM meta WHERE key='boot_id'")
            conn.execute("INSERT INTO meta VALUES('boot_id','1000')")
    boot.monotonic, boot.boot_time = 10.0, 2000.0
    assert upgraded.complete_v3_cold_boot_migration() == "v3_activity_after_stage"
    assert rows(path)[0] == 3


def test_missing_witness_trigger_blocks_completion(tmp_path: Path) -> None:
    boot = Boot()
    path = tmp_path / "lease.sqlite3"
    _, upgraded = ledgers(path, boot)
    with sqlite3.connect(path) as conn:
        conn.execute("DELETE FROM leases")
    assert upgraded.stage_v3_cold_boot_migration() == "staged_for_cold_boot"
    with sqlite3.connect(path) as conn:
        conn.execute("DROP TRIGGER v4_migration_watch_leases_insert")
    boot.monotonic, boot.boot_time = 10.0, 2000.0
    assert upgraded.complete_v3_cold_boot_migration() == "v3_activity_after_stage"
    assert rows(path)[0] == 3


@pytest.mark.parametrize("marker", [None, "bad-json", "{}"])
def test_missing_or_corrupt_marker_blocks_completion(tmp_path: Path, marker: str | None) -> None:
    boot = Boot()
    path = tmp_path / "lease.sqlite3"
    _, upgraded = ledgers(path, boot)
    with sqlite3.connect(path) as conn:
        conn.execute("DELETE FROM leases")
    if marker is not None:
        assert upgraded.stage_v3_cold_boot_migration() == "staged_for_cold_boot"
        with sqlite3.connect(path) as conn:
            conn.execute("UPDATE meta SET value=? WHERE key='v4_cold_boot_migration'", (marker,))
    boot.monotonic, boot.boot_time = 10.0, 2000.0
    assert upgraded.complete_v3_cold_boot_migration() != "migrated"
    assert rows(path)[0] == 3
