"""Durable capacity is released only after the exact Windows Job tree exits."""

import subprocess
import sys
from pathlib import Path

import pytest
import win32con

from systemsense.orchestration.probe_capacity_custody import ProbeCapacityCustody
from systemsense.orchestration.probe_capacity_ledger import (
    DurableProbeLedger,
    LedgerBudget,
)
from systemsense.orchestration.windows_probe_job import WindowsProbeJob


def _ledger(tmp_path: Path) -> DurableProbeLedger:
    return DurableProbeLedger(
        tmp_path / "probe-capacity.sqlite3",
        LedgerBudget(global_limit=1, per_resource={"cpu": 1}),
        "test-registered-probes-v1",
    )


def _custody(ledger: DurableProbeLedger) -> ProbeCapacityCustody:
    ticket = ledger.enqueue("case-one", "probe-one", "cpu", 0)
    reservation = ledger.try_reserve(ticket)
    assert reservation is not None
    return ProbeCapacityCustody(ledger, reservation)


def _second_can_reserve(ledger: DurableProbeLedger) -> bool:
    ticket = ledger.enqueue("case-two", "probe-two", "cpu", 0)
    return ledger.try_reserve(ticket) is not None


def test_prelaunch_release_frees_durable_capacity(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    custody = _custody(ledger)

    assert custody.release_or_quarantine()
    assert _second_can_reserve(ledger)


def test_launch_intent_without_exit_proof_quarantines_capacity(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    custody = _custody(ledger)

    custody.record_launch_intent()

    assert not custody.release_or_quarantine()
    assert not _second_can_reserve(ledger)


def test_exact_job_exit_proof_releases_durable_capacity(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    custody = _custody(ledger)
    job = WindowsProbeJob()
    custody.record_launch_intent()
    worker = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(0.1)"],
        creationflags=win32con.CREATE_SUSPENDED,
    )
    try:
        custody.bind_suspended_worker(worker)
        job.assign_suspended(worker)
        custody.confirm_job_assignment()
        job.resume_assigned(worker)
        custody.confirm_resume()
        worker.wait(timeout=3)
        assert job.wait_until_empty(2)
        custody.record_tree_exit_proof(job, worker)
        assert custody.release_or_quarantine()
        assert _second_can_reserve(ledger)
    finally:
        job.close()
        if worker.poll() is None:
            worker.kill()
        worker.wait(timeout=3)


def test_other_job_cannot_prove_this_worker_exit(tmp_path: Path) -> None:
    ledger = _ledger(tmp_path)
    custody = _custody(ledger)
    job = WindowsProbeJob()
    wrong_job = WindowsProbeJob()
    custody.record_launch_intent()
    worker = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(0.1)"],
        creationflags=win32con.CREATE_SUSPENDED,
    )
    try:
        custody.bind_suspended_worker(worker)
        job.assign_suspended(worker)
        custody.confirm_job_assignment()
        job.resume_assigned(worker)
        custody.confirm_resume()
        worker.wait(timeout=3)
        assert job.wait_until_empty(2)
        with pytest.raises(Exception, match=r"unproved|custody|assigned"):
            custody.record_tree_exit_proof(wrong_job, worker)
        assert not custody.release_or_quarantine()
        assert not _second_can_reserve(ledger)
    finally:
        wrong_job.close()
        job.close()
        if worker.poll() is None:
            worker.kill()
        worker.wait(timeout=3)
