"""A named Windows Job is an independent exit witness after owner loss."""

import subprocess
import sys
from uuid import uuid4

import win32con

from systemsense.orchestration.probe_capacity_ledger import WorkerIdentity
from systemsense.orchestration.probe_capacity_recovery import (
    current_process_identity,
    live_process_identity,
    prove_orphaned_job_exited,
)
from systemsense.orchestration.windows_probe_job import WindowsProbeJob


def test_named_job_recovery_requires_dead_owner_and_empty_worker_tree() -> None:
    name = f"Local\\SystemSenseProbeV1-{uuid4().hex}"
    job = WindowsProbeJob(name=name)
    worker = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(2)"],
        creationflags=win32con.CREATE_SUSPENDED,
    )
    try:
        worker_identity = live_process_identity(worker.pid)
        assert worker_identity is not None
        owner = current_process_identity()
        job.assign_suspended(worker)
        job.resume_assigned(worker)
        assert not prove_orphaned_job_exited(name, worker_identity, owner)
        absent_owner = WorkerIdentity(owner.pid, owner.creation_time_ns + 100)
        assert not prove_orphaned_job_exited(name, worker_identity, absent_owner)
        worker.wait(timeout=5)
        assert job.wait_until_empty(2)
        assert prove_orphaned_job_exited(name, worker_identity, absent_owner)
    finally:
        job.close()
        if worker.poll() is None:
            worker.kill()
        worker.wait(timeout=5)
