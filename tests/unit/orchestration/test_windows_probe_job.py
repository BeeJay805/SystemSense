import subprocess
import sys

import pytest
import win32con
import win32job

from systemsense.orchestration.windows_probe_job import WindowsProbeJob


def test_job_reports_empty_while_handle_is_open() -> None:
    job = WindowsProbeJob()
    try:
        assert job.wait_until_empty(0)
    finally:
        job.close()


def test_job_waits_for_assigned_worker_exit() -> None:
    job = WindowsProbeJob()
    worker = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(0.5)"],
        creationflags=win32con.CREATE_SUSPENDED,
    )
    try:
        assert not job.is_assigned_worker(worker)
        job.assign_suspended(worker)
        assert job.is_assigned_worker(worker)
        assert not job.wait_until_empty(0)
        job.resume_assigned(worker)
        assert job.wait_until_empty(3)
        worker.wait(timeout=1)
    finally:
        job.close()
        if worker.poll() is None:
            worker.kill()
        worker.wait(timeout=3)


def test_job_does_not_report_empty_when_worker_child_survives() -> None:
    job = WindowsProbeJob()
    worker = subprocess.Popen(
        [
            sys.executable,
            "-c",
            "import subprocess, sys; "
            "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(0.8)'])",
        ],
        creationflags=win32con.CREATE_SUSPENDED,
    )
    try:
        job.assign_suspended(worker)
        job.resume_assigned(worker)
        worker.wait(timeout=3)
        assert not job.wait_until_empty(0)
        assert job.wait_until_empty(3)
    finally:
        job.close()
        if worker.poll() is None:
            worker.kill()
        worker.wait(timeout=3)


def test_job_rejects_second_resume() -> None:
    job = WindowsProbeJob()
    worker = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(0.2)"],
        creationflags=win32con.CREATE_SUSPENDED,
    )
    try:
        job.assign_suspended(worker)
        job.resume_assigned(worker)
        with pytest.raises(RuntimeError, match="not assigned"):
            job.resume_assigned(worker)
    finally:
        job.close()
        worker.wait(timeout=3)


def test_job_termination_can_be_verified_before_handle_closes() -> None:
    job = WindowsProbeJob()
    worker = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        creationflags=win32con.CREATE_SUSPENDED,
    )
    try:
        job.assign_suspended(worker)
        job.resume_assigned(worker)
        assert not job.wait_until_empty(0)
        job.terminate_processes()
        assert job.wait_until_empty(3)
        worker.wait(timeout=1)
    finally:
        job.close()
        if worker.poll() is None:
            worker.kill()
        worker.wait(timeout=3)


def test_job_query_failure_does_not_report_empty(monkeypatch: pytest.MonkeyPatch) -> None:
    job = WindowsProbeJob()
    try:

        def deny_query(*_args: object) -> None:
            raise PermissionError("denied")

        monkeypatch.setattr(win32job, "QueryInformationJobObject", deny_query)
        with pytest.raises(PermissionError, match="denied"):
            job.wait_until_empty(0)
    finally:
        job.close()


def test_job_rejects_query_after_close() -> None:
    job = WindowsProbeJob()
    job.close()
    with pytest.raises(RuntimeError, match="closed"):
        job.wait_until_empty(0)


def test_job_rejects_unbounded_wait() -> None:
    job = WindowsProbeJob()
    try:
        with pytest.raises(ValueError, match="0 to 5"):
            job.wait_until_empty(6)
    finally:
        job.close()
