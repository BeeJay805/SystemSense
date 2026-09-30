from __future__ import annotations

import hashlib
import io
import json
import subprocess
import tarfile
import tempfile
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast
from unittest.mock import patch

import pytest

from systemsense.application import laya_provisioning as PROVISIONING


class FakeProcess(subprocess.Popen[bytes]):
    pid = 100
    returncode: int | None = None
    stdout: Any = None

    def __init__(self) -> None:
        self.running = True
        self.terminated = False
        self.wait_calls = 0

    def poll(self) -> int | None:
        return None if self.running else 0

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        self.wait_calls += 1
        self.running = False
        self.returncode = 0
        return 0

    def terminate(self) -> None:
        self.terminated = True
        self.running = False


class FakeJob:
    def __init__(
        self,
        *,
        assignment_error: BaseException | None = None,
        drains: bool = True,
    ) -> None:
        self.assignment_error = assignment_error
        self.drains = drains
        self.worker: subprocess.Popen[bytes] | None = None
        self.terminated = False
        self.closed = False
        self.resumed = False
        self.waited = False

    def assign_suspended(self, worker: subprocess.Popen[bytes]) -> None:
        if self.assignment_error is not None:
            raise self.assignment_error
        self.worker = worker

    def resume_assigned(self, worker: subprocess.Popen[bytes]) -> None:
        del worker
        self.resumed = True

    def is_assigned_worker(self, worker: subprocess.Popen[bytes]) -> bool:
        return self.worker is worker

    def terminate_processes(self) -> None:
        self.terminated = True
        if self.worker is not None:
            self.worker.terminate()

    def wait_until_empty(self, timeout_seconds: float) -> bool:
        del timeout_seconds
        self.waited = True
        return self.drains

    def close(self) -> None:
        self.closed = True


class KeyboardInterruptWithCleanup(KeyboardInterrupt):
    def __init__(self) -> None:
        super().__init__()
        self.cleanup_error = OSError(6, "thread handle close failed")


class ControllerFixture:
    def __init__(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        self.resources = self.root / "resources"
        self.exe = self.resources / "investigator" / "investigator.exe"
        self.exe.parent.mkdir(parents=True)
        self.exe.write_bytes(b"test app")
        archive = self.resources / PROVISIONING.PYTHON_ARCHIVE_RELATIVE
        archive.parent.mkdir(parents=True)
        with tarfile.open(archive, "w:gz") as stream:
            payload = b"synthetic python"
            item = tarfile.TarInfo("python/python.exe")
            item.size = len(payload)
            stream.addfile(item, io.BytesIO(payload))
        script = self.resources / PROVISIONING.INSTALLER_RELATIVE
        script.parent.mkdir(parents=True, exist_ok=True)
        script.write_text("# test", encoding="utf-8")
        self.local = self.root / "LocalAppData"
        self.local.mkdir()
        self.system_directory = self.root / "Windows" / "System32"
        powershell = self.system_directory / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        powershell.parent.mkdir(parents=True)
        powershell.write_bytes(b"fake powershell")
        self.context = PROVISIONING.ProvisioningContext(self.exe, self.local)
        self.hash_patch = patch.object(
            PROVISIONING,
            "BUNDLED_PYTHON_ARCHIVE_SHA256",
            hashlib.sha256(archive.read_bytes()).hexdigest(),
        )
        self.hash_patch.start()

    def close(self) -> None:
        self.hash_patch.stop()
        self.tmp.cleanup()

    def controller(
        self, process: FakeProcess, job: FakeJob
    ) -> tuple[Any, SimpleNamespace, SimpleNamespace]:
        def launch(*_args: Any, **_kwargs: Any) -> subprocess.Popen[bytes]:
            return cast(subprocess.Popen[bytes], process)

        controller = PROVISIONING.LayaSetupController(
            self.context,
            process_factory=launch,
            job_factory=lambda _name: job,
            python_probe=lambda _path: True,
            system_directory_provider=lambda: self.system_directory,
        )
        owner = SimpleNamespace(pid=1, creation_time_ns=1)
        worker = SimpleNamespace(pid=100, creation_time_ns=100)
        return controller, owner, worker


def start_controller(controller: Any, owner: SimpleNamespace, worker: SimpleNamespace) -> None:
    with (
        patch.object(
            PROVISIONING,
            "_current_owner_identity",
            return_value=owner,
        ),
        patch.object(
            PROVISIONING,
            "_live_worker_identity",
            return_value=worker,
        ),
    ):
        controller.start()
        assert controller._worker is not None
        controller._worker.join(5)
        assert not controller._worker.is_alive()


def run_controller_synchronously(
    controller: Any, owner: SimpleNamespace, worker: SimpleNamespace
) -> None:
    with (
        patch.object(PROVISIONING, "_current_owner_identity", return_value=owner),
        patch.object(PROVISIONING, "_live_worker_identity", return_value=worker),
    ):
        assert controller.status()["can_install"] is True
        controller._run()


def only_failure_record(fixture: ControllerFixture) -> tuple[Path, dict[str, Any]]:
    transaction_dir = fixture.local / "SystemSense" / "setup-transactions"
    records = list(transaction_dir.glob("*.failure.log"))
    assert len(records) == 1
    path = records[0]
    return path, cast(dict[str, Any], json.loads(path.read_text(encoding="utf-8")))


def test_actual_controller_assignment_failure_records_stage_and_stops_worker():
    fixture = ControllerFixture()
    try:
        process = FakeProcess()
        error = RuntimeError("do not persist this secret detail")
        error.stage = "job_assign_process"  # type: ignore[attr-defined]
        error.winerror = 5  # type: ignore[attr-defined]
        job = FakeJob(assignment_error=error)
        controller, owner, worker = fixture.controller(process, job)
        start_controller(controller, owner, worker)
        diagnostic_path, record = only_failure_record(fixture)
        assert record["primary"]["stage"] == "job_assign_process"
        assert record["primary"]["winerror"] == 5
        assert record["cleanup"]["child_exit_observed"] is True
        assert record["cleanup"]["job_empty"] is True
        assert record["cleanup"]["job_closed"] is True
        assert isinstance(record["recorded_at"], str)
        assert process.terminated and process.wait_calls == 1
        assert not job.resumed and job.waited and job.closed
        assert controller.status()["state"] == "failed"
        assert controller.status()["can_install"] is True
        assert "secret" not in diagnostic_path.read_text(encoding="utf-8")
    finally:
        fixture.close()


def test_actual_controller_assigned_receipt_write_failure_records_write_stage():
    fixture = ControllerFixture()
    try:
        process = FakeProcess()
        job = FakeJob()
        controller, owner, worker = fixture.controller(process, job)
        atomic_json_attribute = "_atomic_json"
        original_atomic_json = getattr(PROVISIONING, atomic_json_attribute)

        def fail_worker_assigned_receipt(path: Path, data: dict[str, Any]) -> None:
            if data.get("phase") == "worker_assigned":
                error = OSError(5, "do not persist private path")
                error.winerror = 5  # type: ignore[attr-defined]
                raise error
            original_atomic_json(path, data)

        with patch.object(PROVISIONING, "_atomic_json", fail_worker_assigned_receipt):
            start_controller(controller, owner, worker)
        diagnostic_path, record = only_failure_record(fixture)
        assert record["primary"]["stage"] == "worker_assigned_receipt_write"
        assert record["primary"]["winerror"] == 5
        assert isinstance(record["recorded_at"], str)
        assert process.terminated and process.wait_calls == 1
        assert job.terminated and job.waited and job.closed
        assert not job.resumed
        assert controller.status()["state"] == "failed"
        assert controller.status()["can_install"] is True
        assert "private path" not in diagnostic_path.read_text(encoding="utf-8")
    finally:
        fixture.close()


def test_actual_controller_cleanup_uncertainty_preserves_failure_and_blocks_retry():
    fixture = ControllerFixture()
    try:
        process = FakeProcess()
        error = RuntimeError("assignment detail")
        error.stage = "job_assign_process"  # type: ignore[attr-defined]
        job = FakeJob(assignment_error=error, drains=False)
        controller, owner, worker = fixture.controller(process, job)
        start_controller(controller, owner, worker)
        _diagnostic_path, record = only_failure_record(fixture)
        assert record["primary"]["stage"] == "job_assign_process"
        assert record["cleanup"]["uncertain"] is True
        assert record["cleanup"]["job_empty"] is False
        assert isinstance(record["recorded_at"], str)
        assert process.terminated and process.wait_calls == 1
        assert not job.closed and not job.resumed
        assert controller.status()["state"] == "cleanup_pending"
        assert controller.status()["can_install"] is False
    finally:
        fixture.close()


class BlockingOutputStream:
    def __init__(self) -> None:
        self.release = threading.Event()

    def read(self, _size: int) -> bytes:
        self.release.wait()
        return b""


def test_actual_controller_reader_thread_uncertainty_blocks_terminal_failure():
    fixture = ControllerFixture()
    stream = BlockingOutputStream()
    capture_threads: list[threading.Thread] = []
    original_thread = PROVISIONING.threading.Thread
    original_join = threading.Thread.join

    def thread_factory(*args: Any, **kwargs: Any) -> threading.Thread:
        thread = original_thread(*args, **kwargs)
        if kwargs.get("name") == "laya-setup-output":
            capture_threads.append(thread)
        return thread

    def bounded_join(thread: threading.Thread, timeout: float | None = None) -> None:
        if thread.name == "laya-setup-output":
            return None
        return original_join(thread, timeout)

    try:
        process = FakeProcess()
        process.stdout = stream
        error = RuntimeError("assignment failure")
        error.stage = "job_assign_process"  # type: ignore[attr-defined]
        job = FakeJob(assignment_error=error)
        controller, owner, worker = fixture.controller(process, job)
        with (
            patch.object(PROVISIONING.threading, "Thread", thread_factory),
            patch.object(original_thread, "join", bounded_join),
        ):
            start_controller(controller, owner, worker)
        _diagnostic_path, record = only_failure_record(fixture)
        assert record["primary"]["stage"] == "job_assign_process"
        assert record["cleanup"]["job_empty"] is True
        assert record["cleanup"]["job_closed"] is True
        assert record["cleanup"]["output_reader_stopped"] is False
        assert record["cleanup"]["uncertain"] is True
        assert controller.status()["state"] == "cleanup_pending"
        assert controller.status()["can_install"] is False
        assert len(capture_threads) == 1
    finally:
        stream.release.set()
        if capture_threads:
            original_join(capture_threads[0], 2.0)
            assert not capture_threads[0].is_alive()
        fixture.close()


def test_actual_controller_keyboard_interrupt_is_drained_recorded_then_reraised():
    fixture = ControllerFixture()
    try:
        process = FakeProcess()
        error = KeyboardInterruptWithCleanup()
        job = FakeJob(assignment_error=error)
        controller, owner, worker = fixture.controller(process, job)
        with pytest.raises(KeyboardInterrupt) as captured:
            run_controller_synchronously(controller, owner, worker)

        diagnostic_path, record = only_failure_record(fixture)
        assert captured.value is error
        assert record["primary"]["exception_type"] == "KeyboardInterruptWithCleanup"
        assert record["primary"]["stage"] == "worker_job_assignment"
        assert record["cleanup"]["child_exit_observed"] is True
        assert record["cleanup"]["job_empty"] is True
        assert record["cleanup"]["job_closed"] is True
        assert record["cleanup"]["uncertain"] is True
        assert record["cleanup"]["assignment_thread_handle"] == {
            "stage": "worker_thread_close",
            "exception_type": "OSError",
            "winerror": None,
            "errno": 6,
        }
        assert process.terminated and process.wait_calls == 1
        assert job.waited and job.closed and not job.resumed
        assert controller.status()["state"] == "failed"
        assert controller.status()["can_install"] is True
        assert diagnostic_path.exists()
    finally:
        fixture.close()


def test_actual_controller_keyboard_interrupt_with_uncertain_drain_stays_pending():
    fixture = ControllerFixture()
    try:
        process = FakeProcess()
        job = FakeJob(assignment_error=KeyboardInterrupt(), drains=False)
        controller, owner, worker = fixture.controller(process, job)
        with pytest.raises(KeyboardInterrupt):
            run_controller_synchronously(controller, owner, worker)

        _diagnostic_path, record = only_failure_record(fixture)
        assert record["primary"]["exception_type"] == "KeyboardInterrupt"
        assert record["cleanup"]["child_exit_observed"] is True
        assert record["cleanup"]["job_empty"] is False
        assert record["cleanup"]["job_closed"] is False
        assert record["cleanup"]["uncertain"] is True
        assert process.terminated and process.wait_calls == 1
        assert not job.closed
        assert controller.status()["state"] == "cleanup_pending"
        assert controller.status()["can_install"] is False
        assert controller._active_plan is not None
        assert controller._active_plan.receipt.exists()
        assert controller._active_plan.runtime_root.exists()
    finally:
        fixture.close()


def test_actual_controller_does_not_rollback_before_durable_failure_record():
    fixture = ControllerFixture()
    try:
        process = FakeProcess()
        job = FakeJob(assignment_error=KeyboardInterrupt())
        controller, owner, worker = fixture.controller(process, job)
        with (
            patch.object(
                PROVISIONING,
                "write_failure_record",
                side_effect=OSError("diagnostic storage failed"),
            ),
            pytest.raises(KeyboardInterrupt),
        ):
            run_controller_synchronously(controller, owner, worker)

        assert process.terminated and job.closed
        assert controller._snapshot.state == "cleanup_pending"
        assert controller._snapshot.reason_code == "failure_diagnostics_not_persisted"
        assert controller.status()["can_install"] is False
        assert controller._active_plan is not None
        assert controller._active_plan.receipt.exists()
        assert controller._active_plan.runtime_root.exists()
        assert (
            list((fixture.local / "SystemSense" / "setup-transactions").glob("*.failure.log")) == []
        )
    finally:
        fixture.close()
