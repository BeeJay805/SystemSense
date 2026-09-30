from __future__ import annotations

import hashlib
import io
import subprocess
import tarfile
import tempfile
import threading
import unittest
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

from systemsense.application import laya_provisioning as provisioning

# Narrow white-box regressions for transaction cleanup and Popen custody.
# pyright: reportPrivateUsage=false


class _Process(subprocess.Popen[bytes]):
    pid = 100
    returncode = 1

    def __init__(self, *, stdout: Any = None, running: bool = False):
        self.stdout = stdout
        self.running = running
        self.terminated = False

    def poll(self) -> int | None:
        return None if self.running else self.returncode

    def wait(self, timeout: float | None = None) -> int:
        self.running = False
        return self.returncode

    def terminate(self) -> None:
        self.terminated = True
        self.running = False


class _Job:
    def __init__(self) -> None:
        self.closed = False
        self.terminated = False

    def assign_suspended(self, worker: subprocess.Popen[bytes]) -> None:
        pass

    def resume_assigned(self, worker: subprocess.Popen[bytes]) -> None:
        pass

    def is_assigned_worker(self, worker: subprocess.Popen[bytes]) -> bool:
        return False

    def wait_until_empty(self, timeout_seconds: float) -> bool:
        return True

    def terminate_processes(self) -> None:
        self.terminated = True

    def close(self) -> None:
        self.closed = True


class LayaSetupCleanupRegressions(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.resources = self.root / "resources"
        self.exe = self.resources / "investigator" / "investigator.exe"
        self.exe.parent.mkdir(parents=True)
        self.exe.write_bytes(b"fixture")
        self.archive = self.resources / provisioning.PYTHON_ARCHIVE_RELATIVE
        self.archive.parent.mkdir(parents=True)
        with tarfile.open(self.archive, "w:gz") as archive:
            payload = b"python fixture"
            item = tarfile.TarInfo("python/python.exe")
            item.size = len(payload)
            archive.addfile(item, io.BytesIO(payload))
        installer = self.resources / provisioning.INSTALLER_RELATIVE
        installer.parent.mkdir(parents=True, exist_ok=True)
        installer.write_text("# fixture", encoding="utf-8")
        self.local = self.root / "LocalAppData"
        self.local.mkdir()
        self.system_directory = self.root / "Windows" / "System32"
        powershell = self.system_directory / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        powershell.parent.mkdir(parents=True)
        powershell.write_bytes(b"fixture")
        self.context = provisioning.ProvisioningContext(self.exe, self.local)
        self.hash_patch = patch.object(
            provisioning,
            "BUNDLED_PYTHON_ARCHIVE_SHA256",
            hashlib.sha256(self.archive.read_bytes()).hexdigest(),
        )
        self.hash_patch.start()
        self.addCleanup(self.hash_patch.stop)

    def _controller(self, **kwargs: Any) -> provisioning.LayaSetupController:
        return provisioning.LayaSetupController(
            self.context,
            system_directory_provider=lambda: self.system_directory,
            python_probe=lambda path: True,
            **kwargs,
        )

    def _write_marker(self, path: Path, attempt: str) -> None:
        provisioning._write_json_new(
            path / provisioning._OWNER_FILE,
            {"attempt_id": attempt, "kind": "foreign-owner"},
        )

    def _always_valid(self, path: Path) -> bool:
        del path
        return True

    def _never_valid(self, path: Path) -> bool:
        del path
        return False

    def test_rollback_retains_receipt_when_existing_stage_marker_does_not_match(self) -> None:
        controller = self._controller()
        self.assertEqual(controller.status()["state"], "ready_to_install")
        plan = controller._active_plan
        assert plan is not None
        plan.receipt.parent.mkdir(parents=True)
        provisioning._write_json_new(plan.receipt, {"attempt_id": plan.attempt_id})
        plan.stage_root.parent.mkdir(parents=True)
        plan.stage_root.mkdir()
        self._write_marker(plan.stage_root, "not-the-current-attempt")

        with self.assertRaises(provisioning.ProvisioningBlocked):
            controller._rollback(plan)

        self.assertTrue(plan.receipt.exists())
        self.assertTrue(plan.stage_root.exists())
        self.assertTrue((plan.stage_root / provisioning._OWNER_FILE).exists())

    def test_temp_cleanup_refuses_existing_root_without_matching_marker(self) -> None:
        controller = self._controller()
        self.assertEqual(controller.status()["state"], "ready_to_install")
        plan = controller._active_plan
        assert plan is not None
        plan.temp_root.mkdir(parents=True)
        self._write_marker(plan.temp_root, "not-the-current-attempt")

        with self.assertRaises(provisioning.ProvisioningBlocked):
            controller._remove_owned_temp(plan)

        self.assertTrue(plan.temp_root.exists())

    def test_valid_install_recovery_keeps_receipt_when_temp_marker_mismatches(self) -> None:
        controller = self._controller(install_validator=self._always_valid)
        self.assertEqual(controller.status()["state"], "ready_to_install")
        plan = controller._active_plan
        assert plan is not None
        attempt = "12345678-1234-1234-1234-123456789abc"
        receipt = plan.receipt.with_name(f"{attempt}.json")
        receipt.parent.mkdir(parents=True)
        provisioning._write_json_new(
            receipt,
            {
                "attempt_id": attempt,
                "job_name": provisioning._job_name(attempt),
                "lifetime_job_name": (
                    "Local\\SystemSense.LayaSetupOwner.12345678-1234-1234-1234-123456789abc"
                ),
                "phase": "complete",
            },
        )
        temp_root = plan.temp_root.with_name(attempt)
        temp_root.mkdir(parents=True)
        self._write_marker(temp_root, "not-the-current-attempt")
        plan.laya_root.mkdir(parents=True)

        with patch.object(provisioning, "_orphan_proven", return_value=True):
            recovered = controller._recover_receipt(receipt, self.local / "SystemSense")

        self.assertFalse(recovered)
        self.assertTrue(receipt.exists())
        self.assertTrue(temp_root.exists())
        self.assertTrue(plan.laya_root.exists())

    def _make_recovery_transaction(
        self, *, reuse_python: bool | None
    ) -> tuple[provisioning.LayaSetupController, Path, Path, Path, str]:
        controller = self._controller(install_validator=self._never_valid)
        self.assertEqual(controller.status()["state"], "ready_to_install")
        plan = controller._active_plan
        assert plan is not None
        attempt = "22345678-1234-1234-1234-123456789abc"
        receipt = plan.receipt.with_name(f"{attempt}.json")
        receipt.parent.mkdir(parents=True)
        data: dict[str, object] = {
            "attempt_id": attempt,
            "job_name": provisioning._job_name(attempt),
            "lifetime_job_name": (
                "Local\\SystemSense.LayaSetupOwner.22345678-1234-1234-1234-123456789abc"
            ),
            "phase": "laya_install",
        }
        if reuse_python is not None:
            data["reuse_python"] = reuse_python
        provisioning._write_json_new(receipt, data)
        runtime = self.local / "SystemSense" / provisioning.PYTHON_RUNTIME_RELATIVE
        runtime.mkdir(parents=True)
        (runtime / "python.exe").write_bytes(b"verified prior runtime")
        provisioning._write_json_new(
            runtime / provisioning._PYTHON_RECEIPT,
            {
                "version": provisioning.PYTHON_VERSION,
                "archive_sha256": provisioning.BUNDLED_PYTHON_ARCHIVE_SHA256,
                "source": provisioning.PYTHON_ARCHIVE_URL,
            },
        )
        laya = self.local / "SystemSense" / provisioning.LAYA_INSTALL_RELATIVE
        laya.mkdir(parents=True)
        provisioning._write_json_new(
            laya / provisioning._OWNER_FILE,
            {"attempt_id": attempt, "kind": "laya-install"},
        )
        return controller, receipt, runtime, laya, attempt

    def test_recovery_reuses_and_preserves_recorded_python_base(self) -> None:
        controller, receipt, runtime, laya, _attempt = self._make_recovery_transaction(
            reuse_python=True
        )
        with patch.object(provisioning, "_orphan_proven", return_value=True):
            recovered = controller._recover_receipt(receipt, self.local / "SystemSense")
        self.assertTrue(recovered)
        self.assertFalse(receipt.exists())
        self.assertFalse(laya.exists())
        self.assertTrue((runtime / "python.exe").exists())
        self.assertTrue((runtime / provisioning._PYTHON_RECEIPT).exists())

    def test_legacy_receipt_cannot_claim_or_delete_unmarked_python_base(self) -> None:
        controller, receipt, runtime, _laya, _attempt = self._make_recovery_transaction(
            reuse_python=None
        )
        with patch.object(provisioning, "_orphan_proven", return_value=True):
            recovered = controller._recover_receipt(receipt, self.local / "SystemSense")
        self.assertFalse(recovered)
        self.assertTrue(receipt.exists())
        self.assertTrue(runtime.exists())

    def test_capture_thread_start_failure_drains_exact_popen_before_rollback(self) -> None:
        process = _Process(stdout=io.BytesIO(b"synthetic output"), running=True)
        jobs: list[_Job] = []
        identity = type("Identity", (), {"pid": 100, "creation_time_ns": 100})()
        owner = type("Identity", (), {"pid": 1, "creation_time_ns": 1})()

        def make_process(*args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
            return cast(subprocess.Popen[bytes], process)

        def make_job(name: str) -> _Job:
            job = _Job()
            jobs.append(job)
            return job

        controller = self._controller(
            process_factory=make_process,
            job_factory=make_job,
        )
        self.assertEqual(controller.status()["state"], "ready_to_install")
        original_start = threading.Thread.start

        def fail_capture_thread(thread: threading.Thread) -> None:
            if thread.name == "laya-setup-output":
                raise RuntimeError("injected capture thread startup failure")
            original_start(thread)

        with (
            patch.object(provisioning, "_current_owner_identity", return_value=owner),
            patch.object(provisioning, "_live_worker_identity", return_value=identity),
            patch.object(threading.Thread, "start", fail_capture_thread),
        ):
            controller.start()
            assert controller._worker is not None
            controller._worker.join(3)

        self.assertFalse(controller._worker.is_alive())
        self.assertTrue(process.terminated)
        self.assertTrue(jobs[0].closed)
        self.assertEqual(controller._snapshot.state, "failed")
        tx = self.local / "SystemSense" / "setup-transactions"
        self.assertFalse(tx.exists() and list(tx.glob("*.json")))


if __name__ == "__main__":
    unittest.main()
