from __future__ import annotations

# White-box lifecycle failure injection needs private transaction boundaries.
# pyright: reportPrivateUsage=false
import hashlib
import io
import os
import subprocess
import tarfile
import tempfile
import unittest
from collections.abc import Callable
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

from systemsense.application import laya_provisioning as provisioning


class FakeProcess(subprocess.Popen[bytes]):
    pid = 100
    returncode = 0
    stdout = None

    def __init__(
        self,
        on_launch: Callable[[], None] | None = None,
        running_on_start: bool = False,
    ):
        self.running = running_on_start
        self.terminated = False
        if on_launch:
            on_launch()

    def poll(self) -> int | None:
        return None if self.running else 0

    def wait(self, timeout: float | None = None) -> int:
        self.running = False
        return 0

    def terminate(self) -> None:
        self.terminated = True
        self.running = False


class FakeJob:
    def __init__(self, drains: bool = True, assign_error: bool = False):
        self.drains = drains
        self.assign_error = assign_error
        self.terminated = False
        self.closed = False

    def assign_suspended(self, worker: subprocess.Popen[bytes]) -> None:
        if self.assign_error:
            raise RuntimeError("synthetic assignment failure")

    def resume_assigned(self, worker: subprocess.Popen[bytes]) -> None:
        pass

    def is_assigned_worker(self, worker: subprocess.Popen[bytes]) -> bool:
        return False

    def terminate_processes(self) -> None:
        self.terminated = True

    def wait_until_empty(self, timeout_seconds: float) -> bool:
        return self.drains

    def close(self) -> None:
        self.closed = True


class ProvisioningTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.resources = self.root / "resources"
        self.exe = self.resources / "investigator/investigator.exe"
        self.exe.parent.mkdir(parents=True)
        self.exe.write_bytes(b"test app")
        self.archive = self.resources / provisioning.PYTHON_ARCHIVE_RELATIVE
        self.archive.parent.mkdir(parents=True)
        with tarfile.open(self.archive, "w:gz") as tar:
            payload = b"synthetic-python"
            item = tarfile.TarInfo("python/python.exe")
            item.size = len(payload)
            tar.addfile(item, io.BytesIO(payload))
        self.script = self.resources / provisioning.INSTALLER_RELATIVE
        self.script.parent.mkdir(parents=True, exist_ok=True)
        self.script.write_text("# fixture", encoding="utf-8")
        self.local = self.root / "LocalAppData"
        self.local.mkdir()
        self.system_directory = self.root / "Windows/System32"
        powershell = self.system_directory / "WindowsPowerShell/v1.0/powershell.exe"
        powershell.parent.mkdir(parents=True)
        powershell.write_bytes(b"fake powershell")
        self.context = provisioning.ProvisioningContext(self.exe, self.local)
        self.hashpatch = patch.object(
            provisioning,
            "BUNDLED_PYTHON_ARCHIVE_SHA256",
            hashlib.sha256(self.archive.read_bytes()).hexdigest(),
        )
        self.hashpatch.start()
        self.addCleanup(self.hashpatch.stop)

    def _system_directory(self) -> Path:
        return self.system_directory

    def _always_valid(self, path: Path) -> bool:
        return True

    def _never_valid(self, path: Path) -> bool:
        return False

    def _owned_marker_valid(self, path: Path) -> bool:
        return (path / provisioning._OWNER_FILE).exists()

    def _python_file_exists(self, path: Path) -> bool:
        return path.is_file()

    def _python_always_true(self, path: Path) -> bool:
        return True

    def _process_factory(self, *args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
        return cast(subprocess.Popen[bytes], FakeProcess())

    def _job_factory(self, name: str) -> FakeJob:
        return FakeJob()

    def test_fixed_status_fields_and_readiness(self):
        controller = provisioning.LayaSetupController(self.context)
        snapshot = controller.status()
        self.assertEqual(
            set(snapshot),
            {"state", "stage", "reason_code", "can_install", "existing_install"},
        )
        self.assertEqual(snapshot["state"], "ready_to_install")
        self.assertTrue(snapshot["can_install"])

    def test_fixed_args_and_existing_valid_install_is_read_only(self):
        root = self.local / "SystemSense/runtimes/laya-0.3.5"
        root.mkdir(parents=True)
        marker = root / "keep.txt"
        marker.write_text("unchanged")
        controller = provisioning.LayaSetupController(
            self.context, install_validator=self._always_valid
        )
        self.assertEqual(controller.status()["state"], "installed")
        self.assertTrue(controller.status()["existing_install"])
        self.assertEqual(marker.read_text(), "unchanged")
        self.assertFalse(controller.start()["can_install"])

    def test_invalid_existing_root_is_never_overwritten(self):
        root = self.local / "SystemSense/runtimes/laya-0.3.5"
        root.mkdir(parents=True)
        marker = root / "keep.txt"
        marker.write_text("untouched")
        controller = provisioning.LayaSetupController(
            self.context, install_validator=self._never_valid
        )
        snap = controller.status()
        self.assertEqual(snap["reason_code"], "existing_install_unverified")
        self.assertEqual(marker.read_text(), "untouched")

    def test_synthetic_install_uses_job_and_cleans_receipt(self):
        jobs: list[FakeJob] = []

        def launched() -> None:
            plan = controller._active_plan
            assert plan is not None
            plan.laya_root.mkdir(parents=True)
            provisioning._write_json_new(
                plan.laya_root / provisioning._OWNER_FILE,
                {"attempt_id": plan.attempt_id, "kind": "laya-install"},
            )

        def launch_process(*args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
            return cast(subprocess.Popen[bytes], FakeProcess(launched))

        def make_job(name: str) -> FakeJob:
            jobs.append(FakeJob())
            return jobs[-1]

        controller = provisioning.LayaSetupController(
            self.context,
            process_factory=launch_process,
            job_factory=make_job,
            install_validator=self._owned_marker_valid,
            python_probe=self._python_file_exists,
            system_directory_provider=self._system_directory,
        )
        identity = type("Identity", (), {"pid": 1, "creation_time_ns": 1})()
        with (
            patch.object(provisioning, "_current_owner_identity", return_value=identity),
            patch.object(
                provisioning,
                "_live_worker_identity",
                return_value=type("Identity", (), {"pid": 100, "creation_time_ns": 100})(),
            ),
        ):
            self.assertEqual(controller.start()["state"], "installing")
            assert controller._worker is not None
            controller._worker.join(3)
        self.assertFalse(controller._worker.is_alive())
        snap = controller._snapshot.to_dict()
        self.assertEqual(snap["state"], "installed", snap)
        self.assertFalse(snap["existing_install"])
        self.assertTrue(jobs[0].closed)
        self.assertEqual(list((self.local / "SystemSense/setup-transactions").glob("*.json")), [])

    def test_installer_environment_is_fixed_and_output_capture_is_bounded(self):
        jobs: list[FakeJob] = []
        captured_env: dict[str, str] = {}
        captured_cwd: list[str] = []

        def launch_process(*args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
            captured_env.update(kwargs["env"])
            captured_cwd.append(str(kwargs.get("cwd")))
            return cast(subprocess.Popen[bytes], FakeProcess())

        def make_job(name: str) -> FakeJob:
            del name
            jobs.append(FakeJob())
            return jobs[-1]

        controller = provisioning.LayaSetupController(
            self.context,
            process_factory=launch_process,
            job_factory=make_job,
            install_validator=self._never_valid,
            python_probe=self._python_always_true,
            system_directory_provider=self._system_directory,
        )
        owner = type("Identity", (), {"pid": 1, "creation_time_ns": 1})()
        worker = type("Identity", (), {"pid": 100, "creation_time_ns": 100})()
        with (
            patch.dict(
                os.environ,
                {
                    "HF_TOKEN": "must-not-inherit",
                    "USERPROFILE": "must-not-inherit",
                    "PIP_CONFIG_FILE": "must-not-inherit",
                },
            ),
            patch.object(provisioning, "_current_owner_identity", return_value=owner),
            patch.object(provisioning, "_live_worker_identity", return_value=worker),
        ):
            controller.start()
            assert controller._worker is not None
            controller._worker.join(3)
        self.assertNotIn("HF_TOKEN", captured_env)
        self.assertNotIn("USERPROFILE", captured_env)
        self.assertNotIn("PATH", captured_env)
        self.assertEqual(captured_env.get("PATHEXT"), ".EXE")
        self.assertEqual(captured_env.get("SystemDrive"), self.system_directory.drive)
        self.assertEqual(captured_cwd, [captured_env["TEMP"]])
        self.assertEqual(Path(captured_cwd[0]).parent, self.local / "SystemSense/setup-temp")
        self.assertEqual(captured_env["PIP_CONFIG_FILE"], os.devnull)
        self.assertEqual(captured_env["PIP_INDEX_URL"], "https://pypi.org/simple")
        sample = io.BytesIO(b"x" * (600 * 1024))
        capture = bytearray()
        provisioning._capture_bounded_output(sample, capture)
        self.assertEqual(len(capture), 512 * 1024)

    def test_python_archive_path_traversal_rejected_and_owned_stage_removed(self):
        evil = self.resources / "evil.tar.gz"
        with tarfile.open(evil, "w:gz") as tar:
            payload = b"oops"
            info = tarfile.TarInfo("python/../escape")
            info.size = len(payload)
            tar.addfile(info, io.BytesIO(payload))
        stage = self.local / "stage"
        with self.assertRaises(provisioning.ProvisioningBlocked):
            provisioning._archive_extract(evil, stage, "attempt", __import__("threading").Event())
        self.assertFalse((self.local / "escape").exists())

    def test_bundle_hash_mismatch_fails_closed(self):
        with patch.object(provisioning, "BUNDLED_PYTHON_ARCHIVE_SHA256", "0" * 64):
            controller = provisioning.LayaSetupController(self.context)
            self.assertEqual(controller.status()["reason_code"], "python_bundle_hash_mismatch")

    def test_process_tree_timeout_retains_job_and_owned_roots(self):
        jobs: list[FakeJob] = []

        def launched() -> None:
            plan = controller._active_plan
            assert plan
            plan.laya_root.mkdir(parents=True)
            provisioning._write_json_new(
                plan.laya_root / provisioning._OWNER_FILE,
                {"attempt_id": plan.attempt_id},
            )

        def launch_process(*args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
            return cast(subprocess.Popen[bytes], FakeProcess(launched))

        def make_job(name: str) -> FakeJob:
            jobs.append(FakeJob(False))
            return jobs[-1]

        controller = provisioning.LayaSetupController(
            self.context,
            process_factory=launch_process,
            job_factory=make_job,
            install_validator=self._never_valid,
            python_probe=self._python_always_true,
            system_directory_provider=self._system_directory,
        )
        identity = type("Identity", (), {"pid": 1, "creation_time_ns": 1})()
        with (
            patch.object(provisioning, "_current_owner_identity", return_value=identity),
            patch.object(
                provisioning,
                "_live_worker_identity",
                return_value=type("Identity", (), {"pid": 100, "creation_time_ns": 100})(),
            ),
        ):
            controller.start()
            assert controller._worker is not None
            controller._worker.join(3)
        self.assertEqual(
            controller.status()["state"],
            "cleanup_pending",
            controller._snapshot.to_dict(),
        )
        self.assertFalse(jobs[0].closed)
        self.assertTrue((self.local / "SystemSense/runtimes/laya-0.3.5").exists())
        self.assertFalse(controller.close(0))

    def test_assignment_failure_terminates_exact_suspended_child_and_allows_retry(self):
        processes: list[FakeProcess] = []
        jobs: list[FakeJob] = []

        def process_factory(*args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
            process = FakeProcess(running_on_start=True)
            processes.append(process)
            return cast(subprocess.Popen[bytes], process)

        def assignment_failing_job(name: str) -> FakeJob:
            jobs.append(FakeJob(assign_error=True))
            return jobs[-1]

        def python_probe(path: Path) -> bool:
            del path
            return True

        controller = provisioning.LayaSetupController(
            self.context,
            process_factory=process_factory,
            job_factory=assignment_failing_job,
            python_probe=python_probe,
            system_directory_provider=self._system_directory,
        )
        owner = type("Identity", (), {"pid": 1, "creation_time_ns": 1})()
        worker = type("Identity", (), {"pid": 100, "creation_time_ns": 100})()
        with (
            patch.object(provisioning, "_current_owner_identity", return_value=owner),
            patch.object(provisioning, "_live_worker_identity", return_value=worker),
        ):
            controller.start()
            assert controller._worker is not None
            controller._worker.join(3)
        self.assertTrue(processes[0].terminated)
        self.assertTrue(jobs[0].closed)
        self.assertEqual(controller._snapshot.state, "failed")
        self.assertTrue(controller._snapshot.can_install)
        self.assertFalse(
            (self.local / "SystemSense/setup-transactions").exists()
            and list((self.local / "SystemSense/setup-transactions").glob("*.json"))
        )

    def test_launch_intent_without_durable_worker_identity_is_not_recovered(self):
        app = self.local / "SystemSense"
        transaction = app / "setup-transactions"
        transaction.mkdir(parents=True)
        attempt = "12345678-1234-1234-1234-123456789abc"
        receipt = transaction / f"{attempt}.json"
        provisioning._write_json_new(
            receipt,
            {
                "attempt_id": attempt,
                "job_name": provisioning._job_name(attempt),
                "lifetime_job_name": (
                    "Local\\SystemSense.LayaSetupOwner.12345678-1234-1234-1234-123456789abc"
                ),
                "phase": "launch_intent",
                "owner_pid": 99999999,
                "owner_creation_time_ns": 1,
            },
        )
        controller = provisioning.LayaSetupController(
            self.context, system_directory_provider=self._system_directory
        )
        with (
            patch.object(provisioning, "_owner_exited", return_value=True),
            patch.object(provisioning, "_job_empty_or_gone", return_value=False),
        ):
            snapshot = controller.status()
        self.assertEqual(snapshot["state"], "cleanup_pending")
        self.assertEqual(snapshot["reason_code"], "lifetime_job_not_drained")
        self.assertTrue(receipt.exists())

    def test_real_process_start_requires_parent_lifetime_job(self):
        controller = provisioning.LayaSetupController(self.context)
        self.assertEqual(controller.status()["state"], "ready_to_install")
        result = controller.start()
        self.assertEqual(result["reason_code"], "lifetime_job_required")
        self.assertFalse(result["can_install"])

    def test_launch_intent_recovers_only_after_outer_job_is_empty(self):
        app = self.local / "SystemSense"
        transaction = app / "setup-transactions"
        transaction.mkdir(parents=True)
        attempt = "32345678-1234-1234-1234-123456789abc"
        receipt = transaction / f"{attempt}.json"
        provisioning._write_json_new(
            receipt,
            {
                "attempt_id": attempt,
                "job_name": provisioning._job_name(attempt),
                "lifetime_job_name": (
                    "Local\\SystemSense.LayaSetupOwner.32345678-1234-1234-1234-123456789abc"
                ),
                "phase": "launch_intent",
                "owner_pid": 99999999,
                "owner_creation_time_ns": 1,
            },
        )
        partial = app / provisioning.LAYA_INSTALL_RELATIVE
        partial.mkdir(parents=True)
        provisioning._write_json_new(
            partial / provisioning._OWNER_FILE,
            {"attempt_id": attempt, "kind": "laya-install"},
        )
        controller = provisioning.LayaSetupController(
            self.context, system_directory_provider=self._system_directory
        )
        with (
            patch.object(provisioning, "_owner_exited", return_value=True),
            patch.object(provisioning, "_job_empty_or_gone", return_value=True),
        ):
            snapshot = controller.status()
        self.assertEqual(snapshot["state"], "ready_to_install")
        self.assertFalse(receipt.exists())
        self.assertFalse(partial.exists())

    def test_no_shell_or_renderer_values_in_command(self):
        controller = provisioning.LayaSetupController(self.context)
        controller.status()
        plan = controller._active_plan
        assert plan
        self.assertNotIn("shell", plan.arguments)
        self.assertEqual(plan.arguments[plan.arguments.index("-Device") + 1], "cuda")
        self.assertNotIn("arbitrary", " ".join(plan.arguments))

    def test_python_version_probe_is_hidden_and_does_not_inherit_environment(self):
        completed = subprocess.CompletedProcess(
            [], 0, stdout=provisioning.PYTHON_VERSION.encode("ascii")
        )
        with (
            patch.object(provisioning, "_system_directory", return_value=self.system_directory),
            patch.object(provisioning.subprocess, "run", return_value=completed) as run,
        ):
            self.assertTrue(provisioning._probe_bundled_python(self.exe))
        self.assertEqual(run.call_args.kwargs["creationflags"], subprocess.CREATE_NO_WINDOW)
        self.assertEqual(set(run.call_args.kwargs["env"]), {"SystemRoot", "SystemDrive", "WINDIR"})
        self.assertEqual(run.call_args.kwargs["env"]["SystemDrive"], self.system_directory.drive)
        self.assertEqual(run.call_args.kwargs["cwd"], self.exe.parent)
        self.assertEqual(run.call_args.args[0][0], str(self.exe))

    def test_rollback_preserves_valid_laya_and_its_new_python_base(self):
        controller = provisioning.LayaSetupController(
            self.context, install_validator=self._owned_marker_valid
        )
        controller.status()
        plan = controller._active_plan
        assert plan is not None
        self.assertFalse(plan.reuse_python)
        for root in (plan.laya_root, plan.runtime_root):
            root.mkdir(parents=True)
            provisioning._write_json_new(
                root / provisioning._OWNER_FILE, {"attempt_id": plan.attempt_id}
            )
        (plan.runtime_root / "python.exe").write_bytes(b"validated base")
        plan.receipt.parent.mkdir(parents=True)
        provisioning._write_json_new(plan.receipt, {"attempt_id": plan.attempt_id})
        controller._rollback(plan)
        self.assertTrue(plan.laya_root.exists())
        self.assertEqual((plan.runtime_root / "python.exe").read_bytes(), b"validated base")

    def test_cancel_during_python_probe_does_not_launch_installer(self):
        processes: list[FakeProcess] = []

        def python_probe(path: Path) -> bool:
            controller._cancel.set()
            return path.is_file()

        def launch(*args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
            process = FakeProcess()
            processes.append(process)
            return process

        controller = provisioning.LayaSetupController(
            self.context,
            process_factory=launch,
            job_factory=self._job_factory,
            python_probe=python_probe,
            system_directory_provider=self._system_directory,
        )
        controller.start()
        assert controller._worker is not None
        controller._worker.join(3)
        self.assertEqual(len(processes), 0)
        self.assertEqual(controller._snapshot.state, "cancelled")

    def test_cancel_after_job_assignment_does_not_resume_installer(self):
        process = FakeProcess(running_on_start=True)
        resumed: list[bool] = []

        class CancellingJob(FakeJob):
            def assign_suspended(self, worker: subprocess.Popen[bytes]) -> None:
                controller._cancel.set()

            def resume_assigned(self, worker: subprocess.Popen[bytes]) -> None:
                resumed.append(True)

        def launch(*args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
            return process

        def job_factory(name: str) -> FakeJob:
            return CancellingJob()

        controller = provisioning.LayaSetupController(
            self.context,
            process_factory=launch,
            job_factory=job_factory,
            python_probe=self._python_always_true,
            system_directory_provider=self._system_directory,
        )
        worker = type("Identity", (), {"pid": 100, "creation_time_ns": 100})()
        with patch.object(provisioning, "_live_worker_identity", return_value=worker):
            controller.start()
            assert controller._worker is not None
            controller._worker.join(3)
        self.assertEqual(resumed, [])
        self.assertTrue(process.terminated)
        self.assertEqual(controller._snapshot.state, "cancelled")


if __name__ == "__main__":
    unittest.main()
