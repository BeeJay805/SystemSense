"""Fixed, app-owned Laya provisioning with cancellation and durable recovery."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import threading
import uuid
from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path, PurePosixPath
from typing import Any, Protocol, cast

from systemsense.application.setup_worker_failure_diagnostics import (
    failure_record,
    primary_failure,
    write_failure_record,
)

PYTHON_VERSION = "3.12.14"
PYTHON_ARCHIVE_RELATIVE = Path(
    "laya-setup/python/cpython-3.12.14+20260814-x86_64-pc-windows-msvc-install_only_stripped.tar.gz"
)
INSTALLER_RELATIVE = Path("laya-setup/install-laya-runtime.ps1")
PYTHON_RUNTIME_RELATIVE = Path("runtimes") / f"python-{PYTHON_VERSION}"
LAYA_INSTALL_RELATIVE = Path("runtimes/laya-0.3.5")
BUNDLED_PYTHON_ARCHIVE_SHA256 = "89f18f6932917163b74339ebcec2645c8e47ae7f1c5f2ac37f2b4f4cf3beb647"
PYTHON_ARCHIVE_URL = "https://github.com/astral-sh/python-build-standalone/releases/download/20260814/cpython-3.12.14%2B20260814-x86_64-pc-windows-msvc-install_only_stripped.tar.gz"
_OWNER_FILE = ".systemsense-setup-owned.json"
_PYTHON_RECEIPT = ".systemsense-python-runtime.json"
_ATTRIBUTE_REPARSE_POINT = 0x0400
_MAX_ARCHIVE_FILES = 20_000
_MAX_UNPACKED_BYTES = 512 * 1024 * 1024
_WINDOWS_NAME_TOO_LONG_ERROR = 206
_WINDOWS_STATUS_NAME_TOO_LONG = 0xC0000106


class ProvisioningBlocked(RuntimeError):
    def __init__(self, reason_code: str):
        super().__init__(reason_code)
        self.reason_code = reason_code


@dataclass(frozen=True, slots=True)
class ProvisioningContext:
    executable: Path
    local_app_data: Path


@dataclass(frozen=True, slots=True)
class SetupSnapshot:
    state: str
    stage: str
    reason_code: str | None
    can_install: bool
    existing_install: bool

    def __post_init__(self) -> None:
        if self.state not in {
            "unavailable",
            "ready_to_install",
            "installing",
            "cancelling",
            "installed",
            "cancelled",
            "failed",
            "cleanup_pending",
        }:
            raise ValueError("invalid Laya setup state")

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class InstallPlan:
    archive: Path
    installer: Path
    runtime_root: Path
    python_executable: Path
    laya_root: Path
    arguments: tuple[str, ...]
    attempt_id: str
    receipt: Path
    stage_root: Path
    temp_root: Path
    reuse_python: bool


def default_context() -> ProvisioningContext:
    value = os.environ.get("LOCALAPPDATA")
    if not value:
        raise ProvisioningBlocked("local_app_data_unavailable")
    return ProvisioningContext(Path(sys.executable), Path(value))


def _reparse(path: Path) -> bool:
    current = Path(path.anchor)
    for piece in path.parts[1:]:
        current /= piece
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        except OSError as error:
            raise ProvisioningBlocked("path_metadata_unavailable") from error
        if (
            stat.S_ISLNK(info.st_mode)
            or getattr(info, "st_file_attributes", 0) & _ATTRIBUTE_REPARSE_POINT
        ):
            return True
    return False


def _fixed(path: Path) -> Path:
    if not path.is_absolute() or ".." in path.parts:
        raise ProvisioningBlocked("path_not_fixed_absolute")
    path = Path(os.path.abspath(path))
    if _reparse(path):
        raise ProvisioningBlocked("reparse_path_rejected")
    return path


def _hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def _resource_root(context: ProvisioningContext) -> Path:
    exe = _fixed(context.executable)
    if (
        exe.name.casefold() != "investigator.exe"
        or exe.parent.name.casefold() != "investigator"
        or not exe.is_file()
    ):
        raise ProvisioningBlocked("packaged_layout_unexpected")
    return _fixed(exe.parent.parent)


def _read_receipt(path: Path) -> dict[str, object] | None:
    try:
        raw: object = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError, UnicodeError):
        return None
    if not isinstance(raw, dict):
        return None
    return cast(dict[str, object], raw)


def _write_json_new(path: Path, value: dict[str, object]) -> None:
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    with path.open("xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())


def _atomic_json(path: Path, value: dict[str, object]) -> None:
    temporary = path.with_name(path.name + ".tmp")
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")
    with temporary.open("xb") as stream:
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _archive_extract(archive: Path, stage: Path, attempt: str, cancel: threading.Event) -> None:
    stage.mkdir(parents=False, exist_ok=False)
    _write_json_new(stage / _OWNER_FILE, {"attempt_id": attempt, "kind": "python-stage"})
    count = total = 0
    with tarfile.open(archive, "r:gz") as tar:
        members = tar.getmembers()
        if len(members) > _MAX_ARCHIVE_FILES:
            raise ProvisioningBlocked("python_archive_entry_limit")
        for member in members:
            if cancel.is_set():
                raise InterruptedError("cancelled")
            name = member.name
            pure = PurePosixPath(name)
            if (
                "\\" in name
                or pure.is_absolute()
                or any(part in {"", ".", ".."} for part in pure.parts)
                or not pure.parts
                or pure.parts[0] != "python"
            ):
                raise ProvisioningBlocked("python_archive_path_rejected")
            if member.issym() or member.islnk() or not (member.isfile() or member.isdir()):
                raise ProvisioningBlocked("python_archive_member_rejected")
            relative = Path(*pure.parts[1:])
            if not relative.parts:
                continue
            target = stage / relative
            if not target.resolve().is_relative_to(stage.resolve()):
                raise ProvisioningBlocked("python_archive_path_rejected")
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            count += 1
            total += member.size
            if count > _MAX_ARCHIVE_FILES or total > _MAX_UNPACKED_BYTES:
                raise ProvisioningBlocked("python_archive_size_limit")
            target.parent.mkdir(parents=True, exist_ok=True)
            source = tar.extractfile(member)
            if source is None:
                raise ProvisioningBlocked("python_archive_member_unreadable")
            with source, target.open("xb") as output:
                shutil.copyfileobj(source, output, 1024 * 1024)
        if not (stage / "python.exe").is_file():
            raise ProvisioningBlocked("python_archive_layout_unexpected")


def _python_runtime_receipt_valid(root: Path) -> bool:
    receipt = _read_receipt(root / _PYTHON_RECEIPT)
    return bool(
        receipt
        and receipt.get("version") == PYTHON_VERSION
        and receipt.get("archive_sha256") == BUNDLED_PYTHON_ARCHIVE_SHA256
        and receipt.get("source") == PYTHON_ARCHIVE_URL
        and (root / "python.exe").is_file()
    )


def _probe_bundled_python(path: Path) -> bool:
    try:
        system_root = _system_directory().parent
        result = subprocess.run(
            [
                str(path),
                "-I",
                "-c",
                "import sys; print('.'.join(map(str, sys.version_info[:3])))",
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=10,
            check=False,
            shell=False,
            cwd=path.parent,
            creationflags=subprocess.CREATE_NO_WINDOW,
            env={
                "SystemRoot": str(system_root),
                "SystemDrive": system_root.drive,
                "WINDIR": str(system_root),
            },
        )
    except OSError as error:
        if getattr(error, "winerror", None) == _WINDOWS_NAME_TOO_LONG_ERROR:
            raise ProvisioningBlocked("python_runtime_name_too_long") from error
        return False
    except subprocess.TimeoutExpired:
        return False
    if result.returncode & 0xFFFFFFFF == _WINDOWS_STATUS_NAME_TOO_LONG:
        raise ProvisioningBlocked("python_runtime_name_too_long")
    return result.returncode == 0 and result.stdout.strip() == PYTHON_VERSION.encode("ascii")


def _valid_laya(root: Path) -> bool:
    try:
        from systemsense.inference.laya_runtime import LayaRuntimeConfig

        config = LayaRuntimeConfig(
            interpreter_path=root / "venv/Scripts/python.exe",
            model_path=root / "model",
            device="cuda",
            precision="float16",
        )
        config.validate_install()
        return True
    except Exception:
        return False


def _valid_lifetime_job_name(name: str) -> bool:
    prefix = "Local\\SystemSense.LayaSetupOwner."
    if not name.startswith(prefix):
        return False
    suffix = name[len(prefix) :]
    try:
        return str(uuid.UUID(suffix)).casefold() == suffix.casefold()
    except ValueError:
        return False


def _system_directory() -> Path:
    import win32api

    return Path(win32api.GetSystemDirectory())


def _capture_bounded_output(stream: Any, captured: bytearray, limit: int = 512 * 1024) -> None:
    while True:
        chunk = stream.read(64 * 1024)
        if not chunk:
            return
        remaining = limit - len(captured)
        if remaining > 0:
            captured.extend(chunk[:remaining])


def _join_output_reader(reader: threading.Thread | None) -> bool:
    if reader is None:
        return True
    # Thread.start() can fail before creating a native reader. Joining that
    # never-started object raises even though no output worker needs draining.
    if reader.ident is None and not reader.is_alive():
        return True
    try:
        reader.join(5.0)
    except Exception:
        return False
    return not reader.is_alive()


def _job_name(attempt_id: str) -> str:
    if len(attempt_id) != 36 or any(c not in "0123456789abcdef-" for c in attempt_id.lower()):
        raise ProvisioningBlocked("setup_attempt_id_invalid")
    return f"Local\\SystemSense.Laya.{attempt_id}"


def _current_owner_identity() -> Any:
    from systemsense.orchestration.probe_capacity_recovery import (
        current_process_identity,
    )

    return current_process_identity()


def _live_worker_identity(pid: int) -> Any:
    from systemsense.orchestration.probe_capacity_recovery import live_process_identity

    return live_process_identity(pid)


def _owner_exited(receipt: dict[str, object]) -> bool:
    from systemsense.orchestration.probe_capacity_ledger import WorkerIdentity
    from systemsense.orchestration.probe_capacity_recovery import live_process_identity

    pid = receipt.get("owner_pid")
    created = receipt.get("owner_creation_time_ns")
    if (
        not isinstance(pid, int)
        or isinstance(pid, bool)
        or not isinstance(created, int)
        or isinstance(created, bool)
        or pid <= 0
        or created <= 0
    ):
        return False
    identity = WorkerIdentity(pid, created)
    return live_process_identity(pid) != identity


def _job_empty_or_gone(name: str) -> bool:
    try:
        import win32job

        job_api: Any = win32job
        job: Any = job_api.OpenJobObject(job_api.JOB_OBJECT_QUERY, False, name)
    except Exception as error:
        if getattr(error, "winerror", None) == 2:
            return True
        return False
    try:
        raw_details: object = job_api.QueryInformationJobObject(
            job, job_api.JobObjectBasicAccountingInformation
        )
        details = cast(dict[str, object], raw_details) if isinstance(raw_details, dict) else {}
        active = details.get("ActiveProcesses")
        return isinstance(active, int) and not isinstance(active, bool) and active == 0
    except Exception:
        return False
    finally:
        job.Close()


def _orphan_proven(
    receipt: dict[str, object],
    name: str,
    expected_executable: Path,
    expected_argv: tuple[str, ...],
    lifetime_job_name: str | None,
) -> bool:
    if not _owner_exited(receipt):
        return False
    worker_pid = receipt.get("worker_pid")
    worker_created = receipt.get("worker_creation_time_ns")
    if (
        not isinstance(worker_pid, int)
        or isinstance(worker_pid, bool)
        or not isinstance(worker_created, int)
        or isinstance(worker_created, bool)
    ):
        # The durable launch-intent window has no exact process identity. A Job
        # being empty cannot prove there was no suspended, unassigned child.
        if receipt.get("phase") in {"launch_intent", "worker_identity_pending"}:
            return bool(
                lifetime_job_name
                and receipt.get("lifetime_job_name") == lifetime_job_name
                and _job_empty_or_gone(lifetime_job_name)
            )
        return _job_empty_or_gone(name)
    from systemsense.orchestration.probe_capacity_ledger import WorkerIdentity
    from systemsense.orchestration.probe_capacity_recovery import (
        live_process_identity,
        prove_orphaned_job_exited,
    )

    owner_pid = receipt.get("owner_pid")
    owner_created = receipt.get("owner_creation_time_ns")
    if (
        not isinstance(owner_pid, int)
        or isinstance(owner_pid, bool)
        or not isinstance(owner_created, int)
        or isinstance(owner_created, bool)
    ):
        return False
    expected_worker = WorkerIdentity(worker_pid, worker_created)
    expected_owner = WorkerIdentity(owner_pid, owner_created)
    try:
        if prove_orphaned_job_exited(name, expected_worker, expected_owner):
            return True
    except Exception:
        pass
    if live_process_identity(worker_pid) != expected_worker:
        return _job_empty_or_gone(name)

    # A known worker may have died in the CreateProcess-to-Job assignment gap.
    # Kill only when both image path and complete fixed argument vector match.
    try:
        import psutil
        import win32api
        import win32event
        import win32job
        import win32process

        job_api: Any = win32job

        process_info = psutil.Process(worker_pid)
        image = Path(process_info.exe())
        command = process_info.cmdline()
        expected = [str(expected_executable), *expected_argv]
        if str(image).casefold() != str(expected_executable).casefold() or len(command) != len(
            expected
        ):
            return False
        if any(
            str(actual).casefold() != wanted.casefold()
            for actual, wanted in zip(command, expected, strict=True)
        ):
            return False
        handle: Any = win32api.OpenProcess(0x100001 | 0x1000, False, worker_pid)
        process_api: Any = win32process
        try:
            if process_api.GetProcessId(int(handle)) != worker_pid:
                return False
            if live_process_identity(worker_pid) != expected_worker:
                return False
            job: Any = None
            try:
                job = job_api.OpenJobObject(
                    job_api.JOB_OBJECT_QUERY | job_api.JOB_OBJECT_TERMINATE, False, name
                )
            except Exception as error:
                if getattr(error, "winerror", None) != 2:
                    return False
                job = None
            if job is not None:
                try:
                    job_api.TerminateJobObject(job, 1)
                finally:
                    job.Close()
            if win32event.WaitForSingleObject(handle, 5000) != win32event.WAIT_OBJECT_0:
                # It may be the known suspended process created just before it
                # entered the named Job. The exact PID/birth/image/argv checks
                # above authorize terminating only that Popen child.
                win32api.TerminateProcess(handle, 1)
                if win32event.WaitForSingleObject(handle, 5000) != win32event.WAIT_OBJECT_0:
                    return False
        finally:
            handle.Close()
        return _job_empty_or_gone(name)
    except Exception:
        return False


class _Job(Protocol):
    def assign_suspended(self, worker: subprocess.Popen[bytes]) -> None: ...
    def resume_assigned(self, worker: subprocess.Popen[bytes]) -> None: ...
    def is_assigned_worker(self, worker: subprocess.Popen[bytes]) -> bool: ...
    def wait_until_empty(self, timeout_seconds: float) -> bool: ...
    def terminate_processes(self) -> None: ...
    def close(self) -> None: ...


class LayaSetupController:
    """Fixed controller. Renderer never supplies paths, commands, device, or environment."""

    def __init__(
        self,
        context: ProvisioningContext | None = None,
        *,
        process_factory: Callable[..., subprocess.Popen[bytes]] | None = None,
        job_factory: Callable[[str], _Job] | None = None,
        lifetime_job_name: str | None = None,
        system_directory_provider: Callable[[], Path] | None = None,
        install_validator: Callable[[Path], bool] = _valid_laya,
        python_probe: Callable[[Path], bool] | None = None,
    ) -> None:
        self._context = context or default_context()
        self._process_factory = process_factory or subprocess.Popen
        self._job_factory = job_factory or self._default_job
        if lifetime_job_name is not None and not _valid_lifetime_job_name(lifetime_job_name):
            raise ProvisioningBlocked("lifetime_job_name_invalid")
        self._lifetime_job_name = lifetime_job_name
        self._system_directory_provider = system_directory_provider or _system_directory
        self._install_validator = install_validator
        self._python_probe = python_probe or _probe_bundled_python
        self._lock = threading.RLock()
        self._cancel = threading.Event()
        self._worker: threading.Thread | None = None
        self._process: subprocess.Popen[bytes] | None = None
        self._job: _Job | None = None
        self._active_plan: InstallPlan | None = None
        self._attempt: str | None = None
        self._bundle_fingerprint: tuple[int, int] | None = None
        self._bundle_hash: str | None = None
        self._existing_fingerprint: tuple[tuple[str, int, int], ...] | None = None
        self._existing_valid: bool | None = None
        self._recovery_reason = "prior_setup_pending"
        self._snapshot = SetupSnapshot("unavailable", "checking", "not_checked", False, False)

    @staticmethod
    def _default_job(name: str) -> _Job:
        from systemsense.orchestration.windows_probe_job import WindowsProbeJob

        return WindowsProbeJob(name=name)

    def _make_plan(self) -> InstallPlan:
        ctx = self._context
        resources = _resource_root(ctx)
        local = _fixed(ctx.local_app_data)
        if not local.is_dir():
            raise ProvisioningBlocked("local_app_data_unavailable")
        archive = _fixed(resources / PYTHON_ARCHIVE_RELATIVE)
        installer = _fixed(resources / INSTALLER_RELATIVE)
        app_root = _fixed(local / "SystemSense")
        runtime = _fixed(app_root / PYTHON_RUNTIME_RELATIVE)
        laya = _fixed(app_root / LAYA_INSTALL_RELATIVE)
        if not archive.is_file() or not installer.is_file():
            raise ProvisioningBlocked("packaged_setup_resources_missing")
        fingerprint = (archive.stat().st_size, archive.stat().st_mtime_ns)
        if fingerprint != self._bundle_fingerprint:
            self._bundle_hash = _hash(archive)
            self._bundle_fingerprint = fingerprint
        if self._bundle_hash != BUNDLED_PYTHON_ARCHIVE_SHA256:
            raise ProvisioningBlocked("python_bundle_hash_mismatch")
        if laya.exists():
            raise ProvisioningBlocked("fixed_install_target_exists")
        reuse_python = runtime.exists()
        if reuse_python:
            if _reparse(runtime) or not _python_runtime_receipt_valid(runtime):
                raise ProvisioningBlocked("existing_python_runtime_unverified")
        attempt = str(uuid.uuid4())
        tx = _fixed(app_root / "setup-transactions")
        receipt = tx / f"{attempt}.json"
        stage = _fixed(app_root / "runtimes" / f".python-{PYTHON_VERSION}-stage-{attempt}")
        temp_root = _fixed(app_root / "setup-temp" / attempt)
        return InstallPlan(
            archive,
            installer,
            runtime,
            runtime / "python.exe",
            laya,
            (
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(installer),
                "-PythonPath",
                str(runtime / "python.exe"),
                "-Device",
                "cuda",
                "-InstallRoot",
                str(laya),
                "-SetupAttemptId",
                attempt,
                "-OwnershipReceiptPath",
                str(receipt),
            ),
            attempt,
            receipt,
            stage,
            temp_root,
            reuse_python,
        )

    def status(self) -> dict[str, object]:
        with self._lock:
            if self._worker is not None and self._worker.is_alive():
                return self._snapshot.to_dict()
            if self._snapshot.state in {"cancelled", "failed"}:
                return self._snapshot.to_dict()
            try:
                app_root = _fixed(self._context.local_app_data / "SystemSense")
                tx_root = _fixed(app_root / "setup-transactions")
                if tx_root.exists():
                    pending = list(tx_root.glob("*.json"))
                    for receipt_path in pending:
                        if not self._recover_receipt(receipt_path, app_root):
                            self._snapshot = SetupSnapshot(
                                "cleanup_pending",
                                "recovery_required",
                                self._recovery_reason,
                                False,
                                False,
                            )
                            return self._snapshot.to_dict()
                root = _fixed(app_root / LAYA_INSTALL_RELATIVE)
                if root.exists():
                    fingerprint = self._install_fingerprint(root)
                    if (
                        fingerprint == self._existing_fingerprint
                        and self._existing_valid is not None
                    ):
                        valid = self._existing_valid
                    else:
                        valid = self._install_validator(root)
                        self._existing_fingerprint = fingerprint
                        self._existing_valid = valid
                    if valid:
                        self._snapshot = SetupSnapshot("installed", "ready", None, False, True)
                    else:
                        self._snapshot = SetupSnapshot(
                            "unavailable",
                            "existing_install",
                            "existing_install_unverified",
                            False,
                            False,
                        )
                    return self._snapshot.to_dict()
                plan = self._make_plan()
                self._active_plan = plan
                self._snapshot = SetupSnapshot("ready_to_install", "ready", None, True, False)
            except ProvisioningBlocked as error:
                self._snapshot = SetupSnapshot(
                    "unavailable", "prerequisite_check", error.reason_code, False, False
                )
            except OSError:
                self._snapshot = SetupSnapshot(
                    "unavailable",
                    "prerequisite_check",
                    "setup_resource_unreadable",
                    False,
                    False,
                )
            return self._snapshot.to_dict()

    def _recover_receipt(self, receipt_path: Path, app_root: Path) -> bool:
        try:
            attempt = receipt_path.stem
            if _job_name(attempt) == "":
                return False
            _fixed(receipt_path)
            if receipt_path.is_symlink() or _reparse(receipt_path):
                return False
            data = _read_receipt(receipt_path)
            if data is None:
                return False
            lifetime_job_name = data.get("lifetime_job_name")
            if (
                data.get("attempt_id") != attempt
                or data.get("job_name") != _job_name(attempt)
                or not isinstance(lifetime_job_name, str)
                or not _valid_lifetime_job_name(lifetime_job_name)
            ):
                return False
            reuse_python = data.get("reuse_python", False)
            if not isinstance(reuse_python, bool):
                return False
            laya_root = _fixed(app_root / LAYA_INSTALL_RELATIVE)
            resources = _resource_root(self._context)
            system_directory = _fixed(self._system_directory_provider())
            if system_directory.name.casefold() != "system32":
                return False
            powershell = system_directory / "WindowsPowerShell/v1.0/powershell.exe"
            runtime = _fixed(app_root / PYTHON_RUNTIME_RELATIVE)
            installer = _fixed(resources / INSTALLER_RELATIVE)
            expected_argv = (
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(installer),
                "-PythonPath",
                str(runtime / "python.exe"),
                "-Device",
                "cuda",
                "-InstallRoot",
                str(laya_root),
                "-SetupAttemptId",
                attempt,
                "-OwnershipReceiptPath",
                str(receipt_path),
            )
            plan = InstallPlan(
                Path(),
                Path(),
                _fixed(app_root / PYTHON_RUNTIME_RELATIVE),
                _fixed(app_root / PYTHON_RUNTIME_RELATIVE / "python.exe"),
                laya_root,
                (),
                attempt,
                receipt_path,
                _fixed(app_root / "runtimes" / f".python-{PYTHON_VERSION}-stage-{attempt}"),
                _fixed(app_root / "setup-temp" / attempt),
                reuse_python,
            )
            lifetime_name = data.get("lifetime_job_name")
            if not isinstance(lifetime_name, str) or not _orphan_proven(
                data, _job_name(attempt), powershell, expected_argv, lifetime_name
            ):
                self._recovery_reason = (
                    "lifetime_job_not_drained"
                    if data.get("phase") == "launch_intent" and "worker_pid" not in data
                    else "prior_setup_pending"
                )
                return False
            if laya_root.exists() and self._install_validator(laya_root):
                self._remove_owned_temp(plan)
                receipt_path.unlink()
                return True
            self._rollback(plan)
            return True
        except Exception:
            self._recovery_reason = "prior_setup_pending"
            return False

    def _install_fingerprint(self, root: Path) -> tuple[tuple[str, int, int], ...]:
        names = (
            "venv/Scripts/python.exe",
            "model/model.safetensors",
            "model/rl_agent_config.json",
            "model/INSTALL-MANIFEST.json",
            "model/tokenizer",
            "model/encoder",
        )
        result: list[tuple[str, int, int]] = []
        for name in names:
            path = root / name
            try:
                info = path.stat()
            except OSError:
                result.append((name, -1, -1))
            else:
                result.append((name, info.st_size, info.st_mtime_ns))
        return tuple(result)

    def start(self) -> dict[str, object]:
        with self._lock:
            if self._snapshot.state in {"cancelled", "failed"}:
                self._snapshot = SetupSnapshot("unavailable", "retry_check", None, False, False)
                self._active_plan = None
            current = self.status()
            if current["state"] != "ready_to_install":
                return current
            assert self._active_plan is not None
            if self._process_factory is subprocess.Popen and self._lifetime_job_name is None:
                self._snapshot = SetupSnapshot(
                    "unavailable",
                    "lifetime_custody",
                    "lifetime_job_required",
                    False,
                    False,
                )
                return self._snapshot.to_dict()
            if _hash(self._active_plan.archive) != BUNDLED_PYTHON_ARCHIVE_SHA256:
                self._snapshot = SetupSnapshot(
                    "unavailable",
                    "prerequisite_check",
                    "python_bundle_hash_mismatch",
                    False,
                    False,
                )
                return self._snapshot.to_dict()
            self._cancel.clear()
            self._attempt = self._active_plan.attempt_id
            self._snapshot = SetupSnapshot("installing", "preparing_python", None, False, False)
            self._worker = threading.Thread(target=self._run, name="laya-setup", daemon=False)
            self._worker.start()
            return self._snapshot.to_dict()

    def cancel(self) -> dict[str, object]:
        with self._lock:
            if self._worker is None or not self._worker.is_alive():
                return self.status()
            self._cancel.set()
            self._snapshot = SetupSnapshot(
                "cancelling", "stopping_process_tree", None, False, False
            )
            job = self._job
        if job is not None:
            try:
                job.terminate_processes()
            except Exception:
                pass
        return self._snapshot.to_dict()

    def close(self, timeout: float = 5.0) -> bool:
        if timeout < 0 or timeout > 3600:
            raise ValueError("timeout must be from zero to one hour")
        self.cancel()
        worker = self._worker
        if worker is not None:
            worker.join(timeout)
            if worker.is_alive():
                with self._lock:
                    self._snapshot = SetupSnapshot(
                        "cleanup_pending",
                        "waiting_for_process_tree",
                        "cleanup_not_proven",
                        False,
                        False,
                    )
                return False
        return self._snapshot.state != "cleanup_pending"

    def _run(self) -> None:
        plan = self._active_plan
        assert plan is not None
        job: _Job | None = None
        process: subprocess.Popen[bytes] | None = None
        capture_thread: threading.Thread | None = None
        setup_failure_stage = "setup_initialization"
        try:
            _fixed(plan.receipt.parent)
            plan.receipt.parent.mkdir(parents=True, exist_ok=True)
            _fixed(plan.receipt.parent)
            _fixed(plan.stage_root.parent)
            plan.stage_root.parent.mkdir(parents=True, exist_ok=True)
            _fixed(plan.stage_root.parent)
            owner = _current_owner_identity()
            _write_json_new(
                plan.receipt,
                {
                    "attempt_id": plan.attempt_id,
                    "laya_root": str(plan.laya_root),
                    "reuse_python": plan.reuse_python,
                    "phase": "python_stage",
                    "archive_sha256": BUNDLED_PYTHON_ARCHIVE_SHA256,
                    "owner_pid": owner.pid,
                    "owner_creation_time_ns": owner.creation_time_ns,
                    "job_name": _job_name(plan.attempt_id),
                    "lifetime_job_name": self._lifetime_job_name,
                },
            )
            if not plan.reuse_python:
                _archive_extract(plan.archive, plan.stage_root, plan.attempt_id, self._cancel)
                if self._cancel.is_set():
                    raise InterruptedError("cancelled")
                _atomic_json(
                    plan.stage_root / _PYTHON_RECEIPT,
                    {
                        "version": PYTHON_VERSION,
                        "archive_sha256": BUNDLED_PYTHON_ARCHIVE_SHA256,
                        "source": PYTHON_ARCHIVE_URL,
                    },
                )
                if not self._python_probe(plan.stage_root / "python.exe"):
                    raise ProvisioningBlocked("python_runtime_probe_failed")
                if self._cancel.is_set():
                    raise InterruptedError("cancelled")
                plan.runtime_root.parent.mkdir(parents=True, exist_ok=True)
                _fixed(plan.runtime_root.parent)
                os.replace(plan.stage_root, plan.runtime_root)
            elif not self._python_probe(plan.python_executable):
                raise ProvisioningBlocked("existing_python_runtime_probe_failed")
            with self._lock:
                if self._cancel.is_set():
                    raise InterruptedError("cancelled")
                self._snapshot = SetupSnapshot("installing", "installing_laya", None, False, False)
            receipt_data = _read_receipt(plan.receipt) or {}
            receipt_data["phase"] = "laya_install"
            _atomic_json(plan.receipt, receipt_data)
            job_name = _job_name(plan.attempt_id)
            job = self._job_factory(job_name)
            with self._lock:
                self._job = job
            flags = getattr(subprocess, "CREATE_NO_WINDOW", 0) | getattr(
                subprocess, "CREATE_SUSPENDED", 0x00000004
            )
            _fixed(plan.temp_root.parent)
            plan.temp_root.parent.mkdir(parents=True, exist_ok=True)
            _fixed(plan.temp_root.parent)
            plan.temp_root.mkdir(exist_ok=False)
            _write_json_new(
                plan.temp_root / _OWNER_FILE,
                {"attempt_id": plan.attempt_id, "kind": "setup-temp"},
            )
            system_directory = _fixed(self._system_directory_provider())
            if system_directory.name.casefold() != "system32":
                raise ProvisioningBlocked("windows_system_directory_unexpected")
            system_root = system_directory.parent
            powershell = _fixed(system_directory / "WindowsPowerShell/v1.0/powershell.exe")
            if not powershell.is_file():
                raise ProvisioningBlocked("windows_powershell_missing")
            local_app_data = _fixed(self._context.local_app_data)
            hf_home = plan.laya_root / ".systemsense-hf-home"
            env = {
                "SystemRoot": str(system_root),
                # Windows known-folder expansion needs the trusted OS drive.
                "SystemDrive": system_root.drive,
                "WINDIR": str(system_root),
                "LOCALAPPDATA": str(local_app_data),
                "TEMP": str(plan.temp_root),
                "TMP": str(plan.temp_root),
                # Windows PowerShell needs this even for an absolute .exe path.
                # Without it, invocation can use file association instead of waiting.
                "PATHEXT": ".EXE",
                "PIP_CONFIG_FILE": os.devnull,
                "PIP_INDEX_URL": "https://pypi.org/simple",
                "PIP_NO_CACHE_DIR": "1",
                "PYTHONNOUSERSITE": "1",
                "HF_HOME": str(hf_home),
                "HF_HUB_CACHE": str(hf_home / "hub"),
                "HF_HUB_DISABLE_IMPLICIT_TOKEN": "1",
            }
            receipt_data = _read_receipt(plan.receipt) or {}
            receipt_data["phase"] = "launch_intent"
            _atomic_json(plan.receipt, receipt_data)
            if self._cancel.is_set():
                raise InterruptedError("cancelled")
            process = self._process_factory(
                [str(powershell), *plan.arguments],
                cwd=plan.temp_root,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                shell=False,
                close_fds=True,
                env=env,
                creationflags=flags,
            )
            # Retain the exact Popen handle before any fallible output-reader,
            # identity, journal, or Job work so exception cleanup can stop an
            # unassigned suspended child directly.
            with self._lock:
                self._process = process
            captured = bytearray()
            output_stream = getattr(process, "stdout", None)
            if output_stream is not None:
                capture_thread = threading.Thread(
                    target=_capture_bounded_output,
                    args=(output_stream, captured),
                    name="laya-setup-output",
                    daemon=False,
                )
                capture_thread.start()
            worker_identity = _live_worker_identity(process.pid)
            if worker_identity is None:
                raise ProvisioningBlocked("setup_worker_identity_unavailable")
            receipt_data = _read_receipt(plan.receipt) or {}
            receipt_data.update(
                {
                    "worker_pid": worker_identity.pid,
                    "worker_creation_time_ns": worker_identity.creation_time_ns,
                    "phase": "worker_suspended",
                }
            )
            setup_failure_stage = "worker_suspended_receipt_write"
            _atomic_json(plan.receipt, receipt_data)
            setup_failure_stage = "worker_job_assignment"
            job.assign_suspended(process)
            receipt_data["phase"] = "worker_assigned"
            setup_failure_stage = "worker_assigned_receipt_write"
            _atomic_json(plan.receipt, receipt_data)
            with self._lock:
                if self._cancel.is_set():
                    raise InterruptedError("cancelled")
                setup_failure_stage = "worker_resume"
                job.resume_assigned(process)
            while process.poll() is None:
                if self._cancel.wait(0.1):
                    job.terminate_processes()
                    break
            process.wait()
            if not job.wait_until_empty(5.0):
                with self._lock:
                    self._snapshot = SetupSnapshot(
                        "cleanup_pending",
                        "waiting_for_process_tree",
                        "process_tree_not_drained",
                        False,
                        False,
                    )
                return
            if capture_thread is not None:
                capture_thread.join(5.0)
                if capture_thread.is_alive():
                    with self._lock:
                        self._snapshot = SetupSnapshot(
                            "cleanup_pending",
                            "output_drain",
                            "setup_output_not_drained",
                            False,
                            False,
                        )
                    return
            job.close()
            with self._lock:
                self._job = None
                self._process = None
            valid_install = self._install_validator(plan.laya_root)
            if valid_install:
                receipt_data = _read_receipt(plan.receipt) or {}
                receipt_data["phase"] = "complete"
                _atomic_json(plan.receipt, receipt_data)
                self._remove_owned_temp(plan)
                plan.receipt.unlink(missing_ok=True)
                reason = (
                    "cancelled_after_install_completed"
                    if self._cancel.is_set()
                    else "installer_exit_nonzero_after_validation"
                    if process.returncode != 0
                    else None
                )
                self._finish("installed", "ready", reason)
            elif self._cancel.is_set():
                self._save_diagnostics(plan, captured)
                self._rollback_and_finish(plan, "cancelled", "cancelled", None)
            else:
                self._save_diagnostics(plan, captured)
                self._rollback_and_finish(plan, "failed", "install_failed", "laya_install_failed")
        except InterruptedError:
            job_drained = True if job is None else self._drain(job)
            reader_stopped = _join_output_reader(capture_thread)
            if not job_drained or not reader_stopped:
                self._finish(
                    "cleanup_pending",
                    "waiting_for_process_tree",
                    "process_tree_not_drained" if not job_drained else "setup_output_not_drained",
                )
                return
            self._rollback_and_finish(plan, "cancelled", "cancelled", None)
        except BaseException as error:
            # Custody cleanup applies to SystemExit/KeyboardInterrupt too. Keep
            # the original BaseException authoritative even if cleanup fails.
            propagate = not isinstance(error, Exception)
            job_drained = True
            cleanup_error: BaseException | None = None
            if job is not None:
                try:
                    job_drained = self._drain(job)
                except BaseException as caught:
                    job_drained = False
                    cleanup_error = caught
            try:
                reader_stopped = _join_output_reader(capture_thread)
            except BaseException as caught:
                reader_stopped = False
                if cleanup_error is None:
                    cleanup_error = caught
            drained = job_drained and reader_stopped
            diagnostics_written = False
            try:
                phase_data = _read_receipt(plan.receipt) or {}
                stage = getattr(error, "stage", setup_failure_stage)
                if isinstance(error, ProvisioningBlocked):
                    stage = error.reason_code
                assignment_cleanup_error = getattr(error, "cleanup_error", None)
                record = failure_record(
                    plan.attempt_id,
                    str(phase_data.get("phase", "unknown")),
                    stage,
                    error,
                    child_exit_observed=(process is None or process.poll() is not None),
                    job_empty=job_drained if job is not None else None,
                    job_closed=job_drained if job is not None else None,
                    cleanup_error=(
                        RuntimeError("owned setup worker cleanup not proven")
                        if not drained
                        else assignment_cleanup_error or cleanup_error
                    ),
                )
                record["cleanup"]["output_reader_stopped"] = reader_stopped
                if assignment_cleanup_error is not None:
                    record["cleanup"]["assignment_thread_handle"] = primary_failure(
                        "worker_thread_close", assignment_cleanup_error
                    )
                if cleanup_error is not None:
                    record["cleanup"]["controller_cleanup_error"] = primary_failure(
                        "controller_cleanup", cleanup_error
                    )
                transaction_dir = _fixed(plan.receipt.parent)
                failure_path = _fixed(transaction_dir / f"{plan.attempt_id}.failure.log")
                if failure_path.parent != transaction_dir:
                    raise ProvisioningBlocked("failure_diagnostic_path_mismatch")
                write_failure_record(failure_path, record)
                diagnostics_written = True
            except BaseException:
                # Do not let diagnostic I/O replace the setup or cleanup error.
                pass

            safe_to_rollback = drained and diagnostics_written
            if safe_to_rollback:
                try:
                    self._rollback(plan)
                except BaseException as caught:
                    safe_to_rollback = False
                    if cleanup_error is None:
                        cleanup_error = caught

            if safe_to_rollback:
                try:
                    reason = (
                        error.reason_code
                        if isinstance(error, ProvisioningBlocked)
                        else "setup_operation_failed"
                    )
                    self._finish("failed", "install_failed", reason)
                except BaseException:
                    # The primary failure is still re-raised below.
                    pass
            else:
                try:
                    reason = (
                        "failure_diagnostics_not_persisted"
                        if drained and not diagnostics_written
                        else "process_tree_not_drained"
                        if not job_drained
                        else "setup_output_not_drained"
                        if not reader_stopped
                        else "owned_cleanup_failed"
                    )
                    self._finish("cleanup_pending", "cleanup", reason)
                except BaseException:
                    # Never replace the setup failure with cleanup reporting.
                    pass
            if propagate:
                raise
        finally:
            if job is not None and self._job is job:
                # Keep an undrained job open. KILL_ON_JOB_CLOSE handles backend death.
                pass

    def _drain(self, job: _Job) -> bool:
        try:
            process = self._process
            if process is not None and process.poll() is None:
                if job.is_assigned_worker(process):
                    job.terminate_processes()
                else:
                    process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    return False
            else:
                job.terminate_processes()
            if not job.wait_until_empty(5.0):
                return False
            job.close()
            with self._lock:
                self._job = None
                self._process = None
            return True
        except Exception:
            return False

    def _save_diagnostics(self, plan: InstallPlan, captured: bytearray) -> None:
        if not captured:
            return
        diagnostics = _fixed(plan.receipt.parent / f"{plan.attempt_id}.log")
        with diagnostics.open("xb") as stream:
            stream.write(captured[: 512 * 1024])
            stream.flush()
            os.fsync(stream.fileno())

    def _remove_owned_temp(self, plan: InstallPlan) -> None:
        if not plan.temp_root.exists() and not plan.temp_root.is_symlink():
            return
        marker = plan.temp_root / _OWNER_FILE
        data = _read_receipt(marker)
        if data is None or data.get("attempt_id") != plan.attempt_id:
            raise ProvisioningBlocked("owned_temp_marker_missing_or_mismatched")
        if _reparse(plan.temp_root):
            raise ProvisioningBlocked("owned_temp_reparse_rejected")
        for directory, subdirs, files in os.walk(plan.temp_root, followlinks=False):
            for name in [*subdirs, *files]:
                if _reparse(Path(directory) / name):
                    raise ProvisioningBlocked("owned_temp_tree_reparse_rejected")
        shutil.rmtree(plan.temp_root)

    def _rollback_and_finish(
        self, plan: InstallPlan, state: str, stage: str, reason: str | None
    ) -> None:
        try:
            self._rollback(plan)
        except Exception:
            self._finish("cleanup_pending", "cleanup", "owned_cleanup_failed")
            return
        self._finish(state, stage, reason)

    def _rollback(self, plan: InstallPlan) -> None:
        # Delete only targets carrying this exact attempt's exclusive ownership marker.
        preserve_install = plan.laya_root.exists() and self._install_validator(plan.laya_root)
        roots = (
            (plan.laya_root, plan.stage_root, plan.temp_root)
            if plan.reuse_python or preserve_install
            else (plan.laya_root, plan.runtime_root, plan.stage_root, plan.temp_root)
        )
        for root in roots:
            if root == plan.laya_root and preserve_install:
                continue
            if not root.exists() and not root.is_symlink():
                continue
            marker = root / _OWNER_FILE
            data = _read_receipt(marker)
            if data is None or data.get("attempt_id") != plan.attempt_id:
                raise ProvisioningBlocked("owned_root_marker_missing_or_mismatched")
            if _reparse(root):
                raise ProvisioningBlocked("owned_root_reparse_rejected")
            for directory, subdirs, files in os.walk(root, followlinks=False):
                for name in [*subdirs, *files]:
                    candidate = Path(directory) / name
                    if _reparse(candidate):
                        raise ProvisioningBlocked("owned_tree_reparse_rejected")
            shutil.rmtree(root)
        plan.receipt.unlink(missing_ok=True)

    def _finish(self, state: str, stage: str, reason: str | None, existing: bool = False) -> None:
        can_retry = False
        if state in {"cancelled", "failed"}:
            try:
                self._active_plan = self._make_plan()
                can_retry = True
            except (ProvisioningBlocked, OSError):
                can_retry = False
        with self._lock:
            self._snapshot = SetupSnapshot(state, stage, reason, can_retry, existing)
            self._existing_fingerprint = None
            self._existing_valid = None
