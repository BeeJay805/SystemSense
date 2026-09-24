"""One-shot subprocess execution for registered diagnostic probes."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import tempfile
import threading
import time
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO, Protocol, cast

from pydantic import Field, model_validator

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import JsonValue
from systemsense.evidence.redaction import Redactor
from systemsense.worker import REGISTERED_PROBE_IDS

if TYPE_CHECKING:
    from systemsense.orchestration.windows_probe_job import WindowsProbeJob

_MAX_OUTPUT_BYTES = 262_144
_MAX_ERROR_BYTES = 65_536
_MAX_REQUEST_BYTES = 65_536
_POLL_SECONDS = 0.005
_STOP_GRACE_SECONDS = 0.25


class CancellationSignal(Protocol):
    @property
    def cancelled(self) -> bool: ...


class ProbeLaunchLifecycle(Protocol):
    """Trusted recorder for durable custody of a suspended Windows worker."""

    def record_launch_intent(self) -> None: ...

    def bind_suspended_worker(self, process: subprocess.Popen[bytes]) -> None: ...

    def confirm_job_assignment(self) -> None: ...

    def confirm_resume(self) -> None: ...

    def record_tree_exit_proof(
        self, job: WindowsProbeJob, process: subprocess.Popen[bytes]
    ) -> None: ...


class WorkerExecutionStatus(StrEnum):
    OK = "ok"
    DENIED = "denied"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"


class WorkerTreeExitStatus(StrEnum):
    NOT_LAUNCHED = "not_launched"
    VERIFIED_EMPTY = "verified_empty"
    UNKNOWN = "unknown"


class WorkerExecution(FrozenModel):
    status: WorkerExecutionStatus
    evidence: tuple[dict[str, JsonValue], ...] = ()
    error: str | None = Field(default=None, max_length=4096)
    tree_exit: WorkerTreeExitStatus = WorkerTreeExitStatus.NOT_LAUNCHED

    @model_validator(mode="after")
    def require_tree_proof_for_success(self) -> WorkerExecution:
        if (
            self.status is WorkerExecutionStatus.OK
            and self.tree_exit is WorkerTreeExitStatus.UNKNOWN
        ):
            raise ValueError("successful execution cannot have an unverified worker tree")
        return self


class ProbeExecutor:
    def __init__(self, *, redactor: Redactor | None = None) -> None:
        self._redactor = redactor or Redactor()

    def execute(
        self,
        probe_id: str,
        parameters: dict[str, JsonValue],
        *,
        timeout_ms: int,
        deadline_at: datetime | None = None,
        cancellation: CancellationSignal | None = None,
        custody: ProbeLaunchLifecycle | None = None,
    ) -> WorkerExecution:
        if probe_id not in REGISTERED_PROBE_IDS:
            return WorkerExecution(
                status=WorkerExecutionStatus.DENIED,
                error="probe ID is not registered",
            )
        if not 1 <= timeout_ms <= 120_000:
            raise ValueError("timeout_ms must be between 1 and 120000")
        if deadline_at is not None and deadline_at.tzinfo is None:
            raise ValueError("deadline_at must be timezone-aware")
        request = (
            json.dumps(
                {"probe_id": probe_id, "parameters": parameters},
                allow_nan=False,
                separators=(",", ":"),
                sort_keys=True,
            )
            + "\n"
        ).encode("utf-8")
        if len(request) > _MAX_REQUEST_BYTES:
            return WorkerExecution(
                status=WorkerExecutionStatus.FAILED,
                error="worker request exceeded limit",
            )
        deadline_mono = time.monotonic() + (timeout_ms / 1000)
        if deadline_at is not None:
            remaining = (deadline_at - datetime.now(UTC)).total_seconds()
            deadline_mono = min(deadline_mono, time.monotonic() + max(0.0, remaining))
        if time.monotonic() >= deadline_mono:
            return WorkerExecution(
                status=WorkerExecutionStatus.TIMED_OUT,
                error="probe exceeded deadline",
            )
        if cancellation is not None and cancellation.cancelled:
            return WorkerExecution(
                status=WorkerExecutionStatus.CANCELLED,
                error="probe cancelled",
            )
        try:
            job = _new_windows_job()
        except Exception:
            return WorkerExecution(
                status=WorkerExecutionStatus.FAILED,
                error="worker containment setup failed",
            )
        if custody is not None:
            if job is None:
                return WorkerExecution(
                    status=WorkerExecutionStatus.FAILED,
                    error="durable custody requires a Windows Job",
                )
            try:
                custody.record_launch_intent()
            except Exception:
                cleanup_failed = not _close_job(job)
                return WorkerExecution(
                    status=WorkerExecutionStatus.FAILED,
                    error=(
                        "worker containment cleanup failed"
                        if cleanup_failed
                        else "worker custody launch intent failed"
                    ),
                )
        try:
            creation_flags = 0
            if job is not None:
                import win32con

                creation_flags = subprocess.CREATE_NO_WINDOW | win32con.CREATE_SUSPENDED
            process = subprocess.Popen(
                [sys.executable, "-m", "systemsense.worker"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self._minimal_environment(),
                creationflags=creation_flags,
            )
        except Exception:
            if job is not None:
                if not _close_job(job):
                    return WorkerExecution(
                        status=WorkerExecutionStatus.FAILED,
                        error="worker containment cleanup failed",
                    )
            return WorkerExecution(
                status=WorkerExecutionStatus.FAILED,
                error="worker launch failed",
            )
        if job is not None:
            try:
                if custody is not None:
                    custody.bind_suspended_worker(process)
                job.assign_suspended(process)
                if custody is not None:
                    custody.confirm_job_assignment()
                job.resume_assigned(process)
                if custody is not None:
                    custody.confirm_resume()
            except Exception:
                tree_exit, cleanup_failed = _finish_windows_job(job, process, terminate=True)
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None:
                        try:
                            stream.close()
                        except Exception:
                            cleanup_failed = True
                return WorkerExecution(
                    status=WorkerExecutionStatus.FAILED,
                    tree_exit=tree_exit,
                    error=(
                        "worker containment cleanup failed"
                        if cleanup_failed
                        else "worker containment assignment failed"
                    ),
                )
        stdout_reader: _BoundedPipeReader | None = None
        stderr_reader: _BoundedPipeReader | None = None
        started_threads: list[threading.Thread] = []
        terminal_status: WorkerExecutionStatus | None = None
        terminal_error: str | None = None
        tree_exit = WorkerTreeExitStatus.NOT_LAUNCHED
        readers_started = False
        try:
            assert process.stdin is not None
            assert process.stdout is not None
            assert process.stderr is not None
            stdout_reader = _BoundedPipeReader(cast("BinaryIO", process.stdout), _MAX_OUTPUT_BYTES)
            stderr_reader = _BoundedPipeReader(cast("BinaryIO", process.stderr), _MAX_ERROR_BYTES)
            for reader in (stdout_reader, stderr_reader):
                thread = threading.Thread(target=reader.read, daemon=True)
                thread.start()
                started_threads.append(thread)
            readers_started = True
            process.stdin.write(request)
            process.stdin.close()
            while process.poll() is None:
                if time.monotonic() >= deadline_mono:
                    terminal_status = WorkerExecutionStatus.TIMED_OUT
                    terminal_error = "probe exceeded deadline"
                    break
                if cancellation is not None and cancellation.cancelled:
                    terminal_status = WorkerExecutionStatus.CANCELLED
                    terminal_error = "probe cancelled"
                    break
                if stdout_reader.exceeded or stderr_reader.exceeded:
                    terminal_status = WorkerExecutionStatus.FAILED
                    terminal_error = "worker output exceeded limit"
                    break
                time.sleep(_POLL_SECONDS)
            if terminal_status is not None:
                if job is None:
                    _stop_owned_process(process)
            else:
                process.wait()
        except Exception:
            terminal_status = WorkerExecutionStatus.FAILED
            terminal_error = (
                "worker pipe failed" if readers_started else "worker reader startup failed"
            )
            if job is None:
                try:
                    _stop_owned_process(process)
                except (OSError, subprocess.TimeoutExpired):
                    terminal_error = "worker containment cleanup failed"
        finally:
            if job is not None:
                tree_exit, cleanup_failed = _finish_windows_job(
                    job, process, terminate=terminal_status is not None, custody=custody
                )
                if cleanup_failed or tree_exit is WorkerTreeExitStatus.UNKNOWN:
                    terminal_status = WorkerExecutionStatus.FAILED
                    terminal_error = "worker containment cleanup failed"
            pipe_cleanup_failed = False
            if process.stdin is not None and not process.stdin.closed:
                try:
                    process.stdin.close()
                except Exception:
                    pipe_cleanup_failed = True
            for thread in started_threads:
                try:
                    thread.join(timeout=_STOP_GRACE_SECONDS)
                except Exception:
                    pipe_cleanup_failed = True
            if process.stdout is not None:
                if started_threads and started_threads[0].is_alive():
                    pipe_cleanup_failed = True
                else:
                    try:
                        process.stdout.close()
                    except Exception:
                        pipe_cleanup_failed = True
            if process.stderr is not None:
                if len(started_threads) > 1 and started_threads[1].is_alive():
                    pipe_cleanup_failed = True
                else:
                    try:
                        process.stderr.close()
                    except Exception:
                        pipe_cleanup_failed = True
            if pipe_cleanup_failed and terminal_error != "worker containment cleanup failed":
                earlier_error = terminal_error
                terminal_status = WorkerExecutionStatus.FAILED
                terminal_error = (
                    f"worker pipe cleanup failed after {earlier_error}"
                    if earlier_error is not None
                    else "worker pipe cleanup failed"
                )

        stdout = stdout_reader.text() if stdout_reader is not None else ""
        stderr = stderr_reader.text() if stderr_reader is not None else ""

        evidence, reported_status, reported_error = self._parse_output(stdout)
        if terminal_status is not None:
            return WorkerExecution(
                status=terminal_status,
                evidence=evidence,
                error=terminal_error,
                tree_exit=tree_exit,
            )
        if (stdout_reader is not None and stdout_reader.exceeded) or (
            stderr_reader is not None and stderr_reader.exceeded
        ):
            return WorkerExecution(
                status=WorkerExecutionStatus.FAILED,
                evidence=evidence,
                error="worker output exceeded limit",
                tree_exit=tree_exit,
            )
        if process.returncode != 0 and reported_status is WorkerExecutionStatus.OK:
            reported_status = WorkerExecutionStatus.FAILED
            reported_error = f"worker exited with code {process.returncode}"
        elif process.returncode != 0 and reported_error is None:
            reported_error = f"worker exited with code {process.returncode}"
        error = reported_error or stderr.strip() or None
        if error is not None:
            error = self._redactor.redact_text(error).text[:4096]
        return WorkerExecution(
            status=reported_status,
            evidence=evidence,
            error=error,
            tree_exit=tree_exit,
        )

    @staticmethod
    def _parse_output(
        stdout: str,
    ) -> tuple[
        tuple[dict[str, JsonValue], ...],
        WorkerExecutionStatus,
        str | None,
    ]:
        evidence: list[dict[str, JsonValue]] = []
        status = WorkerExecutionStatus.FAILED
        error: str | None = None
        for line in stdout.splitlines():
            try:
                decoded: object = json.loads(line)
            except (json.JSONDecodeError, TypeError):
                continue
            if not isinstance(decoded, dict):
                continue
            message = cast("dict[str, JsonValue]", decoded)
            if message.get("type") == "evidence":
                payload = message.get("payload")
                if isinstance(payload, dict):
                    evidence.append(payload)
            elif message.get("type") == "result":
                raw_status = message.get("status")
                if isinstance(raw_status, str):
                    try:
                        status = WorkerExecutionStatus(raw_status)
                    except ValueError:
                        status = WorkerExecutionStatus.FAILED
                raw_error = message.get("error")
                if isinstance(raw_error, str):
                    error = raw_error
        return tuple(evidence), status, error

    @staticmethod
    def _minimal_environment() -> dict[str, str]:
        source_root = Path(__file__).resolve().parents[2]
        system_root = os.environ.get("SystemRoot", r"C:\Windows")
        environment = {
            "PATH": os.pathsep.join(
                {
                    str(Path(sys.executable).parent),
                    str(Path(system_root) / "System32"),
                }
            ),
            "PYTHONIOENCODING": "utf-8",
            "PYTHONNOUSERSITE": "1",
            "PYTHONPATH": str(source_root),
            "TEMP": tempfile.gettempdir(),
            "TMP": tempfile.gettempdir(),
        }
        if os.name == "nt":
            environment["SystemRoot"] = system_root
            environment["WINDIR"] = os.environ.get("WINDIR", system_root)
        return environment


class _BoundedPipeReader:
    def __init__(self, stream: BinaryIO, limit: int) -> None:
        self._stream = stream
        self._limit = limit
        self._chunks: list[bytes] = []
        self._size = 0
        self._exceeded = threading.Event()

    @property
    def exceeded(self) -> bool:
        return self._exceeded.is_set()

    def read(self) -> None:
        try:
            while chunk := self._stream.read(8192):
                remaining = self._limit - self._size
                if remaining > 0:
                    kept = chunk[:remaining]
                    self._chunks.append(kept)
                    self._size += len(kept)
                if len(chunk) > remaining:
                    self._exceeded.set()
        except (OSError, ValueError):
            return

    def text(self) -> str:
        return b"".join(self._chunks).decode("utf-8", errors="replace")


def _new_windows_job() -> WindowsProbeJob | None:
    if os.name != "nt":
        return None
    from systemsense.orchestration.windows_probe_job import WindowsProbeJob

    return WindowsProbeJob()


def _finish_windows_job(
    job: WindowsProbeJob,
    process: subprocess.Popen[bytes],
    *,
    terminate: bool,
    custody: ProbeLaunchLifecycle | None = None,
) -> tuple[WorkerTreeExitStatus, bool]:
    """Drain a private Job before handle closure and prove the launched worker exited."""
    verified = False
    query_failed = False
    cleanup_failed = False
    stop_failed = False
    proof_failed = False
    try:
        if not terminate:
            try:
                verified = job.wait_until_empty(0)
            except Exception:
                query_failed = True
        if terminate or not verified:
            try:
                job.terminate_processes()
            except Exception:
                cleanup_failed = True
            try:
                _stop_owned_process(process)
            except Exception:
                cleanup_failed = True
                stop_failed = True
            if not query_failed:
                try:
                    verified = job.wait_until_empty(_STOP_GRACE_SECONDS)
                except Exception:
                    query_failed = True
        try:
            process_exited = process.poll() is not None
        except Exception:
            process_exited = False
            cleanup_failed = True
        if not process_exited:
            verified = False
        if verified and not query_failed and not stop_failed and custody is not None:
            try:
                custody.record_tree_exit_proof(job, process)
            except Exception:
                proof_failed = True
                cleanup_failed = True
    finally:
        if not _close_job(job):
            cleanup_failed = True
    tree_exit = (
        WorkerTreeExitStatus.VERIFIED_EMPTY
        if verified and not query_failed and not stop_failed and not proof_failed
        else WorkerTreeExitStatus.UNKNOWN
    )
    return tree_exit, cleanup_failed


def _close_job(job: WindowsProbeJob) -> bool:
    try:
        job.close()
        return True
    except Exception:
        try:
            job.terminate()
        except Exception:
            pass
        try:
            job.close()
        except Exception:
            pass
        return False


def _stop_owned_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=_STOP_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=_STOP_GRACE_SECONDS)
