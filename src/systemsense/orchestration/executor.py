"""One-shot subprocess execution for registered diagnostic probes."""

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
from typing import BinaryIO, Protocol, cast

from pydantic import Field

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import JsonValue
from systemsense.evidence.redaction import Redactor
from systemsense.worker import REGISTERED_PROBE_IDS

_MAX_OUTPUT_BYTES = 262_144
_MAX_ERROR_BYTES = 65_536
_MAX_REQUEST_BYTES = 65_536
_POLL_SECONDS = 0.005
_STOP_GRACE_SECONDS = 0.25


class CancellationSignal(Protocol):
    @property
    def cancelled(self) -> bool: ...


class WorkerExecutionStatus(StrEnum):
    OK = "ok"
    DENIED = "denied"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"


class WorkerExecution(FrozenModel):
    status: WorkerExecutionStatus
    evidence: tuple[dict[str, JsonValue], ...] = ()
    error: str | None = Field(default=None, max_length=4096)


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
        creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        process = subprocess.Popen(
            [sys.executable, "-m", "systemsense.worker"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self._minimal_environment(),
            creationflags=creation_flags,
        )
        assert process.stdin is not None
        assert process.stdout is not None
        assert process.stderr is not None
        stdout_reader = _BoundedPipeReader(cast("BinaryIO", process.stdout), _MAX_OUTPUT_BYTES)
        stderr_reader = _BoundedPipeReader(cast("BinaryIO", process.stderr), _MAX_ERROR_BYTES)
        stdout_thread = threading.Thread(target=stdout_reader.read, daemon=True)
        stderr_thread = threading.Thread(target=stderr_reader.read, daemon=True)
        stdout_thread.start()
        stderr_thread.start()
        terminal_status: WorkerExecutionStatus | None = None
        terminal_error: str | None = None
        try:
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
                _stop_owned_process(process)
            else:
                process.wait()
        except OSError:
            terminal_status = WorkerExecutionStatus.FAILED
            terminal_error = "worker pipe failed"
            _stop_owned_process(process)
        finally:
            if not process.stdin.closed:
                process.stdin.close()
            stdout_thread.join(timeout=_STOP_GRACE_SECONDS)
            stderr_thread.join(timeout=_STOP_GRACE_SECONDS)
            process.stdout.close()
            process.stderr.close()

        stdout = stdout_reader.text()
        stderr = stderr_reader.text()

        evidence, reported_status, reported_error = self._parse_output(stdout)
        if terminal_status is not None:
            return WorkerExecution(
                status=terminal_status,
                evidence=evidence,
                error=terminal_error,
            )
        if stdout_reader.exceeded or stderr_reader.exceeded:
            return WorkerExecution(
                status=WorkerExecutionStatus.FAILED,
                evidence=evidence,
                error="worker output exceeded limit",
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


def _stop_owned_process(process: subprocess.Popen[bytes]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=_STOP_GRACE_SECONDS)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=_STOP_GRACE_SECONDS)
