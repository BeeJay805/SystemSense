"""One-shot subprocess execution for registered diagnostic probes."""

import json
import os
import subprocess
import sys
import tempfile
from enum import StrEnum
from pathlib import Path
from typing import cast

from pydantic import Field

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import JsonValue
from systemsense.evidence.redaction import Redactor
from systemsense.worker import REGISTERED_PROBE_IDS

_MAX_OUTPUT_BYTES = 262_144


class WorkerExecutionStatus(StrEnum):
    OK = "ok"
    DENIED = "denied"
    FAILED = "failed"
    TIMED_OUT = "timed_out"


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
    ) -> WorkerExecution:
        if probe_id not in REGISTERED_PROBE_IDS:
            return WorkerExecution(
                status=WorkerExecutionStatus.DENIED,
                error="probe ID is not registered",
            )
        if not 1 <= timeout_ms <= 120_000:
            raise ValueError("timeout_ms must be between 1 and 120000")

        request = json.dumps(
            {"probe_id": probe_id, "parameters": parameters},
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        process = subprocess.Popen(
            [sys.executable, "-m", "systemsense.worker"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            env=self._minimal_environment(),
            creationflags=creation_flags,
        )
        timed_out = False
        try:
            stdout, stderr = process.communicate(
                request + "\n",
                timeout=timeout_ms / 1000,
            )
        except subprocess.TimeoutExpired as timeout:
            timed_out = True
            partial_stdout = self._decoded(timeout.stdout)
            partial_stderr = self._decoded(timeout.stderr)
            process.terminate()
            try:
                stdout, stderr = process.communicate(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                stdout, stderr = process.communicate()
            if partial_stdout and partial_stdout not in stdout:
                stdout = partial_stdout + stdout
            if partial_stderr and partial_stderr not in stderr:
                stderr = partial_stderr + stderr

        evidence, reported_status, reported_error = self._parse_output(stdout)
        if timed_out:
            return WorkerExecution(
                status=WorkerExecutionStatus.TIMED_OUT,
                evidence=evidence,
                error="probe exceeded deadline",
            )
        if len(stdout.encode("utf-8")) > _MAX_OUTPUT_BYTES:
            return WorkerExecution(
                status=WorkerExecutionStatus.FAILED,
                evidence=evidence,
                error="worker output exceeded limit",
            )
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
                message = cast("dict[str, JsonValue]", json.loads(line))
            except (json.JSONDecodeError, TypeError):
                continue
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

    @staticmethod
    def _decoded(value: str | bytes | None) -> str:
        if value is None:
            return ""
        return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value
