"""Experiment-only tool execution, identical in both arms."""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

from benchmarks.ab.systemsense_bridge import MCPToolBridge
from benchmarks.ab.tools import SYSTEMSENSE_TOOL_NAMES


class PowerShellExecutor:
    def __init__(
        self,
        *,
        working_directory: Path,
        environment: dict[str, str] | None = None,
        output_limit_bytes: int = 64_000,
    ) -> None:
        self._working_directory = working_directory
        self._environment = {**os.environ, **(environment or {})}
        self._output_limit_bytes = output_limit_bytes

    def execute(self, name: str, arguments: dict[str, object]) -> object:
        if name != "run_powershell":
            raise ValueError(f"unknown repair tool: {name}")
        command = arguments.get("command")
        timeout = arguments.get("timeout_seconds", 60)
        if not isinstance(command, str) or not command or len(command) > 8000:
            raise ValueError("PowerShell command is invalid")
        if not isinstance(timeout, int) or isinstance(timeout, bool) or not 1 <= timeout <= 120:
            raise ValueError("PowerShell timeout must be between 1 and 120 seconds")
        started = time.perf_counter()
        creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        try:
            completed = subprocess.run(
                [
                    "powershell.exe",
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    command,
                ],
                cwd=self._working_directory,
                env=self._environment,
                capture_output=True,
                check=False,
                timeout=timeout,
                creationflags=creation_flags,
            )
            return {
                "exit_code": completed.returncode,
                "stdout": _bounded(completed.stdout, self._output_limit_bytes),
                "stderr": _bounded(completed.stderr, self._output_limit_bytes),
                "elapsed_ms": round((time.perf_counter() - started) * 1000),
            }
        except subprocess.TimeoutExpired as error:
            return {
                "exit_code": None,
                "stdout": _bounded(error.stdout or b"", self._output_limit_bytes),
                "stderr": _bounded(error.stderr or b"", self._output_limit_bytes),
                "elapsed_ms": round((time.perf_counter() - started) * 1000),
                "timed_out": True,
            }


class ExperimentToolExecutor:
    def __init__(
        self,
        *,
        powershell: PowerShellExecutor,
        systemsense: MCPToolBridge | None,
    ) -> None:
        self._powershell = powershell
        self._systemsense = systemsense

    def execute(self, name: str, arguments: dict[str, object]) -> object:
        if name == "run_powershell":
            return self._powershell.execute(name, arguments)
        if name in SYSTEMSENSE_TOOL_NAMES and self._systemsense is not None:
            return self._systemsense.call(name, arguments)
        raise ValueError(f"tool is unavailable in this arm: {name}")


def _bounded(value: bytes, limit: int) -> str:
    if len(value) <= limit:
        return value.decode("utf-8", errors="replace")
    suffix = b"\n[output truncated]"
    return (value[: max(0, limit - len(suffix))] + suffix).decode(
        "utf-8",
        errors="replace",
    )
