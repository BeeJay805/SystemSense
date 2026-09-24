"""Inactive, bounded custody of one explicitly admitted local Ollama server.

This module does not acquire or release a host lease. Its required admission
callback must reserve the entire service lifetime before the suspended process
is resumed. The caller may release that reservation only after close reports
a verified empty Job; every other result requires quarantine.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import re
import subprocess
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol, cast
from urllib.parse import urlsplit

import psutil
import win32api
import win32con
import win32job
import win32process

from systemsense.inference.ollama import OllamaTransport
from systemsense.orchestration.windows_probe_job import WindowsProbeJob


class OwnedOllamaError(RuntimeError):
    """Startup failed; tree_exit_verified controls lifetime-lease disposition."""

    def __init__(
        self, message: str, *, tree_exit_verified: bool, admission_finalized: bool = False
    ) -> None:
        super().__init__(message)
        self.tree_exit_verified = tree_exit_verified
        self.admission_finalized = admission_finalized


@dataclass(frozen=True, slots=True)
class OwnedOllamaConfig:
    executable: Path
    executable_sha256: str
    models_dir: Path
    endpoint: str
    model: str
    model_digest: str
    startup_timeout_seconds: float = 15.0
    exit_timeout_seconds: float = 3.0

    def __post_init__(self) -> None:
        parsed = urlsplit(self.endpoint)
        if (
            parsed.scheme != "http"
            or parsed.hostname != "127.0.0.1"
            or parsed.path != "/api/chat"
            or parsed.query
            or parsed.fragment
            or parsed.username is not None
            or parsed.password is not None
            or parsed.port is None
            or not 1024 <= parsed.port <= 65535
        ):
            raise ValueError("endpoint must be a fixed IPv4 loopback Ollama chat URL")
        for name, path in (("executable", self.executable), ("models_dir", self.models_dir)):
            if not path.is_absolute() or path.resolve() != path:
                raise ValueError(f"{name} must be a canonical absolute path")
        if not re.fullmatch(r"[0-9a-f]{64}", self.executable_sha256):
            raise ValueError("executable SHA-256 must be pinned")
        if not re.fullmatch(r"[0-9a-f]{64}", self.model_digest):
            raise ValueError("model digest must be pinned")
        if (
            not self.model
            or len(self.model) > 120
            or "://" in self.model
            or "cloud" in self.model.casefold()
            or any(ch.isspace() for ch in self.model)
        ):
            raise ValueError("model must be a fixed local identifier")
        for value in (self.startup_timeout_seconds, self.exit_timeout_seconds):
            if not math.isfinite(value) or not 0 < value <= 30:
                raise ValueError("service deadlines must be finite and at most 30 seconds")

    @property
    def port(self) -> int:
        port = urlsplit(self.endpoint).port
        assert port is not None
        return port


@dataclass(frozen=True, slots=True)
class OwnedOllamaCloseResult:
    tree_exit_verified: bool
    admission_finalized: bool
    resume_attempted: bool


class _Process(Protocol):
    pid: int

    def poll(self) -> int | None: ...


class _Job(Protocol):
    def assign_suspended(self, process: Any) -> None: ...

    def resume_assigned(self, process: Any) -> None: ...

    def is_assigned_worker(self, process: Any) -> bool: ...

    def terminate_processes(self) -> None: ...

    def wait_until_empty(self, timeout_seconds: float) -> bool: ...

    def close(self) -> None: ...


def _listeners() -> Sequence[Any]:
    return psutil.net_connections(kind="tcp")


def _verify_process(process: _Process, executable: Path) -> bool:
    """Check the launched handle, process image and live incarnation."""
    handle = getattr(process, "_handle", None)
    process_api: Any = win32process
    if not isinstance(handle, int) or process_api.GetProcessId(handle) != process.pid:
        return False
    observed = psutil.Process(process.pid)
    return observed.is_running() and Path(observed.exe()).resolve() == executable


def _owns_listener(job: _Job, process: _Process, pid: int) -> bool:
    """Prove membership in the still-open private Job, including runner children."""
    if not job.is_assigned_worker(process):
        return False
    handle: Any = win32api.OpenProcess(win32con.PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    try:
        job_api: Any = win32job
        return bool(job_api.IsProcessInJob(handle, cast(Any, job)._job))
    finally:
        handle.Close()


def _launch(config: OwnedOllamaConfig) -> subprocess.Popen[bytes]:
    system_root = os.environ.get("SystemRoot")
    if not system_root:
        raise RuntimeError("Windows SystemRoot is unavailable")
    env = {
        "SystemRoot": system_root,
        "WINDIR": system_root,
        "PATH": f"{config.executable.parent};{Path(system_root) / 'System32'}",
        "OLLAMA_HOST": f"127.0.0.1:{config.port}",
        "OLLAMA_NO_CLOUD": "1",
        "OLLAMA_MODELS": str(config.models_dir),
        "OLLAMA_NUM_PARALLEL": "1",
        "OLLAMA_MAX_LOADED_MODELS": "1",
        "OLLAMA_KEEP_ALIVE": "0",
    }
    return subprocess.Popen(
        [str(config.executable), "serve"],
        cwd=config.executable.parent,
        env=env,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=win32con.CREATE_SUSPENDED | subprocess.CREATE_NO_WINDOW,
    )


def _inspect(config: OwnedOllamaConfig) -> bytes:
    return OllamaTransport(endpoint=config.endpoint).tags(
        timeout_seconds=min(config.startup_timeout_seconds, 2.0), max_response_bytes=65_536
    )


class OwnedOllamaService:
    """One-shot service: assign, admit, resume, prove ownership, then inspect."""

    def __init__(
        self,
        config: OwnedOllamaConfig,
        *,
        admit: Callable[[Any, Any], bool],
        finalize_admission: Callable[[bool, Any | None, Any | None], bool],
        launcher: Callable[..., _Process] | None = None,
        job_factory: Callable[[], _Job] | None = None,
        listeners: Callable[[], Sequence[Any]] = _listeners,
        owns_listener: Callable[[_Job, _Process, int], bool] = _owns_listener,
        inspect_models: Callable[[], bytes] | None = None,
        verify_process: Callable[[_Process, Path], bool] = _verify_process,
    ) -> None:
        self.config = config
        self._admit = admit
        self._finalize_admission = finalize_admission
        self._launcher = launcher or _launch
        self._job_factory = job_factory or cast(Callable[[], _Job], WindowsProbeJob)
        self._listeners = listeners
        self._owns_listener = owns_listener
        self._inspect_models = inspect_models or (lambda: _inspect(config))
        self._verify_process = verify_process
        self._job: _Job | None = None
        self._process: _Process | None = None
        self._started = False
        self._resume_attempted = False
        self._ready = False
        self._close_result: OwnedOllamaCloseResult | None = None

    @property
    def ready(self) -> bool:
        return self._ready and self._close_result is None

    def owns_ready_endpoint(self) -> bool:
        """Recheck the exact live root and Job-owned loopback listener for a call."""
        if not self.ready or self._job is None or self._process is None:
            return False
        try:
            if self._process.poll() is not None or not self._verify_process(
                self._process, self.config.executable
            ):
                return False
            found = self._port_listeners()
            return (
                len(found) == 1
                and found[0].laddr[0] == "127.0.0.1"
                and isinstance(found[0].pid, int)
                and self._owns_listener(self._job, self._process, found[0].pid)
            )
        except (OSError, RuntimeError, ValueError, AttributeError, psutil.Error):
            return False

    def start(self) -> None:
        if self._started or self._close_result is not None:
            raise OwnedOllamaError("owned service is one-shot", tree_exit_verified=False)
        self._started = True
        try:
            if not self.config.executable.is_file() or not self.config.models_dir.is_dir():
                raise RuntimeError("pinned executable or model directory is unavailable")
            with self.config.executable.open("rb") as binary:
                digest = hashlib.file_digest(binary, "sha256").hexdigest()
                if digest != self.config.executable_sha256:
                    raise RuntimeError("Ollama executable differs from the pinned SHA-256")
            if self._port_listeners():
                raise RuntimeError("endpoint already has a listener")
            self._job = self._job_factory()
            self._process = self._launcher(self.config)
            if not self._verify_process(self._process, self.config.executable):
                raise RuntimeError("launched Ollama process identity is unverified")
            with self.config.executable.open("rb") as binary:
                digest = hashlib.file_digest(binary, "sha256").hexdigest()
                if digest != self.config.executable_sha256:
                    raise RuntimeError("launched executable path changed after creation")
            self._job.assign_suspended(self._process)
            if not self._admit(self._process, self._job):
                raise RuntimeError("lifetime admission denied")
            self._resume_attempted = True
            self._job.resume_assigned(self._process)
            deadline = time.monotonic() + self.config.startup_timeout_seconds
            while True:
                if self._process.poll() is not None:
                    raise RuntimeError("owned Ollama server exited during startup")
                if not self._verify_process(self._process, self.config.executable):
                    raise RuntimeError("owned Ollama process identity changed")
                found = self._port_listeners()
                if found:
                    if len(found) != 1 or found[0].laddr[0] != "127.0.0.1":
                        raise RuntimeError("Ollama endpoint has an unowned listener")
                    pid = found[0].pid
                    if not isinstance(pid, int) or not self._owns_listener(
                        self._job, self._process, pid
                    ):
                        raise RuntimeError("Ollama listener Job ownership is unverified")
                    self._verify_model()
                    if time.monotonic() >= deadline:
                        raise RuntimeError("owned Ollama startup timed out")
                    confirmed = self._port_listeners()
                    if (
                        len(confirmed) != 1
                        or confirmed[0].pid != pid
                        or not self._owns_listener(self._job, self._process, pid)
                        or self._process.poll() is not None
                    ):
                        raise RuntimeError("Ollama endpoint ownership changed")
                    self._ready = True
                    return
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("owned Ollama startup timed out")
                time.sleep(min(0.02, remaining))
        except BaseException as error:
            result = self.close()
            raise OwnedOllamaError(
                str(error),
                tree_exit_verified=result.tree_exit_verified,
                admission_finalized=result.admission_finalized,
            ) from error

    def _port_listeners(self) -> list[Any]:
        return [
            item
            for item in self._listeners()
            if item.status == "LISTEN"
            and len(item.laddr) >= 2
            and item.laddr[1] == self.config.port
        ]

    def _verify_model(self) -> None:
        raw = self._inspect_models()
        if len(raw) > 65_536:
            raise RuntimeError("Ollama model list exceeds the byte limit")
        payload = cast(object, json.loads(raw))
        if not isinstance(payload, dict):
            raise RuntimeError("Ollama model list is invalid")
        envelope = cast(dict[str, object], payload)
        if not isinstance(envelope.get("models"), list):
            raise RuntimeError("Ollama model list is invalid")
        models = cast(list[object], envelope["models"])
        matches = [
            cast(dict[str, object], item)
            for item in models
            if isinstance(item, dict)
            and (
                cast(dict[str, object], item).get("name") == self.config.model
                or cast(dict[str, object], item).get("model") == self.config.model
            )
        ]
        if (
            len(matches) != 1
            or matches[0].get("digest") != self.config.model_digest
            or matches[0].get("remote_model")
            or matches[0].get("remote_host")
        ):
            raise RuntimeError("pinned local model digest is unavailable")

    def close(self) -> OwnedOllamaCloseResult:
        if self._close_result is not None:
            return self._close_result
        self._ready = False
        verified = self._process is None
        finalized = False
        job = self._job
        if job is not None:
            try:
                if self._process is not None:
                    if job.is_assigned_worker(self._process):
                        job.terminate_processes()
                        verified = job.wait_until_empty(self.config.exit_timeout_seconds)
                    else:
                        # Lost Job custody cannot prove tree exit, even if the
                        # root exits. Resume may have created runner children.
                        try:
                            job.terminate_processes()
                        except (OSError, RuntimeError):
                            pass
                        # The Popen handle still identifies only our root.
                        # This is best-effort cleanup, never a release proof.
                        process = cast(subprocess.Popen[bytes], self._process)
                        if process.poll() is None:
                            process.kill()
                            process.wait(timeout=self.config.exit_timeout_seconds)
                        verified = False
            except (OSError, RuntimeError, ValueError):
                verified = False
            finally:
                try:
                    finalized = self._finalize_admission(verified, job, self._process)
                except BaseException:
                    finalized = False
                try:
                    job.close()
                except (OSError, RuntimeError):
                    # Empty-tree proof was already collected while open.
                    pass
        else:
            try:
                finalized = self._finalize_admission(verified, None, None)
            except BaseException:
                finalized = False
        self._close_result = OwnedOllamaCloseResult(verified, finalized, self._resume_attempted)
        return self._close_result
