"""Bounded read-only host telemetry for future model admission.

This supplies a source-bound measurement, not a resource reservation. The
coordinator must separately own concurrency counts, leases, and admission.
"""

from __future__ import annotations

import ctypes
import os
import re
import subprocess
import time
from pathlib import Path

import psutil
from pydantic import Field, model_validator

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.time import UtcDateTime, utc_now
from systemsense.inference.host_resources import HostResourceSnapshot

_MIB = 1024**2
_MAX_MEMORY_BYTES = 512 * 1024**3
_QUERY_TIMEOUT_SECONDS = 2
_MAX_SOURCE_INTERVAL_MS = 2000
_MAX_OUTPUT_CHARS = 256
_GPU_UUID = re.compile(
    r"GPU-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)


class HostTelemetryUnavailable(ValueError):
    """The complete RAM/GPU observation cannot safely support admission."""


class HostTelemetryReading(FrozenModel):
    """One bounded host reading, with explicit source identity and time window."""

    source_window_started_at: UtcDateTime
    source_window_ended_at: UtcDateTime
    source: str = "psutil.virtual_memory+nvidia-smi"
    gpu_uuid: str = Field(pattern=_GPU_UUID.pattern)
    gpu_device_index: int = Field(ge=0, le=15)
    available_ram_bytes: int = Field(gt=0, le=_MAX_MEMORY_BYTES)
    free_vram_bytes: int = Field(ge=0, le=_MAX_MEMORY_BYTES)
    limitation: str = "GPU sample instant is unknown within the bounded query interval"

    @model_validator(mode="after")
    def validate_source_interval(self) -> HostTelemetryReading:
        interval_ms = (
            self.source_window_ended_at - self.source_window_started_at
        ).total_seconds() * 1000
        if not 0 <= interval_ms <= _MAX_SOURCE_INTERVAL_MS:
            raise ValueError("source interval is invalid or stale")
        return self

    def to_resource_snapshot(
        self,
        *,
        active_sessions: int,
        active_fast_calls: int,
        active_deep_calls: int,
    ) -> HostResourceSnapshot:
        """Map measurements only; caller must supply its trusted activity counts."""

        return HostResourceSnapshot(
            observed_at=self.source_window_started_at,
            available_ram_bytes=self.available_ram_bytes,
            free_vram_bytes=self.free_vram_bytes,
            gpu_device_index=self.gpu_device_index,
            active_sessions=active_sessions,
            active_fast_calls=active_fast_calls,
            active_deep_calls=active_deep_calls,
        )


def _system_directory() -> Path | None:
    """Read System32 from the Windows API, never from process environment."""

    if os.name != "nt":
        return None
    try:
        buffer = ctypes.create_unicode_buffer(32_768)
        getter = ctypes.WinDLL("kernel32.dll", use_last_error=True).GetSystemDirectoryW
        getter.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
        getter.restype = ctypes.c_uint
        length = getter(buffer, len(buffer))
    except (AttributeError, OSError, ValueError):
        return None
    if not 0 < length < len(buffer):
        return None
    directory = Path(buffer.value)
    if not directory.is_absolute() or directory.name.casefold() != "system32":
        return None
    return directory


def _registered_nvidia_smi() -> Path | None:
    """Resolve NVIDIA's binary only within the OS-reported System32 folder."""

    directory = _system_directory()
    if directory is None:
        return None
    candidate = directory / "nvidia-smi.exe"
    return candidate if candidate.is_file() and not candidate.is_symlink() else None


def _nvidia_environment(executable: Path) -> dict[str, str]:
    system_directory = executable.parent
    system_root = system_directory.parent
    volume_root = Path(system_directory.anchor)
    return {
        "PATH": str(system_directory),
        "ProgramData": str(volume_root / "ProgramData"),
        "ProgramFiles": str(volume_root / "Program Files"),
        "SystemRoot": str(system_root),
        "WINDIR": str(system_root),
    }


def _parse_gpu_row(stdout: str, selected_index: int) -> tuple[str, int]:
    if len(stdout) > _MAX_OUTPUT_CHARS:
        raise HostTelemetryUnavailable("gpu_output_invalid")
    lines = stdout.splitlines()
    if len(lines) > 1:
        raise HostTelemetryUnavailable("gpu_ambiguous")
    if len(lines) != 1:
        raise HostTelemetryUnavailable("gpu_output_invalid")
    parts = [part.strip() for part in lines[0].split(",")]
    if len(parts) != 3:
        raise HostTelemetryUnavailable("gpu_output_invalid")
    index_text, gpu_uuid, free_mib_text = parts
    if (
        not index_text.isascii()
        or not index_text.isdecimal()
        or not _GPU_UUID.fullmatch(gpu_uuid)
        or not free_mib_text.isascii()
        or not free_mib_text.isdecimal()
    ):
        raise HostTelemetryUnavailable("gpu_output_invalid")
    index = int(index_text)
    free_bytes = int(free_mib_text) * _MIB
    if index > 15 or free_bytes > _MAX_MEMORY_BYTES:
        raise HostTelemetryUnavailable("gpu_output_invalid")
    if index != selected_index:
        raise HostTelemetryUnavailable("gpu_selection_mismatch")
    return gpu_uuid, free_bytes


def read_host_telemetry(*, gpu_device_index: int) -> HostTelemetryReading:
    """Read RAM and one NVIDIA GPU via fixed, non-shell, bounded CLI query.

    Multiple GPUs deliberately fail closed until a cross-device selection and
    identity policy exists. This function never loads, unloads, or reserves a
    model and does not mutate the host.
    """

    if type(gpu_device_index) is not int or not 0 <= gpu_device_index <= 15:
        raise HostTelemetryUnavailable("gpu_selection_invalid")
    executable = _registered_nvidia_smi()
    if executable is None:
        raise HostTelemetryUnavailable("nvidia_smi_unavailable")
    source_started_at = utc_now()
    monotonic_started = time.monotonic()
    try:
        available_ram = psutil.virtual_memory().available
    except (OSError, RuntimeError) as error:
        raise HostTelemetryUnavailable("ram_unavailable") from error
    if type(available_ram) is not int or not 0 < available_ram <= _MAX_MEMORY_BYTES:
        raise HostTelemetryUnavailable("ram_unavailable")
    creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    try:
        completed = subprocess.run(
            [
                str(executable),
                "--query-gpu=index,uuid,memory.free",
                "--format=csv,noheader,nounits",
            ],
            check=False,
            shell=False,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="strict",
            timeout=_QUERY_TIMEOUT_SECONDS,
            creationflags=creation_flags,
            env=_nvidia_environment(executable),
            cwd=str(executable.parent),
        )
    except subprocess.TimeoutExpired as error:
        raise HostTelemetryUnavailable("gpu_query_timeout") from error
    except (OSError, UnicodeError) as error:
        raise HostTelemetryUnavailable("gpu_query_failed") from error
    source_ended_at = utc_now()
    interval_ms = (source_ended_at - source_started_at).total_seconds() * 1000
    monotonic_ms = (time.monotonic() - monotonic_started) * 1000
    clock_interval_valid = 0 <= interval_ms <= _MAX_SOURCE_INTERVAL_MS
    elapsed_interval_valid = 0 <= monotonic_ms <= _MAX_SOURCE_INTERVAL_MS
    if not clock_interval_valid or not elapsed_interval_valid:
        raise HostTelemetryUnavailable("source_interval_stale")
    if completed.returncode != 0:
        raise HostTelemetryUnavailable("gpu_query_failed")
    gpu_uuid, free_vram = _parse_gpu_row(completed.stdout, gpu_device_index)
    return HostTelemetryReading(
        source_window_started_at=source_started_at,
        source_window_ended_at=source_ended_at,
        gpu_uuid=gpu_uuid,
        gpu_device_index=gpu_device_index,
        available_ram_bytes=available_ram,
        free_vram_bytes=free_vram,
    )
