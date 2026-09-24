"""Admission telemetry must be fresh, bounded, and tied to one physical GPU."""

from __future__ import annotations

import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from systemsense.inference import host_telemetry

NOW = datetime(2026, 9, 23, 12, tzinfo=UTC)
GPU_UUID = "GPU-12345678-1234-1234-1234-123456789abc"


def _arrange(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    *,
    stdout: str = f"0, {GPU_UUID}, 8192\n",
    returncode: int = 0,
) -> list[tuple[list[str], dict[str, object]]]:
    executable = tmp_path / "nvidia-smi.exe"
    executable.touch()
    monkeypatch.setattr(host_telemetry, "_registered_nvidia_smi", lambda: executable)
    monkeypatch.setattr(
        host_telemetry.psutil,
        "virtual_memory",
        lambda: SimpleNamespace(available=16 * 1024**3),
    )
    monkeypatch.setattr(host_telemetry, "utc_now", lambda: NOW)
    calls: list[tuple[list[str], dict[str, object]]] = []

    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, returncode, stdout, "")

    monkeypatch.setattr(host_telemetry.subprocess, "run", run)
    return calls


def test_reads_exact_single_gpu_and_maps_to_resource_snapshot(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    calls = _arrange(monkeypatch, tmp_path)

    reading = host_telemetry.read_host_telemetry(gpu_device_index=0)
    snapshot = reading.to_resource_snapshot(
        active_sessions=1, active_fast_calls=0, active_deep_calls=1
    )

    assert reading.gpu_uuid == GPU_UUID
    assert reading.gpu_device_index == 0
    assert reading.free_vram_bytes == 8192 * 1024**2
    assert reading.available_ram_bytes == 16 * 1024**3
    assert reading.source_window_started_at == NOW
    assert reading.source_window_ended_at == NOW
    assert snapshot.free_vram_bytes == reading.free_vram_bytes
    assert snapshot.available_ram_bytes == reading.available_ram_bytes
    assert snapshot.gpu_device_index == 0
    assert snapshot.active_sessions == 1
    assert snapshot.active_deep_calls == 1
    argv, kwargs = calls[0]
    assert argv == [
        str(tmp_path / "nvidia-smi.exe"),
        "--query-gpu=index,uuid,memory.free",
        "--format=csv,noheader,nounits",
    ]
    assert kwargs["timeout"] == 2
    assert kwargs["shell"] is False
    environment = kwargs["env"]
    assert isinstance(environment, dict)
    assert "ProgramData" in environment
    assert "ProgramFiles" in environment


def test_resource_snapshot_uses_oldest_possible_measurement_time() -> None:
    reading = host_telemetry.HostTelemetryReading(
        source_window_started_at=NOW - timedelta(milliseconds=1000),
        source_window_ended_at=NOW,
        gpu_uuid=GPU_UUID,
        gpu_device_index=0,
        available_ram_bytes=16 * 1024**3,
        free_vram_bytes=8 * 1024**3,
    )
    snapshot = reading.to_resource_snapshot(
        active_sessions=0, active_fast_calls=0, active_deep_calls=0
    )
    assert snapshot.observed_at == reading.source_window_started_at


@pytest.mark.parametrize(
    ("stdout", "reason"),
    [
        ("", "gpu_output_invalid"),
        (
            f"0, {GPU_UUID}, 8192\n1, GPU-abcdefab-1234-1234-1234-123456789abc, 4096\n",
            "gpu_ambiguous",
        ),
        (f"1, {GPU_UUID}, 8192\n", "gpu_selection_mismatch"),
        (f"0, {GPU_UUID}, N/A\n", "gpu_output_invalid"),
        ("0, GPU-invalid, 8192\n", "gpu_output_invalid"),
        (f"0, {GPU_UUID}, 8192, extra\n", "gpu_output_invalid"),
        (f"0, {GPU_UUID}, -1\n", "gpu_output_invalid"),
    ],
)
def test_rejects_ambiguous_or_malformed_gpu_data(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
    stdout: str,
    reason: str,
) -> None:
    _arrange(monkeypatch, tmp_path, stdout=stdout)
    with pytest.raises(host_telemetry.HostTelemetryUnavailable, match=reason):
        host_telemetry.read_host_telemetry(gpu_device_index=0)


def test_rejects_missing_executable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(host_telemetry, "_registered_nvidia_smi", lambda: None)
    with pytest.raises(host_telemetry.HostTelemetryUnavailable, match="nvidia_smi_unavailable"):
        host_telemetry.read_host_telemetry(gpu_device_index=0)


def test_rejects_command_failure_and_timeout(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _arrange(monkeypatch, tmp_path, returncode=2)
    with pytest.raises(host_telemetry.HostTelemetryUnavailable, match="gpu_query_failed"):
        host_telemetry.read_host_telemetry(gpu_device_index=0)

    def timed_out(*args: object, **kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired("nvidia-smi", 2)

    monkeypatch.setattr(host_telemetry.subprocess, "run", timed_out)
    with pytest.raises(host_telemetry.HostTelemetryUnavailable, match="gpu_query_timeout"):
        host_telemetry.read_host_telemetry(gpu_device_index=0)


def test_rejects_stale_or_backward_clock_source_interval(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _arrange(monkeypatch, tmp_path)
    times = iter((NOW, NOW + timedelta(seconds=3)))
    monkeypatch.setattr(host_telemetry, "utc_now", lambda: next(times))
    with pytest.raises(host_telemetry.HostTelemetryUnavailable, match="source_interval_stale"):
        host_telemetry.read_host_telemetry(gpu_device_index=0)

    times = iter((NOW, NOW - timedelta(seconds=1)))
    monkeypatch.setattr(host_telemetry, "utc_now", lambda: next(times))
    with pytest.raises(host_telemetry.HostTelemetryUnavailable, match="source_interval_stale"):
        host_telemetry.read_host_telemetry(gpu_device_index=0)


def test_rejects_unavailable_ram(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _arrange(monkeypatch, tmp_path)
    monkeypatch.setattr(
        host_telemetry.psutil,
        "virtual_memory",
        lambda: SimpleNamespace(available=None),
    )
    with pytest.raises(host_telemetry.HostTelemetryUnavailable, match="ram_unavailable"):
        host_telemetry.read_host_telemetry(gpu_device_index=0)


@pytest.mark.parametrize("elapsed_seconds", [-1, 2.001])
def test_reading_rejects_invalid_source_interval_when_constructed_directly(
    elapsed_seconds: float,
) -> None:
    with pytest.raises(ValidationError, match="source interval"):
        host_telemetry.HostTelemetryReading(
            source_window_started_at=NOW,
            source_window_ended_at=NOW + timedelta(seconds=elapsed_seconds),
            gpu_uuid=GPU_UUID,
            gpu_device_index=0,
            available_ram_bytes=16 * 1024**3,
            free_vram_bytes=8192 * 1024**2,
        )


def test_executable_resolution_ignores_poisoned_environment(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    trusted_directory = tmp_path / "trusted" / "System32"
    trusted_directory.mkdir(parents=True)
    trusted_executable = trusted_directory / "nvidia-smi.exe"
    trusted_executable.touch()
    attacker_root = tmp_path / "attacker"
    poisoned_executable = attacker_root / "System32" / "nvidia-smi.exe"
    poisoned_executable.parent.mkdir(parents=True)
    poisoned_executable.touch()
    monkeypatch.setenv("SystemRoot", str(attacker_root))
    monkeypatch.setenv("ProgramFiles", str(attacker_root))
    monkeypatch.setattr(host_telemetry, "_system_directory", lambda: trusted_directory)
    monkeypatch.setattr(
        host_telemetry.psutil,
        "virtual_memory",
        lambda: SimpleNamespace(available=16 * 1024**3),
    )
    monkeypatch.setattr(host_telemetry, "utc_now", lambda: NOW)
    calls: list[tuple[list[str], dict[str, object]]] = []

    def run(argv: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, f"0, {GPU_UUID}, 8192\n", "")

    monkeypatch.setattr(host_telemetry.subprocess, "run", run)
    reading = host_telemetry.read_host_telemetry(gpu_device_index=0)

    assert reading.gpu_uuid == GPU_UUID
    assert calls[0][0][0] == str(trusted_executable)
    environment = calls[0][1]["env"]
    assert isinstance(environment, dict)
    assert environment["SystemRoot"] == str(trusted_directory.parent)
    assert str(attacker_root) not in environment["PATH"]

    trusted_executable.unlink()
    with pytest.raises(host_telemetry.HostTelemetryUnavailable, match="nvidia_smi_unavailable"):
        host_telemetry.read_host_telemetry(gpu_device_index=0)
