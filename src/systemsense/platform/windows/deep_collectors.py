"""Fixed, bounded, read-only Windows inventory and incident collectors.

The public collection functions have no caller-controlled query, registry path,
filesystem path, executable, or network target.  Native APIs are used only with
the constants in this module and failures remain explicit component data.
"""

from __future__ import annotations

import csv
import importlib
import io
import os
import re
import socket
import subprocess
import time
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta, timezone
from enum import StrEnum
from pathlib import Path
from typing import Any, Literal, Protocol, cast

import psutil
from pydantic import Field, computed_field, model_validator

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import JsonValue
from systemsense.domain.time import UtcDateTime, utc_now
from systemsense.packs.network.routes import RouteObservation, WmiRouteBackend
from systemsense.platform.windows.eventlog import (
    FixedEventLogAdapter,
    PyWin32EventLogBackend,
    QueryStatus,
    WindowsEvent,
)


class ComponentStatus(StrEnum):
    AVAILABLE = "available"
    PARTIAL = "partial"
    UNSUPPORTED = "unsupported"
    PERMISSION_DENIED = "permission_denied"
    FAILED = "failed"


_LISTENER_INTERVAL_LIMITATION = (
    "listener table and process owners were read sequentially; "
    "owners may have changed after the table query"
)


class _CollectionInterval(FrozenModel):
    collection_started_at: UtcDateTime | None = None
    captured_at: UtcDateTime

    @model_validator(mode="after")
    def validate_collection_interval(self) -> _CollectionInterval:
        if self.collection_started_at is not None and self.captured_at < self.collection_started_at:
            raise ValueError("collection completion precedes query start")
        return self


class StorageVolume(FrozenModel):
    volume_id: str = Field(min_length=1, max_length=4096)
    filesystem: str | None = Field(default=None, max_length=64)
    label: str | None = Field(default=None, max_length=1024)
    total_bytes: int | None = Field(default=None, ge=0)
    free_bytes: int | None = Field(default=None, ge=0)
    status: ComponentStatus = ComponentStatus.AVAILABLE


class DiskPartition(FrozenModel):
    partition_id: str = Field(min_length=1, max_length=4096)
    disk_index: int = Field(ge=0)


class PhysicalDisk(FrozenModel):
    disk_index: int = Field(ge=0)
    device_id: str = Field(min_length=1, max_length=4096)
    model: str | None = Field(default=None, max_length=1024)
    serial_number: str | None = Field(default=None, max_length=1024)
    interface_type: str | None = Field(default=None, max_length=255)
    media_type: str | None = Field(default=None, max_length=255)
    size_bytes: int | None = Field(default=None, ge=0)
    status: str | None = Field(default=None, max_length=255)


class VolumeDiskMapping(FrozenModel):
    volume_id: str = Field(min_length=1, max_length=4096)
    partition_id: str = Field(min_length=1, max_length=4096)
    disk_index: int = Field(ge=0)


class ReliabilityCounter(FrozenModel):
    disk_index: int = Field(ge=0)
    status: ComponentStatus
    temperature_c: int | None = None
    wear_percent: int | None = Field(default=None, ge=0, le=100)
    read_errors_total: int | None = Field(default=None, ge=0)
    write_errors_total: int | None = Field(default=None, ge=0)
    limitation: str | None = Field(default=None, max_length=1000)


class StorageSnapshot(_CollectionInterval):
    volumes: tuple[StorageVolume, ...]
    partitions: tuple[DiskPartition, ...]
    physical_disks: tuple[PhysicalDisk, ...]
    volume_mappings: tuple[VolumeDiskMapping, ...]
    reliability: tuple[ReliabilityCounter, ...]
    status: ComponentStatus
    limitations: tuple[str, ...] = ()


def join_storage_topology(
    *,
    volumes: tuple[StorageVolume, ...],
    partitions: tuple[DiskPartition, ...],
    disks: tuple[PhysicalDisk, ...],
    volume_to_partition: Mapping[str, str],
    reliability: tuple[ReliabilityCounter, ...],
    captured_at: UtcDateTime | None = None,
    collection_started_at: UtcDateTime | None = None,
    limitations: tuple[str, ...] = (),
) -> StorageSnapshot:
    partition_by_id = {item.partition_id.casefold(): item for item in partitions}
    disk_indices = {item.disk_index for item in disks}
    mappings: list[VolumeDiskMapping] = []
    for volume in volumes:
        partition_id = volume_to_partition.get(volume.volume_id)
        if partition_id is None:
            continue
        partition = partition_by_id.get(partition_id.casefold())
        if partition is None or partition.disk_index not in disk_indices:
            continue
        mappings.append(
            VolumeDiskMapping(
                volume_id=volume.volume_id,
                partition_id=partition.partition_id,
                disk_index=partition.disk_index,
            )
        )
    by_disk = {item.disk_index: item for item in reliability}
    normalized_reliability = tuple(
        by_disk.get(
            disk.disk_index,
            ReliabilityCounter(
                disk_index=disk.disk_index,
                status=ComponentStatus.UNSUPPORTED,
                limitation="storage reliability counters were not exposed for this disk",
            ),
        )
        for disk in disks
    )
    status = ComponentStatus.AVAILABLE
    if (
        limitations
        or not volumes
        or not disks
        or len(mappings) < len(volumes)
        or any(item.status is not ComponentStatus.AVAILABLE for item in normalized_reliability)
    ):
        status = ComponentStatus.PARTIAL
    return StorageSnapshot(
        collection_started_at=collection_started_at,
        captured_at=captured_at or utc_now(),
        volumes=volumes[:64],
        partitions=partitions[:128],
        physical_disks=disks[:64],
        volume_mappings=tuple(mappings[:128]),
        reliability=normalized_reliability[:64],
        status=status,
        limitations=limitations,
    )


class ProcessTopology(FrozenModel):
    pid: int = Field(gt=0)
    ppid: int = Field(ge=0)
    name: str = Field(min_length=1, max_length=255)
    creation_time: UtcDateTime
    executable: str | None = Field(default=None, max_length=32_768)
    username: str | None = Field(default=None, max_length=1024)
    status: str | None = Field(default=None, max_length=64)

    @computed_field
    @property
    def identity(self) -> str:
        return f"{self.pid}@{self.creation_time.isoformat()}"


class ServiceTopology(FrozenModel):
    name: str = Field(min_length=1, max_length=255)
    display_name: str = Field(min_length=1, max_length=1024)
    state: str = Field(min_length=1, max_length=64)
    start_mode: str = Field(min_length=1, max_length=64)
    process_id: int | None = Field(default=None, ge=0)
    dependencies: tuple[str, ...] = ()
    account: str | None = Field(default=None, max_length=1024)
    binary_path: str | None = Field(default=None, max_length=32_768)


class StartupEntry(FrozenModel):
    name: str = Field(min_length=1, max_length=1024)
    command: str = Field(min_length=1, max_length=32_768)
    location: str | None = Field(default=None, max_length=4096)
    user: str | None = Field(default=None, max_length=1024)


class ApplicationTopologySnapshot(_CollectionInterval):
    boot_time: UtcDateTime
    processes: tuple[ProcessTopology, ...]
    services: tuple[ServiceTopology, ...]
    startup: tuple[StartupEntry, ...]
    omitted_process_count: int = Field(ge=0)
    omitted_service_count: int = Field(ge=0)
    omitted_startup_count: int = Field(ge=0)
    status: ComponentStatus
    limitations: tuple[str, ...] = ()


def normalize_application_topology(
    *,
    processes: tuple[ProcessTopology, ...],
    services: tuple[ServiceTopology, ...],
    startup: tuple[StartupEntry, ...],
    max_processes: int = 256,
    max_services: int = 512,
    max_startup: int = 256,
    captured_at: UtcDateTime | None = None,
    collection_started_at: UtcDateTime | None = None,
    limitations: tuple[str, ...] = (),
) -> ApplicationTopologySnapshot:
    for value in (max_processes, max_services, max_startup):
        if not 1 <= value <= 1024:
            raise ValueError("application topology limits must be between 1 and 1024")
    omitted_processes = max(0, len(processes) - max_processes)
    omitted_services = max(0, len(services) - max_services)
    omitted_startup = max(0, len(startup) - max_startup)
    normalized_limitations = list(limitations)
    if omitted_processes:
        normalized_limitations.append("process limit reached")
    if omitted_services:
        normalized_limitations.append("service limit reached")
    if omitted_startup:
        normalized_limitations.append("startup-entry limit reached")
    boot_time = datetime.fromtimestamp(psutil.boot_time(), tz=UTC)
    return ApplicationTopologySnapshot(
        collection_started_at=collection_started_at,
        captured_at=captured_at or utc_now(),
        boot_time=boot_time,
        processes=tuple(sorted(processes, key=lambda item: (item.pid, item.creation_time)))[
            :max_processes
        ],
        services=tuple(sorted(services, key=lambda item: item.name.casefold()))[:max_services],
        startup=tuple(sorted(startup, key=lambda item: item.name.casefold()))[:max_startup],
        omitted_process_count=omitted_processes,
        omitted_service_count=omitted_services,
        omitted_startup_count=omitted_startup,
        status=(
            ComponentStatus.AVAILABLE
            if processes
            and services
            and not (omitted_processes or omitted_services or omitted_startup)
            else ComponentStatus.PARTIAL
        ),
        limitations=tuple(normalized_limitations),
    )


class AdapterConfiguration(FrozenModel):
    interface_index: int = Field(ge=0)
    description: str = Field(min_length=1, max_length=1024)
    dhcp_enabled: bool | None = None
    dns_servers: tuple[str, ...] = ()
    default_gateways: tuple[str, ...] = ()


class ProxyConfiguration(FrozenModel):
    enabled: bool | None = None
    server: str | None = Field(default=None, max_length=4096)
    status: ComponentStatus


class NetworkConfigurationSnapshot(_CollectionInterval):
    routes: tuple[RouteObservation, ...]
    adapters: tuple[AdapterConfiguration, ...]
    proxy: ProxyConfiguration
    status: ComponentStatus
    limitations: tuple[str, ...] = ()


class NetworkListener(FrozenModel):
    protocol: str = Field(pattern=r"^tcp[46]$")
    local_address: str = Field(min_length=1, max_length=255)
    local_port: int = Field(ge=0, le=65_535)
    pid: int | None = Field(default=None, ge=0)
    process_name: str | None = Field(default=None, max_length=255)
    process_creation_time: UtcDateTime | None = None
    owner_status: ComponentStatus


class NetworkListenerSnapshot(_CollectionInterval):
    listener_table_started_at: UtcDateTime | None = None
    listener_table_completed_at: UtcDateTime | None = None
    listeners: tuple[NetworkListener, ...]
    omitted_listener_count: int = Field(ge=0)
    status: ComponentStatus
    limitations: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_listener_table_interval(self) -> NetworkListenerSnapshot:
        if self.listener_table_started_at is None and self.listener_table_completed_at is None:
            return self
        if self.listener_table_started_at is None or self.listener_table_completed_at is None:
            raise ValueError("listener table interval requires both bounds")
        if self.listener_table_completed_at < self.listener_table_started_at:
            raise ValueError("listener table completion precedes query start")
        if (
            self.collection_started_at is not None
            and self.listener_table_started_at < self.collection_started_at
        ):
            raise ValueError("listener table started before collection")
        if self.captured_at < self.listener_table_completed_at:
            raise ValueError("collection completed before listener table")
        return self


class PowerSnapshot(_CollectionInterval):
    ac_line_status: str
    battery_percent: int | None = Field(default=None, ge=0, le=100)
    battery_seconds_remaining: int | None = Field(default=None, ge=0)
    active_scheme_guid: str | None = Field(default=None, max_length=64)
    processors: tuple[dict[str, JsonValue], ...] = ()
    status: ComponentStatus
    limitations: tuple[str, ...] = ()


class SecuritySnapshot(_CollectionInterval):
    antivirus_products: tuple[dict[str, JsonValue], ...] = ()
    firewall_profiles: tuple[dict[str, JsonValue], ...] = ()
    uac_enabled: bool | None = None
    status: ComponentStatus
    limitations: tuple[str, ...] = ()


class PressureProcessObservation(FrozenModel):
    pid: int = Field(gt=0)
    name: str = Field(min_length=1, max_length=255)
    creation_time: UtcDateTime
    cpu_percent: float | None = Field(default=None, ge=0, le=100)
    rss_bytes: int = Field(ge=0)
    read_bytes_delta: int | None = Field(default=None, ge=0)
    write_bytes_delta: int | None = Field(default=None, ge=0)

    @computed_field
    @property
    def identity(self) -> str:
        return f"{self.pid}@{self.creation_time.isoformat()}"


class PressureSample(FrozenModel):
    collection_started_at: UtcDateTime | None = None
    observed_at: UtcDateTime
    system_cpu_percent: float | None = Field(default=None, ge=0, le=100)
    per_cpu_percent: tuple[float | None, ...]
    memory_percent: float = Field(ge=0, le=100)
    memory_available_bytes: int = Field(ge=0)
    swap_percent: float = Field(ge=0, le=100)
    disk_read_bytes_delta: int | None = Field(default=None, ge=0)
    disk_write_bytes_delta: int | None = Field(default=None, ge=0)
    processes: tuple[PressureProcessObservation, ...]
    omitted_process_count: int = Field(ge=0)

    @model_validator(mode="after")
    def validate_collection_interval(self) -> PressureSample:
        if self.collection_started_at is not None and self.observed_at < self.collection_started_at:
            raise ValueError("pressure frame completion precedes query start")
        return self


class PressureSnapshot(FrozenModel):
    captured_at: UtcDateTime
    window_started_at: UtcDateTime
    window_ended_at: UtcDateTime
    inter_sample_delay_seconds: float = Field(gt=0, le=5)
    samples: tuple[PressureSample, ...]
    status: ComponentStatus
    limitations: tuple[str, ...] = ()


class TargetPressureStatus(StrEnum):
    AVAILABLE = "available"
    PARTIAL = "partial"
    UNAVAILABLE = "unavailable"
    PERMISSION_DENIED = "permission_denied"
    REUSED = "reused"


class TargetPressureClockRollback(RuntimeError):
    """UTC provenance cannot be ordered, so no target evidence may be emitted."""


class TargetPressureSample(FrozenModel):
    query_started_at: UtcDateTime
    observed_at: UtcDateTime
    status: TargetPressureStatus
    delta_status: Literal["baseline", "measured", "partial", "unavailable"]
    name: str | None = Field(default=None, max_length=255)
    cpu_percent: float | None = Field(default=None, ge=0, le=100)
    rss_bytes: int | None = Field(default=None, ge=0)
    read_bytes_delta: int | None = Field(default=None, ge=0)
    write_bytes_delta: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def validate_times(self) -> TargetPressureSample:
        if self.observed_at < self.query_started_at:
            raise ValueError("target sample completion precedes query start")
        return self


class TargetPressureSnapshot(FrozenModel):
    target_pid: int = Field(gt=0)
    target_creation_time: UtcDateTime
    window_started_at: UtcDateTime
    window_ended_at: UtcDateTime
    captured_at: UtcDateTime
    inter_sample_delay_seconds: float = Field(default=1.0, ge=1.0, le=1.0)
    samples: tuple[TargetPressureSample, ...] = Field(min_length=1, max_length=3)
    status: TargetPressureStatus
    limitations: tuple[str, ...] = ()

    @model_validator(mode="after")
    def validate_times(self) -> TargetPressureSnapshot:
        if not self.window_started_at <= self.window_ended_at <= self.captured_at:
            raise ValueError("target pressure collection times are out of order")
        return self


@dataclass(frozen=True)
class _TargetCounter:
    name: str
    cpu_seconds: float
    rss_bytes: int
    read_bytes: int | None
    write_bytes: int | None


@dataclass(frozen=True)
class _CpuCounter:
    total: float
    busy: float


@dataclass(frozen=True)
class _ProcessCounter:
    pid: int
    name: str
    creation_time: UtcDateTime
    cpu_seconds: float
    rss_bytes: int
    read_bytes: int | None
    write_bytes: int | None


@dataclass(frozen=True)
class _PressureFrame:
    observed_at: UtcDateTime
    cpus: tuple[_CpuCounter, ...]
    memory_percent: float
    memory_available_bytes: int
    swap_percent: float
    disk_read_bytes: int | None
    disk_write_bytes: int | None
    processes: tuple[_ProcessCounter, ...]
    omitted_process_count: int
    collection_started_at: UtcDateTime | None = None


class NvidiaGpuTelemetry(FrozenModel):
    index: int = Field(ge=0)
    uuid: str = Field(min_length=1, max_length=255)
    name: str = Field(min_length=1, max_length=1024)
    driver_version: str | None = Field(default=None, max_length=255)
    utilization_percent: int | None = Field(default=None, ge=0, le=100)
    memory_used_mib: float | None = Field(default=None, ge=0)
    memory_free_mib: float | None = Field(default=None, ge=0)
    temperature_c: float | None = None
    power_draw_w: float | None = Field(default=None, ge=0)
    power_limit_w: float | None = Field(default=None, ge=0)
    graphics_clock_mhz: float | None = Field(default=None, ge=0)
    memory_clock_mhz: float | None = Field(default=None, ge=0)
    throttle_reasons_active: str | None = Field(default=None, max_length=255)


class NvidiaTelemetrySnapshot(FrozenModel):
    sample_started_at: UtcDateTime | None = None
    captured_at: UtcDateTime
    status: ComponentStatus
    gpus: tuple[NvidiaGpuTelemetry, ...] = ()
    limitation: str | None = Field(default=None, max_length=1000)

    @model_validator(mode="after")
    def validate_sample_interval(self) -> NvidiaTelemetrySnapshot:
        if self.sample_started_at is not None and self.captured_at < self.sample_started_at:
            raise ValueError("GPU telemetry completion precedes query start")
        return self


class NvidiaTelemetrySeries(FrozenModel):
    captured_at: UtcDateTime
    window_started_at: UtcDateTime
    window_ended_at: UtcDateTime
    inter_sample_delay_seconds: float = Field(gt=0, le=5)
    samples: tuple[NvidiaTelemetrySnapshot, ...]
    status: ComponentStatus
    limitations: tuple[str, ...] = ()


_NVIDIA_QUERY_FIELDS = (
    "index",
    "uuid",
    "name",
    "driver_version",
    "utilization.gpu",
    "memory.used",
    "memory.free",
    "temperature.gpu",
    "power.draw",
    "power.limit",
    "clocks.gr",
    "clocks.mem",
    "clocks_throttle_reasons.active",
)


def parse_nvidia_smi_csv(text: str) -> tuple[NvidiaGpuTelemetry, ...]:
    records: list[NvidiaGpuTelemetry] = []
    for row in csv.reader(io.StringIO(text)):
        values = [value.strip() for value in row]
        if len(values) != len(_NVIDIA_QUERY_FIELDS):
            continue
        index = _int(values[0])
        if index is None or index < 0 or not values[1] or not values[2]:
            continue
        records.append(
            NvidiaGpuTelemetry(
                index=index,
                uuid=values[1],
                name=values[2],
                driver_version=_optional_text(values[3]),
                utilization_percent=_int(_optional_text(values[4])),
                memory_used_mib=_float(_optional_text(values[5])),
                memory_free_mib=_float(_optional_text(values[6])),
                temperature_c=_float(_optional_text(values[7])),
                power_draw_w=_float(_optional_text(values[8])),
                power_limit_w=_float(_optional_text(values[9])),
                graphics_clock_mhz=_float(_optional_text(values[10])),
                memory_clock_mhz=_float(_optional_text(values[11])),
                throttle_reasons_active=_optional_text(values[12]),
            )
        )
        if len(records) >= 16:
            break
    return tuple(records)


def collect_nvidia_telemetry() -> NvidiaTelemetrySnapshot:
    executable = next((path for path in _nvidia_smi_candidates() if path.is_file()), None)
    if executable is None:
        return NvidiaTelemetrySnapshot(
            captured_at=utc_now(),
            status=ComponentStatus.UNSUPPORTED,
            limitation="nvidia-smi was not present at a registered system location",
        )
    query = ",".join(_NVIDIA_QUERY_FIELDS)
    creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    sample_started_at = utc_now()
    try:
        completed = subprocess.run(
            [
                str(executable),
                f"--query-gpu={query}",
                "--format=csv,noheader,nounits",
            ],
            check=False,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=3,
            creationflags=creation_flags,
            env=_nvidia_smi_environment(executable),
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        return NvidiaTelemetrySnapshot(
            sample_started_at=sample_started_at,
            captured_at=utc_now(),
            status=_exception_status(error),
            limitation=f"nvidia-smi telemetry unavailable: {type(error).__name__}",
        )
    captured_at = utc_now()
    if completed.returncode != 0:
        return NvidiaTelemetrySnapshot(
            sample_started_at=sample_started_at,
            captured_at=captured_at,
            status=ComponentStatus.FAILED,
            limitation=f"nvidia-smi exited with code {completed.returncode}",
        )
    records = parse_nvidia_smi_csv(completed.stdout)
    if not records:
        return NvidiaTelemetrySnapshot(
            sample_started_at=sample_started_at,
            captured_at=captured_at,
            status=ComponentStatus.UNSUPPORTED,
            limitation="nvidia-smi returned no parseable GPU telemetry",
        )
    return NvidiaTelemetrySnapshot(
        sample_started_at=sample_started_at,
        captured_at=captured_at,
        status=ComponentStatus.AVAILABLE,
        gpus=records,
        limitation="nvidia-smi sample instant is unknown within the bounded query interval",
    )


def collect_gpu_telemetry_sample() -> NvidiaTelemetrySeries:
    """Take three passive fixed NVIDIA samples without starting GPU work."""

    samples: list[NvidiaTelemetrySnapshot] = []
    for index in range(3):
        if index:
            time.sleep(0.5)
        samples.append(collect_nvidia_telemetry())
    available = sum(item.status is ComponentStatus.AVAILABLE for item in samples)
    if available == len(samples):
        status = ComponentStatus.AVAILABLE
    elif available:
        status = ComponentStatus.PARTIAL
    elif all(item.status is ComponentStatus.UNSUPPORTED for item in samples):
        status = ComponentStatus.UNSUPPORTED
    elif all(item.status is ComponentStatus.PERMISSION_DENIED for item in samples):
        status = ComponentStatus.PERMISSION_DENIED
    else:
        status = ComponentStatus.FAILED
    limitations = tuple(
        dict.fromkeys(item.limitation for item in samples if item.limitation is not None)
    )
    return NvidiaTelemetrySeries(
        captured_at=utc_now(),
        window_started_at=samples[0].sample_started_at or samples[0].captured_at,
        window_ended_at=samples[-1].captured_at,
        inter_sample_delay_seconds=0.5,
        samples=tuple(samples),
        status=status,
        limitations=limitations,
    )


def _nvidia_smi_candidates() -> tuple[Path, ...]:
    system_root = Path(os.environ.get("SystemRoot", r"C:\Windows"))
    program_files = Path(os.environ.get("ProgramFiles", r"C:\Program Files"))
    return (
        system_root / "System32" / "nvidia-smi.exe",
        program_files / "NVIDIA Corporation" / "NVSMI" / "nvidia-smi.exe",
    )


def _nvidia_smi_environment(executable: Path) -> dict[str, str]:
    system_root = os.environ.get("SystemRoot", r"C:\Windows")
    program_files = os.environ.get("ProgramFiles", r"C:\Program Files")
    program_data = os.environ.get("ProgramData", r"C:\ProgramData")
    return {
        "PATH": os.pathsep.join((str(executable.parent), str(Path(system_root) / "System32"))),
        "ProgramData": program_data,
        "ProgramFiles": program_files,
        "SystemRoot": system_root,
        "WINDIR": os.environ.get("WINDIR", system_root),
    }


def _optional_text(value: str) -> str | None:
    normalized = value.strip()
    if not normalized or normalized.casefold() in {
        "n/a",
        "[not supported]",
        "not supported",
        "unknown",
    }:
        return None
    return normalized


def _float(value: object) -> float | None:
    try:
        return None if value is None else float(cast(Any, value))
    except (TypeError, ValueError):
        return None


class IncidentProfileEvent(FrozenModel):
    profile: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$")
    channel: str
    provider: str
    event_id: int = Field(ge=0)
    record_id: int = Field(ge=0)
    level: int = Field(ge=0)
    observed_at: UtcDateTime
    event_data: dict[str, str]
    rendered_message: str | None = Field(default=None, max_length=16_384)
    source_id: str

    @classmethod
    def from_event(cls, event: WindowsEvent, *, profile: str) -> IncidentProfileEvent:
        return cls(
            profile=profile,
            channel=event.channel,
            provider=event.provider,
            event_id=event.event_id,
            record_id=event.record_id,
            level=event.level,
            observed_at=event.observed_at,
            event_data=event.event_data,
            rendered_message=event.rendered_message,
            source_id=event.source_id,
        )


_INCIDENT_PAIRS: dict[tuple[str, int], str] = {
    ("microsoft-windows-whea-logger", 1): "hardware",
    ("microsoft-windows-whea-logger", 17): "hardware",
    ("microsoft-windows-whea-logger", 18): "hardware",
    ("microsoft-windows-whea-logger", 19): "hardware",
    ("microsoft-windows-kernel-power", 41): "power",
    ("microsoft-windows-kernel-power", 42): "power",
    ("microsoft-windows-kernel-power", 105): "power",
    ("disk", 7): "storage",
    ("disk", 51): "storage",
    ("disk", 153): "storage",
    ("ntfs", 55): "storage",
    ("microsoft-windows-ntfs", 55): "storage",
    ("microsoft-windows-storport", 129): "storage",
    ("service control manager", 7000): "service",
    ("service control manager", 7001): "service",
    ("service control manager", 7009): "service",
    ("service control manager", 7031): "service",
    ("service control manager", 7034): "service",
    ("application error", 1000): "application",
    ("application hang", 1002): "application",
    ("windows error reporting", 1001): "application",
}


def filter_incident_events(
    events: Iterable[WindowsEvent], *, max_records: int = 128
) -> tuple[IncidentProfileEvent, ...]:
    if not 1 <= max_records <= 512:
        raise ValueError("max_records must be between 1 and 512")
    selected = [
        IncidentProfileEvent.from_event(event, profile=profile)
        for event in events
        if (profile := _INCIDENT_PAIRS.get((event.provider.casefold(), event.event_id))) is not None
    ]
    return tuple(sorted(selected, key=lambda item: (item.observed_at, item.record_id)))[
        -max_records:
    ]


class IncidentEventSnapshot(_CollectionInterval):
    events: tuple[IncidentProfileEvent, ...]
    channel_status: dict[str, ComponentStatus]
    limitations: tuple[str, ...] = ()


class _WmiService(Protocol):
    def ExecQuery(self, query: str) -> Iterable[object]: ...


def _wmi_service(namespace: str) -> _WmiService:
    client = cast(Any, importlib.import_module("win32com.client"))
    return cast(_WmiService, client.GetObject(rf"winmgmts:\\.\{namespace}"))


def _attr(row: object, name: str, default: object = None) -> object:
    return getattr(row, name, default)


def _int(value: object) -> int | None:
    try:
        return None if value is None else int(cast(Any, value))
    except (TypeError, ValueError):
        return None


def _nonnegative_int(value: object) -> int | None:
    parsed = _int(value)
    return parsed if parsed is not None and parsed >= 0 else None


def _strings(value: object) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    try:
        return tuple(str(item) for item in cast(Iterable[object], value))
    except TypeError:
        return ()


def _exception_status(error: BaseException) -> ComponentStatus:
    return (
        ComponentStatus.PERMISSION_DENIED
        if isinstance(error, PermissionError) or getattr(error, "winerror", None) == 5
        else ComponentStatus.FAILED
    )


_ASSOCIATION_VALUE = re.compile(r'="(?P<value>[^"]+)"')
_DMTF_DATETIME = re.compile(
    r"^(?P<stamp>\d{14})\.(?P<microseconds>\d{6})(?P<sign>[+-])(?P<offset>\d{3})$"
)


def parse_wmi_datetime(value: str) -> UtcDateTime | None:
    match = _DMTF_DATETIME.fullmatch(value)
    if match is None:
        return None
    try:
        local = datetime.strptime(match.group("stamp"), "%Y%m%d%H%M%S").replace(
            microsecond=int(match.group("microseconds"))
        )
        offset_minutes = int(match.group("offset"))
        if match.group("sign") == "-":
            offset_minutes = -offset_minutes
        return local.replace(tzinfo=timezone(timedelta(minutes=offset_minutes))).astimezone(UTC)
    except ValueError:
        return None


def collect_storage_snapshot() -> StorageSnapshot:
    collection_started_at = utc_now()
    limitations: list[str] = []
    try:
        service = _wmi_service(r"root\cimv2")
        volumes = tuple(
            StorageVolume(
                volume_id=str(_attr(row, "DeviceID")),
                filesystem=None
                if _attr(row, "FileSystem") is None
                else str(_attr(row, "FileSystem")),
                label=None if _attr(row, "VolumeName") is None else str(_attr(row, "VolumeName")),
                total_bytes=_int(_attr(row, "Size")),
                free_bytes=_int(_attr(row, "FreeSpace")),
            )
            for row in service.ExecQuery(
                "SELECT DeviceID,FileSystem,VolumeName,Size,FreeSpace FROM Win32_LogicalDisk"
            )
            if _attr(row, "DeviceID")
        )[:64]
        partition_items: list[DiskPartition] = []
        invalid_partitions = 0
        for row in service.ExecQuery("SELECT DeviceID,DiskIndex FROM Win32_DiskPartition"):
            partition_id = _attr(row, "DeviceID")
            disk_index = _nonnegative_int(_attr(row, "DiskIndex"))
            if not partition_id or disk_index is None:
                invalid_partitions += 1
                continue
            if len(partition_items) < 128:
                partition_items.append(
                    DiskPartition(partition_id=str(partition_id), disk_index=disk_index)
                )
        partitions = tuple(partition_items)
        if invalid_partitions:
            limitations.append(f"omitted {invalid_partitions} partitions with invalid disk indices")
        disk_items: list[PhysicalDisk] = []
        invalid_disks = 0
        for row in service.ExecQuery(
            "SELECT Index,DeviceID,Model,SerialNumber,InterfaceType,MediaType,Size,Status "
            "FROM Win32_DiskDrive"
        ):
            device_id = _attr(row, "DeviceID")
            disk_index = _nonnegative_int(_attr(row, "Index"))
            if not device_id or disk_index is None:
                invalid_disks += 1
                continue
            if len(disk_items) >= 64:
                continue
            disk_items.append(
                PhysicalDisk(
                    disk_index=disk_index,
                    device_id=str(device_id),
                    model=None if _attr(row, "Model") is None else str(_attr(row, "Model")),
                    serial_number=None
                    if _attr(row, "SerialNumber") is None
                    else str(_attr(row, "SerialNumber")).strip() or None,
                    interface_type=None
                    if _attr(row, "InterfaceType") is None
                    else str(_attr(row, "InterfaceType")),
                    media_type=None
                    if _attr(row, "MediaType") is None
                    else str(_attr(row, "MediaType")),
                    size_bytes=_nonnegative_int(_attr(row, "Size")),
                    status=None if _attr(row, "Status") is None else str(_attr(row, "Status")),
                )
            )
        disks = tuple(disk_items)
        if invalid_disks:
            limitations.append(f"omitted {invalid_disks} physical disks with invalid indices")
        volume_to_partition: dict[str, str] = {}
        for row in service.ExecQuery(
            "SELECT Antecedent,Dependent FROM Win32_LogicalDiskToPartition"
        ):
            antecedent = _ASSOCIATION_VALUE.search(str(_attr(row, "Antecedent", "")))
            dependent = _ASSOCIATION_VALUE.search(str(_attr(row, "Dependent", "")))
            if antecedent and dependent:
                volume_to_partition[dependent.group("value")] = antecedent.group("value")
    except Exception as error:
        return StorageSnapshot(
            collection_started_at=collection_started_at,
            captured_at=utc_now(),
            volumes=(),
            partitions=(),
            physical_disks=(),
            volume_mappings=(),
            reliability=(),
            status=_exception_status(error),
            limitations=(f"storage topology unavailable: {type(error).__name__}",),
        )
    reliability: tuple[ReliabilityCounter, ...] = ()
    try:
        storage = _wmi_service(r"root\Microsoft\Windows\Storage")
        reliability_items: list[ReliabilityCounter] = []
        invalid_reliability = 0
        for row in storage.ExecQuery(
            "SELECT DeviceId,Temperature,Wear,ReadErrorsTotal,WriteErrorsTotal "
            "FROM MSFT_StorageReliabilityCounter"
        ):
            disk_index = _nonnegative_int(_attr(row, "DeviceId"))
            if disk_index is None:
                invalid_reliability += 1
                continue
            if len(reliability_items) >= 64:
                continue
            reliability_items.append(
                ReliabilityCounter(
                    disk_index=disk_index,
                    status=ComponentStatus.AVAILABLE,
                    temperature_c=_int(_attr(row, "Temperature")),
                    wear_percent=_nonnegative_int(_attr(row, "Wear")),
                    read_errors_total=_nonnegative_int(_attr(row, "ReadErrorsTotal")),
                    write_errors_total=_nonnegative_int(_attr(row, "WriteErrorsTotal")),
                )
            )
        reliability = tuple(reliability_items)
        if invalid_reliability:
            limitations.append(
                f"omitted {invalid_reliability} reliability rows with invalid disk indices"
            )
    except Exception as error:
        limitations.append(f"storage reliability unavailable: {type(error).__name__}")
    return join_storage_topology(
        volumes=volumes,
        partitions=partitions,
        disks=disks,
        volume_to_partition=volume_to_partition,
        reliability=reliability,
        collection_started_at=collection_started_at,
        captured_at=utc_now(),
        limitations=tuple(limitations),
    )


def collect_application_topology() -> ApplicationTopologySnapshot:
    collection_started_at = utc_now()
    limitations: list[str] = []
    processes: list[ProcessTopology] = []
    services: list[ServiceTopology] = []
    startup: list[StartupEntry] = []
    try:
        service = _wmi_service(r"root\cimv2")
        for row in service.ExecQuery(
            "SELECT ProcessId,ParentProcessId,Name,CreationDate,ExecutablePath FROM Win32_Process"
        ):
            pid = _int(_attr(row, "ProcessId"))
            name = str(_attr(row, "Name", ""))
            raw_created = _attr(row, "CreationDate")
            created = None if raw_created is None else parse_wmi_datetime(str(raw_created))
            if pid is None or pid <= 0 or not name or created is None:
                continue
            processes.append(
                ProcessTopology(
                    pid=pid,
                    ppid=max(0, _int(_attr(row, "ParentProcessId")) or 0),
                    name=name,
                    creation_time=created,
                    executable=None
                    if _attr(row, "ExecutablePath") is None
                    else str(_attr(row, "ExecutablePath")),
                    username=None,
                    status=None,
                )
            )
            if len(processes) >= 4096:
                limitations.append("process scan safety limit reached")
                break
        dependency_map: dict[str, list[str]] = {}
        for row in service.ExecQuery("SELECT Antecedent,Dependent FROM Win32_DependentService"):
            parent = _ASSOCIATION_VALUE.search(str(_attr(row, "Antecedent", "")))
            child = _ASSOCIATION_VALUE.search(str(_attr(row, "Dependent", "")))
            if parent and child:
                dependency_map.setdefault(child.group("value").casefold(), []).append(
                    parent.group("value")
                )
        for row in service.ExecQuery(
            "SELECT Name,DisplayName,State,StartMode,ProcessId,StartName,PathName "
            "FROM Win32_Service"
        ):
            name = str(_attr(row, "Name", ""))
            if not name:
                continue
            services.append(
                ServiceTopology(
                    name=name,
                    display_name=str(_attr(row, "DisplayName", name)),
                    state=str(_attr(row, "State", "Unknown")),
                    start_mode=str(_attr(row, "StartMode", "Unknown")),
                    process_id=_int(_attr(row, "ProcessId")),
                    dependencies=tuple(sorted(dependency_map.get(name.casefold(), ())))[:32],
                    account=None
                    if _attr(row, "StartName") is None
                    else str(_attr(row, "StartName")),
                    binary_path=None
                    if _attr(row, "PathName") is None
                    else str(_attr(row, "PathName")),
                )
            )
            if len(services) >= 4096:
                limitations.append("service scan safety limit reached")
                break
        for row in service.ExecQuery("SELECT Name,Command,Location,User FROM Win32_StartupCommand"):
            command = str(_attr(row, "Command", ""))
            name = str(_attr(row, "Name", ""))
            if not name or not command:
                continue
            startup.append(
                StartupEntry(
                    name=name,
                    command=command,
                    location=None
                    if _attr(row, "Location") is None
                    else str(_attr(row, "Location")),
                    user=None if _attr(row, "User") is None else str(_attr(row, "User")),
                )
            )
            if len(startup) >= 4096:
                limitations.append("startup-entry scan safety limit reached")
                break
    except Exception as error:
        limitations.append(f"service or startup topology unavailable: {type(error).__name__}")
    return normalize_application_topology(
        processes=tuple(processes),
        services=tuple(services),
        startup=tuple(startup),
        collection_started_at=collection_started_at,
        limitations=tuple(limitations),
    )


def collect_network_configuration() -> NetworkConfigurationSnapshot:
    collection_started_at = utc_now()
    limitations: list[str] = []
    routes: tuple[RouteObservation, ...] = ()
    adapters: tuple[AdapterConfiguration, ...] = ()
    try:
        routes = WmiRouteBackend().routes(max_records=256)
    except Exception as error:
        limitations.append(f"route table unavailable: {type(error).__name__}")
    try:
        service = _wmi_service(r"root\cimv2")
        adapter_items: list[AdapterConfiguration] = []
        invalid_adapters = 0
        for row in service.ExecQuery(
            "SELECT InterfaceIndex,Description,DHCPEnabled,DNSServerSearchOrder,"
            "DefaultIPGateway FROM Win32_NetworkAdapterConfiguration WHERE IPEnabled=TRUE"
        ):
            interface_index = _nonnegative_int(_attr(row, "InterfaceIndex"))
            if interface_index is None:
                invalid_adapters += 1
                continue
            if len(adapter_items) >= 64:
                continue
            adapter_items.append(
                AdapterConfiguration(
                    interface_index=interface_index,
                    description=str(_attr(row, "Description", "Unknown adapter")),
                    dhcp_enabled=(
                        None
                        if _attr(row, "DHCPEnabled") is None
                        else bool(_attr(row, "DHCPEnabled"))
                    ),
                    dns_servers=_strings(_attr(row, "DNSServerSearchOrder"))[:32],
                    default_gateways=_strings(_attr(row, "DefaultIPGateway"))[:16],
                )
            )
        adapters = tuple(adapter_items)
        if invalid_adapters:
            limitations.append(
                f"omitted {invalid_adapters} adapter rows with invalid interface indices"
            )
    except Exception as error:
        limitations.append(f"adapter DNS configuration unavailable: {type(error).__name__}")
    proxy = _read_proxy_configuration()
    if proxy.status is not ComponentStatus.AVAILABLE:
        limitations.append("WinINET proxy configuration was unavailable")
    status = (
        ComponentStatus.AVAILABLE
        if routes and adapters and not limitations
        else ComponentStatus.PARTIAL
    )
    return NetworkConfigurationSnapshot(
        collection_started_at=collection_started_at,
        captured_at=utc_now(),
        routes=routes,
        adapters=adapters,
        proxy=proxy,
        status=status,
        limitations=tuple(limitations),
    )


def collect_network_listeners() -> NetworkListenerSnapshot:
    """Read fixed TCP LISTEN endpoints and join available owner identities."""

    collection_started_at = utc_now()
    listener_table_started_at = utc_now()
    limitations: list[str] = []
    try:
        connections = psutil.net_connections(kind="tcp")
    except (psutil.AccessDenied, PermissionError) as error:
        listener_table_completed_at = utc_now()
        return NetworkListenerSnapshot(
            collection_started_at=collection_started_at,
            listener_table_started_at=listener_table_started_at,
            listener_table_completed_at=listener_table_completed_at,
            captured_at=listener_table_completed_at,
            listeners=(),
            omitted_listener_count=0,
            status=ComponentStatus.PERMISSION_DENIED,
            limitations=(f"TCP listener table unavailable: {type(error).__name__}",),
        )
    except (OSError, RuntimeError) as error:
        listener_table_completed_at = utc_now()
        return NetworkListenerSnapshot(
            collection_started_at=collection_started_at,
            listener_table_started_at=listener_table_started_at,
            listener_table_completed_at=listener_table_completed_at,
            captured_at=listener_table_completed_at,
            listeners=(),
            omitted_listener_count=0,
            status=ComponentStatus.FAILED,
            limitations=(f"TCP listener table unavailable: {type(error).__name__}",),
        )
    listener_table_completed_at = utc_now()
    limitations.append(_LISTENER_INTERVAL_LIMITATION)

    owner_cache: dict[int, tuple[str | None, UtcDateTime | None, ComponentStatus]] = {}
    listeners: list[NetworkListener] = []
    for connection in connections:
        if str(getattr(connection, "status", "")).upper() != "LISTEN":
            continue
        endpoint = _local_endpoint(getattr(connection, "laddr", None))
        family = getattr(connection, "family", None)
        if endpoint is None or family not in {socket.AF_INET, socket.AF_INET6}:
            limitations.append("a listening endpoint used an unsupported address representation")
            continue
        address, port = endpoint
        raw_pid = _int(getattr(connection, "pid", None))
        pid = raw_pid if raw_pid is not None and raw_pid >= 0 else None
        if pid is None:
            process_name = None
            creation_time = None
            owner_status = ComponentStatus.UNSUPPORTED
            limitations.append("one or more listener owners were not exposed")
        else:
            cached = owner_cache.get(pid)
            if cached is None:
                cached = _listener_owner(pid)
                owner_cache[pid] = cached
            process_name, creation_time, owner_status = cached
            if owner_status is not ComponentStatus.AVAILABLE:
                limitations.append("one or more listener process identities were unavailable")
        listeners.append(
            NetworkListener(
                protocol="tcp6" if family == socket.AF_INET6 else "tcp4",
                local_address=address,
                local_port=port,
                pid=pid,
                process_name=process_name,
                process_creation_time=creation_time,
                owner_status=owner_status,
            )
        )
    ordered = sorted(
        listeners,
        key=lambda item: (
            item.protocol,
            item.local_port,
            item.local_address.casefold(),
            -1 if item.pid is None else item.pid,
        ),
    )
    omitted = max(0, len(ordered) - 1024)
    if omitted:
        limitations.append("TCP listener record limit reached")
    selected = tuple(ordered[:1024])
    partial_owner = any(item.owner_status is not ComponentStatus.AVAILABLE for item in selected)
    other_limitations = any(item != _LISTENER_INTERVAL_LIMITATION for item in limitations)
    return NetworkListenerSnapshot(
        collection_started_at=collection_started_at,
        listener_table_started_at=listener_table_started_at,
        listener_table_completed_at=listener_table_completed_at,
        captured_at=utc_now(),
        listeners=selected,
        omitted_listener_count=omitted,
        status=(
            ComponentStatus.PARTIAL
            if omitted or partial_owner or other_limitations
            else ComponentStatus.AVAILABLE
        ),
        limitations=tuple(dict.fromkeys(limitations)),
    )


def _local_endpoint(value: object) -> tuple[str, int] | None:
    address = getattr(value, "ip", None)
    port = _int(getattr(value, "port", None))
    if address is None and isinstance(value, tuple):
        endpoint = cast(tuple[object, ...], value)
        if len(endpoint) >= 2:
            address = endpoint[0]
            port = _int(endpoint[1])
    if not isinstance(address, str) or not address or port is None or not 0 <= port <= 65_535:
        return None
    return address, port


def _listener_owner(pid: int) -> tuple[str | None, UtcDateTime | None, ComponentStatus]:
    try:
        process = psutil.Process(pid)
        name = process.name().strip()[:255] or None
        created_seconds = float(process.create_time())
        if created_seconds <= 0:
            return name, None, ComponentStatus.UNSUPPORTED
        creation_time = datetime.fromtimestamp(created_seconds, tz=UTC)
        if name is None:
            return None, creation_time, ComponentStatus.UNSUPPORTED
        return name, creation_time, ComponentStatus.AVAILABLE
    except (psutil.AccessDenied, PermissionError):
        return None, None, ComponentStatus.PERMISSION_DENIED
    except (psutil.NoSuchProcess, psutil.ZombieProcess, OSError, ValueError, OverflowError):
        return None, None, ComponentStatus.UNSUPPORTED


def _read_proxy_configuration() -> ProxyConfiguration:
    try:
        registry = cast(Any, importlib.import_module("winreg"))
        with registry.OpenKey(
            registry.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            0,
            registry.KEY_READ,
        ) as key:
            enabled = bool(registry.QueryValueEx(key, "ProxyEnable")[0])
            try:
                server = str(registry.QueryValueEx(key, "ProxyServer")[0]) or None
            except OSError:
                server = None
        return ProxyConfiguration(enabled=enabled, server=server, status=ComponentStatus.AVAILABLE)
    except Exception as error:
        return ProxyConfiguration(enabled=None, server=None, status=_exception_status(error))


def collect_power_snapshot() -> PowerSnapshot:
    collection_started_at = utc_now()
    limitations: list[str] = []
    battery = psutil.sensors_battery()
    ac_line_status = "unknown"
    percent: int | None = None
    seconds: int | None = None
    if battery is not None:
        ac_line_status = "online" if battery.power_plugged else "battery"
        percent = max(0, min(100, round(battery.percent)))
        seconds = battery.secsleft if battery.secsleft >= 0 else None
    scheme: str | None = None
    try:
        registry = cast(Any, importlib.import_module("winreg"))
        with registry.OpenKey(
            registry.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Power\User\PowerSchemes",
            0,
            registry.KEY_READ,
        ) as key:
            scheme = str(registry.QueryValueEx(key, "ActivePowerScheme")[0]) or None
    except Exception as error:
        limitations.append(f"active power scheme unavailable: {type(error).__name__}")
    processors: list[dict[str, JsonValue]] = []
    try:
        service = _wmi_service(r"root\cimv2")
        for row in service.ExecQuery(
            "SELECT DeviceID,Name,CurrentClockSpeed,MaxClockSpeed,LoadPercentage "
            "FROM Win32_Processor"
        ):
            processors.append(
                {
                    "device_id": str(_attr(row, "DeviceID", "processor")),
                    "name": str(_attr(row, "Name", "Unknown processor")),
                    "current_clock_mhz": _int(_attr(row, "CurrentClockSpeed")),
                    "max_clock_mhz": _int(_attr(row, "MaxClockSpeed")),
                    "load_percent": _int(_attr(row, "LoadPercentage")),
                }
            )
            if len(processors) >= 16:
                break
    except Exception as error:
        limitations.append(f"processor power metadata unavailable: {type(error).__name__}")
    return PowerSnapshot(
        collection_started_at=collection_started_at,
        captured_at=utc_now(),
        ac_line_status=ac_line_status,
        battery_percent=percent,
        battery_seconds_remaining=seconds,
        active_scheme_guid=scheme,
        processors=tuple(processors),
        status=ComponentStatus.AVAILABLE
        if scheme is not None or battery is not None or processors
        else ComponentStatus.UNSUPPORTED,
        limitations=tuple(limitations),
    )


def collect_security_snapshot() -> SecuritySnapshot:
    collection_started_at = utc_now()
    limitations: list[str] = []
    antivirus: list[dict[str, JsonValue]] = []
    firewall: list[dict[str, JsonValue]] = []
    try:
        service = _wmi_service(r"root\SecurityCenter2")
        for row in service.ExecQuery(
            "SELECT displayName,instanceGuid,productState,pathToSignedProductExe "
            "FROM AntiVirusProduct"
        ):
            antivirus.append(
                {
                    "display_name": str(_attr(row, "displayName", "Unknown antivirus")),
                    "instance_guid": str(_attr(row, "instanceGuid", "")),
                    "product_state": _int(_attr(row, "productState")),
                    "signed_product_path": str(_attr(row, "pathToSignedProductExe", "")),
                }
            )
            if len(antivirus) >= 16:
                break
    except Exception as error:
        limitations.append(
            f"Security Center antivirus inventory unavailable: {type(error).__name__}"
        )
    try:
        client = cast(Any, importlib.import_module("win32com.client"))
        policy = client.Dispatch("HNetCfg.FwPolicy2")
        for profile_id, name in ((1, "domain"), (2, "private"), (4, "public")):
            firewall.append(
                {
                    "profile": name,
                    "enabled": bool(policy.FirewallEnabled(profile_id)),
                }
            )
    except Exception as error:
        limitations.append(f"firewall profile state unavailable: {type(error).__name__}")
    uac: bool | None = None
    try:
        registry = cast(Any, importlib.import_module("winreg"))
        with registry.OpenKey(
            registry.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            0,
            registry.KEY_READ,
        ) as key:
            uac = bool(registry.QueryValueEx(key, "EnableLUA")[0])
    except Exception as error:
        limitations.append(f"UAC configuration unavailable: {type(error).__name__}")
    return SecuritySnapshot(
        collection_started_at=collection_started_at,
        captured_at=utc_now(),
        antivirus_products=tuple(antivirus),
        firewall_profiles=tuple(firewall),
        uac_enabled=uac,
        status=ComponentStatus.AVAILABLE
        if antivirus or firewall or uac is not None
        else ComponentStatus.UNSUPPORTED,
        limitations=tuple(limitations),
    )


def collect_pressure_sample() -> PressureSnapshot:
    """Take three passive counter snapshots over two seconds."""

    frames: list[_PressureFrame] = []
    for index in range(3):
        if index:
            time.sleep(1.0)
        frames.append(_capture_pressure_frame())
    samples = _normalize_pressure_frames(tuple(frames))
    omitted = sum(item.omitted_process_count for item in samples)
    limitations = [
        "first sample is a cumulative-counter baseline; CPU and I/O deltas begin with sample 2",
        "process CPU is normalized across the observed logical processors",
        "bounded process counters are read sequentially around each system sample timestamp",
    ]
    if omitted:
        limitations.append("process detail was bounded or unavailable during sampling")
    return PressureSnapshot(
        captured_at=utc_now(),
        window_started_at=frames[0].collection_started_at or frames[0].observed_at,
        window_ended_at=frames[-1].observed_at,
        inter_sample_delay_seconds=1.0,
        samples=samples,
        status=ComponentStatus.PARTIAL if omitted else ComponentStatus.AVAILABLE,
        limitations=tuple(limitations),
    )


def collect_target_pressure(
    *,
    pid: int,
    creation_time: UtcDateTime,
    clock: Callable[[], UtcDateTime] = utc_now,
    sleep: Callable[[float], None] = time.sleep,
) -> TargetPressureSnapshot:
    """Read one previously bound process identity at three fixed instants."""

    if pid <= 0 or creation_time.tzinfo is None or creation_time.utcoffset() is None:
        raise ValueError("target requires a positive PID and aware creation time")
    expected = creation_time.astimezone(UTC)
    samples: list[TargetPressureSample] = []
    prior: _TargetCounter | None = None
    prior_at: datetime | None = None
    logical_cpus = max(1, psutil.cpu_count(logical=True) or 1)
    for index in range(3):
        if index:
            sleep(1.0)
        started_at = clock()
        if prior_at is not None and started_at < prior_at:
            raise TargetPressureClockRollback("UTC clock moved backwards during target sampling")
        status, counter = _read_target_counter(pid, expected)
        observed_at = clock()
        if observed_at < started_at:
            raise TargetPressureClockRollback("UTC clock moved backwards during target sampling")
        if status in {
            TargetPressureStatus.UNAVAILABLE,
            TargetPressureStatus.PERMISSION_DENIED,
            TargetPressureStatus.REUSED,
        }:
            samples.append(
                TargetPressureSample(
                    query_started_at=started_at,
                    observed_at=observed_at,
                    status=status,
                    delta_status="unavailable",
                )
            )
            break
        assert counter is not None
        elapsed = None if prior_at is None else (observed_at - prior_at).total_seconds()
        cpu = None
        if (
            prior is not None
            and elapsed is not None
            and elapsed > 0
            and counter.cpu_seconds >= prior.cpu_seconds
        ):
            cpu = _bounded_percent(
                (counter.cpu_seconds - prior.cpu_seconds) / elapsed / logical_cpus * 100.0
            )
        read_delta = None if prior is None else _counter_delta(prior.read_bytes, counter.read_bytes)
        write_delta = (
            None if prior is None else _counter_delta(prior.write_bytes, counter.write_bytes)
        )
        complete_delta = (
            prior is not None
            and cpu is not None
            and read_delta is not None
            and write_delta is not None
        )
        sample_status = (
            TargetPressureStatus.PARTIAL
            if status is TargetPressureStatus.PARTIAL or (prior is not None and not complete_delta)
            else TargetPressureStatus.AVAILABLE
        )
        samples.append(
            TargetPressureSample(
                query_started_at=started_at,
                observed_at=observed_at,
                status=sample_status,
                delta_status="baseline"
                if prior is None
                else "measured"
                if complete_delta
                else "partial",
                name=counter.name,
                cpu_percent=cpu,
                rss_bytes=counter.rss_bytes,
                read_bytes_delta=read_delta,
                write_bytes_delta=write_delta,
            )
        )
        prior, prior_at = counter, observed_at
    captured_at = clock()
    if captured_at < samples[-1].observed_at:
        raise TargetPressureClockRollback("UTC clock moved backwards during target sampling")
    final = samples[-1].status
    overall = (
        TargetPressureStatus.AVAILABLE
        if len(samples) == 3
        and all(item.status is TargetPressureStatus.AVAILABLE for item in samples)
        else TargetPressureStatus.PARTIAL
        if any(item.rss_bytes is not None for item in samples)
        else final
    )
    limitations = [
        "first sample is a counter baseline; CPU and I/O deltas begin with sample 2",
        "process CPU is normalized across logical processors",
        "samples are separate instants and do not measure application interaction latency",
    ]
    if overall is not TargetPressureStatus.AVAILABLE:
        limitations.append(f"target sampling incomplete: {final.value}")
    if any(item.delta_status == "partial" for item in samples):
        limitations.append("one or more CPU or I/O deltas were unavailable")
    return TargetPressureSnapshot(
        target_pid=pid,
        target_creation_time=expected,
        window_started_at=samples[0].query_started_at,
        window_ended_at=samples[-1].observed_at,
        captured_at=captured_at,
        samples=tuple(samples),
        status=overall,
        limitations=tuple(limitations),
    )


def _read_target_counter(
    pid: int, expected_creation: datetime
) -> tuple[TargetPressureStatus, _TargetCounter | None]:
    try:
        process = psutil.Process(pid)
        before = datetime.fromtimestamp(process.create_time(), tz=UTC)
        if before != expected_creation:
            return TargetPressureStatus.REUSED, None
        name = process.name()[:255]
        cpu_times = process.cpu_times()
        memory = process.memory_info()
        try:
            io = process.io_counters()
        except (psutil.AccessDenied, OSError):
            io = None
        after = datetime.fromtimestamp(process.create_time(), tz=UTC)
        if after != expected_creation:
            return TargetPressureStatus.REUSED, None
        if not name:
            return TargetPressureStatus.UNAVAILABLE, None
        counter = _TargetCounter(
            name=name,
            cpu_seconds=max(0.0, float(cpu_times.user) + float(cpu_times.system)),
            rss_bytes=max(0, int(memory.rss)),
            read_bytes=None if io is None else max(0, int(io.read_bytes)),
            write_bytes=None if io is None else max(0, int(io.write_bytes)),
        )
        return (
            TargetPressureStatus.PARTIAL if io is None else TargetPressureStatus.AVAILABLE
        ), counter
    except (psutil.NoSuchProcess, psutil.ZombieProcess, OSError, ValueError, OverflowError):
        return TargetPressureStatus.UNAVAILABLE, None
    except psutil.AccessDenied:
        return TargetPressureStatus.PERMISSION_DENIED, None


def _capture_pressure_frame() -> _PressureFrame:
    collection_started_at = utc_now()
    cpu_times = tuple(_cpu_counter(item) for item in psutil.cpu_times(percpu=True))
    memory = psutil.virtual_memory()
    swap = psutil.swap_memory()
    disk = psutil.disk_io_counters()
    processes: list[_ProcessCounter] = []
    omitted = 0
    for process in psutil.process_iter(
        ["pid", "name", "create_time", "cpu_times", "memory_info", "io_counters"]
    ):
        if len(processes) >= 4096:
            omitted += 1
            continue
        try:
            info: dict[str, Any] = process.info
            pid = _int(info.get("pid"))
            name = str(info.get("name") or "").strip()
            created_seconds = _float(info.get("create_time"))
            cpu = info.get("cpu_times")
            memory_info = info.get("memory_info")
            io_counters = info.get("io_counters")
            cpu_user = _float(getattr(cpu, "user", None))
            cpu_system = _float(getattr(cpu, "system", None))
            rss_bytes = (
                None if memory_info is None else _nonnegative_int(getattr(memory_info, "rss", None))
            )
            if (
                pid is None
                or pid <= 0
                or not name
                or created_seconds is None
                or created_seconds <= 0
                or cpu_user is None
                or cpu_system is None
                or rss_bytes is None
            ):
                omitted += 1
                continue
            read_bytes = (
                None
                if io_counters is None
                else _nonnegative_int(getattr(io_counters, "read_bytes", None))
            )
            write_bytes = (
                None
                if io_counters is None
                else _nonnegative_int(getattr(io_counters, "write_bytes", None))
            )
            processes.append(
                _ProcessCounter(
                    pid=pid,
                    name=name[:255],
                    creation_time=datetime.fromtimestamp(created_seconds, tz=UTC),
                    cpu_seconds=max(0.0, cpu_user + cpu_system),
                    rss_bytes=rss_bytes,
                    read_bytes=read_bytes,
                    write_bytes=write_bytes,
                )
            )
        except (
            psutil.AccessDenied,
            psutil.NoSuchProcess,
            psutil.ZombieProcess,
            OSError,
            ValueError,
            OverflowError,
        ):
            omitted += 1
    return _PressureFrame(
        observed_at=utc_now(),
        cpus=cpu_times,
        memory_percent=float(memory.percent),
        memory_available_bytes=max(0, int(memory.available)),
        swap_percent=float(swap.percent),
        disk_read_bytes=None if disk is None else max(0, int(disk.read_bytes)),
        disk_write_bytes=None if disk is None else max(0, int(disk.write_bytes)),
        processes=tuple(processes),
        omitted_process_count=omitted,
        collection_started_at=collection_started_at,
    )


def _cpu_counter(value: object) -> _CpuCounter:
    if hasattr(value, "_asdict"):
        fields = cast(Any, value)._asdict()
        total = sum(
            float(field_value)
            for field_name, field_value in fields.items()
            if field_name not in {"guest", "guest_nice"}
        )
        idle = float(fields.get("idle", 0.0)) + float(fields.get("iowait", 0.0))
        return _CpuCounter(total=max(0.0, total), busy=max(0.0, total - idle))
    converted = tuple(_float(item) for item in cast(Iterable[object], value))
    values = tuple(item for item in converted if item is not None)
    total = sum(values)
    idle = values[3] if len(values) > 3 else 0.0
    return _CpuCounter(total=max(0.0, total), busy=max(0.0, total - idle))


def _normalize_pressure_frames(
    frames: tuple[_PressureFrame, ...],
) -> tuple[PressureSample, ...]:
    samples: list[PressureSample] = []
    previous: _PressureFrame | None = None
    for frame in frames:
        elapsed = (
            None
            if previous is None
            else max(0.0, (frame.observed_at - previous.observed_at).total_seconds())
        )
        previous_processes = (
            {}
            if previous is None
            else {(item.pid, item.creation_time): item for item in previous.processes}
        )
        processes: list[PressureProcessObservation] = []
        logical_cpu_count = max(1, len(frame.cpus))
        for current in frame.processes:
            prior = previous_processes.get((current.pid, current.creation_time))
            cpu_percent: float | None = None
            read_delta: int | None = None
            write_delta: int | None = None
            if prior is not None and elapsed is not None and elapsed > 0:
                cpu_percent = _bounded_percent(
                    (current.cpu_seconds - prior.cpu_seconds) / elapsed / logical_cpu_count * 100.0
                )
                read_delta = _counter_delta(prior.read_bytes, current.read_bytes)
                write_delta = _counter_delta(prior.write_bytes, current.write_bytes)
            processes.append(
                PressureProcessObservation(
                    pid=current.pid,
                    name=current.name,
                    creation_time=current.creation_time,
                    cpu_percent=cpu_percent,
                    rss_bytes=current.rss_bytes,
                    read_bytes_delta=read_delta,
                    write_bytes_delta=write_delta,
                )
            )
        processes.sort(
            key=lambda item: (
                -(item.cpu_percent or 0.0),
                -((item.read_bytes_delta or 0) + (item.write_bytes_delta or 0)),
                -item.rss_bytes,
                item.pid,
            )
        )
        per_cpu = tuple(
            None
            if previous is None or index >= len(previous.cpus)
            else _cpu_delta(previous.cpus[index], current)
            for index, current in enumerate(frame.cpus)
        )
        system_cpu = (
            None
            if previous is None
            else _cpu_delta(
                _CpuCounter(
                    total=sum(item.total for item in previous.cpus),
                    busy=sum(item.busy for item in previous.cpus),
                ),
                _CpuCounter(
                    total=sum(item.total for item in frame.cpus),
                    busy=sum(item.busy for item in frame.cpus),
                ),
            )
        )
        selected = tuple(processes[:32])
        samples.append(
            PressureSample(
                collection_started_at=frame.collection_started_at,
                observed_at=frame.observed_at,
                system_cpu_percent=system_cpu,
                per_cpu_percent=per_cpu,
                memory_percent=frame.memory_percent,
                memory_available_bytes=frame.memory_available_bytes,
                swap_percent=frame.swap_percent,
                disk_read_bytes_delta=(
                    None
                    if previous is None
                    else _counter_delta(previous.disk_read_bytes, frame.disk_read_bytes)
                ),
                disk_write_bytes_delta=(
                    None
                    if previous is None
                    else _counter_delta(previous.disk_write_bytes, frame.disk_write_bytes)
                ),
                processes=selected,
                omitted_process_count=(
                    frame.omitted_process_count + max(0, len(processes) - len(selected))
                ),
            )
        )
        previous = frame
    return tuple(samples)


def _cpu_delta(previous: _CpuCounter, current: _CpuCounter) -> float | None:
    total_delta = current.total - previous.total
    if total_delta <= 0:
        return None
    return _bounded_percent((current.busy - previous.busy) / total_delta * 100.0)


def _bounded_percent(value: float) -> float:
    return round(max(0.0, min(100.0, value)), 3)


def _counter_delta(previous: int | None, current: int | None) -> int | None:
    if previous is None or current is None or current < previous:
        return None
    return current - previous


def collect_incident_events() -> IncidentEventSnapshot:
    collection_started_at = utc_now()
    adapter = FixedEventLogAdapter(PyWin32EventLogBackend(), max_records=100)
    events: list[WindowsEvent] = []
    statuses: dict[str, ComponentStatus] = {}
    limitations: list[str] = []
    for channel in ("System", "Application"):
        result = adapter.query(channel, after_record_id=None, limit=100)
        if result.status is QueryStatus.OK:
            statuses[channel] = ComponentStatus.AVAILABLE
            events.extend(result.events)
            if result.reason:
                limitations.append(f"{channel}: {result.reason}")
        else:
            statuses[channel] = (
                ComponentStatus.PERMISSION_DENIED
                if result.status is QueryStatus.DENIED
                else ComponentStatus.FAILED
            )
            limitations.append(f"{channel}: {result.reason or result.status.value}")
    return IncidentEventSnapshot(
        collection_started_at=collection_started_at,
        captured_at=utc_now(),
        events=filter_incident_events(events, max_records=128),
        channel_status=statuses,
        limitations=tuple(limitations),
    )
