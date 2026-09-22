"""Bounded current CPU, memory, and disk resource observations."""

from collections.abc import Callable
from typing import Protocol

import psutil
from pydantic import Field

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.time import UtcDateTime, utc_now

_CPU_SAMPLE_INTERVAL_SECONDS = 0.2


class MemoryUsage(FrozenModel):
    total_bytes: int = Field(gt=0)
    available_bytes: int = Field(ge=0)
    percent: float = Field(ge=0, le=100)


class DiskUsage(FrozenModel):
    mountpoint: str = Field(min_length=1, max_length=255)
    total_bytes: int = Field(ge=0)
    free_bytes: int = Field(ge=0)
    percent: float = Field(ge=0, le=100)


class DiskUsageCollection(FrozenModel):
    disks: tuple[DiskUsage, ...]
    omitted_disk_count: int = Field(ge=0)
    limitations: tuple[str, ...] = ()


class ResourceObservation(FrozenModel):
    captured_at: UtcDateTime
    cpu_sample_started_at: UtcDateTime
    cpu_sample_ended_at: UtcDateTime
    cpu_sample_interval_seconds: float = Field(gt=0, le=0.5)
    cpu_percent: float = Field(ge=0, le=100)
    memory: MemoryUsage
    disks: tuple[DiskUsage, ...]
    omitted_disk_count: int = Field(ge=0)
    limitations: tuple[str, ...] = ()


class ResourceBackend(Protocol):
    def cpu_percent(self, interval_seconds: float) -> float: ...

    def memory_usage(self) -> MemoryUsage: ...

    def disk_usage(self) -> DiskUsageCollection: ...


def collect_resources(
    backend: ResourceBackend,
    *,
    clock: Callable[[], UtcDateTime] = utc_now,
) -> ResourceObservation:
    sample_started_at = clock()
    cpu_percent = backend.cpu_percent(_CPU_SAMPLE_INTERVAL_SECONDS)
    sample_ended_at = clock()
    memory = backend.memory_usage()
    disk_usage = backend.disk_usage()
    return ResourceObservation(
        captured_at=clock(),
        cpu_sample_started_at=sample_started_at,
        cpu_sample_ended_at=sample_ended_at,
        cpu_sample_interval_seconds=_CPU_SAMPLE_INTERVAL_SECONDS,
        cpu_percent=cpu_percent,
        memory=memory,
        disks=disk_usage.disks,
        omitted_disk_count=disk_usage.omitted_disk_count,
        limitations=disk_usage.limitations,
    )


class PsutilResourceBackend:
    def cpu_percent(self, interval_seconds: float = _CPU_SAMPLE_INTERVAL_SECONDS) -> float:
        return float(psutil.cpu_percent(interval=interval_seconds))

    def memory_usage(self) -> MemoryUsage:
        memory = psutil.virtual_memory()
        return MemoryUsage(
            total_bytes=int(memory.total),
            available_bytes=int(memory.available),
            percent=float(memory.percent),
        )

    def disk_usage(self) -> DiskUsageCollection:
        usage_records: list[DiskUsage] = []
        seen: set[str] = set()
        unavailable = 0
        record_limit_omissions = 0
        for partition in psutil.disk_partitions(all=False):
            if partition.mountpoint in seen:
                continue
            seen.add(partition.mountpoint)
            if len(usage_records) >= 8:
                record_limit_omissions += 1
                continue
            try:
                usage = psutil.disk_usage(partition.mountpoint)
            except OSError:
                unavailable += 1
                continue
            usage_records.append(
                DiskUsage(
                    mountpoint=partition.mountpoint,
                    total_bytes=int(usage.total),
                    free_bytes=int(usage.free),
                    percent=float(usage.percent),
                )
            )
        limitations: list[str] = []
        if unavailable:
            noun = "record was" if unavailable == 1 else "records were"
            limitations.append(f"{unavailable} mounted filesystem usage {noun} unavailable")
        if record_limit_omissions:
            noun = "record was" if record_limit_omissions == 1 else "records were"
            limitations.append(
                f"{record_limit_omissions} mounted filesystem usage {noun} omitted by the "
                "8-record limit"
            )
        return DiskUsageCollection(
            disks=tuple(usage_records),
            omitted_disk_count=unavailable + record_limit_omissions,
            limitations=tuple(limitations),
        )
