"""Bounded current CPU, memory, and disk resource observations."""

from typing import Protocol

import psutil
from pydantic import Field

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.time import UtcDateTime


class MemoryUsage(FrozenModel):
    total_bytes: int = Field(gt=0)
    available_bytes: int = Field(ge=0)
    percent: float = Field(ge=0, le=100)


class DiskUsage(FrozenModel):
    mountpoint: str = Field(min_length=1, max_length=255)
    total_bytes: int = Field(ge=0)
    free_bytes: int = Field(ge=0)
    percent: float = Field(ge=0, le=100)


class ResourceObservation(FrozenModel):
    captured_at: UtcDateTime
    cpu_percent: float = Field(ge=0, le=100)
    memory: MemoryUsage
    disks: tuple[DiskUsage, ...]


class ResourceBackend(Protocol):
    def cpu_percent(self) -> float: ...

    def memory_usage(self) -> MemoryUsage: ...

    def disk_usage(self) -> tuple[DiskUsage, ...]: ...


def collect_resources(
    backend: ResourceBackend,
    *,
    captured_at: UtcDateTime,
) -> ResourceObservation:
    return ResourceObservation(
        captured_at=captured_at,
        cpu_percent=backend.cpu_percent(),
        memory=backend.memory_usage(),
        disks=backend.disk_usage()[:8],
    )


class PsutilResourceBackend:
    def cpu_percent(self) -> float:
        return float(psutil.cpu_percent(interval=None))

    def memory_usage(self) -> MemoryUsage:
        memory = psutil.virtual_memory()
        return MemoryUsage(
            total_bytes=int(memory.total),
            available_bytes=int(memory.available),
            percent=float(memory.percent),
        )

    def disk_usage(self) -> tuple[DiskUsage, ...]:
        usage_records: list[DiskUsage] = []
        seen: set[str] = set()
        for partition in psutil.disk_partitions(all=False):
            if partition.mountpoint in seen:
                continue
            seen.add(partition.mountpoint)
            try:
                usage = psutil.disk_usage(partition.mountpoint)
            except OSError:
                continue
            usage_records.append(
                DiskUsage(
                    mountpoint=partition.mountpoint,
                    total_bytes=int(usage.total),
                    free_bytes=int(usage.free),
                    percent=float(usage.percent),
                )
            )
            if len(usage_records) == 8:
                break
        return tuple(usage_records)
