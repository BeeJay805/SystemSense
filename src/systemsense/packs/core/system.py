"""Core Windows identity, boot, and hardware capacity observations."""

import platform
from datetime import UTC, datetime
from typing import Protocol

import psutil
from pydantic import Field

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.time import UtcDateTime


class DiskCapacity(FrozenModel):
    device: str = Field(min_length=1, max_length=255)
    mountpoint: str = Field(min_length=1, max_length=255)
    total_bytes: int = Field(ge=0)


class SystemIdentity(FrozenModel):
    captured_at: UtcDateTime
    os_name: str
    os_version: str
    windows_build: str
    architecture: str
    boot_time: UtcDateTime
    uptime_seconds: float = Field(ge=0)
    logical_cpu_count: int = Field(ge=1)
    physical_cpu_count: int | None = Field(default=None, ge=1)
    total_memory_bytes: int = Field(gt=0)
    disks: tuple[DiskCapacity, ...]


class SystemBackend(Protocol):
    def platform_name(self) -> str: ...

    def platform_version(self) -> str: ...

    def windows_build(self) -> str: ...

    def architecture(self) -> str: ...

    def boot_time(self) -> datetime: ...

    def logical_cpu_count(self) -> int: ...

    def physical_cpu_count(self) -> int | None: ...

    def total_memory_bytes(self) -> int: ...

    def disk_capacities(self) -> tuple[DiskCapacity, ...]: ...


def collect_system_identity(
    backend: SystemBackend,
    *,
    captured_at: UtcDateTime,
) -> SystemIdentity:
    boot_time = backend.boot_time()
    return SystemIdentity(
        captured_at=captured_at,
        os_name=backend.platform_name(),
        os_version=backend.platform_version(),
        windows_build=backend.windows_build(),
        architecture=backend.architecture(),
        boot_time=boot_time,
        uptime_seconds=max(0.0, (captured_at - boot_time).total_seconds()),
        logical_cpu_count=backend.logical_cpu_count(),
        physical_cpu_count=backend.physical_cpu_count(),
        total_memory_bytes=backend.total_memory_bytes(),
        disks=backend.disk_capacities()[:8],
    )


class PsutilSystemBackend:
    def platform_name(self) -> str:
        return platform.system()

    def platform_version(self) -> str:
        return platform.version()

    def windows_build(self) -> str:
        return platform.version()

    def architecture(self) -> str:
        return platform.machine() or "unknown"

    def boot_time(self) -> datetime:
        return datetime.fromtimestamp(psutil.boot_time(), tz=UTC)

    def logical_cpu_count(self) -> int:
        return psutil.cpu_count(logical=True) or 1

    def physical_cpu_count(self) -> int | None:
        return psutil.cpu_count(logical=False)

    def total_memory_bytes(self) -> int:
        return int(psutil.virtual_memory().total)

    def disk_capacities(self) -> tuple[DiskCapacity, ...]:
        capacities: list[DiskCapacity] = []
        seen: set[str] = set()
        for partition in psutil.disk_partitions(all=False):
            if partition.mountpoint in seen:
                continue
            seen.add(partition.mountpoint)
            try:
                total_bytes = int(psutil.disk_usage(partition.mountpoint).total)
            except OSError:
                continue
            capacities.append(
                DiskCapacity(
                    device=partition.device or partition.mountpoint,
                    mountpoint=partition.mountpoint,
                    total_bytes=total_bytes,
                )
            )
            if len(capacities) == 8:
                break
        return tuple(capacities)
