from datetime import UTC, datetime, timedelta

from systemsense.packs.core.resources import (
    DiskUsage,
    MemoryUsage,
    ResourceBackend,
    collect_resources,
)
from systemsense.packs.core.system import (
    DiskCapacity,
    SystemBackend,
    collect_system_identity,
)

_NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)


class FakeSystemBackend(SystemBackend):
    def platform_name(self) -> str:
        return "Windows"

    def platform_version(self) -> str:
        return "10.0.26100"

    def windows_build(self) -> str:
        return "26100"

    def architecture(self) -> str:
        return "AMD64"

    def boot_time(self) -> datetime:
        return _NOW - timedelta(hours=1)

    def logical_cpu_count(self) -> int:
        return 16

    def physical_cpu_count(self) -> int | None:
        return 8

    def total_memory_bytes(self) -> int:
        return 32 * 1024**3

    def disk_capacities(self) -> tuple[DiskCapacity, ...]:
        return (DiskCapacity(device="C:", mountpoint="C:\\", total_bytes=1024**4),)


class FakeResourceBackend(ResourceBackend):
    def cpu_percent(self) -> float:
        return 12.5

    def memory_usage(self) -> MemoryUsage:
        return MemoryUsage(
            total_bytes=32 * 1024**3,
            available_bytes=20 * 1024**3,
            percent=37.5,
        )

    def disk_usage(self) -> tuple[DiskUsage, ...]:
        return (
            DiskUsage(
                mountpoint="C:\\",
                total_bytes=1024**4,
                free_bytes=512 * 1024**3,
                percent=50.0,
            ),
        )


def test_system_identity_includes_boot_hardware_and_disk_capacity() -> None:
    observation = collect_system_identity(FakeSystemBackend(), captured_at=_NOW)

    assert observation.os_name == "Windows"
    assert observation.os_version == "10.0.26100"
    assert observation.windows_build == "26100"
    assert observation.architecture == "AMD64"
    assert observation.boot_time == _NOW - timedelta(hours=1)
    assert observation.uptime_seconds == 3600
    assert observation.logical_cpu_count == 16
    assert observation.physical_cpu_count == 8
    assert observation.total_memory_bytes == 32 * 1024**3
    assert observation.disks[0].device == "C:"


def test_current_resources_are_structured_and_bounded() -> None:
    observation = collect_resources(FakeResourceBackend(), captured_at=_NOW)

    assert observation.cpu_percent == 12.5
    assert observation.memory.available_bytes == 20 * 1024**3
    assert observation.disks[0].free_bytes == 512 * 1024**3
    assert len(observation.disks) <= 8
