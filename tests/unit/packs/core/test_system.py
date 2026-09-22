from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest

from systemsense.packs.core import resources
from systemsense.packs.core.resources import (
    DiskUsage,
    DiskUsageCollection,
    MemoryUsage,
    PsutilResourceBackend,
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
    def cpu_percent(self, interval_seconds: float) -> float:
        assert interval_seconds == 0.2
        return 12.5

    def memory_usage(self) -> MemoryUsage:
        return MemoryUsage(
            total_bytes=32 * 1024**3,
            available_bytes=20 * 1024**3,
            percent=37.5,
        )

    def disk_usage(self) -> DiskUsageCollection:
        return DiskUsageCollection(
            disks=(
                DiskUsage(
                    mountpoint="C:\\",
                    total_bytes=1024**4,
                    free_bytes=512 * 1024**3,
                    percent=50.0,
                ),
            ),
            omitted_disk_count=0,
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
    observation = collect_resources(FakeResourceBackend(), clock=lambda: _NOW)

    assert observation.cpu_percent == 12.5
    assert observation.memory.available_bytes == 20 * 1024**3
    assert observation.disks[0].free_bytes == 512 * 1024**3
    assert len(observation.disks) <= 8
    assert observation.omitted_disk_count == 0
    assert observation.limitations == ()


def test_psutil_cpu_percent_uses_a_real_bounded_sampling_interval(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    intervals: list[float | None] = []

    def cpu_percent(*, interval: float | None = None) -> float:
        intervals.append(interval)
        return 17.5

    monkeypatch.setattr(resources.psutil, "cpu_percent", cpu_percent)

    assert PsutilResourceBackend().cpu_percent() == 17.5
    assert len(intervals) == 1
    assert intervals[0] is not None
    assert 0 < intervals[0] <= 0.5


def test_resource_observation_discloses_cpu_sample_window_and_post_capture_time() -> None:
    class TimedBackend(FakeResourceBackend):
        def cpu_percent(self, interval_seconds: float) -> float:
            assert interval_seconds == 0.2
            return 12.5

    timestamps = iter(
        (
            _NOW,
            _NOW + timedelta(milliseconds=200),
            _NOW + timedelta(milliseconds=210),
        )
    )

    observation = collect_resources(TimedBackend(), clock=lambda: next(timestamps))

    assert observation.cpu_sample_started_at == _NOW
    assert observation.cpu_sample_ended_at == _NOW + timedelta(milliseconds=200)
    assert observation.cpu_sample_interval_seconds == 0.2
    assert observation.captured_at == _NOW + timedelta(milliseconds=210)


def test_psutil_disk_usage_discloses_unavailable_and_record_limit_omissions(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    partitions = [SimpleNamespace(mountpoint=f"D{index}:\\") for index in range(10)]

    def disk_partitions(*, all: bool) -> list[SimpleNamespace]:
        assert not all
        return partitions

    def disk_usage(mountpoint: str) -> SimpleNamespace:
        if mountpoint == "D0:\\":
            raise PermissionError("fixture denied")
        return SimpleNamespace(total=1000, free=500, percent=50.0)

    monkeypatch.setattr(resources.psutil, "disk_partitions", disk_partitions)
    monkeypatch.setattr(resources.psutil, "disk_usage", disk_usage)

    result = PsutilResourceBackend().disk_usage()

    assert len(result.disks) == 8
    assert result.omitted_disk_count == 2
    assert result.limitations == (
        "1 mounted filesystem usage record was unavailable",
        "1 mounted filesystem usage record was omitted by the 8-record limit",
    )
