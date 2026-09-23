"""Worker evidence never implies complete coverage or exact GPU sample instants."""

import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from systemsense import worker
from systemsense.domain.ids import JsonValue
from systemsense.packs.core import resources as core_resources
from systemsense.packs.core import system as core_system
from systemsense.packs.devices.drivers import DriverObservation, WmiDriverBackend
from systemsense.packs.devices.pnp import DeviceObservation, WmiDeviceBackend
from systemsense.packs.local_ai import packages as local_ai_packages
from systemsense.packs.local_ai import python as local_ai_python
from systemsense.packs.local_ai.gpu import WmiGpuBackend
from systemsense.packs.network.adapters import AdapterObservation, PsutilAdapterBackend
from systemsense.packs.network.connections import (
    ConnectionObservation,
    PsutilNetworkConnectionBackend,
)
from systemsense.packs.servicing.history import (
    InstalledUpdate,
    RegistryRebootBackend,
    WmiServicingBackend,
)
from systemsense.platform.windows import connectivity, deep_collectors, display_mode

NOW = datetime(2026, 9, 23, 12, tzinfo=UTC)


@pytest.mark.parametrize(
    ("handler_name", "collector_name", "collector_module"),
    [
        ("_application_snapshot", "collect_application_topology", deep_collectors),
        ("_storage_snapshot", "collect_storage_snapshot", deep_collectors),
        ("_network_configuration", "collect_network_configuration", deep_collectors),
        ("_network_connectivity", "collect_connectivity_snapshot", connectivity),
        ("_power_snapshot", "collect_power_snapshot", deep_collectors),
        ("_security_snapshot", "collect_security_snapshot", deep_collectors),
        ("_incident_events", "collect_incident_events", deep_collectors),
        ("_network_listeners", "collect_network_listeners", deep_collectors),
        ("_pressure_sample", "collect_pressure_sample", deep_collectors),
    ],
)
def test_multistep_worker_collectors_publish_completion_bounded_envelope(
    monkeypatch: pytest.MonkeyPatch,
    handler_name: str,
    collector_name: str,
    collector_module: object,
) -> None:
    completed_at = NOW + timedelta(seconds=4)
    times = iter((NOW, completed_at))
    monkeypatch.setattr(worker, "utc_now", lambda: next(times))
    status = SimpleNamespace(value="available")

    def empty_model_dump(**_kwargs: object) -> dict[str, JsonValue]:
        return {}

    def source_model_dump(**_kwargs: object) -> dict[str, JsonValue]:
        return {"captured_at": NOW.isoformat()}

    def empty_preview(_snapshot: object) -> dict[str, JsonValue]:
        return {}

    nested = SimpleNamespace(model_dump=empty_model_dump)
    observation = SimpleNamespace(
        captured_at=NOW,
        window_ended_at=NOW + timedelta(seconds=2),
        listener_table_started_at=NOW + timedelta(seconds=1),
        listener_table_completed_at=NOW + timedelta(seconds=2),
        processes=(),
        services=(),
        startup=(),
        boot_time=NOW - timedelta(hours=1),
        omitted_process_count=0,
        omitted_service_count=0,
        omitted_startup_count=0,
        volumes=(),
        physical_disks=(),
        volume_mappings=(),
        partitions=(),
        reliability=(),
        routes=(),
        adapters=(),
        proxy=nested,
        wifi_interfaces=(),
        recent_failures=(),
        ac_line_status="online",
        active_scheme_guid=None,
        antivirus_products=(),
        firewall_profiles=(),
        events=(),
        channel_status={},
        listeners=(),
        omitted_listener_count=0,
        status=status,
        limitations=(),
        model_dump=source_model_dump,
    )
    monkeypatch.setattr(collector_module, collector_name, lambda: observation)
    monkeypatch.setattr(connectivity, "connectivity_preview", empty_preview)
    payloads: list[dict[str, JsonValue]] = []
    monkeypatch.setattr(worker, "_emit", payloads.append)

    getattr(worker, handler_name)({})

    payload = payloads[0]
    facts = cast("dict[str, JsonValue]", payload["facts"])
    assert payload["observed_at"] == completed_at.isoformat()
    assert payload["captured_at"] == completed_at.isoformat()
    assert payload["time_quality"] == "bounded_interval"
    assert facts["collection_started_at"] == NOW.isoformat()
    assert facts["collection_completed_at"] == completed_at.isoformat()
    assert any("interval" in item for item in cast("list[str]", payload["limitations"]))
    if handler_name == "_network_listeners":
        assert facts["listener_table_started_at"] == (NOW + timedelta(seconds=1)).isoformat()
        assert facts["listener_table_completed_at"] == (NOW + timedelta(seconds=2)).isoformat()


def test_display_worker_preserves_bounded_query_interval(monkeypatch: pytest.MonkeyPatch) -> None:
    completed_at = NOW + timedelta(seconds=3)
    observation = display_mode.DisplayModeObservation(
        collection_started_at=NOW,
        observed_at=completed_at,
        captured_at=completed_at,
        status=display_mode.DisplayModeStatus.AVAILABLE,
        width_pixels=2560,
        height_pixels=1440,
        refresh_hz=144,
        limitations=("Display-mode query instant is unknown within the collection interval",),
    )
    monkeypatch.setattr(display_mode, "collect_display_mode", lambda: observation)
    payloads: list[dict[str, JsonValue]] = []
    monkeypatch.setattr(worker, "_emit", payloads.append)

    worker._display_mode({})  # pyright: ignore[reportPrivateUsage]

    payload = payloads[0]
    facts = cast("dict[str, JsonValue]", payload["facts"])
    nested = cast("dict[str, JsonValue]", facts["display_mode"])
    assert payload["observed_at"] == completed_at.isoformat()
    assert payload["time_quality"] == "bounded_interval"
    assert nested["collection_started_at"] == NOW.isoformat().replace("+00:00", "Z")


def test_devices_snapshot_reports_hidden_tail_instead_of_implying_gpu_was_inspected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    devices = tuple(
        DeviceObservation(
            instance_id=f"DEVICE_{index}",
            name="Target NVIDIA GPU" if index == 64 else f"Device {index}",
            present=True,
        )
        for index in range(65)
    )
    drivers = tuple(
        DriverObservation(
            device_id=f"DEVICE_{index}",
            name="Target NVIDIA driver" if index == 64 else f"Driver {index}",
        )
        for index in range(65)
    )
    requested: list[int] = []

    def get_devices(
        _self: WmiDeviceBackend, *, max_records: int = 1024
    ) -> tuple[DeviceObservation, ...]:
        requested.append(max_records)
        return devices[:max_records]

    def get_drivers(
        _self: WmiDriverBackend, *, max_records: int = 1024
    ) -> tuple[DriverObservation, ...]:
        requested.append(max_records)
        return drivers[:max_records]

    payloads: list[dict[str, JsonValue]] = []
    monkeypatch.setattr(WmiDeviceBackend, "devices", get_devices)
    monkeypatch.setattr(WmiDriverBackend, "drivers", get_drivers)
    monkeypatch.setattr("systemsense.worker._emit", payloads.append)

    worker._devices_snapshot({})  # pyright: ignore[reportPrivateUsage]

    payload = payloads[0]
    facts = cast("dict[str, JsonValue]", payload["facts"])
    returned_devices = cast("list[dict[str, JsonValue]]", facts["devices"])
    returned_drivers = cast("list[dict[str, JsonValue]]", facts["drivers"])
    assert requested == [65, 65]
    assert len(returned_devices) == len(returned_drivers) == 64
    assert all(item["name"] != "Target NVIDIA GPU" for item in returned_devices)
    assert all(item["name"] != "Target NVIDIA driver" for item in returned_drivers)
    assert facts["devices_truncated"] is True
    assert facts["drivers_truncated"] is True
    limitations = cast("list[str]", payload["limitations"])
    assert any("device" in item and "at least one" in item for item in limitations)
    assert any("driver" in item and "at least one" in item for item in limitations)


def test_devices_snapshot_under_cap_has_no_truncation_claim(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    device = DeviceObservation(instance_id="ONE", name="One", present=True)
    driver = DriverObservation(device_id="ONE", name="One")

    def get_devices(
        _self: WmiDeviceBackend, *, max_records: int = 1024
    ) -> tuple[DeviceObservation, ...]:
        return (device,)

    def get_drivers(
        _self: WmiDriverBackend, *, max_records: int = 1024
    ) -> tuple[DriverObservation, ...]:
        return (driver,)

    monkeypatch.setattr(WmiDeviceBackend, "devices", get_devices)
    monkeypatch.setattr(WmiDriverBackend, "drivers", get_drivers)
    payloads: list[dict[str, JsonValue]] = []
    monkeypatch.setattr("systemsense.worker._emit", payloads.append)

    worker._devices_snapshot({})  # pyright: ignore[reportPrivateUsage]

    facts = cast("dict[str, JsonValue]", payloads[0]["facts"])
    assert facts["devices_truncated"] is False
    assert facts["drivers_truncated"] is False
    assert not any("omitted" in item for item in cast("list[str]", payloads[0]["limitations"]))
    assert payloads[0]["time_quality"] == "bounded_interval"


def test_nvidia_query_uses_completion_upper_bound_not_pre_query_as_capture(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    executable = tmp_path / "nvidia-smi.exe"
    executable.touch()
    monkeypatch.setattr(deep_collectors, "_nvidia_smi_candidates", lambda: (executable,))
    times = iter((NOW, NOW + timedelta(seconds=3)))
    monkeypatch.setattr(deep_collectors, "utc_now", lambda: next(times))

    def run(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            args=[],
            returncode=0,
            stdout=(
                "0, GPU-abc, RTX Fixture, 600.1, 72, 4096, 2048, 61, "
                "320.5, 450.0, 2550, 10501, 0x0\n"
            ),
        )

    monkeypatch.setattr(deep_collectors.subprocess, "run", run)
    snapshot = deep_collectors.collect_nvidia_telemetry()

    assert snapshot.sample_started_at == NOW
    assert snapshot.captured_at == NOW + timedelta(seconds=3)
    assert snapshot.status is deep_collectors.ComponentStatus.AVAILABLE
    assert snapshot.limitation is not None and "sample instant" in snapshot.limitation


def test_nvidia_query_failure_captures_failure_completion_not_start(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    executable = tmp_path / "nvidia-smi.exe"
    executable.touch()
    monkeypatch.setattr(deep_collectors, "_nvidia_smi_candidates", lambda: (executable,))
    times = iter((NOW, NOW + timedelta(seconds=3)))
    monkeypatch.setattr(deep_collectors, "utc_now", lambda: next(times))

    def timeout(*_args: object, **_kwargs: object) -> subprocess.CompletedProcess[str]:
        raise subprocess.TimeoutExpired(cmd="nvidia-smi.exe", timeout=3)

    monkeypatch.setattr(deep_collectors.subprocess, "run", timeout)
    snapshot = deep_collectors.collect_nvidia_telemetry()

    assert snapshot.sample_started_at == NOW
    assert snapshot.captured_at == NOW + timedelta(seconds=3)
    assert snapshot.status is deep_collectors.ComponentStatus.FAILED


def test_nvidia_series_starts_at_first_query_start_not_first_completion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    starts = (NOW, NOW + timedelta(seconds=1), NOW + timedelta(seconds=2))
    samples = iter(
        deep_collectors.NvidiaTelemetrySnapshot(
            sample_started_at=start,
            captured_at=start + timedelta(milliseconds=400),
            status=deep_collectors.ComponentStatus.AVAILABLE,
            limitation="nvidia-smi sample instant is unknown within the bounded query interval",
        )
        for start in starts
    )
    monkeypatch.setattr(deep_collectors, "collect_nvidia_telemetry", lambda: next(samples))

    def no_sleep(_delay: float) -> None:
        pass

    monkeypatch.setattr(deep_collectors.time, "sleep", no_sleep)
    monkeypatch.setattr(deep_collectors, "utc_now", lambda: NOW + timedelta(seconds=3))

    series = deep_collectors.collect_gpu_telemetry_sample()

    assert series.window_started_at == NOW
    assert series.window_ended_at == NOW + timedelta(seconds=2, milliseconds=400)
    assert series.captured_at == NOW + timedelta(seconds=3)
    assert len(series.limitations) == 1


def test_nvidia_snapshot_rejects_completion_before_query_start() -> None:
    with pytest.raises(ValueError, match="precedes query start"):
        deep_collectors.NvidiaTelemetrySnapshot(
            sample_started_at=NOW + timedelta(seconds=1),
            captured_at=NOW,
            status=deep_collectors.ComponentStatus.AVAILABLE,
        )


def test_local_ai_worker_marks_multi_source_collection_as_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    end = NOW + timedelta(seconds=4)
    times = iter((NOW, end))
    monkeypatch.setattr(worker, "utc_now", lambda: next(times))

    def no_gpus(_self: WmiGpuBackend, *, max_records: int = 32):
        return ()

    monkeypatch.setattr(WmiGpuBackend, "gpus", no_gpus)
    monkeypatch.setattr(
        deep_collectors,
        "collect_nvidia_telemetry",
        lambda: deep_collectors.NvidiaTelemetrySnapshot(
            captured_at=NOW + timedelta(seconds=2),
            status=deep_collectors.ComponentStatus.UNSUPPORTED,
            limitation="nvidia-smi unavailable",
        ),
    )
    monkeypatch.setattr(
        local_ai_python,
        "current_python_environment",
        lambda: local_ai_python.PythonEnvironment(
            executable="python.exe",
            version="3.12",
            implementation="CPython",
            prefix="C:\\Python",
            base_prefix="C:\\Python",
            virtual_environment=False,
            architecture="64-bit",
        ),
    )
    monkeypatch.setattr(local_ai_packages, "current_packages", lambda *, max_records=2048: ())
    payloads: list[dict[str, JsonValue]] = []
    monkeypatch.setattr("systemsense.worker._emit", payloads.append)

    worker._local_ai_snapshot({})  # pyright: ignore[reportPrivateUsage]

    payload = payloads[0]
    facts = cast("dict[str, JsonValue]", payload["facts"])
    assert payload["observed_at"] == end.isoformat()
    assert payload["captured_at"] == end.isoformat()
    assert payload["time_quality"] == "bounded_interval"
    assert facts["collection_started_at"] == NOW.isoformat()
    assert facts["collection_completed_at"] == end.isoformat()


def test_network_snapshot_uses_completion_as_upper_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    end = NOW + timedelta(seconds=2)
    times = iter((NOW, end))
    monkeypatch.setattr(worker, "utc_now", lambda: next(times))

    def adapters(_self: PsutilAdapterBackend) -> tuple[AdapterObservation, ...]:
        return ()

    def connections(
        _self: PsutilNetworkConnectionBackend, *, max_records: int = 256
    ) -> tuple[ConnectionObservation, ...]:
        return ()

    monkeypatch.setattr(PsutilAdapterBackend, "adapters", adapters)
    monkeypatch.setattr(PsutilNetworkConnectionBackend, "connections", connections)
    payloads: list[dict[str, JsonValue]] = []
    monkeypatch.setattr("systemsense.worker._emit", payloads.append)

    worker._network_snapshot({})  # pyright: ignore[reportPrivateUsage]

    payload = payloads[0]
    facts = cast("dict[str, JsonValue]", payload["facts"])
    assert payload["observed_at"] == end.isoformat()
    assert payload["captured_at"] == end.isoformat()
    assert payload["time_quality"] == "bounded_interval"
    assert facts["collection_started_at"] == NOW.isoformat()


def test_network_snapshot_reports_endpoint_tail(monkeypatch: pytest.MonkeyPatch) -> None:
    records = tuple(
        ConnectionObservation(local_address="127.0.0.1", local_port=1000 + index, status="LISTEN")
        for index in range(129)
    )
    requested: list[int] = []

    def adapters(_self: PsutilAdapterBackend) -> tuple[AdapterObservation, ...]:
        return ()

    def connections(
        _self: PsutilNetworkConnectionBackend, *, max_records: int = 256
    ) -> tuple[ConnectionObservation, ...]:
        requested.append(max_records)
        return records[:max_records]

    monkeypatch.setattr(PsutilAdapterBackend, "adapters", adapters)
    monkeypatch.setattr(PsutilNetworkConnectionBackend, "connections", connections)
    payloads: list[dict[str, JsonValue]] = []
    monkeypatch.setattr("systemsense.worker._emit", payloads.append)

    worker._network_snapshot({})  # pyright: ignore[reportPrivateUsage]

    facts = cast("dict[str, JsonValue]", payloads[0]["facts"])
    assert requested == [129]
    assert len(cast("list[JsonValue]", facts["connections"])) == 128
    assert facts["connections_truncated"] is True
    assert any(
        "endpoint was omitted" in item for item in cast("list[str]", payloads[0]["limitations"])
    )


def test_servicing_snapshot_uses_completion_as_upper_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    end = NOW + timedelta(seconds=2)
    times = iter((NOW, end))
    monkeypatch.setattr(worker, "utc_now", lambda: next(times))

    def updates(
        _self: WmiServicingBackend, *, max_records: int = 256
    ) -> tuple[InstalledUpdate, ...]:
        return ()

    def reboot_sources(_self: RegistryRebootBackend) -> dict[str, bool]:
        return {"windows_update": False}

    monkeypatch.setattr(WmiServicingBackend, "updates", updates)
    monkeypatch.setattr(RegistryRebootBackend, "sources", reboot_sources)
    payloads: list[dict[str, JsonValue]] = []
    monkeypatch.setattr("systemsense.worker._emit", payloads.append)

    worker._servicing_snapshot({})  # pyright: ignore[reportPrivateUsage]

    payload = payloads[0]
    facts = cast("dict[str, JsonValue]", payload["facts"])
    assert payload["observed_at"] == end.isoformat()
    assert payload["captured_at"] == end.isoformat()
    assert payload["time_quality"] == "bounded_interval"
    assert facts["collection_started_at"] == NOW.isoformat()


def test_servicing_snapshot_reports_update_tail(monkeypatch: pytest.MonkeyPatch) -> None:
    records = tuple(InstalledUpdate(kb=f"KB{index}", description="fixture") for index in range(129))
    requested: list[int] = []

    def updates(
        _self: WmiServicingBackend, *, max_records: int = 256
    ) -> tuple[InstalledUpdate, ...]:
        requested.append(max_records)
        return records[:max_records]

    def reboot_sources(_self: RegistryRebootBackend) -> dict[str, bool]:
        return {"windows_update": False}

    monkeypatch.setattr(WmiServicingBackend, "updates", updates)
    monkeypatch.setattr(RegistryRebootBackend, "sources", reboot_sources)
    payloads: list[dict[str, JsonValue]] = []
    monkeypatch.setattr("systemsense.worker._emit", payloads.append)

    worker._servicing_snapshot({})  # pyright: ignore[reportPrivateUsage]

    facts = cast("dict[str, JsonValue]", payloads[0]["facts"])
    assert requested == [129]
    assert len(cast("list[JsonValue]", facts["updates"])) == 128
    assert facts["updates_truncated"] is True
    assert any(
        "update was omitted" in item for item in cast("list[str]", payloads[0]["limitations"])
    )


def test_core_system_nested_and_outer_capture_are_completion_upper_bound(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    end = NOW + timedelta(seconds=3)
    times = iter((NOW, end))
    monkeypatch.setattr(worker, "utc_now", lambda: next(times))

    def identity(_backend: object, *, captured_at: datetime) -> core_system.SystemIdentity:
        return core_system.SystemIdentity(
            captured_at=captured_at,
            os_name="Windows",
            os_version="11",
            windows_build="fixture",
            architecture="x64",
            boot_time=NOW - timedelta(hours=1),
            uptime_seconds=3600,
            logical_cpu_count=8,
            total_memory_bytes=1024,
            disks=(),
        )

    monkeypatch.setattr(core_system, "collect_system_identity", identity)
    payloads: list[dict[str, JsonValue]] = []
    monkeypatch.setattr("systemsense.worker._emit", payloads.append)

    worker._core_system({})  # pyright: ignore[reportPrivateUsage]

    payload = payloads[0]
    facts = cast("dict[str, JsonValue]", payload["facts"])
    system = cast("dict[str, JsonValue]", facts["system"])
    assert payload["observed_at"] == end.isoformat()
    assert payload["time_quality"] == "bounded_interval"
    assert system["captured_at"] == end.isoformat().replace("+00:00", "Z")
    assert system["uptime_seconds"] == 3603.0
    assert facts["collection_started_at"] == NOW.isoformat()


def test_core_resources_preserves_cpu_interval_and_marks_envelope_bounded(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observation = core_resources.ResourceObservation(
        captured_at=NOW + timedelta(seconds=2),
        cpu_sample_started_at=NOW,
        cpu_sample_ended_at=NOW + timedelta(milliseconds=200),
        cpu_sample_interval_seconds=0.2,
        cpu_percent=12.5,
        memory=core_resources.MemoryUsage(total_bytes=1024, available_bytes=512, percent=50.0),
        disks=(),
        omitted_disk_count=0,
    )

    def resources(
        _backend: core_resources.PsutilResourceBackend,
    ) -> core_resources.ResourceObservation:
        return observation

    monkeypatch.setattr(core_resources, "collect_resources", resources)
    payloads: list[dict[str, JsonValue]] = []
    monkeypatch.setattr("systemsense.worker._emit", payloads.append)

    worker._core_resources({})  # pyright: ignore[reportPrivateUsage]

    payload = payloads[0]
    assert payload["observed_at"] == observation.captured_at.isoformat()
    assert payload["time_quality"] == "bounded_interval"
    assert any("CPU is an interval" in item for item in cast("list[str]", payload["limitations"]))


def test_gpu_worker_marks_completion_time_as_bounded_not_exact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    started = NOW
    ended = NOW + timedelta(seconds=3)
    series = deep_collectors.NvidiaTelemetrySeries(
        captured_at=ended + timedelta(milliseconds=20),
        window_started_at=started,
        window_ended_at=ended,
        inter_sample_delay_seconds=0.5,
        samples=(
            deep_collectors.NvidiaTelemetrySnapshot(
                sample_started_at=started,
                captured_at=ended,
                status=deep_collectors.ComponentStatus.AVAILABLE,
            ),
        ),
        status=deep_collectors.ComponentStatus.AVAILABLE,
        limitations=("nvidia-smi sample instant is unknown within each query interval",),
    )
    monkeypatch.setattr(deep_collectors, "collect_gpu_telemetry_sample", lambda: series)
    payloads: list[dict[str, JsonValue]] = []
    monkeypatch.setattr("systemsense.worker._emit", payloads.append)

    worker._gpu_telemetry_sample({})  # pyright: ignore[reportPrivateUsage]

    payload = payloads[0]
    assert payload["observed_at"] == ended.isoformat()
    assert payload["captured_at"] == series.captured_at.isoformat()
    assert payload["time_quality"] == "bounded_interval"
    assert any("sample instant" in item for item in cast("list[str]", payload["limitations"]))
