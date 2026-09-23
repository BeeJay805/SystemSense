from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from systemsense.platform.windows import deep_collectors
from systemsense.platform.windows.deep_collectors import (
    ComponentStatus,
    DiskPartition,
    IncidentProfileEvent,
    PhysicalDisk,
    ProcessTopology,
    ReliabilityCounter,
    ServiceTopology,
    StartupEntry,
    StorageVolume,
    collect_gpu_telemetry_sample,
    collect_incident_events,
    collect_network_configuration,
    collect_network_listeners,
    collect_pressure_sample,
    collect_storage_snapshot,
    filter_incident_events,
    join_storage_topology,
    normalize_application_topology,
    parse_nvidia_smi_csv,
    parse_wmi_datetime,
)
from systemsense.platform.windows.eventlog import EventQuery, QueryStatus, WindowsEvent

NOW = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)


def _event(provider: str, event_id: int, record_id: int) -> WindowsEvent:
    return WindowsEvent(
        channel="System",
        provider=provider,
        event_id=event_id,
        record_id=record_id,
        level=2,
        observed_at=NOW,
        computer="fixture",
        event_data={},
        source_id=f"src_{record_id:064x}",
    )


def test_storage_topology_preserves_explicit_volume_disk_mapping_and_unknown_reliability() -> None:
    snapshot = join_storage_topology(
        volumes=(
            StorageVolume(
                volume_id="C:",
                filesystem="NTFS",
                total_bytes=1000,
                free_bytes=250,
                status=ComponentStatus.AVAILABLE,
            ),
        ),
        partitions=(DiskPartition(partition_id="Disk #0, Partition #1", disk_index=0),),
        disks=(
            PhysicalDisk(
                disk_index=0,
                device_id=r"\\.\PHYSICALDRIVE0",
                model="Fixture SSD",
                size_bytes=2000,
            ),
        ),
        volume_to_partition=(("C:", "Disk #0, Partition #1"),),
        reliability=(),
    )

    assert snapshot.volume_mappings[0].disk_index == 0
    assert snapshot.reliability == (
        ReliabilityCounter(
            disk_index=0,
            status=ComponentStatus.UNSUPPORTED,
            limitation="storage reliability counters were not exposed for this disk",
        ),
    )
    assert snapshot.status is ComponentStatus.PARTIAL


def test_storage_topology_preserves_every_volume_partition_association() -> None:
    snapshot = join_storage_topology(
        volumes=(StorageVolume(volume_id="S:"),),
        partitions=(
            DiskPartition(partition_id="Disk #0, Partition #1", disk_index=0),
            DiskPartition(partition_id="Disk #1, Partition #2", disk_index=1),
        ),
        disks=(
            PhysicalDisk(disk_index=0, device_id=r"\\.\PHYSICALDRIVE0"),
            PhysicalDisk(disk_index=1, device_id=r"\\.\PHYSICALDRIVE1"),
        ),
        volume_to_partition=(
            ("S:", "Disk #0, Partition #1"),
            ("S:", "Disk #1, Partition #2"),
        ),
        reliability=(),
    )

    assert {(item.partition_id, item.disk_index) for item in snapshot.volume_mappings} == {
        ("Disk #0, Partition #1", 0),
        ("Disk #1, Partition #2", 1),
    }
    assert snapshot.status is ComponentStatus.PARTIAL
    assert any("multiple disks" in item for item in snapshot.limitations)


def test_application_topology_uses_boot_safe_identity_and_service_dependencies() -> None:
    snapshot = normalize_application_topology(
        processes=(
            ProcessTopology(
                pid=42,
                ppid=4,
                name="service-host.exe",
                creation_time=NOW,
                executable=r"C:\Windows\service-host.exe",
                username="SYSTEM",
                status="running",
            ),
            ProcessTopology(
                pid=43,
                ppid=42,
                name="bounded-out.exe",
                creation_time=NOW,
                executable=None,
                username=None,
                status="running",
            ),
        ),
        services=(
            ServiceTopology(
                name="AudioSrv",
                display_name="Windows Audio",
                state="Running",
                start_mode="Auto",
                process_id=42,
                dependencies=("RpcSs",),
            ),
        ),
        startup=(
            StartupEntry(
                name="Fixture",
                command="fixture.exe --start",
                location="HKLM Run",
                user="Public",
            ),
        ),
        max_processes=1,
        max_services=1,
        max_startup=1,
    )

    assert snapshot.processes[0].identity == f"42@{NOW.isoformat()}"
    assert snapshot.omitted_process_count == 1
    assert "process limit reached" in snapshot.limitations
    assert snapshot.services[0].dependencies == ("RpcSs",)
    assert snapshot.startup[0].name == "Fixture"


def test_incident_profile_accepts_only_fixed_provider_event_pairs_and_keeps_source_time() -> None:
    events = (
        _event("Microsoft-Windows-WHEA-Logger", 18, 3),
        _event("Microsoft-Windows-Kernel-Power", 41, 2),
        _event("Unrelated", 999, 1),
    )

    selected = filter_incident_events(events, max_records=8)

    assert selected == (
        IncidentProfileEvent.from_event(events[1], profile="power"),
        IncidentProfileEvent.from_event(events[0], profile="hardware"),
    )
    assert selected[0].observed_at == NOW


def test_incident_profile_accepts_storage_reset_provider_aliases() -> None:
    events = (
        _event("Microsoft-Windows-Storport", 129, 1),
        _event("storahci", 129, 2),
        _event("stornvme", 129, 3),
    )

    selected = filter_incident_events(events)

    assert [item.provider for item in selected] == [item.provider for item in events]
    assert all(item.profile == "storage" for item in selected)


def test_incident_collection_reports_profile_gap_when_event_precedes_recent_cap(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    source_events = (
        _event("stornvme", 129, 1),
        *(_event("Unrelated", 999, record_id) for record_id in range(2, 102)),
    )

    class Adapter:
        def __init__(self, _backend: object, *, max_records: int) -> None:
            assert max_records == 100

        def query(self, channel: str, *, after_record_id: int | None, limit: int) -> EventQuery:
            assert after_record_id is None
            assert limit == 100
            return EventQuery(
                status=QueryStatus.OK,
                events=source_events[-100:] if channel == "System" else (),
            )

    monkeypatch.setattr(deep_collectors, "FixedEventLogAdapter", Adapter)

    snapshot = collect_incident_events()

    assert snapshot.events == ()
    assert snapshot.channel_status["System"] is ComponentStatus.PARTIAL
    assert any("System" in item and "profile" in item for item in snapshot.limitations)


def test_nvidia_telemetry_parser_keeps_supported_values_and_marks_missing_values_unknown() -> None:
    rows = parse_nvidia_smi_csv(
        "0, GPU-abc, RTX Fixture, 600.1, 72, 4096, 2048, 61, 320.5, 450.0, "
        "2550, 10501, 0x0000000000000000\n"
        "1, GPU-def, RTX Other, 600.1, N/A, N/A, 8192, [Not Supported], "
        "N/A, 350.0, 1800, 9000, 0x0000000000000001\n"
    )

    assert rows[0].utilization_percent == 72
    assert rows[0].power_draw_w == 320.5
    assert rows[1].utilization_percent is None
    assert rows[1].temperature_c is None
    assert rows[1].throttle_reasons_active == "0x0000000000000001"


def test_nvidia_telemetry_parser_rejects_negative_device_indices() -> None:
    rows = parse_nvidia_smi_csv(
        "-1, GPU-invalid, Invalid, 600.1, 0, 0, 0, 0, 0, 0, 0, 0, 0x0\n"
        "0, GPU-valid, Valid, 600.1, 0, 0, 0, 0, 0, 0, 0, 0, 0x0\n"
    )

    assert [item.uuid for item in rows] == ["GPU-valid"]


def test_wmi_process_creation_time_is_normalized_to_utc() -> None:
    assert parse_wmi_datetime("20260920162621.549812-420") == datetime(
        2026, 9, 20, 23, 26, 21, 549812, tzinfo=UTC
    )


def test_nvidia_worker_environment_includes_fixed_driver_runtime_directories() -> None:
    environment = deep_collectors._nvidia_smi_environment(  # pyright: ignore[reportPrivateUsage]
        Path(r"C:\Windows\System32\nvidia-smi.exe")
    )

    assert environment["ProgramFiles"]
    assert environment["ProgramData"]


def test_network_listeners_join_exact_tcp_endpoint_to_stable_process_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = SimpleNamespace(
        status="LISTEN",
        laddr=SimpleNamespace(ip="127.0.0.1", port=18765),
        family=2,
        pid=4242,
    )
    process = SimpleNamespace(
        name=lambda: "systemsense-preview.exe",
        create_time=lambda: NOW.timestamp(),
    )

    def net_connections(*, kind: str) -> list[SimpleNamespace]:
        del kind
        return [connection]

    def process_for_pid(pid: int) -> SimpleNamespace:
        del pid
        return process

    monkeypatch.setattr(deep_collectors.psutil, "net_connections", net_connections)
    monkeypatch.setattr(deep_collectors.psutil, "Process", process_for_pid)

    snapshot = collect_network_listeners()

    assert snapshot.status is ComponentStatus.AVAILABLE
    assert snapshot.omitted_listener_count == 0
    assert snapshot.listeners[0].local_address == "127.0.0.1"
    assert snapshot.listeners[0].local_port == 18765
    assert snapshot.listeners[0].protocol == "tcp4"
    assert snapshot.listeners[0].pid == 4242
    assert snapshot.listeners[0].process_name == "systemsense-preview.exe"
    assert snapshot.listeners[0].process_creation_time == NOW


def test_network_listener_zero_creation_sentinel_is_not_a_1970_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    connection = SimpleNamespace(
        status="LISTEN",
        laddr=SimpleNamespace(ip="0.0.0.0", port=445),
        family=2,
        pid=4,
    )
    process = SimpleNamespace(name=lambda: "System", create_time=lambda: 0.0)

    def net_connections(*, kind: str) -> list[SimpleNamespace]:
        assert kind == "tcp"
        return [connection]

    def process_for_pid(pid: int) -> SimpleNamespace:
        assert pid == 4
        return process

    monkeypatch.setattr(
        deep_collectors.psutil,
        "net_connections",
        net_connections,
    )
    monkeypatch.setattr(deep_collectors.psutil, "Process", process_for_pid)

    snapshot = collect_network_listeners()

    assert snapshot.status is ComponentStatus.PARTIAL
    assert snapshot.listeners[0].pid == 4
    assert snapshot.listeners[0].process_name == "System"
    assert snapshot.listeners[0].process_creation_time is None
    assert snapshot.listeners[0].owner_status is ComponentStatus.UNSUPPORTED
    assert all("1970" not in item for item in snapshot.limitations)


def test_storage_snapshot_omits_invalid_indices_without_fabricating_disk_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Service:
        def __init__(self, storage: bool) -> None:
            self.storage = storage

        def ExecQuery(self, query: str) -> list[SimpleNamespace]:
            if self.storage:
                return [
                    SimpleNamespace(DeviceId=None),
                    SimpleNamespace(DeviceId=-1),
                    SimpleNamespace(
                        DeviceId=7,
                        Temperature=30,
                        Wear=1,
                        ReadErrorsTotal=0,
                        WriteErrorsTotal=0,
                    ),
                ]
            if "Win32_LogicalDiskToPartition" in query:
                return []
            if "Win32_LogicalDisk" in query:
                return []
            if "Win32_DiskPartition" in query:
                return [
                    SimpleNamespace(DeviceID="missing", DiskIndex=None),
                    SimpleNamespace(DeviceID="negative", DiskIndex=-1),
                    SimpleNamespace(DeviceID="valid", DiskIndex=7),
                ]
            if "Win32_DiskDrive" in query:
                return [
                    SimpleNamespace(DeviceID="missing", Index=None),
                    SimpleNamespace(DeviceID="negative", Index=-1),
                    SimpleNamespace(DeviceID="valid", Index=7),
                ]
            raise AssertionError(query)

    def service_for_namespace(namespace: str) -> Service:
        return Service("Microsoft" in namespace)

    monkeypatch.setattr(deep_collectors, "_wmi_service", service_for_namespace)

    snapshot = collect_storage_snapshot()

    assert [item.disk_index for item in snapshot.partitions] == [7]
    assert [item.disk_index for item in snapshot.physical_disks] == [7]
    assert [item.disk_index for item in snapshot.reliability] == [7]
    assert snapshot.status is ComponentStatus.PARTIAL
    assert any("2 partitions" in item for item in snapshot.limitations)
    assert any("2 physical disks" in item for item in snapshot.limitations)
    assert any("2 reliability rows" in item for item in snapshot.limitations)


def test_storage_collector_retains_both_associations_for_one_volume(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Service:
        def ExecQuery(self, query: str) -> list[SimpleNamespace]:
            if "Win32_LogicalDiskToPartition" in query:
                return [
                    SimpleNamespace(
                        Antecedent='Win32_DiskPartition.DeviceID="Disk #0, Partition #1"',
                        Dependent='Win32_LogicalDisk.DeviceID="S:"',
                    ),
                    SimpleNamespace(
                        Antecedent='Win32_DiskPartition.DeviceID="Disk #1, Partition #2"',
                        Dependent='Win32_LogicalDisk.DeviceID="S:"',
                    ),
                ]
            if "Win32_LogicalDisk" in query:
                return [SimpleNamespace(DeviceID="S:")]
            if "Win32_DiskPartition" in query:
                return [
                    SimpleNamespace(DeviceID="Disk #0, Partition #1", DiskIndex=0),
                    SimpleNamespace(DeviceID="Disk #1, Partition #2", DiskIndex=1),
                ]
            if "Win32_DiskDrive" in query:
                return [
                    SimpleNamespace(Index=0, DeviceID=r"\\.\PHYSICALDRIVE0"),
                    SimpleNamespace(Index=1, DeviceID=r"\\.\PHYSICALDRIVE1"),
                ]
            return []

    def service_for_namespace(_namespace: str) -> Service:
        return Service()

    monkeypatch.setattr(deep_collectors, "_wmi_service", service_for_namespace)

    snapshot = collect_storage_snapshot()

    assert {item.disk_index for item in snapshot.volume_mappings} == {0, 1}
    assert any("multiple disks" in item for item in snapshot.limitations)


def test_storage_reliability_does_not_join_on_unrelated_numeric_device_id(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Service:
        def __init__(self, storage: bool) -> None:
            self.storage = storage

        def ExecQuery(self, query: str) -> list[SimpleNamespace]:
            if self.storage:
                return [
                    SimpleNamespace(
                        DeviceId="7",
                        Temperature=89,
                        Wear=95,
                        ReadErrorsTotal=12,
                        WriteErrorsTotal=3,
                    )
                ]
            if "Win32_DiskDrive" in query:
                return [SimpleNamespace(Index=7, DeviceID=r"\\.\PHYSICALDRIVE7")]
            return []

    def service_for_namespace(namespace: str) -> Service:
        return Service("Microsoft" in namespace)

    monkeypatch.setattr(deep_collectors, "_wmi_service", service_for_namespace)

    snapshot = collect_storage_snapshot()

    assert snapshot.reliability[0].status is ComponentStatus.UNSUPPORTED
    assert snapshot.reliability[0].temperature_c is None
    assert any("unbound" in item for item in snapshot.limitations)


def test_network_configuration_omits_invalid_interface_indices(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rows = [
        SimpleNamespace(InterfaceIndex=None, Description="missing"),
        SimpleNamespace(InterfaceIndex=-1, Description="negative"),
        SimpleNamespace(
            InterfaceIndex=0,
            Description="valid zero",
            DHCPEnabled=False,
            DNSServerSearchOrder=(),
            DefaultIPGateway=(),
        ),
    ]

    class Service:
        def ExecQuery(self, query: str) -> list[SimpleNamespace]:
            assert query
            return rows

    def service_for_namespace(namespace: str) -> Service:
        assert namespace
        return Service()

    def no_routes(
        _self: deep_collectors.WmiRouteBackend,
        *,
        max_records: int = 1024,
    ) -> tuple[deep_collectors.RouteObservation, ...]:
        assert max_records > 0
        return (
            deep_collectors.RouteObservation(
                destination="0.0.0.0",
                prefix_length=0,
                next_hop="192.0.2.1",
                interface_index=0,
                metric=1,
            ),
        )

    monkeypatch.setattr(deep_collectors, "_wmi_service", service_for_namespace)
    monkeypatch.setattr(deep_collectors.WmiRouteBackend, "routes", no_routes)
    monkeypatch.setattr(
        deep_collectors,
        "_read_proxy_configuration",
        lambda: deep_collectors.ProxyConfiguration(
            enabled=None,
            status=ComponentStatus.UNSUPPORTED,
        ),
    )

    snapshot = collect_network_configuration()

    assert [item.interface_index for item in snapshot.adapters] == [0]
    assert snapshot.status is ComponentStatus.PARTIAL
    assert any("2 adapter rows" in item for item in snapshot.limitations)


def test_network_configuration_reports_route_and_adapter_caps(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    rows = [
        SimpleNamespace(
            InterfaceIndex=index,
            Description=f"Adapter {index}",
            DHCPEnabled=False,
            DNSServerSearchOrder=(),
            DefaultIPGateway=(),
        )
        for index in range(65)
    ]

    class Service:
        def ExecQuery(self, _query: str) -> list[SimpleNamespace]:
            return rows

    class Backend:
        omitted_route_count = 1

        def routes(
            self, *, max_records: int = 1024
        ) -> tuple[deep_collectors.RouteObservation, ...]:
            return (
                deep_collectors.RouteObservation(
                    destination="0.0.0.0",
                    prefix_length=0,
                    next_hop="192.0.2.1",
                    interface_index=3,
                    metric=1,
                ),
            )

    monkeypatch.setattr(deep_collectors, "WmiRouteBackend", Backend)

    def service_for_namespace(_namespace: str) -> Service:
        return Service()

    monkeypatch.setattr(deep_collectors, "_wmi_service", service_for_namespace)
    monkeypatch.setattr(
        deep_collectors,
        "_read_proxy_configuration",
        lambda: deep_collectors.ProxyConfiguration(
            enabled=False,
            status=ComponentStatus.AVAILABLE,
        ),
    )

    snapshot = collect_network_configuration()

    assert len(snapshot.adapters) == 64
    assert snapshot.omitted_adapter_count >= 1
    assert snapshot.omitted_route_count >= 1
    assert snapshot.status is ComponentStatus.PARTIAL
    assert any("capped" in item for item in snapshot.limitations)


def test_pressure_frame_omits_invalid_identity_and_required_rss_but_keeps_real_zero(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    valid = SimpleNamespace(
        info={
            "pid": 42,
            "name": "valid.exe",
            "create_time": NOW.timestamp(),
            "cpu_times": SimpleNamespace(user=0.0, system=0.0),
            "memory_info": SimpleNamespace(rss=0),
            "io_counters": SimpleNamespace(read_bytes=0, write_bytes=0),
        }
    )
    zero_created = SimpleNamespace(info={**valid.info, "pid": 4, "create_time": 0.0})
    missing_memory = SimpleNamespace(info={**valid.info, "pid": 43, "memory_info": None})

    def cpu_times(*, percpu: bool) -> list[tuple[int, int, int, int]]:
        assert percpu
        return [(1, 1, 1, 1)]

    def process_iter(_attrs: list[str]) -> list[SimpleNamespace]:
        return [zero_created, missing_memory, valid]

    monkeypatch.setattr(deep_collectors.psutil, "cpu_times", cpu_times)
    monkeypatch.setattr(
        deep_collectors.psutil,
        "virtual_memory",
        lambda: SimpleNamespace(percent=10.0, available=100),
    )
    monkeypatch.setattr(
        deep_collectors.psutil,
        "swap_memory",
        lambda: SimpleNamespace(percent=0.0),
    )
    monkeypatch.setattr(deep_collectors.psutil, "disk_io_counters", lambda: None)
    monkeypatch.setattr(
        deep_collectors.psutil,
        "process_iter",
        process_iter,
    )

    frame = deep_collectors._capture_pressure_frame()  # pyright: ignore[reportPrivateUsage]

    assert frame.omitted_process_count == 2
    assert len(frame.processes) == 1
    assert frame.processes[0].pid == 42
    assert frame.processes[0].rss_bytes == 0
    assert frame.processes[0].read_bytes == 0
    assert frame.processes[0].write_bytes == 0


def test_pressure_sample_keeps_baseline_unknown_then_reports_two_measured_deltas(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    cpu = deep_collectors._CpuCounter  # pyright: ignore[reportPrivateUsage]
    process = deep_collectors._ProcessCounter  # pyright: ignore[reportPrivateUsage]
    frame = deep_collectors._PressureFrame  # pyright: ignore[reportPrivateUsage]
    frames = iter(
        (
            frame(
                observed_at=NOW,
                cpus=(cpu(total=100.0, busy=40.0), cpu(total=100.0, busy=20.0)),
                memory_percent=50.0,
                memory_available_bytes=1000,
                swap_percent=5.0,
                disk_read_bytes=100,
                disk_write_bytes=200,
                processes=(
                    process(
                        pid=42,
                        name="worker.exe",
                        creation_time=NOW,
                        cpu_seconds=10.0,
                        rss_bytes=500,
                        read_bytes=100,
                        write_bytes=200,
                    ),
                ),
                omitted_process_count=0,
            ),
            frame(
                observed_at=NOW + timedelta(seconds=1),
                cpus=(cpu(total=110.0, busy=45.0), cpu(total=110.0, busy=25.0)),
                memory_percent=55.0,
                memory_available_bytes=900,
                swap_percent=6.0,
                disk_read_bytes=140,
                disk_write_bytes=260,
                processes=(
                    process(
                        pid=42,
                        name="worker.exe",
                        creation_time=NOW,
                        cpu_seconds=11.0,
                        rss_bytes=550,
                        read_bytes=120,
                        write_bytes=230,
                    ),
                ),
                omitted_process_count=0,
            ),
            frame(
                observed_at=NOW + timedelta(seconds=2),
                cpus=(cpu(total=120.0, busy=47.0), cpu(total=120.0, busy=27.0)),
                memory_percent=54.0,
                memory_available_bytes=925,
                swap_percent=6.0,
                disk_read_bytes=170,
                disk_write_bytes=300,
                processes=(
                    process(
                        pid=42,
                        name="worker.exe",
                        creation_time=NOW,
                        cpu_seconds=11.5,
                        rss_bytes=560,
                        read_bytes=130,
                        write_bytes=250,
                    ),
                ),
                omitted_process_count=0,
            ),
        )
    )
    sleeps: list[float] = []
    monkeypatch.setattr(deep_collectors, "_capture_pressure_frame", lambda: next(frames))
    monkeypatch.setattr(deep_collectors.time, "sleep", sleeps.append)

    snapshot = collect_pressure_sample()

    assert sleeps == [1.0, 1.0]
    assert snapshot.inter_sample_delay_seconds == 1.0
    assert snapshot.window_started_at == NOW
    assert snapshot.window_ended_at == NOW + timedelta(seconds=2)
    assert snapshot.samples[0].system_cpu_percent is None
    assert snapshot.samples[0].disk_read_bytes_delta is None
    assert snapshot.samples[1].system_cpu_percent == 50.0
    assert snapshot.samples[1].disk_read_bytes_delta == 40
    assert snapshot.samples[1].processes[0].cpu_percent == 50.0
    assert any(
        "first sample is a cumulative-counter baseline" in item for item in snapshot.limitations
    )


def test_gpu_telemetry_sample_retains_three_source_timestamps_and_fixed_intervals(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    snapshots = iter(
        deep_collectors.NvidiaTelemetrySnapshot(
            captured_at=NOW + timedelta(milliseconds=offset),
            status=ComponentStatus.AVAILABLE,
            gpus=(
                deep_collectors.NvidiaGpuTelemetry(
                    index=0,
                    uuid="GPU-fixture",
                    name="Fixture GPU",
                    utilization_percent=offset // 10,
                ),
            ),
        )
        for offset in (0, 500, 1000)
    )
    sleeps: list[float] = []
    monkeypatch.setattr(deep_collectors, "collect_nvidia_telemetry", lambda: next(snapshots))
    monkeypatch.setattr(deep_collectors.time, "sleep", sleeps.append)

    series = collect_gpu_telemetry_sample()

    assert sleeps == [0.5, 0.5]
    assert series.inter_sample_delay_seconds == 0.5
    assert series.window_started_at == NOW
    assert series.window_ended_at == NOW + timedelta(seconds=1)
    assert [item.captured_at for item in series.samples] == [
        NOW,
        NOW + timedelta(milliseconds=500),
        NOW + timedelta(seconds=1),
    ]
