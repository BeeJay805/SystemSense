"""Collection bounds describe backend read intervals, not instantaneous snapshots."""

from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest

from systemsense.platform.windows import deep_collectors as dc
from systemsense.platform.windows.eventlog import QueryStatus, WindowsEvent


class Clock:
    def __init__(self) -> None:
        self.value = datetime(2026, 9, 23, 12, tzinfo=UTC)

    def now(self) -> datetime:
        return self.value

    def advance(self) -> None:
        self.value += timedelta(seconds=1)


def test_storage_collection_finishes_after_delayed_wmi_reads(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = Clock()

    class Service:
        def ExecQuery(self, _query: str) -> list[object]:
            clock.advance()
            return []

    monkeypatch.setattr(dc, "utc_now", clock.now)

    def service_for_namespace(_namespace: str) -> Service:
        return Service()

    monkeypatch.setattr(dc, "_wmi_service", service_for_namespace)

    result = dc.collect_storage_snapshot()

    assert result.collection_started_at == clock.value - timedelta(seconds=5)
    assert result.captured_at == clock.value


def test_application_collection_finishes_after_boot_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = Clock()

    class Service:
        def ExecQuery(self, _query: str) -> list[object]:
            clock.advance()
            return []

    def boot_time() -> float:
        clock.advance()
        return 1.0

    monkeypatch.setattr(dc, "utc_now", clock.now)

    def service_for_namespace(_namespace: str) -> Service:
        return Service()

    monkeypatch.setattr(dc, "_wmi_service", service_for_namespace)
    monkeypatch.setattr(dc.psutil, "boot_time", boot_time)

    result = dc.collect_application_topology()

    assert result.collection_started_at == clock.value - timedelta(seconds=5)
    assert result.captured_at == clock.value
    assert result.boot_time == datetime.fromtimestamp(1, tz=UTC)


def test_network_configuration_finishes_after_proxy_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = Clock()

    class Service:
        def ExecQuery(self, _query: str) -> list[object]:
            clock.advance()
            return []

    def routes(_self: Any, *, max_records: int) -> tuple[()]:
        assert max_records == 256
        clock.advance()
        return ()

    def proxy() -> dc.ProxyConfiguration:
        clock.advance()
        return dc.ProxyConfiguration(enabled=False, status=dc.ComponentStatus.AVAILABLE)

    monkeypatch.setattr(dc, "utc_now", clock.now)
    monkeypatch.setattr(dc.WmiRouteBackend, "routes", routes)

    def service_for_namespace(_namespace: str) -> Service:
        return Service()

    monkeypatch.setattr(dc, "_wmi_service", service_for_namespace)
    monkeypatch.setattr(dc, "_read_proxy_configuration", proxy)

    result = dc.collect_network_configuration()

    assert result.collection_started_at == clock.value - timedelta(seconds=3)
    assert result.captured_at == clock.value


def test_listener_table_interval_excludes_later_owner_lookup(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = Clock()
    connection = SimpleNamespace(
        status="LISTEN",
        laddr=SimpleNamespace(ip="127.0.0.1", port=1234),
        family=dc.socket.AF_INET,
        pid=42,
    )

    def connections(*, kind: str) -> list[SimpleNamespace]:
        assert kind == "tcp"
        clock.advance()
        return [connection]

    def owner(_pid: int) -> tuple[str, datetime, dc.ComponentStatus]:
        clock.advance()
        return "fixture.exe", clock.value, dc.ComponentStatus.AVAILABLE

    monkeypatch.setattr(dc, "utc_now", clock.now)
    monkeypatch.setattr(dc.psutil, "net_connections", connections)
    monkeypatch.setattr(dc, "_listener_owner", owner)

    result = dc.collect_network_listeners()

    assert result.collection_started_at is not None
    assert result.listener_table_completed_at is not None
    assert result.collection_started_at == result.listener_table_started_at
    assert result.listener_table_completed_at == result.collection_started_at + timedelta(seconds=1)
    assert result.captured_at == result.listener_table_completed_at + timedelta(seconds=1)
    assert result.status is dc.ComponentStatus.AVAILABLE
    assert any("owners may have changed" in item for item in result.limitations)


def test_listener_table_failure_still_reports_query_bounds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = Clock()

    def denied(*, kind: str) -> list[object]:
        assert kind == "tcp"
        clock.advance()
        raise PermissionError("fixture")

    monkeypatch.setattr(dc, "utc_now", clock.now)
    monkeypatch.setattr(dc.psutil, "net_connections", denied)

    result = dc.collect_network_listeners()

    assert result.status is dc.ComponentStatus.PERMISSION_DENIED
    assert result.collection_started_at == result.listener_table_started_at
    assert result.listener_table_completed_at == clock.value
    assert result.captured_at == clock.value


def test_power_and_security_completion_follow_delayed_backends(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = Clock()

    class Service:
        def ExecQuery(self, _query: str) -> list[object]:
            clock.advance()
            return []

    def battery() -> None:
        clock.advance()
        return None

    monkeypatch.setattr(dc, "utc_now", clock.now)
    monkeypatch.setattr(dc.psutil, "sensors_battery", battery)

    def service_for_namespace(_namespace: str) -> Service:
        return Service()

    monkeypatch.setattr(dc, "_wmi_service", service_for_namespace)

    power = dc.collect_power_snapshot()
    security = dc.collect_security_snapshot()

    assert power.collection_started_at is not None
    assert power.captured_at >= power.collection_started_at + timedelta(seconds=2)
    assert security.collection_started_at is not None
    assert security.captured_at >= security.collection_started_at + timedelta(seconds=1)


def test_pressure_frame_completion_follows_process_scan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = Clock()

    def cpu_times(*, percpu: bool) -> list[tuple[int, int, int, int]]:
        assert percpu
        clock.advance()
        return [(1, 1, 1, 1)]

    def processes(_attrs: list[str]) -> list[object]:
        clock.advance()
        return []

    monkeypatch.setattr(dc, "utc_now", clock.now)
    monkeypatch.setattr(dc.psutil, "cpu_times", cpu_times)
    monkeypatch.setattr(
        dc.psutil, "virtual_memory", lambda: SimpleNamespace(percent=10, available=100)
    )
    monkeypatch.setattr(dc.psutil, "swap_memory", lambda: SimpleNamespace(percent=0))
    monkeypatch.setattr(dc.psutil, "disk_io_counters", lambda: None)
    monkeypatch.setattr(dc.psutil, "process_iter", processes)

    frame = dc._capture_pressure_frame()  # pyright: ignore[reportPrivateUsage]
    sample = dc._normalize_pressure_frames((frame,))[0]  # pyright: ignore[reportPrivateUsage]

    assert frame.collection_started_at == clock.value - timedelta(seconds=2)
    assert frame.observed_at == clock.value
    assert sample.collection_started_at == frame.collection_started_at
    assert sample.observed_at == frame.observed_at


def test_incident_collection_preserves_event_source_time_and_query_completion(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clock = Clock()
    source_time = clock.value - timedelta(days=1)
    event = WindowsEvent(
        channel="System",
        provider="Microsoft-Windows-Kernel-Power",
        event_id=41,
        record_id=7,
        level=2,
        observed_at=source_time,
        computer="fixture",
        event_data={},
        source_id=f"src_{7:064x}",
    )

    class Adapter:
        def __init__(self, _backend: object, *, max_records: int) -> None:
            assert max_records == 100

        def query(self, channel: str, *, after_record_id: None, limit: int) -> SimpleNamespace:
            assert after_record_id is None and limit == 100
            clock.advance()
            return SimpleNamespace(
                status=QueryStatus.OK,
                events=(event,) if channel == "System" else (),
                reason=None,
            )

    monkeypatch.setattr(dc, "utc_now", clock.now)
    monkeypatch.setattr(dc, "PyWin32EventLogBackend", lambda: object())
    monkeypatch.setattr(dc, "FixedEventLogAdapter", Adapter)

    result = dc.collect_incident_events()

    assert result.collection_started_at == clock.value - timedelta(seconds=2)
    assert result.captured_at == clock.value
    assert result.events[0].observed_at == source_time


def test_collection_interval_rejects_completion_before_start() -> None:
    now = datetime(2026, 9, 23, 12, tzinfo=UTC)
    with pytest.raises(ValueError, match="completion precedes query start"):
        dc.IncidentEventSnapshot(
            collection_started_at=now + timedelta(seconds=1),
            captured_at=now,
            events=(),
            channel_status={},
        )
