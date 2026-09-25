"""The opt-in host observer retains bounded metadata, never event payloads."""

from __future__ import annotations

import threading
from datetime import UTC, datetime
from typing import NoReturn, cast

from benchmarks.host_diagnostic_trace import (
    HostDiagnosticTrace,
    _read_event_channel,  # pyright: ignore[reportPrivateUsage]
)


class FakeEventLog:
    EvtQueryChannelPath = 1
    EvtQueryReverseDirection = 2
    EvtRenderEventXml = 3

    def __init__(self, xml: str) -> None:
        self.xml = xml
        self.handles: list[FakeHandle] = []
        self.timeouts: list[int] = []
        self.queries: list[str] = []

    def EvtQuery(self, channel: str, flags: int, query: str) -> FakeHandle:
        self.queries.append(query)
        handle = FakeHandle()
        self.handles.append(handle)
        return handle

    def EvtNext(self, result_set: object, count: int, timeout: int) -> list[FakeHandle]:
        self.timeouts.append(timeout)
        handles = [FakeHandle() for _ in range(count)]
        self.handles.extend(handles)
        return handles

    def EvtRender(self, event: object, flags: int) -> str:
        return self.xml


class FakeHandle:
    def __init__(self) -> None:
        self.closed = False

    def Close(self) -> None:
        self.closed = True


def test_event_channel_keeps_only_allowlisted_metadata_and_caps_results() -> None:
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        '<System><Provider Name="Application Error"/><EventID>1000</EventID>'
        '<TimeCreated SystemTime="2026-09-24T12:00:01.0000000Z"/>'
        "<EventRecordID>42</EventRecordID></System>"
        '<EventData><Data Name="Private">SECRET COMMAND LINE</Data></EventData></Event>'
    )
    module = FakeEventLog(xml)
    events = _read_event_channel(
        module,
        "Application",
        datetime(2026, 9, 24, 12, tzinfo=UTC),
        datetime(2026, 9, 24, 12, 1, tzinfo=UTC),
        limit=2,
    )
    assert len(events) == 2
    assert events[0] == {
        "channel": "Application",
        "provider": "Application Error",
        "event_id": 1000,
        "record_id": 42,
        "occurred_at": "2026-09-24T12:00:01+00:00",
    }
    assert "SECRET" not in str(events)
    assert module.timeouts == [0]
    assert all(handle.closed for handle in module.handles)


def test_event_provider_is_filtered_before_bounded_fetch() -> None:
    xml = (
        '<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
        '<System><Provider Name="nvlddmkm"/><EventID>153</EventID>'
        '<TimeCreated SystemTime="2026-09-24T12:00:01Z"/>'
        "<EventRecordID>9</EventRecordID></System></Event>"
    )
    module = FakeEventLog(xml)
    _read_event_channel(
        module,
        "System",
        datetime(2026, 9, 24, 12, tzinfo=UTC),
        datetime(2026, 9, 24, 12, 1, tzinfo=UTC),
        limit=16,
    )
    assert "Provider[@Name='nvlddmkm']" in module.queries[0]
    assert "Provider[@Name='Display']" in module.queries[0]


def test_event_query_closes_handle_when_next_fails() -> None:
    module = FakeEventLog("")

    def fail_next(result_set: object, count: int, timeout: int) -> NoReturn:
        raise RuntimeError("event query failed")

    module.EvtNext = fail_next  # type: ignore[method-assign]
    try:
        _read_event_channel(
            module,
            "System",
            datetime(2026, 9, 24, 12, tzinfo=UTC),
            datetime(2026, 9, 24, 12, 1, tzinfo=UTC),
        )
    except RuntimeError:
        pass
    else:
        raise AssertionError("expected query failure")
    assert all(handle.closed for handle in module.handles)


def test_event_query_treats_no_more_items_as_empty_and_closes_handle() -> None:
    module = FakeEventLog("")

    class NoMoreItems(Exception):
        winerror = 259

    def no_more(result_set: object, count: int, timeout: int) -> NoReturn:
        raise NoMoreItems()

    module.EvtNext = no_more  # type: ignore[method-assign]
    events = _read_event_channel(
        module,
        "System",
        datetime(2026, 9, 24, 12, tzinfo=UTC),
        datetime(2026, 9, 24, 12, 1, tzinfo=UTC),
    )
    assert events == []
    assert all(handle.closed for handle in module.handles)


def test_trace_bounds_samples_and_marks_telemetry_failure() -> None:
    def unavailable(_index: int) -> NoReturn:
        raise ValueError("private path /example")

    trace = HostDiagnosticTrace(gpu_device_index=0, sample=unavailable, max_samples=2)
    trace.sample_once()
    trace.sample_once()
    trace.sample_once()
    report = trace.finish(read_events=lambda _start, _end: ([], "unavailable"))
    samples = cast(list[dict[str, object]], report["vram_samples"])
    assert len(samples) == 2
    assert samples[0]["status"] == "unavailable"
    assert "private" not in str(report)
    assert report["event_query_status"] == "unavailable"


def test_trace_reports_sampler_still_alive_after_join() -> None:
    class StuckThread:
        def join(self, timeout: float) -> None:
            assert timeout == 3

        def is_alive(self) -> bool:
            return True

    trace = HostDiagnosticTrace(gpu_device_index=0)
    trace._thread = cast(threading.Thread, StuckThread())  # pyright: ignore[reportPrivateUsage]
    report = trace.finish(read_events=lambda _start, _end: ([], "bounded_not_exhaustive"))
    assert report["sampling_status"] == "observer_still_running"
    assert "did not stop" in str(report["limitations"])
