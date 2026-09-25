"""Bounded, read-only host context for the opt-in real-model fixture.

This is correlation evidence. A nearby driver event or low free VRAM does not
establish why a model child crashed. Event payloads are never retained.
"""

from __future__ import annotations

import importlib
import os
import threading
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from typing import Protocol, cast
from xml.etree import ElementTree

from systemsense.domain.time import utc_now
from systemsense.inference.host_telemetry import HostTelemetryReading, read_host_telemetry

_EVENT_NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"
_EVENT_LIMIT = 16
_SAMPLE_INTERVAL_SECONDS = 2.0
_MAX_SAMPLES = 64


class _EventLogModule(Protocol):
    EvtQueryChannelPath: int
    EvtQueryReverseDirection: int
    EvtRenderEventXml: int

    def EvtQuery(self, channel: str, flags: int, query: str) -> _EventHandle: ...

    def EvtNext(
        self, result_set: _EventHandle, count: int, timeout: int
    ) -> Sequence[_EventHandle]: ...

    def EvtRender(self, event: _EventHandle, flags: int) -> str: ...


class _EventHandle(Protocol):
    def Close(self) -> None: ...


def _read_event_channel(
    module: _EventLogModule,
    channel: str,
    started_at: datetime,
    ended_at: datetime,
    *,
    limit: int = _EVENT_LIMIT,
) -> list[dict[str, str | int]]:
    """Query fixed event IDs and retain only XML System metadata."""

    if channel not in {"Application", "System"} or not 1 <= limit <= _EVENT_LIMIT:
        raise ValueError("invalid event query")
    ids = (1000, 1001) if channel == "Application" else (153, 4101)
    start = started_at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    end = ended_at.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
    id_filter = " or ".join(f"EventID={event_id}" for event_id in ids)
    provider_names = (
        ("Application Error", "Windows Error Reporting")
        if channel == "Application"
        else ("nvlddmkm", "Display")
    )
    provider_filter = " or ".join(f"Provider[@Name='{name}']" for name in provider_names)
    query = (
        "*[System[(" + id_filter + ") and "
        "(" + provider_filter + ") and "
        "TimeCreated[@SystemTime >= '" + start + "' and @SystemTime <= '" + end + "']]]"
    )
    flags = module.EvtQueryChannelPath | module.EvtQueryReverseDirection
    handle = module.EvtQuery(channel, flags, query)
    records: list[dict[str, str | int]] = []
    batch: Sequence[_EventHandle] = ()
    try:
        try:
            batch = module.EvtNext(handle, limit, 0)
        except Exception as error:
            if getattr(error, "winerror", None) == 259:
                return []
            raise
        for event in batch:
            root = ElementTree.fromstring(module.EvtRender(event, module.EvtRenderEventXml))
            system = root.find(f"{_EVENT_NS}System")
            if system is None:
                continue
            provider = system.find(f"{_EVENT_NS}Provider")
            event_id = system.find(f"{_EVENT_NS}EventID")
            created = system.find(f"{_EVENT_NS}TimeCreated")
            record_id = system.find(f"{_EVENT_NS}EventRecordID")
            if provider is None or event_id is None or created is None or record_id is None:
                continue
            name = provider.get("Name", "")
            number = int(event_id.text or "0")
            if channel == "Application" and (
                number not in ids or name not in {"Application Error", "Windows Error Reporting"}
            ):
                continue
            if channel == "System" and (
                number not in ids or name.casefold() not in {"nvlddmkm", "display"}
            ):
                continue
            timestamp = datetime.fromisoformat(created.get("SystemTime", "").replace("Z", "+00:00"))
            records.append(
                {
                    "channel": channel,
                    "provider": name,
                    "event_id": number,
                    "record_id": int(record_id.text or "0"),
                    "occurred_at": timestamp.astimezone(UTC).isoformat(),
                }
            )
    finally:
        try:
            for event in batch:
                event.Close()
        finally:
            handle.Close()
    return records


def _read_events(
    started_at: datetime, ended_at: datetime
) -> tuple[list[dict[str, str | int]], str]:
    if os.name != "nt":
        return [], "unsupported"
    try:
        module = cast(_EventLogModule, importlib.import_module("win32evtlog"))
    except ImportError:
        return [], "unavailable"
    events: list[dict[str, str | int]] = []
    failures = 0
    for channel in ("Application", "System"):
        try:
            events.extend(_read_event_channel(module, channel, started_at, ended_at))
        except Exception:
            failures += 1
    if failures == 2:
        return [], "unavailable"
    return events, "partial" if failures else "bounded_not_exhaustive"


class HostDiagnosticTrace:
    """Observe one fixture run; bounded samples and fixed Event Log metadata only."""

    def __init__(
        self,
        *,
        gpu_device_index: int,
        sample: Callable[[int], HostTelemetryReading] | None = None,
        max_samples: int = _MAX_SAMPLES,
    ) -> None:
        if not 0 <= gpu_device_index <= 15 or not 1 <= max_samples <= _MAX_SAMPLES:
            raise ValueError("invalid trace bound")
        self.gpu_device_index = gpu_device_index
        self.sample: Callable[[int], HostTelemetryReading] = sample or (
            lambda index: read_host_telemetry(gpu_device_index=index)
        )
        self.max_samples = max_samples
        self.started_at = utc_now()
        self._samples: list[dict[str, object]] = []
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def sample_once(self) -> None:
        with self._lock:
            if len(self._samples) >= self.max_samples:
                return
        try:
            reading = self.sample(self.gpu_device_index)
            record: dict[str, object] = {
                "status": "ok",
                "source_started_at": reading.source_window_started_at.isoformat(),
                "source_ended_at": reading.source_window_ended_at.isoformat(),
                "gpu_device_index": reading.gpu_device_index,
                "gpu_uuid": reading.gpu_uuid,
                "free_vram_bytes": reading.free_vram_bytes,
                "available_ram_bytes": reading.available_ram_bytes,
            }
        except Exception:
            record = {"status": "unavailable", "observed_at": utc_now().isoformat()}
        with self._lock:
            if len(self._samples) < self.max_samples:
                self._samples.append(record)

    def start(self) -> None:
        if self._thread is not None:
            raise RuntimeError("trace already started")

        def collect() -> None:
            while not self._stop.is_set():
                self.sample_once()
                if len(self._samples) >= self.max_samples:
                    break
                self._stop.wait(_SAMPLE_INTERVAL_SECONDS)

        self._thread = threading.Thread(target=collect, name="host-diagnostic-trace", daemon=True)
        self._thread.start()

    def finish(
        self,
        *,
        read_events: Callable[
            [datetime, datetime], tuple[list[dict[str, str | int]], str]
        ] = _read_events,
    ) -> dict[str, object]:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=3)
        sampling_status = (
            "not_started"
            if self._thread is None
            else "observer_still_running"
            if self._thread.is_alive()
            else "stopped"
        )
        ended_at = utc_now()
        with self._lock:
            samples = list(self._samples)
        events, status = read_events(self.started_at - timedelta(seconds=15), ended_at)
        limitations = [
            "Samples show free VRAM at query intervals, not allocation peaks.",
            "Windows events are temporal context and do not establish crash cause.",
            "Application event metadata does not identify the crashed executable.",
            "Event queries are capped and can omit matching records.",
        ]
        if sampling_status == "observer_still_running":
            limitations.append(
                "Sampling thread did not stop within 3 seconds; samples may be incomplete."
            )
        return {
            "schema_version": 1,
            "started_at": self.started_at.isoformat(),
            "ended_at": ended_at.isoformat(),
            "sample_interval_seconds": _SAMPLE_INTERVAL_SECONDS,
            "sample_limit": self.max_samples,
            "sampling_status": sampling_status,
            "vram_samples": samples,
            "event_pre_run_lookback_seconds": 15,
            "event_limit_per_channel": _EVENT_LIMIT,
            "event_query_status": status,
            "events": events[: 2 * _EVENT_LIMIT],
            "limitations": limitations,
        }
