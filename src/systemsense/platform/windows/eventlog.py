"""Fixed-channel Windows Event Log query and XML normalization."""

import importlib
from collections.abc import Callable
from datetime import datetime
from enum import StrEnum
from typing import Protocol, cast
from xml.etree import ElementTree

from pydantic import Field

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import stable_source_id
from systemsense.domain.time import UtcDateTime

_MAX_XML_BYTES = 1_048_576
REGISTERED_CHANNELS = frozenset(
    {
        "Application",
        "System",
        "Microsoft-Windows-WindowsUpdateClient/Operational",
    }
)


class EventLogParseError(ValueError):
    """An Event Log XML record is malformed or outside its size contract."""


class StaleBookmarkError(RuntimeError):
    """The saved record position no longer exists in the channel."""


class WindowsEvent(FrozenModel):
    channel: str = Field(min_length=1, max_length=255)
    provider: str = Field(min_length=1, max_length=255)
    event_id: int = Field(ge=0)
    record_id: int = Field(ge=0)
    level: int = Field(ge=0)
    observed_at: UtcDateTime
    computer: str = Field(min_length=1, max_length=255)
    event_data: dict[str, str]
    rendered_message: str | None = Field(default=None, max_length=16_384)
    source_id: str = Field(pattern=r"^src_[0-9a-f]{64}$")


class RawEventBatch(FrozenModel):
    xml_events: tuple[str, ...]


class QueryStatus(StrEnum):
    OK = "ok"
    DENIED = "denied"
    STALE = "stale"
    FAILED = "failed"


class EventQuery(FrozenModel):
    status: QueryStatus
    events: tuple[WindowsEvent, ...] = ()
    reason: str | None = Field(default=None, max_length=1000)


class EventLogBackend(Protocol):
    def query(
        self,
        channel: str,
        *,
        after_record_id: int | None,
        limit: int,
    ) -> RawEventBatch: ...


def parse_event_xml(xml: str) -> WindowsEvent:
    if len(xml.encode("utf-8")) > _MAX_XML_BYTES:
        raise EventLogParseError("event XML exceeds size limit")
    try:
        root = ElementTree.fromstring(xml)
    except ElementTree.ParseError as error:
        raise EventLogParseError("malformed event XML") from error
    if root.tag.rsplit("}", 1)[-1] != "Event":
        raise EventLogParseError("root element is not Event")

    system = root.find("./{*}System")
    if system is None:
        raise EventLogParseError("event System element is missing")
    provider_element = system.find("./{*}Provider")
    time_element = system.find("./{*}TimeCreated")
    if provider_element is None or time_element is None:
        raise EventLogParseError("event provider or timestamp is missing")

    provider = provider_element.attrib.get("Name")
    timestamp = time_element.attrib.get("SystemTime")
    if not provider or not timestamp:
        raise EventLogParseError("event provider or timestamp is empty")
    try:
        observed_at = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        event_id = int(_required_text(system, "EventID"))
        level = int(_required_text(system, "Level"))
        record_id = int(_required_text(system, "EventRecordID"))
        channel = _required_text(system, "Channel")
        computer = _required_text(system, "Computer")
    except (TypeError, ValueError) as error:
        raise EventLogParseError("event System fields are invalid") from error

    event_data: dict[str, str] = {}
    event_data_element = root.find("./{*}EventData")
    if event_data_element is not None:
        for index, data in enumerate(event_data_element.findall("./{*}Data")):
            name = data.attrib.get("Name") or f"param_{index}"
            event_data[name] = data.text or ""

    message_element = root.find("./{*}RenderingInfo/{*}Message")
    rendered_message = None if message_element is None else message_element.text
    source_id = stable_source_id(
        "windows.eventlog",
        {
            "channel": channel,
            "provider": provider,
            "event_id": event_id,
            "record_id": record_id,
        },
    )
    return WindowsEvent(
        channel=channel,
        provider=provider,
        event_id=event_id,
        record_id=record_id,
        level=level,
        observed_at=observed_at,
        computer=computer,
        event_data=event_data,
        rendered_message=rendered_message,
        source_id=source_id,
    )


def _required_text(parent: ElementTree.Element, name: str) -> str:
    element = parent.find(f"./{{*}}{name}")
    if element is None or element.text is None or not element.text.strip():
        raise EventLogParseError(f"event {name} is missing")
    return element.text.strip()


class FixedEventLogAdapter:
    def __init__(self, backend: EventLogBackend, *, max_records: int = 100) -> None:
        if max_records < 1 or max_records > 1000:
            raise ValueError("max_records must be between 1 and 1000")
        self._backend = backend
        self._max_records = max_records

    def query(
        self,
        channel: str,
        *,
        after_record_id: int | None,
        limit: int,
    ) -> EventQuery:
        self._validate_request(channel, limit)
        try:
            batch = self._backend.query(
                channel,
                after_record_id=after_record_id,
                limit=limit,
            )
            events = tuple(parse_event_xml(xml) for xml in batch.xml_events)
        except PermissionError as error:
            return EventQuery(status=QueryStatus.DENIED, reason=str(error))
        except StaleBookmarkError as error:
            return EventQuery(status=QueryStatus.STALE, reason=str(error))
        except Exception as error:
            return EventQuery(
                status=QueryStatus.FAILED,
                reason=f"{type(error).__name__}: {error}",
            )
        return EventQuery(status=QueryStatus.OK, events=events)

    def subscribe(
        self,
        channel: str,
        *,
        after_record_id: int | None,
        limit: int,
        on_event: Callable[[WindowsEvent], None],
    ) -> EventQuery:
        result = self.query(
            channel,
            after_record_id=after_record_id,
            limit=limit,
        )
        for event in result.events:
            on_event(event)
        return result

    def _validate_request(self, channel: str, limit: int) -> None:
        if channel not in REGISTERED_CHANNELS:
            raise ValueError(f"event channel is not registered: {channel}")
        if limit < 1 or limit > self._max_records:
            raise ValueError(f"limit must be between 1 and {self._max_records}")


class _Win32EvtLog(Protocol):
    EvtQueryChannelPath: int
    EvtQueryForwardDirection: int
    EvtQueryReverseDirection: int
    EvtRenderEventXml: int

    def EvtQuery(self, channel: str, flags: int, query: str) -> "_EventHandle": ...

    def EvtNext(self, result_set: "_EventHandle", count: int) -> list["_EventHandle"]: ...

    def EvtRender(self, event: "_EventHandle", flags: int) -> str: ...


class _EventHandle(Protocol):
    def Close(self) -> None: ...


class PyWin32EventLogBackend:
    """Read fixed channels through the local Windows Event Log API."""

    def query(
        self,
        channel: str,
        *,
        after_record_id: int | None,
        limit: int,
    ) -> RawEventBatch:
        if channel not in REGISTERED_CHANNELS:
            raise ValueError("channel is not registered")
        module = cast("_Win32EvtLog", importlib.import_module("win32evtlog"))
        expression = (
            "*"
            if after_record_id is None
            else f"*[System[(EventRecordID > {int(after_record_id)})]]"
        )
        direction = (
            module.EvtQueryReverseDirection
            if after_record_id is None
            else module.EvtQueryForwardDirection
        )
        flags = module.EvtQueryChannelPath | direction
        result_set = module.EvtQuery(channel, flags, expression)
        events: list[_EventHandle] = []
        try:
            events = module.EvtNext(result_set, limit)
            xml_events = tuple(
                module.EvtRender(event, module.EvtRenderEventXml) for event in events
            )
        except Exception as error:
            if getattr(error, "winerror", None) == 5:
                raise PermissionError(f"access denied to {channel}") from error
            raise
        finally:
            for event in events:
                event.Close()
            result_set.Close()
        return RawEventBatch(xml_events=xml_events)
