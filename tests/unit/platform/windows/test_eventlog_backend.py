from dataclasses import dataclass
from types import ModuleType

import pytest

from systemsense.platform.windows import eventlog
from systemsense.platform.windows.eventlog import (
    FixedEventLogAdapter,
    PyWin32EventLogBackend,
    QueryStatus,
    StaleBookmarkError,
)


def _event(record_id: int) -> str:
    return f"""
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Provider" />
        <EventID>1</EventID><Level>4</Level>
        <TimeCreated SystemTime="2026-07-30T12:00:00Z" />
        <EventRecordID>{record_id}</EventRecordID>
        <Channel>Application</Channel><Computer>PC</Computer>
      </System>
    </Event>
    """


@dataclass
class _Handle:
    newest: bool
    closed: bool = False

    def Close(self) -> None:
        self.closed = True


class _ResetLogModule(ModuleType):
    EvtQueryChannelPath = 1
    EvtQueryForwardDirection = 2
    EvtQueryReverseDirection = 4
    EvtRenderEventXml = 8

    def __init__(self) -> None:
        super().__init__("win32evtlog")
        self.handles: list[_Handle] = []

    def EvtQuery(self, channel: str, flags: int, query: str) -> _Handle:
        del channel, query
        handle = _Handle(newest=bool(flags & self.EvtQueryReverseDirection))
        self.handles.append(handle)
        return handle

    def EvtNext(self, result_set: _Handle, count: int) -> list[_Handle]:
        del count
        if result_set.newest:
            return [_Handle(newest=True)]
        return []

    def EvtRender(self, event: _Handle, flags: int) -> str:
        del event, flags
        return _event(3)


class _AccessDeniedError(OSError):
    winerror = 5


class _DeniedEventLogModule(_ResetLogModule):
    def EvtQuery(self, channel: str, flags: int, query: str) -> _Handle:
        del channel, flags, query
        raise _AccessDeniedError("access denied")


def test_real_backend_rejects_bookmark_beyond_current_log_generation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _ResetLogModule()

    def import_module(_name: str, package: str | None = None) -> ModuleType:
        del package
        return module

    monkeypatch.setattr(eventlog.importlib, "import_module", import_module)

    with pytest.raises(StaleBookmarkError, match="newest record is 3"):
        PyWin32EventLogBackend().query(
            "Application",
            after_record_id=42,
            limit=10,
        )

    assert module.handles
    assert all(handle.closed for handle in module.handles)


def test_real_backend_maps_high_water_access_denied_to_denied_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _DeniedEventLogModule()

    def import_module(_name: str, package: str | None = None) -> ModuleType:
        del package
        return module

    monkeypatch.setattr(eventlog.importlib, "import_module", import_module)

    result = FixedEventLogAdapter(PyWin32EventLogBackend()).query(
        "Application",
        after_record_id=42,
        limit=10,
    )

    assert result.status is QueryStatus.DENIED
    assert result.reason == "access denied to Application"


def test_real_backend_maps_initial_query_access_denied_to_denied_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = _DeniedEventLogModule()

    def import_module(_name: str, package: str | None = None) -> ModuleType:
        del package
        return module

    monkeypatch.setattr(eventlog.importlib, "import_module", import_module)

    result = FixedEventLogAdapter(PyWin32EventLogBackend()).query(
        "Application",
        after_record_id=None,
        limit=10,
    )

    assert result.status is QueryStatus.DENIED
    assert result.reason == "access denied to Application"


def test_initial_capture_starts_at_recent_tail_and_labels_missing_history(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class TailModule(_ResetLogModule):
        def __init__(self) -> None:
            super().__init__()
            self.record_ids: dict[int, int] = {}

        def EvtNext(self, result_set: _Handle, count: int) -> list[_Handle]:
            assert result_set.newest, "initial capture must not replay the oldest channel records"
            handles = [_Handle(newest=True) for _ in range(min(3, count))]
            self.record_ids = {id(handle): 100 - i for i, handle in enumerate(handles)}
            return handles

        def EvtRender(self, event: _Handle, flags: int) -> str:
            del flags
            return _event(self.record_ids[id(event)])

    module = TailModule()

    def import_module(name: str, package: str | None = None) -> ModuleType:
        del name, package
        return module

    monkeypatch.setattr(eventlog.importlib, "import_module", import_module)
    result = FixedEventLogAdapter(PyWin32EventLogBackend()).query(
        "Application",
        after_record_id=None,
        limit=3,
    )
    assert result.status is QueryStatus.OK
    assert [event.record_id for event in result.events] == [98, 99, 100]
    assert result.reason is not None and "bounded tail" in result.reason
