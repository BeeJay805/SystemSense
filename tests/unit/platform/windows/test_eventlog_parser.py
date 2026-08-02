from pathlib import Path

import pytest

from systemsense.platform.windows.eventlog import (
    EventLogParseError,
    PyWin32EventLogBackend,
    parse_event_xml,
)


def test_parser_extracts_structured_event_fields() -> None:
    fixture = Path(__file__).parents[3] / "fixtures" / "eventlog" / "application_error.xml"

    event = parse_event_xml(fixture.read_text(encoding="utf-8"))

    assert event.channel == "Application"
    assert event.provider == "Application Error"
    assert event.event_id == 1000
    assert event.record_id == 42
    assert event.level == 2
    assert event.computer == "TEST-PC"
    assert event.event_data == {
        "AppName": "sample.exe",
        "FaultingModule": "example.dll",
    }
    assert event.rendered_message == "Sample application stopped working."
    assert event.source_id.startswith("src_")


def test_parser_does_not_require_rendered_message() -> None:
    xml = """
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Provider" />
        <EventID>1</EventID><Level>4</Level>
        <TimeCreated SystemTime="2026-07-30T12:00:00Z" />
        <EventRecordID>7</EventRecordID><Channel>System</Channel>
        <Computer>PC</Computer>
      </System>
    </Event>
    """

    assert parse_event_xml(xml).rendered_message is None


@pytest.mark.parametrize("xml", ["<not-event />", "<Event>", ""])
def test_parser_rejects_missing_or_malformed_event_xml(xml: str) -> None:
    with pytest.raises(EventLogParseError):
        parse_event_xml(xml)


def test_parser_rejects_oversized_xml() -> None:
    with pytest.raises(EventLogParseError, match="size limit"):
        parse_event_xml("x" * 1_048_577)


def test_first_eventlog_query_reads_newest_records_then_bookmarks_forward(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    queries: list[tuple[int, str]] = []

    class Handle:
        def Close(self) -> None:
            return None

    class Module:
        EvtQueryChannelPath = 1
        EvtQueryForwardDirection = 2
        EvtQueryReverseDirection = 4
        EvtRenderEventXml = 8

        @staticmethod
        def EvtQuery(_channel: str, flags: int, expression: str) -> Handle:
            queries.append((flags, expression))
            return Handle()

        @staticmethod
        def EvtNext(_result: Handle, _count: int) -> list[Handle]:
            return []

        @staticmethod
        def EvtRender(_event: Handle, _flags: int) -> str:
            return ""

    def fake_import(_name: str) -> Module:
        return Module()

    monkeypatch.setattr(
        "systemsense.platform.windows.eventlog.importlib.import_module",
        fake_import,
    )
    backend = PyWin32EventLogBackend()

    backend.query("Application", after_record_id=None, limit=10)
    backend.query("Application", after_record_id=42, limit=10)

    assert queries == [
        (5, "*"),
        (3, "*[System[(EventRecordID > 42)]]"),
    ]
