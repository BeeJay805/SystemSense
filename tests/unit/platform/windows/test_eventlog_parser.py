from pathlib import Path

import pytest

from systemsense.platform.windows.eventlog import EventLogParseError, parse_event_xml


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
