from datetime import UTC, datetime
from pathlib import Path

from systemsense.packs.servicing.history import (
    InstalledUpdate,
    assess_reboot_pending,
    collect_update_history,
)
from systemsense.packs.servicing.logs import parse_servicing_log_increment
from systemsense.packs.servicing.update_events import parse_update_event

_NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)


def test_update_failure_event_preserves_code_and_operation() -> None:
    event = parse_update_event(
        event_id=20,
        observed_at=_NOW,
        fields={
            "updateTitle": "Security Update",
            "errorCode": "0x800f081f",
            "operation": "Installation",
        },
    )

    assert event.error_code == "0x800f081f"
    assert event.operation == "Installation"


def test_installed_update_history_is_bounded_and_sorted() -> None:
    updates = (
        InstalledUpdate(kb="KB1", description="Older", installed_on="2026-07-01"),
        InstalledUpdate(kb="KB2", description="Newer", installed_on="2026-07-30"),
    )

    result = collect_update_history(updates, max_records=1)

    assert result[0].kb == "KB2"


def test_reboot_pending_records_each_read_only_source() -> None:
    result = assess_reboot_pending(
        {
            "component_based_servicing": True,
            "windows_update": False,
        }
    )

    assert result.pending
    assert result.pending_sources == ("component_based_servicing",)


def test_servicing_log_increment_extracts_errors_and_advances_offset() -> None:
    fixture = Path(__file__).parents[3] / "fixtures" / "servicing" / "cbs.log"
    raw = fixture.read_bytes()

    increment = parse_servicing_log_increment(raw, start_offset=0, max_bytes=4096)

    assert increment.next_offset == len(raw)
    assert not increment.truncated
    assert len(increment.error_lines) == 1
    assert "0x800f081f" in increment.error_lines[0]
