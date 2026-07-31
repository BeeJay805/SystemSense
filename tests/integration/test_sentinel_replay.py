from datetime import UTC, datetime
from pathlib import Path

from systemsense.domain.coverage import CoverageStatus
from systemsense.domain.evidence import EvidenceRecord
from systemsense.domain.ids import CaseId
from systemsense.platform.windows.eventlog import (
    EventLogBackend,
    FixedEventLogAdapter,
    RawEventBatch,
    StaleBookmarkError,
)
from systemsense.sentinel import Sentinel
from systemsense.storage.sqlite_store import SQLiteStore

_CASE_ID = CaseId(root="case_0123456789abcdef0123456789abcdef")
_NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)


def _event(record_id: int) -> str:
    return f"""
    <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
      <System>
        <Provider Name="Application Error" />
        <EventID>1000</EventID><Level>2</Level>
        <TimeCreated SystemTime="2026-07-30T12:00:00Z" />
        <EventRecordID>{record_id}</EventRecordID>
        <Channel>Application</Channel><Computer>TEST-PC</Computer>
      </System>
      <EventData><Data Name="AppName">sample.exe</Data></EventData>
    </Event>
    """


class ReplayBackend(EventLogBackend):
    def query(
        self,
        channel: str,
        *,
        after_record_id: int | None,
        limit: int,
    ) -> RawEventBatch:
        del channel, after_record_id
        return RawEventBatch(xml_events=(_event(1), _event(2))[:limit])


class DeniedBackend(EventLogBackend):
    def query(
        self,
        channel: str,
        *,
        after_record_id: int | None,
        limit: int,
    ) -> RawEventBatch:
        del channel, after_record_id, limit
        raise PermissionError("fixture denied")


class StaleBackend(EventLogBackend):
    def query(
        self,
        channel: str,
        *,
        after_record_id: int | None,
        limit: int,
    ) -> RawEventBatch:
        del channel, after_record_id, limit
        raise StaleBookmarkError("fixture stale")


def _store(tmp_path: Path) -> SQLiteStore:
    store = SQLiteStore(tmp_path / "systemsense.db")
    store.initialize()
    store.create_case(
        case_id=str(_CASE_ID),
        kind="application",
        symptom="App failed",
        created_at=_NOW.isoformat(),
    )
    return store


def test_replayed_events_are_idempotent_and_bookmark_resumes(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        sentinel = Sentinel(FixedEventLogAdapter(ReplayBackend()), store)

        first = sentinel.poll(_CASE_ID, "Application", limit=10, captured_at=_NOW)
        replay = sentinel.poll(_CASE_ID, "Application", limit=10, captured_at=_NOW)

        assert first.inserted == 2
        assert first.bookmark == 2
        assert replay.inserted == 0
        assert store.record_counts()["evidence"] == 2
        assert store.bookmark("eventlog.Application") == "2"
        rows = store.evidence_page(case_id=str(_CASE_ID), offset=0, limit=10)
        assert all(EvidenceRecord.model_validate_json(row.record_json) for row in rows)


def test_access_denial_creates_coverage_without_advancing_bookmark(
    tmp_path: Path,
) -> None:
    with _store(tmp_path) as store:
        result = Sentinel(FixedEventLogAdapter(DeniedBackend()), store).poll(
            _CASE_ID,
            "Application",
            limit=10,
            captured_at=_NOW,
        )

        assert result.coverage is not None
        assert result.coverage.status is CoverageStatus.DENIED
        assert store.bookmark("eventlog.Application") is None


def test_stale_bookmark_creates_stale_coverage(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        result = Sentinel(FixedEventLogAdapter(StaleBackend()), store).poll(
            _CASE_ID,
            "Application",
            limit=10,
            captured_at=_NOW,
        )

        assert result.coverage is not None
        assert result.coverage.status is CoverageStatus.STALE
        assert store.bookmark("eventlog.Application") is None
