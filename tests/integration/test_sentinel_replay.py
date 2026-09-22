import json
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from systemsense.audit import AuditChain, AuditCheckpoint
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
from systemsense.storage.sqlite_store import SQLiteStore, StaleCaseStateError

_CASE_ID = CaseId(root="case_0123456789abcdef0123456789abcdef")
_OTHER_CASE_ID = CaseId(root="case_abcdefabcdefabcdefabcdefabcdefab")
_NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)
_CAPTURED = _NOW + timedelta(minutes=5)


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
    def __init__(self) -> None:
        self.after_record_ids: list[int | None] = []

    def query(
        self,
        channel: str,
        *,
        after_record_id: int | None,
        limit: int,
    ) -> RawEventBatch:
        del channel
        self.after_record_ids.append(after_record_id)
        return RawEventBatch(xml_events=(_event(1), _event(2))[:limit])


class EmptyBackend(EventLogBackend):
    def query(
        self,
        channel: str,
        *,
        after_record_id: int | None,
        limit: int,
    ) -> RawEventBatch:
        del channel, after_record_id, limit
        return RawEventBatch(xml_events=())


class DeniedBackend(EventLogBackend):
    def query(
        self,
        channel: str,
        *,
        after_record_id: int | None,
        limit: int,
    ) -> RawEventBatch:
        del channel, after_record_id, limit
        raise PermissionError("password=fixture-secret")


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


class StateChangingBackend(EventLogBackend):
    def __init__(self, store: SQLiteStore) -> None:
        self._store = store

    def query(
        self,
        channel: str,
        *,
        after_record_id: int | None,
        limit: int,
    ) -> RawEventBatch:
        del channel, after_record_id, limit
        with self._store.transaction() as transaction:
            transaction.transition_case(
                case_id=str(_CASE_ID),
                expected_state_version=0,
                status="ready",
            )
        return RawEventBatch(xml_events=())


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
        sentinel = Sentinel(
            FixedEventLogAdapter(ReplayBackend()),
            store,
            now=lambda: _CAPTURED + timedelta(minutes=1),
        )

        first = sentinel.poll(_CASE_ID, "Application", limit=10)
        replay = sentinel.poll(_CASE_ID, "Application", limit=10)

        assert first.inserted == 2
        assert first.bookmark == 2
        assert replay.inserted == 0
        assert store.record_counts()["evidence"] == 2
        assert store.bookmark(f"eventlog.{_CASE_ID}.Application") == "2"
        rows = store.evidence_page(case_id=str(_CASE_ID), offset=0, limit=10)
        assert all(EvidenceRecord.model_validate_json(row.record_json) for row in rows)
        assert {row.observed_at for row in rows} == {_NOW.isoformat()}
        assert {row.captured_at for row in rows} == {(_CAPTURED + timedelta(minutes=1)).isoformat()}
        assert {row.time_basis for row in rows} == {"source_event"}
        assert {row.time_quality for row in rows} == {"exact"}
        assert all(row.execution_id is not None for row in rows)
        with sqlite3.connect(tmp_path / "systemsense.db") as connection:
            audit_rows = connection.execute(
                "SELECT event_json FROM audit_events WHERE case_id = ? ORDER BY sequence",
                (str(_CASE_ID),),
            ).fetchall()

    entries = [json.loads(row[0]) for row in audit_rows]
    assert len(entries) == 2
    assert {entry["outcome"] for entry in entries} == {"allowed"}
    assert entries[0]["previous_hash"] == "0" * 64
    assert entries[1]["previous_hash"] == entries[0]["event_hash"]


def test_access_denial_creates_coverage_without_advancing_bookmark(
    tmp_path: Path,
) -> None:
    with _store(tmp_path) as store:
        result = Sentinel(FixedEventLogAdapter(DeniedBackend()), store).poll(
            _CASE_ID,
            "Application",
            limit=10,
        )

        assert result.coverage is not None
        assert result.coverage.status is CoverageStatus.DENIED
        assert store.bookmark(f"eventlog.{_CASE_ID}.Application") is None


def test_bookmarks_are_case_scoped_so_two_cases_observe_the_same_events(
    tmp_path: Path,
) -> None:
    with _store(tmp_path) as store:
        store.create_case(
            case_id=str(_OTHER_CASE_ID),
            kind="application",
            symptom="Other app failed",
            created_at=_NOW.isoformat(),
        )
        backend = ReplayBackend()
        sentinel = Sentinel(
            FixedEventLogAdapter(backend),
            store,
            now=lambda: _CAPTURED,
        )

        first = sentinel.poll(_CASE_ID, "Application", limit=10)
        second = sentinel.poll(_OTHER_CASE_ID, "Application", limit=10)

        assert first.inserted == 2
        assert second.inserted == 2
        assert backend.after_record_ids == [None, None]
        assert store.bookmark(f"eventlog.{_CASE_ID}.Application") == "2"
        assert store.bookmark(f"eventlog.{_OTHER_CASE_ID}.Application") == "2"


def test_repeated_denials_are_distinct_attempts_with_stable_source_identity(
    tmp_path: Path,
) -> None:
    clock_values = iter(
        (
            _NOW,
            _NOW + timedelta(seconds=1),
            _NOW + timedelta(seconds=2),
            _NOW + timedelta(seconds=3),
            _NOW + timedelta(seconds=4),
            _NOW + timedelta(seconds=5),
        )
    )
    with _store(tmp_path) as store:
        sentinel = Sentinel(
            FixedEventLogAdapter(DeniedBackend()),
            store,
            now=lambda: next(clock_values),
        )
        first = sentinel.poll(_CASE_ID, "Application", limit=10)
        second = sentinel.poll(_CASE_ID, "Application", limit=10)

        assert first.coverage is not None
        assert second.coverage is not None
        assert first.coverage.source_id == second.coverage.source_id
        assert store.coverage_count(case_id=str(_CASE_ID)) == 2
        assert store.probe_execution_count(case_id=str(_CASE_ID)) == 2
        rows = store.coverage_page(case_id=str(_CASE_ID), offset=0, limit=10)
        assert len(rows) == 2
        assert len({row.dedupe_key for row in rows}) == 2
        assert {row.captured_at for row in rows} == {
            (_NOW + timedelta(seconds=1)).isoformat(),
            (_NOW + timedelta(seconds=4)).isoformat(),
        }

        with sqlite3.connect(tmp_path / "systemsense.db") as connection:
            audit_rows = connection.execute(
                """
                SELECT event_json, occurred_at, persisted_at
                FROM audit_events
                WHERE case_id = ?
                ORDER BY sequence
                """,
                (str(_CASE_ID),),
            ).fetchall()

    assert len(audit_rows) == 2
    assert all(row[1] != _CAPTURED.isoformat() for row in audit_rows)
    assert all(row[2] >= row[1] for row in audit_rows)
    entries = [json.loads(row[0]) for row in audit_rows]
    assert entries[0]["previous_hash"] == "0" * 64
    assert entries[1]["previous_hash"] == entries[0]["event_hash"]
    assert {entry["outcome"] for entry in entries} == {"denied"}
    assert all("fixture-secret" not in (entry["error"] or "") for entry in entries)


def test_empty_query_is_journaled_with_actual_probe_times(
    tmp_path: Path,
) -> None:
    clock_values = iter(_NOW + timedelta(seconds=second) for second in (0, 7, 8, 9, 16, 17))
    with _store(tmp_path) as store:
        sentinel = Sentinel(
            FixedEventLogAdapter(EmptyBackend()),
            store,
            now=lambda: next(clock_values),
        )
        first = sentinel.poll(_CASE_ID, "Application", limit=10)
        second = sentinel.poll(_CASE_ID, "Application", limit=10)

        assert first.inserted == second.inserted == 0
        assert first.coverage is not None
        assert second.coverage is not None
        assert first.coverage.status is CoverageStatus.COVERED
        assert second.coverage.status is CoverageStatus.COVERED
        assert first.coverage.source_id == second.coverage.source_id
        assert store.probe_execution_count(case_id=str(_CASE_ID)) == 2
        assert store.audit_count(case_id=str(_CASE_ID)) == 2
        assert store.coverage_count(case_id=str(_CASE_ID)) == 2
        coverage_rows = store.coverage_page(case_id=str(_CASE_ID), offset=0, limit=10)
        assert len({row.dedupe_key for row in coverage_rows}) == 2
        assert len({row.execution_id for row in coverage_rows}) == 2

        with sqlite3.connect(tmp_path / "systemsense.db") as connection:
            execution_rows = connection.execute(
                """
                SELECT started_at, finished_at, status, state_version
                FROM probe_executions
                WHERE case_id = ?
                ORDER BY started_at
                """,
                (str(_CASE_ID),),
            ).fetchall()

    assert execution_rows == [
        (
            _NOW.isoformat(),
            (_NOW + timedelta(seconds=7)).isoformat(),
            "ok",
            0,
        ),
        (
            (_NOW + timedelta(seconds=9)).isoformat(),
            (_NOW + timedelta(seconds=16)).isoformat(),
            "ok",
            0,
        ),
    ]


def test_audit_chain_resumes_across_sentinel_instances(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        Sentinel(FixedEventLogAdapter(EmptyBackend()), store, now=lambda: _NOW).poll(
            _CASE_ID,
            "Application",
            limit=10,
        )
        Sentinel(FixedEventLogAdapter(EmptyBackend()), store, now=lambda: _NOW).poll(
            _CASE_ID,
            "Application",
            limit=10,
        )

        entries = store.audit_entries(case_id=str(_CASE_ID), limit=10)

    checkpoint = AuditCheckpoint(entry_count=2, head_hash=entries[-1].event_hash)
    assert [entry.sequence for entry in entries] == [1, 2]
    assert AuditChain.verify(entries, checkpoint=checkpoint).valid


def test_poll_rejects_evidence_write_after_case_state_changes(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        sentinel = Sentinel(
            FixedEventLogAdapter(StateChangingBackend(store)),
            store,
            now=lambda: _NOW,
        )

        with pytest.raises(StaleCaseStateError, match="changed before persistence"):
            sentinel.poll(_CASE_ID, "Application", limit=10)

        assert store.probe_execution_count(case_id=str(_CASE_ID)) == 0
        assert store.audit_count(case_id=str(_CASE_ID)) == 0


def test_attempt_uses_current_case_state_version_and_rejects_missing_case(
    tmp_path: Path,
) -> None:
    with _store(tmp_path) as store:
        with store.transaction() as transaction:
            assert (
                transaction.transition_case(
                    case_id=str(_CASE_ID),
                    expected_state_version=0,
                    status="ready",
                )
                == 1
            )
        sentinel = Sentinel(
            FixedEventLogAdapter(EmptyBackend()),
            store,
            now=lambda: _NOW,
        )
        sentinel.poll(_CASE_ID, "Application", limit=10)
        execution = store.probe_execution_count(case_id=str(_CASE_ID))
        with sqlite3.connect(tmp_path / "systemsense.db") as connection:
            state_version = connection.execute(
                "SELECT state_version FROM probe_executions WHERE case_id = ?",
                (str(_CASE_ID),),
            ).fetchone()[0]

        assert execution == 1
        assert state_version == 1
        missing = CaseId(root="case_abcdefabcdefabcdefabcdefabcdefab")
        try:
            sentinel.poll(missing, "Application", limit=10)
        except ValueError as error:
            assert "does not exist" in str(error)
        else:
            raise AssertionError("missing cases must not be queried")


def test_stale_bookmark_creates_stale_coverage(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        result = Sentinel(FixedEventLogAdapter(StaleBackend()), store).poll(
            _CASE_ID,
            "Application",
            limit=10,
        )

        assert result.coverage is not None
        assert result.coverage.status is CoverageStatus.STALE
        assert store.bookmark(f"eventlog.{_CASE_ID}.Application") is None
