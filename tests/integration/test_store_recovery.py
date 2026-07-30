import sqlite3
import time
from pathlib import Path

import pytest

from systemsense.storage.sqlite_store import SQLiteStore

_NOW = "2026-07-30T12:00:00+00:00"
_CASE_ID = "case_0123456789abcdef0123456789abcdef"


def test_uncommitted_records_are_replayed_after_simulated_crash(tmp_path: Path) -> None:
    database_path = tmp_path / "systemsense.db"

    with SQLiteStore(database_path) as store:
        store.create_case(
            case_id=_CASE_ID,
            kind="application",
            symptom="App fails during startup",
            created_at=_NOW,
        )
        with pytest.raises(RuntimeError, match="simulated crash"):
            with store.transaction() as transaction:
                transaction.insert_evidence(
                    case_id=_CASE_ID,
                    evidence_id="evidence_0123456789abcdef0123456789abcdef",
                    source_id=f"src_{'d' * 64}",
                    record_json='{"summary":"uncommitted"}',
                    captured_at=_NOW,
                )
                transaction.advance_bookmark(
                    source="eventlog.application",
                    position="bookmark-11",
                    updated_at=_NOW,
                )
                raise RuntimeError("simulated crash")

    with SQLiteStore(database_path) as recovered:
        assert recovered.record_counts()["evidence"] == 0
        assert recovered.bookmark("eventlog.application") is None
        assert recovered.integrity_check() == "ok"


def test_busy_writer_failure_is_bounded(tmp_path: Path) -> None:
    database_path = tmp_path / "systemsense.db"

    with (
        SQLiteStore(database_path, busy_timeout_ms=200) as first,
        SQLiteStore(database_path, busy_timeout_ms=200) as second,
    ):
        with first.transaction():
            started = time.monotonic()
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                with second.transaction():
                    pass
            elapsed = time.monotonic() - started

    assert elapsed < 1.0
