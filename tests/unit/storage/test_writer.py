import sqlite3
import threading
from pathlib import Path

import pytest

from systemsense.storage.sqlite_store import SQLiteStore
from systemsense.storage.writer import SingleWriter

_NOW = "2026-07-30T12:00:00+00:00"


def _seed_case(store: SQLiteStore) -> None:
    store.create_case(
        case_id="case_0123456789abcdef0123456789abcdef",
        kind="application",
        symptom="App fails during startup",
        created_at=_NOW,
    )


def test_single_writer_thread_owns_write_connection(tmp_path: Path) -> None:
    caller_thread = threading.get_ident()

    with SingleWriter(tmp_path / "systemsense.db") as writer:
        writer_threads = {
            writer.execute(lambda _store: threading.get_ident()) for _index in range(3)
        }

    assert len(writer_threads) == 1
    assert caller_thread not in writer_threads


def test_transaction_commits_evidence_inventory_audit_and_bookmark(tmp_path: Path) -> None:
    with SingleWriter(tmp_path / "systemsense.db") as writer:
        writer.execute(_seed_case)

        def persist(store: SQLiteStore) -> None:
            with store.transaction() as transaction:
                assert transaction.insert_evidence(
                    case_id="case_0123456789abcdef0123456789abcdef",
                    evidence_id="evidence_0123456789abcdef0123456789abcdef",
                    source_id=f"src_{'a' * 64}",
                    record_json='{"summary":"failure event"}',
                    captured_at=_NOW,
                )
                transaction.upsert_inventory(
                    category="system",
                    fact_key="windows.build",
                    record_json='{"value":"26100"}',
                    observed_at=_NOW,
                )
                transaction.append_audit(
                    event_id="audit-1",
                    case_id="case_0123456789abcdef0123456789abcdef",
                    event_json='{"outcome":"allowed"}',
                    created_at=_NOW,
                )
                transaction.advance_bookmark(
                    source="eventlog.application",
                    position="bookmark-7",
                    updated_at=_NOW,
                )

        writer.execute(persist)
        counts = writer.execute(lambda store: store.record_counts())
        bookmark = writer.execute(lambda store: store.bookmark("eventlog.application"))

    assert counts == {
        "evidence": 1,
        "inventory_current": 1,
        "inventory_history": 1,
        "audit_events": 1,
    }
    assert bookmark == "bookmark-7"


def test_failed_evidence_rolls_back_advanced_bookmark(tmp_path: Path) -> None:
    with SingleWriter(tmp_path / "systemsense.db") as writer:
        writer.execute(_seed_case)

        def fail_persistence(store: SQLiteStore) -> None:
            with store.transaction() as transaction:
                transaction.advance_bookmark(
                    source="eventlog.application",
                    position="bookmark-8",
                    updated_at=_NOW,
                )
                transaction.insert_evidence(
                    case_id="case_0123456789abcdef0123456789abcdef",
                    evidence_id="evidence_0123456789abcdef0123456789abcdef",
                    source_id=f"src_{'b' * 64}",
                    record_json="not valid JSON",
                    captured_at=_NOW,
                )

        with pytest.raises(sqlite3.IntegrityError):
            writer.execute(fail_persistence)

        assert writer.execute(lambda store: store.bookmark("eventlog.application")) is None
        assert writer.execute(lambda store: store.record_counts()["evidence"]) == 0


def test_duplicate_stable_source_id_is_idempotent_and_bookmark_advances(
    tmp_path: Path,
) -> None:
    with SingleWriter(tmp_path / "systemsense.db") as writer:
        writer.execute(_seed_case)

        def persist(store: SQLiteStore, evidence_id: str, bookmark: str) -> bool:
            with store.transaction() as transaction:
                inserted = transaction.insert_evidence(
                    case_id="case_0123456789abcdef0123456789abcdef",
                    evidence_id=evidence_id,
                    source_id=f"src_{'c' * 64}",
                    record_json='{"summary":"same source"}',
                    captured_at=_NOW,
                )
                transaction.advance_bookmark(
                    source="eventlog.application",
                    position=bookmark,
                    updated_at=_NOW,
                )
            return inserted

        assert writer.execute(
            lambda store: persist(
                store,
                "evidence_0123456789abcdef0123456789abcdef",
                "bookmark-9",
            )
        )
        assert not writer.execute(
            lambda store: persist(
                store,
                "evidence_fedcba9876543210fedcba9876543210",
                "bookmark-10",
            )
        )
        assert writer.execute(lambda store: store.record_counts()["evidence"]) == 1
        assert writer.execute(lambda store: store.bookmark("eventlog.application")) == "bookmark-10"
