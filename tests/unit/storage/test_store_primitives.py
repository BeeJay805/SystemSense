import sqlite3
from pathlib import Path

import pytest

from systemsense.storage.sqlite_store import SQLiteStore


def test_store_exposes_initialized_thread_owned_connection_and_path(tmp_path: Path) -> None:
    database_path = tmp_path / "systemsense.db"
    store = SQLiteStore(database_path)

    assert store.path == database_path
    with pytest.raises(RuntimeError, match="not initialized"):
        _ = store.connection

    with store:
        assert isinstance(store.connection, sqlite3.Connection)
        assert store.connection.execute("SELECT 1").fetchone() == (1,)


def test_case_listing_is_filtered_bounded_and_stably_newest_first(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        for suffix, kind, created_at in (
            ("1", "incident", "2026-07-29T12:00:00+00:00"),
            ("2", "passive", "2026-07-30T12:00:00+00:00"),
            ("3", "passive", "2026-07-31T12:00:00+00:00"),
        ):
            store.create_case(
                case_id=f"case_{suffix * 32}",
                kind=kind,
                symptom=f"case {suffix}",
                created_at=created_at,
            )

        rows = store.cases(
            created_from="2026-07-30T00:00:00+00:00",
            created_until="2026-08-01T00:00:00+00:00",
            kinds=("passive",),
            limit=1,
        )

        assert tuple(row.case_id for row in rows) == (f"case_{'3' * 32}",)
        assert tuple(row.case_id for row in store.cases(limit=1, offset=1)) == (f"case_{'2' * 32}",)


@pytest.mark.parametrize("limit", [0, 501])
def test_case_listing_rejects_unbounded_limits(tmp_path: Path, limit: int) -> None:
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        with pytest.raises(ValueError, match="between 1 and 500"):
            store.cases(limit=limit)


def test_case_listing_rejects_negative_offset(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        with pytest.raises(ValueError, match="offset"):
            store.cases(offset=-1)


def test_investigation_memory_rows_follow_case_retention(tmp_path: Path) -> None:
    case_id = "case_11111111111111111111111111111111"
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        store.create_case(
            case_id=case_id,
            kind="incident",
            symptom="checkpoint fixture",
            created_at="2026-07-30T12:00:00+00:00",
        )
        store.connection.execute(
            "INSERT INTO investigation_checkpoints (case_id, record_json) VALUES (?, ?)",
            (case_id, '{"state_version":1}'),
        )
        store.connection.execute(
            """
            INSERT INTO investigation_steps (case_id, state_version, record_json)
            VALUES (?, ?, ?)
            """,
            (case_id, 1, '{"state_version":1}'),
        )

        store.connection.execute("DELETE FROM cases WHERE case_id = ?", (case_id,))

        assert store.connection.execute(
            "SELECT COUNT(*) FROM investigation_checkpoints"
        ).fetchone() == (0,)
        assert store.connection.execute("SELECT COUNT(*) FROM investigation_steps").fetchone() == (
            0,
        )
