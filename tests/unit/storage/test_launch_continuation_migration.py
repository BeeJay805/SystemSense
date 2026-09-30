from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from systemsense.storage import sqlite_store
from systemsense.storage.sqlite_store import SQLiteStore

MIGRATIONS = Path(sqlite_store.__file__).parent / "migrations"
MIGRATION_SQL = (MIGRATIONS / "041_candidate_launch_continuations_v2.sql").read_text(
    encoding="utf-8"
)
V32_SQL = MIGRATIONS / "032_candidate_launch_continuations.sql"


def _create_v40_minimal(path: Path) -> None:
    """Build the real V32 continuation/consumption tables with minimal FK parents."""
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.executescript(
            """
            CREATE TABLE cases(case_id TEXT PRIMARY KEY) STRICT;
            CREATE TABLE candidate_dispatch_claims(admission_id TEXT PRIMARY KEY) STRICT;
            CREATE TABLE search_frontier_investigator_turns(turn_id TEXT PRIMARY KEY) STRICT;
            INSERT INTO cases VALUES ('case_a'), ('case_b');
            INSERT INTO candidate_dispatch_claims VALUES ('claim_a'), ('claim_b');
            INSERT INTO search_frontier_investigator_turns VALUES ('turn_a'), ('turn_b');
            """
        )
        connection.executescript(V32_SQL.read_text(encoding="utf-8-sig"))
        connection.executemany(
            "INSERT INTO candidate_launch_continuations VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                (
                    "candidate_launch_v1_a",
                    1,
                    "claim_a",
                    "turn_a",
                    "case_a",
                    7,
                    8,
                    1,
                    "probe-0-a",
                    "a" * 64,
                    "2026-09-30T14:11:10.096397+00:00",
                    "2026-09-30T14:11:09.463487+00:00",
                ),
                (
                    "candidate_launch_v1_b",
                    1,
                    "claim_b",
                    "turn_b",
                    "case_b",
                    14,
                    15,
                    1,
                    "probe-0-b",
                    "b" * 64,
                    "2026-09-30T14:11:16.090676+00:00",
                    "2026-09-30T14:11:15.582719+00:00",
                ),
            ),
        )
        connection.execute(
            "INSERT INTO candidate_launch_consumptions VALUES (?,?,?)",
            ("candidate_launch_v1_a", "case_a", "2026-09-30T14:11:09.900000+00:00"),
        )
        connection.execute("PRAGMA user_version = 40")
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def _rows(connection: sqlite3.Connection, table: str) -> tuple[tuple[object, ...], ...]:
    return tuple(connection.execute(f"SELECT * FROM {table} ORDER BY 1").fetchall())


def _custody_schema(connection: sqlite3.Connection) -> tuple[object, ...]:
    return (
        tuple(connection.execute("PRAGMA foreign_key_list(candidate_launch_continuations)")),
        tuple(connection.execute("PRAGMA foreign_key_list(candidate_launch_consumptions)")),
        tuple(
            connection.execute(
                "SELECT type,name,sql FROM sqlite_schema WHERE type IN ('trigger','index') "
                "AND tbl_name IN "
                "('candidate_launch_continuations','candidate_launch_consumptions') "
                "ORDER BY type,name"
            )
        ),
    )


def _migrate(connection: sqlite3.Connection, script: str = MIGRATION_SQL) -> None:
    SQLiteStore._apply_frontier_snapshot_migration(  # pyright: ignore[reportPrivateUsage]
        connection, script=script, version=41
    )


def test_v40_to_v41_preserves_continuation_and_consumption_rows_and_custody(
    tmp_path: Path,
) -> None:
    database = tmp_path / "v40-launches.db"
    _create_v40_minimal(database)
    with sqlite3.connect(database) as connection:
        before_parent = _rows(connection, "candidate_launch_continuations")
        before_child = _rows(connection, "candidate_launch_consumptions")
        before_custody = _custody_schema(connection)
        _migrate(connection)
        assert _custody_schema(connection) == before_custody
        assert connection.execute("PRAGMA user_version").fetchone() == (41,)
        assert _rows(connection, "candidate_launch_continuations") == before_parent
        assert _rows(connection, "candidate_launch_consumptions") == before_child
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert (
            connection.execute(
                "SELECT sql FROM sqlite_schema WHERE type='table' "
                "AND name='candidate_launch_continuations'"
            )
            .fetchone()[0]
            .find("IN (1, 2)")
            >= 0
        )
        assert connection.execute(
            "SELECT name FROM sqlite_schema WHERE type='index' "
            "AND name='candidate_launch_continuations_case_version'"
        ).fetchone() == ("candidate_launch_continuations_case_version",)
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE candidate_launch_continuations SET task_id='changed' "
                "WHERE continuation_id='candidate_launch_v1_a'"
            )
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "DELETE FROM candidate_launch_continuations "
                "WHERE continuation_id='candidate_launch_v1_a'"
            )
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "UPDATE candidate_launch_consumptions SET consumed_at='changed' "
                "WHERE continuation_id='candidate_launch_v1_a'"
            )
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            connection.execute(
                "DELETE FROM candidate_launch_consumptions "
                "WHERE continuation_id='candidate_launch_v1_a'"
            )
        connection.execute("DELETE FROM cases WHERE case_id='case_a'")
        assert connection.execute(
            "SELECT COUNT(*) FROM candidate_launch_continuations "
            "WHERE continuation_id='candidate_launch_v1_a'"
        ).fetchone() == (0,)
        assert connection.execute(
            "SELECT COUNT(*) FROM candidate_launch_consumptions "
            "WHERE continuation_id='candidate_launch_v1_a'"
        ).fetchone() == (0,)
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_v40_to_v41_failure_rolls_back_parent_rebuild_and_version(tmp_path: Path) -> None:
    database = tmp_path / "v40-launches-rollback.db"
    _create_v40_minimal(database)
    with sqlite3.connect(database) as connection:
        before_parent = _rows(connection, "candidate_launch_continuations")
        before_child = _rows(connection, "candidate_launch_consumptions")
        before_schema = tuple(
            connection.execute(
                "SELECT type,name,sql FROM sqlite_schema WHERE name LIKE "
                "'candidate_launch_continuation%' ORDER BY type,name"
            ).fetchall()
        )
        broken = MIGRATION_SQL + "\nSELECT * FROM deliberately_missing_after_rebuild;\n"
        with pytest.raises(sqlite3.OperationalError, match="no such table"):
            _migrate(connection, broken)
        assert connection.execute("PRAGMA user_version").fetchone() == (40,)
        assert _rows(connection, "candidate_launch_continuations") == before_parent
        assert _rows(connection, "candidate_launch_consumptions") == before_child
        after_schema = tuple(
            connection.execute(
                "SELECT type,name,sql FROM sqlite_schema WHERE name LIKE "
                "'candidate_launch_continuation%' ORDER BY type,name"
            ).fetchall()
        )
        assert after_schema == before_schema
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
