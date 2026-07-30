"""SQLite persistence with explicit transactions and bounded lock waits."""

import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path


class StoreTransaction:
    """Write operations that must commit or roll back as one unit."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    def insert_evidence(
        self,
        *,
        case_id: str,
        evidence_id: str,
        source_id: str,
        record_json: str,
        captured_at: str,
    ) -> bool:
        cursor = self._connection.execute(
            """
            INSERT INTO evidence (
                evidence_id, case_id, source_id, record_json, captured_at
            ) VALUES (?, ?, ?, ?, ?)
            ON CONFLICT (case_id, source_id) DO NOTHING
            """,
            (evidence_id, case_id, source_id, record_json, captured_at),
        )
        return cursor.rowcount == 1

    def upsert_inventory(
        self,
        *,
        category: str,
        fact_key: str,
        record_json: str,
        observed_at: str,
    ) -> bool:
        current = self._connection.execute(
            """
            SELECT record_json
            FROM inventory_current
            WHERE category = ? AND fact_key = ?
            """,
            (category, fact_key),
        ).fetchone()
        changed = current is None or current[0] != record_json
        if changed:
            self._connection.execute(
                """
                INSERT INTO inventory_history (
                    category, fact_key, record_json, observed_at
                ) VALUES (?, ?, ?, ?)
                """,
                (category, fact_key, record_json, observed_at),
            )
        self._connection.execute(
            """
            INSERT INTO inventory_current (
                category, fact_key, record_json, observed_at
            ) VALUES (?, ?, ?, ?)
            ON CONFLICT (category, fact_key) DO UPDATE SET
                record_json = excluded.record_json,
                observed_at = excluded.observed_at
            """,
            (category, fact_key, record_json, observed_at),
        )
        return changed

    def append_audit(
        self,
        *,
        event_id: str,
        case_id: str | None,
        event_json: str,
        created_at: str,
    ) -> None:
        self._connection.execute(
            """
            INSERT INTO audit_events (
                event_id, case_id, event_json, created_at
            ) VALUES (?, ?, ?, ?)
            """,
            (event_id, case_id, event_json, created_at),
        )

    def advance_bookmark(
        self,
        *,
        source: str,
        position: str,
        updated_at: str,
    ) -> None:
        self._connection.execute(
            """
            INSERT INTO bookmarks (source, position, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT (source) DO UPDATE SET
                position = excluded.position,
                updated_at = excluded.updated_at
            """,
            (source, position, updated_at),
        )


class SQLiteStore:
    """One SQLite connection intended to remain on its creating thread."""

    def __init__(self, path: Path, *, busy_timeout_ms: int = 1000) -> None:
        if busy_timeout_ms < 1:
            raise ValueError("busy_timeout_ms must be positive")
        self._path = path
        self._configured_busy_timeout_ms = busy_timeout_ms
        self._connection: sqlite3.Connection | None = None

    def __enter__(self) -> "SQLiteStore":
        self.initialize()
        return self

    def __exit__(
        self,
        _exception_type: type[BaseException] | None,
        _exception: BaseException | None,
        _traceback: object | None,
    ) -> None:
        self.close()

    def initialize(self) -> None:
        if self._connection is not None:
            return
        self._path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(
            self._path,
            timeout=self._configured_busy_timeout_ms / 1000,
            isolation_level=None,
        )
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute(f"PRAGMA busy_timeout = {self._configured_busy_timeout_ms}")
            connection.execute("PRAGMA journal_mode = WAL")
            migration_path = Path(__file__).with_name("migrations") / "001_initial.sql"
            connection.executescript(migration_path.read_text(encoding="utf-8"))
        except BaseException:
            connection.close()
            raise
        self._connection = connection

    def close(self) -> None:
        if self._connection is not None:
            self._connection.close()
            self._connection = None

    @contextmanager
    def transaction(self) -> Generator[StoreTransaction]:
        connection = self._require_connection()
        connection.execute("BEGIN IMMEDIATE")
        try:
            yield StoreTransaction(connection)
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        else:
            connection.commit()

    def create_case(
        self,
        *,
        case_id: str,
        kind: str,
        symptom: str,
        created_at: str,
    ) -> None:
        self._require_connection().execute(
            """
            INSERT INTO cases (case_id, kind, symptom, created_at)
            VALUES (?, ?, ?, ?)
            """,
            (case_id, kind, symptom, created_at),
        )

    def schema_version(self) -> int:
        row = self._require_connection().execute("PRAGMA user_version").fetchone()
        assert row is not None
        return int(row[0])

    def foreign_keys_enabled(self) -> bool:
        row = self._require_connection().execute("PRAGMA foreign_keys").fetchone()
        return row is not None and row[0] == 1

    def journal_mode(self) -> str:
        row = self._require_connection().execute("PRAGMA journal_mode").fetchone()
        assert row is not None
        return str(row[0])

    def busy_timeout_ms(self) -> int:
        row = self._require_connection().execute("PRAGMA busy_timeout").fetchone()
        assert row is not None
        return int(row[0])

    def integrity_check(self) -> str:
        row = self._require_connection().execute("PRAGMA integrity_check").fetchone()
        assert row is not None
        return str(row[0])

    def table_names(self) -> set[str]:
        rows = self._require_connection().execute(
            """
            SELECT name
            FROM sqlite_schema
            WHERE type = 'table' AND name NOT LIKE 'sqlite_%'
            """
        )
        return {str(row[0]) for row in rows}

    def bookmark(self, source: str) -> str | None:
        row = (
            self._require_connection()
            .execute(
                "SELECT position FROM bookmarks WHERE source = ?",
                (source,),
            )
            .fetchone()
        )
        return None if row is None else str(row[0])

    def record_counts(self) -> dict[str, int]:
        tables = ("evidence", "inventory_current", "inventory_history", "audit_events")
        counts: dict[str, int] = {}
        connection = self._require_connection()
        for table in tables:
            row = connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone()
            assert row is not None
            counts[table] = int(row[0])
        return counts

    def _require_connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise RuntimeError("store is not initialized")
        return self._connection
