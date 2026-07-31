"""SQLite persistence with explicit transactions and bounded lock waits."""

import json
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import cast

from systemsense.domain.ids import JsonValue


@dataclass(frozen=True, slots=True)
class ArtifactRow:
    artifact_id: str
    sha256: str
    byte_size: int
    media_type: str
    sensitivity: str
    created_at: str


@dataclass(frozen=True, slots=True)
class CaseRow:
    case_id: str
    kind: str
    symptom: str
    created_at: str


@dataclass(frozen=True, slots=True)
class EvidenceRow:
    evidence_id: str
    case_id: str
    record_json: str
    captured_at: str


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
        changed = current is None or self._inventory_value(str(current[0])) != (
            self._inventory_value(record_json)
        )
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

    def invalidate_inventory(self, *, category: str, invalidated_at: str) -> int:
        cursor = self._connection.execute(
            """
            UPDATE inventory_current
            SET record_json = json_set(record_json, '$.invalidated_at', ?)
            WHERE category = ?
            """,
            (invalidated_at, category),
        )
        return cursor.rowcount

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

    @staticmethod
    def _inventory_value(record_json: str) -> object:
        try:
            record = cast("JsonValue", json.loads(record_json))
        except json.JSONDecodeError:
            return record_json
        if isinstance(record, dict) and "value" in record:
            return record["value"]
        return record

    def link_artifact(
        self,
        *,
        artifact_id: str,
        case_id: str,
        sha256: str,
        byte_size: int,
        media_type: str,
        sensitivity: str,
        created_at: str,
    ) -> None:
        self._connection.execute(
            """
            INSERT INTO artifacts (
                artifact_id, sha256, byte_size, media_type, sensitivity, created_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT (sha256) DO NOTHING
            """,
            (
                artifact_id,
                sha256,
                byte_size,
                media_type,
                sensitivity,
                created_at,
            ),
        )
        row = self._connection.execute(
            "SELECT artifact_id FROM artifacts WHERE sha256 = ?",
            (sha256,),
        ).fetchone()
        if row is None:
            raise RuntimeError("artifact metadata was not persisted")
        self._connection.execute(
            """
            INSERT INTO artifact_cases (artifact_id, case_id)
            VALUES (?, ?)
            ON CONFLICT (artifact_id, case_id) DO NOTHING
            """,
            (str(row[0]), case_id),
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

    def case_count(self) -> int:
        row = self._require_connection().execute("SELECT COUNT(*) FROM cases").fetchone()
        assert row is not None
        return int(row[0])

    def case(self, case_id: str) -> CaseRow | None:
        row = (
            self._require_connection()
            .execute(
                """
                SELECT case_id, kind, symptom, created_at
                FROM cases
                WHERE case_id = ?
                """,
                (case_id,),
            )
            .fetchone()
        )
        if row is None:
            return None
        return CaseRow(
            case_id=str(row[0]),
            kind=str(row[1]),
            symptom=str(row[2]),
            created_at=str(row[3]),
        )

    def evidence(
        self,
        *,
        case_id: str,
        evidence_id: str,
    ) -> EvidenceRow | None:
        row = (
            self._require_connection()
            .execute(
                """
                SELECT evidence_id, case_id, record_json, captured_at
                FROM evidence
                WHERE case_id = ? AND evidence_id = ?
                """,
                (case_id, evidence_id),
            )
            .fetchone()
        )
        return None if row is None else self._evidence_row(row)

    def evidence_page(
        self,
        *,
        case_id: str,
        offset: int,
        limit: int,
        category: str | None = None,
        statement_kind: str | None = None,
    ) -> tuple[EvidenceRow, ...]:
        if offset < 0:
            raise ValueError("offset must not be negative")
        if limit < 1:
            raise ValueError("limit must be positive")
        clauses = [
            "case_id = ?",
            "json_type(record_json, '$.statement_kind') IS NOT NULL",
        ]
        parameters: list[str | int] = [case_id]
        if category is not None:
            clauses.append(
                "(json_extract(record_json, '$.collector.id') = ? "
                "OR json_extract(record_json, '$.collector.id') LIKE ?)"
            )
            parameters.extend((category, f"{category}.%"))
        if statement_kind is not None:
            clauses.append("json_extract(record_json, '$.statement_kind') = ?")
            parameters.append(statement_kind)
        parameters.extend((limit, offset))
        rows = self._require_connection().execute(
            f"""
            SELECT evidence_id, case_id, record_json, captured_at
            FROM evidence
            WHERE {" AND ".join(clauses)}
            ORDER BY captured_at DESC, evidence_id
            LIMIT ? OFFSET ?
            """,
            parameters,
        )
        return tuple(self._evidence_row(row) for row in rows)

    def coverage_page(
        self,
        *,
        case_id: str,
        offset: int,
        limit: int,
    ) -> tuple[EvidenceRow, ...]:
        if offset < 0:
            raise ValueError("offset must not be negative")
        if limit < 1:
            raise ValueError("limit must be positive")
        rows = self._require_connection().execute(
            """
            SELECT evidence_id, case_id, record_json, captured_at
            FROM evidence
            WHERE case_id = ?
              AND json_type(record_json, '$.status') IS NOT NULL
              AND json_type(record_json, '$.category') IS NOT NULL
            ORDER BY captured_at DESC, evidence_id
            LIMIT ? OFFSET ?
            """,
            (case_id, limit, offset),
        )
        return tuple(self._evidence_row(row) for row in rows)

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

    def inventory_record(self, *, category: str, fact_key: str) -> str | None:
        row = (
            self._require_connection()
            .execute(
                """
                SELECT record_json
                FROM inventory_current
                WHERE category = ? AND fact_key = ?
                """,
                (category, fact_key),
            )
            .fetchone()
        )
        return None if row is None else str(row[0])

    def inventory_history_count(self, *, category: str, fact_key: str) -> int:
        row = (
            self._require_connection()
            .execute(
                """
                SELECT COUNT(*)
                FROM inventory_history
                WHERE category = ? AND fact_key = ?
                """,
                (category, fact_key),
            )
            .fetchone()
        )
        assert row is not None
        return int(row[0])

    def artifact_for_case(self, *, case_id: str, artifact_id: str) -> ArtifactRow | None:
        row = (
            self._require_connection()
            .execute(
                """
                SELECT
                    artifacts.artifact_id,
                    artifacts.sha256,
                    artifacts.byte_size,
                    artifacts.media_type,
                    artifacts.sensitivity,
                    artifacts.created_at
                FROM artifacts
                JOIN artifact_cases USING (artifact_id)
                WHERE artifact_cases.case_id = ? AND artifacts.artifact_id = ?
                """,
                (case_id, artifact_id),
            )
            .fetchone()
        )
        if row is None:
            return None
        return ArtifactRow(
            artifact_id=str(row[0]),
            sha256=str(row[1]),
            byte_size=int(row[2]),
            media_type=str(row[3]),
            sensitivity=str(row[4]),
            created_at=str(row[5]),
        )

    @staticmethod
    def _evidence_row(row: sqlite3.Row | tuple[object, ...]) -> EvidenceRow:
        return EvidenceRow(
            evidence_id=str(row[0]),
            case_id=str(row[1]),
            record_json=str(row[2]),
            captured_at=str(row[3]),
        )

    def _require_connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise RuntimeError("store is not initialized")
        return self._connection
