"""SQLite persistence with explicit transactions and bounded lock waits."""

import json
import sqlite3
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from pydantic import ValidationError

from systemsense.audit import (
    AUDIT_GENESIS_HASH,
    AuditChain,
    AuditCheckpoint,
    AuditEntry,
)
from systemsense.domain.ids import JsonValue
from systemsense.storage.runtime_trace import TraceKind, append_coordinator_event


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
    status: str = "open"
    state_version: int = 0
    time_window_start: str | None = None
    time_window_end: str | None = None
    time_window_basis: str = "unknown"


@dataclass(frozen=True, slots=True)
class ProbeExecutionRow:
    execution_id: str
    case_id: str
    probe_id: str
    probe_version: int
    status: str
    parameters_json: str
    started_at: str
    finished_at: str | None
    state_version: int
    tree_exit_status: str


@dataclass(frozen=True, slots=True)
class EvidenceRow:
    evidence_id: str
    case_id: str
    record_json: str
    observed_at: str
    captured_at: str
    execution_id: str | None
    dedupe_key: str
    time_basis: str
    time_quality: str


@dataclass(frozen=True, slots=True)
class InventoryRow:
    category: str
    fact_key: str
    record_json: str
    observed_at: str


class StaleCaseStateError(RuntimeError):
    """A case transition was based on an obsolete state version."""


class StaleAuditHeadError(RuntimeError):
    """An audit entry was prepared from an obsolete per-case chain head."""


class AuditEntryBindingError(ValueError):
    """Persisted audit metadata does not bind to its typed entry."""


class StoreTransaction:
    """Write operations that must commit or roll back as one unit."""

    def __init__(self, connection: sqlite3.Connection) -> None:
        self._connection = connection

    def record_probe_execution(
        self,
        *,
        execution_id: str,
        case_id: str,
        probe_id: str,
        probe_version: int,
        status: str,
        parameters_json: str,
        started_at: str,
        finished_at: str | None,
        state_version: int,
        followup_admission_id: str | None = None,
        tree_exit_status: str = "not_tracked",
    ) -> None:
        self._connection.execute(
            """
            INSERT INTO probe_executions (
                execution_id,
                case_id,
                probe_id,
                probe_version,
                status,
                parameters_json,
                started_at,
                finished_at,
                state_version,
                followup_admission_id,
                tree_exit_status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                execution_id,
                case_id,
                probe_id,
                probe_version,
                status,
                parameters_json,
                started_at,
                finished_at,
                state_version,
                followup_admission_id,
                tree_exit_status,
            ),
        )
        if self._traced_case(case_id):
            append_coordinator_event(
                self._connection,
                case_id=case_id,
                kind="probe",
                fields={"probe_id": probe_id, "status": status},
                source_record_id=execution_id,
                source_observed_at=finished_at,
            )

    def link_decision_execution(self, *, snapshot_id: str, execution_id: str) -> None:
        """Bind one completed read-only execution to its frozen decision, atomically.

        The caller must invoke this inside the same transaction that inserts the
        execution. Neither matching timestamps nor neighboring state versions
        establish this provenance.
        """

        row = self._connection.execute(
            """SELECT snapshot.case_id, snapshot.state_version,
                      snapshot.candidate_probe_ids_json, execution.case_id,
                      execution.probe_id, execution.state_version,
                      snapshot.captured_at, execution.started_at, execution.finished_at
               FROM decision_snapshots AS snapshot
               JOIN probe_executions AS execution ON execution.execution_id = ?
               WHERE snapshot.snapshot_id = ?""",
            (execution_id, snapshot_id),
        ).fetchone()
        if row is None or (
            str(row[0]) != str(row[3])
            or int(row[5]) <= int(row[1])
            or str(row[4]) not in json.loads(str(row[2]))
        ):
            raise ValueError("execution does not match frozen decision candidate")
        if row[8] is None:
            raise ValueError("decision execution chronology requires a finished run")
        try:
            snapshot_at = _parse_utc_timestamp(str(row[6]))
            started_at = _parse_utc_timestamp(str(row[7]))
            finished_at = _parse_utc_timestamp(str(row[8]))
        except ValueError as error:
            raise ValueError("decision execution chronology has an invalid timestamp") from error
        if not snapshot_at <= started_at <= finished_at:
            raise ValueError("decision execution chronology is invalid")
        self._connection.execute(
            """INSERT INTO decision_execution_links
               (snapshot_id, execution_id, case_id, probe_id, schema_version)
               VALUES (?, ?, ?, ?, 1)""",
            (snapshot_id, execution_id, str(row[0]), str(row[4])),
        )

    def append_coordinator_event(
        self,
        *,
        case_id: str,
        kind: TraceKind,
        fields: dict[str, str | bool | None],
        source_record_id: str | None = None,
        source_observed_at: str | None = None,
    ) -> None:
        if not self._traced_case(case_id):
            raise ValueError("coordinator trace requires an investigation case")
        append_coordinator_event(
            self._connection,
            case_id=case_id,
            kind=kind,
            fields=fields,
            source_record_id=source_record_id,
            source_observed_at=source_observed_at,
        )

    def _traced_case(self, case_id: str) -> bool:
        return (
            self._connection.execute(
                "SELECT 1 FROM investigation_checkpoints WHERE case_id = ?", (case_id,)
            ).fetchone()
            is not None
        )

    def transition_case(
        self,
        *,
        case_id: str,
        expected_state_version: int,
        status: str,
    ) -> int:
        next_version = expected_state_version + 1
        cursor = self._connection.execute(
            """
            UPDATE cases
            SET status = ?, state_version = ?
            WHERE case_id = ? AND state_version = ?
            """,
            (status, next_version, case_id, expected_state_version),
        )
        if cursor.rowcount != 1:
            raise StaleCaseStateError("case state changed before transition")
        return next_version

    def require_case_state(self, *, case_id: str, expected_state_version: int) -> None:
        """Reject writes prepared against a case state that has since changed."""
        row = self._connection.execute(
            "SELECT state_version FROM cases WHERE case_id = ?",
            (case_id,),
        ).fetchone()
        if row is None or int(row[0]) != expected_state_version:
            raise StaleCaseStateError("case state changed before persistence")

    def insert_evidence(
        self,
        *,
        case_id: str,
        evidence_id: str,
        source_id: str,
        record_json: str,
        captured_at: str,
        observed_at: str | None = None,
        execution_id: str | None = None,
        dedupe_key: str | None = None,
        time_basis: str = "unknown",
        time_quality: str = "unknown",
    ) -> bool:
        effective_observed_at = observed_at or captured_at
        effective_dedupe_key = dedupe_key or source_id
        cursor = self._connection.execute(
            """
            INSERT INTO evidence (
                evidence_id,
                case_id,
                source_id,
                record_json,
                observed_at,
                captured_at,
                execution_id,
                dedupe_key,
                time_basis,
                time_quality
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (case_id, dedupe_key) DO NOTHING
            """,
            (
                evidence_id,
                case_id,
                source_id,
                record_json,
                effective_observed_at,
                captured_at,
                execution_id,
                effective_dedupe_key,
                time_basis,
                time_quality,
            ),
        )
        inserted = cursor.rowcount == 1
        if inserted and self._traced_case(case_id):
            raw = json.loads(record_json)
            kind: TraceKind = (
                "coverage"
                if isinstance(raw, dict) and "status" in raw and "category" in raw
                else "evidence"
            )
            append_coordinator_event(
                self._connection,
                case_id=case_id,
                kind=kind,
                fields={},
                source_record_id=evidence_id,
                source_observed_at=observed_at or captured_at,
            )
        return inserted

    def upsert_inventory(
        self,
        *,
        category: str,
        fact_key: str,
        record_json: str,
        observed_at: str,
        captured_at: str | None = None,
        time_basis: str = "unknown",
        time_quality: str = "unknown",
    ) -> bool:
        observed_instant = _parse_utc_timestamp(observed_at)
        effective_captured_at = captured_at or observed_at
        _parse_utc_timestamp(effective_captured_at)
        current = self._connection.execute(
            """
            SELECT record_json, observed_at
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
                    category,
                    fact_key,
                    record_json,
                    observed_at,
                    captured_at,
                    time_basis,
                    time_quality
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    category,
                    fact_key,
                    record_json,
                    observed_at,
                    effective_captured_at,
                    time_basis,
                    time_quality,
                ),
            )
        if current is not None and _parse_utc_timestamp(str(current[1])) > observed_instant:
            return changed
        self._connection.execute(
            """
            INSERT INTO inventory_current (
                category,
                fact_key,
                record_json,
                observed_at,
                captured_at,
                time_basis,
                time_quality
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT (category, fact_key) DO UPDATE SET
                record_json = excluded.record_json,
                observed_at = excluded.observed_at,
                captured_at = excluded.captured_at,
                time_basis = excluded.time_basis,
                time_quality = excluded.time_quality
            """,
            (
                category,
                fact_key,
                record_json,
                observed_at,
                effective_captured_at,
                time_basis,
                time_quality,
            ),
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
        occurred_at: str | None = None,
        persisted_at: str | None = None,
    ) -> None:
        try:
            entry = AuditEntry.model_validate_json(event_json)
        except ValidationError as error:
            raise AuditEntryBindingError("event_json must be a valid AuditEntry") from error
        if entry.event_id != event_id:
            raise AuditEntryBindingError("event_id does not match the typed AuditEntry")
        if case_id is None or entry.case_id is None or str(entry.case_id) != case_id:
            raise AuditEntryBindingError("case_id does not match the typed AuditEntry")

        effective_occurred_at = occurred_at or created_at
        effective_persisted_at = persisted_at or created_at
        entry_occurred_at = entry.occurred_at
        if _parse_utc_timestamp(created_at) != entry_occurred_at:
            raise AuditEntryBindingError("created_at does not match AuditEntry.occurred_at")
        if _parse_utc_timestamp(effective_occurred_at) != entry_occurred_at:
            raise AuditEntryBindingError("occurred_at does not match AuditEntry.occurred_at")
        _parse_utc_timestamp(effective_persisted_at)
        if AuditChain.entry_hash(entry) != entry.event_hash:
            raise AuditEntryBindingError("event_hash does not match the typed AuditEntry")

        self._connection.execute("SAVEPOINT append_audit")
        try:
            head = self._connection.execute(
                "SELECT sequence, head_hash FROM audit_heads WHERE case_id = ?",
                (case_id,),
            ).fetchone()
            expected_sequence = 1 if head is None else int(head[0]) + 1
            expected_previous_hash = AUDIT_GENESIS_HASH if head is None else str(head[1])
            if entry.sequence != expected_sequence or entry.previous_hash != expected_previous_hash:
                raise StaleAuditHeadError("audit head changed before this entry could be persisted")

            if head is None:
                cursor = self._connection.execute(
                    """
                    INSERT INTO audit_heads (case_id, sequence, head_hash)
                    VALUES (?, ?, ?)
                    ON CONFLICT (case_id) DO NOTHING
                    """,
                    (case_id, entry.sequence, entry.event_hash),
                )
            else:
                cursor = self._connection.execute(
                    """
                    UPDATE audit_heads
                    SET sequence = ?, head_hash = ?
                    WHERE case_id = ? AND sequence = ? AND head_hash = ?
                    """,
                    (
                        entry.sequence,
                        entry.event_hash,
                        case_id,
                        int(head[0]),
                        str(head[1]),
                    ),
                )
            if cursor.rowcount != 1:
                raise StaleAuditHeadError("audit head changed before this entry could be persisted")

            self._connection.execute(
                """
                INSERT INTO audit_events (
                    event_id,
                    case_id,
                    event_json,
                    created_at,
                    occurred_at,
                    persisted_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.event_id,
                    case_id,
                    entry.model_dump_json(),
                    created_at,
                    effective_occurred_at,
                    effective_persisted_at,
                ),
            )
        except BaseException:
            self._connection.execute("ROLLBACK TO append_audit")
            self._connection.execute("RELEASE append_audit")
            raise
        else:
            self._connection.execute("RELEASE append_audit")

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

    @property
    def path(self) -> Path:
        """Return the database path for internal repositories using this store."""

        return self._path

    @property
    def connection(self) -> sqlite3.Connection:
        """Return the initialized connection to same-thread internal repositories.

        This is an internal repository API, not an application or transport query
        surface. SQLite's default thread ownership checks remain enabled.
        """

        return self._require_connection()

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
            self._apply_migrations(connection)
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

    @contextmanager
    def read_snapshot(self) -> Generator[None]:
        """Keep related reads on one WAL snapshot without blocking writers."""

        connection = self._require_connection()
        owns_snapshot = not connection.in_transaction
        if owns_snapshot:
            connection.execute("BEGIN")
        try:
            yield
        finally:
            if owns_snapshot and connection.in_transaction:
                connection.rollback()

    def create_case(
        self,
        *,
        case_id: str,
        kind: str,
        symptom: str,
        created_at: str,
        status: str = "open",
        state_version: int = 0,
        time_window_start: str | None = None,
        time_window_end: str | None = None,
        time_window_basis: str = "unknown",
    ) -> None:
        self._require_connection().execute(
            """
            INSERT INTO cases (
                case_id, kind, symptom, created_at, status, state_version,
                time_window_start, time_window_end, time_window_basis
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                case_id,
                kind,
                symptom,
                created_at,
                status,
                state_version,
                time_window_start,
                time_window_end,
                time_window_basis,
            ),
        )

    def schema_version(self) -> int:
        row = self._require_connection().execute("PRAGMA user_version").fetchone()
        assert row is not None
        return int(row[0])

    def column_names(self, table: str) -> set[str]:
        if table not in self.table_names():
            raise ValueError(f"unknown table: {table}")
        rows = self._require_connection().execute(f"PRAGMA table_info({table})")
        return {str(row[1]) for row in rows}

    def case_count(self) -> int:
        row = self._require_connection().execute("SELECT COUNT(*) FROM cases").fetchone()
        assert row is not None
        return int(row[0])

    def cases(
        self,
        *,
        created_from: str | None = None,
        created_until: str | None = None,
        kinds: tuple[str, ...] = (),
        limit: int = 100,
        offset: int = 0,
    ) -> tuple[CaseRow, ...]:
        """List a bounded, deterministic case page for internal retrieval policy."""

        if limit < 1 or limit > 500:
            raise ValueError("case limit must be between 1 and 500")
        if offset < 0:
            raise ValueError("case offset must not be negative")
        clauses: list[str] = []
        parameters: list[str | int] = []
        if created_from is not None:
            normalized_from = _parse_utc_timestamp(created_from).isoformat()
            clauses.append("datetime(created_at) >= datetime(?)")
            parameters.append(normalized_from)
        if created_until is not None:
            normalized_until = _parse_utc_timestamp(created_until).isoformat()
            clauses.append("datetime(created_at) <= datetime(?)")
            parameters.append(normalized_until)
        if kinds:
            clauses.append(f"kind IN ({','.join('?' for _ in kinds)})")
            parameters.extend(kinds)
        where = "" if not clauses else f"WHERE {' AND '.join(clauses)}"
        parameters.extend((limit, offset))
        rows = self._require_connection().execute(
            f"""
            SELECT
                case_id,
                kind,
                symptom,
                created_at,
                status,
                state_version,
                time_window_start,
                time_window_end,
                time_window_basis
            FROM cases
            {where}
            ORDER BY datetime(created_at) DESC, case_id
            LIMIT ? OFFSET ?
            """,
            parameters,
        )
        return tuple(self._case_row(row) for row in rows)

    def probe_execution_count(self, *, case_id: str) -> int:
        row = (
            self._require_connection()
            .execute(
                "SELECT COUNT(*) FROM probe_executions WHERE case_id = ?",
                (case_id,),
            )
            .fetchone()
        )
        assert row is not None
        return int(row[0])

    def probe_execution(self, execution_id: str) -> ProbeExecutionRow | None:
        row = (
            self._require_connection()
            .execute(
                """
            SELECT
                execution_id,
                case_id,
                probe_id,
                probe_version,
                status,
                parameters_json,
                started_at,
                finished_at,
                state_version,
                tree_exit_status
            FROM probe_executions
            WHERE execution_id = ?
            """,
                (execution_id,),
            )
            .fetchone()
        )
        if row is None:
            return None
        return ProbeExecutionRow(
            execution_id=str(row[0]),
            case_id=str(row[1]),
            probe_id=str(row[2]),
            probe_version=int(row[3]),
            status=str(row[4]),
            parameters_json=str(row[5]),
            started_at=str(row[6]),
            finished_at=None if row[7] is None else str(row[7]),
            state_version=int(row[8]),
            tree_exit_status=str(row[9]),
        )

    def coverage_count(self, *, case_id: str) -> int:
        row = (
            self._require_connection()
            .execute(
                """
                SELECT COUNT(*)
                FROM evidence
                WHERE case_id = ?
                  AND json_type(record_json, '$.status') IS NOT NULL
                  AND json_type(record_json, '$.category') IS NOT NULL
                """,
                (case_id,),
            )
            .fetchone()
        )
        assert row is not None
        return int(row[0])

    def raw_evidence_bytes(self) -> int:
        row = (
            self._require_connection()
            .execute(
                """
                SELECT COALESCE(SUM(length(CAST(record_json AS BLOB))), 0)
                FROM evidence
                WHERE json_type(record_json, '$.status') IS NULL
                """
            )
            .fetchone()
        )
        assert row is not None
        return int(row[0])

    def delete_expired_raw_evidence(
        self,
        *,
        captured_before: str,
        limit: int,
    ) -> int:
        self._validate_retention_limit(limit)
        cursor = self._require_connection().execute(
            """
            DELETE FROM evidence
            WHERE evidence_id IN (
                SELECT evidence_id
                FROM evidence
                WHERE captured_at < ?
                  AND json_type(record_json, '$.status') IS NULL
                ORDER BY captured_at, evidence_id
                LIMIT ?
            )
            """,
            (captured_before, limit),
        )
        return cursor.rowcount

    def delete_oldest_raw_evidence(self, *, limit: int) -> int:
        self._validate_retention_limit(limit)
        cursor = self._require_connection().execute(
            """
            DELETE FROM evidence
            WHERE evidence_id IN (
                SELECT evidence_id
                FROM evidence
                WHERE json_type(record_json, '$.status') IS NULL
                ORDER BY captured_at, evidence_id
                LIMIT ?
            )
            """,
            (limit,),
        )
        return cursor.rowcount

    def case(self, case_id: str) -> CaseRow | None:
        row = (
            self._require_connection()
            .execute(
                """
                SELECT
                    case_id,
                    kind,
                    symptom,
                    created_at,
                    status,
                    state_version,
                    time_window_start,
                    time_window_end,
                    time_window_basis
                FROM cases
                WHERE case_id = ?
                """,
                (case_id,),
            )
            .fetchone()
        )
        if row is None:
            return None
        return self._case_row(row)

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
                SELECT
                    evidence_id,
                    case_id,
                    record_json,
                    observed_at,
                    captured_at,
                    execution_id,
                    dedupe_key,
                    time_basis,
                    time_quality
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
            SELECT
                evidence_id,
                case_id,
                record_json,
                observed_at,
                captured_at,
                execution_id,
                dedupe_key,
                time_basis,
                time_quality
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
            SELECT
                evidence_id,
                case_id,
                record_json,
                observed_at,
                captured_at,
                execution_id,
                dedupe_key,
                time_basis,
                time_quality
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

    def audit_count(self, *, case_id: str) -> int:
        row = (
            self._require_connection()
            .execute(
                "SELECT COUNT(*) FROM audit_events WHERE case_id = ?",
                (case_id,),
            )
            .fetchone()
        )
        assert row is not None
        return int(row[0])

    def audit_entries(
        self,
        *,
        case_id: str,
        limit: int = 1000,
        offset: int = 0,
    ) -> tuple[AuditEntry, ...]:
        """Read a bounded page of a case chain in stable persisted sequence order.

        The database sequence controls read order; the embedded AuditEntry sequence and
        hashes are verified by ``AuditChain`` with a caller-held checkpoint.
        """
        self._validate_retention_limit(limit)
        if offset < 0:
            raise ValueError("audit offset must not be negative")
        rows = self._require_connection().execute(
            """
            SELECT event_json
            FROM audit_events
            WHERE case_id = ?
            ORDER BY sequence
            LIMIT ? OFFSET ?
            """,
            (case_id, limit, offset),
        )
        return tuple(AuditEntry.model_validate_json(str(row[0])) for row in rows)

    def audit_checkpoint(self, *, case_id: str) -> AuditCheckpoint:
        """Return the durable head used for transactional append validation.

        This checkpoint shares the database trust boundary with the events. It
        prevents stale writers from forking a live chain, but does not provide
        forensic integrity against whole-database replacement or coordinated edits.
        """
        row = (
            self._require_connection()
            .execute(
                "SELECT sequence, head_hash FROM audit_heads WHERE case_id = ?",
                (case_id,),
            )
            .fetchone()
        )
        if row is None:
            return AuditCheckpoint(entry_count=0, head_hash=AUDIT_GENESIS_HASH)
        return AuditCheckpoint(entry_count=int(row[0]), head_hash=str(row[1]))

    def inventory_categories(self) -> set[str]:
        rows = self._require_connection().execute("SELECT DISTINCT category FROM inventory_current")
        return {str(row[0]) for row in rows}

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

    def inventory_page(
        self,
        *,
        category: str | None = None,
        limit: int = 100,
    ) -> tuple[InventoryRow, ...]:
        if limit < 1 or limit > 500:
            raise ValueError("limit must be between 1 and 500")
        if category is None:
            rows = self._require_connection().execute(
                """
                SELECT category, fact_key, record_json, observed_at
                FROM inventory_current
                ORDER BY category, fact_key
                LIMIT ?
                """,
                (limit,),
            )
        else:
            rows = self._require_connection().execute(
                """
                SELECT category, fact_key, record_json, observed_at
                FROM inventory_current
                WHERE category = ?
                ORDER BY fact_key
                LIMIT ?
                """,
                (category, limit),
            )
        return tuple(
            InventoryRow(
                category=str(row[0]),
                fact_key=str(row[1]),
                record_json=str(row[2]),
                observed_at=str(row[3]),
            )
            for row in rows
        )

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

    def artifact_count(self) -> int:
        row = self._require_connection().execute("SELECT COUNT(*) FROM artifacts").fetchone()
        assert row is not None
        return int(row[0])

    def artifact_total_bytes(self) -> int:
        row = (
            self._require_connection()
            .execute("SELECT COALESCE(SUM(byte_size), 0) FROM artifacts")
            .fetchone()
        )
        assert row is not None
        return int(row[0])

    def unreferenced_artifacts(self, *, limit: int) -> tuple[ArtifactRow, ...]:
        self._validate_retention_limit(limit)
        rows = self._require_connection().execute(
            """
            SELECT
                artifacts.artifact_id,
                artifacts.sha256,
                artifacts.byte_size,
                artifacts.media_type,
                artifacts.sensitivity,
                artifacts.created_at
            FROM artifacts
            LEFT JOIN artifact_cases USING (artifact_id)
            WHERE artifact_cases.artifact_id IS NULL
            ORDER BY artifacts.created_at, artifacts.artifact_id
            LIMIT ?
            """,
            (limit,),
        )
        return tuple(
            ArtifactRow(
                artifact_id=str(row[0]),
                sha256=str(row[1]),
                byte_size=int(row[2]),
                media_type=str(row[3]),
                sensitivity=str(row[4]),
                created_at=str(row[5]),
            )
            for row in rows
        )

    def delete_unreferenced_artifact(self, *, artifact_id: str) -> bool:
        cursor = self._require_connection().execute(
            """
            DELETE FROM artifacts
            WHERE artifact_id = ?
              AND NOT EXISTS (
                  SELECT 1
                  FROM artifact_cases
                  WHERE artifact_cases.artifact_id = artifacts.artifact_id
              )
            """,
            (artifact_id,),
        )
        return cursor.rowcount == 1

    def has_artifact_sha(self, sha256: str) -> bool:
        row = (
            self._require_connection()
            .execute(
                "SELECT 1 FROM artifacts WHERE sha256 = ?",
                (sha256,),
            )
            .fetchone()
        )
        return row is not None

    @staticmethod
    def _case_row(row: sqlite3.Row | tuple[object, ...]) -> CaseRow:
        return CaseRow(
            case_id=str(row[0]),
            kind=str(row[1]),
            symptom=str(row[2]),
            created_at=str(row[3]),
            status=str(row[4]),
            state_version=int(cast("int | str", row[5])),
            time_window_start=None if row[6] is None else str(row[6]),
            time_window_end=None if row[7] is None else str(row[7]),
            time_window_basis=str(row[8]),
        )

    @staticmethod
    def _evidence_row(row: sqlite3.Row | tuple[object, ...]) -> EvidenceRow:
        return EvidenceRow(
            evidence_id=str(row[0]),
            case_id=str(row[1]),
            record_json=str(row[2]),
            observed_at=str(row[3]),
            captured_at=str(row[4]),
            execution_id=None if row[5] is None else str(row[5]),
            dedupe_key=str(row[6]),
            time_basis=str(row[7]),
            time_quality=str(row[8]),
        )

    @staticmethod
    def _apply_migrations(connection: sqlite3.Connection) -> None:
        migrations = Path(__file__).with_name("migrations")
        connection.create_function(
            "systemsense_audit_event_hash",
            6,
            _validated_audit_event_hash,
            deterministic=True,
        )
        row = connection.execute("PRAGMA user_version").fetchone()
        current_version = 0 if row is None else int(row[0])
        migration_paths = sorted(migrations.glob("[0-9][0-9][0-9]_*.sql"))
        supported_version = max(
            (int(path.name.split("_", 1)[0]) for path in migration_paths),
            default=0,
        )
        if current_version > supported_version:
            raise sqlite3.DatabaseError(
                f"database schema version {current_version} is newer than supported "
                f"version {supported_version}"
            )
        for migration_path in migration_paths:
            version = int(migration_path.name.split("_", 1)[0])
            if version <= current_version:
                continue
            script = migration_path.read_text(encoding="utf-8")
            if version == 5:
                SQLiteStore._apply_probe_execution_state_version_migration(
                    connection,
                    script=script,
                )
                current_version = version
                continue
            if version == 23:
                SQLiteStore._apply_frontier_snapshot_migration(connection, script=script)
                current_version = version
                continue
            try:
                connection.executescript(f"BEGIN IMMEDIATE;\n{script}\nCOMMIT;")
            except BaseException:
                if connection.in_transaction:
                    connection.rollback()
                raise
            current_version = version

    @staticmethod
    def _apply_frontier_snapshot_migration(connection: sqlite3.Connection, *, script: str) -> None:
        """Rebuild one FK parent atomically, retaining its historical children."""

        if connection.in_transaction:
            raise sqlite3.DatabaseError("frontier snapshot migration requires no transaction")
        connection.execute("PRAGMA foreign_keys = OFF")
        try:
            connection.execute("BEGIN IMMEDIATE")
            statement = ""
            for line in script.splitlines(keepends=True):
                statement += line
                if sqlite3.complete_statement(statement):
                    connection.execute(statement)
                    statement = ""
            if statement.strip():
                raise sqlite3.DatabaseError("frontier snapshot migration has incomplete SQL")
            if connection.execute("PRAGMA foreign_key_check").fetchone() is not None:
                raise sqlite3.DatabaseError("frontier snapshot migration broke a foreign key")
            if connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
                raise sqlite3.DatabaseError("frontier snapshot migration failed integrity check")
            connection.execute("PRAGMA user_version = 23")
            connection.commit()
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise
        finally:
            connection.execute("PRAGMA foreign_keys = ON")

    @staticmethod
    def _apply_probe_execution_state_version_migration(
        connection: sqlite3.Connection,
        *,
        script: str,
    ) -> None:
        executable = "".join(
            line for line in script.splitlines() if not line.lstrip().startswith("--")
        )
        if "".join(executable.casefold().split()) != "pragmauser_version=5;":
            raise sqlite3.DatabaseError("migration 005 contains unexpected SQL")
        connection.execute("BEGIN IMMEDIATE")
        try:
            columns = connection.execute("PRAGMA table_info(probe_executions)").fetchall()
            if not columns:
                raise sqlite3.DatabaseError("probe_executions table is unavailable")
            state_columns = [row for row in columns if str(row[1]) == "state_version"]
            if not state_columns:
                connection.execute(
                    "ALTER TABLE probe_executions ADD COLUMN state_version "
                    "INTEGER NOT NULL DEFAULT 0 CHECK (state_version >= 0)"
                )
                columns = connection.execute("PRAGMA table_info(probe_executions)").fetchall()
                state_columns = [row for row in columns if str(row[1]) == "state_version"]
            if len(state_columns) != 1:
                raise sqlite3.DatabaseError(
                    "probe_executions.state_version has an unexpected definition"
                )
            column = state_columns[0]
            table_row = connection.execute(
                "SELECT sql FROM sqlite_schema WHERE type = 'table' AND name = 'probe_executions'"
            ).fetchone()
            table_sql = "" if table_row is None or table_row[0] is None else str(table_row[0])
            compact_sql = "".join(table_sql.casefold().split())
            expected_constraint = "state_versionintegernotnulldefault0check(state_version>=0)"
            if (
                str(column[2]).upper() != "INTEGER"
                or int(column[3]) != 1
                or str(column[4]) != "0"
                or int(column[5]) != 0
                or expected_constraint not in compact_sql
            ):
                raise sqlite3.DatabaseError(
                    "probe_executions.state_version has an unexpected definition"
                )
            connection.execute("PRAGMA user_version = 5")
            connection.commit()
        except BaseException:
            if connection.in_transaction:
                connection.rollback()
            raise

    @staticmethod
    def _validate_retention_limit(limit: int) -> None:
        if limit < 1 or limit > 1000:
            raise ValueError("retention limit must be between 1 and 1000")

    def _require_connection(self) -> sqlite3.Connection:
        if self._connection is None:
            raise RuntimeError("store is not initialized")
        return self._connection


def _parse_utc_timestamp(value: str) -> datetime:
    """Parse an aware ISO timestamp and normalize it for instant comparisons."""
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError) as error:
        raise ValueError("timestamp must be a timezone-aware ISO timestamp") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp must be a timezone-aware ISO timestamp")
    return parsed.astimezone(UTC)


def _validated_audit_event_hash(
    event_json: object,
    event_id: object,
    case_id: object,
    created_at: object,
    occurred_at: object,
    persisted_at: object,
) -> str | None:
    """Validate a legacy row before migration trusts it as a chain head."""
    if not all(
        isinstance(value, str)
        for value in (
            event_json,
            event_id,
            case_id,
            created_at,
            occurred_at,
            persisted_at,
        )
    ):
        return None
    assert isinstance(event_json, str)
    assert isinstance(event_id, str)
    assert isinstance(case_id, str)
    assert isinstance(created_at, str)
    assert isinstance(occurred_at, str)
    assert isinstance(persisted_at, str)
    try:
        entry = AuditEntry.model_validate_json(event_json)
        if entry.case_id is None:
            return None
        if entry.event_id != event_id or str(entry.case_id) != case_id:
            return None
        if _parse_utc_timestamp(created_at) != entry.occurred_at:
            return None
        if _parse_utc_timestamp(occurred_at) != entry.occurred_at:
            return None
        _parse_utc_timestamp(persisted_at)
    except (ValidationError, ValueError, TypeError):
        return None
    expected_hash = AuditChain.entry_hash(entry)
    return entry.event_hash if entry.event_hash == expected_hash else None
