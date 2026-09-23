"""Durable, case-scoped coordinator event projection for benchmark capture."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Literal, cast

if TYPE_CHECKING:
    from systemsense.storage.sqlite_store import SQLiteStore

TraceKind = Literal["probe", "provider", "evidence", "coverage", "terminal"]
_KINDS = frozenset({"probe", "provider", "evidence", "coverage", "terminal"})
_FIELDS: dict[str, frozenset[str]] = {
    "probe": frozenset({"probe_id", "status"}),
    "provider": frozenset({"role", "attempted_provider_id", "effective_provider_id", "failed"}),
    "evidence": frozenset(),
    "coverage": frozenset(),
    "terminal": frozenset({"status", "outcome"}),
}
_MAX_EXPORT_EVENTS = 512


def append_coordinator_event(
    connection: sqlite3.Connection,
    *,
    case_id: str,
    kind: TraceKind,
    fields: dict[str, str | bool | None],
    source_record_id: str | None = None,
    source_observed_at: str | None = None,
) -> None:
    """Append one event inside the caller's existing SQLite transaction."""

    if kind not in _KINDS:
        raise ValueError("unsupported coordinator event kind")
    if frozenset(fields) != _FIELDS[kind] or any(
        isinstance(value, str) and len(value) > 120 for value in fields.values()
    ):
        raise ValueError("coordinator event fields are invalid")
    if (kind == "provider") != (source_record_id is None):
        raise ValueError("coordinator event source binding is invalid")
    if kind == "provider":
        if (
            fields["role"] not in {"decision", "catalog_attention", "reasoning"}
            or type(fields["failed"]) is not bool
            or not isinstance(fields["attempted_provider_id"], str)
            or not isinstance(fields["effective_provider_id"], str)
        ):
            raise ValueError("coordinator provider fields are invalid")
    elif any(not isinstance(value, str) or not value for value in fields.values()):
        raise ValueError("coordinator event fields are invalid")
    row = connection.execute(
        "SELECT sequence, persisted_at FROM coordinator_events "
        "WHERE case_id = ? ORDER BY sequence DESC LIMIT 1",
        (case_id,),
    ).fetchone()
    sequence = 1 if row is None else int(row[0]) + 1
    now = datetime.now(UTC)
    if row is not None:
        previous = datetime.fromisoformat(str(row[1]))
        if previous > now:
            now = previous
    stamp = now.isoformat()
    event_id = f"trace_{sequence:06d}"
    event = {
        "kind": kind,
        "event_id": event_id,
        "observed_at": stamp,
        **fields,
    }
    encoded = json.dumps(event, sort_keys=True, separators=(",", ":"))
    if len(encoded.encode("utf-8")) > 2048:
        raise ValueError("coordinator event is too large")
    connection.execute(
        "INSERT INTO coordinator_events "
        "(case_id, sequence, schema_version, event_id, kind, event_json, "
        "source_record_id, source_observed_at, persisted_at) "
        "VALUES (?, ?, 1, ?, ?, ?, ?, ?, ?)",
        (
            case_id,
            sequence,
            event_id,
            kind,
            encoded,
            source_record_id,
            source_observed_at,
            stamp,
        ),
    )


def export_coordinator_event_log(store: SQLiteStore, case_id: str) -> dict[str, object]:
    """Read only committed events; reject partial, ambiguous or oversized runs."""

    with store.read_snapshot():
        if store.case(case_id) is None:
            raise ValueError("case is unavailable")
        rows = store.connection.execute(
            "SELECT sequence, event_id, kind, event_json, source_record_id, "
            "source_observed_at, persisted_at "
            "FROM coordinator_events WHERE case_id = ? ORDER BY sequence LIMIT ?",
            (case_id, _MAX_EXPORT_EVENTS + 1),
        ).fetchall()
        if not rows or len(rows) > _MAX_EXPORT_EVENTS:
            raise ValueError("coordinator trace is missing or exceeds export limit")
        events: list[dict[str, object]] = []
        previous_stamp: datetime | None = None
        for expected_sequence, row in enumerate(rows, start=1):
            sequence, event_id, kind, raw, source_id, source_observed_at, persisted_at = row
            loaded: object = json.loads(str(raw))
            if not isinstance(loaded, dict):
                raise ValueError("coordinator trace event is not an object")
            event = cast(dict[str, object], loaded)
            if (
                int(sequence) != expected_sequence
                or str(kind) not in _KINDS
                or event.get("kind") != kind
                or event.get("event_id") != event_id
                or event.get("observed_at") != persisted_at
            ):
                raise ValueError("coordinator trace row is inconsistent")
            stamp = datetime.fromisoformat(str(persisted_at))
            if stamp.utcoffset() != datetime.now(UTC).utcoffset():
                raise ValueError("coordinator trace receipt time is not UTC")
            if previous_stamp is not None and stamp < previous_stamp:
                raise ValueError("coordinator trace receipt times are out of order")
            previous_stamp = stamp
            if source_observed_at is not None:
                source_stamp = datetime.fromisoformat(str(source_observed_at))
                if source_stamp.utcoffset() != stamp.utcoffset():
                    raise ValueError("coordinator trace source time is not UTC")
            if kind == "probe":
                linked = store.connection.execute(
                    "SELECT probe_id, status, finished_at FROM probe_executions "
                    "WHERE case_id = ? AND execution_id = ?",
                    (case_id, source_id),
                ).fetchone()
                if linked is None or tuple(linked) != (
                    event.get("probe_id"),
                    event.get("status"),
                    source_observed_at,
                ):
                    raise ValueError("coordinator probe event lost source binding")
            elif kind in {"evidence", "coverage"}:
                linked = store.connection.execute(
                    "SELECT observed_at, record_json FROM evidence "
                    "WHERE case_id = ? AND evidence_id = ?",
                    (case_id, source_id),
                ).fetchone()
                if linked is None or str(linked[0]) != source_observed_at:
                    raise ValueError("coordinator evidence event lost source binding")
                record: object = json.loads(str(linked[1]))
                is_coverage = (
                    isinstance(record, dict) and "status" in record and "category" in record
                )
                if (kind == "coverage") != is_coverage:
                    raise ValueError("coordinator evidence kind differs from source")
            elif kind == "terminal":
                linked = store.connection.execute(
                    "SELECT record_json FROM investigation_steps "
                    "WHERE case_id = ? AND state_version = ?",
                    (case_id, source_id),
                ).fetchone()
                if linked is None:
                    raise ValueError("coordinator terminal lost checkpoint step")
                step: object = json.loads(str(linked[0]))
                if not isinstance(step, dict):
                    raise ValueError("coordinator terminal step is invalid")
                typed_step = cast(dict[str, object], step)
                occurred_at = typed_step.get("occurred_at")
                if (
                    not isinstance(occurred_at, str)
                    or source_observed_at is None
                    or datetime.fromisoformat(occurred_at)
                    != datetime.fromisoformat(str(source_observed_at))
                ):
                    raise ValueError("coordinator terminal step time differs")
            events.append(event)
        if (
            sum(event["kind"] == "terminal" for event in events) != 1
            or events[-1]["kind"] != "terminal"
        ):
            raise ValueError("coordinator trace lacks a unique final terminal event")
        checkpoint = store.connection.execute(
            "SELECT record_json FROM investigation_checkpoints WHERE case_id = ?", (case_id,)
        ).fetchone()
        if checkpoint is None:
            raise ValueError("coordinator trace checkpoint is missing")
        state: object = json.loads(str(checkpoint[0]))
        if not isinstance(state, dict):
            raise ValueError("coordinator terminal checkpoint is invalid")
        typed_state = cast(dict[str, object], state)
        if typed_state.get("status") != events[-1].get("status") or typed_state.get(
            "outcome"
        ) != events[-1].get("outcome"):
            raise ValueError("coordinator terminal differs from current checkpoint")
        result: dict[str, object] = {"schema_version": 1, "case_id": case_id, "events": events}
        if len(json.dumps(result, separators=(",", ":")).encode("utf-8")) > 48 * 1024:
            raise ValueError("coordinator trace exceeds capture budget")
        return result
