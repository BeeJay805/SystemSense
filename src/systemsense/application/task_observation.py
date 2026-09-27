"""Resolve an explicitly bound synthetic task record for advisory input.

This fixture-scoped reference is never a user-task verifier or a model-granted
target. The owner rereads the immutable record and its actual probe execution.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timedelta

from systemsense.domain.affected_task import (
    TaskObservationContextV1,
    TaskObservationReferenceV1,
)
from systemsense.domain.evidence import EvidenceRecord, StatementKind
from systemsense.domain.ids import CaseId
from systemsense.domain.time import ensure_utc
from systemsense.storage.sqlite_store import SQLiteStore


class TaskObservationUnavailable(ValueError):
    """The stored task binding failed custody or completeness checks."""


_FIXTURE_PROBE_ID = "fixture.task_baseline"
_FIXTURE_FACT_PATHS = (
    "target_handle",
    "action",
    "expected",
    "observed",
    "synthetic_window_start_utc",
    "synthetic_window_end_utc",
    "sample_window_ms",
)


def resolve_task_observation(
    store: SQLiteStore, *, case_id: CaseId, reference: TaskObservationReferenceV1
) -> TaskObservationContextV1:
    """Return complete source-bound fixture facts or reject the entire binding."""

    try:
        return _resolve_task_observation(store, case_id=case_id, reference=reference)
    except TaskObservationUnavailable:
        raise
    except (TypeError, ValueError) as error:
        raise TaskObservationUnavailable("task observation source is invalid") from error


def _resolve_task_observation(
    store: SQLiteStore, *, case_id: CaseId, reference: TaskObservationReferenceV1
) -> TaskObservationContextV1:
    """Validate the one known synthetic producer and exact persisted record."""

    paths = reference.fact_paths
    if (
        reference.case_id != case_id
        or reference.collector_id != _FIXTURE_PROBE_ID
        or reference.collector_version != 1
        or (
            paths.target_handle,
            paths.action,
            paths.expected,
            paths.observed,
            paths.window_start,
            paths.window_end,
            paths.window_ms,
        )
        != _FIXTURE_FACT_PATHS
    ):
        raise TaskObservationUnavailable(
            "task observation producer is not the registered fixture contract"
        )
    row = store.evidence(case_id=str(case_id), evidence_id=str(reference.evidence_id))
    if row is None or row.execution_id != str(reference.execution_id):
        raise TaskObservationUnavailable("task observation source record is unavailable")
    duplicates = store.connection.execute(
        "SELECT COUNT(*) FROM evidence WHERE case_id=? AND "
        "json_extract(record_json, '$.collector.id')=?",
        (str(case_id), _FIXTURE_PROBE_ID),
    ).fetchone()
    if duplicates is None or int(duplicates[0]) != 1:
        raise TaskObservationUnavailable("task observation fixture source is not unique")
    record_sha = hashlib.sha256(row.record_json.encode("utf-8")).hexdigest()
    if record_sha != reference.record_sha256:
        raise TaskObservationUnavailable("task observation source record changed")
    record = EvidenceRecord.model_validate_json(row.record_json)
    execution = store.probe_execution(str(reference.execution_id))
    if (
        record.case_id != case_id
        or record.evidence_id != reference.evidence_id
        or record.statement_kind is not StatementKind.OBSERVED_FACT
        or record.source.type != "systemsense.probe"
        or record.source.source_id != reference.source_id
        or record.collector.id != reference.collector_id
        or record.collector.version != reference.collector_version
        or record.collector.execution_id != reference.execution_id
        or row.time_basis != "collector_observed"
        or row.time_quality != "exact"
        or row.observed_at != record.observed_at.isoformat()
        or row.captured_at != record.captured_at.isoformat()
        or execution is None
        or execution.case_id != str(case_id)
        or execution.probe_id != reference.collector_id
        or execution.probe_version != reference.collector_version
        or execution.status != "ok"
        or execution.finished_at is None
    ):
        raise TaskObservationUnavailable("task observation record/probe custody does not match")
    facts = {fact.name: fact.value for fact in record.facts}
    if len(facts) != len(record.facts):
        raise TaskObservationUnavailable("task observation has duplicate fact names")

    def exact_text(path: str) -> str:
        value = facts.get(path)
        if not isinstance(value, str) or not value or "<redacted" in value.casefold():
            raise TaskObservationUnavailable(
                "task observation has a missing or redacted required value"
            )
        return value

    target_handle = exact_text(paths.target_handle)
    action = exact_text(paths.action)
    expected = exact_text(paths.expected)
    observed = exact_text(paths.observed)
    start_text = exact_text(paths.window_start)
    end_text = exact_text(paths.window_end)
    window_ms = facts.get(paths.window_ms)
    if (
        not isinstance(window_ms, int)
        or isinstance(window_ms, bool)
        or not 1 <= window_ms <= 600_000
    ):
        raise TaskObservationUnavailable("task observation duration is invalid")
    try:
        start = ensure_utc(datetime.fromisoformat(start_text))
        end = ensure_utc(datetime.fromisoformat(end_text))
    except (TypeError, ValueError) as error:
        raise TaskObservationUnavailable("task observation window is invalid") from error
    if end - start != timedelta(milliseconds=window_ms) or end != record.observed_at:
        raise TaskObservationUnavailable("task observation duration conflicts with its UTC window")
    limitation = next(
        (
            item
            for item in record.limitations
            if "synthetic fixture" in item.casefold() and "no windows" in item.casefold()
        ),
        None,
    )
    if limitation is None:
        raise TaskObservationUnavailable(
            "synthetic task source lacks an explicit no-Windows limitation"
        )
    context = TaskObservationContextV1(
        case_id=case_id,
        evidence_id=record.evidence_id,
        source_id=record.source.source_id,
        collector_id=record.collector.id,
        collector_version=record.collector.version,
        execution_id=record.collector.execution_id,
        record_sha256=record_sha,
        target_handle=target_handle,
        action=action,
        expected=expected,
        observed=observed,
        window_start=start,
        window_end=end,
        sample_window_ms=window_ms,
        observed_at=record.observed_at,
        captured_at=record.captured_at,
        limitation=limitation,
    )
    if len(json.dumps(context.model_visible(), ensure_ascii=False).encode("utf-8")) > 1200:
        raise TaskObservationUnavailable("task observation exceeds the bounded model context")
    return context
