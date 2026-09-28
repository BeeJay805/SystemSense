"""Resolve an explicitly bound task record for advisory input.

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
from systemsense.domain.ids import CaseId, stable_source_id
from systemsense.domain.time import ensure_utc
from systemsense.storage.investigations import InvestigationRepository
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
_LOOPBACK_PROBE_ID = "task.loopback_http"
_LOOPBACK_FACT_PATHS = (
    "target_handle",
    "action",
    "expected",
    "outcome",
    "request_started_at_utc",
    "request_finished_at_utc",
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
    """Validate one known producer and its exact persisted execution and record."""

    paths = reference.fact_paths
    expected_probe, expected_paths = (
        (_LOOPBACK_PROBE_ID, _LOOPBACK_FACT_PATHS)
        if reference.scope == "test_owned_loopback"
        else (_FIXTURE_PROBE_ID, _FIXTURE_FACT_PATHS)
    )
    if (
        reference.case_id != case_id
        or reference.collector_id != expected_probe
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
        != expected_paths
    ):
        raise TaskObservationUnavailable(
            "task observation producer is not the registered fixture contract"
            if reference.scope == "synthetic_fixture"
            else "task observation producer is not the registered loopback contract"
        )
    row = store.evidence(case_id=str(case_id), evidence_id=str(reference.evidence_id))
    if row is None or row.execution_id != str(reference.execution_id):
        raise TaskObservationUnavailable("task observation source record is unavailable")
    duplicates = store.connection.execute(
        "SELECT COUNT(*) FROM evidence WHERE case_id=? AND "
        "json_extract(record_json, '$.collector.id')=?",
        (str(case_id), expected_probe),
    ).fetchone()
    if duplicates is None or int(duplicates[0]) != 1:
        raise TaskObservationUnavailable("task observation source is not unique")
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
    duration_error = abs((end - start).total_seconds() * 1000 - window_ms)
    if (
        duration_error > 1
        if reference.scope == "test_owned_loopback"
        else end - start != timedelta(milliseconds=window_ms)
    ) or end != record.observed_at:
        raise TaskObservationUnavailable("task observation duration conflicts with its UTC window")
    if reference.scope == "test_owned_loopback":
        try:
            parameters = json.loads(execution.parameters_json)
            port = parameters["port"]
            nonce = parameters["nonce"]
            timeout_seconds = parameters["timeout_seconds"]
            execution_start = ensure_utc(datetime.fromisoformat(execution.started_at))
            execution_end = ensure_utc(datetime.fromisoformat(execution.finished_at))
        except (KeyError, TypeError, ValueError) as error:
            raise TaskObservationUnavailable("loopback execution custody is invalid") from error
        if (
            not isinstance(port, int)
            or isinstance(port, bool)
            or not 49152 <= port <= 65535
            or not isinstance(nonce, str)
            or len(nonce) != 32
            or any(character not in "0123456789abcdef" for character in nonce)
            or not isinstance(timeout_seconds, (int, float))
            or not 0.1 <= timeout_seconds <= 2.0
            or execution_start != start
            or execution_end != end
        ):
            raise TaskObservationUnavailable("loopback execution custody is invalid")
        path = f"/health/{nonce}"
        if (
            target_handle != f"127.0.0.1:{port}"
            or action != f"GET {path}"
            or expected != "HTTP 200 with matching nonce"
            or observed
            not in {
                "http_200_nonce_match",
                "wrong_response",
                "http_503",
                "http_other_status",
                "connection_refused",
                "timeout",
                "request_error",
            }
            or record.source.locator
            != {
                "probe_id": _LOOPBACK_PROBE_ID,
                "target_handle": target_handle,
                "path": path,
            }
            or record.source.source_id
            != stable_source_id(
                "systemsense.probe",
                {"case_id": str(case_id), "target": target_handle, "path": path},
            )
            or (observed == "http_200_nonce_match")
            != (facts.get("http_status") == 200 and facts.get("nonce_match") is True)
            or (observed == "http_503") != (facts.get("http_status") == 503)
            or (
                observed in {"connection_refused", "timeout", "request_error"}
                and (facts.get("http_status") is not None or facts.get("nonce_match") is not None)
            )
            or (observed == "connection_refused")
            != (facts.get("error_type") == "ConnectionRefusedError")
            or (observed == "timeout") != (facts.get("error_type") == "TimeoutError")
        ):
            raise TaskObservationUnavailable("loopback task facts do not bind the execution")
        state = InvestigationRepository(store).load(str(case_id))
        if state.reported_task is not None:
            if (
                state.reported_task.target_hint != target_handle
                or state.reported_task_action_sha256
                != hashlib.sha256(f"GET http://{target_handle}{path}".encode()).hexdigest()
            ):
                raise TaskObservationUnavailable(
                    "loopback task does not replay the reported exact action"
                )
            reported_task_relation = "exact_action_replayed"
        else:
            reported_task_relation = "unbound"
        limitation_phrase = "test-owned loopback fixture"
    else:
        limitation_phrase = "synthetic fixture"
        reported_task_relation = "unbound"
    limitation = next(
        (
            item
            for item in record.limitations
            if limitation_phrase in item.casefold()
            and (reference.scope != "synthetic_fixture" or "no windows" in item.casefold())
        ),
        None,
    )
    if limitation is None:
        raise TaskObservationUnavailable("task source lacks its explicit scope limitation")
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
        scope=reference.scope,
        reported_task_relation=reported_task_relation,
    )
    if len(json.dumps(context.model_visible(), ensure_ascii=False).encode("utf-8")) > 1200:
        raise TaskObservationUnavailable("task observation exceeds the bounded model context")
    return context
