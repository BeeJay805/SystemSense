"""Custody-synthetic SQLite fixtures, not host or actual-worker evidence.

No network request, model call, hidden case, or injected host fault is involved.
These tests exercise the durable verifier with inconsistent execution receipts.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from systemsense.application.bootstrap import default_investigator
from systemsense.application.loopback_replay_evidence import verified_replay
from systemsense.domain.affected_task import TaskObservationContextV1
from systemsense.domain.evidence import (
    CollectorReference,
    EvidenceFact,
    EvidenceRecord,
    EvidenceSource,
    Extraction,
    Sensitivity,
    StatementKind,
)
from systemsense.domain.ids import EvidenceId, ExecutionId, stable_source_id
from systemsense.storage.sqlite_store import SQLiteStore

NOW = datetime(2026, 9, 29, tzinfo=UTC)
NONCE = "a" * 32


def _persist(store: SQLiteStore) -> tuple[TaskObservationContextV1, EvidenceRecord]:
    state = default_investigator(store).create(objective="Custody-synthetic replay review")
    task = TaskObservationContextV1(
        case_id=state.case_id,
        evidence_id=EvidenceId.new(),
        source_id=stable_source_id("systemsense.probe", {"probe_id": "task.loopback_http"}),
        collector_id="task.loopback_http",
        collector_version=1,
        execution_id=ExecutionId.new(),
        record_sha256="a" * 64,
        target_handle="127.0.0.1:59152",
        action=f"GET /health/{NONCE}",
        expected="HTTP 200 with matching nonce",
        observed="timeout",
        window_start=NOW,
        window_end=NOW + timedelta(seconds=1),
        sample_window_ms=1000,
        observed_at=NOW + timedelta(seconds=1),
        captured_at=NOW + timedelta(seconds=1),
        limitation="Synthetic custody fixture, not a host observation.",
        scope="test_owned_loopback",
        reported_task_relation="exact_action_replayed",
    )
    probe_id = "network.loopback_replay"
    record = EvidenceRecord(
        evidence_id=EvidenceId.new(),
        case_id=state.case_id,
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=NOW + timedelta(seconds=4),
        captured_at=NOW + timedelta(seconds=4),
        source=EvidenceSource(
            type="systemsense.probe",
            source_id=stable_source_id(
                "systemsense.probe", {"probe_id": probe_id, "probe_version": 1}
            ),
            locator={"probe_id": probe_id},
        ),
        collector=CollectorReference(id=probe_id, version=1, execution_id=ExecutionId.new()),
        summary="Synthetic replay recovered.",
        facts=(
            EvidenceFact(
                name="loopback_replay",
                value={
                    "target_handle": task.target_handle,
                    "action": task.action,
                    "outcome": "http_200_nonce_match",
                    "http_status": 200,
                    "nonce_match": True,
                    "request_started_at": (NOW + timedelta(seconds=2)).isoformat(),
                    "request_finished_at": (NOW + timedelta(seconds=3)).isoformat(),
                },
            ),
        ),
        extraction=Extraction(confidence=1.0, parser="builtin.probe", parser_version=1),
        sensitivity=Sensitivity.SYSTEM_METADATA,
    )
    with store.transaction() as transaction:
        transaction.record_probe_execution(
            execution_id=str(record.collector.execution_id),
            case_id=str(state.case_id),
            probe_id=probe_id,
            probe_version=1,
            status="ok",
            parameters_json=json.dumps({"port": 59152, "nonce": NONCE}),
            started_at=(NOW + timedelta(seconds=1.5)).isoformat(),
            finished_at=(NOW + timedelta(seconds=5)).isoformat(),
            state_version=state.state_version,
        )
        transaction.insert_evidence(
            case_id=str(state.case_id),
            evidence_id=str(record.evidence_id),
            source_id=record.source.source_id,
            record_json=record.model_dump_json(),
            observed_at=record.observed_at.isoformat(),
            captured_at=record.captured_at.isoformat(),
            execution_id=str(record.collector.execution_id),
            dedupe_key=f"execution:{record.collector.execution_id}",
            time_basis="collector_upper_bound",
            time_quality="bounded_interval",
        )
    return task, record


def test_persisted_synthetic_exact_replay_passes(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        task, record = _persist(store)
        replay = verified_replay(store, task, record)
        assert replay is not None
        assert replay["outcome"] == "http_200_nonce_match"


@pytest.mark.parametrize(
    "parameters",
    [
        {"port": 59153, "nonce": NONCE},
        {"port": 59152, "nonce": "b" * 32},
        {"port": 59152, "nonce": NONCE, "url": "https://example.invalid/"},
        {"port": True, "nonce": NONCE},
        {},
    ],
)
def test_execution_parameters_must_match_claimed_exact_action(
    tmp_path: Path, parameters: dict[str, object]
) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        task, record = _persist(store)
        with store.transaction():
            store.connection.execute(
                "UPDATE probe_executions SET parameters_json=? WHERE execution_id=?",
                (json.dumps(parameters), str(record.collector.execution_id)),
            )
        assert verified_replay(store, task, record) is None


@pytest.mark.parametrize(
    "start,end",
    [(3.5, 5), (1.5, 2.5), (6, 5), (-2, -1)],
)
def test_execution_must_enclose_claimed_request_interval(
    tmp_path: Path, start: float, end: float
) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        task, record = _persist(store)
        with store.transaction():
            store.connection.execute(
                "UPDATE probe_executions SET started_at=?,finished_at=? WHERE execution_id=?",
                (
                    (NOW + timedelta(seconds=start)).isoformat(),
                    (NOW + timedelta(seconds=end)).isoformat(),
                    str(record.collector.execution_id),
                ),
            )
        assert verified_replay(store, task, record) is None


def test_duplicate_persisted_fact_names_are_not_last_value_wins(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        task, record = _persist(store)
        duplicate = record.model_copy(update={"facts": (*record.facts, *record.facts)})
        with store.transaction():
            store.connection.execute(
                "UPDATE evidence SET record_json=? WHERE evidence_id=?",
                (duplicate.model_dump_json(), str(record.evidence_id)),
            )
        assert verified_replay(store, task, duplicate) is None


def test_unpersisted_replay_projection_is_rejected(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        task, record = _persist(store)
        projected = record.model_copy(update={"summary": "Changed outside durable storage"})
        assert verified_replay(store, task, projected) is None
