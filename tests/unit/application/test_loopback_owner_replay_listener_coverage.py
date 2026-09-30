"""Synthetic custody tests for owner-replay coverage of a listener snapshot.

These SQLite fixtures do not contact the network, inspect Windows, call a model,
or represent actual-model evidence.
"""

from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

import pytest

from systemsense.application.bootstrap import default_investigator
from systemsense.application.loopback_owner import LoopbackOwner
from systemsense.application.loopback_replay_evidence import (
    verified_owner_replay_covers_listener,
)
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
from systemsense.domain.ids import EvidenceId, ExecutionId, JsonValue, stable_source_id
from systemsense.packs.runtime import LoopbackOwnerPressureParametersV1
from systemsense.storage.sqlite_store import SQLiteStore

NOW = datetime(2026, 9, 29, tzinfo=UTC)
NONCE = "a" * 32
PID = 4321
PORT = 59152
CREATION_TIME = NOW - timedelta(hours=1)


def _persist_pressure(
    store: SQLiteStore,
) -> tuple[TaskObservationContextV1, EvidenceRecord, LoopbackOwner]:
    task, _replay = _persist_task_and_replay(store)
    owner = LoopbackOwner(
        evidence_id=EvidenceId.new(),
        pid=PID,
        creation_time=CREATION_TIME,
        name="fixture-service.exe",
        port=PORT,
        nonce=NONCE,
    )
    probe_id = "network.listener_owner_pressure"
    replay: dict[str, JsonValue] = {
        "target_handle": task.target_handle,
        "action": task.action,
        "outcome": "timeout",
        "request_started_at": (NOW + timedelta(seconds=6)).isoformat(),
        "request_finished_at": (NOW + timedelta(seconds=7)).isoformat(),
    }
    ownership: dict[str, JsonValue] = {
        "schema_version": 1,
        "status": "verified_at_boundaries",
        "target_pid": PID,
        "target_creation_time": CREATION_TIME.isoformat(),
        "target_handle": task.target_handle,
        "before_replay": {
            "status": "verified",
            "query_started_at": (NOW + timedelta(seconds=4)).isoformat(),
            "observed_at": (NOW + timedelta(seconds=5)).isoformat(),
        },
        "after_replay": {
            "status": "verified",
            "query_started_at": (NOW + timedelta(seconds=7)).isoformat(),
            "observed_at": (NOW + timedelta(seconds=8)).isoformat(),
        },
    }
    record = EvidenceRecord(
        evidence_id=EvidenceId.new(),
        case_id=task.case_id,
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=NOW + timedelta(seconds=8),
        captured_at=NOW + timedelta(seconds=8, milliseconds=500),
        source=EvidenceSource(
            type="systemsense.probe",
            source_id=stable_source_id(
                "systemsense.probe", {"probe_id": probe_id, "probe_version": 2}
            ),
            locator={"probe_id": probe_id},
        ),
        collector=CollectorReference(id=probe_id, version=2, execution_id=ExecutionId.new()),
        summary="Synthetic exact owner replay and boundary proof.",
        facts=(
            EvidenceFact(name="loopback_replay", value=replay),
            EvidenceFact(name="listener_ownership", value=ownership),
        ),
        extraction=Extraction(confidence=1.0, parser="builtin.probe", parser_version=1),
        sensitivity=Sensitivity.SYSTEM_METADATA,
    )
    parameters = LoopbackOwnerPressureParametersV1(
        pid=PID,
        creation_time=CREATION_TIME,
        port=PORT,
        nonce=NONCE,
    )
    with store.transaction() as transaction:
        transaction.record_probe_execution(
            execution_id=str(record.collector.execution_id),
            case_id=str(task.case_id),
            probe_id=probe_id,
            probe_version=2,
            status="ok",
            parameters_json=parameters.model_dump_json(),
            started_at=(NOW + timedelta(seconds=3)).isoformat(),
            finished_at=(NOW + timedelta(seconds=9)).isoformat(),
            state_version=0,
        )
        transaction.insert_evidence(
            case_id=str(task.case_id),
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
    return task, record, owner


def _persist_task_and_replay(
    store: SQLiteStore,
) -> tuple[TaskObservationContextV1, EvidenceRecord]:
    """Create the same source-bound synthetic task/replay used by custody tests."""
    state = default_investigator(store).create(objective="Synthetic owner-replay custody test")
    task = TaskObservationContextV1(
        case_id=state.case_id,
        evidence_id=EvidenceId.new(),
        source_id=stable_source_id("systemsense.probe", {"probe_id": "task.loopback_http"}),
        collector_id="task.loopback_http",
        collector_version=1,
        execution_id=ExecutionId.new(),
        record_sha256="a" * 64,
        target_handle=f"127.0.0.1:{PORT}",
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
        summary="Synthetic replay result.",
        facts=(
            EvidenceFact(
                name="loopback_replay",
                value={
                    "target_handle": task.target_handle,
                    "action": task.action,
                    "outcome": "timeout",
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
            parameters_json=json.dumps({"port": PORT, "nonce": NONCE}),
            started_at=(NOW + timedelta(seconds=1, milliseconds=500)).isoformat(),
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


def _persist_changed_record(store: SQLiteStore, updated: EvidenceRecord) -> EvidenceRecord:
    with store.transaction():
        store.connection.execute(
            "UPDATE evidence SET record_json=?,source_id=? WHERE evidence_id=?",
            (updated.model_dump_json(), updated.source.source_id, str(updated.evidence_id)),
        )
    return updated


def _replace_facts(
    store: SQLiteStore, record: EvidenceRecord, facts: dict[str, JsonValue]
) -> EvidenceRecord:
    updated_facts = tuple(EvidenceFact(name=name, value=value) for name, value in facts.items())
    updated = record.model_copy(update={"facts": updated_facts})
    return _persist_changed_record(store, updated)


def test_source_bound_owner_replay_covers_listener_snapshot(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        task, record, owner = _persist_pressure(store)

        assert verified_owner_replay_covers_listener(store, task, record, owner)


@pytest.mark.parametrize("field", ["pid", "creation_time", "port", "nonce"])
def test_owner_replay_must_match_the_trusted_owner_identity(
    tmp_path: Path, field: Literal["pid", "creation_time", "port", "nonce"]
) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        task, record, owner = _persist_pressure(store)
        altered = {
            "pid": owner.pid + 1,
            "creation_time": owner.creation_time + timedelta(seconds=1),
            "port": owner.port + 1,
            "nonce": "b" * 32,
        }[field]
        mismatched_owner = replace(owner, **{field: altered})

        assert not verified_owner_replay_covers_listener(store, task, record, mismatched_owner)


def test_owner_replay_requires_an_ok_execution(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        task, record, owner = _persist_pressure(store)
        with store.transaction():
            store.connection.execute(
                "UPDATE probe_executions SET status='failed' WHERE execution_id=?",
                (str(record.collector.execution_id),),
            )

        assert not verified_owner_replay_covers_listener(store, task, record, owner)


def test_owner_replay_rejects_a_record_different_from_durable_evidence(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        task, record, owner = _persist_pressure(store)
        changed = record.model_copy(update={"summary": "Changed after persistence."})

        assert not verified_owner_replay_covers_listener(store, task, changed, owner)


def test_owner_replay_rejects_a_mismatched_source_identity(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        task, record, owner = _persist_pressure(store)
        wrong_source_id = stable_source_id(
            "systemsense.probe", {"probe_id": "application.snapshot", "probe_version": 2}
        )
        changed_source = record.source.model_copy(update={"source_id": wrong_source_id})
        changed = _persist_changed_record(
            store, record.model_copy(update={"source": changed_source})
        )

        assert not verified_owner_replay_covers_listener(store, task, changed, owner)


def test_owner_replay_must_be_after_the_exact_task_window(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        task, record, owner = _persist_pressure(store)
        facts = {fact.name: fact.value for fact in record.facts}
        replay_fact = facts["loopback_replay"]
        assert isinstance(replay_fact, dict)
        replay = dict(replay_fact)
        replay["request_started_at"] = task.window_end.isoformat()
        replay["request_finished_at"] = (task.window_end + timedelta(seconds=1)).isoformat()
        facts["loopback_replay"] = replay
        changed = _replace_facts(store, record, facts)

        assert not verified_owner_replay_covers_listener(store, task, changed, owner)


@pytest.mark.parametrize("defect", ["missing", "status", "pid", "creation", "order"])
def test_owner_replay_requires_valid_boundaries(
    tmp_path: Path, defect: Literal["missing", "status", "pid", "creation", "order"]
) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        task, record, owner = _persist_pressure(store)
        facts = {fact.name: fact.value for fact in record.facts}
        ownership_fact = facts.get("listener_ownership")
        assert isinstance(ownership_fact, dict)
        ownership = dict(ownership_fact)
        if defect == "missing":
            facts.pop("listener_ownership")
        elif defect == "status":
            ownership["status"] = "unverified"
            facts["listener_ownership"] = ownership
        elif defect == "pid":
            ownership["target_pid"] = owner.pid + 1
            facts["listener_ownership"] = ownership
        elif defect == "creation":
            ownership["target_creation_time"] = (
                owner.creation_time + timedelta(seconds=1)
            ).isoformat()
            facts["listener_ownership"] = ownership
        else:
            after_fact = ownership["after_replay"]
            assert isinstance(after_fact, dict)
            after = dict(after_fact)
            after["query_started_at"] = (NOW + timedelta(seconds=6, milliseconds=500)).isoformat()
            ownership["after_replay"] = after
            facts["listener_ownership"] = ownership
        changed = _replace_facts(store, record, facts)

        assert not verified_owner_replay_covers_listener(store, task, changed, owner)
