"""A process target is selected from persisted case evidence, never a caller PID."""

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

from systemsense.application.targets import ProcessTargetRepository, TargetSelectionError
from systemsense.domain.evidence import (
    CollectorReference,
    EvidenceFact,
    EvidenceRecord,
    EvidenceSource,
    Extraction,
    Sensitivity,
    StatementKind,
)
from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId, JsonValue, stable_source_id
from systemsense.storage.sqlite_store import SQLiteStore

NOW = datetime(2026, 9, 23, 12, tzinfo=UTC)


def _case(store: SQLiteStore) -> CaseId:
    case_id = CaseId.new()
    store.create_case(
        case_id=str(case_id), kind="general", symptom="PDF is slow", created_at=NOW.isoformat()
    )
    return case_id


def _snapshot(
    store: SQLiteStore,
    case_id: CaseId,
    *,
    processes: list[dict[str, JsonValue]],
    at: datetime = NOW,
    omitted: int = 0,
    collector_version: int = 1,
) -> EvidenceId:
    evidence_id = EvidenceId.new()
    execution_id = ExecutionId.new()
    source_id = stable_source_id(
        "systemsense.probe",
        {"probe_id": "application.snapshot", "probe_version": collector_version},
    )
    facts: dict[str, JsonValue] = {
        "collection_started_at": (at - timedelta(seconds=1)).isoformat(),
        "collection_completed_at": at.isoformat(),
        "collection_status": "partial" if omitted else "available",
        "processes": cast("JsonValue", processes),
        "omitted_counts": {"processes": omitted, "services": 0, "startup": 0},
    }
    record = EvidenceRecord(
        evidence_id=evidence_id,
        case_id=case_id,
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=at,
        captured_at=at,
        source=EvidenceSource(
            type="systemsense.probe",
            source_id=source_id,
            locator={"probe_id": "application.snapshot"},
        ),
        collector=CollectorReference(
            id="application.snapshot", version=collector_version, execution_id=execution_id
        ),
        summary="Application topology",
        facts=tuple(EvidenceFact(name=name, value=value) for name, value in facts.items()),
        extraction=Extraction(confidence=1, parser="builtin.probe", parser_version=1),
        sensitivity=Sensitivity.PERSONAL,
    )
    with store.transaction() as transaction:
        transaction.record_probe_execution(
            execution_id=str(execution_id),
            case_id=str(case_id),
            probe_id="application.snapshot",
            probe_version=collector_version,
            status="ok",
            parameters_json="{}",
            started_at=(at - timedelta(seconds=2)).isoformat(),
            finished_at=at.isoformat(),
            state_version=0,
        )
        transaction.insert_evidence(
            case_id=str(case_id),
            evidence_id=str(evidence_id),
            source_id=source_id,
            record_json=record.model_dump_json(),
            observed_at=at.isoformat(),
            captured_at=at.isoformat(),
            execution_id=str(execution_id),
            dedupe_key=f"execution:{execution_id}",
            time_basis="collector_upper_bound",
            time_quality="bounded_interval",
        )
    return evidence_id


def _process(pid: int, created: datetime = NOW - timedelta(minutes=1)) -> dict[str, JsonValue]:
    return {
        "pid": pid,
        "ppid": 1,
        "name": "sample.exe",
        "creation_time": created.isoformat(),
        "identity": f"{pid}@{created.isoformat()}",
    }


def test_bind_persists_exact_candidate_provenance_and_is_idempotent(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        evidence_id = _snapshot(store, case_id, processes=[_process(42)], omitted=2)
        targets = ProcessTargetRepository(store, clock=lambda: NOW + timedelta(seconds=1))

        inventory = targets.list_process_candidates(case_id)
        assert len(inventory.candidates) == 1
        assert inventory.omitted_process_count == 2
        assert inventory.inventory_complete is False
        candidate = inventory.candidates[0]
        assert candidate.evidence_id == evidence_id
        assert candidate.pid == 42
        assert candidate.creation_time == NOW - timedelta(minutes=1)
        assert candidate.collection_started_at == NOW - timedelta(seconds=1)
        assert candidate.collection_completed_at == NOW

        bound = targets.bind_process_target(case_id, candidate.candidate_id)
        assert bound == targets.bind_process_target(case_id, candidate.candidate_id)
        assert bound.evidence_id == evidence_id
        assert bound.selected_at == NOW + timedelta(seconds=1)
        assert bound.case_state_version == 0
        assert targets.selected_process_target(case_id) == bound
        assert targets.resolve_process_target_for_sampling(case_id) == bound
        assert store.connection.execute("SELECT COUNT(*) FROM case_process_targets").fetchone() == (
            1,
        )
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            store.connection.execute(
                "UPDATE case_process_targets SET pid = 43 WHERE case_id = ?", (str(case_id),)
            )


def test_pid_reuse_and_cross_case_identifiers_do_not_bind(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        first = _case(store)
        second = _case(store)
        _snapshot(store, first, processes=[_process(42)])
        _snapshot(store, second, processes=[_process(42, NOW - timedelta(seconds=20))])
        targets = ProcessTargetRepository(store, clock=lambda: NOW + timedelta(seconds=1))
        first_id = targets.list_process_candidates(first).candidates[0].candidate_id
        second_id = targets.list_process_candidates(second).candidates[0].candidate_id
        assert first_id != second_id
        with pytest.raises(TargetSelectionError):
            targets.bind_process_target(second, first_id)
        with pytest.raises(TargetSelectionError):
            targets.bind_process_target(first, "proc_" + "0" * 32)


def test_stale_snapshot_rejects_binding_but_case_progress_keeps_candidate(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        _snapshot(store, case_id, processes=[_process(42)], at=NOW - timedelta(minutes=6))
        targets = ProcessTargetRepository(store, clock=lambda: NOW)
        with pytest.raises(TargetSelectionError, match="stale"):
            targets.list_process_candidates(case_id)

        _snapshot(store, case_id, processes=[_process(42)], at=NOW)
        candidate_id = targets.list_process_candidates(case_id).candidates[0].candidate_id
        store.connection.execute(
            "UPDATE cases SET state_version = 1 WHERE case_id = ?", (str(case_id),)
        )
        assert targets.bind_process_target(case_id, candidate_id).case_state_version == 1


def test_candidate_cap_reports_unlisted_processes_without_inference(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        _snapshot(store, case_id, processes=[_process(pid) for pid in range(1, 71)], omitted=3)
        inventory = ProcessTargetRepository(store, clock=lambda: NOW).list_process_candidates(
            case_id
        )
        assert len(inventory.candidates) == 64
        assert inventory.omitted_process_count == 9
        assert all(candidate.omitted_process_count == 9 for candidate in inventory.candidates)
        assert inventory.inventory_complete is False


@pytest.mark.parametrize("status", ["failed", "unsupported", "permission_denied"])
def test_failed_snapshot_cannot_supply_process_target(tmp_path: Path, status: str) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        evidence_id = _snapshot(store, case_id, processes=[_process(42)])
        assert store.connection.execute(
            "SELECT json_extract(record_json, '$.facts[2].name') FROM evidence "
            "WHERE case_id = ? AND evidence_id = ?",
            (str(case_id), str(evidence_id)),
        ).fetchone() == ("collection_status",)
        store.connection.execute(
            "UPDATE evidence SET record_json = json_set(record_json, '$.facts[2].value', ?) "
            "WHERE case_id = ? AND evidence_id = ?",
            (status, str(case_id), str(evidence_id)),
        )
        with pytest.raises(TargetSelectionError):
            ProcessTargetRepository(store, clock=lambda: NOW).list_process_candidates(case_id)


def test_sampling_resolver_rejects_expired_and_superseded_binding(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        _snapshot(store, case_id, processes=[_process(42)])
        targets = ProcessTargetRepository(store, clock=lambda: NOW)
        candidate_id = targets.list_process_candidates(case_id).candidates[0].candidate_id
        bound = targets.bind_process_target(case_id, candidate_id)
        assert targets.resolve_process_target_for_sampling(case_id) == bound

        expired = ProcessTargetRepository(store, clock=lambda: NOW + timedelta(seconds=301))
        assert expired.selected_process_target(case_id) == bound  # Display only.
        with pytest.raises(TargetSelectionError, match="stale"):
            expired.resolve_process_target_for_sampling(case_id)

        _snapshot(store, case_id, processes=[_process(43)], at=NOW + timedelta(seconds=2))
        with pytest.raises(TargetSelectionError):
            targets.resolve_process_target_for_sampling(case_id)


def test_sampling_resolver_keeps_binding_across_case_progress(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        _snapshot(store, case_id, processes=[_process(42)])
        targets = ProcessTargetRepository(store, clock=lambda: NOW)
        candidate_id = targets.list_process_candidates(case_id).candidates[0].candidate_id
        bound = targets.bind_process_target(case_id, candidate_id)
        store.connection.execute(
            "UPDATE cases SET state_version = 1 WHERE case_id = ?", (str(case_id),)
        )
        assert targets.resolve_process_target_for_sampling(case_id) == bound


@pytest.mark.parametrize("checkpoint_status", ["complete", "cancelled", "failed"])
def test_terminal_investigation_rejects_selection(tmp_path: Path, checkpoint_status: str) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        _snapshot(store, case_id, processes=[_process(42)])
        targets = ProcessTargetRepository(store, clock=lambda: NOW)
        candidate_id = targets.list_process_candidates(case_id).candidates[0].candidate_id
        store.connection.execute(
            "INSERT INTO investigation_checkpoints (case_id, record_json) VALUES (?, ?)",
            (str(case_id), f'{{"status":"{checkpoint_status}"}}'),
        )
        with pytest.raises(TargetSelectionError, match="not active"):
            targets.bind_process_target(case_id, candidate_id)


def test_unregistered_snapshot_version_rejects_candidates(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        _snapshot(store, case_id, processes=[_process(42)], collector_version=2)
        with pytest.raises(TargetSelectionError, match="binding"):
            ProcessTargetRepository(store, clock=lambda: NOW).list_process_candidates(case_id)


def test_newer_snapshot_invalidates_old_candidate_even_with_same_pid(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        _snapshot(store, case_id, processes=[_process(42)], at=NOW - timedelta(seconds=30))
        targets = ProcessTargetRepository(store, clock=lambda: NOW)
        old_id = targets.list_process_candidates(case_id).candidates[0].candidate_id
        _snapshot(store, case_id, processes=[_process(42, NOW - timedelta(seconds=10))])

        with pytest.raises(TargetSelectionError):
            targets.bind_process_target(case_id, old_id)
        new_id = targets.list_process_candidates(case_id).candidates[0].candidate_id
        assert new_id != old_id


def test_ambiguous_process_identity_rejects_inventory(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        _snapshot(store, case_id, processes=[_process(42), _process(42)])
        with pytest.raises(TargetSelectionError, match="ambiguous"):
            ProcessTargetRepository(store, clock=lambda: NOW).list_process_candidates(case_id)
