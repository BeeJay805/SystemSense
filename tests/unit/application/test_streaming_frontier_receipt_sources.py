"""Streaming Laya receipts must include every offered measurement's evidence."""

import json
import sqlite3

import pytest

import systemsense.application.investigator as investigator
from systemsense.application.investigator import (
    _streaming_receipt_source_ids,  # pyright: ignore[reportPrivateUsage]
)
from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId


def _candidate_table() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.execute(
        "CREATE TABLE case_measurement_candidates ("
        "case_id TEXT, candidate_id TEXT, source_evidence_id TEXT, "
        "dependency_bindings_json TEXT)"
    )
    return connection


def _candidate(
    connection: sqlite3.Connection,
    case_id: CaseId,
    candidate_id: str,
    source: EvidenceId,
    dependencies: tuple[EvidenceId, ...],
) -> None:
    connection.execute(
        "INSERT INTO case_measurement_candidates VALUES (?,?,?,?)",
        (
            str(case_id),
            candidate_id,
            str(source),
            json.dumps([{"evidence_id": str(item)} for item in dependencies]),
        ),
    )


def _parent_table() -> sqlite3.Connection:
    connection = sqlite3.connect(":memory:")
    connection.execute(
        "CREATE TABLE evidence (case_id TEXT, execution_id TEXT, "
        "evidence_id TEXT, captured_at TEXT)"
    )
    return connection


def _add_parent_records(
    connection: sqlite3.Connection, case_id: CaseId, execution_id: ExecutionId, count: int
) -> tuple[EvidenceId, ...]:
    evidence_ids = tuple(EvidenceId.new() for _ in range(count))
    connection.executemany(
        "INSERT INTO evidence VALUES (?,?,?,?)",
        (
            (str(case_id), str(execution_id), str(evidence_id), f"2026-01-01T00:00:{i:02d}+00:00")
            for i, evidence_id in enumerate(evidence_ids)
        ),
    )
    return evidence_ids


def test_streaming_receipt_preserves_candidate_dependencies_and_parent() -> None:
    connection = _candidate_table()
    case_id = CaseId.new()
    source = EvidenceId.new()
    dependency = EvidenceId.new()
    parent = EvidenceId.new()
    context = EvidenceId.new()
    _candidate(connection, case_id, "candidate-1", source, (dependency,))

    selected = _streaming_receipt_source_ids(
        connection=connection,
        case_id=case_id,
        candidate_ids=("candidate-1",),
        parent_ids=(parent,),
        projectable_optional_ids=(parent, context),
    )

    assert selected == (source, dependency, parent, context)


def test_streaming_receipt_rejects_candidate_provenance_over_capacity() -> None:
    connection = _candidate_table()
    case_id = CaseId.new()
    source = EvidenceId.new()
    dependencies = tuple(EvidenceId.new() for _ in range(16))
    _candidate(connection, case_id, "candidate-1", source, dependencies)

    with pytest.raises(ValueError, match="candidate sources exceed receipt capacity"):
        _streaming_receipt_source_ids(
            connection=connection,
            case_id=case_id,
            candidate_ids=("candidate-1",),
            parent_ids=(),
            projectable_optional_ids=(),
        )


def test_streaming_receipt_does_not_silently_omit_new_parent() -> None:
    connection = _candidate_table()
    case_id = CaseId.new()
    source = EvidenceId.new()
    dependencies = tuple(EvidenceId.new() for _ in range(15))
    parent = EvidenceId.new()
    _candidate(connection, case_id, "candidate-1", source, dependencies)

    with pytest.raises(ValueError, match="parent evidence exceeds receipt capacity"):
        _streaming_receipt_source_ids(
            connection=connection,
            case_id=case_id,
            candidate_ids=("candidate-1",),
            parent_ids=(parent,),
            projectable_optional_ids=(parent,),
        )


def test_streaming_receipt_rejects_partially_visible_parent_execution() -> None:
    connection = _candidate_table()
    case_id = CaseId.new()
    source = EvidenceId.new()
    dependencies = tuple(EvidenceId.new() for _ in range(14))
    first_parent, second_parent = EvidenceId.new(), EvidenceId.new()
    _candidate(connection, case_id, "candidate-1", source, dependencies)

    with pytest.raises(ValueError, match="parent evidence exceeds receipt capacity"):
        _streaming_receipt_source_ids(
            connection=connection,
            case_id=case_id,
            candidate_ids=("candidate-1",),
            parent_ids=(first_parent, second_parent),
            projectable_optional_ids=(first_parent, second_parent),
        )


def test_streaming_receipt_rejects_one_unprojectable_parent_record() -> None:
    connection = _candidate_table()
    case_id = CaseId.new()
    first_parent, second_parent = EvidenceId.new(), EvidenceId.new()

    with pytest.raises(ValueError, match="parent evidence is unavailable for receipt"):
        _streaming_receipt_source_ids(
            connection=connection,
            case_id=case_id,
            candidate_ids=(),
            parent_ids=(first_parent, second_parent),
            projectable_optional_ids=(first_parent,),
        )


def test_streaming_parent_source_query_does_not_truncate_fifth_record() -> None:
    connection = _parent_table()
    case_id, execution_id = CaseId.new(), ExecutionId.new()
    expected = _add_parent_records(connection, case_id, execution_id, 5)
    _add_parent_records(connection, case_id, ExecutionId.new(), 2)
    parent_sources = getattr(investigator, "_streaming_parent_source_ids", None)

    assert parent_sources is not None, "bounded parent source query is missing"
    assert parent_sources(connection, case_id, execution_id) == expected


def test_streaming_parent_source_query_rejects_more_than_packet_capacity() -> None:
    connection = _parent_table()
    case_id, execution_id = CaseId.new(), ExecutionId.new()
    _add_parent_records(connection, case_id, execution_id, 17)
    parent_sources = getattr(investigator, "_streaming_parent_source_ids", None)

    assert parent_sources is not None, "bounded parent source query is missing"
    with pytest.raises(ValueError, match="parent evidence exceeds receipt capacity"):
        parent_sources(connection, case_id, execution_id)
