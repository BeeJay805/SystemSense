"""Frozen decision evidence is an exact read set, not the whole moving case catalog."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from systemsense.domain.coverage import CoverageRecord, CoverageStatus
from systemsense.domain.evidence import (
    CollectorReference,
    EvidenceRecord,
    EvidenceSource,
    Extraction,
    Sensitivity,
    StatementKind,
)
from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId
from systemsense.storage.presented_read_set import (
    PresentedReadSetEntryV1,
    capture_presented_read_set,
    revalidate_presented_read_set,
)
from systemsense.storage.sqlite_store import SQLiteStore

NOW = datetime(2026, 9, 23, 12, tzinfo=UTC)
CASE = CaseId(root="case_" + "a" * 32)
OTHER = CaseId(root="case_" + "b" * 32)


def _case(store: SQLiteStore, case_id: CaseId = CASE) -> None:
    store.create_case(
        case_id=str(case_id), kind="incident", symptom="read-set test", created_at=NOW.isoformat()
    )


def _evidence(
    store: SQLiteStore, number: int, *, case_id: CaseId = CASE, raw: str | None = None
) -> EvidenceId:
    evidence_id = EvidenceId(root=f"ev_{number:032x}")
    record = EvidenceRecord(
        evidence_id=evidence_id,
        case_id=case_id,
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=NOW - timedelta(seconds=number),
        captured_at=NOW,
        source=EvidenceSource(type="test.fixture", source_id="src_" + f"{number:064x}", locator={}),
        collector=CollectorReference(
            id="core.system", version=1, execution_id=ExecutionId(root=f"exec_{number:032x}")
        ),
        summary=f"Observed {number}",
        extraction=Extraction(confidence=1, parser="test.fixture", parser_version=1),
        sensitivity=Sensitivity.SYSTEM_METADATA,
    )
    with store.transaction() as transaction:
        transaction.insert_evidence(
            case_id=str(case_id),
            evidence_id=str(evidence_id),
            source_id=record.source.source_id,
            record_json=raw or record.model_dump_json(),
            observed_at=record.observed_at.isoformat(),
            captured_at=record.captured_at.isoformat(),
        )
    return evidence_id


def _coverage(store: SQLiteStore, number: int) -> EvidenceId:
    evidence_id = EvidenceId(root=f"ev_{number:032x}")
    record = CoverageRecord(
        evidence_id=evidence_id,
        case_id=CASE,
        category="network",
        status=CoverageStatus.DENIED,
        captured_at=NOW,
        reason="Permission denied",
    )
    with store.transaction() as transaction:
        transaction.insert_evidence(
            case_id=str(CASE),
            evidence_id=str(evidence_id),
            source_id="src_" + f"{number:064x}",
            record_json=record.model_dump_json(),
            captured_at=NOW.isoformat(),
        )
    return evidence_id


def test_exact_evidence_and_coverage_survive_unrelated_append(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "read-set.db") as store:
        _case(store)
        observed = _evidence(store, 1)
        denied = _coverage(store, 2)
        snapshot = capture_presented_read_set(store, CASE, (observed, denied))
        assert snapshot.schema_version == 1
        assert tuple(item.evidence_id for item in snapshot.entries) == (observed, denied)
        assert tuple(item.kind for item in snapshot.entries) == ("evidence", "coverage")
        assert all(item.owner_case_id == CASE for item in snapshot.entries)
        assert all(item.row_sha256 is not None for item in snapshot.entries)
        assert len(snapshot.read_set_sha256) == 64

        _evidence(store, 3)
        result = revalidate_presented_read_set(store, snapshot)
        assert result.consistent is True
        assert result.generation_advanced is True
        assert result.modified_ids == ()
        assert result.missing_or_retained_away_ids == ()


def test_raw_payload_and_row_metadata_changes_invalidate_only_presented_id(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "read-set.db") as store:
        _case(store)
        first = _evidence(store, 1)
        second = _evidence(store, 2)
        snapshot = capture_presented_read_set(store, CASE, (first, second))
        store.connection.execute(
            "UPDATE evidence SET captured_at=? WHERE evidence_id=?",
            ((NOW + timedelta(seconds=1)).isoformat(), str(second)),
        )
        result = revalidate_presented_read_set(store, snapshot)
        assert result.consistent is False
        assert result.modified_ids == (second,)
        assert result.missing_or_retained_away_ids == ()

        store.connection.execute(
            "UPDATE evidence SET record_json=json_set(record_json, '$.summary', 'changed') "
            "WHERE evidence_id=?",
            (str(first),),
        )
        result = revalidate_presented_read_set(store, snapshot)
        assert result.modified_ids == (first, second)


def test_retained_away_row_is_explicitly_missing_and_not_a_new_observation(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "read-set.db") as store:
        _case(store)
        first = _evidence(store, 1)
        snapshot = capture_presented_read_set(store, CASE, (first,))
        store.connection.execute("DELETE FROM evidence WHERE evidence_id=?", (str(first),))
        result = revalidate_presented_read_set(store, snapshot)
        assert result.consistent is False
        assert result.missing_or_retained_away_ids == (first,)
        assert result.modified_ids == ()


def test_missing_at_freeze_and_outside_case_are_distinguished_without_foreign_payload(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "read-set.db") as store:
        _case(store)
        _case(store, OTHER)
        foreign = _evidence(store, 1, case_id=OTHER)
        missing = EvidenceId(root="ev_" + "f" * 32)
        snapshot = capture_presented_read_set(store, CASE, (foreign, missing))
        assert tuple(item.kind for item in snapshot.entries) == ("outside_case", "missing")
        assert all(item.row_sha256 is None for item in snapshot.entries)
        assert all(item.owner_case_id is None for item in snapshot.entries)
        result = revalidate_presented_read_set(store, snapshot)
        assert result.consistent is False
        assert result.outside_case_ids == (foreign,)
        assert result.missing_at_freeze_ids == (missing,)


def test_noop_generation_bump_does_not_falsely_mark_read_set_modified(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "read-set.db") as store:
        _case(store)
        first = _evidence(store, 1)
        snapshot = capture_presented_read_set(store, CASE, (first,))
        store.connection.execute(
            "UPDATE evidence SET captured_at=captured_at WHERE evidence_id=?", (str(first),)
        )
        result = revalidate_presented_read_set(store, snapshot)
        assert result.consistent is True
        assert result.generation_advanced is True


def test_tampered_snapshot_or_repeated_or_unbounded_ids_fail_closed(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "read-set.db") as store:
        _case(store)
        first = _evidence(store, 1)
        snapshot = capture_presented_read_set(store, CASE, (first,))
        with pytest.raises(ValueError, match="digest"):
            revalidate_presented_read_set(
                store, snapshot.model_copy(update={"read_set_sha256": "0" * 64})
            )
        with pytest.raises(ValueError, match="repeat"):
            capture_presented_read_set(store, CASE, (first, first))
        with pytest.raises(ValueError, match="bound"):
            capture_presented_read_set(
                store, CASE, tuple(EvidenceId(root=f"ev_{number:032x}") for number in range(257))
            )


def test_entry_rejects_partial_owner_or_digest_binding() -> None:
    evidence_id = EvidenceId(root="ev_" + "a" * 32)
    with pytest.raises(ValueError, match="owner/digest"):
        PresentedReadSetEntryV1(evidence_id=evidence_id, kind="missing", owner_case_id=CASE)
    with pytest.raises(ValueError, match="owner/digest"):
        PresentedReadSetEntryV1(evidence_id=evidence_id, kind="evidence", row_sha256="a" * 64)
