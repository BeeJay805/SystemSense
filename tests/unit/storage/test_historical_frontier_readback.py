"""Read actual frontier custody produced by commit 41f46dd."""

from __future__ import annotations

import hashlib
import json
import sqlite3
import zipfile
from pathlib import Path

import pytest

from systemsense.domain.ids import CaseId
from systemsense.storage.candidate_decision_snapshots import CandidateDecisionSnapshotRepository
from systemsense.storage.candidate_dispatch_admissions import CandidateDispatchAdmissionRepository
from systemsense.storage.case_candidates import CandidateGap, CandidateResolution
from systemsense.storage.sqlite_store import SQLiteStore

_ARCHIVE = Path(__file__).parents[2] / "fixtures" / "historical-frontier-41f46dd.zip"
_SNAPSHOT_ID = "frontier_decision_snapshot_2d8a2b153c134cce8c380d51ffa117c5"


class _UnusedResolver:
    def resolve(
        self, case_id: CaseId, epoch_state_version: int, candidate_id: str
    ) -> CandidateResolution | CandidateGap:
        raise AssertionError("historical snapshot must be rejected before registry resolution")


def _historical_store(tmp_path: Path) -> SQLiteStore:
    with zipfile.ZipFile(_ARCHIVE) as archive:
        assert archive.namelist() == ["historical-41f46dd.db"]
        archive.extractall(tmp_path)
    return SQLiteStore(tmp_path / "historical-41f46dd.db")


def test_historical_frontier_is_inspectable_without_execution_authority(tmp_path: Path) -> None:
    with _historical_store(tmp_path) as store:
        row = store.connection.execute(
            "SELECT request_json,response_json,serializer_version "
            "FROM candidate_decision_snapshots "
            "WHERE snapshot_id=?",
            (_SNAPSHOT_ID,),
        ).fetchone()
        assert row is not None
        request_wire, response_wire, serializer = row
        assert serializer == "frontier-rank-json-v1"
        assert "measurement" not in json.loads(request_wire)["item_semantics"][0]
        assert "presentation_trace" not in json.loads(response_wire)

        repository = CandidateDecisionSnapshotRepository(store)
        snapshot = repository.readback_frontier(_SNAPSHOT_ID)
        assert snapshot.selected_kind == "measure"
        assert snapshot.candidate_id == snapshot.request.items[0].reference.candidate_id
        assert snapshot.response.ranked_item_ids[0] == snapshot.selected_item_id
        assert snapshot.serializer_version == "frontier-rank-json-v1"
        candidate = snapshot.candidate_refs[0]
        with pytest.raises(ValueError, match=r"historical|current|version"):
            repository.verify_selection(
                _SNAPSHOT_ID,
                snapshot.case_id,
                snapshot.epoch_state_version,
                candidate.candidate_id,
                candidate.invocation_sha256,
            )
        with pytest.raises(ValueError, match="historical frontier snapshot"):
            CandidateDispatchAdmissionRepository(store, registry=_UnusedResolver()).admit(
                snapshot_id=_SNAPSHOT_ID,
                candidate_id=candidate.candidate_id,
                case_id=snapshot.case_id,
                epoch_state_version=snapshot.epoch_state_version,
                task_id="historical-admission-must-fail",
                invocation_sha256=candidate.invocation_sha256,
                cost_ms=candidate.cost_ms,
            )
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_dispatch_admissions WHERE snapshot_id=?",
            (_SNAPSHOT_ID,),
        ).fetchone() == (0,)


def test_historical_frontier_response_tampering_is_rejected(tmp_path: Path) -> None:
    with _historical_store(tmp_path) as store:
        repository = CandidateDecisionSnapshotRepository(store)
        assert repository.readback_frontier(_SNAPSHOT_ID)
        store.connection.execute("DROP TRIGGER candidate_decision_snapshots_no_update")
        store.connection.execute(
            "UPDATE candidate_decision_snapshots SET response_json=? WHERE snapshot_id=?",
            ('{"schema_version":1}', _SNAPSHOT_ID),
        )
        with pytest.raises(ValueError, match="digest mismatch"):
            repository.readback_frontier(_SNAPSHOT_ID)


def test_migration_preserves_historical_payload_bytes(tmp_path: Path) -> None:
    with zipfile.ZipFile(_ARCHIVE) as archive:
        archive.extractall(tmp_path)
    path = tmp_path / "historical-41f46dd.db"
    with sqlite3.connect(path) as connection:
        original = connection.execute(
            "SELECT request_json,request_sha256,response_json,response_sha256,"
            "registry_refs_json,registry_manifest_sha256 "
            "FROM candidate_decision_snapshots WHERE snapshot_id=?",
            (_SNAPSHOT_ID,),
        ).fetchone()
        assert original is not None
    with SQLiteStore(path) as store:
        assert (
            store.connection.execute(
                "SELECT request_json,request_sha256,response_json,response_sha256,"
                "registry_refs_json,registry_manifest_sha256 "
                "FROM candidate_decision_snapshots WHERE snapshot_id=?",
                (_SNAPSHOT_ID,),
            ).fetchone()
            == original
        )
        assert store.connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_historical_serializer_rejects_new_measurement_field(tmp_path: Path) -> None:
    with _historical_store(tmp_path) as store:
        request_json = store.connection.execute(
            "SELECT request_json FROM candidate_decision_snapshots WHERE snapshot_id=?",
            (_SNAPSHOT_ID,),
        ).fetchone()[0]
        request = json.loads(request_json)
        request["item_semantics"][0]["measurement"] = None
        altered = json.dumps(request, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        store.connection.execute("DROP TRIGGER candidate_decision_snapshots_no_update")
        store.connection.execute(
            "UPDATE candidate_decision_snapshots SET request_json=?,request_sha256=? "
            "WHERE snapshot_id=?",
            (altered, hashlib.sha256(altered.encode()).hexdigest(), _SNAPSHOT_ID),
        )
        with pytest.raises(ValueError, match=r"historical.*measurement"):
            CandidateDecisionSnapshotRepository(store).readback_frontier(_SNAPSHOT_ID)
