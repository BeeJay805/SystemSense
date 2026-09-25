"""Read a frontier snapshot written by the 5f1335b code, without authority."""

from __future__ import annotations

import sqlite3
import zipfile
from pathlib import Path

import pytest

from systemsense.storage.candidate_decision_snapshots import CandidateDecisionSnapshotRepository
from systemsense.storage.sqlite_store import SQLiteStore

_ARCHIVE = Path(__file__).parents[2] / "fixtures" / "historical-frontier-5f1335b.zip"
_DATABASE = "historical-5f1335b.db"


def _store(tmp_path: Path) -> SQLiteStore:
    with zipfile.ZipFile(_ARCHIVE) as archive:
        assert archive.namelist() == [_DATABASE]
        archive.extractall(tmp_path)
    return SQLiteStore(tmp_path / _DATABASE)


def _snapshot_id(connection: sqlite3.Connection) -> str:
    rows = connection.execute(
        "SELECT snapshot_id FROM candidate_decision_snapshots "
        "WHERE serializer_version='frontier-rank-json-v1'"
    ).fetchall()
    assert len(rows) == 1
    return str(rows[0][0])


def test_5f1335b_frontier_is_readable_but_cannot_authorize_new_selection(
    tmp_path: Path,
) -> None:
    with _store(tmp_path) as store:
        snapshot_id = _snapshot_id(store.connection)
        repository = CandidateDecisionSnapshotRepository(store)
        snapshot = repository.readback_frontier(snapshot_id)
        assert snapshot.serializer_version == "frontier-rank-json-v1"
        assert snapshot.selected_kind == "measure"
        assert snapshot.selected_item_id == snapshot.response.ranked_item_ids[0]
        candidate = snapshot.candidate_refs[0]
        with pytest.raises(ValueError, match="historical frontier snapshot"):
            repository.verify_selection(
                snapshot_id,
                snapshot.case_id,
                snapshot.epoch_state_version,
                candidate.candidate_id,
                candidate.invocation_sha256,
            )


def test_5f1335b_frontier_tampering_is_rejected(tmp_path: Path) -> None:
    with _store(tmp_path) as store:
        snapshot_id = _snapshot_id(store.connection)
        repository = CandidateDecisionSnapshotRepository(store)
        assert repository.readback_frontier(snapshot_id)
        store.connection.execute("DROP TRIGGER candidate_decision_snapshots_no_update")
        store.connection.execute(
            "UPDATE candidate_decision_snapshots SET response_json=? WHERE snapshot_id=?",
            ('{"schema_version":1}', snapshot_id),
        )
        with pytest.raises(ValueError, match="digest mismatch"):
            repository.readback_frontier(snapshot_id)
