import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from systemsense.domain.evidence import Sensitivity
from systemsense.domain.ids import CaseId
from systemsense.storage.artifact_store import ArtifactStore
from systemsense.storage.retention import RetentionManager, RetentionPolicy
from systemsense.storage.sqlite_store import SQLiteStore

_CASE_ID = CaseId(root="case_11111111111111111111111111111111")
_NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)


def test_recovery_cleans_file_left_after_metadata_first_crash(tmp_path: Path) -> None:
    database_path = tmp_path / "systemsense.db"
    artifact_root = tmp_path / "artifacts"
    with SQLiteStore(database_path) as store:
        store.create_case(
            case_id=str(_CASE_ID),
            kind="general",
            symptom="crash fixture",
            created_at=_NOW.isoformat(),
        )
        artifact = ArtifactStore(artifact_root, store).put(
            case_id=_CASE_ID,
            content=b"crash residue",
            media_type="text/plain",
            sensitivity=Sensitivity.SYSTEM_METADATA,
        )

    object_path = artifact_root / "objects" / artifact.sha256[:2] / artifact.sha256
    with sqlite3.connect(database_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("DELETE FROM cases WHERE case_id = ?", (str(_CASE_ID),))
        connection.execute(
            "DELETE FROM artifacts WHERE artifact_id = ?", (str(artifact.artifact_id),)
        )
        connection.commit()
    assert object_path.is_file()

    with SQLiteStore(database_path) as recovered:
        result = RetentionManager(
            store=recovered,
            artifact_root=artifact_root,
            policy=RetentionPolicy(
                max_evidence_age_days=7,
                max_evidence_bytes=1_000_000,
                max_artifact_bytes=1_000_000,
                batch_size=10,
            ),
        ).prune(now=_NOW + timedelta(days=8))

        assert result.orphan_files_deleted == 1
        assert not object_path.exists()
        assert recovered.integrity_check() == "ok"
