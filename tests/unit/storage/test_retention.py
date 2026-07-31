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
_OLD = _NOW - timedelta(days=30)


def _seed_case(store: SQLiteStore) -> None:
    store.create_case(
        case_id=str(_CASE_ID),
        kind="general",
        symptom="retention fixture",
        created_at=_OLD.isoformat(),
    )


def _policy(*, batch_size: int = 2, evidence_bytes: int = 1_000_000) -> RetentionPolicy:
    return RetentionPolicy(
        max_evidence_age_days=7,
        max_evidence_bytes=evidence_bytes,
        max_artifact_bytes=1,
        batch_size=batch_size,
    )


def test_retention_deletes_only_one_raw_batch_and_preserves_coverage(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        _seed_case(store)
        for number in range(5):
            with store.transaction() as transaction:
                transaction.insert_evidence(
                    case_id=str(_CASE_ID),
                    evidence_id=f"ev_{number:032x}",
                    source_id=f"src_{number:064x}",
                    record_json='{"summary":"old raw evidence"}',
                    captured_at=_OLD.isoformat(),
                )
        with store.transaction() as transaction:
            transaction.insert_evidence(
                case_id=str(_CASE_ID),
                evidence_id="ev_ffffffffffffffffffffffffffffffff",
                source_id=f"src_{'f' * 64}",
                record_json='{"category":"eventlog","status":"missing"}',
                captured_at=_OLD.isoformat(),
            )

        result = RetentionManager(
            store=store,
            artifact_root=tmp_path / "artifacts",
            policy=_policy(),
        ).prune(now=_NOW)

        assert result.evidence_deleted == 2
        assert store.record_counts()["evidence"] == 4
        assert store.coverage_count(case_id=str(_CASE_ID)) == 1


def test_size_cap_uses_small_oldest_first_batches(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        _seed_case(store)
        for number in range(4):
            with store.transaction() as transaction:
                transaction.insert_evidence(
                    case_id=str(_CASE_ID),
                    evidence_id=f"ev_{number:032x}",
                    source_id=f"src_{number:064x}",
                    record_json='{"summary":"' + ("x" * 900) + '"}',
                    captured_at=(_NOW + timedelta(seconds=number)).isoformat(),
                )

        result = RetentionManager(
            store=store,
            artifact_root=tmp_path / "artifacts",
            policy=_policy(evidence_bytes=1_000),
        ).prune(now=_NOW)

        assert result.evidence_deleted == 2
        assert result.evidence_cap_blocked is True
        assert store.raw_evidence_bytes() > 1_000


def test_referenced_artifact_is_preserved_and_orphan_file_is_cleaned(
    tmp_path: Path,
) -> None:
    artifact_root = tmp_path / "artifacts"
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        _seed_case(store)
        artifacts = ArtifactStore(artifact_root, store)
        stored = artifacts.put(
            case_id=_CASE_ID,
            content=b"referenced",
            media_type="text/plain",
            sensitivity=Sensitivity.SYSTEM_METADATA,
        )
        orphan_digest = "a" * 64
        orphan_path = artifact_root / "objects" / "aa" / orphan_digest
        orphan_path.parent.mkdir(parents=True)
        orphan_path.write_bytes(b"orphan")

        result = RetentionManager(
            store=store,
            artifact_root=artifact_root,
            policy=_policy(),
        ).prune(now=_NOW)

        assert result.artifact_cap_blocked is True
        assert result.orphan_files_deleted == 1
        assert (
            artifacts.get_text_excerpt(
                case_id=_CASE_ID,
                artifact_id=stored.artifact_id,
            ).text
            == "referenced"
        )
        assert not orphan_path.exists()


def test_unreferenced_artifact_metadata_and_file_expire(tmp_path: Path) -> None:
    database_path = tmp_path / "systemsense.db"
    artifact_root = tmp_path / "artifacts"
    with SQLiteStore(database_path) as store:
        _seed_case(store)
        artifacts = ArtifactStore(artifact_root, store)
        stored = artifacts.put(
            case_id=_CASE_ID,
            content=b"expired orphan",
            media_type="text/plain",
            sensitivity=Sensitivity.SYSTEM_METADATA,
        )

    with sqlite3.connect(database_path) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("DELETE FROM cases WHERE case_id = ?", (str(_CASE_ID),))
        connection.execute(
            "UPDATE artifacts SET created_at = ? WHERE artifact_id = ?",
            (_OLD.isoformat(), str(stored.artifact_id)),
        )
        connection.commit()

    with SQLiteStore(database_path) as store:
        result = RetentionManager(
            store=store,
            artifact_root=artifact_root,
            policy=_policy(),
        ).prune(now=_NOW)

        assert result.artifact_metadata_deleted == 1
        assert result.artifact_files_deleted == 1
        assert store.artifact_count() == 0
