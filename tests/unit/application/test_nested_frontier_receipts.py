"""Nested packets retain historical receipt and snapshot custody across migration 40."""

from __future__ import annotations

import json
import sqlite3
from datetime import timedelta
from pathlib import Path
from textwrap import dedent
from typing import Any, Literal

import pytest
from test_frontier_policy import (  # pyright: ignore[reportPrivateUsage]
    CASE,
    EPOCH,
    MODEL_SHA,
    PROVIDER,
    _candidate_fixture,  # pyright: ignore[reportPrivateUsage]
    _issued_candidates,  # pyright: ignore[reportPrivateUsage]
    _ranker,  # pyright: ignore[reportPrivateUsage]
    _versions,  # pyright: ignore[reportPrivateUsage]
)  # pyright: ignore[reportPrivateUsage]

from systemsense.application.frontier_policy import assemble_frontier_request
from systemsense.decision.frontier_ranker import (
    SemanticPacketRefV1,
    SemanticPacketRefV2,
)
from systemsense.domain.time import utc_now
from systemsense.evidence.retrieval import EvidenceCatalogQuery
from systemsense.storage.candidate_decision_snapshots import CandidateDecisionSnapshotRepository
from systemsense.storage.frontier_packet_receipts import FrontierPacketReceiptRepository
from systemsense.storage.search_frontier import FrontierReferenceV1
from systemsense.storage.sqlite_store import SQLiteStore

_SNAPSHOT_COLUMNS = (
    "snapshot_id,schema_version,serializer_version,case_id,epoch_state_version,correlation_id,"
    "request_frozen_at,captured_at,request_json,request_sha256,response_json,response_sha256,"
    "candidate_ids_json,candidate_manifest_sha256,registry_refs_json,registry_manifest_sha256"
)
_RECEIPT_COLUMNS = (
    "receipt_id,schema_version,case_id,epoch_state_version,receipt_json,receipt_sha256,frozen_at"
)


def _frontier_fixture(store: SQLiteStore) -> tuple[Any, ...]:
    registry, retriever, frontier = _candidate_fixture(store)
    checkpoint_row = store.connection.execute(
        "SELECT record_json FROM investigation_checkpoints WHERE case_id=?", (str(CASE),)
    ).fetchone()
    assert checkpoint_row is not None
    checkpoint: dict[str, Any] = json.loads(str(checkpoint_row[0]))
    now = utc_now()
    checkpoint.update(
        objective="Game stutters",
        created_at=(now - timedelta(seconds=10)).isoformat(),
        updated_at=now.isoformat(),
        incident_start=(now - timedelta(minutes=1)).isoformat(),
        incident_end=now.isoformat(),
    )
    store.connection.execute(
        "UPDATE investigation_checkpoints SET record_json=? WHERE case_id=?",
        (json.dumps(checkpoint), str(CASE)),
    )
    entry = retriever.discover(EvidenceCatalogQuery(case_id=CASE, limit=1)).entries[0]
    candidate = _issued_candidates(registry)[0]
    versions = _versions(retriever)
    item = frontier.upsert_item(
        CASE,
        FrontierReferenceV1(kind="measure", candidate_id=candidate.candidate_id),
        versions,
        cost_ms=candidate.cost_ms,
    )
    return registry, retriever, frontier, entry, candidate, versions, item


def _add_bound_snapshot(
    store: SQLiteStore, *, schema_version: Literal[1, 2], fixture: tuple[Any, ...] | None = None
) -> tuple[str, str]:
    registry, retriever, frontier, entry, candidate, versions, item = (
        _frontier_fixture(store) if fixture is None else fixture
    )
    receipt_repo = FrontierPacketReceiptRepository(store)
    receipt = receipt_repo.freeze(
        case_id=CASE,
        epoch_state_version=EPOCH,
        evidence_ids=(entry.evidence_id,),
        expected_generation=versions.evidence or 0,
        schema_version=schema_version,
    )
    frozen_at = utc_now()
    now = utc_now()
    request = assemble_frontier_request(
        case_id=CASE,
        items=(item,),
        versions=versions,
        symptom="Game stutters",
        hypothesis_briefs=(),
        deadline_at=now + timedelta(minutes=5),
        provider=PROVIDER,
        model_weight_sha256=MODEL_SHA,
        catalog_entries=(),
        candidate_refs=(candidate,),
        candidate_registry=registry,
        candidate_epoch=EPOCH,
        store=store,
        retriever=retriever,
        frontier=frontier,
        evidence_packets=receipt.packets,
    )
    if schema_version == 1:
        assert request.schema_version == 1
        assert all(isinstance(packet, SemanticPacketRefV1) for packet in request.evidence_packets)
    else:
        assert request.schema_version == 3
        assert all(isinstance(packet, SemanticPacketRefV2) for packet in request.evidence_packets)
    response = _ranker().rank(request)
    snapshots = CandidateDecisionSnapshotRepository(store)
    snapshot = snapshots.capture_frontier(
        request,
        response,
        registry=registry,
        retriever=retriever,
        frontier=frontier,
        catalog_entries=(),
        candidate_refs=(candidate,),
        selected_item_id=item.item_id,
        epoch_state_version=EPOCH,
        request_frozen_at=frozen_at,
        packet_receipt_id=receipt.receipt_id,
    )
    assert receipt_repo.bound_receipt(snapshot.snapshot_id) == receipt
    return receipt.receipt_id, snapshot.snapshot_id


def _raw_custody(
    database_path: Path, receipt_id: str, snapshot_id: str
) -> tuple[tuple[object, ...], ...]:
    with sqlite3.connect(database_path) as connection:
        receipt = connection.execute(
            f"SELECT {_RECEIPT_COLUMNS} FROM frontier_packet_receipts WHERE receipt_id=?",
            (receipt_id,),
        ).fetchone()
        binding = connection.execute(
            "SELECT snapshot_id,receipt_id,bound_at FROM frontier_packet_snapshot_bindings "
            "WHERE snapshot_id=?",
            (snapshot_id,),
        ).fetchone()
        snapshot = connection.execute(
            f"SELECT {_SNAPSHOT_COLUMNS} FROM candidate_decision_snapshots WHERE snapshot_id=?",
            (snapshot_id,),
        ).fetchone()
    assert receipt is not None and binding is not None and snapshot is not None
    return (tuple(receipt), tuple(binding), tuple(snapshot))


def _recreate_v39_constraints(database_path: Path) -> None:
    """Turn a current fixture into the exact v39 parent-table constraints.

    Rows and JSON bytes are copied as-is. Foreign keys are disabled only during
    the test fixture's parent-table rebuild, then immediately re-enabled.
    """
    with sqlite3.connect(database_path, isolation_level=None) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute("BEGIN IMMEDIATE")
        connection.execute("DROP TRIGGER candidate_decision_snapshots_no_update")
        connection.execute("DROP TRIGGER candidate_decision_snapshots_no_delete")
        connection.execute("DROP TRIGGER frontier_packet_snapshot_bindings_no_delete")
        connection.execute("DROP INDEX candidate_decision_snapshots_case_epoch")
        script = dedent(
            """
            CREATE TABLE candidate_decision_snapshots_v39 (
                snapshot_id TEXT PRIMARY KEY,
                schema_version INTEGER NOT NULL CHECK (schema_version IN (1, 2)),
                serializer_version TEXT NOT NULL CHECK (
                    (schema_version = 1 AND serializer_version = 'candidate-decision-json-v1') OR
                    (schema_version = 2 AND serializer_version IN
                        ('frontier-rank-json-v1','frontier-rank-json-v2'))
                ),
                case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
                epoch_state_version INTEGER NOT NULL CHECK (epoch_state_version >= 0),
                correlation_id TEXT NOT NULL,
                request_frozen_at TEXT NOT NULL,
                captured_at TEXT NOT NULL,
                request_json TEXT NOT NULL CHECK (json_valid(request_json)),
                request_sha256 TEXT NOT NULL CHECK (length(request_sha256) = 64),
                response_json TEXT NOT NULL CHECK (json_valid(response_json)),
                response_sha256 TEXT NOT NULL CHECK (length(response_sha256) = 64),
                candidate_ids_json TEXT NOT NULL CHECK (json_valid(candidate_ids_json)),
                candidate_manifest_sha256 TEXT NOT NULL
                    CHECK (length(candidate_manifest_sha256) = 64),
                registry_refs_json TEXT NOT NULL CHECK (json_valid(registry_refs_json)),
                registry_manifest_sha256 TEXT NOT NULL CHECK (length(registry_manifest_sha256) = 64)
            ) STRICT;
            INSERT INTO candidate_decision_snapshots_v39 SELECT * FROM candidate_decision_snapshots;
            DROP TABLE candidate_decision_snapshots;
            ALTER TABLE candidate_decision_snapshots_v39 RENAME TO candidate_decision_snapshots;
            CREATE INDEX candidate_decision_snapshots_case_epoch
            ON candidate_decision_snapshots(case_id,epoch_state_version,captured_at);
            CREATE TRIGGER candidate_decision_snapshots_no_update
            BEFORE UPDATE ON candidate_decision_snapshots
            BEGIN SELECT RAISE(ABORT, 'candidate decision snapshot is immutable'); END;
            CREATE TRIGGER candidate_decision_snapshots_no_delete
            BEFORE DELETE ON candidate_decision_snapshots
            WHEN EXISTS (SELECT 1 FROM cases WHERE case_id=OLD.case_id)
            BEGIN SELECT RAISE(ABORT, 'candidate decision snapshot is immutable'); END;
            CREATE TRIGGER frontier_packet_snapshot_bindings_no_delete
            BEFORE DELETE ON frontier_packet_snapshot_bindings
            WHEN EXISTS (SELECT 1 FROM candidate_decision_snapshots
                WHERE snapshot_id=OLD.snapshot_id)
            BEGIN SELECT RAISE(ABORT, 'frontier packet binding is immutable'); END;
            DROP TRIGGER frontier_packet_receipts_no_update;
            DROP TRIGGER frontier_packet_receipts_no_delete;
            CREATE TABLE frontier_packet_receipts_v39 (
                receipt_id TEXT PRIMARY KEY,
                schema_version INTEGER NOT NULL CHECK (schema_version = 1),
                case_id TEXT NOT NULL REFERENCES cases(case_id) ON DELETE CASCADE,
                epoch_state_version INTEGER NOT NULL CHECK (epoch_state_version >= 0),
                receipt_json TEXT NOT NULL CHECK (json_valid(receipt_json)),
                receipt_sha256 TEXT NOT NULL CHECK (length(receipt_sha256) = 64),
                frozen_at TEXT NOT NULL
            ) STRICT;
            INSERT INTO frontier_packet_receipts_v39 SELECT * FROM frontier_packet_receipts;
            DROP TABLE frontier_packet_receipts;
            ALTER TABLE frontier_packet_receipts_v39 RENAME TO frontier_packet_receipts;
            CREATE TRIGGER frontier_packet_receipts_no_update
            BEFORE UPDATE ON frontier_packet_receipts
            BEGIN SELECT RAISE(ABORT, 'frontier packet receipt is immutable'); END;
            CREATE TRIGGER frontier_packet_receipts_no_delete
            BEFORE DELETE ON frontier_packet_receipts
            WHEN EXISTS (SELECT 1 FROM cases WHERE case_id=OLD.case_id)
            BEGIN SELECT RAISE(ABORT, 'frontier packet receipt is immutable'); END;
            PRAGMA user_version=39;
            """
        )
        statement = ""
        for line in script.splitlines(keepends=True):
            statement += line
            if sqlite3.complete_statement(statement):
                connection.execute(statement)
                statement = ""
        assert not statement.strip()
        connection.commit()
        connection.execute("PRAGMA foreign_keys=ON")
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_v39_migration_preserves_bound_v1_receipt_and_snapshot_bytes(tmp_path: Path) -> None:
    database_path = tmp_path / "nested-receipt-v39.db"
    with SQLiteStore(database_path) as store:
        receipt_id, snapshot_id = _add_bound_snapshot(store, schema_version=1)
    before = _raw_custody(database_path, receipt_id, snapshot_id)
    _recreate_v39_constraints(database_path)

    with SQLiteStore(database_path) as migrated:
        assert migrated.schema_version() == 41
        assert _raw_custody(database_path, receipt_id, snapshot_id) == before
        receipt = FrontierPacketReceiptRepository(migrated).readback(receipt_id)
        snapshot = CandidateDecisionSnapshotRepository(migrated).readback_frontier(snapshot_id)
        assert receipt.schema_version == 1
        assert receipt.semantic_serializer == "semantic_fact_packets_v1"
        assert receipt.max_packets == 24
        assert len(receipt.packets) <= 16  # V1 projector emits at most 16 today.
        assert snapshot.serializer_version == "frontier-rank-json-v2"
        assert FrontierPacketReceiptRepository(migrated).bound_receipt(snapshot_id) == receipt
        assert migrated.connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert migrated.integrity_check() == "ok"


def test_v39_migration_failure_rolls_back_schema_and_custody(tmp_path: Path) -> None:
    database_path = tmp_path / "nested-receipt-v39-rollback.db"
    with SQLiteStore(database_path) as store:
        receipt_id, snapshot_id = _add_bound_snapshot(store, schema_version=1)
    before = _raw_custody(database_path, receipt_id, snapshot_id)
    _recreate_v39_constraints(database_path)
    with sqlite3.connect(database_path) as connection:
        connection.execute("CREATE TABLE candidate_decision_snapshots_v4 (collision INTEGER)")
        connection.commit()

    with pytest.raises(sqlite3.OperationalError, match="already exists"):
        SQLiteStore(database_path).initialize()

    with sqlite3.connect(database_path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (39,)
        assert _raw_custody(database_path, receipt_id, snapshot_id) == before
        sql = connection.execute(
            "SELECT sql FROM sqlite_schema WHERE name='frontier_packet_receipts'"
        ).fetchone()[0]
        assert "CHECK (schema_version = 1)" in str(sql)
        snapshot_sql = connection.execute(
            "SELECT sql FROM sqlite_schema WHERE name='candidate_decision_snapshots'"
        ).fetchone()[0]
        assert "frontier-rank-json-v3" not in str(snapshot_sql)
        for object_name in (
            "candidate_decision_snapshots_no_update",
            "candidate_decision_snapshots_no_delete",
            "candidate_decision_snapshots_case_epoch",
        ):
            assert connection.execute(
                "SELECT 1 FROM sqlite_schema WHERE name=?", (object_name,)
            ).fetchone() == (1,)
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_v40_preserves_immutability_and_owner_cascade_for_both_receipt_versions(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "nested-receipt-immutability.db"
    with SQLiteStore(database_path) as store:
        fixture = _frontier_fixture(store)
        old_receipt_id, old_snapshot_id = _add_bound_snapshot(
            store, schema_version=1, fixture=fixture
        )
        new_receipt_id, new_snapshot_id = _add_bound_snapshot(
            store, schema_version=2, fixture=fixture
        )
        for receipt_id in (old_receipt_id, new_receipt_id):
            with pytest.raises(sqlite3.IntegrityError, match="immutable"):
                store.connection.execute(
                    "UPDATE frontier_packet_receipts SET frozen_at='changed' WHERE receipt_id=?",
                    (receipt_id,),
                )
            with pytest.raises(sqlite3.IntegrityError, match="immutable"):
                store.connection.execute(
                    "DELETE FROM frontier_packet_receipts WHERE receipt_id=?", (receipt_id,)
                )
        for snapshot_id in (old_snapshot_id, new_snapshot_id):
            with pytest.raises(sqlite3.IntegrityError, match="immutable"):
                store.connection.execute(
                    "UPDATE candidate_decision_snapshots SET captured_at='changed' "
                    "WHERE snapshot_id=?",
                    (snapshot_id,),
                )
            with pytest.raises(sqlite3.IntegrityError, match="immutable"):
                store.connection.execute(
                    "DELETE FROM frontier_packet_snapshot_bindings WHERE snapshot_id=?",
                    (snapshot_id,),
                )
            with pytest.raises(sqlite3.IntegrityError, match="immutable"):
                store.connection.execute(
                    "UPDATE frontier_packet_snapshot_bindings SET bound_at='changed' "
                    "WHERE snapshot_id=?",
                    (snapshot_id,),
                )
            with pytest.raises(sqlite3.IntegrityError, match="immutable"):
                store.connection.execute(
                    "DELETE FROM candidate_decision_snapshots WHERE snapshot_id=?",
                    (snapshot_id,),
                )
        assert store.connection.execute("PRAGMA foreign_key_check").fetchall() == []
        store.connection.execute("DELETE FROM cases WHERE case_id=?", (str(CASE),))
        for table in (
            "frontier_packet_receipts",
            "frontier_packet_snapshot_bindings",
            "candidate_decision_snapshots",
        ):
            assert store.connection.execute(f"SELECT COUNT(*) FROM {table}").fetchone() == (0,)
        assert store.connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_v2_receipt_binds_only_v3_snapshot_and_v1_stays_v2(tmp_path: Path) -> None:
    database_path = tmp_path / "nested-receipt-v2-live.db"
    with SQLiteStore(database_path) as store:
        fixture = _frontier_fixture(store)
        old_receipt_id, old_snapshot_id = _add_bound_snapshot(
            store, schema_version=1, fixture=fixture
        )
        new_receipt_id, new_snapshot_id = _add_bound_snapshot(
            store, schema_version=2, fixture=fixture
        )
        receipts = FrontierPacketReceiptRepository(store)
        snapshots = CandidateDecisionSnapshotRepository(store)
        old = receipts.readback(old_receipt_id)
        new = receipts.readback(new_receipt_id)
        assert old.schema_version == 1
        assert old.semantic_serializer == "semantic_fact_packets_v1"
        assert old.max_packets == 24
        assert len(old.packets) <= 16
        assert all(isinstance(packet, SemanticPacketRefV1) for packet in old.packets)
        assert (
            snapshots.readback_frontier(old_snapshot_id).serializer_version
            == "frontier-rank-json-v2"
        )
        assert new.schema_version == 2
        assert new.source_projection == "frontier_typed_row_context_v2_p16"
        assert new.max_packets == 16
        assert new.semantic_serializer == "semantic_fact_packets_v2"
        assert len(new.packets) <= 16
        assert all(isinstance(packet, SemanticPacketRefV2) for packet in new.packets)
        assert (
            snapshots.readback_frontier(new_snapshot_id).serializer_version
            == "frontier-rank-json-v3"
        )
        assert receipts.bound_receipt(new_snapshot_id) == new
        assert store.connection.execute(
            "SELECT schema_version FROM frontier_packet_receipts WHERE receipt_id=?",
            (new_receipt_id,),
        ).fetchone() == (2,)
        assert store.connection.execute("PRAGMA foreign_key_check").fetchall() == []

        # Bypass only SQL immutability in this corruption fixture. Readback must
        # independently reject column/JSON and serializer/request mismatches.
        store.connection.execute("DROP TRIGGER candidate_decision_snapshots_no_update")
        store.connection.execute(
            "UPDATE candidate_decision_snapshots SET serializer_version=? WHERE snapshot_id=?",
            ("frontier-rank-json-v2", new_snapshot_id),
        )
        with pytest.raises(ValueError, match="payload is invalid"):
            snapshots.readback_frontier(new_snapshot_id)

        store.connection.execute("DROP TRIGGER frontier_packet_receipts_no_update")
        store.connection.execute(
            "UPDATE frontier_packet_receipts SET schema_version=1 WHERE receipt_id=?",
            (new_receipt_id,),
        )
        with pytest.raises(ValueError, match="binding is invalid"):
            receipts.readback(new_receipt_id)
