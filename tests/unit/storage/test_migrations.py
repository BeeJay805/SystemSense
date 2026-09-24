import sqlite3
from pathlib import Path

import pytest
from test_candidate_dispatch_admissions import _setup  # pyright: ignore[reportPrivateUsage]

from systemsense.audit import AuditChain, AuditOutcome
from systemsense.domain.ids import CaseId
from systemsense.domain.time import utc_now
from systemsense.storage.candidate_decision_snapshots import CandidateDecisionSnapshotRepository
from systemsense.storage.candidate_dispatch_admissions import CandidateDispatchAdmissionRepository
from systemsense.storage.sqlite_store import SQLiteStore


def test_initial_migration_configures_durable_store(tmp_path: Path) -> None:
    database_path = tmp_path / "systemsense.db"

    with SQLiteStore(database_path, busy_timeout_ms=250) as store:
        assert store.schema_version() == 23
        assert store.foreign_keys_enabled()
        assert store.journal_mode() == "wal"
        assert store.busy_timeout_ms() == 250
        assert store.integrity_check() == "ok"
        assert {
            "cases",
            "probe_manifests",
            "probe_executions",
            "evidence",
            "inventory_current",
            "inventory_history",
            "audit_events",
            "audit_heads",
            "bookmarks",
            "artifacts",
            "artifact_cases",
            "evidence_relations",
            "evidence_relation_evidence",
            "evidence_relation_sources",
            "investigation_checkpoints",
            "investigation_steps",
            "repair_proposals",
            "repair_approval_claims",
            "repair_plan_heads",
            "repair_execution_claims",
            "repair_execution_target_locks",
            "repair_execution_terminals",
            "case_process_targets",
            "evidence_case_generations",
            "collection_followup_admissions",
            "collection_followup_execution_links",
            "case_measurement_candidates",
            "candidate_dispatch_admissions",
            "candidate_dispatch_claims",
            "search_frontier_items",
            "search_frontier_transitions",
            "search_frontier_events",
            "search_frontier_event_acks",
            "search_frontier_event_overflows",
        } <= store.table_names()
        assert {
            "observed_at",
            "captured_at",
            "execution_id",
            "dedupe_key",
            "time_basis",
            "time_quality",
        } <= store.column_names("evidence")
        assert {"case_id", "sequence", "head_hash"} == store.column_names("audit_heads")
        assert {"case_id", "record_json"} == store.column_names("investigation_checkpoints")
        assert {"case_id", "state_version", "record_json"} == store.column_names(
            "investigation_steps"
        )
        assert "state_version" in store.column_names("probe_executions")


def test_v23_upgrade_preserves_v1_snapshot_admission_fks_and_rolls_back_on_error(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "v22-candidate.db"
    with SQLiteStore(database_path) as store:
        case_id, snapshot_id, candidate, invocation, registry = _setup(store)
        admissions = CandidateDispatchAdmissionRepository(store, registry=registry)
        admission = admissions.admit(
            snapshot_id=snapshot_id,
            candidate_id=candidate.candidate_id,
            case_id=case_id,
            epoch_state_version=3,
            task_id="case:target-pressure:migration",
            invocation_sha256=candidate.invocation_sha256,
            cost_ms=candidate.cost_ms,
        )
        admission_id = admission.admission_id
        admissions.claim_for_worker(
            admission_id,
            case_id=case_id,
            epoch_state_version=3,
            task_id="case:target-pressure:migration",
            invocation_sha256=candidate.invocation_sha256,
        )
        execution_id = "exec_" + "e" * 32
        started_at = utc_now()
        with store.transaction() as transaction:
            transaction.record_probe_execution(
                execution_id=execution_id,
                case_id=str(case_id),
                probe_id=candidate.probe_id,
                probe_version=1,
                status="ok",
                parameters_json='{"pid":101}',
                started_at=started_at.isoformat(),
                finished_at=started_at.isoformat(),
                state_version=3,
            )
            admissions.link_execution(admission_id, execution_id, invocation)

    migrations = Path(__file__).parents[3] / "src" / "systemsense" / "storage" / "migrations"
    v1_sql = (migrations / "019_candidate_decision_snapshots.sql").read_text(encoding="utf-8")
    columns_sql = v1_sql.split("CREATE TABLE candidate_decision_snapshots (", 1)[1].split(
        ") STRICT;", 1
    )[0]
    upgrade_sql = (migrations / "023_frontier_candidate_snapshot.sql").read_text(encoding="utf-8")
    with sqlite3.connect(database_path, isolation_level=None) as connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("BEGIN IMMEDIATE")
        rows = connection.execute("SELECT * FROM candidate_decision_snapshots").fetchall()
        connection.execute("DROP TABLE candidate_decision_snapshots")
        connection.execute(f"CREATE TABLE candidate_decision_snapshots ({columns_sql}) STRICT")
        connection.executemany(
            "INSERT INTO candidate_decision_snapshots VALUES ("
            + ",".join("?" for _ in range(16))
            + ")",
            rows,
        )
        connection.execute(
            "CREATE INDEX candidate_decision_snapshots_case_epoch "
            "ON candidate_decision_snapshots(case_id,epoch_state_version,captured_at)"
        )
        connection.execute(
            "CREATE TRIGGER candidate_decision_snapshots_no_update "
            "BEFORE UPDATE ON candidate_decision_snapshots "
            "BEGIN SELECT RAISE(ABORT, 'candidate decision snapshot is immutable'); END"
        )
        connection.execute(
            "CREATE TRIGGER candidate_decision_snapshots_no_delete "
            "BEFORE DELETE ON candidate_decision_snapshots "
            "WHEN EXISTS (SELECT 1 FROM cases WHERE case_id=OLD.case_id) "
            "BEGIN SELECT RAISE(ABORT, 'candidate decision snapshot is immutable'); END"
        )
        connection.execute("PRAGMA user_version = 22")
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        connection.commit()
        connection.execute("PRAGMA foreign_keys = ON")

        with pytest.raises(sqlite3.OperationalError, match="no such table"):
            SQLiteStore._apply_frontier_snapshot_migration(  # pyright: ignore[reportPrivateUsage]
                connection,
                script=upgrade_sql + "\nINSERT INTO missing_migration_table VALUES (1);",
            )
        assert connection.execute("PRAGMA user_version").fetchone() == (22,)
        assert connection.execute(
            "SELECT snapshot_id FROM candidate_decision_snapshots"
        ).fetchone() == (snapshot_id,)
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert connection.execute("PRAGMA foreign_keys").fetchone() == (1,)

    with SQLiteStore(database_path) as store:
        assert store.schema_version() == 23
        assert (
            CandidateDecisionSnapshotRepository(store).readback(snapshot_id).snapshot_id
            == snapshot_id
        )
        assert (
            CandidateDispatchAdmissionRepository(store).readback(admission_id).snapshot_id
            == snapshot_id
        )
        upgraded_admission = CandidateDispatchAdmissionRepository(store).readback(admission_id)
        assert upgraded_admission.claimed_at is not None
        assert upgraded_admission.execution_id == execution_id
        assert (
            CandidateDecisionSnapshotRepository(store).execution_links(snapshot_id)[0].execution_id
            == execution_id
        )
        assert store.connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert store.integrity_check() == "ok"
        with pytest.raises(sqlite3.IntegrityError, match="immutable"):
            store.connection.execute(
                "UPDATE candidate_decision_snapshots SET correlation_id='changed' "
                "WHERE snapshot_id=?",
                (snapshot_id,),
            )


def test_machine_relation_adjacency_lookup_uses_index(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        plan = store.connection.execute(
            "EXPLAIN QUERY PLAN SELECT record_json FROM evidence_relations "
            "WHERE json_extract(record_json, '$.source_entity_id') IN (?, ?) "
            "ORDER BY relation_id, relation_version LIMIT ?",
            ("device:gpu", "driver:gpu", 64),
        ).fetchall()
    assert any("USING INDEX evidence_relations_source_entity_id" in str(row[3]) for row in plan)


def test_existing_v1_database_is_upgraded_without_losing_evidence(tmp_path: Path) -> None:
    database_path = tmp_path / "systemsense.db"
    migration = (
        Path(__file__).parents[3]
        / "src"
        / "systemsense"
        / "storage"
        / "migrations"
        / "001_initial.sql"
    )
    case_id = "case_0123456789abcdef0123456789abcdef"
    evidence_id = "evidence_0123456789abcdef0123456789abcdef"
    source_id = f"src_{'a' * 64}"
    captured_at = "2026-07-30T12:00:00+00:00"
    with sqlite3.connect(database_path) as connection:
        connection.executescript(migration.read_text(encoding="utf-8"))
        connection.execute(
            "INSERT INTO cases (case_id, kind, symptom, created_at) VALUES (?, ?, ?, ?)",
            (case_id, "general", "legacy fixture", captured_at),
        )
        connection.execute(
            """
            INSERT INTO evidence (evidence_id, case_id, source_id, record_json, captured_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (evidence_id, case_id, source_id, '{"summary":"legacy"}', captured_at),
        )

    with SQLiteStore(database_path) as store:
        row = store.evidence(case_id=case_id, evidence_id=evidence_id)

        assert store.schema_version() == 23
        assert store.integrity_check() == "ok"
        assert row is not None
        assert row.observed_at == captured_at
        assert row.captured_at == captured_at
        assert row.dedupe_key == source_id
        assert row.time_basis == "legacy_case_opened"
        assert row.time_quality == "unknown"


def test_existing_v2_audit_chain_backfills_trusted_case_head(tmp_path: Path) -> None:
    database_path = tmp_path / "systemsense.db"
    migrations = Path(__file__).parents[3] / "src" / "systemsense" / "storage" / "migrations"
    case_id = "case_0123456789abcdef0123456789abcdef"
    chain = AuditChain()
    for index in range(2):
        chain.append(
            event_id=f"audit-{index + 1}",
            case_id=CaseId(root=case_id),
            probe_id="core.resources",
            outcome=AuditOutcome.ALLOWED,
        )

    with sqlite3.connect(database_path) as connection:
        connection.executescript((migrations / "001_initial.sql").read_text(encoding="utf-8"))
        connection.executescript(
            (migrations / "002_temporal_evidence.sql").read_text(encoding="utf-8")
        )
        connection.execute(
            "INSERT INTO cases (case_id, kind, symptom, created_at) VALUES (?, ?, ?, ?)",
            (case_id, "general", "legacy fixture", "2026-07-30T12:00:00+00:00"),
        )
        for entry in chain.entries:
            occurred_at = entry.occurred_at.isoformat()
            connection.execute(
                """
                INSERT INTO audit_events (
                    event_id, case_id, event_json, created_at, occurred_at, persisted_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    entry.event_id,
                    case_id,
                    entry.model_dump_json(),
                    occurred_at,
                    occurred_at,
                    occurred_at,
                ),
            )

    with SQLiteStore(database_path) as store:
        assert store.schema_version() == 23
        assert store.audit_checkpoint(case_id=case_id) == chain.checkpoint()


def test_v2_audit_backfill_rejects_an_invalid_chain_atomically(tmp_path: Path) -> None:
    database_path = tmp_path / "systemsense.db"
    migrations = Path(__file__).parents[3] / "src" / "systemsense" / "storage" / "migrations"
    case_id = "case_0123456789abcdef0123456789abcdef"
    entry = AuditChain().append(
        event_id="audit-1",
        case_id=CaseId(root=case_id),
        probe_id="core.resources",
        outcome=AuditOutcome.ALLOWED,
    )
    tampered = entry.model_copy(update={"probe_id": "changed.probe"})
    occurred_at = entry.occurred_at.isoformat()

    with sqlite3.connect(database_path) as connection:
        connection.executescript((migrations / "001_initial.sql").read_text(encoding="utf-8"))
        connection.executescript(
            (migrations / "002_temporal_evidence.sql").read_text(encoding="utf-8")
        )
        connection.execute(
            "INSERT INTO cases (case_id, kind, symptom, created_at) VALUES (?, ?, ?, ?)",
            (case_id, "general", "legacy fixture", occurred_at),
        )
        connection.execute(
            """
            INSERT INTO audit_events (
                event_id, case_id, event_json, created_at, occurred_at, persisted_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                entry.event_id,
                case_id,
                tampered.model_dump_json(),
                occurred_at,
                occurred_at,
                occurred_at,
            ),
        )

    with pytest.raises(sqlite3.DatabaseError):
        SQLiteStore(database_path).initialize()

    with sqlite3.connect(database_path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (2,)
        assert (
            connection.execute(
                "SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'audit_heads'"
            ).fetchone()
            is None
        )


@pytest.mark.parametrize(
    ("missing_state_version", "expected_state_version"),
    [(True, 0), (False, 7)],
)
def test_v4_probe_execution_schema_drift_is_repaired_without_losing_rows_or_audit(
    tmp_path: Path,
    *,
    missing_state_version: bool,
    expected_state_version: int,
) -> None:
    database_path = tmp_path / "systemsense.db"
    case_id = "case_0123456789abcdef0123456789abcdef"
    execution_id = "exec_0123456789abcdef0123456789abcdef"
    event_id = "audit-probe-execution-fixture"
    created_at = "2026-09-22T12:00:00+00:00"
    chain = AuditChain()
    audit_entry = chain.append(
        event_id=event_id,
        case_id=CaseId(root=case_id),
        probe_id="core.resources",
        outcome=AuditOutcome.ALLOWED,
    )
    audit_time = audit_entry.occurred_at.isoformat()

    with SQLiteStore(database_path) as store:
        store.connection.execute(
            """
            INSERT INTO cases (
                case_id, kind, symptom, created_at, status, state_version, time_window_basis
            ) VALUES (?, 'general', 'legacy fixture', ?, 'collecting', 7, 'unknown')
            """,
            (case_id, created_at),
        )
        store.connection.execute(
            """
            INSERT INTO probe_executions (
                execution_id, case_id, probe_id, probe_version, status,
                parameters_json, started_at, finished_at, state_version
            ) VALUES (?, ?, 'core.resources', 1, 'ok', '{}', ?, ?, 7)
            """,
            (execution_id, case_id, created_at, created_at),
        )
        store.connection.execute(
            """
            INSERT INTO audit_events (
                event_id, case_id, event_json, created_at, occurred_at, persisted_at
            ) VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                event_id,
                case_id,
                audit_entry.model_dump_json(),
                audit_time,
                audit_time,
                audit_time,
            ),
        )
        store.connection.execute(
            "INSERT INTO audit_heads (case_id, sequence, head_hash) VALUES (?, 1, ?)",
            (case_id, chain.checkpoint().head_hash),
        )

    with sqlite3.connect(database_path) as connection:
        # This fixture models a v4 database, not a v10 database with a forged
        # version number. Remove later schemas before replaying upgrades.
        connection.execute("DROP TABLE search_frontier_event_acks")
        connection.execute("DROP TABLE search_frontier_event_overflows")
        connection.execute("DROP TABLE search_frontier_transitions")
        connection.execute("DROP TABLE search_frontier_events")
        connection.execute("DROP TABLE search_frontier_items")
        connection.execute("DROP TABLE candidate_dispatch_claims")
        connection.execute("DROP TABLE candidate_dispatch_admissions")
        connection.execute("DROP TRIGGER candidate_decision_execution_links_no_update")
        connection.execute("DROP TRIGGER candidate_decision_execution_links_no_delete")
        connection.execute("DROP TRIGGER candidate_decision_snapshots_no_update")
        connection.execute("DROP TRIGGER candidate_decision_snapshots_no_delete")
        connection.execute("DROP TABLE candidate_decision_execution_links")
        connection.execute("DROP TABLE candidate_decision_snapshots")
        connection.execute("DROP TRIGGER case_measurement_candidates_no_update")
        connection.execute("DROP TRIGGER case_measurement_candidates_no_delete")
        connection.execute("DROP TABLE case_measurement_candidates")
        connection.execute("DROP TRIGGER cases_evidence_generation_insert")
        connection.execute("DROP TRIGGER evidence_case_generation_insert")
        connection.execute("DROP TRIGGER evidence_case_generation_delete")
        connection.execute("DROP TRIGGER evidence_case_generation_update")
        connection.execute("DROP TABLE evidence_case_generations")
        connection.execute("DROP TRIGGER case_process_targets_no_update")
        connection.execute("DROP TRIGGER probe_executions_followup_admission_no_update")
        connection.execute("DROP INDEX probe_executions_followup_admission_unique")
        connection.execute("ALTER TABLE probe_executions DROP COLUMN followup_admission_id")
        connection.execute("DROP TABLE collection_followup_execution_links")
        connection.execute("DROP TABLE collection_followup_read_set_checks")
        connection.execute("DROP TABLE collection_followup_admissions")
        connection.execute("DROP TABLE decision_execution_links")
        connection.execute("DROP TABLE decision_presentation_traces")
        connection.execute("DROP TABLE decision_snapshots")
        connection.execute("DROP TABLE coordinator_events")
        connection.execute("DROP TABLE case_process_targets")
        connection.execute("DROP TRIGGER cases_repair_execution_state_fence")
        connection.execute("DROP TABLE repair_execution_terminals")
        connection.execute("DROP TABLE repair_execution_target_locks")
        connection.execute("DROP TABLE repair_execution_claims")
        connection.execute("DROP TABLE repair_plan_heads")
        connection.execute("DROP TABLE repair_approval_claims")
        connection.execute("DROP TABLE repair_proposals")
        if missing_state_version:
            connection.execute("ALTER TABLE probe_executions DROP COLUMN state_version")
        connection.execute("PRAGMA user_version = 4")

    with SQLiteStore(database_path) as store:
        execution = store.connection.execute(
            "SELECT case_id, state_version FROM probe_executions WHERE execution_id = ?",
            (execution_id,),
        ).fetchone()
        audit = store.connection.execute(
            "SELECT event_id, case_id FROM audit_events WHERE event_id = ?", (event_id,)
        ).fetchone()
        head = store.connection.execute(
            "SELECT sequence, head_hash FROM audit_heads WHERE case_id = ?", (case_id,)
        ).fetchone()
        verification = AuditChain.verify(
            store.audit_entries(case_id=case_id),
            checkpoint=store.audit_checkpoint(case_id=case_id),
        )

        assert store.schema_version() == 23
        assert execution == (case_id, expected_state_version)
        assert audit == (event_id, case_id)
        assert head == (1, chain.checkpoint().head_hash)
        assert verification.valid
        assert store.integrity_check() == "ok"


def test_v4_repair_rejects_an_existing_state_version_column_with_wrong_semantics(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "systemsense.db"
    with SQLiteStore(database_path):
        pass
    with sqlite3.connect(database_path) as connection:
        connection.execute("DROP TRIGGER candidate_decision_execution_links_no_update")
        connection.execute("DROP TRIGGER candidate_decision_execution_links_no_delete")
        connection.execute("DROP TRIGGER candidate_decision_snapshots_no_update")
        connection.execute("DROP TRIGGER candidate_decision_snapshots_no_delete")
        connection.execute("DROP TABLE candidate_decision_execution_links")
        connection.execute("DROP TABLE candidate_decision_snapshots")
        connection.execute("DROP TRIGGER case_process_targets_no_update")
        connection.execute("DROP TRIGGER probe_executions_followup_admission_no_update")
        connection.execute("DROP INDEX probe_executions_followup_admission_unique")
        connection.execute("ALTER TABLE probe_executions DROP COLUMN followup_admission_id")
        connection.execute("DROP TABLE collection_followup_execution_links")
        connection.execute("DROP TABLE collection_followup_read_set_checks")
        connection.execute("DROP TABLE collection_followup_admissions")
        connection.execute("DROP TABLE decision_execution_links")
        connection.execute("DROP TABLE decision_presentation_traces")
        connection.execute("DROP TABLE decision_snapshots")
        connection.execute("DROP TABLE coordinator_events")
        connection.execute("DROP TABLE case_process_targets")
        connection.execute("DROP TRIGGER cases_repair_execution_state_fence")
        connection.execute("DROP TABLE repair_execution_terminals")
        connection.execute("DROP TABLE repair_execution_target_locks")
        connection.execute("DROP TABLE repair_execution_claims")
        connection.execute("DROP TABLE repair_plan_heads")
        connection.execute("DROP TABLE repair_approval_claims")
        connection.execute("DROP TABLE repair_proposals")
        connection.execute("ALTER TABLE probe_executions DROP COLUMN state_version")
        connection.execute(
            "ALTER TABLE probe_executions ADD COLUMN state_version INTEGER NOT NULL DEFAULT 0"
        )
        connection.execute("PRAGMA user_version = 4")

    with pytest.raises(sqlite3.DatabaseError, match="state_version"):
        SQLiteStore(database_path).initialize()

    with sqlite3.connect(database_path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (4,)


def test_newer_database_schema_version_is_rejected_without_modification(tmp_path: Path) -> None:
    database_path = tmp_path / "systemsense.db"
    with SQLiteStore(database_path):
        pass
    with sqlite3.connect(database_path) as connection:
        connection.execute("PRAGMA user_version = 24")

    with pytest.raises(sqlite3.DatabaseError, match="newer than supported"):
        SQLiteStore(database_path).initialize()

    with sqlite3.connect(database_path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (24,)


def test_v15_upgrade_seeds_monotonic_generation_for_existing_cases(tmp_path: Path) -> None:
    database_path = tmp_path / "v15.db"
    with sqlite3.connect(database_path) as connection:
        connection.executescript(
            "CREATE TABLE cases (case_id TEXT PRIMARY KEY);"
            "CREATE TABLE evidence (evidence_id TEXT PRIMARY KEY, case_id TEXT NOT NULL);"
            "INSERT INTO cases VALUES ('case_a'), ('case_b');"
            "INSERT INTO evidence VALUES ('evidence_a', 'case_a');"
            "PRAGMA user_version = 15;"
        )
        old_rowid = connection.execute(
            "SELECT MAX(rowid) FROM evidence WHERE case_id = 'case_a'"
        ).fetchone()[0]

    # This deliberately minimal v15 fixture exercises only the v16 generation
    # migration; it lacks the pre-existing tables required by v17.
    generation_migration = (
        Path(__file__).parents[3]
        / "src"
        / "systemsense"
        / "storage"
        / "migrations"
        / "016_evidence_case_generations.sql"
    ).read_text(encoding="utf-8")
    with sqlite3.connect(database_path) as connection:
        connection.executescript(generation_migration)
        assert connection.execute("PRAGMA user_version").fetchone() == (16,)
        revisions = dict(
            connection.execute(
                "SELECT case_id, generation FROM evidence_case_generations"
            ).fetchall()
        )
        assert revisions["case_a"] > old_rowid
        assert revisions["case_b"] >= 1
        connection.execute("INSERT INTO evidence VALUES ('evidence_b', 'case_b')")
        connection.execute("DELETE FROM evidence WHERE evidence_id = 'evidence_a'")
        changed = dict(
            connection.execute(
                "SELECT case_id, generation FROM evidence_case_generations"
            ).fetchall()
        )
        assert changed["case_a"] == revisions["case_a"] + 1
        assert changed["case_b"] == revisions["case_b"] + 1

    with sqlite3.connect(database_path) as reopened:
        assert (
            dict(
                reopened.execute(
                    "SELECT case_id, generation FROM evidence_case_generations"
                ).fetchall()
            )
            == changed
        )
