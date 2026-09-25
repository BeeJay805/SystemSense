import sqlite3
from pathlib import Path

import pytest
from test_candidate_dispatch_admissions import _setup  # pyright: ignore[reportPrivateUsage]

from systemsense.audit import AuditChain, AuditOutcome
from systemsense.domain.ids import CaseId, EvidenceId
from systemsense.domain.time import utc_now
from systemsense.storage.candidate_decision_snapshots import CandidateDecisionSnapshotRepository
from systemsense.storage.candidate_dispatch_admissions import CandidateDispatchAdmissionRepository
from systemsense.storage.search_frontier import (
    FrontierEventV1,
    RelevantVersionsV1,
    SearchFrontierRepository,
)
from systemsense.storage.sqlite_store import SQLiteStore


def _drop_v32_launch_schema(connection: sqlite3.Connection) -> None:
    """Remove later worker-draft and launch tables before replaying older migrations."""

    connection.execute("DROP TABLE IF EXISTS search_frontier_focus_delivery_receipts")
    connection.execute("DROP TABLE IF EXISTS frontier_worker_capture_drafts")
    connection.execute("DROP TABLE IF EXISTS candidate_followup_parents")
    connection.execute("DROP TABLE IF EXISTS candidate_launch_consumptions")
    connection.execute("DROP TABLE IF EXISTS candidate_launch_continuations")


def _drop_v24_receipt_schema(connection: sqlite3.Connection) -> None:
    """Make a current fixture a faithful pre-v24 schema before replaying migrations."""

    _drop_v32_launch_schema(connection)
    connection.execute("ALTER TABLE probe_executions DROP COLUMN tree_exit_status")
    connection.execute("DROP TABLE diagnostic_progress")
    connection.execute("DROP TABLE diagnostic_intent_terminals")
    connection.execute("DROP TABLE diagnostic_intent_execution_links")
    connection.execute("DROP TABLE diagnostic_intent_dispatch_claims")
    connection.execute("DROP TABLE diagnostic_intent_admissions")
    connection.execute("DROP TABLE deep_mailbox")
    connection.execute("DROP TRIGGER frontier_packet_snapshot_bindings_no_update")
    connection.execute("DROP TRIGGER frontier_packet_snapshot_bindings_no_delete")
    connection.execute("DROP TRIGGER frontier_packet_receipts_no_update")
    connection.execute("DROP TRIGGER frontier_packet_receipts_no_delete")
    connection.execute("DROP TABLE frontier_packet_snapshot_bindings")
    connection.execute("DROP TABLE frontier_packet_receipts")


def _drop_v30_investigator_turn_schema(connection: sqlite3.Connection) -> None:
    _drop_v32_launch_schema(connection)
    connection.execute("DROP TABLE search_frontier_investigator_turn_closures")
    connection.execute("DROP TABLE search_frontier_investigator_turn_outcomes")
    connection.execute("DROP TABLE search_frontier_investigator_turns")
    connection.execute("DROP TRIGGER search_frontier_investigator_active_sessions_no_delete")
    connection.execute(
        "CREATE TRIGGER search_frontier_investigator_active_sessions_no_delete "
        "BEFORE DELETE ON search_frontier_investigator_active_sessions "
        "WHEN EXISTS (SELECT 1 FROM cases WHERE case_id=OLD.case_id) "
        "AND NOT EXISTS (SELECT 1 FROM search_frontier_investigator_terminals "
        "WHERE event_id=OLD.event_id) "
        "BEGIN SELECT RAISE(ABORT, 'investigator active session lacks terminal'); END"
    )


def _drop_v29_investigator_schema(connection: sqlite3.Connection) -> None:
    _drop_v30_investigator_turn_schema(connection)
    connection.execute("DROP TABLE search_frontier_investigator_terminals")
    connection.execute("DROP TABLE search_frontier_investigator_active_sessions")
    connection.execute("DROP TABLE search_frontier_investigator_sessions")
    connection.execute("DROP TABLE search_frontier_investigator_event_acks")
    connection.execute("DROP TABLE search_frontier_investigator_triggers")
    connection.execute("DROP INDEX search_frontier_events_id_case")


def test_initial_migration_configures_durable_store(tmp_path: Path) -> None:
    database_path = tmp_path / "systemsense.db"

    with SQLiteStore(database_path, busy_timeout_ms=250) as store:
        assert store.schema_version() == 37
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
            "candidate_followup_parents",
            "search_frontier_items",
            "search_frontier_focus_delivery_receipts",
            "search_frontier_transitions",
            "search_frontier_events",
            "search_frontier_event_acks",
            "search_frontier_event_overflows",
            "search_frontier_investigator_triggers",
            "search_frontier_investigator_event_acks",
            "search_frontier_investigator_sessions",
            "search_frontier_investigator_active_sessions",
            "search_frontier_investigator_terminals",
            "search_frontier_investigator_turns",
            "search_frontier_investigator_turn_outcomes",
            "search_frontier_investigator_turn_closures",
            "deep_mailbox",
            "diagnostic_progress",
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
        assert "tree_exit_status" in store.column_names("probe_executions")


def test_v36_focus_receipts_upgrade_preserves_existing_case(tmp_path: Path) -> None:
    path = tmp_path / "v35-focus.db"
    with SQLiteStore(path) as store:
        case_id = CaseId.new()
        store.create_case(
            case_id=str(case_id),
            kind="general",
            symptom="Preserve case across focus receipt upgrade",
            created_at="2026-09-23T12:00:00+00:00",
        )
        original = store.case(str(case_id))
        assert original is not None
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE search_frontier_focus_delivery_receipts")
        connection.execute("PRAGMA user_version = 35")
    with SQLiteStore(path) as upgraded:
        assert upgraded.schema_version() == 37
        assert upgraded.case(str(case_id)) == original
        assert "search_frontier_focus_delivery_receipts" in upgraded.table_names()
        assert upgraded.connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_v34_upgrade_adds_parent_binding_without_changing_v33_case(tmp_path: Path) -> None:
    path = tmp_path / "v33.db"
    with SQLiteStore(path) as store:
        case_id = CaseId.new()
        store.create_case(
            case_id=str(case_id),
            kind="general",
            symptom="Preserve this case across the candidate parent upgrade",
            created_at="2026-09-23T12:00:00+00:00",
        )
        original = store.case(str(case_id))
        assert original is not None
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE search_frontier_focus_delivery_receipts")
        connection.execute("DROP TABLE frontier_worker_capture_drafts")
        connection.execute("DROP TABLE candidate_followup_parents")
        connection.execute("PRAGMA user_version = 33")
    with SQLiteStore(path) as upgraded:
        assert upgraded.schema_version() == 37
        assert upgraded.case(str(case_id)) == original
        assert "candidate_followup_parents" in upgraded.table_names()
        assert upgraded.connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_v29_upgrade_preserves_legacy_event_ack_and_source(tmp_path: Path) -> None:
    path = tmp_path / "v28-frontier.db"
    with SQLiteStore(path) as store:
        case_id = CaseId.new()
        store.create_case(
            case_id=str(case_id),
            kind="general",
            symptom="slow PDF",
            created_at="2026-09-23T12:00:00+00:00",
        )
        evidence_id = EvidenceId.new()
        repo = SearchFrontierRepository(store)
        with store.transaction() as transaction:
            transaction.insert_evidence(
                case_id=str(case_id),
                evidence_id=str(evidence_id),
                source_id="src_" + "a" * 64,
                record_json='{"summary":"observed"}',
                captured_at="2026-09-23T12:00:00+00:00",
            )
            event = repo.append_result_event(
                case_id,
                source_evidence_id=evidence_id,
                source_execution_id=None,
                versions=RelevantVersionsV1(objective=1, evidence=1),
            )
        assert isinstance(event, FrontierEventV1)
        repo.ack_event(event.event_id)
    with sqlite3.connect(path) as connection:
        _drop_v29_investigator_schema(connection)
        connection.execute("PRAGMA user_version = 28")
    with SQLiteStore(path) as upgraded:
        repo = SearchFrontierRepository(upgraded)
        assert upgraded.schema_version() == 37
        assert repo.read_event(event.event_id) == event
        assert repo.pending_events(case_id) == ()
        assert repo.pending_investigator_events(case_id) == (event,)
        assert upgraded.connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_v30_upgrade_preserves_populated_v29_investigator_custody(tmp_path: Path) -> None:
    path = tmp_path / "v29-populated.db"
    with SQLiteStore(path) as store:
        case_id = CaseId.new()
        store.create_case(
            case_id=str(case_id),
            kind="general",
            symptom="slow PDF",
            created_at="2026-09-23T12:00:00+00:00",
        )
        repo = SearchFrontierRepository(store)
        evidence_id = EvidenceId.new()
        with store.transaction() as transaction:
            transaction.insert_evidence(
                case_id=str(case_id),
                evidence_id=str(evidence_id),
                source_id="src_" + "e" * 64,
                record_json='{"summary":"observed"}',
                captured_at="2026-09-23T12:00:00+00:00",
            )
            event = repo.append_result_event(
                case_id,
                source_evidence_id=evidence_id,
                source_execution_id=None,
                versions=RelevantVersionsV1(objective=1, evidence=2),
            )
        assert isinstance(event, FrontierEventV1)
        repo.intake_investigator_event(case_id, event.event_id)
        session = repo.start_investigator_session(case_id, event.event_id, decision_budget=2)
    with sqlite3.connect(path) as connection:
        _drop_v30_investigator_turn_schema(connection)
        connection.execute("PRAGMA user_version = 29")
    with SQLiteStore(path) as upgraded:
        repo = SearchFrontierRepository(upgraded)
        assert upgraded.schema_version() == 37
        assert repo.read_event(event.event_id) == event
        assert repo.active_investigator_session(case_id) == session
        assert repo.investigator_turns(case_id, event.event_id) == ()
        assert upgraded.connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_v30_migration_collision_rolls_back_at_v29(tmp_path: Path) -> None:
    path = tmp_path / "v29-collision.db"
    with SQLiteStore(path):
        pass
    with sqlite3.connect(path) as connection:
        _drop_v30_investigator_turn_schema(connection)
        connection.execute("PRAGMA user_version = 29")
        connection.execute(
            "CREATE TRIGGER search_frontier_investigator_turns_no_update "
            "BEFORE UPDATE ON cases BEGIN SELECT 1; END"
        )
    with pytest.raises(sqlite3.OperationalError, match="already exists"):
        SQLiteStore(path).initialize()
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (29,)
        assert (
            connection.execute(
                "SELECT 1 FROM sqlite_schema WHERE name='search_frontier_investigator_turns'"
            ).fetchone()
            is None
        )
        connection.execute("DROP TRIGGER search_frontier_investigator_turns_no_update")
    with SQLiteStore(path) as upgraded:
        assert upgraded.schema_version() == 37


def test_v29_migration_collision_rolls_back_without_partial_schema(tmp_path: Path) -> None:
    path = tmp_path / "v28-collision.db"
    with SQLiteStore(path):
        pass
    with sqlite3.connect(path) as connection:
        _drop_v29_investigator_schema(connection)
        connection.execute("PRAGMA user_version = 28")
        connection.execute(
            "CREATE TRIGGER search_frontier_investigator_triggers_no_update "
            "BEFORE UPDATE ON cases BEGIN SELECT 1; END"
        )
    with pytest.raises(sqlite3.OperationalError, match="already exists"):
        SQLiteStore(path).initialize()
    with sqlite3.connect(path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (28,)
        assert (
            connection.execute(
                "SELECT 1 FROM sqlite_schema WHERE name='search_frontier_investigator_triggers'"
            ).fetchone()
            is None
        )
        assert (
            connection.execute(
                "SELECT 1 FROM sqlite_schema WHERE name='search_frontier_events_id_case'"
            ).fetchone()
            is None
        )
        connection.execute("DROP TRIGGER search_frontier_investigator_triggers_no_update")
    with SQLiteStore(path) as upgraded:
        assert upgraded.schema_version() == 37


def test_v28_migration_preserves_old_execution_without_inventing_tree_proof(
    tmp_path: Path,
) -> None:
    database_path = tmp_path / "v27.db"
    with SQLiteStore(database_path) as store:
        store.create_case(
            case_id="case_old",
            kind="general",
            symptom="old execution",
            created_at="2026-07-30T12:00:00+00:00",
        )
    with sqlite3.connect(database_path) as connection:
        _drop_v29_investigator_schema(connection)
        connection.execute("ALTER TABLE probe_executions DROP COLUMN tree_exit_status")
        connection.execute("PRAGMA user_version=27")
    with sqlite3.connect(database_path) as connection:
        connection.execute(
            "INSERT INTO probe_executions "
            "(execution_id,case_id,probe_id,probe_version,status,parameters_json,"
            "started_at,finished_at,state_version) VALUES (?,?,?,?,?,?,?,?,?)",
            (
                "exec_old",
                "case_old",
                "fixture.echo",
                1,
                "ok",
                "{}",
                "2026-07-30T12:05:00+00:00",
                "2026-07-30T12:05:01+00:00",
                0,
            ),
        )

    with SQLiteStore(database_path) as store:
        assert store.schema_version() == 37
        previous = store.probe_execution("exec_old")
        assert previous is not None
        assert previous.tree_exit_status == "not_recorded"


def test_diagnostic_progress_is_append_only_and_bound_to_case_and_admission(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "progress.db") as store:
        connection = store.connection
        connection.execute(
            "INSERT INTO cases(case_id, kind, symptom, created_at) "
            "VALUES ('case_a', 'general', 's', 'now')"
        )
        connection.execute(
            "INSERT INTO diagnostic_intent_admissions "
            "(admission_id, case_id, intent_id, epoch_state_version, plan_instance_id, "
            "record_json, record_sha256, admitted_at) "
            "VALUES ('admission_a', 'case_a', 'intent_a', 0, 'plan_a', '{}', ?, 'now')",
            ("a" * 64,),
        )
        values = (
            "admission_a",
            "case_a",
            "branch_a",
            "b" * 64,
            "a" * 64,
            "{}",
            "c" * 64,
            "now",
        )
        insert = (
            "INSERT INTO diagnostic_progress "
            "(admission_id, case_id, branch_id, terminal_sha256, admission_sha256, "
            "record_json, record_sha256, projected_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
        )
        connection.execute(insert, values)
        assert store.schema_version() == 37
        assert connection.execute("SELECT * FROM diagnostic_progress").fetchone() == values
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(insert, values)
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(insert, ("missing", *values[1:]))
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("UPDATE diagnostic_progress SET branch_id='changed'")
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute("DELETE FROM diagnostic_progress")


def test_diagnostic_progress_migration_rolls_back_on_trigger_collision(tmp_path: Path) -> None:
    database_path = tmp_path / "progress.db"
    with SQLiteStore(database_path):
        pass
    with sqlite3.connect(database_path) as connection:
        _drop_v29_investigator_schema(connection)
        connection.execute("DROP TABLE diagnostic_progress")
        connection.execute("ALTER TABLE probe_executions DROP COLUMN tree_exit_status")
        connection.execute("PRAGMA user_version = 26")
        connection.execute(
            "CREATE TRIGGER diagnostic_progress_no_update BEFORE UPDATE ON cases "
            "BEGIN SELECT 1; END"
        )
    with pytest.raises(sqlite3.OperationalError, match="already exists"):
        SQLiteStore(database_path).initialize()
    with sqlite3.connect(database_path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (26,)
        assert (
            connection.execute(
                "SELECT 1 FROM sqlite_schema WHERE name='diagnostic_progress'"
            ).fetchone()
            is None
        )
        connection.execute("DROP TRIGGER diagnostic_progress_no_update")
    with SQLiteStore(database_path) as store:
        assert store.schema_version() == 37


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
        _drop_v29_investigator_schema(connection)
        _drop_v24_receipt_schema(connection)
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
        assert store.schema_version() == 37
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


def test_v24_receipt_migration_rolls_back_and_preserves_old_snapshot(tmp_path: Path) -> None:
    database_path = tmp_path / "v23-receipts.db"
    with SQLiteStore(database_path) as store:
        _case_id, snapshot_id, _candidate, _invocation, _registry = _setup(store)
    with sqlite3.connect(database_path, isolation_level=None) as connection:
        _drop_v29_investigator_schema(connection)
        _drop_v24_receipt_schema(connection)
        connection.execute("PRAGMA user_version = 23")
        connection.commit()
        migration = (
            Path(__file__).parents[3]
            / "src"
            / "systemsense"
            / "storage"
            / "migrations"
            / "024_frontier_packet_receipts.sql"
        ).read_text(encoding="utf-8")
        with pytest.raises(sqlite3.OperationalError, match="no such table"):
            connection.executescript(
                "BEGIN IMMEDIATE;\n"
                + migration
                + "\nINSERT INTO missing_receipt_migration_table VALUES (1);\nCOMMIT;"
            )
        if connection.in_transaction:
            connection.rollback()
        assert connection.execute("PRAGMA user_version").fetchone() == (23,)
        assert (
            connection.execute(
                "SELECT name FROM sqlite_schema WHERE name='frontier_packet_receipts'"
            ).fetchone()
            is None
        )
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []

    with SQLiteStore(database_path) as store:
        assert store.schema_version() == 37
        assert (
            CandidateDecisionSnapshotRepository(store).readback(snapshot_id).snapshot_id
            == snapshot_id
        )
        assert store.connection.execute("PRAGMA foreign_key_check").fetchall() == []
        assert store.integrity_check() == "ok"


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

        assert store.schema_version() == 37
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
        assert store.schema_version() == 37
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
        _drop_v30_investigator_turn_schema(connection)
        connection.execute("DROP TABLE search_frontier_investigator_terminals")
        connection.execute("DROP TABLE search_frontier_investigator_active_sessions")
        connection.execute("DROP TABLE search_frontier_investigator_sessions")
        connection.execute("DROP TABLE search_frontier_investigator_event_acks")
        connection.execute("DROP TABLE search_frontier_investigator_triggers")
        connection.execute("DROP TABLE search_frontier_event_acks")
        connection.execute("DROP TABLE search_frontier_event_overflows")
        connection.execute("DROP TABLE search_frontier_transitions")
        connection.execute("DROP TABLE search_frontier_events")
        connection.execute("DROP TABLE search_frontier_items")
        connection.execute("DROP TABLE candidate_dispatch_claims")
        connection.execute("DROP TABLE candidate_dispatch_admissions")
        _drop_v24_receipt_schema(connection)
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

        assert store.schema_version() == 37
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
        _drop_v24_receipt_schema(connection)
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
        connection.execute("PRAGMA user_version = 38")

    with pytest.raises(sqlite3.DatabaseError, match="newer than supported"):
        SQLiteStore(database_path).initialize()

    with sqlite3.connect(database_path) as connection:
        assert connection.execute("PRAGMA user_version").fetchone() == (38,)


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
