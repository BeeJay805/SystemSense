import sqlite3
import threading
from pathlib import Path

import pytest

from systemsense.audit import AuditChain, AuditEntry, AuditOutcome
from systemsense.domain.ids import CaseId
from systemsense.storage.sqlite_store import (
    SQLiteStore,
    StaleAuditHeadError,
    StaleCaseStateError,
)
from systemsense.storage.writer import SingleWriter

_NOW = "2026-07-30T12:00:00+00:00"


def _seed_case(store: SQLiteStore) -> None:
    store.create_case(
        case_id="case_0123456789abcdef0123456789abcdef",
        kind="application",
        symptom="App fails during startup",
        created_at=_NOW,
    )


def _append_audit_entry(store: SQLiteStore, entry: AuditEntry) -> None:
    occurred_at = entry.occurred_at.isoformat()
    with store.transaction() as transaction:
        transaction.append_audit(
            event_id=entry.event_id,
            case_id=None if entry.case_id is None else str(entry.case_id),
            event_json=entry.model_dump_json(),
            created_at=occurred_at,
            occurred_at=occurred_at,
            persisted_at=occurred_at,
        )


def test_single_writer_thread_owns_write_connection(tmp_path: Path) -> None:
    caller_thread = threading.get_ident()

    with SingleWriter(tmp_path / "systemsense.db") as writer:
        writer_threads = {
            writer.execute(lambda _store: threading.get_ident()) for _index in range(3)
        }

    assert len(writer_threads) == 1
    assert caller_thread not in writer_threads


def test_transaction_commits_evidence_inventory_audit_and_bookmark(tmp_path: Path) -> None:
    with SingleWriter(tmp_path / "systemsense.db") as writer:
        writer.execute(_seed_case)

        def persist(store: SQLiteStore) -> None:
            audit_entry = AuditChain().append(
                event_id="audit-1",
                case_id=CaseId(root="case_0123456789abcdef0123456789abcdef"),
                probe_id="core.resources",
                outcome=AuditOutcome.ALLOWED,
            )
            with store.transaction() as transaction:
                assert transaction.insert_evidence(
                    case_id="case_0123456789abcdef0123456789abcdef",
                    evidence_id="evidence_0123456789abcdef0123456789abcdef",
                    source_id=f"src_{'a' * 64}",
                    record_json='{"summary":"failure event"}',
                    captured_at=_NOW,
                )
                transaction.upsert_inventory(
                    category="system",
                    fact_key="windows.build",
                    record_json='{"value":"26100"}',
                    observed_at=_NOW,
                )
                transaction.append_audit(
                    event_id=audit_entry.event_id,
                    case_id="case_0123456789abcdef0123456789abcdef",
                    event_json=audit_entry.model_dump_json(),
                    created_at=audit_entry.occurred_at.isoformat(),
                    occurred_at=audit_entry.occurred_at.isoformat(),
                    persisted_at=audit_entry.occurred_at.isoformat(),
                )
                transaction.advance_bookmark(
                    source="eventlog.application",
                    position="bookmark-7",
                    updated_at=_NOW,
                )

        writer.execute(persist)
        counts = writer.execute(lambda store: store.record_counts())
        bookmark = writer.execute(lambda store: store.bookmark("eventlog.application"))

    assert counts == {
        "evidence": 1,
        "inventory_current": 1,
        "inventory_history": 1,
        "audit_events": 1,
    }
    assert bookmark == "bookmark-7"


def test_failed_evidence_rolls_back_advanced_bookmark(tmp_path: Path) -> None:
    with SingleWriter(tmp_path / "systemsense.db") as writer:
        writer.execute(_seed_case)

        def fail_persistence(store: SQLiteStore) -> None:
            with store.transaction() as transaction:
                transaction.advance_bookmark(
                    source="eventlog.application",
                    position="bookmark-8",
                    updated_at=_NOW,
                )
                transaction.insert_evidence(
                    case_id="case_0123456789abcdef0123456789abcdef",
                    evidence_id="evidence_0123456789abcdef0123456789abcdef",
                    source_id=f"src_{'b' * 64}",
                    record_json="not valid JSON",
                    captured_at=_NOW,
                )

        with pytest.raises(sqlite3.IntegrityError):
            writer.execute(fail_persistence)

        assert writer.execute(lambda store: store.bookmark("eventlog.application")) is None
        assert writer.execute(lambda store: store.record_counts()["evidence"]) == 0


def test_duplicate_stable_source_id_is_idempotent_and_bookmark_advances(
    tmp_path: Path,
) -> None:
    with SingleWriter(tmp_path / "systemsense.db") as writer:
        writer.execute(_seed_case)

        def persist(store: SQLiteStore, evidence_id: str, bookmark: str) -> bool:
            with store.transaction() as transaction:
                inserted = transaction.insert_evidence(
                    case_id="case_0123456789abcdef0123456789abcdef",
                    evidence_id=evidence_id,
                    source_id=f"src_{'c' * 64}",
                    record_json='{"summary":"same source"}',
                    captured_at=_NOW,
                )
                transaction.advance_bookmark(
                    source="eventlog.application",
                    position=bookmark,
                    updated_at=_NOW,
                )
            return inserted

        assert writer.execute(
            lambda store: persist(
                store,
                "evidence_0123456789abcdef0123456789abcdef",
                "bookmark-9",
            )
        )
        assert not writer.execute(
            lambda store: persist(
                store,
                "evidence_fedcba9876543210fedcba9876543210",
                "bookmark-10",
            )
        )
        assert writer.execute(lambda store: store.record_counts()["evidence"]) == 1
        assert writer.execute(lambda store: store.bookmark("eventlog.application")) == "bookmark-10"


def test_distinct_observations_from_same_source_are_preserved(tmp_path: Path) -> None:
    with SingleWriter(tmp_path / "systemsense.db") as writer:
        writer.execute(_seed_case)

        def persist(store: SQLiteStore, evidence_id: str, dedupe_key: str) -> bool:
            with store.transaction() as transaction:
                return transaction.insert_evidence(
                    case_id="case_0123456789abcdef0123456789abcdef",
                    evidence_id=evidence_id,
                    source_id=f"src_{'d' * 64}",
                    record_json='{"summary":"snapshot"}',
                    observed_at=_NOW,
                    captured_at=_NOW,
                    dedupe_key=dedupe_key,
                    time_basis="snapshot",
                    time_quality="exact",
                )

        assert writer.execute(
            lambda store: persist(
                store,
                "evidence_0123456789abcdef0123456789abcdef",
                "run-1",
            )
        )
        assert writer.execute(
            lambda store: persist(
                store,
                "evidence_fedcba9876543210fedcba9876543210",
                "run-2",
            )
        )
        assert not writer.execute(
            lambda store: persist(
                store,
                "evidence_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "run-2",
            )
        )
        assert writer.execute(lambda store: store.record_counts()["evidence"]) == 2


def test_out_of_order_inventory_does_not_replace_newer_current_value(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        with store.transaction() as transaction:
            transaction.upsert_inventory(
                category="core",
                fact_key="host:resources",
                record_json='{"value":{"cpu":20}}',
                observed_at="2026-07-30T12:05:00+00:00",
            )
        with store.transaction() as transaction:
            transaction.upsert_inventory(
                category="core",
                fact_key="host:resources",
                record_json='{"value":{"cpu":10}}',
                observed_at="2026-07-30T12:04:00+00:00",
            )

        current = store.inventory_record(category="core", fact_key="host:resources")

        assert current == '{"value":{"cpu":20}}'
        assert store.inventory_history_count(category="core", fact_key="host:resources") == 2


def test_inventory_ordering_compares_absolute_instants_across_offsets(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        with store.transaction() as transaction:
            transaction.upsert_inventory(
                category="core",
                fact_key="host:resources",
                record_json='{"value":{"cpu":20}}',
                observed_at="2026-07-30T12:00:00+00:00",
            )
        with store.transaction() as transaction:
            # 13:00 at UTC+02:00 is 11:00 UTC, older than the current value.
            transaction.upsert_inventory(
                category="core",
                fact_key="host:resources",
                record_json='{"value":{"cpu":10}}',
                observed_at="2026-07-30T13:00:00+02:00",
            )

        assert store.inventory_record(category="core", fact_key="host:resources") == (
            '{"value":{"cpu":20}}'
        )

        with store.transaction() as transaction:
            # 10:00 at UTC-03:00 is 13:00 UTC, newer despite its clock text.
            transaction.upsert_inventory(
                category="core",
                fact_key="host:resources",
                record_json='{"value":{"cpu":30}}',
                observed_at="2026-07-30T10:00:00-03:00",
            )

        assert store.inventory_record(category="core", fact_key="host:resources") == (
            '{"value":{"cpu":30}}'
        )


@pytest.mark.parametrize(
    "observed_at",
    ["2026-07-30T12:00:00", "not-a-timestamp", "2026-07-30T12:00:00+99:00"],
)
def test_inventory_rejects_naive_or_invalid_observation_time(
    tmp_path: Path,
    observed_at: str,
) -> None:
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        with pytest.raises(ValueError, match="timezone-aware ISO"):
            with store.transaction() as transaction:
                transaction.upsert_inventory(
                    category="core",
                    fact_key="host:resources",
                    record_json='{"value":20}',
                    observed_at=observed_at,
                )


def test_inventory_rejects_naive_capture_time(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        with pytest.raises(ValueError, match="timezone-aware ISO"):
            with store.transaction() as transaction:
                transaction.upsert_inventory(
                    category="core",
                    fact_key="host:resources",
                    record_json='{"value":20}',
                    observed_at="2026-07-30T12:00:00+00:00",
                    captured_at="2026-07-30T12:00:01",
                )


def test_case_scoped_audit_entries_survive_close_reopen_and_verify(
    tmp_path: Path,
) -> None:
    database = tmp_path / "systemsense.db"
    case_id = "case_0123456789abcdef0123456789abcdef"
    chain = AuditChain()
    first = chain.append(
        event_id="audit-1",
        case_id=CaseId(root=case_id),
        probe_id="core.resources",
        outcome=AuditOutcome.ALLOWED,
    )
    second = chain.append(
        event_id="audit-2",
        case_id=CaseId(root=case_id),
        probe_id="eventlog.application",
        outcome=AuditOutcome.FAILED,
        error="redacted failure",
    )

    with SQLiteStore(database) as store:
        _seed_case(store)
        with store.transaction() as transaction:
            for entry in chain.entries:
                transaction.append_audit(
                    event_id=entry.event_id,
                    case_id=case_id,
                    event_json=entry.model_dump_json(),
                    created_at=entry.occurred_at.isoformat(),
                    occurred_at=entry.occurred_at.isoformat(),
                )
        checkpoint = chain.checkpoint()

    with SQLiteStore(database) as store:
        entries = store.audit_entries(case_id=case_id, limit=10)

    assert entries == (first, second)
    assert AuditChain.verify(entries, checkpoint=checkpoint).valid


def test_stale_competing_audit_candidate_is_rejected_without_insert(
    tmp_path: Path,
) -> None:
    case_id = "case_0123456789abcdef0123456789abcdef"
    original = AuditChain()
    first = original.append(
        event_id="audit-1",
        case_id=CaseId(root=case_id),
        probe_id="core.resources",
        outcome=AuditOutcome.ALLOWED,
    )
    first_checkpoint = original.checkpoint()
    accepted_chain = AuditChain.from_verified_entries((first,), checkpoint=first_checkpoint)
    accepted = accepted_chain.append(
        event_id="audit-accepted",
        case_id=CaseId(root=case_id),
        probe_id="eventlog.application",
        outcome=AuditOutcome.ALLOWED,
    )
    stale_chain = AuditChain.from_verified_entries((first,), checkpoint=first_checkpoint)
    stale = stale_chain.append(
        event_id="audit-stale",
        case_id=CaseId(root=case_id),
        probe_id="eventlog.system",
        outcome=AuditOutcome.FAILED,
    )

    with SQLiteStore(tmp_path / "systemsense.db") as store:
        _seed_case(store)
        _append_audit_entry(store, first)
        _append_audit_entry(store, accepted)

        with pytest.raises(StaleAuditHeadError, match="audit head"):
            _append_audit_entry(store, stale)

        assert store.audit_entries(case_id=case_id) == (first, accepted)
        assert store.audit_count(case_id=case_id) == 2
        assert store.audit_checkpoint(case_id=case_id) == accepted_chain.checkpoint()


def test_append_audit_rejects_unbound_typed_entry(tmp_path: Path) -> None:
    case_id = "case_0123456789abcdef0123456789abcdef"
    entry = AuditChain().append(
        event_id="audit-1",
        case_id=CaseId(root=case_id),
        probe_id="core.resources",
        outcome=AuditOutcome.ALLOWED,
    )

    with SQLiteStore(tmp_path / "systemsense.db") as store:
        _seed_case(store)
        with pytest.raises(ValueError, match="event_id"):
            with store.transaction() as transaction:
                transaction.append_audit(
                    event_id="different-event",
                    case_id=case_id,
                    event_json=entry.model_dump_json(),
                    created_at=entry.occurred_at.isoformat(),
                    occurred_at=entry.occurred_at.isoformat(),
                    persisted_at=entry.occurred_at.isoformat(),
                )

        assert store.audit_count(case_id=case_id) == 0


def test_case_state_guard_rejects_stale_writes(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        _seed_case(store)
        with store.transaction() as transaction:
            transaction.require_case_state(
                case_id="case_0123456789abcdef0123456789abcdef",
                expected_state_version=0,
            )
            assert (
                transaction.transition_case(
                    case_id="case_0123456789abcdef0123456789abcdef",
                    expected_state_version=0,
                    status="ready",
                )
                == 1
            )
        with pytest.raises(StaleCaseStateError):
            with store.transaction() as transaction:
                transaction.require_case_state(
                    case_id="case_0123456789abcdef0123456789abcdef",
                    expected_state_version=0,
                )


def test_probe_execution_attempt_is_persisted_with_state_and_real_times(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        _seed_case(store)
        with store.transaction() as transaction:
            transaction.record_probe_execution(
                execution_id="exec_0123456789abcdef0123456789abcdef",
                case_id="case_0123456789abcdef0123456789abcdef",
                probe_id="core.resources",
                probe_version=2,
                status="ok",
                parameters_json="{}",
                started_at="2026-07-30T12:05:00+00:00",
                finished_at="2026-07-30T12:05:01+00:00",
                state_version=3,
                tree_exit_status="verified_empty",
            )

        assert store.probe_execution_count(case_id="case_0123456789abcdef0123456789abcdef") == 1
        execution = store.probe_execution("exec_0123456789abcdef0123456789abcdef")
        assert execution is not None
        assert execution.started_at == "2026-07-30T12:05:00+00:00"
        assert execution.finished_at == "2026-07-30T12:05:01+00:00"
        assert execution.state_version == 3
        assert execution.tree_exit_status == "verified_empty"

        with store.transaction() as transaction:
            transaction.record_probe_execution(
                execution_id="exec_ffffffffffffffffffffffffffffffff",
                case_id="case_0123456789abcdef0123456789abcdef",
                probe_id="core.resources",
                probe_version=2,
                status="ok",
                parameters_json="{}",
                started_at="2026-07-30T12:06:00+00:00",
                finished_at="2026-07-30T12:06:01+00:00",
                state_version=3,
            )
        no_job = store.probe_execution("exec_ffffffffffffffffffffffffffffffff")
        assert no_job is not None
        assert no_job.tree_exit_status == "not_tracked"


def test_case_transition_uses_optimistic_state_version(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "systemsense.db") as store:
        _seed_case(store)
        with store.transaction() as transaction:
            assert (
                transaction.transition_case(
                    case_id="case_0123456789abcdef0123456789abcdef",
                    expected_state_version=0,
                    status="ready",
                )
                == 1
            )

        with pytest.raises(StaleCaseStateError):
            with store.transaction() as transaction:
                transaction.transition_case(
                    case_id="case_0123456789abcdef0123456789abcdef",
                    expected_state_version=0,
                    status="complete",
                )

        persisted = store.case("case_0123456789abcdef0123456789abcdef")
        assert persisted is not None
        assert persisted.status == "ready"
        assert persisted.state_version == 1
