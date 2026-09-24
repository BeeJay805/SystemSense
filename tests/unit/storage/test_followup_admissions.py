"""Same-epoch follow-up provenance is durable, bounded, and never replay authority."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from systemsense.domain.evidence import (
    CollectorReference,
    EvidenceRecord,
    EvidenceSource,
    Extraction,
    Sensitivity,
    StatementKind,
)
from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId, stable_source_id
from systemsense.domain.probes import ProbeInvocation
from systemsense.storage.followup_admissions import FollowupAdmissionRepository
from systemsense.storage.presented_read_set import (
    PresentedReadSetV1,
    capture_presented_read_set,
)
from systemsense.storage.sqlite_store import SQLiteStore, StaleCaseStateError

_CREATED = datetime(2026, 1, 1, 0, 0, tzinfo=UTC)
_PARENT_START = datetime(2026, 1, 1, 0, 0, 1, tzinfo=UTC)
_PARENT_END = datetime(2026, 1, 1, 0, 0, 2, tzinfo=UTC)
_ADMITTED = datetime(2026, 1, 1, 0, 0, 3, tzinfo=UTC)
_CHILD_START = datetime(2026, 1, 1, 0, 0, 4, tzinfo=UTC)
_CHILD_END = datetime(2026, 1, 1, 0, 0, 5, tzinfo=UTC)
_EPOCH = 7
_CASE_A = "case_" + "a" * 32
_PARENT_A = "exec_" + "a" * 32
_CHILD = "exec_" + "c" * 32
_EVIDENCE_A = "ev_" + "a" * 32


def _invocation() -> ProbeInvocation:
    return ProbeInvocation(
        probe_id="fixture.child", probe_version=1, observable="fixture.child", parameters={}
    )


def _repo(store: SQLiteStore) -> FollowupAdmissionRepository:
    return FollowupAdmissionRepository(store, now=lambda: _ADMITTED)


def _case_with_parent(
    store: SQLiteStore,
    *,
    case_id: str = "case_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    max_probes: int = 3,
    budget_ms: int = 100,
) -> int:
    execution_id = f"exec_{case_id.removeprefix('case_')}"
    evidence_id = f"ev_{case_id.removeprefix('case_')}"
    source_id = stable_source_id("fixture.parent", {"case_id": case_id})
    record = EvidenceRecord(
        evidence_id=EvidenceId(root=evidence_id),
        case_id=CaseId(root=case_id),
        statement_kind=StatementKind.OBSERVED_FACT,
        observed_at=_PARENT_END,
        captured_at=_PARENT_END,
        source=EvidenceSource(type="fixture.parent", source_id=source_id, locator={}),
        collector=CollectorReference(
            id="fixture.parent", version=1, execution_id=ExecutionId(root=execution_id)
        ),
        summary="Fixture parent observation",
        extraction=Extraction(confidence=1.0, parser="fixture.parent", parser_version=1),
        sensitivity=Sensitivity.SYSTEM_METADATA,
    )
    store.create_case(
        case_id=case_id,
        kind="general",
        symptom="synthetic",
        created_at=_CREATED.isoformat(),
        status="collecting",
        state_version=_EPOCH,
    )
    store.connection.execute(
        "INSERT INTO investigation_checkpoints (case_id,record_json) VALUES (?,?)",
        (
            case_id,
            json.dumps(
                {
                    "case_id": case_id,
                    "state_version": _EPOCH,
                    "status": "running",
                    "deadline_at": datetime(2026, 1, 1, 0, 10, tzinfo=UTC).isoformat(),
                    "budget_ms": budget_ms,
                    "spent_cost_ms": 10,
                    "max_probes": max_probes,
                    "completed_probe_ids": [],
                    "pending_probe_ids": ["fixture.parent"],
                    "interrupted_probe_ids": [],
                    "unrecorded_attempt_count": 0,
                }
            ),
        ),
    )
    with store.transaction() as transaction:
        transaction.record_probe_execution(
            execution_id=execution_id,
            case_id=case_id,
            probe_id="fixture.parent",
            probe_version=1,
            status="ok",
            parameters_json="{}",
            started_at=_PARENT_START.isoformat(),
            finished_at=_PARENT_END.isoformat(),
            state_version=_EPOCH,
        )
        store.connection.execute(
            "INSERT INTO evidence (evidence_id,case_id,source_id,record_json,observed_at,"
            "captured_at,execution_id,dedupe_key,time_basis,time_quality) "
            "VALUES (?,?,?,?,?,?,?,?,?,?)",
            (
                evidence_id,
                case_id,
                source_id,
                record.model_dump_json(),
                _PARENT_END.isoformat(),
                _PARENT_END.isoformat(),
                execution_id,
                f"fixture.parent:{case_id}",
                "source_observed",
                "exact",
            ),
        )
    row = store.connection.execute(
        "SELECT generation FROM evidence_case_generations WHERE case_id=?", (case_id,)
    ).fetchone()
    assert row is not None
    return int(row[0])


def _admit(
    repo: FollowupAdmissionRepository,
    generation: int,
    *,
    case_id: str = "case_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    task_id: str = "followup-child",
    invocation: ProbeInvocation | None = None,
    estimated_cost_ms: int = 10,
    expected_trigger_evidence_sha256: str | None = None,
    presented_read_set: PresentedReadSetV1 | None = None,
) -> str:
    trigger_execution_id = f"exec_{case_id.removeprefix('case_')}"
    return repo.admit(
        case_id=case_id,
        epoch_state_version=_EPOCH,
        trigger_execution_id=trigger_execution_id,
        expected_evidence_generation=generation,
        expected_trigger_evidence_sha256=(
            expected_trigger_evidence_sha256
            or repo.parent_evidence_digest(case_id, trigger_execution_id)
        ),
        request_sha256="a" * 64,
        decision_snapshot_id=None,
        invocation=invocation or _invocation(),
        task_id=task_id,
        estimated_cost_ms=estimated_cost_ms,
        presented_read_set=presented_read_set,
    ).admission_id


def _add_non_parent_evidence(store: SQLiteStore) -> str:
    evidence_id = "ev_" + "b" * 32
    row = store.connection.execute(
        "SELECT source_id,record_json FROM evidence WHERE evidence_id=?", (_EVIDENCE_A,)
    ).fetchone()
    assert row is not None
    record = EvidenceRecord.model_validate_json(str(row[1])).model_copy(
        update={"evidence_id": EvidenceId(root=evidence_id), "summary": "Other observation"}
    )
    store.connection.execute(
        "INSERT INTO evidence (evidence_id,case_id,source_id,record_json,observed_at,"
        "captured_at,execution_id,dedupe_key,time_basis,time_quality) "
        "VALUES (?,?,?,?,?,?,?,?,?,?)",
        (
            evidence_id,
            _CASE_A,
            str(row[0]),
            record.model_dump_json(),
            _PARENT_END.isoformat(),
            _PARENT_END.isoformat(),
            None,
            "fixture.other",
            "source_observed",
            "exact",
        ),
    )
    return evidence_id


def test_presented_read_set_allows_unrelated_append_and_records_atomic_check(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "read-set.db") as store:
        generation = _case_with_parent(store)
        read_set = capture_presented_read_set(
            store, CaseId(root=_CASE_A), (EvidenceId(root=_EVIDENCE_A),)
        )
        _add_non_parent_evidence(store)
        admission_id = _admit(_repo(store), generation, presented_read_set=read_set)
        readback = _repo(store).readback(case_id=_CASE_A, epoch_state_version=_EPOCH)[0]
        assert readback.admission_id == admission_id
        assert readback.presented_read_set_sha256 == read_set.read_set_sha256
        assert readback.checked_read_set_generation is not None
        assert readback.checked_read_set_generation > read_set.case_generation
        assert readback.frozen_read_set_generation == read_set.case_generation


def test_changed_non_parent_presented_evidence_rejects_admission_atomically(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "changed-read-set.db") as store:
        generation = _case_with_parent(store)
        other = _add_non_parent_evidence(store)
        read_set = capture_presented_read_set(
            store,
            CaseId(root=_CASE_A),
            (EvidenceId(root=_EVIDENCE_A), EvidenceId(root=other)),
        )
        store.connection.execute(
            "UPDATE evidence SET captured_at=? WHERE evidence_id=?",
            (_CHILD_START.isoformat(), other),
        )
        with pytest.raises(ValueError, match="presented evidence changed"):
            _admit(_repo(store), generation, presented_read_set=read_set)
        assert not store.connection.execute(
            "SELECT 1 FROM collection_followup_admissions WHERE case_id=?", (_CASE_A,)
        ).fetchone()
        assert not store.connection.execute(
            "SELECT 1 FROM collection_followup_read_set_checks WHERE case_id=?", (_CASE_A,)
        ).fetchone()


def test_presented_read_set_check_is_immutable_and_readback_detects_tamper(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "check-integrity.db") as store:
        generation = _case_with_parent(store)
        read_set = capture_presented_read_set(
            store, CaseId(root=_CASE_A), (EvidenceId(root=_EVIDENCE_A),)
        )
        admission_id = _admit(_repo(store), generation, presented_read_set=read_set)
        with pytest.raises(Exception, match="immutable"):
            store.connection.execute(
                "UPDATE collection_followup_read_set_checks SET checked_generation=99 "
                "WHERE admission_id=?",
                (admission_id,),
            )
        store.connection.execute("DROP TRIGGER collection_followup_read_set_checks_no_update")
        store.connection.execute(
            "UPDATE collection_followup_read_set_checks SET read_set_sha256=? WHERE admission_id=?",
            ("f" * 64, admission_id),
        )
        with pytest.raises(ValueError, match="read-set check binding"):
            _repo(store).readback(case_id=_CASE_A, epoch_state_version=_EPOCH)


def _child_execution(
    store: SQLiteStore,
    *,
    case_id: str = "case_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    started_at: datetime = _CHILD_START,
) -> None:
    with store.transaction() as transaction:
        transaction.record_probe_execution(
            execution_id="exec_cccccccccccccccccccccccccccccccc",
            case_id=case_id,
            probe_id="fixture.child",
            probe_version=1,
            status="ok",
            parameters_json="{}",
            started_at=started_at.isoformat(),
            finished_at=_CHILD_END.isoformat(),
            state_version=_EPOCH,
        )


def test_admission_is_uncertain_until_atomic_child_outcome_link(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        generation = _case_with_parent(store)
        repo = _repo(store)
        admission_id = _admit(repo, generation)
        before = repo.readback(
            case_id="case_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", epoch_state_version=_EPOCH
        )
        assert len(before) == 1
        assert before[0].admission_id == admission_id
        assert before[0].evidence_generation == generation
        assert before[0].estimated_cost_ms == 10
        assert before[0].admitted_at == _ADMITTED
        assert len(before[0].trigger_evidence_sha256) == 64
        assert before[0].dedupe_key == _invocation().dedupe_key
        assert before[0].outcome_status == "uncertain"
        assert before[0].execution_id is None
        assert before[0].replay_allowed is False
        with store.transaction() as transaction:
            transaction.record_probe_execution(
                execution_id="exec_cccccccccccccccccccccccccccccccc",
                case_id="case_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                probe_id="fixture.child",
                probe_version=1,
                status="failed",
                parameters_json="{}",
                started_at=_CHILD_START.isoformat(),
                finished_at=_CHILD_END.isoformat(),
                state_version=_EPOCH,
                followup_admission_id=admission_id,
            )
            repo.link_execution(
                admission_id=admission_id, execution_id="exec_cccccccccccccccccccccccccccccccc"
            )
        after = repo.readback(
            case_id="case_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", epoch_state_version=_EPOCH
        )
        assert after[0].execution_id == "exec_cccccccccccccccccccccccccccccccc"
        assert after[0].outcome_status == "failed"
        assert after[0].replay_allowed is False


def test_ok_parent_with_coverage_only_cannot_admit_followup(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "coverage-only.db") as store:
        generation = _case_with_parent(store)
        store.connection.execute(
            "UPDATE evidence SET record_json=? WHERE execution_id=?",
            (
                json.dumps(
                    {
                        "schema_version": 1,
                        "status": "unavailable",
                        "category": "core",
                        "reason": "collector returned no observation",
                    }
                ),
                "exec_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            ),
        )
        current = store.connection.execute(
            "SELECT generation FROM evidence_case_generations WHERE case_id=?",
            ("case_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",),
        ).fetchone()
        assert current is not None
        generation = int(current[0])
        with pytest.raises(ValueError, match="observation"):
            _admit(_repo(store), generation)


def test_admission_rejects_stale_cross_case_failed_parent_and_duplicates(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        generation = _case_with_parent(store)
        _case_with_parent(store, case_id="case_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
        repo = _repo(store)
        with pytest.raises(ValueError, match="parent"):
            repo.admit(
                case_id="case_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
                epoch_state_version=_EPOCH,
                trigger_execution_id="exec_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                expected_evidence_generation=generation,
                expected_trigger_evidence_sha256=repo.parent_evidence_digest(_CASE_A, _PARENT_A),
                request_sha256="a" * 64,
                decision_snapshot_id=None,
                invocation=_invocation(),
                task_id="cross-case",
                estimated_cost_ms=10,
            )
        with pytest.raises(ValueError, match="generation"):
            _admit(repo, generation + 1)
        _admit(repo, generation)
        with pytest.raises(ValueError, match="duplicate"):
            _admit(repo, generation, task_id="another-task")
        store.connection.execute(
            "UPDATE cases SET state_version=? WHERE case_id=?",
            (_EPOCH + 1, _CASE_A),
        )
        with pytest.raises(StaleCaseStateError, match="case state changed"):
            _admit(repo, generation, task_id="stale-task")


def test_admission_accepts_newer_unrelated_generation_but_rejects_parent_change(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        generation = _case_with_parent(store)
        repo = _repo(store)
        frozen_digest = repo.parent_evidence_digest(_CASE_A, _PARENT_A)
        store.connection.execute(
            "UPDATE evidence SET captured_at=captured_at WHERE evidence_id=?", (_EVIDENCE_A,)
        )
        _admit(repo, generation, expected_trigger_evidence_sha256=frozen_digest)

    with SQLiteStore(tmp_path / "changed.db") as store:
        generation = _case_with_parent(store)
        repo = _repo(store)
        frozen_digest = repo.parent_evidence_digest(_CASE_A, _PARENT_A)
        row = store.connection.execute(
            "SELECT record_json FROM evidence WHERE evidence_id=?", (_EVIDENCE_A,)
        ).fetchone()
        assert row is not None
        changed = json.loads(str(row[0]))
        changed["summary"] = "Changed after freeze"
        store.connection.execute(
            "UPDATE evidence SET record_json=? WHERE evidence_id=?",
            (json.dumps(changed), _EVIDENCE_A),
        )
        with pytest.raises(ValueError, match="parent evidence"):
            _admit(repo, generation, expected_trigger_evidence_sha256=frozen_digest)


def test_failed_link_rolls_back_child_and_never_infers_outcome(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        generation = _case_with_parent(store)
        repo = _repo(store)
        admission_id = _admit(repo, generation)
        with pytest.raises(ValueError, match="chronology"):
            with store.transaction() as transaction:
                transaction.record_probe_execution(
                    execution_id="exec_cccccccccccccccccccccccccccccccc",
                    case_id="case_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    probe_id="fixture.child",
                    probe_version=1,
                    status="ok",
                    parameters_json="{}",
                    started_at=_PARENT_END.isoformat(),
                    finished_at=_CHILD_END.isoformat(),
                    state_version=_EPOCH,
                    followup_admission_id=admission_id,
                )
                repo.link_execution(
                    admission_id=admission_id, execution_id="exec_cccccccccccccccccccccccccccccccc"
                )
        assert (
            store.connection.execute(
                "SELECT 1 FROM probe_executions WHERE execution_id=?",
                (_CHILD,),
            ).fetchone()
            is None
        )
        assert (
            repo.readback(
                case_id="case_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", epoch_state_version=_EPOCH
            )[0].outcome_status
            == "uncertain"
        )


def test_link_requires_write_transaction_and_exact_invocation(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        generation = _case_with_parent(store)
        repo = _repo(store)
        admission_id = _admit(repo, generation)
        _child_execution(store)
        with pytest.raises(ValueError, match="transaction"):
            repo.link_execution(
                admission_id=admission_id, execution_id="exec_cccccccccccccccccccccccccccccccc"
            )
        store.connection.execute(
            "UPDATE probe_executions SET parameters_json=? WHERE execution_id=?",
            ('{"unexpected":true}', "exec_cccccccccccccccccccccccccccccccc"),
        )
        with pytest.raises(ValueError, match="invocation"):
            with store.transaction():
                repo.link_execution(
                    admission_id=admission_id, execution_id="exec_cccccccccccccccccccccccccccccccc"
                )


def test_preexisting_generic_run_cannot_be_retroactively_linked(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        generation = _case_with_parent(store)
        repo = _repo(store)
        admission_id = _admit(repo, generation)
        _child_execution(store)
        with pytest.raises(ValueError, match="admission identity"):
            with store.transaction():
                repo.link_execution(
                    admission_id=admission_id, execution_id="exec_cccccccccccccccccccccccccccccccc"
                )


def test_parent_must_have_successful_durable_evidence(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "failed.db") as store:
        generation = _case_with_parent(store)
        store.connection.execute(
            "UPDATE probe_executions SET status='failed' WHERE execution_id=?",
            (_PARENT_A,),
        )
        with pytest.raises(ValueError, match="parent"):
            _admit(_repo(store), generation)
    with SQLiteStore(tmp_path / "empty.db") as store:
        _case_with_parent(store)
        store.connection.execute(
            "DELETE FROM evidence WHERE case_id='case_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'"
        )
        generation_row = store.connection.execute(
            "SELECT generation FROM evidence_case_generations WHERE case_id=?",
            (_CASE_A,),
        ).fetchone()
        assert generation_row is not None
        with pytest.raises(ValueError, match="persisted evidence"):
            _admit(_repo(store), int(generation_row[0]))


def test_outcome_link_rejects_case_epoch_change(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        generation = _case_with_parent(store)
        repo = _repo(store)
        admission_id = _admit(repo, generation)
        store.connection.execute(
            "UPDATE cases SET state_version=8 WHERE case_id='case_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'"
        )
        with pytest.raises(ValueError, match="epoch"):
            with store.transaction() as transaction:
                transaction.record_probe_execution(
                    execution_id="exec_cccccccccccccccccccccccccccccccc",
                    case_id="case_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                    probe_id="fixture.child",
                    probe_version=1,
                    status="ok",
                    parameters_json="{}",
                    started_at=_CHILD_START.isoformat(),
                    finished_at=_CHILD_END.isoformat(),
                    state_version=_EPOCH,
                    followup_admission_id=admission_id,
                )
                repo.link_execution(
                    admission_id=admission_id, execution_id="exec_cccccccccccccccccccccccccccccccc"
                )


def test_admission_atomically_reserves_cost_and_probe_slot(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cost.db") as store:
        generation = _case_with_parent(store, budget_ms=100, max_probes=3)
        repo = _repo(store)
        _admit(repo, generation, estimated_cost_ms=60)
        other_invocation = _invocation().model_copy(update={"parameters": {"sample": 2}})
        with pytest.raises(ValueError, match="cost"):
            _admit(
                repo,
                generation,
                task_id="followup-second",
                invocation=other_invocation,
                estimated_cost_ms=40,
            )
    with SQLiteStore(tmp_path / "slots.db") as store:
        generation = _case_with_parent(store, max_probes=2)
        repo = _repo(store)
        _admit(repo, generation)
        with pytest.raises(ValueError, match="slot"):
            _admit(
                repo,
                generation,
                task_id="followup-second",
                invocation=other_invocation,
            )


def test_repository_clock_enforces_case_deadline(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        generation = _case_with_parent(store)
        repo = FollowupAdmissionRepository(
            store, now=lambda: datetime(2026, 1, 1, 0, 11, tzinfo=UTC)
        )
        with pytest.raises(ValueError, match="deadline"):
            _admit(repo, generation)


def test_admission_clock_is_sampled_after_write_lock(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        generation = _case_with_parent(store)
        observed_lock_states: list[bool] = []

        def after_lock_clock() -> datetime:
            observed_lock_states.append(store.connection.in_transaction)
            return _ADMITTED

        repo = FollowupAdmissionRepository(store, now=after_lock_clock)
        _admit(repo, generation)
        assert observed_lock_states and all(observed_lock_states)


def test_readback_detects_parent_evidence_or_chronology_tampering(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "evidence.db") as store:
        generation = _case_with_parent(store)
        repo = _repo(store)
        _admit(repo, generation)
        original = store.connection.execute(
            "SELECT record_json FROM evidence WHERE evidence_id=?",
            ("ev_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",),
        ).fetchone()
        assert original is not None
        altered = json.loads(str(original[0]))
        altered["summary"] = "Tampered parent observation"
        store.connection.execute(
            "UPDATE evidence SET record_json=? WHERE evidence_id=?",
            (json.dumps(altered), _EVIDENCE_A),
        )
        with pytest.raises(ValueError, match="parent evidence"):
            repo.readback(
                case_id="case_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", epoch_state_version=_EPOCH
            )
    with SQLiteStore(tmp_path / "chronology.db") as store:
        generation = _case_with_parent(store)
        repo = _repo(store)
        admission_id = _admit(repo, generation)
        with store.transaction() as transaction:
            transaction.record_probe_execution(
                execution_id="exec_cccccccccccccccccccccccccccccccc",
                case_id="case_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                probe_id="fixture.child",
                probe_version=1,
                status="ok",
                parameters_json="{}",
                started_at=_CHILD_START.isoformat(),
                finished_at=_CHILD_END.isoformat(),
                state_version=_EPOCH,
                followup_admission_id=admission_id,
            )
            repo.link_execution(
                admission_id=admission_id, execution_id="exec_cccccccccccccccccccccccccccccccc"
            )
        store.connection.execute(
            "UPDATE probe_executions SET started_at=? WHERE execution_id=?",
            (_PARENT_START.isoformat(), _CHILD),
        )
        with pytest.raises(ValueError, match="chronology"):
            repo.readback(
                case_id="case_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", epoch_state_version=_EPOCH
            )


def test_case_deletion_cascades_followup_provenance(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "case.db") as store:
        generation = _case_with_parent(store)
        repo = _repo(store)
        admission_id = _admit(repo, generation)
        with store.transaction() as transaction:
            transaction.record_probe_execution(
                execution_id="exec_cccccccccccccccccccccccccccccccc",
                case_id="case_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                probe_id="fixture.child",
                probe_version=1,
                status="ok",
                parameters_json="{}",
                started_at=_CHILD_START.isoformat(),
                finished_at=_CHILD_END.isoformat(),
                state_version=_EPOCH,
                followup_admission_id=admission_id,
            )
            repo.link_execution(
                admission_id=admission_id, execution_id="exec_cccccccccccccccccccccccccccccccc"
            )
        store.connection.execute(
            "DELETE FROM cases WHERE case_id='case_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'"
        )
        assert store.connection.execute(
            "SELECT COUNT(*) FROM collection_followup_admissions"
        ).fetchone() == (0,)
        assert store.connection.execute("SELECT COUNT(*) FROM probe_executions").fetchone() == (0,)
