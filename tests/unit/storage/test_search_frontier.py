"""Durable advisory search work is distinct from probe execution authority."""

from __future__ import annotations

import hashlib
import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path

import pytest
from pydantic import ValidationError

from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId
from systemsense.domain.probes import MeasurementWindow
from systemsense.storage.search_frontier import (
    FrontierEventV1,
    FrontierOutboxGapV1,
    FrontierReferenceV1,
    FrontierStatus,
    RelevantVersionsV1,
    SearchFrontierRepository,
)
from systemsense.storage.sqlite_store import SQLiteStore

_NOW = "2026-09-23T12:00:00+00:00"


def _case(store: SQLiteStore) -> CaseId:
    case_id = CaseId.new()
    store.create_case(case_id=str(case_id), kind="general", symptom="slow PDF", created_at=_NOW)
    return case_id


def _versions(**changes: int) -> RelevantVersionsV1:
    return RelevantVersionsV1.model_validate(
        {"objective": 1, "evidence": 2, "hypotheses": 1, **changes}
    )


def _measurement(candidate: str, *, window: MeasurementWindow | None = None) -> FrontierReferenceV1:
    return FrontierReferenceV1(kind="measure", candidate_id=candidate, window=window)


def _investigator_event(store: SQLiteStore, case_id: CaseId) -> FrontierEventV1:
    evidence_id = EvidenceId.new()
    repo = SearchFrontierRepository(store)
    with store.transaction() as transaction:
        transaction.insert_evidence(
            case_id=str(case_id),
            evidence_id=str(evidence_id),
            source_id="src_" + hashlib.sha256(str(evidence_id).encode()).hexdigest(),
            record_json='{"summary":"observed"}',
            captured_at=_NOW,
        )
        generation = store.connection.execute(
            "SELECT generation FROM evidence_case_generations WHERE case_id=?",
            (str(case_id),),
        ).fetchone()
        assert generation is not None
        event = repo.append_result_event(
            case_id,
            source_evidence_id=evidence_id,
            source_execution_id=None,
            versions=_versions(evidence=int(generation[0])),
        )
    assert isinstance(event, FrontierEventV1)
    return event


def test_unchanged_item_deduplicates_but_target_and_window_are_distinct(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "frontier.db") as store:
        case_id = _case(store)
        repo = SearchFrontierRepository(store)
        first = repo.upsert_item(case_id, _measurement("cand_v1_" + "a" * 32), _versions())
        assert (
            repo.upsert_item(case_id, _measurement("cand_v1_" + "a" * 32), _versions()).item_id
            == first.item_id
        )
        other_target = repo.upsert_item(case_id, _measurement("cand_v1_" + "b" * 32), _versions())
        window = MeasurementWindow(
            start=datetime.fromisoformat("2026-09-23T11:00:00+00:00"),
            end=datetime.fromisoformat("2026-09-23T11:01:00+00:00"),
        )
        other_window = repo.upsert_item(
            case_id, _measurement("cand_v1_" + "a" * 32, window=window), _versions()
        )
        assert len({first.item_id, other_target.item_id, other_window.item_id}) == 3
        assert first.status is FrontierStatus.REQUESTED
        assert repo.readback(first.item_id) == first


def test_versioned_branch_reference_pins_relation_version_and_content(tmp_path: Path) -> None:
    from systemsense.storage import search_frontier

    reference_type = getattr(search_frontier, "FrontierBranchReferenceV2", None)
    assert reference_type is not None
    with SQLiteStore(tmp_path / "versioned-branch.db") as store:
        case_id = _case(store)
        repo = SearchFrontierRepository(store)
        relation_id = "rel_" + "b" * 32
        first_sha = "c" * 64
        second_sha = "d" * 64
        first_branch_id = (
            "branch_v2_" + hashlib.sha256(f"{relation_id}:1:{first_sha}".encode()).hexdigest()[:32]
        )
        second_branch_id = (
            "branch_v2_" + hashlib.sha256(f"{relation_id}:2:{second_sha}".encode()).hexdigest()[:32]
        )
        first = reference_type(
            branch_id=first_branch_id,
            relation_id=relation_id,
            relation_version=1,
            relation_sha256=first_sha,
        )
        second = reference_type(
            branch_id=second_branch_id,
            relation_id=relation_id,
            relation_version=2,
            relation_sha256=second_sha,
        )
        first_item = repo.upsert_item(case_id, first, _versions())
        second_item = repo.upsert_item(case_id, second, _versions())
        assert first_item.item_id != second_item.item_id
        assert repo.readback(first_item.item_id).reference == first
        assert repo.readback(second_item.item_id).reference == second


def test_reference_rejects_untyped_selectors_and_wrong_kind_fields() -> None:
    with pytest.raises(ValidationError):
        FrontierReferenceV1(kind="measure", candidate_id="https://example.com/run")
    with pytest.raises(ValidationError):
        FrontierReferenceV1(kind="measure", evidence_id=EvidenceId.new())
    with pytest.raises(ValidationError):
        FrontierReferenceV1(
            kind="retrieve_evidence",
            evidence_id=EvidenceId.new(),
            candidate_id="cand_v1_" + "a" * 32,
        )


def test_claim_rejects_changed_relevant_versions_and_prerequisite_not_satisfied(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "frontier.db") as store:
        case_id = _case(store)
        repo = SearchFrontierRepository(store)
        parent = repo.upsert_item(
            case_id,
            FrontierReferenceV1(kind="retrieve_evidence", evidence_id=EvidenceId.new()),
            _versions(),
        )
        child = repo.upsert_item(
            case_id,
            _measurement("cand_v1_" + "a" * 32),
            _versions(),
            prerequisite_ids=(parent.item_id,),
        )
        with pytest.raises(ValueError, match="relevant versions"):
            repo.claim_ready(parent.item_id, _versions(evidence=3))
        with pytest.raises(ValueError, match="prerequisite"):
            repo.claim_ready(child.item_id, _versions())
        claimed = repo.claim_ready(parent.item_id, _versions())
        assert claimed.status is FrontierStatus.CLAIMED
        assert (
            repo.transition(
                parent.item_id, FrontierStatus.CLAIMED, FrontierStatus.ADMITTED, "admitted"
            ).status
            is FrontierStatus.ADMITTED
        )
        repo.transition(parent.item_id, FrontierStatus.ADMITTED, FrontierStatus.RUNNING, "running")
        repo.transition(
            parent.item_id, FrontierStatus.RUNNING, FrontierStatus.SATISFIED, "retrieved"
        )
        assert repo.claim_ready(child.item_id, _versions()).status is FrontierStatus.CLAIMED


def test_invalid_transition_and_one_shot_interrupted_custody(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "frontier.db") as store:
        case_id = _case(store)
        repo = SearchFrontierRepository(store)
        item = repo.upsert_item(case_id, _measurement("cand_v1_" + "a" * 32), _versions())
        with pytest.raises(ValueError, match="invalid transition"):
            repo.transition(
                item.item_id, FrontierStatus.REQUESTED, FrontierStatus.RUNNING, "skip_admission"
            )
        repo.claim_ready(item.item_id, _versions())
        repo.transition(item.item_id, FrontierStatus.CLAIMED, FrontierStatus.ADMITTED, "admitted")
        assert repo.interrupt_uncertain(case_id) == (item.item_id,)
        assert repo.readback(item.item_id).status is FrontierStatus.INTERRUPTED
        with pytest.raises(ValueError, match="not requested"):
            repo.claim_ready(item.item_id, _versions())
        assert repo.interrupt_uncertain(case_id) == ()


def test_result_event_is_atomic_idempotent_and_acknowledged(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "frontier.db") as store:
        case_id = _case(store)
        repo = SearchFrontierRepository(store)
        evidence_id = EvidenceId.new()
        with pytest.raises(ValueError, match="active transaction"):
            repo.append_result_event(
                case_id,
                source_evidence_id=evidence_id,
                source_execution_id=None,
                versions=_versions(),
            )
        with pytest.raises(RuntimeError, match="rollback"):
            with store.transaction() as transaction:
                transaction.insert_evidence(
                    case_id=str(case_id),
                    evidence_id=str(evidence_id),
                    source_id="src_" + "a" * 64,
                    record_json='{"summary":"observed"}',
                    captured_at=_NOW,
                )
                repo.append_result_event(
                    case_id,
                    source_evidence_id=evidence_id,
                    source_execution_id=None,
                    versions=_versions(),
                )
                raise RuntimeError("rollback")
        assert repo.pending_events(case_id) == ()
        with store.transaction() as transaction:
            transaction.insert_evidence(
                case_id=str(case_id),
                evidence_id=str(evidence_id),
                source_id="src_" + "a" * 64,
                record_json='{"summary":"observed"}',
                captured_at=_NOW,
            )
            first = repo.append_result_event(
                case_id,
                source_evidence_id=evidence_id,
                source_execution_id=None,
                versions=_versions(),
            )
            second = repo.append_result_event(
                case_id,
                source_evidence_id=evidence_id,
                source_execution_id=None,
                versions=_versions(),
            )
        assert isinstance(first, FrontierEventV1)
        assert isinstance(second, FrontierEventV1)
        assert first.event_id == second.event_id
        assert repo.pending_events(case_id) == (first,)
        repo.ack_event(first.event_id)
        assert repo.pending_events(case_id) == ()
        assert repo.read_event(first.event_id) == first


def test_event_source_must_exist_and_belong_to_case(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "frontier.db") as store:
        owner = _case(store)
        other = _case(store)
        repo = SearchFrontierRepository(store)
        evidence_id = EvidenceId.new()
        with store.transaction() as transaction:
            transaction.insert_evidence(
                case_id=str(owner),
                evidence_id=str(evidence_id),
                source_id="src_" + "b" * 64,
                record_json='{"summary":"observed"}',
                captured_at=_NOW,
            )
            with pytest.raises(ValueError, match=r"source.*case"):
                repo.append_result_event(
                    other,
                    source_evidence_id=evidence_id,
                    source_execution_id=None,
                    versions=_versions(),
                )
            with pytest.raises(ValueError, match=r"source.*case"):
                repo.append_result_event(
                    owner,
                    source_evidence_id=None,
                    source_execution_id=ExecutionId.new(),
                    versions=_versions(),
                )


def test_result_event_survives_raw_evidence_retention_as_unverifiable(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "frontier.db") as store:
        case_id = _case(store)
        repo = SearchFrontierRepository(store)
        evidence_id = EvidenceId.new()
        with store.transaction() as transaction:
            transaction.insert_evidence(
                case_id=str(case_id),
                evidence_id=str(evidence_id),
                source_id="src_" + "e" * 64,
                record_json='{"summary":"observed"}',
                captured_at=_NOW,
            )
            event = repo.append_result_event(
                case_id,
                source_evidence_id=evidence_id,
                source_execution_id=None,
                versions=_versions(),
            )
        assert isinstance(event, FrontierEventV1)
        assert event.source_state == "present"
        assert event.source_record_sha256 is not None
        with store.transaction():
            store.connection.execute(
                "DELETE FROM evidence WHERE evidence_id=?", (str(evidence_id),)
            )
        retained = repo.read_event(event.event_id)
        assert retained.source_evidence_id == evidence_id
        assert retained.source_state == "missing_unverifiable"
        assert retained.source_record_sha256 == event.source_record_sha256
        assert repo.pending_events(case_id) == (retained,)


def test_outbox_capacity_gap_does_not_rollback_evidence(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("systemsense.storage.search_frontier._EVENT_LIMIT", 1)
    with SQLiteStore(tmp_path / "frontier.db") as store:
        case_id = _case(store)
        repo = SearchFrontierRepository(store)
        first_id, second_id = EvidenceId.new(), EvidenceId.new()
        with store.transaction() as transaction:
            transaction.insert_evidence(
                case_id=str(case_id),
                evidence_id=str(first_id),
                source_id="src_" + "c" * 64,
                record_json='{"summary":"first"}',
                captured_at=_NOW,
            )
            repo.append_result_event(
                case_id, source_evidence_id=first_id, source_execution_id=None, versions=_versions()
            )
        with store.transaction() as transaction:
            transaction.insert_evidence(
                case_id=str(case_id),
                evidence_id=str(second_id),
                source_id="src_" + "d" * 64,
                record_json='{"summary":"second"}',
                captured_at=_NOW,
            )
            overflow = repo.append_result_event(
                case_id,
                source_evidence_id=second_id,
                source_execution_id=None,
                versions=_versions(evidence=3),
            )
        assert isinstance(overflow, FrontierOutboxGapV1)
        assert overflow.reason == "capacity_requires_catalog_rescan"
        assert store.evidence(case_id=str(case_id), evidence_id=str(second_id)) is not None
        assert repo.outbox_gap(case_id) == overflow


def test_investigator_intake_is_atomic_independent_and_idempotent(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "investigator-intake.db") as store:
        owner, other = _case(store), _case(store)
        repo = SearchFrontierRepository(store)
        evidence_id = EvidenceId.new()
        with store.transaction() as transaction:
            transaction.insert_evidence(
                case_id=str(owner),
                evidence_id=str(evidence_id),
                source_id="src_" + "f" * 64,
                record_json='{"summary":"observed"}',
                captured_at=_NOW,
            )
            event = repo.append_result_event(
                owner,
                source_evidence_id=evidence_id,
                source_execution_id=None,
                versions=_versions(),
            )
        assert isinstance(event, FrontierEventV1)
        assert repo.pending_investigator_events(owner) == (event,)
        with pytest.raises(ValueError, match="case"):
            repo.intake_investigator_event(other, event.event_id)
        assert repo.pending_investigator_events(other) == ()
        trigger = repo.intake_investigator_event(owner, event.event_id)
        assert trigger.event_id == event.event_id
        assert repo.intake_investigator_event(owner, event.event_id) == trigger
        assert repo.pending_investigator_events(owner) == ()
        assert repo.pending_investigator_triggers(owner) == (event,)
        assert repo.pending_events(owner) == (event,)
        repo.ack_event(event.event_id)
        assert repo.pending_events(owner) == ()
        assert repo.pending_investigator_triggers(owner) == (event,)


def test_investigator_intake_backpressures_without_ack(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("systemsense.storage.search_frontier._INVESTIGATOR_PENDING_LIMIT", 1)
    with SQLiteStore(tmp_path / "investigator-cap.db") as store:
        case_id = _case(store)
        repo = SearchFrontierRepository(store)
        events: list[FrontierEventV1] = []
        for suffix in ("a", "b"):
            evidence_id = EvidenceId.new()
            with store.transaction() as transaction:
                transaction.insert_evidence(
                    case_id=str(case_id),
                    evidence_id=str(evidence_id),
                    source_id="src_" + suffix * 64,
                    record_json='{"summary":"observed"}',
                    captured_at=_NOW,
                )
                event = repo.append_result_event(
                    case_id,
                    source_evidence_id=evidence_id,
                    source_execution_id=None,
                    versions=_versions(),
                )
            assert isinstance(event, FrontierEventV1)
            events.append(event)
        repo.intake_investigator_event(case_id, events[0].event_id)
        with pytest.raises(ValueError, match="capacity"):
            repo.intake_investigator_event(case_id, events[1].event_id)
        assert repo.pending_investigator_events(case_id) == (events[1],)
        assert repo.pending_investigator_triggers(case_id) == (events[0],)
        assert (
            repo.intake_investigator_event(case_id, events[0].event_id).event_id
            == events[0].event_id
        )
        session = repo.start_investigator_session(case_id, events[0].event_id, decision_budget=2)
        assert session.versions == events[0].versions
        assert session.decision_budget == 2
        with pytest.raises(ValueError, match="capacity"):
            repo.intake_investigator_event(case_id, events[1].event_id)
        terminal = repo.finish_investigator_session(
            case_id,
            events[0].event_id,
            outcome="gap",
            reason_code="stale_snapshot",
        )
        assert terminal.event_id == events[0].event_id
        assert repo.pending_investigator_triggers(case_id) == ()
        repo.intake_investigator_event(case_id, events[1].event_id)
        assert repo.pending_investigator_triggers(case_id) == (events[1],)


def test_investigator_session_is_one_per_case_and_survives_restart(tmp_path: Path) -> None:
    path = tmp_path / "investigator-session.db"
    with SQLiteStore(path) as store:
        case_id = _case(store)
        repo = SearchFrontierRepository(store)
        first = _investigator_event(store, case_id)
        execution_id = ExecutionId.new()
        with store.transaction() as transaction:
            transaction.record_probe_execution(
                execution_id=str(execution_id),
                case_id=str(case_id),
                probe_id="disk.health",
                probe_version=1,
                status="unavailable",
                parameters_json="{}",
                started_at=_NOW,
                finished_at=_NOW,
                state_version=1,
            )
            second = repo.append_result_event(
                case_id,
                source_evidence_id=None,
                source_execution_id=execution_id,
                versions=first.versions,
            )
        assert isinstance(second, FrontierEventV1)
        repo.intake_investigator_event(case_id, first.event_id)
        repo.intake_investigator_event(case_id, second.event_id)
        active = repo.start_investigator_session(case_id, first.event_id, decision_budget=3)
        assert repo.start_investigator_session(case_id, first.event_id, decision_budget=3) == active
        with pytest.raises(ValueError, match="active"):
            repo.start_investigator_session(case_id, second.event_id, decision_budget=3)
    with SQLiteStore(path) as reopened:
        repo = SearchFrontierRepository(reopened)
        assert repo.active_investigator_session(case_id) == active
        assert repo.pending_investigator_triggers(case_id) == (second,)
        item = repo.upsert_item(
            case_id,
            FrontierReferenceV1(kind="retrieve_evidence", evidence_id=first.source_evidence_id),
            first.versions,
        )
        terminal = repo.finish_investigator_session(
            case_id,
            first.event_id,
            outcome="frontier_work_recorded",
            frontier_item_ids=(item.item_id,),
        )
        assert terminal.frontier_item_ids == (item.item_id,)
        assert repo.read_investigator_terminal(first.event_id) == terminal
        assert repo.active_investigator_session(case_id) is None
        assert (
            repo.start_investigator_session(case_id, second.event_id, decision_budget=1).event_id
            == second.event_id
        )


def test_investigator_session_rejects_unbound_or_untyped_terminal(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "investigator-terminal.db") as store:
        owner, other = _case(store), _case(store)
        repo = SearchFrontierRepository(store)
        event = _investigator_event(store, owner)
        repo.intake_investigator_event(owner, event.event_id)
        preexisting = repo.upsert_item(
            owner,
            FrontierReferenceV1(kind="retrieve_evidence", evidence_id=event.source_evidence_id),
            event.versions,
        )
        with pytest.raises(ValueError, match="budget"):
            repo.start_investigator_session(owner, event.event_id, decision_budget=0)
        repo.start_investigator_session(owner, event.event_id, decision_budget=1)
        with pytest.raises(ValueError, match="frontier item"):
            repo.finish_investigator_session(
                owner,
                event.event_id,
                outcome="frontier_work_recorded",
                frontier_item_ids=(preexisting.item_id,),
            )
        foreign = repo.upsert_item(
            other,
            FrontierReferenceV1(kind="retrieve_evidence", evidence_id=EvidenceId.new()),
            _versions(),
        )
        with pytest.raises(ValueError, match="frontier item"):
            repo.finish_investigator_session(
                owner,
                event.event_id,
                outcome="frontier_work_recorded",
                frontier_item_ids=(foreign.item_id,),
            )
        with pytest.raises(ValueError, match="reason"):
            repo.finish_investigator_session(
                owner,
                event.event_id,
                outcome="no_new_fact",
            )
        assert repo.active_investigator_session(owner) is not None
        assert repo.read_investigator_terminal(event.event_id) is None


def test_new_event_during_reconsideration_requires_stale_terminal(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "investigator-stale-session.db") as store:
        case_id = _case(store)
        repo = SearchFrontierRepository(store)
        first = _investigator_event(store, case_id)
        repo.intake_investigator_event(case_id, first.event_id)
        session = repo.start_investigator_session(case_id, first.event_id, decision_budget=1)
        second = _investigator_event(store, case_id)
        assert session.versions == first.versions
        with pytest.raises(ValueError, match="stale"):
            repo.finish_investigator_session(
                case_id,
                first.event_id,
                outcome="no_new_fact",
                reason_code="all_facts_already_visible",
            )
        assert repo.active_investigator_session(case_id) == session
        terminal = repo.finish_investigator_session(
            case_id,
            first.event_id,
            outcome="gap",
            reason_code="stale_snapshot",
        )
        assert terminal.reason_code == "stale_snapshot"
        repo.intake_investigator_event(case_id, second.event_id)
        assert repo.pending_investigator_triggers(case_id) == (second,)


def test_investigator_terminal_deadline_is_checked_at_finish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "investigator-deadline.db") as store:
        case_id = _case(store)
        repo = SearchFrontierRepository(store)
        event = _investigator_event(store, case_id)
        repo.intake_investigator_event(case_id, event.event_id)
        session = repo.start_investigator_session(case_id, event.event_id, decision_budget=1)
        item = repo.upsert_item(
            case_id,
            FrontierReferenceV1(kind="retrieve_evidence", evidence_id=event.source_evidence_id),
            event.versions,
        )
        with pytest.raises(ValueError, match="deadline"):
            repo.finish_investigator_session(
                case_id, event.event_id, outcome="gap", reason_code="deadline_expired"
            )
        monkeypatch.setattr(
            "systemsense.storage.search_frontier.utc_now",
            lambda: session.deadline_at + timedelta(seconds=1),
        )
        with pytest.raises(ValueError, match="deadline"):
            repo.finish_investigator_session(
                case_id,
                event.event_id,
                outcome="no_new_fact",
                reason_code="all_facts_already_visible",
            )
        with pytest.raises(ValueError, match="deadline"):
            repo.finish_investigator_session(
                case_id,
                event.event_id,
                outcome="frontier_work_recorded",
                frontier_item_ids=(item.item_id,),
            )
        terminal = repo.finish_investigator_session(
            case_id, event.event_id, outcome="gap", reason_code="deadline_expired"
        )
        assert terminal.reason_code == "deadline_expired"


def test_backward_clock_cannot_terminalize_investigator_session(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "investigator-clock-rollback.db") as store:
        case_id = _case(store)
        repo = SearchFrontierRepository(store)
        event = _investigator_event(store, case_id)
        repo.intake_investigator_event(case_id, event.event_id)
        session = repo.start_investigator_session(case_id, event.event_id, decision_budget=1)
        monkeypatch.setattr(
            "systemsense.storage.search_frontier.utc_now",
            lambda: session.started_at - timedelta(seconds=1),
        )

        with pytest.raises(ValueError, match="chronology"):
            repo.finish_investigator_session(
                case_id, event.event_id, outcome="gap", reason_code="policy_unavailable"
            )
        assert repo.read_investigator_terminal(event.event_id) is None
        assert repo.active_investigator_session(case_id) == session


def test_missing_source_precedes_generation_staleness(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "investigator-missing-source.db") as store:
        case_id = _case(store)
        repo = SearchFrontierRepository(store)
        event = _investigator_event(store, case_id)
        repo.intake_investigator_event(case_id, event.event_id)
        repo.start_investigator_session(case_id, event.event_id, decision_budget=1)
        store.connection.execute(
            "DELETE FROM evidence WHERE evidence_id=?", (str(event.source_evidence_id),)
        )
        assert repo.read_event(event.event_id).source_state == "missing_unverifiable"
        terminal = repo.finish_investigator_session(
            case_id, event.event_id, outcome="gap", reason_code="source_unverifiable"
        )
        assert terminal.reason_code == "source_unverifiable"


def test_terminal_readback_rechecks_work_binding_and_chronology(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "investigator-tampered-terminal.db") as store:
        owner, other = _case(store), _case(store)
        repo = SearchFrontierRepository(store)
        event = _investigator_event(store, owner)
        before = repo.upsert_item(owner, _measurement("cand_v1_" + "a" * 32), event.versions)
        repo.intake_investigator_event(owner, event.event_id)
        session = repo.start_investigator_session(owner, event.event_id, decision_budget=1)
        monkeypatch.setattr(
            "systemsense.storage.search_frontier.utc_now",
            lambda: session.started_at + timedelta(seconds=1),
        )
        valid = repo.upsert_item(owner, _measurement("cand_v1_" + "b" * 32), event.versions)
        foreign = repo.upsert_item(other, _measurement("cand_v1_" + "c" * 32), event.versions)
        assert event.versions.evidence is not None
        wrong_version = repo.upsert_item(
            owner,
            _measurement("cand_v1_" + "d" * 32),
            _versions(evidence=event.versions.evidence + 1),
        )
        terminal = repo.finish_investigator_session(
            owner,
            event.event_id,
            outcome="frontier_work_recorded",
            frontier_item_ids=(valid.item_id,),
        )
        assert repo.read_investigator_terminal(event.event_id) == terminal
        store.connection.execute("DROP TRIGGER search_frontier_investigator_terminals_no_update")
        original = terminal.model_dump(mode="json")
        corruptions = (
            (valid.item_id, valid.item_id),
            (before.item_id,),
            (foreign.item_id,),
            (wrong_version.item_id,),
        )
        for item_ids in corruptions:
            payload = {**original, "frontier_item_ids": list(item_ids)}
            body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            store.connection.execute(
                "UPDATE search_frontier_investigator_terminals "
                "SET record_json=?,record_sha256=? WHERE event_id=?",
                (body, hashlib.sha256(body.encode()).hexdigest(), event.event_id),
            )
            with pytest.raises(ValueError, match="frontier item"):
                repo.read_investigator_terminal(event.event_id)
        early = (session.started_at - timedelta(seconds=1)).isoformat()
        payload = {**original, "terminal_at": early}
        body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        store.connection.execute(
            "UPDATE search_frontier_investigator_terminals "
            "SET record_json=?,record_sha256=?,terminal_at=? WHERE event_id=?",
            (body, hashlib.sha256(body.encode()).hexdigest(), early, event.event_id),
        )
        with pytest.raises(ValueError, match="chronology"):
            repo.read_investigator_terminal(event.event_id)


def test_investigator_accepts_coverage_only_task_completion(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "investigator-coverage.db") as store:
        case_id = _case(store)
        repo = SearchFrontierRepository(store)
        execution_id = ExecutionId.new()
        with store.transaction() as transaction:
            transaction.record_probe_execution(
                execution_id=str(execution_id),
                case_id=str(case_id),
                probe_id="disk.health",
                probe_version=1,
                status="unavailable",
                parameters_json="{}",
                started_at=_NOW,
                finished_at=_NOW,
                state_version=1,
            )
            event = repo.append_result_event(
                case_id,
                source_evidence_id=None,
                source_execution_id=execution_id,
                versions=_versions(),
            )
        assert isinstance(event, FrontierEventV1)
        assert event.kind == "task_completed"
        assert event.source_state == "not_applicable"
        repo.intake_investigator_event(case_id, event.event_id)
        assert repo.pending_investigator_triggers(case_id) == (event,)


def test_investigator_ack_failure_rolls_back_trigger(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "investigator-atomic.db") as store:
        case_id = _case(store)
        repo = SearchFrontierRepository(store)
        evidence_id = EvidenceId.new()
        with store.transaction() as transaction:
            transaction.insert_evidence(
                case_id=str(case_id),
                evidence_id=str(evidence_id),
                source_id="src_" + "f" * 64,
                record_json='{"summary":"observed"}',
                captured_at=_NOW,
            )
            event = repo.append_result_event(
                case_id,
                source_evidence_id=evidence_id,
                source_execution_id=None,
                versions=_versions(),
            )
        assert isinstance(event, FrontierEventV1)
        store.connection.execute(
            "CREATE TRIGGER reject_investigator_ack BEFORE INSERT ON "
            "search_frontier_investigator_event_acks "
            "BEGIN SELECT RAISE(ABORT, 'ack rejected'); END"
        )
        with pytest.raises(sqlite3.IntegrityError, match="ack rejected"):
            repo.intake_investigator_event(case_id, event.event_id)
        assert repo.pending_investigator_events(case_id) == (event,)
        assert repo.pending_investigator_triggers(case_id) == ()


@pytest.mark.parametrize(
    "corruption", ("cross_case", "missing_ack", "schema", "timestamp", "non_utc", "orphan")
)
def test_investigator_trigger_readback_rejects_corrupt_row(tmp_path: Path, corruption: str) -> None:
    with SQLiteStore(tmp_path / f"investigator-corrupt-{corruption}.db") as store:
        owner, other = _case(store), _case(store)
        repo = SearchFrontierRepository(store)
        evidence_id = EvidenceId.new()
        with store.transaction() as transaction:
            transaction.insert_evidence(
                case_id=str(owner),
                evidence_id=str(evidence_id),
                source_id="src_" + "f" * 64,
                record_json='{"summary":"observed"}',
                captured_at=_NOW,
            )
            event = repo.append_result_event(
                owner,
                source_evidence_id=evidence_id,
                source_execution_id=None,
                versions=_versions(),
            )
        assert isinstance(event, FrontierEventV1)
        store.connection.execute("PRAGMA foreign_keys=OFF")
        store.connection.execute("PRAGMA ignore_check_constraints=ON")
        case_id = other if corruption == "cross_case" else owner
        trigger_event_id = "fre_v1_" + "0" * 64 if corruption == "orphan" else event.event_id
        store.connection.execute(
            "INSERT INTO search_frontier_investigator_triggers "
            "(event_id,case_id,schema_version,queued_at) VALUES (?,?,?,?)",
            (
                trigger_event_id,
                str(case_id),
                2 if corruption == "schema" else 1,
                "not-a-time"
                if corruption == "timestamp"
                else "2026-09-23T05:00:00-07:00"
                if corruption == "non_utc"
                else _NOW,
            ),
        )
        if corruption != "missing_ack":
            store.connection.execute(
                "INSERT INTO search_frontier_investigator_event_acks "
                "(event_id,acknowledged_at) VALUES (?,?)",
                (trigger_event_id, _NOW),
            )
        store.connection.execute("PRAGMA ignore_check_constraints=OFF")
        store.connection.execute("PRAGMA foreign_keys=ON")

        with pytest.raises(ValueError, match="investigator trigger"):
            repo.pending_investigator_triggers(case_id)


def test_investigator_trigger_survives_reopen_and_rejects_cross_case_sql(tmp_path: Path) -> None:
    path = tmp_path / "investigator-reopen.db"
    with SQLiteStore(path) as store:
        owner, other = _case(store), _case(store)
        repo = SearchFrontierRepository(store)
        evidence_id = EvidenceId.new()
        with store.transaction() as transaction:
            transaction.insert_evidence(
                case_id=str(owner),
                evidence_id=str(evidence_id),
                source_id="src_" + "f" * 64,
                record_json='{"summary":"observed"}',
                captured_at=_NOW,
            )
            event = repo.append_result_event(
                owner,
                source_evidence_id=evidence_id,
                source_execution_id=None,
                versions=_versions(),
            )
        assert isinstance(event, FrontierEventV1)
        with pytest.raises(sqlite3.IntegrityError, match="FOREIGN KEY"):
            store.connection.execute(
                "INSERT INTO search_frontier_investigator_triggers "
                "(event_id,case_id,schema_version,queued_at) VALUES (?,?,1,?)",
                (event.event_id, str(other), _NOW),
            )
        trigger = repo.intake_investigator_event(owner, event.event_id)
    with SQLiteStore(path) as reopened:
        repo = SearchFrontierRepository(reopened)
        assert repo.pending_investigator_triggers(owner) == (event,)
        assert repo.pending_investigator_events(owner) == ()
        assert repo.intake_investigator_event(owner, event.event_id) == trigger
        reopened.connection.execute("DELETE FROM cases WHERE case_id=?", (str(owner),))
        assert repo.pending_investigator_triggers(owner) == ()
        assert (
            reopened.connection.execute(
                "SELECT 1 FROM search_frontier_investigator_event_acks WHERE event_id=?",
                (event.event_id,),
            ).fetchone()
            is None
        )
