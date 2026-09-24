"""Schema-30 investigator turns retain custody across owner and process loss."""

import hashlib
import json
from datetime import timedelta
from pathlib import Path

import pytest
from test_investigation_frontier_turn_atomic import (
    _prepared_delivery,  # pyright: ignore[reportPrivateUsage]
)
from test_search_frontier import _investigator_event  # pyright: ignore[reportPrivateUsage]

from systemsense.application.investigation_state import InvestigationState, InvestigationStatus
from systemsense.domain.ids import CaseId, EvidenceId
from systemsense.domain.time import utc_now
from systemsense.evidence.retrieval import EvidenceCatalogCursor
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.search_frontier import (
    FrontierInvestigatorItemTransitionV1,
    FrontierInvestigatorTurnClosureIntentV1,
    FrontierInvestigatorTurnCompletionV1,
    FrontierItemCapacityError,
    FrontierReferenceV1,
    FrontierStatus,
    RelevantVersionsV1,
    SearchFrontierRepository,
)
from systemsense.storage.sqlite_store import SQLiteStore


def _owner(store: SQLiteStore) -> tuple[CaseId, InvestigationState]:
    now = utc_now()
    state = InvestigationState(
        case_id=CaseId.new(),
        objective="slow PDF",
        created_at=now,
        updated_at=now,
        deadline_at=now + timedelta(minutes=2),
        incident_start=now - timedelta(minutes=15),
        incident_end=now + timedelta(minutes=5),
        budget_ms=120_000,
    )
    investigation = InvestigationRepository(store)
    investigation.create(state)
    started = investigation.save(
        state.model_copy(update={"status": InvestigationStatus.RUNNING}),
        expected_version=0,
        event="started",
        detail="owner began",
    )
    return state.case_id, started


def _reserve(
    repo: SearchFrontierRepository,
    case_id: CaseId,
    event_id: str,
    state: InvestigationState,
    generation: int,
):
    session = repo.active_investigator_session(case_id)
    assert session is not None
    return repo.reserve_investigator_turn(
        case_id,
        event_id,
        owner_started_version=1,
        expected_checkpoint_version=state.state_version,
        current_versions=RelevantVersionsV1(objective=1, evidence=generation),
        focused_context_sha256="a" * 64,
        catalog_generation=generation,
        cursor_before=None,
        offered_refs=(),
        pending_tail=(),
        offered_item_ids=(),
        pending_item_ids=(),
        eligible_evidence_ids=(),
        cursor_after=None,
        turn_deadline_at=min(state.deadline_at, session.deadline_at),
    )


def test_turn_reservation_survives_restart_and_consumes_budget(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "turns.db"
    with SQLiteStore(path) as store:
        case_id, owner = _owner(store)
        repo = SearchFrontierRepository(store)
        event = _investigator_event(store, case_id)
        assert event.versions.evidence is not None
        repo.intake_investigator_event(case_id, event.event_id)
        repo.start_investigator_session(case_id, event.event_id, decision_budget=1)
        turn = _reserve(repo, case_id, event.event_id, owner, event.versions.evidence)
        assert turn.ordinal == 1
    with SQLiteStore(path) as reopened:
        repo = SearchFrontierRepository(reopened)
        assert repo.read_investigator_turn(turn.turn_id) == turn
        with pytest.raises(ValueError, match=r"unfinished|budget"):
            _reserve(repo, case_id, event.event_id, owner, event.versions.evidence)
        monkeypatch.setattr(
            "systemsense.storage.search_frontier.utc_now",
            lambda: turn.deadline_at + timedelta(seconds=1),
        )
        outcome = repo.recover_interrupted_investigator_turn(turn.turn_id)
        assert outcome.outcome == "interrupted"
        assert repo.read_investigator_turn_outcome(turn.turn_id) == outcome
        assert len(repo.investigator_turns(case_id, event.event_id)) == 1


def test_turn_reservation_requires_current_owner_and_context(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "owner.db") as store:
        case_id, owner = _owner(store)
        repo = SearchFrontierRepository(store)
        event = _investigator_event(store, case_id)
        assert event.versions.evidence is not None
        repo.intake_investigator_event(case_id, event.event_id)
        repo.start_investigator_session(case_id, event.event_id, decision_budget=3)
        with pytest.raises(ValueError, match="owner"):
            repo.reserve_investigator_turn(
                case_id,
                event.event_id,
                owner_started_version=2,
                expected_checkpoint_version=owner.state_version,
                current_versions=event.versions,
                focused_context_sha256="a" * 64,
                catalog_generation=event.versions.evidence,
                cursor_before=None,
                offered_refs=(),
                pending_tail=(),
                turn_deadline_at=owner.deadline_at,
                offered_item_ids=(),
                pending_item_ids=(),
                eligible_evidence_ids=(),
                cursor_after=None,
            )
        with pytest.raises(ValueError, match="generation"):
            _reserve(repo, case_id, event.event_id, owner, event.versions.evidence + 1)
        assert repo.investigator_turns(case_id, event.event_id) == ()


def test_turn_completion_requires_same_transaction_as_checkpoint(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "completion.db") as store:
        case_id, owner = _owner(store)
        repo = SearchFrontierRepository(store)
        event = _investigator_event(store, case_id)
        assert event.versions.evidence is not None
        repo.intake_investigator_event(case_id, event.event_id)
        repo.start_investigator_session(case_id, event.event_id, decision_budget=2)
        turn = _reserve(repo, case_id, event.event_id, owner, event.versions.evidence)
        prepared = FrontierInvestigatorTurnCompletionV1(
            turn_id=turn.turn_id,
            case_id=case_id,
            outcome="no_new_fact",
            reason_code="all_facts_already_visible",
            cursor_after=None,
            focused_context_sha256=turn.focused_context_sha256,
        )
        with pytest.raises(ValueError, match="transaction"):
            repo.complete_investigator_turn_in_transaction(
                prepared,
                expected_checkpoint_version=owner.state_version + 1,
            )
        advanced = InvestigationRepository(store).save(
            owner,
            expected_version=owner.state_version,
            event="attention",
            detail="considered",
        )
        with store.transaction():
            outcome = repo.complete_investigator_turn_in_transaction(
                prepared,
                expected_checkpoint_version=advanced.state_version,
            )
        assert outcome.outcome == "no_new_fact"
        assert repo.read_investigator_turn_outcome(turn.turn_id) == outcome


def test_turn_page_cursor_requires_all_eligible_sources_in_frozen_items(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "page.db") as store:
        case_id, owner = _owner(store)
        repo = SearchFrontierRepository(store)
        event = _investigator_event(store, case_id)
        assert event.source_evidence_id is not None
        assert event.versions.evidence is not None
        repo.intake_investigator_event(case_id, event.event_id)
        session = repo.start_investigator_session(case_id, event.event_id, decision_budget=2)
        cursor = None
        with pytest.raises(ValueError, match="eligible"):
            repo.reserve_investigator_turn(
                case_id,
                event.event_id,
                owner_started_version=1,
                expected_checkpoint_version=owner.state_version,
                current_versions=RelevantVersionsV1(
                    objective=1,
                    evidence=event.versions.evidence,
                ),
                focused_context_sha256="a" * 64,
                catalog_generation=event.versions.evidence,
                cursor_before=None,
                cursor_after=cursor,
                offered_refs=(),
                pending_tail=(),
                offered_item_ids=(),
                pending_item_ids=(),
                eligible_evidence_ids=(event.source_evidence_id,),
                turn_deadline_at=session.deadline_at,
            )
        item = repo.upsert_item(
            case_id,
            FrontierReferenceV1(
                kind="retrieve_evidence",
                evidence_id=event.source_evidence_id,
            ),
            RelevantVersionsV1(objective=1, evidence=event.versions.evidence),
        )
        turn = repo.reserve_investigator_turn(
            case_id,
            event.event_id,
            owner_started_version=1,
            expected_checkpoint_version=owner.state_version,
            current_versions=RelevantVersionsV1(objective=1, evidence=event.versions.evidence),
            focused_context_sha256="a" * 64,
            catalog_generation=event.versions.evidence,
            cursor_before=None,
            cursor_after=None,
            offered_refs=(),
            pending_tail=(),
            offered_item_ids=(item.item_id,),
            pending_item_ids=(),
            eligible_evidence_ids=(event.source_evidence_id,),
            turn_deadline_at=session.deadline_at,
        )
        assert turn.offered_item_ids == (item.item_id,)


def test_typed_intake_reports_active_terminal_and_backpressure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "intake.db") as store:
        case_id, _ = _owner(store)
        repo = SearchFrontierRepository(store)
        event = _investigator_event(store, case_id)
        assert repo.intake_investigator_event_status(case_id, event.event_id).status == "queued"
        second = _investigator_event(store, case_id)
        monkeypatch.setattr("systemsense.storage.search_frontier._INVESTIGATOR_PENDING_LIMIT", 1)
        assert (
            repo.intake_investigator_event_status(case_id, second.event_id).status
            == "backpressured"
        )
        assert repo.pending_investigator_events(case_id) == (second,)
        repo.start_investigator_session(case_id, event.event_id, decision_budget=1)
        assert (
            repo.intake_investigator_event_status(case_id, event.event_id).status
            == "already_active"
        )
        repo.finish_investigator_session(
            case_id,
            event.event_id,
            outcome="gap",
            reason_code="stale_snapshot",
        )
        assert (
            repo.intake_investigator_event_status(case_id, event.event_id).status
            == "already_terminal"
        )


def test_focused_delivery_preserves_other_offered_item_across_restart(tmp_path: Path) -> None:
    path = tmp_path / "tail.db"
    with SQLiteStore(path) as store:
        case_id, owner = _owner(store)
        repo = SearchFrontierRepository(store)
        event = _investigator_event(store, case_id)
        assert event.source_evidence_id is not None
        assert event.versions.evidence is not None
        second_evidence_id = EvidenceId.new()
        with store.transaction() as transaction:
            transaction.insert_evidence(
                case_id=str(case_id),
                evidence_id=str(second_evidence_id),
                source_id="src_" + "b" * 64,
                record_json='{"summary":"second"}',
                captured_at="2026-09-23T12:00:00+00:00",
            )
        generation_row = store.connection.execute(
            "SELECT generation FROM evidence_case_generations WHERE case_id=?",
            (str(case_id),),
        ).fetchone()
        assert generation_row is not None
        generation = int(generation_row[0])
        repo.intake_investigator_event(case_id, event.event_id)
        session = repo.start_investigator_session(case_id, event.event_id, decision_budget=2)
        versions = RelevantVersionsV1(objective=1, evidence=generation)
        selected = repo.upsert_item(
            case_id,
            FrontierReferenceV1(
                kind="retrieve_evidence",
                evidence_id=event.source_evidence_id,
            ),
            versions,
        )
        remaining = repo.upsert_item(
            case_id,
            FrontierReferenceV1(
                kind="retrieve_evidence",
                evidence_id=second_evidence_id,
            ),
            versions,
        )
        turn = repo.reserve_investigator_turn(
            case_id,
            event.event_id,
            owner_started_version=1,
            expected_checkpoint_version=owner.state_version,
            current_versions=versions,
            focused_context_sha256="a" * 64,
            catalog_generation=generation,
            cursor_before=None,
            cursor_after=None,
            offered_refs=(),
            pending_tail=(),
            offered_item_ids=(selected.item_id, remaining.item_id),
            pending_item_ids=(),
            eligible_evidence_ids=(event.source_evidence_id, second_evidence_id),
            turn_deadline_at=session.deadline_at,
        )
        repo.claim_ready(selected.item_id, versions)
        repo.transition(
            selected.item_id, FrontierStatus.CLAIMED, FrontierStatus.ADMITTED, "admitted"
        )
        repo.transition(
            selected.item_id, FrontierStatus.ADMITTED, FrontierStatus.RUNNING, "retrieving"
        )
        completion = FrontierInvestigatorTurnCompletionV1(
            turn_id=turn.turn_id,
            case_id=case_id,
            outcome="focused_delivery",
            reason_code="focused_context_delivered",
            frontier_item_ids=(selected.item_id,),
            remaining_item_ids=(remaining.item_id,),
            focused_context_sha256="a" * 64,
        )
        delivered = owner.model_copy(
            update={
                "fast_catalog_generation": generation,
                "fast_catalog_selected_ids": (event.source_evidence_id,),
            }
        )
        InvestigationRepository(store).save(
            delivered,
            expected_version=owner.state_version,
            event="frontier_retrieved",
            detail="focused delivery confirmed",
            frontier_turn_completion=completion,
            frontier_item_transition=FrontierInvestigatorItemTransitionV1(
                item_id=selected.item_id,
                expected_status=FrontierStatus.RUNNING,
                terminal_status=FrontierStatus.SATISFIED,
                reason="focused_delivery_confirmed",
            ),
        )
    with SQLiteStore(path) as reopened:
        repo = SearchFrontierRepository(reopened)
        outcome = repo.read_investigator_turn_outcome(turn.turn_id)
        assert outcome is not None
        assert outcome.remaining_item_ids == (remaining.item_id,)
        owner2 = InvestigationRepository(reopened).load(str(case_id))
        second = repo.reserve_investigator_turn(
            case_id,
            event.event_id,
            owner_started_version=1,
            expected_checkpoint_version=owner2.state_version,
            current_versions=versions,
            focused_context_sha256="b" * 64,
            catalog_generation=generation,
            cursor_before=outcome.cursor_after,
            cursor_after=None,
            offered_refs=(),
            pending_tail=(),
            offered_item_ids=(),
            pending_item_ids=outcome.remaining_item_ids,
            eligible_evidence_ids=(),
            turn_deadline_at=session.deadline_at,
        )
        assert second.pending_item_ids == (remaining.item_id,)
        with pytest.raises(ValueError, match="pending work"):
            InvestigationRepository(reopened).save(
                owner2,
                expected_version=owner2.state_version,
                event="attention",
                detail="cannot discard tail",
                frontier_turn_completion=FrontierInvestigatorTurnCompletionV1(
                    turn_id=second.turn_id,
                    case_id=case_id,
                    outcome="no_new_fact",
                    reason_code="all_facts_already_visible",
                    focused_context_sha256="b" * 64,
                ),
            )
        assert repo.read_investigator_turn_outcome(second.turn_id) is None
        repo.claim_ready(remaining.item_id, versions)
        repo.transition(
            remaining.item_id, FrontierStatus.CLAIMED, FrontierStatus.ADMITTED, "admitted"
        )
        repo.transition(
            remaining.item_id, FrontierStatus.ADMITTED, FrontierStatus.RUNNING, "retrieving"
        )
        delivered_tail = owner2.model_copy(
            update={
                "fast_catalog_generation": generation,
                "fast_catalog_selected_ids": (second_evidence_id,),
            }
        )
        InvestigationRepository(reopened).save(
            delivered_tail,
            expected_version=owner2.state_version,
            event="frontier_retrieved",
            detail="pending focused delivery confirmed",
            frontier_turn_completion=FrontierInvestigatorTurnCompletionV1(
                turn_id=second.turn_id,
                case_id=case_id,
                outcome="focused_delivery",
                reason_code="focused_context_delivered",
                frontier_item_ids=(remaining.item_id,),
                focused_context_sha256="b" * 64,
            ),
            frontier_item_transition=FrontierInvestigatorItemTransitionV1(
                item_id=remaining.item_id,
                expected_status=FrontierStatus.RUNNING,
                terminal_status=FrontierStatus.SATISFIED,
                reason="focused_delivery_confirmed",
            ),
        )
        final = repo.read_investigator_turn_outcome(second.turn_id)
        assert final is not None
        assert final.outcome == "focused_delivery"
        assert final.remaining_item_ids == ()


@pytest.mark.parametrize("stale_kind", ["new_owner", "expired", "generation"])
def test_turn_completion_rejects_stale_owner_deadline_or_generation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, stale_kind: str
) -> None:
    with SQLiteStore(tmp_path / f"stale-{stale_kind}.db") as store:
        case_id, owner = _owner(store)
        repo = SearchFrontierRepository(store)
        event = _investigator_event(store, case_id)
        assert event.versions.evidence is not None
        repo.intake_investigator_event(case_id, event.event_id)
        repo.start_investigator_session(case_id, event.event_id, decision_budget=2)
        turn = _reserve(repo, case_id, event.event_id, owner, event.versions.evidence)
        if stale_kind == "generation":
            _investigator_event(store, case_id)
        advanced = InvestigationRepository(store).save(
            owner,
            expected_version=owner.state_version,
            event="started" if stale_kind == "new_owner" else "attention",
            detail="next checkpoint",
        )
        if stale_kind == "expired":
            monkeypatch.setattr(
                "systemsense.storage.search_frontier.utc_now",
                lambda: turn.deadline_at + timedelta(seconds=1),
            )
        prepared = FrontierInvestigatorTurnCompletionV1(
            turn_id=turn.turn_id,
            case_id=case_id,
            outcome="no_new_fact",
            reason_code="all_facts_already_visible",
            cursor_after=None,
            focused_context_sha256=turn.focused_context_sha256,
        )
        with store.transaction(), pytest.raises(ValueError, match=r"owner|deadline|generation"):
            repo.complete_investigator_turn_in_transaction(
                prepared,
                expected_checkpoint_version=advanced.state_version,
            )
        assert repo.read_investigator_turn_outcome(turn.turn_id) is None


def test_turn_closure_releases_active_case_without_rewriting_v1_terminal(tmp_path: Path) -> None:
    path = tmp_path / "closure.db"
    with SQLiteStore(path) as store:
        case_id, owner = _owner(store)
        repo = SearchFrontierRepository(store)
        event = _investigator_event(store, case_id)
        assert event.versions.evidence is not None
        repo.intake_investigator_event(case_id, event.event_id)
        repo.start_investigator_session(case_id, event.event_id, decision_budget=1)
        turn = _reserve(repo, case_id, event.event_id, owner, event.versions.evidence)
        intent = FrontierInvestigatorTurnClosureIntentV1(
            event_id=event.event_id,
            case_id=case_id,
            final_turn_id=turn.turn_id,
            outcome="no_new_fact",
            reason_code="all_facts_already_visible",
        )
        with store.transaction(), pytest.raises(ValueError, match="completed"):
            repo.close_investigator_session_in_transaction(intent)
        InvestigationRepository(store).save(
            owner,
            expected_version=owner.state_version,
            event="attention",
            detail="no new fact",
            frontier_turn_completion=FrontierInvestigatorTurnCompletionV1(
                turn_id=turn.turn_id,
                case_id=case_id,
                outcome="no_new_fact",
                reason_code="all_facts_already_visible",
                focused_context_sha256=turn.focused_context_sha256,
            ),
        )
        with store.transaction():
            closed = repo.close_investigator_session_in_transaction(intent)
        assert repo.active_investigator_session(case_id) is None
        assert repo.read_investigator_terminal(event.event_id) is None
        assert (
            repo.intake_investigator_event_status(case_id, event.event_id).status
            == "already_terminal"
        )
    with SQLiteStore(path) as reopened:
        repo = SearchFrontierRepository(reopened)
        assert repo.read_investigator_turn_closure(event.event_id) == closed
        assert repo.active_investigator_session(case_id) is None
        assert reopened.connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_case_turn_budget_is_cumulative_across_closed_sessions(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("systemsense.storage.search_frontier._INVESTIGATOR_CASE_TURN_LIMIT", 1)
    with SQLiteStore(tmp_path / "case-turn-cap.db") as store:
        case_id, owner = _owner(store)
        repo = SearchFrontierRepository(store)
        assert repo.investigator_case_turns_remaining(case_id) == 1
        first = _investigator_event(store, case_id)
        assert first.versions.evidence is not None
        repo.intake_investigator_event(case_id, first.event_id)
        repo.start_investigator_session(case_id, first.event_id, decision_budget=1)
        turn = _reserve(repo, case_id, first.event_id, owner, first.versions.evidence)
        assert repo.investigator_case_turns_remaining(case_id) == 0
        advanced = InvestigationRepository(store).save(
            owner,
            expected_version=owner.state_version,
            event="attention",
            detail="considered",
            frontier_turn_completion=FrontierInvestigatorTurnCompletionV1(
                turn_id=turn.turn_id,
                case_id=case_id,
                outcome="no_new_fact",
                reason_code="all_facts_already_visible",
                focused_context_sha256=turn.focused_context_sha256,
            ),
        )
        with store.transaction():
            repo.close_investigator_session_in_transaction(
                FrontierInvestigatorTurnClosureIntentV1(
                    event_id=first.event_id,
                    case_id=case_id,
                    final_turn_id=turn.turn_id,
                    outcome="no_new_fact",
                    reason_code="all_facts_already_visible",
                )
            )
        second = _investigator_event(store, case_id)
        assert second.versions.evidence is not None
        assert repo.intake_investigator_event_status(case_id, second.event_id).status == "queued"
        repo.start_investigator_session(case_id, second.event_id, decision_budget=1)
        with pytest.raises(ValueError, match="budget"):
            _reserve(repo, case_id, second.event_id, advanced, second.versions.evidence)
        assert repo.investigator_turns(case_id, second.event_id) == ()
        assert repo.investigator_case_turns_remaining(case_id) == 0


def test_full_case_turn_cap_blocks_next_event_before_reservation(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "full-case-turn-cap.db") as store:
        case_id, owner = _owner(store)
        repo = SearchFrontierRepository(store)
        for _ in range(4):
            event = _investigator_event(store, case_id)
            assert event.versions.evidence is not None
            assert repo.intake_investigator_event_status(case_id, event.event_id).status == "queued"
            repo.start_investigator_session(case_id, event.event_id, decision_budget=8)
            for _ in range(8):
                turn = _reserve(repo, case_id, event.event_id, owner, event.versions.evidence)
                owner = InvestigationRepository(store).save(
                    owner,
                    expected_version=owner.state_version,
                    event="attention",
                    detail="bounded reconsideration",
                    frontier_turn_completion=FrontierInvestigatorTurnCompletionV1(
                        turn_id=turn.turn_id,
                        case_id=case_id,
                        outcome="no_new_fact",
                        reason_code="all_facts_already_visible",
                        focused_context_sha256=turn.focused_context_sha256,
                    ),
                )
            with store.transaction():
                repo.close_investigator_session_in_transaction(
                    FrontierInvestigatorTurnClosureIntentV1(
                        event_id=event.event_id,
                        case_id=case_id,
                        final_turn_id=repo.investigator_turns(case_id, event.event_id)[-1].turn_id,
                        outcome="no_new_fact",
                        reason_code="all_facts_already_visible",
                    )
                )
        assert repo.investigator_case_turns_remaining(case_id) == 0
        next_event = _investigator_event(store, case_id)
        assert next_event.versions.evidence is not None
        assert (
            repo.intake_investigator_event_status(case_id, next_event.event_id).status == "queued"
        )
        repo.start_investigator_session(case_id, next_event.event_id, decision_budget=1)
        with pytest.raises(ValueError, match="budget"):
            _reserve(repo, case_id, next_event.event_id, owner, next_event.versions.evidence)
        assert repo.investigator_turns(case_id, next_event.event_id) == ()
        terminal = repo.finish_investigator_session(
            case_id, next_event.event_id, outcome="gap", reason_code="budget_exhausted"
        )
        assert terminal.reason_code == "budget_exhausted"
        assert repo.active_investigator_session(case_id) is None


def test_budget_closure_uses_case_cap_when_session_budget_remains(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr("systemsense.storage.search_frontier._INVESTIGATOR_CASE_TURN_LIMIT", 1)
    path = tmp_path / "case-cap-closure.db"
    with SQLiteStore(path) as store:
        case_id, owner = _owner(store)
        repo = SearchFrontierRepository(store)
        event = _investigator_event(store, case_id)
        assert event.source_evidence_id is not None
        assert event.versions.evidence is not None
        repo.intake_investigator_event(case_id, event.event_id)
        repo.start_investigator_session(case_id, event.event_id, decision_budget=3)
        versions = RelevantVersionsV1(objective=1, evidence=event.versions.evidence)
        item = repo.upsert_item(
            case_id,
            FrontierReferenceV1(kind="retrieve_evidence", evidence_id=event.source_evidence_id),
            versions,
        )
        session = repo.active_investigator_session(case_id)
        assert session is not None
        turn = repo.reserve_investigator_turn(
            case_id,
            event.event_id,
            owner_started_version=1,
            expected_checkpoint_version=owner.state_version,
            current_versions=versions,
            focused_context_sha256="a" * 64,
            catalog_generation=event.versions.evidence,
            cursor_before=None,
            cursor_after=None,
            offered_refs=(),
            pending_tail=(),
            offered_item_ids=(item.item_id,),
            pending_item_ids=(),
            eligible_evidence_ids=(event.source_evidence_id,),
            turn_deadline_at=session.deadline_at,
        )
        intent = FrontierInvestigatorTurnClosureIntentV1(
            event_id=event.event_id,
            case_id=case_id,
            final_turn_id=turn.turn_id,
            outcome="gap",
            reason_code="budget_exhausted",
        )
        InvestigationRepository(store).save(
            owner,
            expected_version=owner.state_version,
            event="attention",
            detail="policy unavailable under case cap",
            frontier_turn_completion=FrontierInvestigatorTurnCompletionV1(
                turn_id=turn.turn_id,
                case_id=case_id,
                outcome="gap",
                reason_code="policy_unavailable",
                remaining_item_ids=(item.item_id,),
                focused_context_sha256=turn.focused_context_sha256,
            ),
            frontier_session_closure=intent,
        )
        assert repo.read_investigator_turn_closure(event.event_id) is not None
        assert repo.active_investigator_session(case_id) is None
    monkeypatch.undo()
    with SQLiteStore(path) as reopened:
        repo = SearchFrontierRepository(reopened)
        closure = repo.read_investigator_turn_closure(event.event_id)
        assert closure is not None
        assert closure.reason_code == "budget_exhausted"


def test_completion_recovery_and_closure_reject_backward_storage_clock(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "chronology.db") as store:
        case_id, owner = _owner(store)
        repo = SearchFrontierRepository(store)
        event = _investigator_event(store, case_id)
        assert event.versions.evidence is not None
        repo.intake_investigator_event(case_id, event.event_id)
        repo.start_investigator_session(case_id, event.event_id, decision_budget=1)
        turn = _reserve(repo, case_id, event.event_id, owner, event.versions.evidence)
        monkeypatch.setattr(
            "systemsense.storage.search_frontier.utc_now",
            lambda: turn.reserved_at - timedelta(seconds=1),
        )
        with pytest.raises(ValueError, match="chronology"):
            InvestigationRepository(store).save(
                owner,
                expected_version=owner.state_version,
                event="attention",
                detail="clock moved backward",
                frontier_turn_completion=FrontierInvestigatorTurnCompletionV1(
                    turn_id=turn.turn_id,
                    case_id=case_id,
                    outcome="no_new_fact",
                    reason_code="all_facts_already_visible",
                    focused_context_sha256=turn.focused_context_sha256,
                ),
            )
        assert (
            InvestigationRepository(store).load(str(case_id)).state_version == owner.state_version
        )
        assert repo.read_investigator_turn_outcome(turn.turn_id) is None
        # A replaced owner otherwise permits recovery, but cannot backdate the outcome.
        InvestigationRepository(store).save(
            owner,
            expected_version=owner.state_version,
            event="started",
            detail="new owner",
        )
        with pytest.raises(ValueError, match="chronology"):
            repo.recover_interrupted_investigator_turn(turn.turn_id)
        monkeypatch.undo()
        outcome = repo.recover_interrupted_investigator_turn(turn.turn_id)
        assert outcome.outcome == "interrupted"
        monkeypatch.setattr(
            "systemsense.storage.search_frontier.utc_now",
            lambda: outcome.completed_at - timedelta(seconds=1),
        )
        with store.transaction(), pytest.raises(ValueError, match="chronology"):
            repo.close_investigator_session_in_transaction(
                FrontierInvestigatorTurnClosureIntentV1(
                    event_id=event.event_id,
                    case_id=case_id,
                    final_turn_id=turn.turn_id,
                    outcome="gap",
                    reason_code="owner_interrupted",
                )
            )
        assert repo.read_investigator_turn_closure(event.event_id) is None
        assert repo.active_investigator_session(case_id) is not None


def test_rehashed_outcome_cannot_invent_unoffered_focused_success(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "outcome-tamper.db") as store:
        cases, frontier, owner, item_id, turn_id, completion, transition = _prepared_delivery(store)
        selected = frontier.readback(item_id)
        assert selected.reference.evidence_id is not None
        turn = frontier.read_investigator_turn(turn_id)
        focused = owner.model_copy(
            update={
                "fast_catalog_selected_ids": (selected.reference.evidence_id,),
                "fast_catalog_generation": turn.catalog_generation,
            }
        )
        cases.save(
            focused,
            expected_version=owner.state_version,
            event="frontier_retrieved",
            detail="focused delivery",
            frontier_turn_completion=completion,
            frontier_item_transition=transition,
        )
        original = frontier.read_investigator_turn_outcome(turn_id)
        assert original is not None
        # Historical success remains readable after new evidence changes current generation.
        _investigator_event(store, owner.case_id)
        assert frontier.read_investigator_turn_outcome(turn_id) == original
        unoffered = frontier.upsert_item(
            owner.case_id,
            FrontierReferenceV1(kind="measure", candidate_id="cand_v1_" + "f" * 32),
            turn.current_versions,
        )
        store.connection.execute(
            "DROP TRIGGER search_frontier_investigator_turn_outcomes_no_update"
        )
        payload = original.model_dump(mode="json")
        payload["frontier_item_ids"] = [unoffered.item_id]
        payload["remaining_item_ids"] = [item_id]
        body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        store.connection.execute(
            "UPDATE search_frontier_investigator_turn_outcomes "
            "SET record_json=?,record_sha256=? WHERE turn_id=?",
            (body, hashlib.sha256(body.encode()).hexdigest(), turn_id),
        )
        with pytest.raises(ValueError, match=r"focused delivery|item crosses cases|item versions"):
            frontier.read_investigator_turn_outcome(turn_id)


@pytest.mark.parametrize(
    "corruption", ["foreign_case", "wrong_versions", "not_satisfied", "skip_pending"]
)
def test_rehashed_focused_outcome_revalidates_frozen_item_history(
    tmp_path: Path, corruption: str
) -> None:
    with SQLiteStore(tmp_path / f"outcome-{corruption}.db") as store:
        cases, frontier, owner, item_id, turn_id, completion, transition = _prepared_delivery(store)
        selected = frontier.readback(item_id)
        assert selected.reference.evidence_id is not None
        turn = frontier.read_investigator_turn(turn_id)
        focused = owner.model_copy(
            update={
                "fast_catalog_selected_ids": (selected.reference.evidence_id,),
                "fast_catalog_generation": turn.catalog_generation,
            }
        )
        cases.save(
            focused,
            expected_version=owner.state_version,
            event="frontier_retrieved",
            detail="focused delivery",
            frontier_turn_completion=completion,
            frontier_item_transition=transition,
        )
        extra_event = _investigator_event(store, owner.case_id)
        assert extra_event.source_evidence_id is not None
        candidate_case = owner.case_id
        candidate_versions = turn.current_versions
        if corruption == "foreign_case":
            candidate_case = CaseId.new()
            store.create_case(
                case_id=str(candidate_case),
                kind="general",
                symptom="other",
                created_at="2026-09-23T12:00:00+00:00",
            )
        elif corruption == "wrong_versions":
            candidate_versions = turn.current_versions.model_copy(
                update={"objective": turn.current_versions.objective + 1}
            )
        candidate = frontier.upsert_item(
            candidate_case,
            FrontierReferenceV1(
                kind="retrieve_evidence",
                evidence_id=extra_event.source_evidence_id,
            ),
            candidate_versions,
        )
        if corruption in {"foreign_case", "wrong_versions"}:
            frontier.claim_ready(candidate.item_id, candidate_versions)
            frontier.transition(
                candidate.item_id, FrontierStatus.CLAIMED, FrontierStatus.ADMITTED, "admitted"
            )
            frontier.transition(
                candidate.item_id, FrontierStatus.ADMITTED, FrontierStatus.RUNNING, "retrieving"
            )
            frontier.transition(
                candidate.item_id, FrontierStatus.RUNNING, FrontierStatus.SATISFIED, "satisfied"
            )
        outcome = frontier.read_investigator_turn_outcome(turn_id)
        assert outcome is not None
        turn_payload = turn.model_dump(mode="json")
        outcome_payload = outcome.model_dump(mode="json")
        if corruption == "skip_pending":
            turn_payload["pending_item_ids"] = [candidate.item_id, item_id]
            turn_payload["offered_item_ids"] = []
            outcome_payload["remaining_item_ids"] = [candidate.item_id]
        else:
            turn_payload["offered_item_ids"] = [candidate.item_id]
            outcome_payload["frontier_item_ids"] = [candidate.item_id]
        for table in (
            "search_frontier_investigator_turns",
            "search_frontier_investigator_turn_outcomes",
        ):
            store.connection.execute(f"DROP TRIGGER {table}_no_update")
        for table, payload in (
            ("search_frontier_investigator_turns", turn_payload),
            ("search_frontier_investigator_turn_outcomes", outcome_payload),
        ):
            body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            store.connection.execute(
                f"UPDATE {table} SET record_json=?,record_sha256=? WHERE turn_id=?",
                (body, hashlib.sha256(body.encode()).hexdigest(), turn_id),
            )
        with pytest.raises(ValueError, match=r"focused delivery|item crosses cases|item versions"):
            frontier.read_investigator_turn_outcome(turn_id)


def test_retrieval_page_upsert_is_source_bound_and_all_or_none(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "page-atomic.db") as store:
        case_id, _ = _owner(store)
        other_case, _ = _owner(store)
        repo = SearchFrontierRepository(store)
        first = _investigator_event(store, case_id)
        second = _investigator_event(store, case_id)
        foreign = _investigator_event(store, other_case)
        assert first.source_evidence_id is not None
        assert second.source_evidence_id is not None
        assert second.versions.evidence is not None
        assert foreign.source_evidence_id is not None
        versions = RelevantVersionsV1(objective=1, evidence=second.versions.evidence)
        with pytest.raises(ValueError, match="source"):
            repo.upsert_retrieval_page(
                case_id,
                (first.source_evidence_id, foreign.source_evidence_id),
                versions,
                expected_generation=second.versions.evidence,
            )
        assert store.connection.execute(
            "SELECT COUNT(*) FROM search_frontier_items WHERE case_id=?",
            (str(case_id),),
        ).fetchone() == (0,)
        monkeypatch.setattr("systemsense.storage.search_frontier._ITEM_LIMIT", 1)
        with pytest.raises(FrontierItemCapacityError, match="frontier item limit reached") as error:
            repo.upsert_retrieval_page(
                case_id,
                (first.source_evidence_id, second.source_evidence_id),
                versions,
                expected_generation=second.versions.evidence,
            )
        assert error.value.code == "item_capacity"
        assert store.connection.execute(
            "SELECT COUNT(*) FROM search_frontier_items WHERE case_id=?",
            (str(case_id),),
        ).fetchone() == (0,)
        monkeypatch.undo()
        items = repo.upsert_retrieval_page(
            case_id,
            (first.source_evidence_id, second.source_evidence_id),
            versions,
            expected_generation=second.versions.evidence,
        )
        assert len(items) == 2
        assert (
            repo.upsert_retrieval_page(
                case_id,
                (first.source_evidence_id, second.source_evidence_id),
                versions,
                expected_generation=second.versions.evidence,
            )
            == items
        )


def test_stale_exact_pending_tail_can_only_close_as_stale_gap(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "stale-tail.db") as store:
        case_id, owner = _owner(store)
        repo = SearchFrontierRepository(store)
        first = _investigator_event(store, case_id)
        assert first.source_evidence_id is not None
        assert first.versions.evidence is not None
        repo.intake_investigator_event(case_id, first.event_id)
        session = repo.start_investigator_session(case_id, first.event_id, decision_budget=3)
        old_versions = RelevantVersionsV1(objective=1, evidence=first.versions.evidence)
        pending = repo.upsert_item(
            case_id,
            FrontierReferenceV1(kind="retrieve_evidence", evidence_id=first.source_evidence_id),
            old_versions,
        )
        first_turn = repo.reserve_investigator_turn(
            case_id,
            first.event_id,
            owner_started_version=1,
            expected_checkpoint_version=owner.state_version,
            current_versions=old_versions,
            focused_context_sha256="a" * 64,
            catalog_generation=first.versions.evidence,
            cursor_before=None,
            cursor_after=None,
            offered_refs=(),
            pending_tail=(),
            offered_item_ids=(pending.item_id,),
            pending_item_ids=(),
            eligible_evidence_ids=(first.source_evidence_id,),
            turn_deadline_at=session.deadline_at,
        )
        owner2 = InvestigationRepository(store).save(
            owner,
            expected_version=owner.state_version,
            event="attention",
            detail="deferred",
            frontier_turn_completion=FrontierInvestigatorTurnCompletionV1(
                turn_id=first_turn.turn_id,
                case_id=case_id,
                outcome="gap",
                reason_code="policy_unavailable",
                remaining_item_ids=(pending.item_id,),
                focused_context_sha256=first_turn.focused_context_sha256,
            ),
        )
        second = _investigator_event(store, case_id)
        assert second.versions.evidence is not None
        current_versions = RelevantVersionsV1(objective=1, evidence=second.versions.evidence)
        stale_turn = repo.reserve_investigator_turn(
            case_id,
            first.event_id,
            owner_started_version=1,
            expected_checkpoint_version=owner2.state_version,
            current_versions=current_versions,
            focused_context_sha256="b" * 64,
            catalog_generation=second.versions.evidence,
            cursor_before=None,
            cursor_after=None,
            offered_refs=(),
            pending_tail=(),
            offered_item_ids=(),
            pending_item_ids=(pending.item_id,),
            eligible_evidence_ids=(),
            turn_deadline_at=session.deadline_at,
        )
        assert stale_turn.stale_pending_only is True
        with pytest.raises(ValueError, match="stale pending"):
            InvestigationRepository(store).save(
                owner2,
                expected_version=owner2.state_version,
                event="attention",
                detail="cannot consider stale item as current",
                frontier_turn_completion=FrontierInvestigatorTurnCompletionV1(
                    turn_id=stale_turn.turn_id,
                    case_id=case_id,
                    outcome="no_new_fact",
                    reason_code="all_facts_already_visible",
                    focused_context_sha256=stale_turn.focused_context_sha256,
                ),
            )
        InvestigationRepository(store).save(
            owner2,
            expected_version=owner2.state_version,
            event="attention",
            detail="stale pending work deferred",
            frontier_turn_completion=FrontierInvestigatorTurnCompletionV1(
                turn_id=stale_turn.turn_id,
                case_id=case_id,
                outcome="gap",
                reason_code="stale_context",
                remaining_item_ids=(pending.item_id,),
                focused_context_sha256=stale_turn.focused_context_sha256,
            ),
            frontier_session_closure=FrontierInvestigatorTurnClosureIntentV1(
                event_id=first.event_id,
                case_id=case_id,
                final_turn_id=stale_turn.turn_id,
                outcome="gap",
                reason_code="stale_context",
            ),
        )
        assert repo.read_investigator_turn_closure(first.event_id) is not None
        assert repo.active_investigator_session(case_id) is None


def test_expired_unresolved_success_closes_as_gap_with_historical_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "expired-continuation.db"
    with SQLiteStore(path) as store:
        case_id, owner = _owner(store)
        repo = SearchFrontierRepository(store)
        event = _investigator_event(store, case_id)
        assert event.source_evidence_id is not None
        assert event.versions.evidence is not None
        repo.intake_investigator_event(case_id, event.event_id)
        session = repo.start_investigator_session(case_id, event.event_id, decision_budget=2)
        versions = RelevantVersionsV1(objective=1, evidence=event.versions.evidence)
        item = repo.upsert_item(
            case_id,
            FrontierReferenceV1(kind="retrieve_evidence", evidence_id=event.source_evidence_id),
            versions,
        )
        cursor_after = EvidenceCatalogCursor(
            observed_at=utc_now(), evidence_id=event.source_evidence_id
        )
        turn = repo.reserve_investigator_turn(
            case_id,
            event.event_id,
            owner_started_version=1,
            expected_checkpoint_version=owner.state_version,
            current_versions=versions,
            focused_context_sha256="a" * 64,
            catalog_generation=event.versions.evidence,
            cursor_before=None,
            cursor_after=cursor_after,
            offered_refs=(),
            pending_tail=(),
            offered_item_ids=(item.item_id,),
            pending_item_ids=(),
            eligible_evidence_ids=(event.source_evidence_id,),
            turn_deadline_at=session.deadline_at,
        )
        repo.claim_ready(item.item_id, versions)
        repo.transition(item.item_id, FrontierStatus.CLAIMED, FrontierStatus.ADMITTED, "admitted")
        repo.transition(item.item_id, FrontierStatus.ADMITTED, FrontierStatus.RUNNING, "retrieving")
        delivered = owner.model_copy(
            update={
                "fast_catalog_selected_ids": (event.source_evidence_id,),
                "fast_catalog_generation": event.versions.evidence,
            }
        )
        InvestigationRepository(store).save(
            delivered,
            expected_version=owner.state_version,
            event="frontier_retrieved",
            detail="delivered one page item",
            frontier_turn_completion=FrontierInvestigatorTurnCompletionV1(
                turn_id=turn.turn_id,
                case_id=case_id,
                outcome="focused_delivery",
                reason_code="focused_context_delivered",
                frontier_item_ids=(item.item_id,),
                cursor_after=cursor_after,
                focused_context_sha256=turn.focused_context_sha256,
            ),
            frontier_item_transition=FrontierInvestigatorItemTransitionV1(
                item_id=item.item_id,
                expected_status=FrontierStatus.RUNNING,
                terminal_status=FrontierStatus.SATISFIED,
                reason="focused_delivery_confirmed",
            ),
        )
        intent = FrontierInvestigatorTurnClosureIntentV1(
            event_id=event.event_id,
            case_id=case_id,
            final_turn_id=turn.turn_id,
            outcome="gap",
            reason_code="deadline_expired",
        )
        with store.transaction(), pytest.raises(ValueError, match="deadline"):
            repo.close_investigator_session_in_transaction(intent)
        monkeypatch.setattr(
            "systemsense.storage.search_frontier.utc_now",
            lambda: session.deadline_at + timedelta(seconds=1),
        )
        with store.transaction():
            closed = repo.close_investigator_session_in_transaction(intent)
        assert closed.reason_code == "deadline_expired"
    monkeypatch.undo()
    with SQLiteStore(path) as reopened:
        repo = SearchFrontierRepository(reopened)
        assert repo.read_investigator_turn_closure(event.event_id) == closed
        assert repo.active_investigator_session(case_id) is None


def test_stale_cursor_only_continuation_is_gap_only(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "stale-cursor.db") as store:
        case_id, owner = _owner(store)
        repo = SearchFrontierRepository(store)
        first = _investigator_event(store, case_id)
        assert first.source_evidence_id is not None
        assert first.versions.evidence is not None
        repo.intake_investigator_event(case_id, first.event_id)
        session = repo.start_investigator_session(case_id, first.event_id, decision_budget=3)
        cursor = EvidenceCatalogCursor(observed_at=utc_now(), evidence_id=first.source_evidence_id)
        old_versions = RelevantVersionsV1(objective=1, evidence=first.versions.evidence)
        first_turn = repo.reserve_investigator_turn(
            case_id,
            first.event_id,
            owner_started_version=1,
            expected_checkpoint_version=owner.state_version,
            current_versions=old_versions,
            focused_context_sha256="a" * 64,
            catalog_generation=first.versions.evidence,
            cursor_before=None,
            cursor_after=cursor,
            offered_refs=(),
            pending_tail=(),
            offered_item_ids=(),
            pending_item_ids=(),
            eligible_evidence_ids=(),
            turn_deadline_at=session.deadline_at,
        )
        owner2 = InvestigationRepository(store).save(
            owner,
            expected_version=owner.state_version,
            event="attention",
            detail="page empty",
            frontier_turn_completion=FrontierInvestigatorTurnCompletionV1(
                turn_id=first_turn.turn_id,
                case_id=case_id,
                outcome="no_new_fact",
                reason_code="all_facts_already_visible",
                cursor_after=cursor,
                focused_context_sha256=first_turn.focused_context_sha256,
            ),
        )
        second = _investigator_event(store, case_id)
        assert second.versions.evidence is not None
        current_versions = RelevantVersionsV1(objective=1, evidence=second.versions.evidence)
        turn = repo.reserve_investigator_turn(
            case_id,
            first.event_id,
            owner_started_version=1,
            expected_checkpoint_version=owner2.state_version,
            current_versions=current_versions,
            focused_context_sha256="b" * 64,
            catalog_generation=second.versions.evidence,
            cursor_before=cursor,
            cursor_after=cursor,
            offered_refs=(),
            pending_tail=(),
            offered_item_ids=(),
            pending_item_ids=(),
            eligible_evidence_ids=(),
            turn_deadline_at=session.deadline_at,
        )
        assert turn.stale_pending_only is True
        with pytest.raises(ValueError, match="stale pending"):
            InvestigationRepository(store).save(
                owner2,
                expected_version=owner2.state_version,
                event="attention",
                detail="cannot classify cursor as current",
                frontier_turn_completion=FrontierInvestigatorTurnCompletionV1(
                    turn_id=turn.turn_id,
                    case_id=case_id,
                    outcome="no_new_fact",
                    reason_code="all_facts_already_visible",
                    cursor_after=cursor,
                    focused_context_sha256=turn.focused_context_sha256,
                ),
            )
        InvestigationRepository(store).save(
            owner2,
            expected_version=owner2.state_version,
            event="attention",
            detail="stale cursor deferred",
            frontier_turn_completion=FrontierInvestigatorTurnCompletionV1(
                turn_id=turn.turn_id,
                case_id=case_id,
                outcome="gap",
                reason_code="stale_context",
                cursor_after=cursor,
                focused_context_sha256=turn.focused_context_sha256,
            ),
            frontier_session_closure=FrontierInvestigatorTurnClosureIntentV1(
                event_id=first.event_id,
                case_id=case_id,
                final_turn_id=turn.turn_id,
                outcome="gap",
                reason_code="stale_context",
            ),
        )
        assert repo.read_investigator_turn_closure(first.event_id) is not None


def test_case_stopped_closure_binds_immutable_terminal_event(tmp_path: Path) -> None:
    path = tmp_path / "case-stopped.db"
    with SQLiteStore(path) as store:
        case_id, owner = _owner(store)
        repo = SearchFrontierRepository(store)
        event = _investigator_event(store, case_id)
        assert event.source_evidence_id is not None
        assert event.versions.evidence is not None
        repo.intake_investigator_event(case_id, event.event_id)
        session = repo.start_investigator_session(case_id, event.event_id, decision_budget=2)
        cursor = EvidenceCatalogCursor(observed_at=utc_now(), evidence_id=event.source_evidence_id)
        turn = repo.reserve_investigator_turn(
            case_id,
            event.event_id,
            owner_started_version=1,
            expected_checkpoint_version=owner.state_version,
            current_versions=RelevantVersionsV1(objective=1, evidence=event.versions.evidence),
            focused_context_sha256="a" * 64,
            catalog_generation=event.versions.evidence,
            cursor_before=None,
            cursor_after=cursor,
            offered_refs=(),
            pending_tail=(),
            offered_item_ids=(),
            pending_item_ids=(),
            eligible_evidence_ids=(),
            turn_deadline_at=session.deadline_at,
        )
        continued = InvestigationRepository(store).save(
            owner,
            expected_version=owner.state_version,
            event="attention",
            detail="page empty",
            frontier_turn_completion=FrontierInvestigatorTurnCompletionV1(
                turn_id=turn.turn_id,
                case_id=case_id,
                outcome="no_new_fact",
                reason_code="all_facts_already_visible",
                cursor_after=cursor,
                focused_context_sha256=turn.focused_context_sha256,
            ),
        )
        intent = FrontierInvestigatorTurnClosureIntentV1(
            event_id=event.event_id,
            case_id=case_id,
            final_turn_id=turn.turn_id,
            outcome="gap",
            reason_code="case_stopped",
        )
        with store.transaction(), pytest.raises(ValueError, match="terminal event"):
            repo.close_investigator_session_in_transaction(intent)
        InvestigationRepository(store).save(
            continued.model_copy(update={"status": InvestigationStatus.COMPLETE}),
            expected_version=continued.state_version,
            event="finished",
            detail="case stopped",
        )
        with store.transaction():
            closed = repo.close_investigator_session_in_transaction(intent)
        assert closed.terminal_event_id is not None
        assert closed.terminal_checkpoint_version == continued.state_version + 1
    with SQLiteStore(path) as reopened:
        repo = SearchFrontierRepository(reopened)
        assert repo.read_investigator_turn_closure(event.event_id) == closed
        assert repo.active_investigator_session(case_id) is None
        with reopened.transaction():
            reopened.connection.execute(
                "DROP TRIGGER search_frontier_investigator_turn_closures_no_update"
            )
            payload = closed.model_dump(mode="json")
            payload["terminal_event_id"] = "trace_999999"
            body = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
            reopened.connection.execute(
                "UPDATE search_frontier_investigator_turn_closures "
                "SET record_json=?,record_sha256=? WHERE event_id=?",
                (body, hashlib.sha256(body.encode()).hexdigest(), event.event_id),
            )
        with pytest.raises(ValueError, match="terminal receipt"):
            repo.read_investigator_turn_closure(event.event_id)


def test_missing_event_source_blocks_turn_reservation(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "source-before-turn.db") as store:
        case_id, owner = _owner(store)
        repo = SearchFrontierRepository(store)
        event = _investigator_event(store, case_id)
        assert event.source_evidence_id is not None
        repo.intake_investigator_event(case_id, event.event_id)
        repo.start_investigator_session(case_id, event.event_id, decision_budget=1)
        store.connection.execute(
            "DELETE FROM evidence WHERE evidence_id=?", (str(event.source_evidence_id),)
        )
        with pytest.raises(ValueError, match="source unverifiable"):
            _reserve(repo, case_id, event.event_id, owner, event.versions.evidence or 0)
        assert repo.investigator_turns(case_id, event.event_id) == ()
        assert (
            repo.finish_investigator_session(
                case_id, event.event_id, outcome="gap", reason_code="source_unverifiable"
            ).reason_code
            == "source_unverifiable"
        )


def test_source_lost_during_reserved_turn_records_gap(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "source-during-turn.db") as store:
        case_id, owner = _owner(store)
        repo = SearchFrontierRepository(store)
        event = _investigator_event(store, case_id)
        assert event.source_evidence_id is not None and event.versions.evidence is not None
        repo.intake_investigator_event(case_id, event.event_id)
        repo.start_investigator_session(case_id, event.event_id, decision_budget=1)
        turn = _reserve(repo, case_id, event.event_id, owner, event.versions.evidence)
        store.connection.execute(
            "DELETE FROM evidence WHERE evidence_id=?", (str(event.source_evidence_id),)
        )
        with pytest.raises(ValueError, match="source unverifiable"):
            InvestigationRepository(store).save(
                owner,
                expected_version=owner.state_version,
                event="attention",
                detail="incorrect success",
                frontier_turn_completion=FrontierInvestigatorTurnCompletionV1(
                    turn_id=turn.turn_id,
                    case_id=case_id,
                    outcome="no_new_fact",
                    reason_code="all_facts_already_visible",
                    focused_context_sha256=turn.focused_context_sha256,
                ),
            )
        assert repo.read_investigator_turn_outcome(turn.turn_id) is None
        InvestigationRepository(store).save(
            owner,
            expected_version=owner.state_version,
            event="attention",
            detail="source unavailable",
            frontier_turn_completion=FrontierInvestigatorTurnCompletionV1(
                turn_id=turn.turn_id,
                case_id=case_id,
                outcome="gap",
                reason_code="source_unverifiable",
                focused_context_sha256=turn.focused_context_sha256,
            ),
        )
        with store.transaction():
            closure = repo.close_investigator_session_in_transaction(
                FrontierInvestigatorTurnClosureIntentV1(
                    event_id=event.event_id,
                    case_id=case_id,
                    final_turn_id=turn.turn_id,
                    outcome="gap",
                    reason_code="source_unverifiable",
                )
            )
        assert closure.reason_code == "source_unverifiable"
        assert repo.read_investigator_turn_closure(event.event_id) == closure


def test_source_lost_after_completed_turn_closes_unresolved_cursor(tmp_path: Path) -> None:
    path = tmp_path / "source-after-turn.db"
    with SQLiteStore(path) as store:
        case_id, owner = _owner(store)
        repo = SearchFrontierRepository(store)
        event = _investigator_event(store, case_id)
        assert event.source_evidence_id is not None and event.versions.evidence is not None
        repo.intake_investigator_event(case_id, event.event_id)
        session = repo.start_investigator_session(case_id, event.event_id, decision_budget=2)
        cursor = EvidenceCatalogCursor(observed_at=utc_now(), evidence_id=event.source_evidence_id)
        turn = repo.reserve_investigator_turn(
            case_id,
            event.event_id,
            owner_started_version=1,
            expected_checkpoint_version=owner.state_version,
            current_versions=RelevantVersionsV1(objective=1, evidence=event.versions.evidence),
            focused_context_sha256="a" * 64,
            catalog_generation=event.versions.evidence,
            cursor_before=None,
            cursor_after=cursor,
            offered_refs=(),
            pending_tail=(),
            offered_item_ids=(),
            pending_item_ids=(),
            eligible_evidence_ids=(),
            turn_deadline_at=session.deadline_at,
        )
        InvestigationRepository(store).save(
            owner,
            expected_version=owner.state_version,
            event="attention",
            detail="page continuation",
            frontier_turn_completion=FrontierInvestigatorTurnCompletionV1(
                turn_id=turn.turn_id,
                case_id=case_id,
                outcome="no_new_fact",
                reason_code="all_facts_already_visible",
                cursor_after=cursor,
                focused_context_sha256=turn.focused_context_sha256,
            ),
        )
        store.connection.execute(
            "DELETE FROM evidence WHERE evidence_id=?", (str(event.source_evidence_id),)
        )
        with store.transaction():
            closed = repo.close_investigator_session_in_transaction(
                FrontierInvestigatorTurnClosureIntentV1(
                    event_id=event.event_id,
                    case_id=case_id,
                    final_turn_id=turn.turn_id,
                    outcome="gap",
                    reason_code="source_unverifiable",
                )
            )
        assert repo.read_investigator_turn_outcome(turn.turn_id) is not None
        assert repo.read_investigator_turn_closure(event.event_id) == closed
        assert repo.active_investigator_session(case_id) is None
    with SQLiteStore(path) as reopened:
        assert (
            SearchFrontierRepository(reopened).read_investigator_turn_closure(event.event_id)
            == closed
        )
