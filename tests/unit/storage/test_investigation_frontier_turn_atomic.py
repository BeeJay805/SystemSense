"""Focused delivery, the case checkpoint, and turn custody commit together."""

from datetime import timedelta
from pathlib import Path

import pytest
from test_search_frontier import _investigator_event  # pyright: ignore[reportPrivateUsage]

from systemsense.application.investigation_state import InvestigationState, InvestigationStatus
from systemsense.domain.ids import CaseId
from systemsense.domain.time import utc_now
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.search_frontier import (
    FrontierInvestigatorItemTransitionV1,
    FrontierInvestigatorTurnClosureIntentV1,
    FrontierInvestigatorTurnCompletionV1,
    FrontierReferenceV1,
    FrontierStatus,
    RelevantVersionsV1,
    SearchFrontierRepository,
)
from systemsense.storage.sqlite_store import SQLiteStore


def _prepared_delivery(store: SQLiteStore):
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
    cases = InvestigationRepository(store)
    cases.create(state)
    owner = cases.save(
        state.model_copy(update={"status": InvestigationStatus.RUNNING}),
        expected_version=0,
        event="started",
        detail="owner began",
    )
    frontier = SearchFrontierRepository(store)
    event = _investigator_event(store, state.case_id)
    assert event.source_evidence_id is not None
    assert event.versions.evidence is not None
    frontier.intake_investigator_event(state.case_id, event.event_id)
    session = frontier.start_investigator_session(state.case_id, event.event_id, decision_budget=2)
    versions = RelevantVersionsV1(objective=1, evidence=event.versions.evidence)
    item = frontier.upsert_item(
        state.case_id,
        FrontierReferenceV1(kind="retrieve_evidence", evidence_id=event.source_evidence_id),
        versions,
    )
    turn = frontier.reserve_investigator_turn(
        state.case_id,
        event.event_id,
        owner_started_version=owner.state_version,
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
        turn_deadline_at=min(owner.deadline_at, session.deadline_at),
    )
    frontier.claim_ready(item.item_id, versions)
    frontier.transition(item.item_id, FrontierStatus.CLAIMED, FrontierStatus.ADMITTED, "admitted")
    frontier.transition(item.item_id, FrontierStatus.ADMITTED, FrontierStatus.RUNNING, "retrieving")
    completion = FrontierInvestigatorTurnCompletionV1(
        turn_id=turn.turn_id,
        case_id=state.case_id,
        outcome="focused_delivery",
        reason_code="focused_context_delivered",
        frontier_item_ids=(item.item_id,),
        cursor_after=None,
        focused_context_sha256=turn.focused_context_sha256,
    )
    transition = FrontierInvestigatorItemTransitionV1(
        item_id=item.item_id,
        expected_status=FrontierStatus.RUNNING,
        terminal_status=FrontierStatus.SATISFIED,
        reason="focused_delivery_confirmed",
    )
    return cases, frontier, owner, item.item_id, turn.turn_id, completion, transition


def test_focused_delivery_and_checkpoint_commit_atomically(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "atomic-delivery.db") as store:
        cases, frontier, owner, item_id, turn_id, completion, transition = _prepared_delivery(store)
        with pytest.raises(ValueError, match="selected evidence"):
            cases.save(
                owner,
                expected_version=owner.state_version,
                event="frontier_retrieved",
                detail="unchanged checkpoint is not delivery",
                frontier_turn_completion=completion,
                frontier_item_transition=transition,
            )
        assert frontier.readback(item_id).status is FrontierStatus.RUNNING
        assert frontier.read_investigator_turn_outcome(turn_id) is None
        selected_item = frontier.readback(item_id)
        assert selected_item.reference.evidence_id is not None
        reserved = frontier.read_investigator_turn(turn_id)
        focused = owner.model_copy(
            update={
                "fast_catalog_selected_ids": (selected_item.reference.evidence_id,),
                "fast_catalog_generation": reserved.catalog_generation,
            }
        )
        turn = frontier.read_investigator_turn(turn_id)
        closure = FrontierInvestigatorTurnClosureIntentV1(
            event_id=turn.event_id,
            case_id=owner.case_id,
            final_turn_id=turn_id,
            outcome="focused_delivery",
            reason_code="focused_context_delivered",
        )

        updated = cases.save(
            focused,
            expected_version=owner.state_version,
            event="frontier_retrieved",
            detail="focused delivery confirmed",
            frontier_turn_completion=completion,
            frontier_item_transition=transition,
            frontier_session_closure=closure,
        )

        assert cases.load(str(owner.case_id)) == updated
        assert frontier.readback(item_id).status is FrontierStatus.SATISFIED
        outcome = frontier.read_investigator_turn_outcome(turn_id)
        assert outcome is not None
        assert outcome.outcome == "focused_delivery"
        assert outcome.resulting_checkpoint_version == updated.state_version
        assert frontier.read_investigator_turn_closure(turn.event_id) is not None
        assert frontier.active_investigator_session(owner.case_id) is None


def test_rejected_turn_completion_rolls_back_checkpoint_and_item(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "atomic-rollback.db") as store:
        cases, frontier, owner, item_id, turn_id, completion, transition = _prepared_delivery(store)
        bad = completion.model_copy(update={"focused_context_sha256": "b" * 64})
        selected_item = frontier.readback(item_id)
        assert selected_item.reference.evidence_id is not None
        reserved = frontier.read_investigator_turn(turn_id)
        focused = owner.model_copy(
            update={
                "fast_catalog_selected_ids": (selected_item.reference.evidence_id,),
                "fast_catalog_generation": reserved.catalog_generation,
            }
        )

        with pytest.raises(ValueError, match="focused context"):
            cases.save(
                focused,
                expected_version=owner.state_version,
                event="frontier_retrieved",
                detail="must roll back",
                frontier_turn_completion=bad,
                frontier_item_transition=transition,
            )

        assert cases.load(str(owner.case_id)).state_version == owner.state_version
        assert frontier.readback(item_id).status is FrontierStatus.RUNNING
        assert frontier.read_investigator_turn_outcome(turn_id) is None


def test_rejected_closure_rolls_back_delivery_and_turn_outcome(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "atomic-closure-rollback.db") as store:
        cases, frontier, owner, item_id, turn_id, completion, transition = _prepared_delivery(store)
        selected_item = frontier.readback(item_id)
        assert selected_item.reference.evidence_id is not None
        turn = frontier.read_investigator_turn(turn_id)
        focused = owner.model_copy(
            update={
                "fast_catalog_selected_ids": (selected_item.reference.evidence_id,),
                "fast_catalog_generation": turn.catalog_generation,
            }
        )
        wrong_closure = FrontierInvestigatorTurnClosureIntentV1(
            event_id=turn.event_id,
            case_id=owner.case_id,
            final_turn_id=turn_id,
            outcome="no_new_fact",
            reason_code="all_facts_already_visible",
        )

        with pytest.raises(ValueError, match="closure"):
            cases.save(
                focused,
                expected_version=owner.state_version,
                event="frontier_retrieved",
                detail="closure must roll back",
                frontier_turn_completion=completion,
                frontier_item_transition=transition,
                frontier_session_closure=wrong_closure,
            )

        assert cases.load(str(owner.case_id)).state_version == owner.state_version
        assert frontier.readback(item_id).status is FrontierStatus.RUNNING
        assert frontier.read_investigator_turn_outcome(turn_id) is None
        assert frontier.read_investigator_turn_closure(turn.event_id) is None
