"""Expiry of an admitted mixed turn without a retained page tail."""

from datetime import timedelta
from pathlib import Path

import pytest

from systemsense.application.investigation_state import InvestigationState, InvestigationStatus
from systemsense.application.investigator import Investigator
from systemsense.storage.search_frontier import (
    FrontierEventV1,
    FrontierInvestigatorTurnClosureIntentV1,
    FrontierInvestigatorTurnOutcomeV3,
    SearchFrontierRepository,
)
from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration.test_event_frontier_loop import (
    MeasurementFirstRanker,
    _app_with_registered_host_probes,  # pyright: ignore[reportPrivateUsage]
    _started_with_event,  # pyright: ignore[reportPrivateUsage]
)
from tests.unit.application.test_general_candidate_catalog import (
    _source,  # pyright: ignore[reportPrivateUsage]
)


def _final_admission(
    store: SQLiteStore, monkeypatch: pytest.MonkeyPatch
) -> tuple[Investigator, InvestigationState, FrontierEventV1, SearchFrontierRepository]:
    app = _app_with_registered_host_probes(store, MeasurementFirstRanker())
    state, event, _ = _started_with_event(app, store, count=1, budget_ms=30_000)
    _source(store, state.case_id, age_seconds=5, epoch=state.state_version)

    def worker_unavailable(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("synthetic worker unavailable after admission")

    monkeypatch.setattr(app.runtime, "execute_candidate_measurement", worker_unavailable)
    updated, _, handled = app._event_frontier_turn(  # pyright: ignore[reportPrivateUsage]
        state, app.context(str(state.case_id), state=state), state.state_version
    )
    frontier = SearchFrontierRepository(store)
    turns = frontier.investigator_turns(state.case_id, event.event_id)
    assert handled and len(turns) == 1
    outcome = frontier.read_investigator_turn_outcome(turns[0].turn_id)
    assert isinstance(outcome, FrontierInvestigatorTurnOutcomeV3)
    assert outcome.outcome == "measurement_admitted"
    assert outcome.remaining_item_ids == ()
    assert outcome.remaining_refs == ()
    assert outcome.cursor_after is None
    assert frontier.active_investigator_session(state.case_id) is not None
    return app, updated, event, frontier


def test_expired_final_measurement_without_tail_closes_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "measurement-expiry.db") as store:
        app, state, event, frontier = _final_admission(store, monkeypatch)
        session = frontier.active_investigator_session(state.case_id)
        assert session is not None
        expired_at = session.deadline_at + timedelta(seconds=1)
        monkeypatch.setattr("systemsense.application.investigator.utc_now", lambda: expired_at)
        monkeypatch.setattr("systemsense.storage.search_frontier.utc_now", lambda: expired_at)

        updated = app._expire_event_frontier_session(  # pyright: ignore[reportPrivateUsage]
            state, frontier, event.event_id
        )

        closure = frontier.read_investigator_turn_closure(event.event_id)
        assert closure is not None and closure.outcome == "gap"
        assert closure.reason_code == "deadline_expired"
        assert frontier.active_investigator_session(state.case_id) is None
        assert updated.status is InvestigationStatus.RUNNING
        assert updated.state_version == state.state_version + 1


def test_final_measurement_without_tail_cannot_close_before_deadline(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "measurement-early-closure.db") as store:
        _, state, event, frontier = _final_admission(store, monkeypatch)
        session = frontier.active_investigator_session(state.case_id)
        assert session is not None
        early_at = min(session.deadline_at, state.deadline_at) - timedelta(milliseconds=1)
        monkeypatch.setattr("systemsense.storage.search_frontier.utc_now", lambda: early_at)
        turn = frontier.investigator_turns(state.case_id, event.event_id)[0]

        with pytest.raises(ValueError, match="deadline closure is not expired or unresolved"):
            with store.transaction():
                frontier.close_investigator_session_in_transaction(
                    FrontierInvestigatorTurnClosureIntentV1(
                        event_id=event.event_id,
                        case_id=state.case_id,
                        final_turn_id=turn.turn_id,
                        outcome="gap",
                        reason_code="deadline_expired",
                    )
                )

        assert frontier.read_investigator_turn_closure(event.event_id) is None
        assert frontier.active_investigator_session(state.case_id) is not None
