"""Pending retrievals survive a same-case evidence generation advance."""

import sqlite3
from pathlib import Path

import pytest
from test_search_frontier import _investigator_event  # pyright: ignore[reportPrivateUsage]
from test_search_frontier_turns import _owner  # pyright: ignore[reportPrivateUsage]

from systemsense.application.investigation_state import InvestigationState
from systemsense.domain.ids import CaseId
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.search_frontier import (
    FrontierEventV1,
    FrontierInvestigatorItemTransitionV1,
    FrontierInvestigatorSessionV1,
    FrontierInvestigatorTurnCompletionV1,
    FrontierInvestigatorTurnV2,
    FrontierItemV1,
    FrontierReferenceV1,
    FrontierStatus,
    RelevantVersionsV1,
    SearchFrontierRepository,
)
from systemsense.storage.sqlite_store import SQLiteStore


def _pending_case(
    store: SQLiteStore,
) -> tuple[
    CaseId,
    InvestigationState,
    SearchFrontierRepository,
    FrontierEventV1,
    FrontierInvestigatorSessionV1,
    FrontierItemV1,
    RelevantVersionsV1,
]:
    case_id, owner = _owner(store)
    repo = SearchFrontierRepository(store)
    event = _investigator_event(store, case_id)
    assert event.source_evidence_id is not None and event.versions.evidence is not None
    repo.intake_investigator_event(case_id, event.event_id)
    session = repo.start_investigator_session(case_id, event.event_id, decision_budget=3)
    old_versions = RelevantVersionsV1(objective=1, evidence=event.versions.evidence)
    pending = repo.upsert_item(
        case_id,
        FrontierReferenceV1(kind="retrieve_evidence", evidence_id=event.source_evidence_id),
        old_versions,
    )
    first_turn = repo.reserve_investigator_turn(
        case_id,
        event.event_id,
        owner_started_version=1,
        expected_checkpoint_version=owner.state_version,
        current_versions=old_versions,
        focused_context_sha256="a" * 64,
        catalog_generation=event.versions.evidence,
        cursor_before=None,
        cursor_after=None,
        offered_refs=(),
        pending_tail=(),
        offered_item_ids=(pending.item_id,),
        pending_item_ids=(),
        eligible_evidence_ids=(event.source_evidence_id,),
        turn_deadline_at=session.deadline_at,
    )
    owner = InvestigationRepository(store).save(
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
    next_event = _investigator_event(store, case_id)
    assert next_event.versions.evidence is not None
    versions = RelevantVersionsV1(objective=1, evidence=next_event.versions.evidence)
    return case_id, owner, repo, event, session, pending, versions


def _refresh(
    case_id: CaseId,
    owner: InvestigationState,
    repo: SearchFrontierRepository,
    event: FrontierEventV1,
    session: FrontierInvestigatorSessionV1,
    pending: FrontierItemV1,
    versions: RelevantVersionsV1,
) -> FrontierInvestigatorTurnV2:
    assert versions.evidence is not None
    turn = repo.reserve_investigator_turn(
        case_id,
        event.event_id,
        owner_started_version=1,
        expected_checkpoint_version=owner.state_version,
        current_versions=versions,
        focused_context_sha256="b" * 64,
        catalog_generation=versions.evidence,
        cursor_before=None,
        cursor_after=None,
        offered_refs=(),
        pending_tail=(),
        offered_item_ids=(),
        pending_item_ids=(pending.item_id,),
        eligible_evidence_ids=(),
        turn_deadline_at=session.deadline_at,
        refresh_pending=True,
    )
    assert isinstance(turn, FrontierInvestigatorTurnV2)
    return turn


def test_refresh_reserves_successor_and_lineage_atomically(tmp_path: Path) -> None:
    path = tmp_path / "refresh.db"
    with SQLiteStore(path) as store:
        case_id, owner, repo, event, session, pending, versions = _pending_case(store)
        turn = _refresh(case_id, owner, repo, event, session, pending, versions)
        assert isinstance(turn, FrontierInvestigatorTurnV2)
        assert turn.stale_pending_only is False
        assert turn.cursor_after is None
        assert len(turn.pending_item_ids) == 1
        successor_id = turn.pending_item_ids[0]
        assert successor_id != pending.item_id
        assert turn.pending_refresh_lineage[0].predecessor_item_id == pending.item_id
        assert turn.pending_refresh_lineage[0].successor_item_id == successor_id
        assert repo.readback(pending.item_id).status is FrontierStatus.OBSOLETE
        assert repo.readback(successor_id).status is FrontierStatus.REQUESTED
        assert repo.read_investigator_turn(turn.turn_id) == turn
    with SQLiteStore(path) as reopened:
        assert SearchFrontierRepository(reopened).read_investigator_turn(turn.turn_id) == turn


def test_refresh_rejects_missing_source_without_partial_successor(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "missing.db") as store:
        case_id, owner, repo, event, session, pending, versions = _pending_case(store)
        assert pending.reference.evidence_id is not None
        store.connection.execute(
            "DELETE FROM evidence WHERE evidence_id=?", (str(pending.reference.evidence_id),)
        )
        with pytest.raises(ValueError, match=r"source unverifiable|source-bound"):
            _refresh(case_id, owner, repo, event, session, pending, versions)
        assert repo.readback(pending.item_id).status is FrontierStatus.REQUESTED
        assert len(repo.investigator_turns(case_id, event.event_id)) == 1


def test_refresh_rejects_objective_change_without_mutation(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "objective.db") as store:
        case_id, owner, repo, event, session, pending, versions = _pending_case(store)
        changed = versions.model_copy(update={"objective": 2})
        with pytest.raises(ValueError, match=r"current case snapshot|retrievable"):
            _refresh(case_id, owner, repo, event, session, pending, changed)
        assert repo.readback(pending.item_id).status is FrontierStatus.REQUESTED
        assert len(repo.investigator_turns(case_id, event.event_id)) == 1


def test_refresh_capacity_failure_rolls_back_obsolete_transition(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "capacity.db") as store:
        case_id, owner, repo, event, session, pending, versions = _pending_case(store)
        for objective in range(2, 129):
            repo.upsert_item(
                case_id,
                pending.reference,
                RelevantVersionsV1(objective=objective, evidence=versions.evidence),
            )
        count_before = store.connection.execute(
            "SELECT COUNT(*) FROM search_frontier_items WHERE case_id=?", (str(case_id),)
        ).fetchone()
        assert count_before == (128,)
        with pytest.raises(ValueError, match="frontier item limit reached"):
            _refresh(case_id, owner, repo, event, session, pending, versions)
        assert repo.readback(pending.item_id).status is FrontierStatus.REQUESTED
        assert len(repo.investigator_turns(case_id, event.event_id)) == 1
        assert (
            store.connection.execute(
                "SELECT COUNT(*) FROM search_frontier_items WHERE case_id=?", (str(case_id),)
            ).fetchone()
            == count_before
        )


def test_v31_upgrade_preserves_historical_v1_turn_and_outcome(tmp_path: Path) -> None:
    path = tmp_path / "historical.db"
    with SQLiteStore(path) as store:
        case_id, _, repo, event, _, _, _ = _pending_case(store)
        historical_turn = repo.investigator_turns(case_id, event.event_id)[0]
        historical_outcome = repo.read_investigator_turn_outcome(historical_turn.turn_id)
        assert historical_outcome is not None
    migration_30 = (
        Path(__file__).parents[3]
        / "src/systemsense/storage/migrations/030_frontier_investigator_turns.sql"
    ).read_text(encoding="utf-8")
    turn_schema_30 = migration_30.split(
        "CREATE TABLE search_frontier_investigator_turn_outcomes", 1
    )[0]
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA foreign_keys = OFF")
        connection.execute("DROP TABLE candidate_launch_consumptions")
        connection.execute("DROP TABLE candidate_launch_continuations")
        historical_row = connection.execute(
            "SELECT * FROM search_frontier_investigator_turns WHERE turn_id=?",
            (historical_turn.turn_id,),
        ).fetchone()
        assert historical_row is not None
        connection.execute("DROP TABLE search_frontier_investigator_turns")
        connection.executescript(turn_schema_30)
        connection.execute(
            "INSERT INTO search_frontier_investigator_turns VALUES (?,?,?,?,?,?,?,?)",
            historical_row,
        )
        table_sql = connection.execute(
            "SELECT sql FROM sqlite_schema WHERE name='search_frontier_investigator_turns'"
        ).fetchone()
        assert table_sql is not None and "schema_version = 1" in str(table_sql[0])
        connection.execute("PRAGMA user_version = 30")
        assert connection.execute("PRAGMA foreign_key_check").fetchall() == []
    with SQLiteStore(path) as upgraded:
        repo = SearchFrontierRepository(upgraded)
        assert upgraded.schema_version() == 33
        assert repo.read_investigator_turn(historical_turn.turn_id) == historical_turn
        assert repo.read_investigator_turn_outcome(historical_turn.turn_id) == historical_outcome
        assert upgraded.connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_refreshed_successor_can_commit_focused_delivery(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "delivered.db") as store:
        case_id, owner, repo, event, session, pending, versions = _pending_case(store)
        turn = _refresh(case_id, owner, repo, event, session, pending, versions)
        successor_id = turn.pending_item_ids[0]
        successor = repo.claim_ready(successor_id, versions)
        assert successor is not None
        repo.transition(successor_id, FrontierStatus.CLAIMED, FrontierStatus.ADMITTED, "admitted")
        repo.transition(successor_id, FrontierStatus.ADMITTED, FrontierStatus.RUNNING, "retrieving")
        assert successor.reference.evidence_id is not None
        focused = owner.model_copy(
            update={
                "fast_catalog_selected_ids": (successor.reference.evidence_id,),
                "fast_catalog_generation": turn.catalog_generation,
            }
        )
        completion = FrontierInvestigatorTurnCompletionV1(
            turn_id=turn.turn_id,
            case_id=case_id,
            outcome="focused_delivery",
            reason_code="focused_context_delivered",
            frontier_item_ids=(successor_id,),
            focused_context_sha256=turn.focused_context_sha256,
        )
        updated = InvestigationRepository(store).save(
            focused,
            expected_version=owner.state_version,
            event="frontier_retrieved",
            detail="refreshed evidence selected",
            frontier_turn_completion=completion,
            frontier_item_transition=FrontierInvestigatorItemTransitionV1(
                item_id=successor_id,
                expected_status=FrontierStatus.RUNNING,
                terminal_status=FrontierStatus.SATISFIED,
                reason="focused_delivery_confirmed",
            ),
        )
        assert updated.fast_catalog_generation == turn.catalog_generation
        assert repo.readback(successor_id).status is FrontierStatus.SATISFIED
        outcome = repo.read_investigator_turn_outcome(turn.turn_id)
        assert outcome is not None and outcome.outcome == "focused_delivery"


def test_refreshed_turn_rejects_later_generation_before_success(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "later-generation.db") as store:
        case_id, owner, repo, event, session, pending, versions = _pending_case(store)
        turn = _refresh(case_id, owner, repo, event, session, pending, versions)
        successor_id = turn.pending_item_ids[0]
        successor = repo.claim_ready(successor_id, versions)
        assert successor is not None and successor.reference.evidence_id is not None
        repo.transition(successor_id, FrontierStatus.CLAIMED, FrontierStatus.ADMITTED, "admitted")
        repo.transition(successor_id, FrontierStatus.ADMITTED, FrontierStatus.RUNNING, "retrieving")
        later = _investigator_event(store, case_id)
        assert later.versions.evidence is not None
        assert later.versions.evidence > turn.catalog_generation
        focused = owner.model_copy(
            update={
                "fast_catalog_selected_ids": (successor.reference.evidence_id,),
                "fast_catalog_generation": turn.catalog_generation,
            }
        )
        with pytest.raises(ValueError, match="catalog generation is stale"):
            InvestigationRepository(store).save(
                focused,
                expected_version=owner.state_version,
                event="frontier_retrieved",
                detail="incorrect same-generation success",
                frontier_turn_completion=FrontierInvestigatorTurnCompletionV1(
                    turn_id=turn.turn_id,
                    case_id=case_id,
                    outcome="focused_delivery",
                    reason_code="focused_context_delivered",
                    frontier_item_ids=(successor_id,),
                    focused_context_sha256=turn.focused_context_sha256,
                ),
                frontier_item_transition=FrontierInvestigatorItemTransitionV1(
                    item_id=successor_id,
                    expected_status=FrontierStatus.RUNNING,
                    terminal_status=FrontierStatus.SATISFIED,
                    reason="focused_delivery_confirmed",
                ),
            )
        assert repo.read_investigator_turn_outcome(turn.turn_id) is None
        assert repo.readback(successor_id).status is FrontierStatus.RUNNING


def test_second_refresh_preserves_two_item_fifo_and_rejects_old_ids(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "second-refresh.db") as store:
        case_id, owner = _owner(store)
        repo = SearchFrontierRepository(store)
        first = _investigator_event(store, case_id)
        second = _investigator_event(store, case_id)
        assert first.source_evidence_id is not None
        assert second.source_evidence_id is not None
        assert second.versions.evidence is not None
        repo.intake_investigator_event(case_id, second.event_id)
        session = repo.start_investigator_session(case_id, second.event_id, decision_budget=3)
        versions_2 = RelevantVersionsV1(objective=1, evidence=second.versions.evidence)
        original = tuple(
            repo.upsert_item(
                case_id,
                FrontierReferenceV1(kind="retrieve_evidence", evidence_id=evidence_id),
                versions_2,
            )
            for evidence_id in (first.source_evidence_id, second.source_evidence_id)
        )
        original_ids = tuple(item.item_id for item in original)
        first_turn = repo.reserve_investigator_turn(
            case_id,
            second.event_id,
            owner_started_version=1,
            expected_checkpoint_version=owner.state_version,
            current_versions=versions_2,
            focused_context_sha256="a" * 64,
            catalog_generation=second.versions.evidence,
            cursor_before=None,
            cursor_after=None,
            offered_refs=(),
            pending_tail=(),
            offered_item_ids=original_ids,
            pending_item_ids=(),
            eligible_evidence_ids=(first.source_evidence_id, second.source_evidence_id),
            turn_deadline_at=session.deadline_at,
        )
        owner = InvestigationRepository(store).save(
            owner,
            expected_version=owner.state_version,
            event="attention",
            detail="deferred first tail",
            frontier_turn_completion=FrontierInvestigatorTurnCompletionV1(
                turn_id=first_turn.turn_id,
                case_id=case_id,
                outcome="gap",
                reason_code="policy_unavailable",
                remaining_item_ids=original_ids,
                focused_context_sha256=first_turn.focused_context_sha256,
            ),
        )
        third = _investigator_event(store, case_id)
        assert third.versions.evidence is not None
        versions_3 = RelevantVersionsV1(objective=1, evidence=third.versions.evidence)
        refreshed = repo.reserve_investigator_turn(
            case_id,
            second.event_id,
            owner_started_version=1,
            expected_checkpoint_version=owner.state_version,
            current_versions=versions_3,
            focused_context_sha256="b" * 64,
            catalog_generation=third.versions.evidence,
            cursor_before=None,
            cursor_after=None,
            offered_refs=(),
            pending_tail=(),
            offered_item_ids=(),
            pending_item_ids=original_ids,
            eligible_evidence_ids=(),
            turn_deadline_at=session.deadline_at,
            refresh_pending=True,
        )
        assert isinstance(refreshed, FrontierInvestigatorTurnV2)
        successor_ids = refreshed.pending_item_ids
        assert len(successor_ids) == 2
        assert (
            tuple(link.predecessor_item_id for link in refreshed.pending_refresh_lineage)
            == original_ids
        )
        assert tuple(link.successor_item_id for link in refreshed.pending_refresh_lineage) == (
            successor_ids
        )
        owner = InvestigationRepository(store).save(
            owner,
            expected_version=owner.state_version,
            event="attention",
            detail="deferred refreshed tail",
            frontier_turn_completion=FrontierInvestigatorTurnCompletionV1(
                turn_id=refreshed.turn_id,
                case_id=case_id,
                outcome="gap",
                reason_code="policy_unavailable",
                remaining_item_ids=successor_ids,
                focused_context_sha256=refreshed.focused_context_sha256,
            ),
        )
        fourth = _investigator_event(store, case_id)
        assert fourth.versions.evidence is not None
        generation_4 = fourth.versions.evidence
        versions_4 = RelevantVersionsV1(objective=1, evidence=generation_4)

        def reserve_latest(ids: tuple[str, ...]) -> FrontierInvestigatorTurnV2:
            turn = repo.reserve_investigator_turn(
                case_id,
                second.event_id,
                owner_started_version=1,
                expected_checkpoint_version=owner.state_version,
                current_versions=versions_4,
                focused_context_sha256="c" * 64,
                catalog_generation=generation_4,
                cursor_before=None,
                cursor_after=None,
                offered_refs=(),
                pending_tail=(),
                offered_item_ids=(),
                pending_item_ids=ids,
                eligible_evidence_ids=(),
                turn_deadline_at=session.deadline_at,
                refresh_pending=True,
            )
            assert isinstance(turn, FrontierInvestigatorTurnV2)
            return turn

        with pytest.raises(ValueError, match="not current and retrievable"):
            reserve_latest(original_ids)
        assert len(repo.investigator_turns(case_id, second.event_id)) == 2
        latest = reserve_latest(successor_ids)
        assert tuple(link.predecessor_item_id for link in latest.pending_refresh_lineage) == (
            successor_ids
        )
        assert tuple(link.successor_item_id for link in latest.pending_refresh_lineage) == (
            latest.pending_item_ids
        )
        assert latest.pending_item_ids != successor_ids
        assert tuple(repo.readback(item_id).status for item_id in successor_ids) == (
            FrontierStatus.OBSOLETE,
            FrontierStatus.OBSOLETE,
        )
        assert tuple(repo.readback(item_id).status for item_id in latest.pending_item_ids) == (
            FrontierStatus.REQUESTED,
            FrontierStatus.REQUESTED,
        )
