"""Versioned mixed turn custody across stored retrieval and registered measurement."""

import sqlite3
from pathlib import Path

import pytest
from test_pending_tail_refresh import _pending_case  # pyright: ignore[reportPrivateUsage]
from test_search_frontier import _investigator_event  # pyright: ignore[reportPrivateUsage]
from test_search_frontier_turns import _owner, _reserve  # pyright: ignore[reportPrivateUsage]

from systemsense.application.candidate_catalog import general_measurement_candidate_catalog
from systemsense.domain.ids import CaseId, EvidenceId
from systemsense.packs.runtime import default_probe_runner
from systemsense.storage.case_candidates import CandidateGap
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.search_frontier import (
    FrontierInvestigatorTurnCompletionV1,
    FrontierInvestigatorTurnCompletionV3,
    FrontierInvestigatorTurnV3,
    FrontierItemCapacityError,
    FrontierPendingRefreshV3,
    FrontierReferenceV1,
    FrontierStatus,
    RelevantVersionsV1,
    SearchFrontierRepository,
)
from systemsense.storage.sqlite_store import SQLiteStore
from tests.unit.application.test_general_candidate_catalog import (
    EPOCH,
    NOW,
    _case,  # pyright: ignore[reportPrivateUsage]
    _gpu_source,  # pyright: ignore[reportPrivateUsage]
    _source,  # pyright: ignore[reportPrivateUsage]
)


def test_mixed_page_capacity_failure_rolls_back_retrieval_and_measurements(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "mixed-page-atomic.db") as store:
        case_id = _case(store)
        source = _source(store, case_id, age_seconds=10)
        _gpu_source(store, case_id, age_seconds=10)
        registry, needs = general_measurement_candidate_catalog(
            store, default_probe_runner(), case_id, clock=lambda: NOW
        )
        records = tuple(registry.issue(case_id, EPOCH, need) for need in needs)
        assert len(records) == 2 and all(not isinstance(item, CandidateGap) for item in records)
        generation_row = store.connection.execute(
            "SELECT generation FROM evidence_case_generations WHERE case_id=?", (str(case_id),)
        ).fetchone()
        assert generation_row is not None
        versions = RelevantVersionsV1(objective=1, evidence=int(generation_row[0]))
        repo = SearchFrontierRepository(store)
        candidate_ids = tuple(
            item.candidate_id for item in records if not isinstance(item, CandidateGap)
        )
        with pytest.raises(ValueError, match="case epoch is stale"):
            repo.upsert_mixed_page(
                case_id,
                (source,),
                candidate_ids,
                versions,
                expected_generation=int(generation_row[0]),
                candidate_epoch=EPOCH + 1,
            )
        monkeypatch.setattr("systemsense.storage.search_frontier._ITEM_LIMIT", 2)

        with pytest.raises(FrontierItemCapacityError):
            repo.upsert_mixed_page(
                case_id,
                (source,),
                candidate_ids,
                versions,
                expected_generation=int(generation_row[0]),
                candidate_epoch=EPOCH,
            )

        assert store.connection.execute(
            "SELECT COUNT(*) FROM search_frontier_items WHERE case_id=?", (str(case_id),)
        ).fetchone() == (0,)


def test_v3_turn_rejects_unregistered_measurement_item(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "mixed.db") as store:
        case_id, owner = _owner(store)
        repo = SearchFrontierRepository(store)
        event = _investigator_event(store, case_id)
        assert event.source_evidence_id is not None
        assert event.versions.evidence is not None
        repo.intake_investigator_event(case_id, event.event_id)
        session = repo.start_investigator_session(case_id, event.event_id, decision_budget=2)
        versions = RelevantVersionsV1(objective=1, evidence=event.versions.evidence)
        retrieval = repo.upsert_item(
            case_id,
            FrontierReferenceV1(kind="retrieve_evidence", evidence_id=event.source_evidence_id),
            versions,
        )
        forged_measurement = repo.upsert_item(
            case_id,
            FrontierReferenceV1(kind="measure", candidate_id="cand_v1_" + "a" * 32),
            versions,
            cost_ms=100,
        )
        with pytest.raises(ValueError, match="candidate"):
            repo.reserve_investigator_turn(
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
                offered_item_ids=(retrieval.item_id, forged_measurement.item_id),
                pending_item_ids=(),
                eligible_evidence_ids=(event.source_evidence_id,),
                turn_deadline_at=min(owner.deadline_at, session.deadline_at),
                mixed_candidate_epoch=owner.state_version,
            )
        assert repo.investigator_turns(case_id, event.event_id) == ()


def test_v3_admission_completion_requires_exact_link_ids() -> None:
    with pytest.raises(ValueError, match=r"admission|snapshot|continuation"):
        FrontierInvestigatorTurnCompletionV3(
            turn_id="frit_v1_" + "a" * 64,
            case_id=CaseId.new(),
            outcome="measurement_admitted",
            reason_code="registered_measurement_admitted",
            frontier_item_ids=("fr_v1_" + "a" * 64,),
            focused_context_sha256="b" * 64,
        )


def test_v3_reservation_and_interrupted_recovery_survive_reopen(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = tmp_path / "mixed-recovery.db"
    with SQLiteStore(path) as store:
        case_id, owner = _owner(store)
        repo = SearchFrontierRepository(store)
        event = _investigator_event(store, case_id)
        assert event.source_evidence_id is not None
        assert event.versions.evidence is not None
        repo.intake_investigator_event(case_id, event.event_id)
        session = repo.start_investigator_session(case_id, event.event_id, decision_budget=2)
        versions = RelevantVersionsV1(objective=1, evidence=event.versions.evidence)
        retrieval = repo.upsert_item(
            case_id,
            FrontierReferenceV1(kind="retrieve_evidence", evidence_id=event.source_evidence_id),
            versions,
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
            cursor_after=None,
            offered_refs=(),
            pending_tail=(),
            offered_item_ids=(retrieval.item_id,),
            pending_item_ids=(),
            eligible_evidence_ids=(event.source_evidence_id,),
            turn_deadline_at=min(owner.deadline_at, session.deadline_at),
            mixed_candidate_epoch=owner.state_version,
        )
        assert isinstance(turn, FrontierInvestigatorTurnV3)
        assert repo.read_investigator_turn(turn.turn_id) == turn
    with SQLiteStore(path) as reopened:
        repo = SearchFrontierRepository(reopened)
        monkeypatch.setattr(
            "systemsense.storage.search_frontier.utc_now",
            lambda: turn.deadline_at,
        )
        outcome = repo.recover_interrupted_investigator_turn(turn.turn_id)
        assert outcome.schema_version == 3
        assert outcome.remaining_item_ids == (retrieval.item_id,)
        assert repo.read_investigator_turn_outcome(turn.turn_id) == outcome


def test_populated_v31_turn_migrates_without_changing_v1_readback(tmp_path: Path) -> None:
    path = tmp_path / "populated-v31.db"
    with SQLiteStore(path) as store:
        case_id, owner = _owner(store)
        repo = SearchFrontierRepository(store)
        event = _investigator_event(store, case_id)
        assert event.versions.evidence is not None
        repo.intake_investigator_event(case_id, event.event_id)
        repo.start_investigator_session(case_id, event.event_id, decision_budget=1)
        turn = _reserve(repo, case_id, event.event_id, owner, event.versions.evidence)
        original_json = store.connection.execute(
            "SELECT record_json FROM search_frontier_investigator_turns WHERE turn_id=?",
            (turn.turn_id,),
        ).fetchone()
        assert original_json is not None
    with sqlite3.connect(path) as connection:
        connection.execute("PRAGMA foreign_keys=OFF")
        connection.execute("DROP TABLE frontier_worker_capture_drafts")
        connection.execute("DROP TABLE candidate_followup_parents")
        connection.execute("DROP TABLE candidate_launch_consumptions")
        connection.execute("DROP TABLE candidate_launch_continuations")
        connection.execute(
            "CREATE TABLE search_frontier_investigator_turns_v31 ("
            "turn_id TEXT PRIMARY KEY,event_id TEXT NOT NULL,case_id TEXT NOT NULL,"
            "ordinal INTEGER NOT NULL,schema_version INTEGER NOT NULL "
            "CHECK(schema_version IN (1,2)),record_json TEXT NOT NULL,"
            "record_sha256 TEXT NOT NULL,reserved_at TEXT NOT NULL) STRICT"
        )
        connection.execute(
            "INSERT INTO search_frontier_investigator_turns_v31 "
            "SELECT * FROM search_frontier_investigator_turns"
        )
        connection.execute("DROP TABLE search_frontier_investigator_turns")
        connection.execute(
            "ALTER TABLE search_frontier_investigator_turns_v31 "
            "RENAME TO search_frontier_investigator_turns"
        )
        connection.execute("PRAGMA user_version=31")
    with SQLiteStore(path) as upgraded:
        repo = SearchFrontierRepository(upgraded)
        assert upgraded.schema_version() == 35
        assert repo.read_investigator_turn(turn.turn_id) == turn
        assert (
            upgraded.connection.execute(
                "SELECT record_json FROM search_frontier_investigator_turns WHERE turn_id=?",
                (turn.turn_id,),
            ).fetchone()
            == original_json
        )
        assert upgraded.connection.execute("PRAGMA foreign_key_check").fetchall() == []


def test_v3_reissue_retires_predecessor_atomically(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "mixed-reissue.db") as store:
        case_id, owner, repo, event, session, pending, versions = _pending_case(store)
        assert versions.evidence is not None
        assert event.source_evidence_id is not None
        other_row = store.connection.execute(
            "SELECT evidence_id FROM evidence WHERE case_id=? AND evidence_id<>?",
            (str(case_id), str(event.source_evidence_id)),
        ).fetchone()
        assert other_row is not None
        wrong = repo.upsert_item(
            case_id,
            FrontierReferenceV1(
                kind="retrieve_evidence", evidence_id=EvidenceId(root=str(other_row[0]))
            ),
            versions,
        )
        # A wrong successor must roll back its predecessor retirement.
        with pytest.raises(ValueError, match="reissue"):
            repo.reserve_investigator_turn(
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
                pending_item_ids=(wrong.item_id,),
                eligible_evidence_ids=(),
                turn_deadline_at=session.deadline_at,
                mixed_candidate_epoch=owner.state_version,
                reissue_lineage=(
                    FrontierPendingRefreshV3(
                        predecessor_item_id=pending.item_id,
                        successor_item_id=wrong.item_id,
                    ),
                ),
            )
        assert repo.readback(pending.item_id).status is FrontierStatus.REQUESTED
        successor = repo.upsert_item(case_id, pending.reference, versions)
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
            pending_item_ids=(successor.item_id,),
            eligible_evidence_ids=(),
            turn_deadline_at=session.deadline_at,
            mixed_candidate_epoch=owner.state_version,
            reissue_lineage=(
                FrontierPendingRefreshV3(
                    predecessor_item_id=pending.item_id,
                    successor_item_id=successor.item_id,
                ),
            ),
        )
        assert isinstance(turn, FrontierInvestigatorTurnV3)
        assert repo.readback(pending.item_id).status is FrontierStatus.OBSOLETE
        assert repo.read_investigator_turn(turn.turn_id) == turn


def test_v3_auto_reissues_retrieval_in_reservation_transaction(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "auto-mixed-reissue.db") as store:
        case_id, owner, repo, event, session, pending, versions = _pending_case(store)
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
            mixed_candidate_epoch=owner.state_version,
            auto_reissue_retrieval=True,
        )
        assert isinstance(turn, FrontierInvestigatorTurnV3)
        assert turn.reissue_lineage == (
            FrontierPendingRefreshV3(
                predecessor_item_id=pending.item_id,
                successor_item_id=turn.pending_item_ids[0],
            ),
        )
        assert turn.pending_item_ids[0] != pending.item_id
        assert repo.readback(pending.item_id).status is FrontierStatus.OBSOLETE
        assert repo.read_investigator_turn(turn.turn_id) == turn
        successor_id = turn.pending_item_ids[0]
        repo.claim_ready(successor_id, versions)
        repo.transition(successor_id, FrontierStatus.CLAIMED, FrontierStatus.ADMITTED, "admitted")
        assert repo.read_investigator_turn(turn.turn_id) == turn


def test_v3_stale_measurement_pending_tail_can_only_record_gap(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "stale-measure-tail.db") as store:
        case_id, owner = _owner(store)
        repo = SearchFrontierRepository(store)
        event = _investigator_event(store, case_id)
        assert event.versions.evidence is not None
        repo.intake_investigator_event(case_id, event.event_id)
        session = repo.start_investigator_session(case_id, event.event_id, decision_budget=2)
        versions = RelevantVersionsV1(objective=1, evidence=event.versions.evidence)
        old = repo.upsert_item(
            case_id,
            FrontierReferenceV1(kind="measure", candidate_id="cand_v1_" + "a" * 32),
            versions,
            cost_ms=100,
        )
        first = repo.reserve_investigator_turn(
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
            offered_item_ids=(old.item_id,),
            pending_item_ids=(),
            eligible_evidence_ids=(),
            turn_deadline_at=session.deadline_at,
        )
        owner = InvestigationRepository(store).save(
            owner,
            expected_version=owner.state_version,
            event="attention",
            detail="deferred candidate",
            frontier_turn_completion=FrontierInvestigatorTurnCompletionV1(
                turn_id=first.turn_id,
                case_id=case_id,
                outcome="gap",
                reason_code="policy_unavailable",
                remaining_item_ids=(old.item_id,),
                focused_context_sha256=first.focused_context_sha256,
            ),
        )
        turn = repo.reserve_investigator_turn(
            case_id,
            event.event_id,
            owner_started_version=1,
            expected_checkpoint_version=owner.state_version,
            current_versions=versions,
            focused_context_sha256="b" * 64,
            catalog_generation=event.versions.evidence,
            cursor_before=None,
            cursor_after=None,
            offered_refs=(),
            pending_tail=(),
            offered_item_ids=(),
            pending_item_ids=(old.item_id,),
            eligible_evidence_ids=(),
            turn_deadline_at=session.deadline_at,
            mixed_candidate_epoch=owner.state_version,
            mixed_stale_pending_gap=True,
        )
        assert isinstance(turn, FrontierInvestigatorTurnV3)
        assert turn.stale_pending_only
        with pytest.raises(ValueError, match="stale pending"):
            InvestigationRepository(store).save(
                owner,
                expected_version=owner.state_version,
                event="attention",
                detail="cannot call it empty",
                frontier_turn_completion=FrontierInvestigatorTurnCompletionV3(
                    turn_id=turn.turn_id,
                    case_id=case_id,
                    outcome="no_new_fact",
                    reason_code="all_facts_already_visible",
                    remaining_item_ids=(old.item_id,),
                    focused_context_sha256=turn.focused_context_sha256,
                ),
            )
        InvestigationRepository(store).save(
            owner,
            expected_version=owner.state_version,
            event="attention",
            detail="stale candidate gap",
            frontier_turn_completion=FrontierInvestigatorTurnCompletionV3(
                turn_id=turn.turn_id,
                case_id=case_id,
                outcome="gap",
                reason_code="stale_context",
                remaining_item_ids=(old.item_id,),
                focused_context_sha256=turn.focused_context_sha256,
            ),
        )
        outcome = repo.read_investigator_turn_outcome(turn.turn_id)
        assert outcome is not None and outcome.outcome == "gap"
        assert store.connection.execute(
            "SELECT COUNT(*) FROM candidate_dispatch_admissions WHERE case_id=?",
            (str(case_id),),
        ).fetchone() == (0,)
