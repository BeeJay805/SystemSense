"""A claimed candidate may cross only its own checkpoint save once."""

from datetime import timedelta
from pathlib import Path

import pytest
from test_candidate_dispatch_admissions import _setup  # pyright: ignore[reportPrivateUsage]
from test_search_frontier import _investigator_event  # pyright: ignore[reportPrivateUsage]
from test_search_frontier_turns import _owner  # pyright: ignore[reportPrivateUsage]

from systemsense.domain.time import utc_now
from systemsense.storage.candidate_dispatch_admissions import CandidateDispatchAdmissionRepository
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.search_frontier import RelevantVersionsV1, SearchFrontierRepository
from systemsense.storage.sqlite_store import SQLiteStore


def test_launch_continuation_requires_claim_and_exact_old_checkpoint(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "candidate-launch.db") as store:
        case_id, owner = _owner(store)
        cases = InvestigationRepository(store)
        owner = cases.save(owner, expected_version=1, event="attention", detail="turn")
        owner = cases.save(owner, expected_version=2, event="attention", detail="turn")
        _, snapshot_id, candidate, _invocation, registry = _setup(store, case_id=case_id)
        repository = CandidateDispatchAdmissionRepository(store, registry=registry)
        with store.transaction():
            admission = repository.admit_in_transaction(
                snapshot_id=snapshot_id,
                candidate_id=candidate.candidate_id,
                case_id=case_id,
                epoch_state_version=3,
                task_id="probe-0-candidate",
                invocation_sha256=candidate.invocation_sha256,
                cost_ms=candidate.cost_ms,
            )
        frontier = SearchFrontierRepository(store)
        event = _investigator_event(store, case_id)
        frontier.intake_investigator_event(case_id, event.event_id)
        session = frontier.start_investigator_session(case_id, event.event_id, decision_budget=2)
        assert event.versions.evidence is not None
        turn = frontier.reserve_investigator_turn(
            case_id,
            event.event_id,
            owner_started_version=1,
            expected_checkpoint_version=3,
            current_versions=RelevantVersionsV1(objective=1, evidence=event.versions.evidence),
            focused_context_sha256="a" * 64,
            catalog_generation=event.versions.evidence,
            cursor_before=None,
            cursor_after=None,
            offered_refs=(),
            pending_tail=(),
            offered_item_ids=(),
            pending_item_ids=(),
            eligible_evidence_ids=(),
            turn_deadline_at=min(owner.deadline_at, session.deadline_at),
        )
        launch_deadline = min(owner.deadline_at, utc_now() + timedelta(seconds=1))
        with store.transaction():
            with pytest.raises(ValueError, match="claim"):
                repository.create_launch_continuation_in_transaction(
                    admission.admission_id,
                    turn_id=turn.turn_id,
                    owner_started_version=1,
                    resulting_checkpoint_version=4,
                    deadline_at=launch_deadline,
                )
        with store.transaction():
            repository.claim_for_worker_in_transaction(
                admission.admission_id,
                case_id=case_id,
                epoch_state_version=3,
                task_id="probe-0-candidate",
                invocation_sha256=candidate.invocation_sha256,
            )
        with store.transaction():
            with pytest.raises(ValueError, match="checkpoint"):
                repository.create_launch_continuation_in_transaction(
                    admission.admission_id,
                    turn_id=turn.turn_id,
                    owner_started_version=1,
                    resulting_checkpoint_version=5,
                    deadline_at=launch_deadline,
                )
            with pytest.raises(ValueError, match="deadline"):
                repository.create_launch_continuation_in_transaction(
                    admission.admission_id,
                    turn_id=turn.turn_id,
                    owner_started_version=1,
                    resulting_checkpoint_version=4,
                    deadline_at=owner.deadline_at,
                )
            continuation = repository.create_launch_continuation_in_transaction(
                admission.admission_id,
                turn_id=turn.turn_id,
                owner_started_version=1,
                resulting_checkpoint_version=4,
                deadline_at=launch_deadline,
            )
            with pytest.raises(ValueError, match="already exists"):
                repository.create_launch_continuation_in_transaction(
                    admission.admission_id,
                    turn_id=turn.turn_id,
                    owner_started_version=1,
                    resulting_checkpoint_version=4,
                    deadline_at=launch_deadline,
                )
        assert continuation.admission_id == admission.admission_id
        assert continuation.epoch_state_version == 3
        assert continuation.resulting_checkpoint_version == 4
        with pytest.raises(ValueError, match="checkpoint"):
            repository.consume_launch_continuation(
                continuation.continuation_id,
                case_id=case_id,
                task_id="probe-0-candidate",
                invocation_sha256=candidate.invocation_sha256,
            )
        cases.save(owner, expected_version=3, event="attention", detail="admitted measurement")
        with pytest.raises(ValueError, match="outcome"):
            repository.consume_launch_continuation(
                continuation.continuation_id,
                case_id=case_id,
                task_id="probe-0-candidate",
                invocation_sha256=candidate.invocation_sha256,
            )
        with pytest.raises(ValueError, match="transaction"):
            repository.create_launch_continuation_in_transaction(
                admission.admission_id,
                turn_id=turn.turn_id,
                owner_started_version=1,
                resulting_checkpoint_version=4,
                deadline_at=launch_deadline,
            )
