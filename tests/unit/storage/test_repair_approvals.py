"""Durable admission of exact server-owned repair proposals and review claims."""

import json
import sqlite3
from collections.abc import Callable, Generator
from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from pathlib import Path
from threading import Barrier
from typing import TypedDict

import pytest

import systemsense.storage.repair_approvals as approvals_module
from systemsense.actions.contracts import (
    ActionAuthorizationError,
    ActionCode,
    ActionGate,
    ActionKind,
    ActionOperation,
    AuthorizationAuthority,
    AuthorizedAction,
    DisruptionLevel,
    ExactTarget,
    ExpectedEffect,
    HumanConsent,
    OperationParameter,
    Precondition,
    PreconditionCode,
    ProposalRisk,
    RepairProposal,
    RiskLevel,
    RollbackLimits,
    TargetKind,
    VerificationCheck,
    VerificationPlan,
)
from systemsense.domain.ids import CaseId, TargetId
from systemsense.storage.repair_approvals import (
    RepairApprovalClaim,
    RepairApprovalRepository,
    RepairApprovalState,
    RepairExecutionClaim,
    RepairTerminalAssessment,
    TerminalOutcome,
    TerminalSetting,
    TerminalSymptom,
)
from systemsense.storage.sqlite_store import SQLiteStore, StoreTransaction

NOW = datetime(2026, 9, 22, 12, tzinfo=UTC)


def _proposal(case_id: CaseId) -> RepairProposal:
    target = ExactTarget(
        target_id=TargetId.new(),
        kind=TargetKind.WININET_USER_PROXY,
        locator="wininet_proxy:S-1-5-21-1000-2000-3000-1001",
    )
    return RepairProposal(
        proposal_id="proposal_0123456789abcdef0123456789abcdef",
        kind=ActionKind.REPAIR,
        case_id=case_id,
        case_state_version=4,
        plan_version="proxy-plan-1",
        created_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
        operations=(
            ActionOperation(
                operation_id="disable_bad_proxy",
                code=ActionCode.DISABLE_WININET_PROXY,
                kind=ActionKind.REPAIR,
                target=target,
                parameters=(OperationParameter(name="new_proxy_enabled", value=False),),
            ),
        ),
        preconditions=(Precondition(code=PreconditionCode.TARGET_VERSION_MATCHES, target=target),),
        expected_effect=ExpectedEffect(summary="Restore connectivity", success_indicators=("204",)),
        risk=ProposalRisk(
            level=RiskLevel.MODERATE,
            disruption=DisruptionLevel.NETWORK_INTERRUPTION,
            summary="Current-user network interruption",
        ),
        verification=VerificationPlan(checks=(VerificationCheck(code="connectivity_restored"),)),
        rollback=RollbackLimits(supported=False, max_attempts=0, limits="Manual recovery"),
    )


def _case(store: SQLiteStore) -> CaseId:
    case_id = CaseId.new()
    store.create_case(
        case_id=str(case_id),
        kind="general",
        symptom="Exact user proxy is wrong",
        created_at=NOW.isoformat(),
        state_version=4,
    )
    return case_id


def _repo(store: SQLiteStore, *, now: datetime = NOW) -> RepairApprovalRepository:
    return RepairApprovalRepository(store, clock=lambda: now)


def _authorized(proposal: RepairProposal, consent_reference: str):
    authority = AuthorizationAuthority(secret=b"test-secret-for-repair-admission")
    consent = HumanConsent(
        reviewer_id="human:test-reviewer",
        consent_reference=consent_reference,
        case_id=proposal.case_id,
        case_state_version=proposal.case_state_version,
        plan_version=proposal.plan_version,
        proposal_digest=proposal.digest(),
        operation_digests=proposal.operation_digests(),
        expires_at=proposal.expires_at,
        reviewed=True,
    )
    token = authority.issue(proposal, consent=consent, issued_at=NOW)
    action = ActionGate(secret=b"test-secret-for-repair-admission").authorize(
        proposal,
        token,
        current_state_version=4,
        current_plan_version=proposal.plan_version,
        now=NOW,
    )
    return action, authority.verify


def _terminal(execution_id: str) -> RepairTerminalAssessment:
    return RepairTerminalAssessment(
        execution_id=execution_id,
        journal_state="verified",
        journal_digest="1" * 64,
        executor_stop_digest="2" * 64,
        executor_stopped_at=NOW + timedelta(seconds=1),
        setting_evidence_id="ev_" + "a" * 32,
        setting_evidence_digest="3" * 64,
        setting_observed_at=NOW + timedelta(seconds=2),
        affected_evidence_id="ev_" + "b" * 32,
        affected_evidence_digest="4" * 64,
        affected_observed_at=NOW + timedelta(seconds=3),
        direct_evidence_id="ev_" + "c" * 32,
        direct_evidence_digest="5" * 64,
        direct_observed_at=NOW + timedelta(seconds=4),
        setting_observed=TerminalSetting.INTENDED,
        symptom_outcome=TerminalSymptom.RECOVERED,
        affected_route_proven=True,
        direct_control_healthy=True,
        outcome=TerminalOutcome.RECOVERED,
        reviewer_id="human:test-reviewer",
        reviewer_sid_digest=sha256(json.dumps("S-1-5-21-1000-2000-3000-1001").encode()).hexdigest(),
        terminal_approval_id="terminal_approval_test",
        terminal_approval_digest="6" * 64,
    )


class _TerminalVerifiers(TypedDict):
    verify_stopped_and_exclusive: (
        Callable[[RepairExecutionClaim, str, RepairTerminalAssessment], bool] | None
    )
    read_journal_binding: (
        Callable[
            [RepairExecutionClaim, RepairApprovalClaim, RepairProposal], tuple[str, str] | None
        ]
        | None
    )
    verify_fresh_evidence: Callable[[RepairTerminalAssessment, RepairProposal], bool] | None
    verify_terminal_approval: (
        Callable[[RepairTerminalAssessment, RepairExecutionClaim], bool] | None
    )
    current_sid_digest: Callable[[], str | None] | None


def _terminal_verifiers(assessment: RepairTerminalAssessment) -> _TerminalVerifiers:
    return {
        "verify_stopped_and_exclusive": lambda _execution, _target, _assessment: True,
        "read_journal_binding": lambda _execution, _review, _proposal: (
            assessment.journal_state,
            assessment.journal_digest,
        ),
        "verify_fresh_evidence": lambda _assessment, _proposal: True,
        "verify_terminal_approval": lambda _assessment, _execution: True,
        "current_sid_digest": lambda: assessment.reviewer_sid_digest,
    }


@pytest.fixture(autouse=True)
def _fake_terminal_arbiter(monkeypatch: pytest.MonkeyPatch) -> None:  # pyright: ignore[reportUnusedFunction]
    @contextmanager
    def hold_target(_target_key: str) -> Generator[bool]:
        yield True

    monkeypatch.setattr(approvals_module, "hold_wininet_target_exclusive", hold_target)


def _claimed_execution(store: SQLiteStore, *, start: bool = True):
    case_id = _case(store)
    proposal = _proposal(case_id)
    repo = _repo(store)
    repo.register_server_proposal(proposal, current_plan_version=proposal.plan_version)
    review = repo.claim_review(
        proposal.proposal_id, case_id=case_id, acknowledged_digest=proposal.digest()
    )
    action, verify = _authorized(proposal, review.consent_reference)
    execution = repo.promote_execution(review.claim_id, action=action, verify_authorization=verify)
    if start:
        execution = repo.recheck_execution(
            execution.execution_id, action=action, verify_authorization=verify
        )
    return repo, proposal, execution, action, verify


def test_terminal_record_requires_every_trusted_verifier_and_keeps_lock_on_denial(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        _repo_created, _proposal_record, execution, _action, _verify = _claimed_execution(store)
        repo = _repo(store, now=NOW + timedelta(seconds=5))
        assessment = _terminal(execution.execution_id)
        checks = _terminal_verifiers(assessment)
        for missing in tuple(checks):
            refused = {**checks, missing: None}
            with pytest.raises(ActionAuthorizationError, match="unavailable"):
                repo.record_terminal_and_release(assessment, **refused)  # type: ignore[arg-type]

        for denied in ("stop", "evidence", "approval"):
            refused = _terminal_verifiers(assessment)
            if denied == "stop":
                refused["verify_stopped_and_exclusive"] = lambda _execution, _target, _assessment: (
                    False
                )
            elif denied == "evidence":
                refused["verify_fresh_evidence"] = lambda _assessment, _proposal: False
            else:
                refused["verify_terminal_approval"] = lambda _assessment, _execution: False
            with pytest.raises(ActionAuthorizationError):
                repo.record_terminal_and_release(assessment, **refused)
        with pytest.raises(ActionAuthorizationError, match="journal binding"):
            repo.record_terminal_and_release(
                assessment,
                **{**checks, "read_journal_binding": lambda _e, _r, _p: None},  # type: ignore[arg-type]
            )
        with pytest.raises(ActionAuthorizationError, match="SID"):
            repo.record_terminal_and_release(
                assessment,
                **{**checks, "current_sid_digest": lambda: "0" * 64},  # type: ignore[arg-type]
            )
        assert store.connection.execute(
            "SELECT COUNT(*) FROM repair_execution_target_locks"
        ).fetchone() == (1,)
        assert store.connection.execute(
            "SELECT COUNT(*) FROM repair_execution_terminals"
        ).fetchone() == (0,)


def test_terminal_record_refuses_unavailable_shared_target_arbiter(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    @contextmanager
    def unavailable(_target_key: str) -> Generator[bool]:
        yield False

    monkeypatch.setattr(approvals_module, "hold_wininet_target_exclusive", unavailable)
    with SQLiteStore(tmp_path / "cases.db") as store:
        _repo_created, _proposal_record, execution, _action, _verify = _claimed_execution(store)
        assessment = _terminal(execution.execution_id)
        with pytest.raises(ActionAuthorizationError, match="target exclusion"):
            _repo(store, now=NOW + timedelta(seconds=5)).record_terminal_and_release(
                assessment, **_terminal_verifiers(assessment)
            )
        assert store.connection.execute(
            "SELECT COUNT(*) FROM repair_execution_target_locks"
        ).fetchone() == (1,)


def test_terminal_exact_commit_is_one_shot_and_unlocks_only_its_target(tmp_path: Path) -> None:
    path = tmp_path / "cases.db"
    with SQLiteStore(path) as store:
        repo, proposal, execution, action, verify = _claimed_execution(store)
        assessment = _terminal(execution.execution_id)
        with pytest.raises(sqlite3.DatabaseError, match="terminal record"):
            store.connection.execute("DELETE FROM repair_execution_target_locks")
        repo = _repo(store, now=NOW + timedelta(seconds=5))
        assert (
            repo.record_terminal_and_release(
                assessment,
                **_terminal_verifiers(assessment),  # type: ignore[arg-type]
            )
            == assessment
        )
        assert store.connection.execute(
            "SELECT COUNT(*) FROM repair_execution_target_locks"
        ).fetchone() == (0,)
        assert store.connection.execute(
            "SELECT assessment_digest FROM repair_execution_terminals"
        ).fetchone() == (assessment.digest(),)
        with pytest.raises(ActionAuthorizationError, match="already resolved"):
            repo.record_terminal_and_release(
                assessment,
                **_terminal_verifiers(assessment),  # type: ignore[arg-type]
            )
        with pytest.raises(ActionAuthorizationError, match="terminal"):
            repo.recheck_execution(
                execution.execution_id, action=action, verify_authorization=verify
            )
        with pytest.raises(ActionAuthorizationError, match="terminal"):
            repo.mark_execution_interrupted(execution.execution_id)
        with pytest.raises(sqlite3.DatabaseError, match="immutable"):
            store.connection.execute("DELETE FROM repair_execution_terminals")
        replacement = proposal.model_copy(
            update={"proposal_id": "proposal_abcdef0123456789abcdef0123456789"}
        )
        repo.register_server_proposal(replacement, current_plan_version=replacement.plan_version)
    with SQLiteStore(path) as reopened:
        assert reopened.connection.execute(
            "SELECT assessment_digest FROM repair_execution_terminals"
        ).fetchone() == (assessment.digest(),)


def test_terminal_assessment_digest_precedes_approval_without_circular_signature() -> None:
    assessment = _terminal("execution_" + "0" * 32)
    assert (
        replace(
            assessment,
            terminal_approval_id="terminal_approval_other",
            terminal_approval_digest="f" * 64,
        ).digest()
        == assessment.digest()
    )
    assert replace(assessment, affected_evidence_digest="f" * 64).digest() != assessment.digest()


def test_terminal_failure_to_release_rolls_back_assessment(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        _repo_created, _proposal_record, execution, _action, _verify = _claimed_execution(store)
        assessment = _terminal(execution.execution_id)
        store.connection.execute(
            "CREATE TRIGGER test_block_terminal_unlock "
            "BEFORE DELETE ON repair_execution_target_locks "
            "BEGIN SELECT RAISE(ABORT, 'simulated storage failure'); END"
        )
        repo = _repo(store, now=NOW + timedelta(seconds=5))
        with pytest.raises(ActionAuthorizationError, match="durable state"):
            repo.record_terminal_and_release(
                assessment,
                **_terminal_verifiers(assessment),  # type: ignore[arg-type]
            )
        assert store.connection.execute(
            "SELECT COUNT(*) FROM repair_execution_terminals"
        ).fetchone() == (0,)
        assert store.connection.execute(
            "SELECT COUNT(*) FROM repair_execution_target_locks"
        ).fetchone() == (1,)


def test_prepared_execution_cannot_be_terminalized_as_applied(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        _repo_created, _proposal_record, execution, _action, _verify = _claimed_execution(
            store, start=False
        )
        assessment = _terminal(execution.execution_id)
        with pytest.raises(ActionAuthorizationError, match="prepared execution"):
            _repo(store, now=NOW + timedelta(seconds=5)).record_terminal_and_release(
                assessment, **_terminal_verifiers(assessment)
            )
        assert store.connection.execute(
            "SELECT COUNT(*) FROM repair_execution_target_locks"
        ).fetchone() == (1,)


def test_target_exclusion_is_held_through_terminal_commit(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        _repo_created, _proposal_record, execution, _action, _verify = _claimed_execution(store)
        assessment = _terminal(execution.execution_id)
        checks = _terminal_verifiers(assessment)
        active = False

        @contextmanager
        def hold_target(_target_key: str) -> Generator[bool]:
            nonlocal active
            active = True
            try:
                yield True
                assert store.connection.execute(
                    "SELECT COUNT(*) FROM repair_execution_terminals"
                ).fetchone() == (1,)
                assert store.connection.execute(
                    "SELECT COUNT(*) FROM repair_execution_target_locks"
                ).fetchone() == (0,)
            finally:
                active = False

        def verify_stopped(
            _execution: RepairExecutionClaim,
            _target_key: str,
            _assessment: RepairTerminalAssessment,
        ) -> bool:
            assert active
            return True

        monkeypatch.setattr(approvals_module, "hold_wininet_target_exclusive", hold_target)
        checks["verify_stopped_and_exclusive"] = verify_stopped
        _repo(store, now=NOW + timedelta(seconds=5)).record_terminal_and_release(
            assessment, **checks
        )
        assert not active


@pytest.mark.parametrize(
    "changed",
    [
        {"affected_evidence_id": "ev_" + "a" * 32},
        {"setting_observed_at": NOW + timedelta(milliseconds=500)},
        {"direct_observed_at": NOW + timedelta(seconds=1)},
        {"setting_observed": TerminalSetting.UNAVAILABLE},
        {"symptom_outcome": TerminalSymptom.UNAVAILABLE},
        {"affected_route_proven": False},
        {"direct_control_healthy": False},
        {"journal_digest": "not a digest"},
    ],
)
def test_terminal_rejects_stale_reused_or_contradictory_proof(
    tmp_path: Path, changed: dict[str, object]
) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        _repo_created, _proposal_record, execution, _action, _verify = _claimed_execution(store)
        assessment = _terminal(execution.execution_id)
        assessment = replace(assessment, **changed)
        repo = _repo(store, now=NOW + timedelta(seconds=5))
        with pytest.raises(ActionAuthorizationError):
            repo.record_terminal_and_release(assessment, **_terminal_verifiers(assessment))
        assert store.connection.execute(
            "SELECT COUNT(*) FROM repair_execution_terminals"
        ).fetchone() == (0,)
        assert store.connection.execute(
            "SELECT COUNT(*) FROM repair_execution_target_locks"
        ).fetchone() == (1,)


def test_concurrent_terminal_reconcilers_have_exactly_one_winner(tmp_path: Path) -> None:
    path = tmp_path / "cases.db"
    with SQLiteStore(path) as store:
        _repo_created, _proposal_record, execution, _action, _verify = _claimed_execution(store)
    assessment = _terminal(execution.execution_id)
    start = Barrier(2)

    def reconcile() -> str:
        with SQLiteStore(path) as store:
            start.wait(5)
            try:
                _repo(store, now=NOW + timedelta(seconds=5)).record_terminal_and_release(
                    assessment, **_terminal_verifiers(assessment)
                )
            except ActionAuthorizationError:
                return "rejected"
            return "released"

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(reconcile)
        second = pool.submit(reconcile)
        outcomes = (
            first.result(timeout=5),
            second.result(timeout=5),
        )
    assert outcomes.count("released") == 1
    assert outcomes.count("rejected") == 1
    with SQLiteStore(path) as store:
        assert store.connection.execute(
            "SELECT COUNT(*) FROM repair_execution_terminals"
        ).fetchone() == (1,)
        assert store.connection.execute(
            "SELECT COUNT(*) FROM repair_execution_target_locks"
        ).fetchone() == (0,)


def test_execution_promotion_is_durable_single_use_and_rechecks_exact_scope(tmp_path: Path) -> None:
    path = tmp_path / "cases.db"
    with SQLiteStore(path) as store:
        case_id = _case(store)
        proposal = _proposal(case_id)
        repo = _repo(store)
        repo.register_server_proposal(proposal, current_plan_version=proposal.plan_version)
        review = repo.claim_review(
            proposal.proposal_id, case_id=case_id, acknowledged_digest=proposal.digest()
        )
        action, verify = _authorized(proposal, review.consent_reference)
        execution = repo.promote_execution(
            review.claim_id, action=action, verify_authorization=verify
        )
        assert execution.state.value == "prepared"
        started = repo.recheck_execution(
            execution.execution_id, action=action, verify_authorization=verify
        )
        assert started.state.value == "applying"
        with pytest.raises(ActionAuthorizationError, match="already started"):
            repo.recheck_execution(
                execution.execution_id, action=action, verify_authorization=verify
            )
        with pytest.raises(ActionAuthorizationError, match="already"):
            repo.promote_execution(review.claim_id, action=action, verify_authorization=verify)
    with SQLiteStore(path) as reopened:
        assert _repo(reopened).execution(execution.execution_id) == started


def test_atomic_review_promotion_rolls_back_failed_authorization_factory(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        proposal = _proposal(case_id)
        repo = _repo(store)
        repo.register_server_proposal(proposal, current_plan_version=proposal.plan_version)

        def fail(_review: RepairApprovalClaim, _proposal: RepairProposal) -> AuthorizedAction:
            raise ValueError("identity unavailable")

        with pytest.raises(ValueError, match="identity unavailable"):
            repo.claim_and_promote(
                proposal.proposal_id,
                case_id=case_id,
                acknowledged_digest=proposal.digest(),
                make_action=fail,
                verify_authorization=lambda token: True,
            )
        assert store.connection.execute(
            "SELECT COUNT(*) FROM repair_approval_claims"
        ).fetchone() == (0,)


def test_atomic_review_promotion_rolls_back_target_collision(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        repo = _repo(store)
        first_case = _case(store)
        first = _proposal(first_case)
        repo.register_server_proposal(first, current_plan_version=first.plan_version)

        def authorize(review: RepairApprovalClaim, proposal: RepairProposal) -> AuthorizedAction:
            action, _verify = _authorized(proposal, review.consent_reference)
            return action

        repo.claim_and_promote(
            first.proposal_id,
            case_id=first_case,
            acknowledged_digest=first.digest(),
            make_action=authorize,
            verify_authorization=lambda token: True,
        )
        second_case = _case(store)
        second = _proposal(second_case).model_copy(
            update={"proposal_id": "proposal_fedcba9876543210fedcba9876543210"}
        )
        repo.register_server_proposal(second, current_plan_version=second.plan_version)
        with pytest.raises(ActionAuthorizationError, match="target reserved"):
            repo.claim_and_promote(
                second.proposal_id,
                case_id=second_case,
                acknowledged_digest=second.digest(),
                make_action=authorize,
                verify_authorization=lambda token: True,
            )
        assert store.connection.execute(
            "SELECT COUNT(*) FROM repair_approval_claims WHERE proposal_id=?",
            (second.proposal_id,),
        ).fetchone() == (0,)


def test_public_admission_rejects_unowned_read_snapshot(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        proposal = _proposal(case_id)
        repo = _repo(store)
        repo.register_server_proposal(proposal, current_plan_version=proposal.plan_version)
        with store.read_snapshot():
            with pytest.raises(ActionAuthorizationError, match="active transaction"):
                repo.claim_review(
                    proposal.proposal_id,
                    case_id=case_id,
                    acknowledged_digest=proposal.digest(),
                )
        assert store.connection.execute(
            "SELECT COUNT(*) FROM repair_approval_claims"
        ).fetchone() == (0,)

        review = repo.claim_review(
            proposal.proposal_id, case_id=case_id, acknowledged_digest=proposal.digest()
        )
        action, verify = _authorized(proposal, review.consent_reference)
        with store.read_snapshot():
            with pytest.raises(ActionAuthorizationError, match="active transaction"):
                repo.promote_execution(review.claim_id, action=action, verify_authorization=verify)
        assert store.connection.execute(
            "SELECT COUNT(*) FROM repair_execution_claims"
        ).fetchone() == (0,)


def test_committed_execution_cannot_replay_or_be_superseded_after_restart(tmp_path: Path) -> None:
    path = tmp_path / "cases.db"
    with SQLiteStore(path) as store:
        case_id = _case(store)
        first = _proposal(case_id)
        repo = _repo(store)
        repo.register_server_proposal(first, current_plan_version=first.plan_version)
        review = repo.claim_review(
            first.proposal_id, case_id=case_id, acknowledged_digest=first.digest()
        )
        action, verify = _authorized(first, review.consent_reference)
        execution = repo.promote_execution(
            review.claim_id, action=action, verify_authorization=verify
        )
        started = repo.recheck_execution(
            execution.execution_id, action=action, verify_authorization=verify
        )
    with SQLiteStore(path) as reopened:
        repo = _repo(reopened)
        assert repo.execution(execution.execution_id) == started
        with pytest.raises(ActionAuthorizationError, match="already started"):
            repo.recheck_execution(
                execution.execution_id, action=action, verify_authorization=verify
            )
        with pytest.raises(ActionAuthorizationError, match="already"):
            repo.promote_execution(review.claim_id, action=action, verify_authorization=verify)
        second = first.model_copy(
            update={"proposal_id": "proposal_fedcba9876543210fedcba9876543210"}
        )
        with pytest.raises(ActionAuthorizationError, match="head binding"):
            repo.register_server_proposal(second, current_plan_version=second.plan_version)
        assert repo.proposal(second.proposal_id) is None
        with pytest.raises(sqlite3.DatabaseError, match="unresolved repair execution"):
            reopened.connection.execute(
                "UPDATE cases SET state_version=5 WHERE case_id=?", (str(case_id),)
            )


def test_interrupted_execution_stays_uncertain_and_cannot_replay(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        proposal = _proposal(case_id)
        repo = _repo(store)
        repo.register_server_proposal(proposal, current_plan_version=proposal.plan_version)
        review = repo.claim_review(
            proposal.proposal_id, case_id=case_id, acknowledged_digest=proposal.digest()
        )
        action, verify = _authorized(proposal, review.consent_reference)
        execution = repo.promote_execution(
            review.claim_id, action=action, verify_authorization=verify
        )
        repo.recheck_execution(execution.execution_id, action=action, verify_authorization=verify)
        interrupted = repo.mark_execution_interrupted(execution.execution_id)
        assert interrupted.state.value == "interrupted_uncertain"
        with pytest.raises(ActionAuthorizationError, match="unavailable"):
            repo.recheck_execution(
                execution.execution_id, action=action, verify_authorization=verify
            )
        with pytest.raises(ActionAuthorizationError, match="already"):
            repo.promote_execution(review.claim_id, action=action, verify_authorization=verify)


def test_execution_promotion_rejects_same_revision_supersession(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        first = _proposal(case_id)
        second = first.model_copy(
            update={"proposal_id": "proposal_fedcba9876543210fedcba9876543210"}
        )
        repo = _repo(store)
        repo.register_server_proposal(first, current_plan_version=first.plan_version)
        review = repo.claim_review(
            first.proposal_id, case_id=case_id, acknowledged_digest=first.digest()
        )
        action, verify = _authorized(first, review.consent_reference)
        repo.register_server_proposal(second, current_plan_version=second.plan_version)
        with pytest.raises(ActionAuthorizationError, match="active"):
            repo.promote_execution(review.claim_id, action=action, verify_authorization=verify)


def test_execution_admission_requires_verified_matching_authorization(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        proposal = _proposal(case_id)
        repo = _repo(store)
        repo.register_server_proposal(proposal, current_plan_version=proposal.plan_version)
        review = repo.claim_review(
            proposal.proposal_id, case_id=case_id, acknowledged_digest=proposal.digest()
        )
        action, verify = _authorized(proposal, review.consent_reference)
        with pytest.raises(ActionAuthorizationError, match="verification"):
            repo.promote_execution(review.claim_id, action=action)
        with pytest.raises(ActionAuthorizationError, match="invalid"):
            repo.promote_execution(
                review.claim_id, action=action, verify_authorization=lambda token: False
            )
        assert (
            repo.promote_execution(
                review.claim_id, action=action, verify_authorization=verify
            ).proposal_digest
            == proposal.digest()
        )


def test_expiry_between_promotion_and_write_boundary_does_not_start(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        proposal = _proposal(case_id)
        repo = _repo(store)
        repo.register_server_proposal(proposal, current_plan_version=proposal.plan_version)
        review = repo.claim_review(
            proposal.proposal_id, case_id=case_id, acknowledged_digest=proposal.digest()
        )
        action, verify = _authorized(proposal, review.consent_reference)
        execution = repo.promote_execution(
            review.claim_id, action=action, verify_authorization=verify
        )
        expired = _repo(store, now=proposal.expires_at)
        with pytest.raises(ActionAuthorizationError, match="expired"):
            expired.recheck_execution(
                execution.execution_id, action=action, verify_authorization=verify
            )
        assert repo.execution(execution.execution_id) == execution


def test_execution_target_is_reserved_across_cases_even_with_distinct_target_ids(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        repo = _repo(store)
        first_case = _case(store)
        first = _proposal(first_case)
        repo.register_server_proposal(first, current_plan_version=first.plan_version)
        first_review = repo.claim_review(
            first.proposal_id, case_id=first_case, acknowledged_digest=first.digest()
        )
        first_action, first_verify = _authorized(first, first_review.consent_reference)
        repo.promote_execution(
            first_review.claim_id, action=first_action, verify_authorization=first_verify
        )

        second_case = _case(store)
        second = _proposal(second_case).model_copy(
            update={"proposal_id": "proposal_fedcba9876543210fedcba9876543210"}
        )
        assert first.operations[0].target.target_id != second.operations[0].target.target_id
        repo.register_server_proposal(second, current_plan_version=second.plan_version)
        second_review = repo.claim_review(
            second.proposal_id, case_id=second_case, acknowledged_digest=second.digest()
        )
        second_action, second_verify = _authorized(second, second_review.consent_reference)
        with pytest.raises(ActionAuthorizationError, match="target reserved"):
            repo.promote_execution(
                second_review.claim_id,
                action=second_action,
                verify_authorization=second_verify,
            )
        assert store.connection.execute(
            "SELECT COUNT(*) FROM repair_execution_claims"
        ).fetchone() == (1,)


@pytest.mark.parametrize(
    ("kind", "locator"),
    [
        (TargetKind.REGISTRY_VALUE, "wininet_proxy:S-1-5-21-1000-2000-3000-1001"),
        (TargetKind.WININET_USER_PROXY, "wininet_proxy:S-1-5-21-01000-2000-3000-1001"),
        (TargetKind.WININET_USER_PROXY, "wininet_proxy:S-1-5-21-1000-2000-3000-1001/alias"),
    ],
)
def test_execution_promotion_rejects_noncanonical_target(
    tmp_path: Path, kind: TargetKind, locator: str
) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        original = _proposal(case_id)
        target = original.operations[0].target.model_copy(update={"kind": kind, "locator": locator})
        operation = original.operations[0].model_copy(update={"target": target})
        proposal = original.model_copy(update={"operations": (operation,)})
        repo = _repo(store)
        repo.register_server_proposal(proposal, current_plan_version=proposal.plan_version)
        review = repo.claim_review(
            proposal.proposal_id, case_id=case_id, acknowledged_digest=proposal.digest()
        )
        action, verify = _authorized(proposal, review.consent_reference)
        with pytest.raises(ActionAuthorizationError, match="canonical WinINet"):
            repo.promote_execution(review.claim_id, action=action, verify_authorization=verify)


def test_sql_cannot_replace_or_rewrite_execution_claim(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        proposal = _proposal(case_id)
        repo = _repo(store)
        repo.register_server_proposal(proposal, current_plan_version=proposal.plan_version)
        review = repo.claim_review(
            proposal.proposal_id, case_id=case_id, acknowledged_digest=proposal.digest()
        )
        action, verify = _authorized(proposal, review.consent_reference)
        execution = repo.promote_execution(
            review.claim_id, action=action, verify_authorization=verify
        )
        store.connection.execute("PRAGMA recursive_triggers = OFF")
        row = store.connection.execute(
            "SELECT * FROM repair_execution_claims WHERE execution_id=?",
            (execution.execution_id,),
        ).fetchone()
        assert row is not None
        with pytest.raises(sqlite3.DatabaseError, match="replayed or rewritten"):
            store.connection.execute(
                "INSERT OR REPLACE INTO repair_execution_claims "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                ("execution_replayed", *row[1:]),
            )
        with pytest.raises(sqlite3.DatabaseError, match="replayed or rewritten"):
            store.connection.execute(
                "UPDATE repair_execution_claims SET authorization_id='other' WHERE execution_id=?",
                (execution.execution_id,),
            )
        with pytest.raises(sqlite3.DatabaseError, match="immutable"):
            store.connection.execute(
                "DELETE FROM repair_execution_claims WHERE execution_id=?",
                (execution.execution_id,),
            )


def test_concurrent_execution_rechecks_start_exactly_once(tmp_path: Path) -> None:
    path = tmp_path / "cases.db"
    with SQLiteStore(path) as store:
        case_id = _case(store)
        proposal = _proposal(case_id)
        repo = _repo(store)
        repo.register_server_proposal(proposal, current_plan_version=proposal.plan_version)
        review = repo.claim_review(
            proposal.proposal_id, case_id=case_id, acknowledged_digest=proposal.digest()
        )
        action, verify = _authorized(proposal, review.consent_reference)
        execution = repo.promote_execution(
            review.claim_id, action=action, verify_authorization=verify
        )
    start = Barrier(2)

    def begin() -> str:
        with SQLiteStore(path) as store:
            start.wait(5)
            try:
                _repo(store).recheck_execution(
                    execution.execution_id, action=action, verify_authorization=verify
                )
            except ActionAuthorizationError:
                return "rejected"
            return "started"

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(begin)
        second = pool.submit(begin)
        outcomes = (first.result(timeout=5), second.result(timeout=5))
    assert outcomes.count("started") == 1
    assert outcomes.count("rejected") == 1


def test_same_revision_proposal_replaces_active_head_and_old_review_cannot_claim(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        first = _proposal(case_id)
        second = first.model_copy(
            update={"proposal_id": "proposal_fedcba9876543210fedcba9876543210"}
        )
        repo = _repo(store)
        repo.register_server_proposal(first, current_plan_version="proxy-plan-1")
        first_head = repo.active_head(case_id)
        assert first_head is not None
        assert first_head.proposal_id == first.proposal_id
        assert first_head.proposal_digest == first.digest()
        assert first_head.case_state_version == 4

        repo.register_server_proposal(second, current_plan_version="proxy-plan-1")
        active_head = repo.active_head(case_id)
        assert active_head is not None
        assert active_head.proposal_id == second.proposal_id
        assert active_head.proposal_digest == second.digest()
        assert active_head.plan_version == first_head.plan_version == "proxy-plan-1"
        with pytest.raises(ActionAuthorizationError, match="active"):
            repo.claim_review(
                first.proposal_id, case_id=case_id, acknowledged_digest=first.digest()
            )
        claim = repo.claim_review(
            second.proposal_id, case_id=case_id, acknowledged_digest=second.digest()
        )
        assert claim.proposal_id == second.proposal_id


def test_v6_proposal_is_not_guessed_into_active_head_on_upgrade(tmp_path: Path) -> None:
    path = tmp_path / "cases.db"
    with SQLiteStore(path) as store:
        case_id = _case(store)
        proposal = _proposal(case_id)
        _repo(store).register_server_proposal(proposal, current_plan_version="proxy-plan-1")
        assert "state_version" in store.column_names("probe_executions")

    # Remove post-v6 tables to recreate the v6 schema. All earlier
    # migrations, including v5's Python column migration, ran through SQLiteStore.
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE diagnostic_progress")
        connection.execute("DROP TABLE diagnostic_intent_terminals")
        connection.execute("DROP TABLE diagnostic_intent_execution_links")
        connection.execute("DROP TABLE diagnostic_intent_dispatch_claims")
        connection.execute("DROP TABLE diagnostic_intent_admissions")
        connection.execute("DROP TABLE search_frontier_investigator_turn_closures")
        connection.execute("DROP TABLE search_frontier_investigator_turn_outcomes")
        connection.execute("DROP TABLE search_frontier_investigator_turns")
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
        connection.execute("DROP TRIGGER frontier_packet_snapshot_bindings_no_update")
        connection.execute("DROP TRIGGER frontier_packet_snapshot_bindings_no_delete")
        connection.execute("DROP TRIGGER frontier_packet_receipts_no_update")
        connection.execute("DROP TRIGGER frontier_packet_receipts_no_delete")
        connection.execute("DROP TABLE frontier_packet_snapshot_bindings")
        connection.execute("DROP TABLE frontier_packet_receipts")
        connection.execute("DROP TABLE deep_mailbox")
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
        connection.execute("ALTER TABLE probe_executions DROP COLUMN tree_exit_status")
        connection.execute("PRAGMA user_version = 6")
        assert connection.execute("PRAGMA user_version").fetchone() == (6,)
        assert "state_version" in {
            row[1] for row in connection.execute("PRAGMA table_info(probe_executions)")
        }
    with SQLiteStore(path) as store:
        repo = _repo(store)
        assert store.schema_version() == 30
        assert repo.proposal(proposal.proposal_id) == proposal
        assert repo.active_head(case_id) is None
        with pytest.raises(ActionAuthorizationError, match="active"):
            repo.claim_review(
                proposal.proposal_id, case_id=case_id, acknowledged_digest=proposal.digest()
            )


def test_v7_review_claim_is_not_automatically_promoted_on_upgrade(tmp_path: Path) -> None:
    path = tmp_path / "cases.db"
    with SQLiteStore(path) as store:
        case_id = _case(store)
        proposal = _proposal(case_id)
        repo = _repo(store)
        repo.register_server_proposal(proposal, current_plan_version=proposal.plan_version)
        review = repo.claim_review(
            proposal.proposal_id, case_id=case_id, acknowledged_digest=proposal.digest()
        )
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE diagnostic_progress")
        connection.execute("DROP TABLE diagnostic_intent_terminals")
        connection.execute("DROP TABLE diagnostic_intent_execution_links")
        connection.execute("DROP TABLE diagnostic_intent_dispatch_claims")
        connection.execute("DROP TABLE diagnostic_intent_admissions")
        connection.execute("DROP TABLE search_frontier_investigator_turn_closures")
        connection.execute("DROP TABLE search_frontier_investigator_turn_outcomes")
        connection.execute("DROP TABLE search_frontier_investigator_turns")
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
        connection.execute("DROP TRIGGER frontier_packet_snapshot_bindings_no_update")
        connection.execute("DROP TRIGGER frontier_packet_snapshot_bindings_no_delete")
        connection.execute("DROP TRIGGER frontier_packet_receipts_no_update")
        connection.execute("DROP TRIGGER frontier_packet_receipts_no_delete")
        connection.execute("DROP TABLE frontier_packet_snapshot_bindings")
        connection.execute("DROP TABLE frontier_packet_receipts")
        connection.execute("DROP TABLE deep_mailbox")
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
        connection.execute("DROP TRIGGER repair_plan_heads_execution_fence")
        connection.execute("DROP TABLE repair_execution_terminals")
        connection.execute("DROP TABLE repair_execution_target_locks")
        connection.execute("DROP TABLE repair_execution_claims")
        connection.execute("ALTER TABLE probe_executions DROP COLUMN tree_exit_status")
        connection.execute("PRAGMA user_version = 7")
    with SQLiteStore(path) as store:
        repo = _repo(store)
        assert store.schema_version() == 30
        assert repo.claim(review.claim_id) == review
        assert store.connection.execute(
            "SELECT COUNT(*) FROM repair_execution_claims"
        ).fetchone() == (0,)


def test_failed_head_replacement_rolls_back_new_proposal(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        first = _proposal(case_id)
        second = first.model_copy(
            update={"proposal_id": "proposal_fedcba9876543210fedcba9876543210"}
        )
        repo = _repo(store)
        repo.register_server_proposal(first, current_plan_version="proxy-plan-1")
        store.connection.execute(
            "CREATE TRIGGER block_head_replacement BEFORE UPDATE ON repair_plan_heads "
            "BEGIN SELECT RAISE(ABORT, 'blocked head replacement'); END"
        )
        with pytest.raises(ActionAuthorizationError, match="head binding"):
            repo.register_server_proposal(second, current_plan_version="proxy-plan-1")
        assert repo.proposal(second.proposal_id) is None
        head = repo.active_head(case_id)
        assert head is not None and head.proposal_id == first.proposal_id


@pytest.mark.parametrize(
    ("pragma", "required"),
    [
        ("PRAGMA synchronous = NORMAL", "FULL"),
        ("PRAGMA journal_mode = MEMORY", "WAL"),
        ("PRAGMA foreign_keys = OFF", "foreign_keys"),
    ],
)
def test_approval_store_refuses_weak_sqlite_durability(
    tmp_path: Path, pragma: str, required: str
) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        store.connection.execute(pragma)
        with pytest.raises(RuntimeError, match=required):
            _repo(store)


@pytest.mark.parametrize(
    ("pragma", "required"),
    [
        ("PRAGMA synchronous = NORMAL", "FULL"),
        ("PRAGMA journal_mode = MEMORY", "WAL"),
        ("PRAGMA foreign_keys = OFF", "foreign_keys"),
    ],
)
def test_claim_refuses_durability_downgrade_after_repository_creation(
    tmp_path: Path, pragma: str, required: str
) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        proposal = _proposal(case_id)
        repo = _repo(store)
        repo.register_server_proposal(proposal, current_plan_version="proxy-plan-1")
        store.connection.execute(pragma)
        with pytest.raises(RuntimeError, match=required):
            repo.claim_review(
                proposal.proposal_id,
                case_id=case_id,
                acknowledged_digest=proposal.digest(),
            )
        assert repo.claim("claim_nonexistent") is None


def test_registered_proposal_is_canonical_immutable_and_bound_to_existing_case(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        proposal = _proposal(case_id)
        repo = _repo(store)
        repo.register_server_proposal(proposal, current_plan_version="proxy-plan-1")

        assert store.schema_version() == 30
        assert repo.proposal(proposal.proposal_id) == proposal
        row = store.connection.execute(
            "SELECT proposal_json, proposal_digest FROM repair_proposals WHERE proposal_id = ?",
            (proposal.proposal_id,),
        ).fetchone()
        assert row == (
            json.dumps(proposal.model_dump(mode="json"), sort_keys=True, separators=(",", ":")),
            proposal.digest(),
        )
        with pytest.raises(ActionAuthorizationError, match="already registered"):
            repo.register_server_proposal(proposal, current_plan_version="proxy-plan-1")
        with pytest.raises(Exception, match="immutable"):
            store.connection.execute(
                "UPDATE repair_proposals SET plan_version='other' WHERE proposal_id=?",
                (proposal.proposal_id,),
            )


def test_claim_is_durable_single_use_and_exactly_bound(tmp_path: Path) -> None:
    path = tmp_path / "cases.db"
    with SQLiteStore(path) as store:
        case_id = _case(store)
        proposal = _proposal(case_id)
        repo = _repo(store)
        repo.register_server_proposal(proposal, current_plan_version="proxy-plan-1")
        claim = repo.claim_review(
            proposal.proposal_id,
            case_id=case_id,
            acknowledged_digest=proposal.digest(),
        )
        assert claim.state is RepairApprovalState.CLAIMED
        assert claim.proposal_digest == proposal.digest()
        assert claim.consent_reference.startswith("consent_")
        assert claim.case_id == case_id
    with SQLiteStore(path) as reopened:
        repo = _repo(reopened)
        head = repo.active_head(case_id)
        assert head is not None and head.proposal_id == proposal.proposal_id
        assert repo.claim(claim.claim_id) == claim
        with pytest.raises(ActionAuthorizationError, match="already claimed"):
            repo.claim_review(
                proposal.proposal_id,
                case_id=case_id,
                acknowledged_digest=proposal.digest(),
            )


def test_wrong_case_digest_and_stale_case_state_never_claim(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        proposal = _proposal(case_id)
        repo = _repo(store)
        repo.register_server_proposal(proposal, current_plan_version="proxy-plan-1")
        with pytest.raises(ActionAuthorizationError, match="case binding"):
            repo.claim_review(
                proposal.proposal_id,
                case_id=CaseId.new(),
                acknowledged_digest=proposal.digest(),
            )
        with pytest.raises(ActionAuthorizationError, match="digest"):
            repo.claim_review(
                proposal.proposal_id,
                case_id=case_id,
                acknowledged_digest="0" * 64,
            )
        store.connection.execute(
            "UPDATE cases SET state_version=5 WHERE case_id=?", (str(case_id),)
        )
        with pytest.raises(ActionAuthorizationError, match="stale"):
            repo.active_head(case_id)
        with pytest.raises(ActionAuthorizationError, match="stale"):
            repo.claim_review(
                proposal.proposal_id,
                case_id=case_id,
                acknowledged_digest=proposal.digest(),
            )
        assert store.connection.execute(
            "SELECT COUNT(*) FROM repair_approval_claims"
        ).fetchone() == (0,)


def test_expired_proposal_cannot_register_or_claim(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        proposal = _proposal(case_id)
        expired_repo = _repo(store, now=NOW + timedelta(minutes=5))
        with pytest.raises(ActionAuthorizationError, match="expired"):
            expired_repo.register_server_proposal(proposal, current_plan_version="proxy-plan-1")
        _repo(store).register_server_proposal(proposal, current_plan_version="proxy-plan-1")
        with pytest.raises(ActionAuthorizationError, match="expired"):
            expired_repo.claim_review(
                proposal.proposal_id,
                case_id=case_id,
                acknowledged_digest=proposal.digest(),
            )


def test_concurrent_claims_allow_exactly_one_winner(tmp_path: Path) -> None:
    path = tmp_path / "cases.db"
    with SQLiteStore(path) as store:
        case_id = _case(store)
        proposal = _proposal(case_id)
        _repo(store).register_server_proposal(proposal, current_plan_version="proxy-plan-1")
    start = Barrier(2)

    def claim() -> str:
        with SQLiteStore(path) as store:
            start.wait(5)
            try:
                result = _repo(store).claim_review(
                    proposal.proposal_id,
                    case_id=case_id,
                    acknowledged_digest=proposal.digest(),
                )
            except ActionAuthorizationError:
                return "rejected"
            return result.claim_id

    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(claim)
        second = pool.submit(claim)
        outcomes = (first.result(timeout=5), second.result(timeout=5))
    assert len([outcome for outcome in outcomes if outcome != "rejected"]) == 1
    assert outcomes.count("rejected") == 1


def test_interrupted_claim_is_explicit_and_never_reopened(tmp_path: Path) -> None:
    path = tmp_path / "cases.db"
    with SQLiteStore(path) as store:
        case_id = _case(store)
        proposal = _proposal(case_id)
        repo = _repo(store)
        repo.register_server_proposal(proposal, current_plan_version="proxy-plan-1")
        claim = repo.claim_review(
            proposal.proposal_id,
            case_id=case_id,
            acknowledged_digest=proposal.digest(),
        )
    with SQLiteStore(path) as reopened:
        repo = _repo(reopened, now=NOW + timedelta(seconds=1))
        interrupted = repo.mark_interrupted(claim.claim_id)
        assert interrupted.state is RepairApprovalState.INTERRUPTED_UNCERTAIN
        assert repo.claim(claim.claim_id) == interrupted
        with pytest.raises(ActionAuthorizationError, match="already interrupted"):
            repo.mark_interrupted(claim.claim_id)
        with pytest.raises(ActionAuthorizationError, match="already claimed"):
            repo.claim_review(
                proposal.proposal_id,
                case_id=case_id,
                acknowledged_digest=proposal.digest(),
            )


def test_claim_rechecks_expiry_after_acquiring_write_transaction(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        proposal = _proposal(case_id)
        _repo(store).register_server_proposal(proposal, current_plan_version="proxy-plan-1")
        current = NOW
        original_transaction = store.transaction

        @contextmanager
        def delayed_transaction() -> Generator[StoreTransaction]:
            nonlocal current
            with original_transaction() as transaction:
                current = proposal.expires_at
                yield transaction

        monkeypatch.setattr(store, "transaction", delayed_transaction)
        repo = RepairApprovalRepository(store, clock=lambda: current)
        with pytest.raises(ActionAuthorizationError, match="expired"):
            repo.claim_review(
                proposal.proposal_id,
                case_id=case_id,
                acknowledged_digest=proposal.digest(),
            )
        assert store.connection.execute(
            "SELECT COUNT(*) FROM repair_approval_claims"
        ).fetchone() == (0,)


def test_interruption_time_cannot_precede_claim(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        proposal = _proposal(case_id)
        repo = _repo(store)
        repo.register_server_proposal(proposal, current_plan_version="proxy-plan-1")
        claim = repo.claim_review(
            proposal.proposal_id,
            case_id=case_id,
            acknowledged_digest=proposal.digest(),
        )
        earlier = _repo(store, now=NOW - timedelta(seconds=1))
        with pytest.raises(ActionAuthorizationError, match="before claim"):
            earlier.mark_interrupted(claim.claim_id)
        assert repo.claim(claim.claim_id) == claim


def test_sql_cannot_rewrite_delete_or_duplicate_a_consumed_claim(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        proposal = _proposal(case_id)
        repo = _repo(store)
        repo.register_server_proposal(proposal, current_plan_version="proxy-plan-1")
        claim = repo.claim_review(
            proposal.proposal_id,
            case_id=case_id,
            acknowledged_digest=proposal.digest(),
        )
        with pytest.raises(sqlite3.DatabaseError, match="replayed or rewritten"):
            store.connection.execute(
                "UPDATE repair_approval_claims SET consent_reference='consent_other' "
                "WHERE claim_id=?",
                (claim.claim_id,),
            )
        with pytest.raises(sqlite3.DatabaseError, match="immutable"):
            store.connection.execute(
                "DELETE FROM repair_approval_claims WHERE claim_id=?", (claim.claim_id,)
            )
        with pytest.raises(sqlite3.IntegrityError):
            store.connection.execute(
                "INSERT INTO repair_approval_claims "
                "(claim_id, proposal_id, case_id, proposal_digest, consent_reference, "
                "state, claimed_at, updated_at) VALUES (?, ?, ?, ?, ?, 'claimed', ?, ?)",
                (
                    "claim_other",
                    proposal.proposal_id,
                    str(case_id),
                    proposal.digest(),
                    "consent_other",
                    NOW.isoformat(),
                    NOW.isoformat(),
                ),
            )


def test_sql_replace_cannot_overwrite_registered_proposal_or_consumed_claim(
    tmp_path: Path,
) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        proposal = _proposal(case_id)
        repo = _repo(store)
        repo.register_server_proposal(proposal, current_plan_version="proxy-plan-1")
        store.connection.execute("PRAGMA recursive_triggers = OFF")
        proposal_row = store.connection.execute(
            "SELECT proposal_id, case_id, case_state_version, plan_version, created_at, "
            "expires_at, proposal_digest, proposal_json FROM repair_proposals WHERE proposal_id=?",
            (proposal.proposal_id,),
        ).fetchone()
        assert proposal_row is not None
        with pytest.raises(sqlite3.DatabaseError):
            store.connection.execute(
                "INSERT OR REPLACE INTO repair_proposals VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (*proposal_row[:3], "altered-plan", *proposal_row[4:]),
            )
        assert repo.proposal(proposal.proposal_id) == proposal

        claim = repo.claim_review(
            proposal.proposal_id,
            case_id=case_id,
            acknowledged_digest=proposal.digest(),
        )

        claim_row = store.connection.execute(
            "SELECT claim_id, proposal_id, case_id, proposal_digest, consent_reference, "
            "state, claimed_at, updated_at FROM repair_approval_claims WHERE claim_id=?",
            (claim.claim_id,),
        ).fetchone()
        assert claim_row is not None
        with pytest.raises(sqlite3.DatabaseError):
            store.connection.execute(
                "INSERT OR REPLACE INTO repair_approval_claims VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                ("claim_replayed", *claim_row[1:]),
            )
        assert repo.claim(claim.claim_id) == claim
