"""A human review must bind the exact proposal before a repair runner is called."""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from systemsense.actions.contracts import (
    ActionAuthorizationError,
    ActionCode,
    ActionGate,
    ActionKind,
    ActionOperation,
    AuthorizationToken,
    DisruptionLevel,
    ExactTarget,
    ExpectedEffect,
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
from systemsense.actions.wininet_proxy import ProxyRepairOutcome, ProxyRepairResult
from systemsense.application.repair_approval import CancellationDisposition, RepairApprovalRoute
from systemsense.domain.ids import CaseId, TargetId
from systemsense.storage.repair_approvals import RepairApprovalRepository
from systemsense.storage.sqlite_store import SQLiteStore

NOW = datetime(2026, 9, 22, 12, tzinfo=UTC)


def _proposal() -> RepairProposal:
    target = ExactTarget(
        target_id=TargetId.new(),
        kind=TargetKind.WININET_USER_PROXY,
        locator="wininet_proxy:S-1-5-21-1000-2000-3000-1001",
    )
    return RepairProposal(
        proposal_id="proposal_0123456789abcdef0123456789abcdef",
        kind=ActionKind.REPAIR,
        case_id=CaseId.new(),
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


class RecordingRunner:
    def __init__(self) -> None:
        self.execution_ids: list[str] = []
        self.calls: list[
            tuple[
                RepairProposal,
                AuthorizationToken,
                int,
                str,
                Callable[[], bool],
                Callable[[], bool],
                datetime,
            ]
        ] = []

    def execute(
        self,
        proposal: RepairProposal,
        token: AuthorizationToken,
        *,
        state_version: int,
        plan_version: str,
        cancelled: Callable[[], bool],
        write_permitted: Callable[[], bool],
        now: datetime,
        execution_id: str,
        verify_authorization: Callable[[AuthorizationToken], bool],
    ) -> ProxyRepairResult:
        assert verify_authorization(token)
        self.execution_ids.append(execution_id)
        self.calls.append(
            (proposal, token, state_version, plan_version, cancelled, write_permitted, now)
        )
        return ProxyRepairResult(ProxyRepairOutcome.PRECONDITION_FAILED)


def _repository(proposal: RepairProposal, path: Path) -> RepairApprovalRepository:
    store = SQLiteStore(path / "cases.db")
    store.initialize()
    store.create_case(
        case_id=str(proposal.case_id),
        kind="general",
        symptom="proxy unavailable",
        created_at=NOW.isoformat(),
        state_version=proposal.case_state_version,
    )
    repo = RepairApprovalRepository(store, clock=lambda: NOW)
    repo.register_server_proposal(proposal, current_plan_version=proposal.plan_version)
    return repo


def _route(proposal: RepairProposal, runner: RecordingRunner, path: Path) -> RepairApprovalRoute:
    return RepairApprovalRoute(
        proposal=proposal,
        runner=runner,
        secret=b"local-consent-secret-123",
        reviewer_identity=lambda: "human:local-user",
        current_binding=lambda: (4, "proxy-plan-1"),
        approval_repository=_repository(proposal, path),
        clock=lambda: NOW,
    )


def test_review_record_shows_exact_signed_scope_before_approval(tmp_path: Path) -> None:
    proposal = _proposal()
    route = _route(proposal, RecordingRunner(), tmp_path)

    record = route.review_record()

    assert record["proposal_digest"] == proposal.digest()
    assert record["proposal"] == proposal.model_dump(mode="json")


def test_exact_review_mints_scoped_token_and_consumes_route(tmp_path: Path) -> None:
    proposal = _proposal()
    runner = RecordingRunner()
    route = _route(proposal, runner, tmp_path)

    result = route.approve(acknowledged_digest=proposal.digest())

    assert result.outcome is ProxyRepairOutcome.PRECONDITION_FAILED
    assert len(runner.calls) == 1
    assert len(runner.execution_ids) == 1
    _, token, state_version, plan_version, _, _, now = runner.calls[0]
    assert token.reviewer_id == "human:local-user"
    assert token.proposal_digest == proposal.digest()
    assert token.operation_digests == proposal.operation_digests()
    with SQLiteStore(tmp_path / "cases.db") as store:
        persisted = store.connection.execute(
            "SELECT claims.consent_reference, execution.execution_id, execution.state "
            "FROM repair_approval_claims AS claims JOIN repair_execution_claims AS execution "
            "ON execution.claim_id=claims.claim_id WHERE claims.proposal_id=?",
            (proposal.proposal_id,),
        ).fetchone()
        assert persisted == (token.consent_reference, runner.execution_ids[0], "prepared")
    assert (state_version, plan_version, now) == (4, "proxy-plan-1", NOW)
    ActionGate(secret=b"local-consent-secret-123").authorize(
        proposal, token, current_state_version=4, current_plan_version="proxy-plan-1", now=NOW
    )
    with pytest.raises(ActionAuthorizationError, match="already consumed"):
        route.approve(acknowledged_digest=proposal.digest())


def test_wrong_digest_or_changed_binding_never_calls_runner(tmp_path: Path) -> None:
    proposal = _proposal()
    runner = RecordingRunner()
    route = _route(proposal, runner, tmp_path)
    with pytest.raises(ActionAuthorizationError, match="digest"):
        route.approve(acknowledged_digest="0" * 64)
    assert runner.calls == []

    route = RepairApprovalRoute(
        proposal=proposal,
        runner=runner,
        secret=b"local-consent-secret-123",
        reviewer_identity=lambda: "human:local-user",
        current_binding=lambda: (5, "proxy-plan-1"),
        approval_repository=_repository(proposal, tmp_path / "changed"),
        clock=lambda: NOW,
    )
    with pytest.raises(ActionAuthorizationError, match="binding"):
        route.approve(acknowledged_digest=proposal.digest())
    assert runner.calls == []


def test_expired_or_cancelled_review_never_calls_runner(tmp_path: Path) -> None:
    proposal = _proposal()
    runner = RecordingRunner()
    expired = RepairApprovalRoute(
        proposal=proposal,
        runner=runner,
        secret=b"local-consent-secret-123",
        reviewer_identity=lambda: "human:local-user",
        current_binding=lambda: (4, "proxy-plan-1"),
        approval_repository=_repository(proposal, tmp_path),
        clock=lambda: NOW + timedelta(minutes=5),
    )
    with pytest.raises(ActionAuthorizationError, match="expired"):
        expired.approve(acknowledged_digest=proposal.digest())
    route = _route(proposal, runner, tmp_path / "cancelled")
    route.cancel()
    with pytest.raises(ActionAuthorizationError, match="cancelled"):
        route.approve(acknowledged_digest=proposal.digest())
    assert runner.calls == []


def test_cancellation_acknowledgment_is_atomic_with_write_gate(tmp_path: Path) -> None:
    proposal = _proposal()
    runner = RecordingRunner()
    route = _route(proposal, runner, tmp_path)
    route.approve(acknowledged_digest=proposal.digest())
    _, _, _, _, cancelled, write_permitted, _ = runner.calls[0]

    assert route.cancel() is CancellationDisposition.ACCEPTED_BEFORE_WRITE
    assert cancelled()
    assert not write_permitted()

    later_runner = RecordingRunner()
    later_route = _route(proposal, later_runner, tmp_path / "later")
    later_route.approve(acknowledged_digest=proposal.digest())
    assert later_runner.calls[0][5]()
    assert later_route.cancel() is CancellationDisposition.TOO_LATE_TO_PREVENT_WRITE


def test_invalid_reviewer_identity_does_not_consume_durable_review(tmp_path: Path) -> None:
    proposal = _proposal()
    runner = RecordingRunner()
    repo = _repository(proposal, tmp_path)
    route = RepairApprovalRoute(
        proposal=proposal,
        runner=runner,
        secret=b"local-consent-secret-123",
        reviewer_identity=lambda: "model:untrusted",
        current_binding=lambda: (4, "proxy-plan-1"),
        approval_repository=repo,
        clock=lambda: NOW,
    )
    with pytest.raises(ValueError):
        route.approve(acknowledged_digest=proposal.digest())
    assert runner.calls == []
    with SQLiteStore(tmp_path / "cases.db") as store:
        assert store.connection.execute(
            "SELECT COUNT(*) FROM repair_approval_claims"
        ).fetchone() == (0,)


def test_route_promotion_collision_does_not_leave_orphan_review(tmp_path: Path) -> None:
    first = _proposal()
    repo = _repository(first, tmp_path)
    first_route = RepairApprovalRoute(
        proposal=first,
        runner=RecordingRunner(),
        secret=b"local-consent-secret-123",
        reviewer_identity=lambda: "human:local-user",
        current_binding=lambda: (4, "proxy-plan-1"),
        approval_repository=repo,
        clock=lambda: NOW,
    )
    first_route.approve(acknowledged_digest=first.digest())

    second = _proposal().model_copy(
        update={"proposal_id": "proposal_fedcba9876543210fedcba9876543210"}
    )
    with SQLiteStore(tmp_path / "cases.db") as store:
        store.create_case(
            case_id=str(second.case_id),
            kind="general",
            symptom="same proxy target",
            created_at=NOW.isoformat(),
            state_version=second.case_state_version,
        )
    repo.register_server_proposal(second, current_plan_version=second.plan_version)
    second_runner = RecordingRunner()
    second_route = RepairApprovalRoute(
        proposal=second,
        runner=second_runner,
        secret=b"local-consent-secret-123",
        reviewer_identity=lambda: "human:local-user",
        current_binding=lambda: (4, "proxy-plan-1"),
        approval_repository=repo,
        clock=lambda: NOW,
    )
    with pytest.raises(ActionAuthorizationError, match="target reserved"):
        second_route.approve(acknowledged_digest=second.digest())
    assert second_runner.calls == []
    with SQLiteStore(tmp_path / "cases.db") as store:
        assert store.connection.execute(
            "SELECT COUNT(*) FROM repair_approval_claims WHERE proposal_id=?",
            (second.proposal_id,),
        ).fetchone() == (0,)
