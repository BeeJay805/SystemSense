"""A human review must bind the exact proposal before a repair runner is called."""

from collections.abc import Callable
from datetime import UTC, datetime, timedelta

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
    ) -> ProxyRepairResult:
        self.calls.append(
            (proposal, token, state_version, plan_version, cancelled, write_permitted, now)
        )
        return ProxyRepairResult(ProxyRepairOutcome.PRECONDITION_FAILED)


def _route(proposal: RepairProposal, runner: RecordingRunner) -> RepairApprovalRoute:
    return RepairApprovalRoute(
        proposal=proposal,
        runner=runner,
        secret=b"local-consent-secret-123",
        reviewer_identity=lambda: "human:local-user",
        current_binding=lambda: (4, "proxy-plan-1"),
        clock=lambda: NOW,
    )


def test_review_record_shows_exact_signed_scope_before_approval() -> None:
    proposal = _proposal()
    route = _route(proposal, RecordingRunner())

    record = route.review_record()

    assert record["proposal_digest"] == proposal.digest()
    assert record["proposal"] == proposal.model_dump(mode="json")


def test_exact_review_mints_scoped_token_and_consumes_route() -> None:
    proposal = _proposal()
    runner = RecordingRunner()
    route = _route(proposal, runner)

    result = route.approve(acknowledged_digest=proposal.digest())

    assert result.outcome is ProxyRepairOutcome.PRECONDITION_FAILED
    assert len(runner.calls) == 1
    _, token, state_version, plan_version, _, _, now = runner.calls[0]
    assert token.reviewer_id == "human:local-user"
    assert token.proposal_digest == proposal.digest()
    assert token.operation_digests == proposal.operation_digests()
    assert (state_version, plan_version, now) == (4, "proxy-plan-1", NOW)
    ActionGate(secret=b"local-consent-secret-123").authorize(
        proposal, token, current_state_version=4, current_plan_version="proxy-plan-1", now=NOW
    )
    with pytest.raises(ActionAuthorizationError, match="already consumed"):
        route.approve(acknowledged_digest=proposal.digest())


def test_wrong_digest_or_changed_binding_never_calls_runner() -> None:
    proposal = _proposal()
    runner = RecordingRunner()
    route = _route(proposal, runner)
    with pytest.raises(ActionAuthorizationError, match="digest"):
        route.approve(acknowledged_digest="0" * 64)
    assert runner.calls == []

    route = RepairApprovalRoute(
        proposal=proposal,
        runner=runner,
        secret=b"local-consent-secret-123",
        reviewer_identity=lambda: "human:local-user",
        current_binding=lambda: (5, "proxy-plan-1"),
        clock=lambda: NOW,
    )
    with pytest.raises(ActionAuthorizationError, match="binding"):
        route.approve(acknowledged_digest=proposal.digest())
    assert runner.calls == []


def test_expired_or_cancelled_review_never_calls_runner() -> None:
    proposal = _proposal()
    runner = RecordingRunner()
    expired = RepairApprovalRoute(
        proposal=proposal,
        runner=runner,
        secret=b"local-consent-secret-123",
        reviewer_identity=lambda: "human:local-user",
        current_binding=lambda: (4, "proxy-plan-1"),
        clock=lambda: NOW + timedelta(minutes=5),
    )
    with pytest.raises(ActionAuthorizationError, match="expired"):
        expired.approve(acknowledged_digest=proposal.digest())
    route = _route(proposal, runner)
    route.cancel()
    with pytest.raises(ActionAuthorizationError, match="cancelled"):
        route.approve(acknowledged_digest=proposal.digest())
    assert runner.calls == []


def test_cancellation_acknowledgment_is_atomic_with_write_gate() -> None:
    proposal = _proposal()
    runner = RecordingRunner()
    route = _route(proposal, runner)
    route.approve(acknowledged_digest=proposal.digest())
    _, _, _, _, cancelled, write_permitted, _ = runner.calls[0]

    assert route.cancel() is CancellationDisposition.ACCEPTED_BEFORE_WRITE
    assert cancelled()
    assert not write_permitted()

    later_runner = RecordingRunner()
    later_route = _route(proposal, later_runner)
    later_route.approve(acknowledged_digest=proposal.digest())
    assert later_runner.calls[0][5]()
    assert later_route.cancel() is CancellationDisposition.TOO_LATE_TO_PREVENT_WRITE
