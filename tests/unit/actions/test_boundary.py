from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from systemsense.actions import (
    ActionAuthorizationError,
    ActionCode,
    ActionGate,
    ActionKind,
    ActionOperation,
    AuthorizationAuthority,
    DiagnosticExperimentProposal,
    DisruptionLevel,
    EvidenceRequirement,
    ExactTarget,
    ExpectedEffect,
    HumanConsent,
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
from systemsense.domain.ids import CaseId, EvidenceId, TargetId

NOW = datetime(2026, 9, 21, 12, 0, tzinfo=UTC)


def target() -> ExactTarget:
    return ExactTarget(
        target_id=TargetId.new(),
        kind=TargetKind.SERVICE,
        locator="service:Windows-Update",
    )


def operation(*, action_kind: ActionKind = ActionKind.REPAIR) -> ActionOperation:
    return ActionOperation(
        operation_id="op_restart_update",
        code=ActionCode.RESTART_SERVICE,
        kind=action_kind,
        target=target(),
    )


def proposal(
    *,
    action_kind: ActionKind = ActionKind.REPAIR,
    case_state_version: int = 4,
    plan_version: str = "plan-2026.09.21-1",
    expires_at: datetime = NOW + timedelta(minutes=10),
) -> RepairProposal | DiagnosticExperimentProposal:
    values = {
        "proposal_id": "proposal_0123456789abcdef0123456789abcdef",
        "kind": action_kind,
        "case_id": CaseId.new(),
        "case_state_version": case_state_version,
        "plan_version": plan_version,
        "created_at": NOW,
        "expires_at": expires_at,
        "operations": (operation(action_kind=action_kind),),
        "preconditions": (
            Precondition(
                code=PreconditionCode.EVIDENCE_PRESENT,
                evidence=(
                    EvidenceRequirement(
                        evidence_id=EvidenceId.new(),
                        max_age_seconds=300,
                        required_fact="service_state",
                    ),
                ),
            ),
        ),
        "expected_effect": ExpectedEffect(
            summary="restart the exact service and re-check availability",
            success_indicators=("service is running",),
        ),
        "risk": ProposalRisk(
            level=RiskLevel.MODERATE,
            disruption=DisruptionLevel.SERVICE_RESTART,
            summary="brief service interruption",
        ),
        "verification": VerificationPlan(
            checks=(VerificationCheck(code="service_state_matches"),),
        ),
        "rollback": RollbackLimits(
            supported=True,
            max_attempts=1,
            limits="restart can be attempted once if verification fails",
        ),
    }
    if action_kind is ActionKind.REPAIR:
        return RepairProposal.model_validate(values)
    return DiagnosticExperimentProposal.model_validate(values)


def consent_for(action: RepairProposal | DiagnosticExperimentProposal) -> HumanConsent:
    return HumanConsent(
        reviewer_id="human:reviewer-1",
        consent_reference="consent_20260921_001",
        case_id=action.case_id,
        case_state_version=action.case_state_version,
        plan_version=action.plan_version,
        proposal_digest=action.digest(),
        operation_digests=action.operation_digests(),
        expires_at=NOW + timedelta(minutes=5),
        reviewed=True,
    )


def test_proposals_are_immutable_and_do_not_expose_commands() -> None:
    repair = proposal()
    with pytest.raises(ValidationError):
        repair.operations[0].target.locator = "service:*"  # type: ignore[misc]
    with pytest.raises(ValidationError):
        ActionOperation.model_validate(
            {
                **operation().model_dump(),
                "command": "powershell Stop-Service Windows-Update",
            }
        )


def test_proposals_require_exact_targets_and_reject_wildcards() -> None:
    with pytest.raises(ValidationError, match="wildcard"):
        ExactTarget(
            target_id=TargetId.new(),
            kind=TargetKind.FILE,
            locator=r"C:\\Temp\\*.log",
        )


def test_experiment_and_repair_kinds_cannot_be_mixed() -> None:
    with pytest.raises(ValidationError, match="kind"):
        DiagnosticExperimentProposal(**proposal(action_kind=ActionKind.REPAIR).model_dump())


def test_gate_rejects_missing_token() -> None:
    repair = proposal()
    gate = ActionGate(secret=b"test-secret-12345")
    with pytest.raises(ActionAuthorizationError, match="missing"):
        gate.authorize(
            repair,
            None,
            current_state_version=4,
            current_plan_version=repair.plan_version,
            now=NOW,
        )


def test_authority_and_gate_accept_independent_human_consent() -> None:
    repair = proposal()
    authority = AuthorizationAuthority(secret=b"test-secret-12345")
    token = authority.issue(repair, consent=consent_for(repair), issued_at=NOW)
    authorized = ActionGate(secret=b"test-secret-12345").authorize(
        repair,
        token,
        current_state_version=4,
        current_plan_version=repair.plan_version,
        now=NOW,
    )
    assert authorized.proposal is repair
    assert authorized.token is token


@pytest.mark.parametrize(
    ("state_version", "plan_version", "message"),
    [
        (5, "plan-2026.09.21-1", "state"),
        (4, "plan-2026.09.21-2", "plan"),
    ],
)
def test_gate_rejects_stale_or_mismatched_binding(
    state_version: int, plan_version: str, message: str
) -> None:
    repair = proposal()
    authority = AuthorizationAuthority(secret=b"test-secret-12345")
    token = authority.issue(repair, consent=consent_for(repair), issued_at=NOW)
    with pytest.raises(ActionAuthorizationError, match=message):
        ActionGate(secret=b"test-secret-12345").authorize(
            repair,
            token,
            current_state_version=state_version,
            current_plan_version=plan_version,
            now=NOW,
        )


def test_gate_rejects_expired_token_and_proposal() -> None:
    repair = proposal(expires_at=NOW + timedelta(seconds=1))
    authority = AuthorizationAuthority(secret=b"test-secret-12345")
    token = authority.issue(repair, consent=consent_for(repair), issued_at=NOW)
    with pytest.raises(ActionAuthorizationError, match="expired"):
        ActionGate(secret=b"test-secret-12345").authorize(
            repair,
            token,
            current_state_version=4,
            current_plan_version=repair.plan_version,
            now=NOW + timedelta(seconds=2),
        )


def test_gate_rejects_clock_before_token_issue() -> None:
    repair = proposal()
    token = AuthorizationAuthority(secret=b"test-secret-12345").issue(
        repair, consent=consent_for(repair), issued_at=NOW + timedelta(seconds=5)
    )

    with pytest.raises(ActionAuthorizationError, match="not yet valid"):
        ActionGate(secret=b"test-secret-12345").authorize(
            repair,
            token,
            current_state_version=4,
            current_plan_version=repair.plan_version,
            now=NOW,
        )


def test_authority_rejects_issue_before_proposal_creation() -> None:
    repair = proposal()

    with pytest.raises(ActionAuthorizationError, match="not yet valid"):
        AuthorizationAuthority(secret=b"test-secret-12345").issue(
            repair, consent=consent_for(repair), issued_at=NOW - timedelta(seconds=1)
        )


def test_gate_rejects_broadened_operations() -> None:
    repair = proposal()
    authority = AuthorizationAuthority(secret=b"test-secret-12345")
    token = authority.issue(repair, consent=consent_for(repair), issued_at=NOW)
    broadened = repair.model_copy(update={"operations": (*repair.operations, operation())})
    with pytest.raises(ActionAuthorizationError, match="operation"):
        ActionGate(secret=b"test-secret-12345").authorize(
            broadened,
            token,
            current_state_version=4,
            current_plan_version=repair.plan_version,
            now=NOW,
        )


def test_unreviewed_consent_cannot_mint_a_token() -> None:
    repair = proposal()
    authority = AuthorizationAuthority(secret=b"test-secret-12345")
    consent = consent_for(repair).model_copy(update={"reviewed": False})
    with pytest.raises(ActionAuthorizationError, match="review"):
        authority.issue(repair, consent=consent, issued_at=NOW)


def test_consent_without_explicit_review_cannot_mint_a_token() -> None:
    repair = proposal()
    consent = HumanConsent.model_validate(consent_for(repair).model_dump(exclude={"reviewed"}))
    assert consent.reviewed is False
    with pytest.raises(ActionAuthorizationError, match="review"):
        AuthorizationAuthority(secret=b"test-secret-12345").issue(
            repair, consent=consent, issued_at=NOW
        )
