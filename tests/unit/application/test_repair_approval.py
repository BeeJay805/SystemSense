"""A human review must bind the exact proposal before a repair runner is called."""

from collections.abc import Callable
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import pytest

import systemsense.application.interactive_consent as consent_module
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
from systemsense.application.interactive_consent import (
    InteractiveConsentBroker,
    WindowsPrincipal,
)
from systemsense.application.repair_approval import (
    CancellationDisposition,
    RepairApprovalRoute,
    RepairExecutionReceipt,
)
from systemsense.domain.ids import CaseId, TargetId
from systemsense.storage.repair_approvals import RepairApprovalRepository
from systemsense.storage.sqlite_store import SQLiteStore

NOW = datetime(2026, 9, 22, 12, tzinfo=UTC)


def test_denied_interactive_review_never_creates_authorization(tmp_path: Path) -> None:
    proposal = _proposal()
    runner = RecordingRunner()
    repo = _repository(proposal, tmp_path)
    shown: list[dict[str, object]] = []
    broker = InteractiveConsentBroker(
        identity=lambda: WindowsPrincipal(
            sid="S-1-5-21-1000-2000-3000-1001", logon_id=42, session_id=3
        ),
        presenter=lambda record, timeout: shown.append(record) or False,
        clock=lambda: NOW,
    )
    route = RepairApprovalRoute(
        proposal=proposal,
        runner=runner,
        secret=b"local-consent-secret-123",
        consent_broker=broker,
        current_binding=lambda: (4, "proxy-plan-1"),
        approval_repository=repo,
        clock=lambda: NOW,
    )

    with pytest.raises(ActionAuthorizationError, match="declined"):
        route.approve()

    assert shown[0]["proposal_digest"] == proposal.digest()
    assert shown[0]["proposal"] == proposal.model_dump(mode="json")
    assert runner.calls == []
    with SQLiteStore(tmp_path / "cases.db") as store:
        assert store.connection.execute(
            "SELECT COUNT(*) FROM repair_approval_claims"
        ).fetchone() == (0,)


def test_switched_logon_session_after_click_is_denied(tmp_path: Path) -> None:
    proposal = _proposal()
    runner = RecordingRunner()
    first = WindowsPrincipal("S-1-5-21-1000-2000-3000-1001", 42, 3)
    identities = iter((first, replace(first, logon_id=99)))
    route = RepairApprovalRoute(
        proposal=proposal,
        runner=runner,
        secret=b"local-consent-secret-123",
        consent_broker=_broker(identity=lambda: next(identities)),
        current_binding=lambda: (4, "proxy-plan-1"),
        approval_repository=_repository(proposal, tmp_path),
        clock=lambda: NOW,
    )

    with pytest.raises(ActionAuthorizationError, match="session"):
        route.approve()

    assert runner.calls == []
    with SQLiteStore(tmp_path / "cases.db") as store:
        assert store.connection.execute(
            "SELECT COUNT(*) FROM repair_approval_claims"
        ).fetchone() == (0,)


def test_forged_or_reused_review_witness_cannot_authorize() -> None:
    proposal = _proposal()
    broker = _broker()
    witness = broker.confirm(proposal)

    with pytest.raises(ActionAuthorizationError, match="missing or already used"):
        broker.consume(replace(witness), proposal)
    with pytest.raises(ActionAuthorizationError, match="missing or already used"):
        broker.consume(witness, proposal)


def test_clock_rollback_after_click_invalidates_review() -> None:
    proposal = _proposal()
    now = [NOW]
    broker = _broker(clock=lambda: now[0])
    witness = broker.confirm(proposal)
    now[0] = NOW - timedelta(seconds=1)

    with pytest.raises(ActionAuthorizationError, match="no longer matches"):
        broker.consume(witness, proposal)


def test_click_challenge_is_bound_to_durable_claim(tmp_path: Path) -> None:
    proposal = _proposal()
    shown: list[dict[str, object]] = []
    broker = _broker(presenter=lambda record, _timeout: shown.append(record) or True)
    route = RepairApprovalRoute(
        proposal=proposal,
        runner=RecordingRunner(),
        secret=b"local-consent-secret-123",
        consent_broker=broker,
        current_binding=lambda: (4, "proxy-plan-1"),
        approval_repository=_repository(proposal, tmp_path),
        clock=lambda: NOW,
    )

    route.approve()

    with SQLiteStore(tmp_path / "cases.db") as store:
        claimed = store.connection.execute(
            "SELECT consent_reference FROM repair_approval_claims WHERE proposal_id=?",
            (proposal.proposal_id,),
        ).fetchone()
    assert claimed == (shown[0]["challenge"],)


def test_headless_principal_is_rejected_before_prompt() -> None:
    with pytest.raises(ActionAuthorizationError, match="invalid"):
        WindowsPrincipal("S-1-5-21-1000-2000-3000-1001", 42, 0)


def test_runner_refusal_marks_prepared_execution_uncertain(tmp_path: Path) -> None:
    class RefusingRunner(RecordingRunner):
        def execute(  # type: ignore[override]
            self,
            proposal: RepairProposal,
            token: AuthorizationToken,
            **_kwargs: object,
        ) -> ProxyRepairResult:
            raise ActionAuthorizationError("trusted target exclusion is unavailable")

    proposal = _proposal()
    route = _route(proposal, RefusingRunner(), tmp_path)

    with pytest.raises(ActionAuthorizationError, match="target exclusion"):
        route.approve()

    with SQLiteStore(tmp_path / "cases.db") as store:
        assert store.connection.execute(
            "SELECT state FROM repair_execution_claims WHERE proposal_id=?",
            (proposal.proposal_id,),
        ).fetchone() == ("interrupted_uncertain",)
        assert store.connection.execute(
            "SELECT COUNT(*) FROM repair_execution_target_locks"
        ).fetchone() == (1,)


def test_invalid_runner_result_cannot_become_execution_receipt(tmp_path: Path) -> None:
    class InvalidRunner(RecordingRunner):
        def execute(  # type: ignore[override]
            self,
            proposal: RepairProposal,
            token: AuthorizationToken,
            **_kwargs: object,
        ) -> ProxyRepairResult:
            return cast(ProxyRepairResult, None)

    proposal = _proposal()
    route = _route(proposal, InvalidRunner(), tmp_path)

    with pytest.raises(ActionAuthorizationError, match="runner result"):
        route.approve()
    with SQLiteStore(tmp_path / "cases.db") as store:
        assert store.connection.execute(
            "SELECT state FROM repair_execution_claims WHERE proposal_id=?",
            (proposal.proposal_id,),
        ).fetchone() == ("interrupted_uncertain",)


def test_runner_claim_of_verified_without_journal_is_not_returned_as_recovery(
    tmp_path: Path,
) -> None:
    class LyingRunner(RecordingRunner):
        def execute(  # type: ignore[override]
            self,
            proposal: RepairProposal,
            token: AuthorizationToken,
            **kwargs: object,
        ) -> ProxyRepairResult:
            super().execute(proposal, token, **kwargs)  # type: ignore[arg-type]
            return ProxyRepairResult(ProxyRepairOutcome.VERIFIED)

    receipt = _route(_proposal(), LyingRunner(), tmp_path).approve()

    assert receipt.execution_id
    assert not hasattr(receipt, "runner_result")


def test_runner_and_interruption_persistence_failures_are_both_preserved(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class RefusingRunner(RecordingRunner):
        def execute(  # type: ignore[override]
            self,
            proposal: RepairProposal,
            token: AuthorizationToken,
            **_kwargs: object,
        ) -> ProxyRepairResult:
            raise ActionAuthorizationError("runner refused")

    def failed_interruption(_self: RepairApprovalRepository, _execution_id: str) -> None:
        raise RuntimeError("interruption write failed")

    monkeypatch.setattr(RepairApprovalRepository, "mark_execution_interrupted", failed_interruption)
    route = _route(_proposal(), RefusingRunner(), tmp_path)

    with pytest.raises(ExceptionGroup) as captured:
        route.approve()
    assert [type(error) for error in captured.value.exceptions] == [
        ActionAuthorizationError,
        RuntimeError,
    ]


def test_changed_interactive_identity_closes_write_gate(tmp_path: Path) -> None:
    proposal = _proposal()
    runner = RecordingRunner()
    current = [WindowsPrincipal("S-1-5-21-1000-2000-3000-1001", 42, 3)]
    route = RepairApprovalRoute(
        proposal=proposal,
        runner=runner,
        secret=b"local-consent-secret-123",
        consent_broker=_broker(identity=lambda: current[0]),
        current_binding=lambda: (4, "proxy-plan-1"),
        approval_repository=_repository(proposal, tmp_path),
        clock=lambda: NOW,
    )
    route.approve()
    current[0] = replace(current[0], session_id=9)

    assert not runner.calls[0][5]()


def test_native_identity_reader_rejects_sid_change() -> None:
    target = "S-1-5-21-1000-2000-3000-1001"
    reads = iter((target, "S-1-5-21-1000-2000-3000-9999"))
    reader = consent_module.WindowsInteractiveIdentityReader(
        active_sid=lambda: next(reads),
        token_identity=lambda: WindowsPrincipal(target, 42, 3),
    )

    with pytest.raises(ActionAuthorizationError, match="changed"):
        reader()


def test_native_review_text_contains_exact_scope_and_digest() -> None:
    proposal = _proposal()
    record = {
        "proposal": proposal.model_dump(mode="json"),
        "proposal_digest": proposal.digest(),
        "challenge": "consent_0123456789abcdef",
    }

    rendered = consent_module.format_review(record)

    assert proposal.digest() in rendered
    assert "wininet_proxy:S-1-5-21-1000-2000-3000-1001" in rendered
    assert "MODERATE" in rendered.upper()
    assert "consent_0123456789abcdef" in rendered


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


def _broker(
    *,
    identity: Callable[[], WindowsPrincipal] | None = None,
    presenter: Callable[[dict[str, object], float], bool] | None = None,
    clock: Callable[[], datetime] = lambda: NOW,
) -> InteractiveConsentBroker:
    return InteractiveConsentBroker(
        identity=identity or (lambda: WindowsPrincipal("S-1-5-21-1000-2000-3000-1001", 42, 3)),
        presenter=presenter or (lambda _record, _timeout: True),
        clock=clock,
    )


def _route(proposal: RepairProposal, runner: RecordingRunner, path: Path) -> RepairApprovalRoute:
    return RepairApprovalRoute(
        proposal=proposal,
        runner=runner,
        secret=b"local-consent-secret-123",
        consent_broker=_broker(),
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

    result = route.approve()

    assert isinstance(result, RepairExecutionReceipt)
    assert not hasattr(result, "runner_result")
    assert result.proposal_id == proposal.proposal_id
    assert result.proposal_digest == proposal.digest()
    assert result.execution_id == runner.execution_ids[0]
    assert len(runner.calls) == 1
    assert len(runner.execution_ids) == 1
    _, token, state_version, plan_version, _, _, now = runner.calls[0]
    assert result.token_id == token.token_id
    assert token.reviewer_id.startswith("human:windows_")
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
        route.approve()
    field_name = "execution_id"
    with pytest.raises(AttributeError):
        setattr(result, field_name, "forged")


def test_changed_binding_never_calls_runner(tmp_path: Path) -> None:
    proposal = _proposal()
    runner = RecordingRunner()
    route = RepairApprovalRoute(
        proposal=proposal,
        runner=runner,
        secret=b"local-consent-secret-123",
        consent_broker=_broker(),
        current_binding=lambda: (5, "proxy-plan-1"),
        approval_repository=_repository(proposal, tmp_path / "changed"),
        clock=lambda: NOW,
    )
    with pytest.raises(ActionAuthorizationError, match="binding"):
        route.approve()
    assert runner.calls == []


def test_expired_or_cancelled_review_never_calls_runner(tmp_path: Path) -> None:
    proposal = _proposal()
    runner = RecordingRunner()
    expired = RepairApprovalRoute(
        proposal=proposal,
        runner=runner,
        secret=b"local-consent-secret-123",
        consent_broker=_broker(),
        current_binding=lambda: (4, "proxy-plan-1"),
        approval_repository=_repository(proposal, tmp_path),
        clock=lambda: NOW + timedelta(minutes=5),
    )
    with pytest.raises(ActionAuthorizationError, match="expired"):
        expired.approve()
    route = _route(proposal, runner, tmp_path / "cancelled")
    route.cancel()
    with pytest.raises(ActionAuthorizationError, match="cancelled"):
        route.approve()
    assert runner.calls == []


def test_cancellation_acknowledgment_is_atomic_with_write_gate(tmp_path: Path) -> None:
    proposal = _proposal()
    runner = RecordingRunner()
    route = _route(proposal, runner, tmp_path)
    route.approve()
    _, _, _, _, cancelled, write_permitted, _ = runner.calls[0]

    assert route.cancel() is CancellationDisposition.ACCEPTED_BEFORE_WRITE
    assert cancelled()
    assert not write_permitted()

    later_runner = RecordingRunner()
    later_route = _route(proposal, later_runner, tmp_path / "later")
    later_route.approve()
    assert later_runner.calls[0][5]()
    assert later_route.cancel() is CancellationDisposition.TOO_LATE_TO_PREVENT_WRITE


def test_wrong_windows_sid_does_not_consume_durable_review(tmp_path: Path) -> None:
    proposal = _proposal()
    runner = RecordingRunner()
    repo = _repository(proposal, tmp_path)
    route = RepairApprovalRoute(
        proposal=proposal,
        runner=runner,
        secret=b"local-consent-secret-123",
        consent_broker=_broker(
            identity=lambda: WindowsPrincipal("S-1-5-21-1000-2000-3000-9999", 42, 3)
        ),
        current_binding=lambda: (4, "proxy-plan-1"),
        approval_repository=repo,
        clock=lambda: NOW,
    )
    with pytest.raises(ActionAuthorizationError, match="does not own"):
        route.approve()
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
        consent_broker=_broker(),
        current_binding=lambda: (4, "proxy-plan-1"),
        approval_repository=repo,
        clock=lambda: NOW,
    )
    first_route.approve()

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
        consent_broker=_broker(),
        current_binding=lambda: (4, "proxy-plan-1"),
        approval_repository=repo,
        clock=lambda: NOW,
    )
    with pytest.raises(ActionAuthorizationError, match="target reserved"):
        second_route.approve()
    assert second_runner.calls == []
    with SQLiteStore(tmp_path / "cases.db") as store:
        assert store.connection.execute(
            "SELECT COUNT(*) FROM repair_approval_claims WHERE proposal_id=?",
            (second.proposal_id,),
        ).fetchone() == (0,)
