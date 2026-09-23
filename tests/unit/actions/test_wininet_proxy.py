"""Executable repair boundary tested against an in-memory user-proxy backend."""

import hashlib
import sqlite3
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from threading import Event

import pytest

from systemsense.actions.contracts import (
    ActionAuthorizationError,
    ActionCode,
    ActionGate,
    ActionKind,
    ActionOperation,
    AuthorizationAuthority,
    AuthorizationToken,
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
from systemsense.actions.wininet_proxy import (
    ConnectivityObservation,
    ConnectivityVerdict,
    ProxyRepairJournal,
    ProxyRepairOutcome,
    ProxyRepairRunner,
    ProxyState,
)
from systemsense.domain.ids import CaseId, EvidenceId, TargetId

NOW = datetime(2026, 9, 22, 12, tzinfo=UTC)
SID = "S-1-5-21-1000-2000-3000-1001"


class FakeProxyBackend:
    def __init__(self, *, sid: str = SID) -> None:
        self.sid = sid
        self.enabled = True
        self.server = "bad.example:8080"
        self.writes = 0
        self.reads = 0
        self.stale = False

    def current_user_sid(self) -> str:
        return self.sid

    def read(self) -> ProxyState:
        self.reads += 1
        return ProxyState(
            user_sid=self.sid,
            enabled=self.enabled,
            server=self.server,
            observed_at=NOW - timedelta(minutes=10)
            if self.stale
            else NOW + timedelta(milliseconds=self.reads),
        )

    def set_enabled(self, value: bool) -> None:
        self.enabled = value
        self.writes += 1


class FakeConnectivityOracle:
    def __init__(
        self,
        backend: FakeProxyBackend,
        *,
        improve: bool = True,
        path: str = "wininet_current_user",
        destination_scope: str = "external",
        stale: bool = False,
        direct_healthy: bool = True,
        before_verdict: ConnectivityVerdict = ConnectivityVerdict.WININET_CONNECTIVITY_FAILURE,
    ) -> None:
        self.backend = backend
        self.improve = improve
        self.path = path
        self.destination_scope = destination_scope
        self.stale = stale
        self.direct_healthy = direct_healthy
        self.before_verdict = before_verdict
        self.checks = 0
        self.direct_checks = 0

    def supports(self, check_id: str) -> bool:
        return check_id == "known-endpoint"

    def check(self, check_id: str) -> ConnectivityObservation:
        self.checks += 1
        return ConnectivityObservation(
            check_id=check_id,
            passed=self.improve and not self.backend.enabled,
            observed_at=(
                NOW - timedelta(minutes=10) + timedelta(seconds=self.checks)
                if self.stale
                else NOW + timedelta(seconds=self.checks)
            ),
            evidence_id=EvidenceId.new(),
            path=self.path,
            destination_scope=self.destination_scope,
            verdict=(
                ConnectivityVerdict.EXPECTED_204
                if self.improve and not self.backend.enabled
                else self.before_verdict
            ),
        )

    def check_direct_control(self, check_id: str) -> ConnectivityObservation:
        self.direct_checks += 1
        return ConnectivityObservation(
            check_id=check_id,
            passed=self.direct_healthy,
            observed_at=NOW + timedelta(seconds=self.checks + self.direct_checks),
            evidence_id=EvidenceId.new(),
            path="wininet_direct_control",
            destination_scope="external",
            verdict=(
                ConnectivityVerdict.EXPECTED_204
                if self.direct_healthy
                else ConnectivityVerdict.UNAVAILABLE
            ),
        )


def _proposal(*, sid: str = SID, rollback_without_consent: bool = True) -> RepairProposal:
    target = ExactTarget(
        target_id=TargetId.new(),
        kind=TargetKind.WININET_USER_PROXY,
        locator=f"wininet_proxy:{sid}",
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
                parameters=(
                    OperationParameter(name="expected_proxy_enabled", value=True),
                    OperationParameter(name="expected_proxy_server", value="bad.example:8080"),
                    OperationParameter(name="new_proxy_enabled", value=False),
                    OperationParameter(name="new_proxy_server", value="bad.example:8080"),
                    OperationParameter(name="connectivity_check_id", value="known-endpoint"),
                ),
            ),
        ),
        preconditions=(Precondition(code=PreconditionCode.TARGET_VERSION_MATCHES, target=target),),
        expected_effect=ExpectedEffect(
            summary="Restore connectivity by disabling the exact user proxy",
            success_indicators=("known endpoint reachable",),
        ),
        risk=ProposalRisk(
            level=RiskLevel.MODERATE,
            disruption=DisruptionLevel.NETWORK_INTERRUPTION,
            summary="The current user's proxy configuration changes",
        ),
        verification=VerificationPlan(
            checks=(VerificationCheck(code="connectivity_restored"),),
        ),
        rollback=RollbackLimits(
            supported=True,
            max_attempts=1,
            limits="Restore ProxyEnable only when ProxyServer remains unchanged",
            requires_new_consent=not rollback_without_consent,
        ),
    )


def _token(proposal: RepairProposal) -> AuthorizationToken:
    consent = HumanConsent(
        reviewer_id="human:reviewer-1",
        consent_reference="consent_proxy_1",
        case_id=proposal.case_id,
        case_state_version=proposal.case_state_version,
        plan_version=proposal.plan_version,
        proposal_digest=proposal.digest(),
        operation_digests=proposal.operation_digests(),
        expires_at=NOW + timedelta(minutes=5),
        reviewed=True,
    )
    return AuthorizationAuthority(secret=b"test-secret-12345").issue(
        proposal, consent=consent, issued_at=NOW
    )


def _runner(
    tmp_path: Path,
    backend: FakeProxyBackend,
    oracle: FakeConnectivityOracle,
    *,
    clock: Callable[[], datetime] | None = None,
    current_binding: Callable[[], tuple[int, str]] | None = None,
) -> ProxyRepairRunner:
    return ProxyRepairRunner(
        gate=ActionGate(secret=b"test-secret-12345"),
        journal=ProxyRepairJournal(tmp_path / "action-journal.db"),
        backend=backend,
        oracle=oracle,
        clock=clock or (lambda: NOW + timedelta(seconds=2)),
        current_binding=current_binding or (lambda: (4, "proxy-plan-1")),
    )


def test_cancelled_before_probe_consumes_token_without_reads_or_writes(tmp_path: Path) -> None:
    backend = FakeProxyBackend()
    oracle = FakeConnectivityOracle(backend)
    runner = _runner(tmp_path, backend, oracle)
    action = _proposal()
    token = _token(action)

    result = runner.execute(
        action,
        token,
        state_version=4,
        plan_version="proxy-plan-1",
        now=NOW,
        cancelled=lambda: True,
    )

    assert result.outcome is ProxyRepairOutcome.CANCELLED
    assert backend.reads == backend.writes == 0
    assert runner.journal.status(token.token_id) == "cancelled"
    with pytest.raises(ActionAuthorizationError, match="already consumed"):
        runner.execute(action, token, state_version=4, plan_version="proxy-plan-1", now=NOW)


def test_cancelled_after_control_check_consumes_token_without_write(tmp_path: Path) -> None:
    backend = FakeProxyBackend()
    oracle = FakeConnectivityOracle(backend)
    runner = _runner(tmp_path, backend, oracle)
    action = _proposal()
    token = _token(action)
    cancelled = False
    original_control = oracle.check_direct_control

    def control_and_cancel(check_id: str) -> ConnectivityObservation:
        nonlocal cancelled
        result = original_control(check_id)
        cancelled = True
        return result

    oracle.check_direct_control = control_and_cancel  # type: ignore[method-assign]
    result = runner.execute(
        action,
        token,
        state_version=4,
        plan_version="proxy-plan-1",
        now=NOW,
        cancelled=lambda: cancelled,
    )

    assert result.outcome is ProxyRepairOutcome.CANCELLED
    assert backend.writes == 0
    assert runner.journal.status(token.token_id) == "cancelled"
    with pytest.raises(ActionAuthorizationError, match="already consumed"):
        runner.execute(action, token, state_version=4, plan_version="proxy-plan-1", now=NOW)


def test_cancellation_during_blocking_oracle_stops_before_write(tmp_path: Path) -> None:
    backend = FakeProxyBackend()
    oracle = FakeConnectivityOracle(backend)
    runner = _runner(tmp_path, backend, oracle)
    action = _proposal()
    token = _token(action)
    entered = Event()
    release = Event()
    cancelled = Event()
    original_control = oracle.check_direct_control

    def blocking_control(check_id: str) -> ConnectivityObservation:
        entered.set()
        assert release.wait(5)
        return original_control(check_id)

    oracle.check_direct_control = blocking_control  # type: ignore[method-assign]
    with ThreadPoolExecutor(max_workers=1) as pool:
        future = pool.submit(
            runner.execute,
            action,
            token,
            state_version=4,
            plan_version="proxy-plan-1",
            now=NOW,
            cancelled=cancelled.is_set,
        )
        assert entered.wait(5)
        assert runner.journal.status(token.token_id) == "claimed"
        cancelled.set()
        release.set()
        result = future.result(timeout=5)

    assert result.outcome is ProxyRepairOutcome.CANCELLED
    assert backend.writes == 0
    assert runner.journal.status(token.token_id) == "cancelled"


def test_cancellation_after_applying_is_uncertain_and_never_writes(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    backend = FakeProxyBackend()
    oracle = FakeConnectivityOracle(backend)
    runner = _runner(tmp_path, backend, oracle)
    action = _proposal()
    token = _token(action)
    cancelled = False
    original_transition = runner.journal.transition

    def transition(
        token_id: str,
        state: str,
        *,
        before_evidence_id: EvidenceId | None = None,
        after_evidence_id: EvidenceId | None = None,
        control_evidence_id: EvidenceId | None = None,
    ) -> None:
        nonlocal cancelled
        original_transition(
            token_id,
            state,
            before_evidence_id=before_evidence_id,
            after_evidence_id=after_evidence_id,
            control_evidence_id=control_evidence_id,
        )
        if state == "applying":
            cancelled = True

    monkeypatch.setattr(runner.journal, "transition", transition)
    result = runner.execute(
        action,
        token,
        state_version=4,
        plan_version="proxy-plan-1",
        now=NOW,
        cancelled=lambda: cancelled,
    )

    assert result.outcome is ProxyRepairOutcome.UNCERTAIN
    assert backend.writes == 0
    assert runner.journal.status(token.token_id) == "uncertain"


def test_route_write_barrier_rejects_cancel_race_after_final_poll(tmp_path: Path) -> None:
    backend = FakeProxyBackend()
    action = _proposal()
    token = _token(action)
    runner = _runner(tmp_path, backend, FakeConnectivityOracle(backend))
    barrier_calls = 0

    def denied_barrier() -> bool:
        nonlocal barrier_calls
        barrier_calls += 1
        return False

    result = runner.execute(
        action,
        token,
        state_version=4,
        plan_version="proxy-plan-1",
        now=NOW,
        cancelled=lambda: False,
        write_permitted=denied_barrier,
    )

    assert barrier_calls == 1
    assert result.outcome is ProxyRepairOutcome.UNCERTAIN
    assert backend.writes == 0
    assert runner.journal.status(token.token_id) == "uncertain"


def test_exact_consented_proxy_change_requires_independent_improvement(tmp_path: Path) -> None:
    backend = FakeProxyBackend()
    action = _proposal()
    oracle = FakeConnectivityOracle(backend)
    runner = _runner(tmp_path, backend, oracle)
    token = _token(action)
    result = runner.execute(action, token, state_version=4, plan_version="proxy-plan-1", now=NOW)
    assert result.outcome is ProxyRepairOutcome.VERIFIED
    assert result.before_evidence_id != result.after_evidence_id
    assert result.control_evidence_id != result.before_evidence_id
    assert result.control_evidence_id != result.after_evidence_id
    assert backend.enabled is False
    assert backend.server == "bad.example:8080"
    assert backend.writes == 1
    assert oracle.direct_checks == 1
    journal = ProxyRepairJournal(tmp_path / "action-journal.db")
    record = journal.record(token.token_id)
    assert record is not None
    assert record.state == "verified"
    assert record.proposal_digest == action.digest()
    assert record.reviewer_id == "human:reviewer-1"
    assert record.consent_reference == "consent_proxy_1"
    assert record.before_evidence_id == result.before_evidence_id
    assert record.after_evidence_id == result.after_evidence_id
    assert record.control_evidence_id == result.control_evidence_id
    assert record.case_id == action.case_id
    assert record.target_digest == hashlib.sha256(f"wininet_proxy:{SID}".encode()).hexdigest()
    assert record.authorization_digest == hashlib.sha256(token.signature.encode()).hexdigest()
    assert record.updated_at >= NOW


def test_failed_direct_control_prevents_proxy_write(tmp_path: Path) -> None:
    backend = FakeProxyBackend()
    oracle = FakeConnectivityOracle(backend, direct_healthy=False)
    runner = _runner(tmp_path, backend, oracle)
    action = _proposal()
    result = runner.execute(
        action, _token(action), state_version=4, plan_version="proxy-plan-1", now=NOW
    )
    assert result.outcome is ProxyRepairOutcome.PRECONDITION_FAILED
    assert backend.writes == 0
    assert oracle.direct_checks == 1


@pytest.mark.parametrize(
    "verdict",
    (ConnectivityVerdict.UNAVAILABLE, ConnectivityVerdict.UNEXPECTED_HTTP),
)
def test_unmeasured_affected_failure_never_authorizes_write(
    tmp_path: Path, verdict: ConnectivityVerdict
) -> None:
    backend = FakeProxyBackend()
    oracle = FakeConnectivityOracle(backend, before_verdict=verdict)
    action = _proposal()
    result = _runner(tmp_path, backend, oracle).execute(
        action, _token(action), state_version=4, plan_version="proxy-plan-1", now=NOW
    )
    assert result.outcome is ProxyRepairOutcome.PRECONDITION_FAILED
    assert backend.writes == 0
    assert oracle.direct_checks == 0


def test_unavailable_direct_control_prevents_proxy_write(tmp_path: Path) -> None:
    class UnavailableOracle(FakeConnectivityOracle):
        def check_direct_control(self, check_id: str) -> ConnectivityObservation:
            raise RuntimeError("direct-path transport unavailable")

    backend = FakeProxyBackend()
    runner = _runner(tmp_path, backend, UnavailableOracle(backend))
    action = _proposal()
    result = runner.execute(
        action, _token(action), state_version=4, plan_version="proxy-plan-1", now=NOW
    )
    assert result.outcome is ProxyRepairOutcome.PRECONDITION_FAILED
    assert backend.writes == 0


@pytest.mark.parametrize(
    "alteration",
    ("wrong_path", "wrong_destination", "wrong_check", "stale", "reused_evidence"),
)
def test_mismatched_direct_control_cannot_authorize_write(tmp_path: Path, alteration: str) -> None:
    class MismatchedControl(FakeConnectivityOracle):
        def __init__(self, backend: FakeProxyBackend) -> None:
            super().__init__(backend)
            self.before_id: EvidenceId | None = None

        def check(self, check_id: str) -> ConnectivityObservation:
            observed = super().check(check_id)
            self.before_id = observed.evidence_id
            return observed

        def check_direct_control(self, check_id: str) -> ConnectivityObservation:
            observed = super().check_direct_control(check_id)
            if alteration == "wrong_path":
                return replace(observed, path="wininet_current_user")
            if alteration == "wrong_destination":
                return replace(observed, destination_scope="loopback")
            if alteration == "wrong_check":
                return replace(observed, check_id="other-endpoint")
            if alteration == "stale":
                return replace(observed, observed_at=NOW - timedelta(minutes=2))
            assert self.before_id is not None
            return replace(observed, evidence_id=self.before_id)

    backend = FakeProxyBackend()
    runner = _runner(tmp_path, backend, MismatchedControl(backend))
    action = _proposal()
    result = runner.execute(
        action, _token(action), state_version=4, plan_version="proxy-plan-1", now=NOW
    )
    assert result.outcome is ProxyRepairOutcome.PRECONDITION_FAILED
    assert backend.writes == 0


def test_token_is_single_use_across_runner_instances(tmp_path: Path) -> None:
    backend = FakeProxyBackend()
    action = _proposal()
    token = _token(action)
    first = _runner(tmp_path, backend, FakeConnectivityOracle(backend))
    first.execute(action, token, state_version=4, plan_version="proxy-plan-1", now=NOW)
    second = _runner(tmp_path, backend, FakeConnectivityOracle(backend))
    with pytest.raises(ValueError, match="already consumed"):
        second.execute(action, token, state_version=4, plan_version="proxy-plan-1", now=NOW)
    assert backend.writes == 1


def test_legacy_journal_migration_does_not_invent_action_binding(tmp_path: Path) -> None:
    path = tmp_path / "legacy-action-journal.db"
    with sqlite3.connect(path) as db:
        db.execute(
            "CREATE TABLE proxy_repairs ("
            "token_id TEXT PRIMARY KEY, proposal_digest TEXT NOT NULL, "
            "target_hash TEXT NOT NULL, state TEXT NOT NULL, updated_at TEXT NOT NULL, "
            "before_evidence_id TEXT, after_evidence_id TEXT, "
            "reviewer_id TEXT, consent_reference TEXT)"
        )
        db.execute(
            "INSERT INTO proxy_repairs VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                "token_legacy",
                "a" * 64,
                "b" * 64,
                "uncertain",
                NOW.isoformat(),
                None,
                None,
                "human:legacy",
                "consent_legacy",
            ),
        )

    record = ProxyRepairJournal(path).record("token_legacy")

    assert record is not None
    assert record.state == "uncertain"
    assert record.case_id is None
    assert record.authorization_digest is None
    assert record.control_evidence_id is None


def test_independent_journal_lookup_binds_verified_action_to_case(tmp_path: Path) -> None:
    from benchmarks.wininet_journal_proof import prove_wininet_action

    backend = FakeProxyBackend()
    action = _proposal()
    token = _token(action)
    runner = _runner(tmp_path, backend, FakeConnectivityOracle(backend))
    result = runner.execute(action, token, state_version=4, plan_version="proxy-plan-1", now=NOW)
    journal = ProxyRepairJournal(tmp_path / "action-journal.db")

    proof = prove_wininet_action(journal, str(action.case_id), token.token_id)

    assert result.outcome is ProxyRepairOutcome.VERIFIED
    assert proof is not None
    assert proof.case_id == str(action.case_id)
    assert proof.action_execution_id == token.token_id
    assert proof.proposal_digest == action.digest()
    assert proof.authorization_digest == hashlib.sha256(token.signature.encode()).hexdigest()
    assert proof.target_digest == hashlib.sha256(f"wininet_proxy:{SID}".encode()).hexdigest()
    assert proof.terminal_outcome == "verified"
    assert prove_wininet_action(journal, str(CaseId.new()), token.token_id) is None


def test_live_proxy_mismatch_never_writes(tmp_path: Path) -> None:
    backend = FakeProxyBackend()
    backend.server = "different.example:8080"
    action = _proposal()
    runner = _runner(tmp_path, backend, FakeConnectivityOracle(backend))
    result = runner.execute(
        action, _token(action), state_version=4, plan_version="proxy-plan-1", now=NOW
    )
    assert result.outcome is ProxyRepairOutcome.PRECONDITION_FAILED
    assert backend.writes == 0


def test_wrong_user_sid_never_writes(tmp_path: Path) -> None:
    backend = FakeProxyBackend(sid="S-1-5-21-9000-9000-9000-1001")
    action = _proposal()
    runner = _runner(tmp_path, backend, FakeConnectivityOracle(backend))
    result = runner.execute(
        action, _token(action), state_version=4, plan_version="proxy-plan-1", now=NOW
    )
    assert result.outcome is ProxyRepairOutcome.PRECONDITION_FAILED
    assert backend.writes == 0


def test_no_connectivity_improvement_restores_prior_value_when_consented(tmp_path: Path) -> None:
    backend = FakeProxyBackend()
    action = _proposal()
    runner = _runner(tmp_path, backend, FakeConnectivityOracle(backend, improve=False))
    result = runner.execute(
        action, _token(action), state_version=4, plan_version="proxy-plan-1", now=NOW
    )
    assert result.outcome is ProxyRepairOutcome.ROLLED_BACK
    assert backend.enabled is True
    assert backend.server == "bad.example:8080"
    assert backend.writes == 2


@pytest.mark.parametrize(
    ("path", "destination"),
    [
        ("winhttp_service", "external"),
        ("wininet_current_user", "loopback"),
    ],
)
def test_unaffected_connection_check_cannot_authorize_proxy_change(
    tmp_path: Path, path: str, destination: str
) -> None:
    backend = FakeProxyBackend()
    action = _proposal()
    oracle = FakeConnectivityOracle(backend, path=path, destination_scope=destination)
    runner = _runner(tmp_path, backend, oracle)
    result = runner.execute(
        action, _token(action), state_version=4, plan_version="proxy-plan-1", now=NOW
    )
    assert result.outcome is ProxyRepairOutcome.PRECONDITION_FAILED
    assert backend.writes == 0


def test_unknown_write_result_is_not_replayed_or_unlocked(tmp_path: Path) -> None:
    from benchmarks.wininet_journal_proof import prove_wininet_action

    class UncertainBackend(FakeProxyBackend):
        def set_enabled(self, value: bool) -> None:
            super().set_enabled(value)
            raise OSError("notification outcome unknown")

    backend = UncertainBackend()
    action = _proposal()
    token = _token(action)
    runner = _runner(tmp_path, backend, FakeConnectivityOracle(backend))
    result = runner.execute(action, token, state_version=4, plan_version="proxy-plan-1", now=NOW)
    assert result.outcome is ProxyRepairOutcome.UNCERTAIN
    assert backend.writes == 1
    assert prove_wininet_action(runner.journal, str(action.case_id), token.token_id) is None
    second = _proposal()
    with pytest.raises(ValueError, match="unresolved"):
        runner.execute(
            second, _token(second), state_version=4, plan_version="proxy-plan-1", now=NOW
        )
    assert backend.writes == 1


def test_stale_live_precondition_never_writes(tmp_path: Path) -> None:
    backend = FakeProxyBackend()
    backend.stale = True
    action = _proposal()
    runner = _runner(tmp_path, backend, FakeConnectivityOracle(backend))
    result = runner.execute(
        action, _token(action), state_version=4, plan_version="proxy-plan-1", now=NOW
    )
    assert result.outcome is ProxyRepairOutcome.PRECONDITION_FAILED
    assert backend.writes == 0


def test_uncertain_journal_entry_cannot_be_promoted_to_verified(tmp_path: Path) -> None:
    journal = ProxyRepairJournal(tmp_path / "journal.db")
    action = _proposal()
    token = _token(action)
    journal.claim(token, action.digest(), f"wininet_proxy:{SID}", NOW)
    journal.transition(token.token_id, "applying")
    journal.transition(token.token_id, "uncertain")
    with pytest.raises(ValueError, match="transition"):
        journal.transition(
            token.token_id,
            "verified",
            before_evidence_id=EvidenceId.new(),
            after_evidence_id=EvidenceId.new(),
            control_evidence_id=EvidenceId.new(),
        )
    assert journal.status(token.token_id) == "uncertain"


def test_stale_connectivity_result_never_authorizes_write(tmp_path: Path) -> None:
    backend = FakeProxyBackend()
    action = _proposal()
    runner = _runner(tmp_path, backend, FakeConnectivityOracle(backend, stale=True))
    result = runner.execute(
        action, _token(action), state_version=4, plan_version="proxy-plan-1", now=NOW
    )
    assert result.outcome is ProxyRepairOutcome.PRECONDITION_FAILED
    assert backend.writes == 0


def test_oracle_delay_expiring_consent_cannot_write(tmp_path: Path) -> None:
    backend = FakeProxyBackend()
    current = [NOW]

    class SlowOracle(FakeConnectivityOracle):
        def check(self, check_id: str) -> ConnectivityObservation:
            current[0] = NOW + timedelta(minutes=6)
            return super().check(check_id)

    action = _proposal()
    runner = _runner(tmp_path, backend, SlowOracle(backend), clock=lambda: current[0])
    result = runner.execute(
        action, _token(action), state_version=4, plan_version="proxy-plan-1", now=NOW
    )
    assert result.outcome is ProxyRepairOutcome.PRECONDITION_FAILED
    assert backend.writes == 0


def test_oracle_change_to_proxy_prevents_stale_write(tmp_path: Path) -> None:
    backend = FakeProxyBackend()

    class ChangingOracle(FakeConnectivityOracle):
        def check(self, check_id: str) -> ConnectivityObservation:
            backend.server = "another.example:8080"
            return super().check(check_id)

    action = _proposal()
    runner = _runner(tmp_path, backend, ChangingOracle(backend))
    result = runner.execute(
        action, _token(action), state_version=4, plan_version="proxy-plan-1", now=NOW
    )
    assert result.outcome is ProxyRepairOutcome.PRECONDITION_FAILED
    assert backend.writes == 0


def test_slow_fresh_read_expiring_consent_cannot_write(tmp_path: Path) -> None:
    current = [NOW]

    class SlowReadBackend(FakeProxyBackend):
        def read(self) -> ProxyState:
            state = super().read()
            if self.reads == 2:
                current[0] = NOW + timedelta(minutes=6)
            return state

    backend = SlowReadBackend()
    action = _proposal()
    runner = _runner(tmp_path, backend, FakeConnectivityOracle(backend), clock=lambda: current[0])
    result = runner.execute(
        action, _token(action), state_version=4, plan_version="proxy-plan-1", now=NOW
    )
    assert result.outcome is ProxyRepairOutcome.PRECONDITION_FAILED
    assert backend.writes == 0


def test_slow_oracle_stale_symptom_cannot_authorize_write(tmp_path: Path) -> None:
    current = [NOW]

    class FreshReadBackend(FakeProxyBackend):
        def read(self) -> ProxyState:
            state = super().read()
            return ProxyState(
                state.user_sid,
                state.enabled,
                state.server,
                current[0] + timedelta(milliseconds=self.reads),
            )

    class SlowOracle(FakeConnectivityOracle):
        def check(self, check_id: str) -> ConnectivityObservation:
            observation = super().check(check_id)
            current[0] = NOW + timedelta(seconds=30)
            return observation

    backend = FreshReadBackend()
    action = _proposal()
    runner = _runner(tmp_path, backend, SlowOracle(backend), clock=lambda: current[0])
    result = runner.execute(
        action, _token(action), state_version=4, plan_version="proxy-plan-1", now=NOW
    )
    assert result.outcome is ProxyRepairOutcome.PRECONDITION_FAILED
    assert backend.writes == 0


def test_concurrent_proxy_change_during_final_check_is_not_verified(tmp_path: Path) -> None:
    backend = FakeProxyBackend()

    class ChangingAfterOracle(FakeConnectivityOracle):
        def check(self, check_id: str) -> ConnectivityObservation:
            observation = super().check(check_id)
            if self.checks == 2:
                backend.server = "someone-else.example:8080"
            return observation

    action = _proposal()
    runner = _runner(tmp_path, backend, ChangingAfterOracle(backend))
    result = runner.execute(
        action, _token(action), state_version=4, plan_version="proxy-plan-1", now=NOW
    )
    assert result.outcome is ProxyRepairOutcome.UNCERTAIN
    assert backend.writes == 1


def test_rollback_result_checks_current_user_identity(tmp_path: Path) -> None:
    class ChangingUserBackend(FakeProxyBackend):
        def set_enabled(self, value: bool) -> None:
            super().set_enabled(value)
            if value:
                self.sid = "S-1-5-21-9000-9000-9000-1001"

    backend = ChangingUserBackend()
    action = _proposal()
    runner = _runner(tmp_path, backend, FakeConnectivityOracle(backend, improve=False))
    result = runner.execute(
        action, _token(action), state_version=4, plan_version="proxy-plan-1", now=NOW
    )
    assert result.outcome is ProxyRepairOutcome.UNCERTAIN


def test_user_switch_between_rollback_read_and_write_prevents_restore(tmp_path: Path) -> None:
    class SwitchingUserBackend(FakeProxyBackend):
        def read(self) -> ProxyState:
            state = super().read()
            if self.reads == 4:
                self.sid = "S-1-5-21-9000-9000-9000-1001"
            return state

    backend = SwitchingUserBackend()
    action = _proposal()
    runner = _runner(tmp_path, backend, FakeConnectivityOracle(backend, improve=False))
    result = runner.execute(
        action, _token(action), state_version=4, plan_version="proxy-plan-1", now=NOW
    )
    assert result.outcome is ProxyRepairOutcome.UNCERTAIN
    assert backend.writes == 1


def test_case_binding_change_during_oracle_prevents_write(tmp_path: Path) -> None:
    backend = FakeProxyBackend()
    version = [4]

    class ChangingBindingOracle(FakeConnectivityOracle):
        def check(self, check_id: str) -> ConnectivityObservation:
            version[0] = 5
            return super().check(check_id)

    action = _proposal()
    runner = _runner(
        tmp_path,
        backend,
        ChangingBindingOracle(backend),
        current_binding=lambda: (version[0], "proxy-plan-1"),
    )
    result = runner.execute(
        action, _token(action), state_version=4, plan_version="proxy-plan-1", now=NOW
    )
    assert result.outcome is ProxyRepairOutcome.PRECONDITION_FAILED
    assert backend.writes == 0


@pytest.mark.parametrize(
    ("enabled", "expected"),
    [(True, "original_observed"), (False, "intended_observed")],
)
def test_interrupted_proxy_inspection_never_replays_or_unlocks(
    tmp_path: Path, enabled: bool, expected: str
) -> None:
    backend = FakeProxyBackend()
    action = _proposal()
    token = _token(action)
    journal = ProxyRepairJournal(tmp_path / "action-journal.db", clock=lambda: NOW)
    journal.claim(token, action.digest(), action.operations[0].target.locator, NOW)
    journal.transition(
        token.token_id,
        "applying",
        before_evidence_id=EvidenceId.new(),
        control_evidence_id=EvidenceId.new(),
    )
    backend.enabled = enabled

    assessment = _runner(tmp_path, backend, FakeConnectivityOracle(backend)).inspect_interrupted(
        action, token.token_id, now=NOW
    )

    assert assessment.disposition.value == expected
    assert assessment.journal_state == "applying"
    assert backend.writes == 0
    assert journal.status(token.token_id) == "applying"
    with pytest.raises(ActionAuthorizationError):
        journal.claim(_token(action), action.digest(), action.operations[0].target.locator, NOW)


def test_interrupted_inspection_rejects_cross_case_proposal(tmp_path: Path) -> None:
    backend = FakeProxyBackend()
    action = _proposal()
    token = _token(action)
    journal = ProxyRepairJournal(tmp_path / "action-journal.db", clock=lambda: NOW)
    journal.claim(token, action.digest(), action.operations[0].target.locator, NOW)
    journal.transition(
        token.token_id,
        "applying",
        before_evidence_id=EvidenceId.new(),
        control_evidence_id=EvidenceId.new(),
    )
    with pytest.raises(ActionAuthorizationError, match="binding"):
        _runner(tmp_path, backend, FakeConnectivityOracle(backend)).inspect_interrupted(
            _proposal(), token.token_id, now=NOW
        )
    assert backend.reads == backend.writes == 0
    assert journal.status(token.token_id) == "applying"


@pytest.mark.parametrize(
    ("journal_state", "server", "stale", "expected"),
    [
        ("claimed", "bad.example:8080", False, "claimed_pending"),
        ("applying", "other.example:8080", False, "diverged"),
        ("applying", "bad.example:8080", True, "unavailable"),
    ],
)
def test_interrupted_inspection_reports_uncertainty_without_mutation(
    tmp_path: Path, journal_state: str, server: str, stale: bool, expected: str
) -> None:
    backend = FakeProxyBackend()
    backend.server = server
    backend.stale = stale
    action = _proposal()
    token = _token(action)
    journal = ProxyRepairJournal(tmp_path / "action-journal.db", clock=lambda: NOW)
    journal.claim(token, action.digest(), action.operations[0].target.locator, NOW)
    if journal_state == "applying":
        journal.transition(
            token.token_id,
            "applying",
            before_evidence_id=EvidenceId.new(),
            control_evidence_id=EvidenceId.new(),
        )
    assessment = _runner(tmp_path, backend, FakeConnectivityOracle(backend)).inspect_interrupted(
        action, token.token_id, now=NOW
    )
    assert assessment.disposition.value == expected
    assert backend.writes == 0
    assert journal.status(token.token_id) == journal_state


def test_interrupted_inspection_rejects_invalid_snapshot_time(tmp_path: Path) -> None:
    class InvalidTimeBackend(FakeProxyBackend):
        def read(self) -> ProxyState:
            self.reads += 1
            return ProxyState(SID, True, self.server, datetime(2026, 9, 22, 12))

    backend = InvalidTimeBackend()
    action = _proposal()
    token = _token(action)
    journal = ProxyRepairJournal(tmp_path / "action-journal.db", clock=lambda: NOW)
    journal.claim(token, action.digest(), action.operations[0].target.locator, NOW)
    journal.transition(
        token.token_id,
        "applying",
        before_evidence_id=EvidenceId.new(),
        control_evidence_id=EvidenceId.new(),
    )
    assessment = _runner(tmp_path, backend, FakeConnectivityOracle(backend)).inspect_interrupted(
        action, token.token_id, now=NOW
    )
    assert assessment.disposition.value == "unavailable"
    assert journal.status(token.token_id) == "applying"
    assert backend.writes == 0


def test_interrupted_inspection_rejects_non_boolean_state(tmp_path: Path) -> None:
    class InvalidFlagBackend(FakeProxyBackend):
        def read(self) -> ProxyState:
            self.reads += 1
            return ProxyState(SID, 1, self.server, NOW)  # type: ignore[arg-type]

    backend = InvalidFlagBackend()
    action = _proposal()
    token = _token(action)
    journal = ProxyRepairJournal(tmp_path / "action-journal.db", clock=lambda: NOW)
    journal.claim(token, action.digest(), action.operations[0].target.locator, NOW)
    journal.transition(
        token.token_id,
        "applying",
        before_evidence_id=EvidenceId.new(),
        control_evidence_id=EvidenceId.new(),
    )
    assessment = _runner(tmp_path, backend, FakeConnectivityOracle(backend)).inspect_interrupted(
        action, token.token_id, now=NOW
    )
    assert assessment.disposition.value == "unavailable"
    assert journal.status(token.token_id) == "applying"
    assert backend.writes == 0


def test_interrupted_inspection_rejects_snapshot_from_before_applying(tmp_path: Path) -> None:
    backend = FakeProxyBackend()
    action = _proposal()
    token = _token(action)
    journal = ProxyRepairJournal(
        tmp_path / "action-journal.db", clock=lambda: NOW + timedelta(seconds=2)
    )
    journal.claim(token, action.digest(), action.operations[0].target.locator, NOW)
    journal.transition(
        token.token_id,
        "applying",
        before_evidence_id=EvidenceId.new(),
        control_evidence_id=EvidenceId.new(),
    )
    assessment = _runner(tmp_path, backend, FakeConnectivityOracle(backend)).inspect_interrupted(
        action, token.token_id, now=NOW + timedelta(seconds=3)
    )
    assert assessment.disposition.value == "unavailable"
    assert backend.writes == 0
    assert journal.status(token.token_id) == "applying"
