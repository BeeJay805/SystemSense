"""Independent post-stop measurements are required even after journal 'verified'."""

import hashlib
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

from systemsense.actions.contracts import (
    AuthorizationToken,
    OperationParameter,
    Precondition,
    PreconditionCode,
    RiskLevel,
    VerificationCheck,
    VerificationPlan,
)
from systemsense.actions.wininet_proxy import ConnectivityVerdict, ProxyRepairRecord
from systemsense.application.repair_reconciliation import (
    ApprovalReader,
    ConnectivityEvidence,
    EvidenceReader,
    JournalReader,
    ReconciliationAssessor,
    RegisteredCheck,
    SettingEvidence,
    StopEvidence,
    TokenReader,
)
from systemsense.domain.ids import CaseId
from systemsense.storage.repair_approvals import TerminalSetting, TerminalSymptom
from systemsense.storage.sqlite_store import SQLiteStore
from tests.unit.storage.test_repair_approvals import (
    _authorized,  # pyright: ignore[reportPrivateUsage]
    _case,  # pyright: ignore[reportPrivateUsage]
    _proposal,  # pyright: ignore[reportPrivateUsage]
    _repo,  # pyright: ignore[reportPrivateUsage]
)

NOW = datetime(2026, 9, 23, 12, tzinfo=UTC)


def test_missing_durable_execution_fails_closed() -> None:
    class MissingRepository:
        def execution(self, execution_id: str):
            assert execution_id == "execution_missing"
            return None

    class NeverCalled:
        def __getattr__(self, name: str):
            raise AssertionError(f"unexpected read: {name}")

    assessor = ReconciliationAssessor(
        approvals=cast(ApprovalReader, MissingRepository()),
        journal=cast(JournalReader, NeverCalled()),
        tokens=cast(TokenReader, NeverCalled()),
        evidence=cast(EvidenceReader, NeverCalled()),
        current_sid=lambda: "S-1-5-21-1-2-3-4",
        clock=lambda: NOW,
    )
    assessment = assessor.assess("execution_missing")
    assert assessment.setting is TerminalSetting.UNAVAILABLE
    assert assessment.symptom is TerminalSymptom.UNAVAILABLE
    assert assessment.qualified is False


def _exercise(tmp_path: Path, *, change: str = ""):
    with SQLiteStore(tmp_path / "cases.db") as store:
        case_id = _case(store)
        original = _proposal(case_id)
        operation = original.operations[0].model_copy(
            update={
                "parameters": (
                    OperationParameter(name="expected_proxy_enabled", value=True),
                    OperationParameter(name="expected_proxy_server", value="bad.example:8080"),
                    OperationParameter(name="new_proxy_enabled", value=False),
                    OperationParameter(name="new_proxy_server", value="bad.example:8080"),
                    OperationParameter(name="connectivity_check_id", value="owned_endpoint"),
                )
            }
        )
        proposal = original.model_copy(update={"operations": (operation,)})
        if change == "wrong_precondition":
            proposal = proposal.model_copy(
                update={
                    "preconditions": (Precondition(code=PreconditionCode.NO_CONCURRENT_ACTION),)
                }
            )
        if change == "wrong_verification":
            proposal = proposal.model_copy(
                update={"verification": VerificationPlan(checks=(VerificationCheck(code="other"),))}
            )
        if change == "wrong_risk":
            proposal = proposal.model_copy(
                update={"risk": proposal.risk.model_copy(update={"level": RiskLevel.HIGH})}
            )
        repo = _repo(store)
        repo.register_server_proposal(proposal, current_plan_version=proposal.plan_version)
        review = repo.claim_review(
            proposal.proposal_id, case_id=case_id, acknowledged_digest=proposal.digest()
        )
        action, verify = _authorized(proposal, review.consent_reference)
        execution = repo.promote_execution(
            review.claim_id, action=action, verify_authorization=verify
        )
        execution = repo.recheck_execution(
            execution.execution_id, action=action, verify_authorization=verify
        )
        token = action.token
        sid = operation.target.locator.split(":", 1)[1]
        endpoint_digest = "9" * 64
        before_id, control_id = "ev_" + "a" * 32, "ev_" + "b" * 32
        journal = ProxyRepairRecord(
            token_id=token.token_id,
            proposal_digest=proposal.digest(),
            reviewer_id=token.reviewer_id,
            consent_reference=review.consent_reference,
            state="verified",
            before_evidence_id=None if change == "missing_before" else _evidence_id(before_id),
            after_evidence_id=_evidence_id("ev_" + "f" * 32),
            control_evidence_id=_evidence_id(control_id),
            case_id=case_id,
            target_digest=hashlib.sha256(operation.target.locator.encode()).hexdigest(),
            authorization_digest=hashlib.sha256(token.signature.encode()).hexdigest(),
            updated_at=NOW + timedelta(seconds=1),
        )
        if change == "journal_target":
            journal = replace(journal, target_digest="0" * 64)
        if change == "journal_auth":
            journal = replace(journal, authorization_digest="0" * 64)
        if change == "journal_after_stop":
            journal = replace(journal, updated_at=NOW + timedelta(seconds=3))

        class Journal:
            def record(self, token_id: str):
                assert token_id == token.token_id
                return journal

        class Tokens:
            def get(self, token_id: str):
                return token if token_id == token.token_id else None

            def verify(self, token: AuthorizationToken) -> bool:
                return verify(token)

        check = RegisteredCheck("owned_endpoint", endpoint_digest, sid)

        class Checks:
            def resolve(self, check_id: str, user_sid: str):
                if change == "unregistered_check":
                    return None
                assert check_id == "owned_endpoint" and user_sid == sid
                return check

        def connection(
            evidence_id: str, at: int, route: str, passed: bool, verdict: ConnectivityVerdict
        ) -> ConnectivityEvidence:
            return ConnectivityEvidence(
                evidence_id,
                "1" * 64,
                NOW + timedelta(seconds=at),
                execution.execution_id,
                case_id,
                sid,
                "owned_endpoint",
                endpoint_digest,
                route,
                "external",
                verdict,
                passed,
                True,
            )

        pre_affected = connection(
            before_id,
            0,
            "wininet_current_user",
            False,
            ConnectivityVerdict.WININET_CONNECTIVITY_FAILURE,
        )
        pre_direct = connection(
            control_id,
            0,
            "wininet_direct_control",
            True,
            ConnectivityVerdict.EXPECTED_204,
        )
        affected = connection(
            "ev_" + "d" * 32,
            4,
            "wininet_current_user",
            True,
            ConnectivityVerdict.EXPECTED_204,
        )
        direct = connection(
            "ev_" + "e" * 32,
            5,
            "wininet_direct_control",
            True,
            ConnectivityVerdict.EXPECTED_204,
        )
        if change == "stale_post":
            affected = replace(affected, observed_at=NOW + timedelta(seconds=1))
        if change == "reused_id":
            direct = replace(direct, evidence_id=affected.evidence_id)
        if change == "bad_direct":
            direct = replace(direct, passed=False, verdict=ConnectivityVerdict.UNAVAILABLE)
        if change == "not_recovered":
            affected = replace(
                affected,
                passed=False,
                verdict=ConnectivityVerdict.WININET_CONNECTIVITY_FAILURE,
            )
        if change == "late_before":
            pre_affected = replace(pre_affected, observed_at=NOW + timedelta(seconds=3))
        if change == "foreign_execution":
            affected = replace(affected, execution_id="execution_" + "0" * 32)
        if change == "foreign_case":
            affected = replace(affected, case_id=_case(store))
        if change == "foreign_endpoint":
            affected = replace(affected, registered_endpoint_digest="0" * 64)
        if change == "foreign_sid":
            affected = replace(affected, user_sid="S-1-5-21-1-2-3-4")
        setting = SettingEvidence(
            "ev_" + "c" * 32,
            "1" * 64,
            NOW + timedelta(seconds=3),
            execution.execution_id,
            case_id,
            sid,
            False,
            "bad.example:8080",
            True,
            True,
        )
        if change == "managed_policy":
            setting = replace(setting, policy_unmanaged=False)
        if change == "wrong_sid":
            setting = replace(setting, user_sid="S-1-5-21-1-2-3-4")
        stop = StopEvidence(
            execution.execution_id,
            operation.target.locator,
            NOW + timedelta(seconds=2),
            True,
        )

        class Evidence:
            def stop(self, execution_id: str):
                return stop

            def setting(self, execution_id: str):
                return setting

            def connectivity(self, evidence_id: str):
                return {before_id: pre_affected, control_id: pre_direct}.get(evidence_id)

            def affected_after(self, execution_id: str):
                return affected

            def direct_after(self, execution_id: str):
                return direct

        class SwappedClaimReader:
            def execution(self, execution_id: str):
                return repo.execution(execution_id)

            def proposal(self, proposal_id: str):
                return repo.proposal(proposal_id)

            def claim(self, claim_id: str):
                row = repo.claim(claim_id)
                return replace(row, claim_id="claim_" + "0" * 32) if row is not None else None

            def active_head(self, case_id: CaseId):
                return repo.active_head(case_id)

        approvals = SwappedClaimReader() if change == "foreign_claim" else repo

        assessor = ReconciliationAssessor(
            approvals=approvals,
            journal=Journal(),
            tokens=Tokens(),
            evidence=Evidence(),
            checks=Checks(),
            current_sid=lambda: sid,
            clock=lambda: NOW + timedelta(seconds=10),
            verify_stop=(lambda _stop, _execution: change != "unverified_stop"),
            verify_evidence=(
                None if change == "no_evidence_verifier" else lambda _record, _scope: True
            ),
            verify_registered_check=(
                None if change == "no_check_verifier" else lambda _check, _proposal: True
            ),
        )
        if change == "no_stop_verifier":
            assessor = ReconciliationAssessor(
                approvals=repo,
                journal=Journal(),
                tokens=Tokens(),
                evidence=Evidence(),
                checks=Checks(),
                current_sid=lambda: sid,
                clock=lambda: NOW + timedelta(seconds=10),
                verify_evidence=lambda _record, _scope: True,
                verify_registered_check=lambda _check, _proposal: True,
            )
        return assessor.assess(execution.execution_id)


def _evidence_id(value: str):
    from systemsense.domain.ids import EvidenceId

    return EvidenceId(root=value)


def test_verified_journal_needs_independent_post_stop_affected_and_direct(tmp_path: Path) -> None:
    assessment = _exercise(tmp_path)
    assert assessment.setting is TerminalSetting.INTENDED
    assert assessment.symptom is TerminalSymptom.RECOVERED
    assert assessment.qualified is False
    assert assessment.reason == "observed_unqualified"


def test_missing_or_untrusted_proof_fails_closed(tmp_path: Path) -> None:
    for change in (
        "missing_before",
        "stale_post",
        "reused_id",
        "bad_direct",
        "late_before",
        "managed_policy",
        "wrong_sid",
        "journal_target",
        "journal_auth",
        "journal_after_stop",
        "unverified_stop",
        "no_stop_verifier",
        "no_evidence_verifier",
        "no_check_verifier",
        "unregistered_check",
        "wrong_precondition",
        "wrong_verification",
        "wrong_risk",
        "foreign_claim",
    ):
        case = tmp_path / change
        case.mkdir()
        assessment = _exercise(case, change=change)
        assert assessment.setting is TerminalSetting.UNAVAILABLE, change
        assert assessment.symptom is TerminalSymptom.UNAVAILABLE, change


def test_setting_and_symptom_remain_separate_when_affected_path_fails(tmp_path: Path) -> None:
    assessment = _exercise(tmp_path, change="not_recovered")
    assert assessment.setting is TerminalSetting.INTENDED
    assert assessment.symptom is TerminalSymptom.NOT_RECOVERED
    assert assessment.qualified is False


def test_cross_execution_case_sid_or_endpoint_evidence_substitution_is_unavailable(
    tmp_path: Path,
) -> None:
    # The fake content verifier accepts every record; scope validation must
    # independently reject metadata borrowed from another execution or source.
    for change in ("foreign_execution", "foreign_case", "foreign_sid", "foreign_endpoint"):
        case = tmp_path / change
        case.mkdir()
        assessment = _exercise(case, change=change)
        assert assessment.setting is TerminalSetting.UNAVAILABLE, change
        assert assessment.symptom is TerminalSymptom.UNAVAILABLE, change
