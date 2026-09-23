"""Read-only, unqualified assessment of one exact WinINet repair execution.

All sources are injected. This module cannot write a proxy setting, approve a
repair, terminalize an execution, or release a target reservation. Its result is
advisory until the stop, evidence, and token sources are independently qualified.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Protocol

from systemsense.actions.contracts import (
    ActionCode,
    ActionKind,
    AuthorizationToken,
    DisruptionLevel,
    PreconditionCode,
    RepairProposal,
    RiskLevel,
    TargetKind,
)
from systemsense.actions.wininet_proxy import (
    ConnectivityVerdict,
    ProxyRepairRecord,
)
from systemsense.domain.ids import CaseId
from systemsense.domain.time import ensure_utc, utc_now
from systemsense.storage.repair_approvals import (
    RepairApprovalClaim,
    RepairExecutionClaim,
    RepairExecutionState,
    RepairPlanHead,
    TerminalSetting,
    TerminalSymptom,
)

_SID = re.compile(
    r"wininet_proxy:(S-1-5-21-(?:0|[1-9][0-9]*)-(?:0|[1-9][0-9]*)-(?:0|[1-9][0-9]*)-(?:0|[1-9][0-9]*))\Z"
)
_DIGEST = re.compile(r"[0-9a-f]{64}\Z")
_MAX_AGE = timedelta(minutes=5)


class ApprovalReader(Protocol):
    def execution(self, execution_id: str) -> RepairExecutionClaim | None: ...
    def proposal(self, proposal_id: str) -> RepairProposal | None: ...
    def claim(self, claim_id: str) -> RepairApprovalClaim | None: ...
    def active_head(self, case_id: CaseId) -> RepairPlanHead | None: ...


class JournalReader(Protocol):
    def record(self, token_id: str) -> ProxyRepairRecord | None: ...


class TokenReader(Protocol):
    def get(self, token_id: str) -> AuthorizationToken | None: ...
    def verify(self, token: AuthorizationToken) -> bool: ...


@dataclass(frozen=True, slots=True)
class StopEvidence:
    """External supervisor attestation; a timestamp alone is never stop proof."""

    execution_id: str
    target_locator: str
    stopped_at: datetime
    executor_stopped: bool


@dataclass(frozen=True, slots=True)
class SettingEvidence:
    """Readback metadata; verifier must bind content_digest to immutable source."""

    evidence_id: str
    content_digest: str
    observed_at: datetime
    execution_id: str
    case_id: CaseId
    user_sid: str
    proxy_enabled: bool
    proxy_server: str
    flags_supported: bool
    policy_unmanaged: bool


@dataclass(frozen=True, slots=True)
class ConnectivityEvidence:
    """Route metadata; verifier must check route proof and content digest."""

    evidence_id: str
    content_digest: str
    observed_at: datetime
    execution_id: str
    case_id: CaseId
    user_sid: str
    check_id: str
    registered_endpoint_digest: str
    route: str
    destination_scope: str
    verdict: ConnectivityVerdict
    passed: bool
    route_proven: bool


@dataclass(frozen=True, slots=True)
class RegisteredCheck:
    """Exact trusted registry lookup; digest must bind endpoint configuration."""

    check_id: str
    endpoint_digest: str
    expected_user_sid: str


class RegisteredCheckReader(Protocol):
    def resolve(self, check_id: str, user_sid: str) -> RegisteredCheck | None: ...


@dataclass(frozen=True, slots=True)
class EvidenceScope:
    execution_id: str
    case_id: CaseId
    user_sid: str
    check_id: str
    registered_endpoint_digest: str


class EvidenceReader(Protocol):
    def stop(self, execution_id: str) -> StopEvidence | None: ...
    def setting(self, execution_id: str) -> SettingEvidence | None: ...
    def connectivity(self, evidence_id: str) -> ConnectivityEvidence | None: ...
    def affected_after(self, execution_id: str) -> ConnectivityEvidence | None: ...
    def direct_after(self, execution_id: str) -> ConnectivityEvidence | None: ...


@dataclass(frozen=True, slots=True)
class ReconciliationAssessment:
    execution_id: str
    setting: TerminalSetting
    symptom: TerminalSymptom
    reason: str
    evidence_ids: tuple[str, ...] = ()
    qualified: bool = False


def _digest(value: object) -> str:
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def _authorization_digest(token: AuthorizationToken) -> str:
    return _digest(
        {
            "token_id": token.token_id,
            "proposal_digest": token.proposal_digest,
            "operation_digests": token.operation_digests,
            "case_id": str(token.case_id),
            "case_state_version": token.case_state_version,
            "plan_version": token.plan_version,
            "reviewer_id": token.reviewer_id,
            "consent_reference": token.consent_reference,
            "issued_at": token.issued_at.isoformat(),
            "expires_at": token.expires_at.isoformat(),
            "signature": token.signature,
        }
    )


def _fresh(at: datetime, *, after: datetime, now: datetime) -> bool:
    at = ensure_utc(at)
    return after < at <= now and now - at <= _MAX_AGE


def _valid_evidence(record: SettingEvidence | ConnectivityEvidence) -> bool:
    return bool(re.fullmatch(r"ev_[0-9a-f]{32}", record.evidence_id)) and bool(
        _DIGEST.fullmatch(record.content_digest)
    )


class ReconciliationAssessor:
    """Re-read independent stores and classify observations without authority.

    Without independently installed stop and evidence verifiers, assessment is
    unavailable. In particular a caller-supplied datetime grants no custody.
    """

    def __init__(
        self,
        *,
        approvals: ApprovalReader,
        journal: JournalReader,
        tokens: TokenReader,
        evidence: EvidenceReader,
        checks: RegisteredCheckReader | None = None,
        current_sid: Callable[[], str],
        clock: Callable[[], datetime] = utc_now,
        verify_stop: Callable[[StopEvidence, RepairExecutionClaim], bool] | None = None,
        verify_evidence: (
            Callable[[SettingEvidence | ConnectivityEvidence, EvidenceScope], bool] | None
        ) = None,
        verify_registered_check: Callable[[RegisteredCheck, RepairProposal], bool] | None = None,
    ) -> None:
        self._approvals = approvals
        self._journal = journal
        self._tokens = tokens
        self._evidence = evidence
        self._checks = checks
        self._current_sid = current_sid
        self._clock = clock
        self._verify_stop = verify_stop
        self._verify_evidence = verify_evidence
        self._verify_registered_check = verify_registered_check

    def assess(self, execution_id: str) -> ReconciliationAssessment:
        def unavailable(reason: str) -> ReconciliationAssessment:
            return ReconciliationAssessment(
                execution_id, TerminalSetting.UNAVAILABLE, TerminalSymptom.UNAVAILABLE, reason
            )

        try:
            now = ensure_utc(self._clock())
            execution = self._approvals.execution(execution_id)
            if execution is None or execution.execution_id != execution_id:
                return unavailable("execution_unavailable")
            proposal = self._approvals.proposal(execution.proposal_id)
            review = self._approvals.claim(execution.claim_id)
            head = self._approvals.active_head(execution.case_id)
            token = self._tokens.get(execution.authorization_id)
            if proposal is None or review is None or head is None or token is None:
                return unavailable("binding_unavailable")
            if not self._bound(execution, proposal, review, head, token):
                return unavailable("binding_mismatch")
            locator = proposal.operations[0].target.locator
            sid = locator.split(":", 1)[1]
            if self._current_sid() != sid:
                return unavailable("identity_mismatch")
            params = {
                parameter.name: parameter.value for parameter in proposal.operations[0].parameters
            }
            server = params.get("expected_proxy_server")
            check_id = params.get("connectivity_check_id")
            if (
                type(server) is not str
                or not server
                or len(server) > 512
                or type(check_id) is not str
                or re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", check_id) is None
            ):
                return unavailable("proposal_scope_unavailable")
            if self._checks is None or self._verify_registered_check is None:
                return unavailable("registered_check_unavailable")
            registered = self._checks.resolve(check_id, sid)
            if (
                registered is None
                or registered.check_id != check_id
                or registered.expected_user_sid != sid
                or not _DIGEST.fullmatch(registered.endpoint_digest)
                or not self._verify_registered_check(registered, proposal)
            ):
                return unavailable("registered_check_unavailable")
            scope = EvidenceScope(
                execution_id, execution.case_id, sid, check_id, registered.endpoint_digest
            )
            journal = self._journal.record(execution.authorization_id)
            if journal is None or not self._journal_bound(
                journal, execution, review, token, locator
            ):
                return unavailable("journal_mismatch")
            stop = self._evidence.stop(execution_id)
            if (
                self._verify_stop is None
                or self._verify_evidence is None
                or stop is None
                or not stop.executor_stopped
                or stop.execution_id != execution_id
                or stop.target_locator != locator
                or not journal.updated_at < stop.stopped_at
                or not _fresh(
                    stop.stopped_at, after=execution.claimed_at - timedelta(microseconds=1), now=now
                )
                or not self._verify_stop(stop, execution)
            ):
                return unavailable("stop_unavailable")
            setting = self._evidence.setting(execution_id)
            affected = self._evidence.affected_after(execution_id)
            direct = self._evidence.direct_after(execution_id)
            before = (
                self._evidence.connectivity(str(journal.before_evidence_id))
                if journal.before_evidence_id is not None
                else None
            )
            control = (
                self._evidence.connectivity(str(journal.control_evidence_id))
                if journal.control_evidence_id is not None
                else None
            )
            records = (setting, affected, direct, before, control)
            if any(item is None for item in records):
                return unavailable("evidence_unavailable")
            assert setting is not None and affected is not None and direct is not None
            assert before is not None and control is not None
            if not all(_valid_evidence(item) for item in records if item is not None):
                return unavailable("evidence_invalid")
            if not all(self._verify_evidence(item, scope) for item in records if item is not None):
                return unavailable("evidence_unverified")
            ids = tuple(item.evidence_id for item in records if item is not None)
            if len(set(ids)) != len(ids) or (
                journal.after_evidence_id is not None and str(journal.after_evidence_id) in ids
            ):
                return unavailable("evidence_reused")
            if (
                set(params)
                != {
                    "expected_proxy_enabled",
                    "expected_proxy_server",
                    "new_proxy_enabled",
                    "new_proxy_server",
                    "connectivity_check_id",
                }
                or params.get("expected_proxy_enabled") is not True
                or params.get("new_proxy_enabled") is not False
                or params.get("new_proxy_server") != server
                or setting.execution_id != execution_id
                or setting.case_id != execution.case_id
                or setting.user_sid != sid
                or type(setting.proxy_enabled) is not bool
                or not setting.flags_supported
                or not setting.policy_unmanaged
                or not _fresh(setting.observed_at, after=stop.stopped_at, now=now)
                or not _fresh(affected.observed_at, after=setting.observed_at, now=now)
                or not _fresh(direct.observed_at, after=setting.observed_at, now=now)
                or not before.observed_at < stop.stopped_at
                or not control.observed_at < stop.stopped_at
                or not execution.claimed_at <= before.observed_at <= journal.updated_at
                or not execution.claimed_at <= control.observed_at <= journal.updated_at
                or stop.stopped_at - before.observed_at > _MAX_AGE
                or stop.stopped_at - control.observed_at > _MAX_AGE
                or not self._check_connectivity(before, scope, "wininet_current_user", False)
                or before.verdict is not ConnectivityVerdict.WININET_CONNECTIVITY_FAILURE
                or not self._check_connectivity(control, scope, "wininet_direct_control", True)
                or not self._check_connectivity(affected, scope, "wininet_current_user", None)
                or not self._check_connectivity(direct, scope, "wininet_direct_control", True)
                or journal.before_evidence_id is None
                or journal.control_evidence_id is None
                or str(journal.before_evidence_id) != before.evidence_id
                or str(journal.control_evidence_id) != control.evidence_id
            ):
                return unavailable("evidence_contradictory")
            if setting.proxy_server != server:
                setting_result = TerminalSetting.DIVERGED
            elif setting.proxy_enabled:
                setting_result = TerminalSetting.ORIGINAL
            else:
                setting_result = TerminalSetting.INTENDED
            if affected.verdict is ConnectivityVerdict.EXPECTED_204 and affected.passed:
                symptom_result = TerminalSymptom.RECOVERED
            elif (
                affected.verdict
                in {
                    ConnectivityVerdict.WININET_CONNECTIVITY_FAILURE,
                    ConnectivityVerdict.UNEXPECTED_HTTP,
                }
                and not affected.passed
            ):
                symptom_result = TerminalSymptom.NOT_RECOVERED
            else:
                symptom_result = TerminalSymptom.UNAVAILABLE
            if (
                self._current_sid() != sid
                or self._journal.record(execution.authorization_id) != journal
                or self._evidence.stop(execution_id) != stop
                or self._evidence.setting(execution_id) != setting
                or self._evidence.affected_after(execution_id) != affected
                or self._evidence.direct_after(execution_id) != direct
                or self._evidence.connectivity(before.evidence_id) != before
                or self._evidence.connectivity(control.evidence_id) != control
                or self._tokens.get(execution.authorization_id) != token
                or self._checks.resolve(check_id, sid) != registered
            ):
                return unavailable("source_changed")
            if (
                self._approvals.execution(execution_id) != execution
                or self._approvals.proposal(execution.proposal_id) != proposal
                or self._approvals.claim(execution.claim_id) != review
                or self._approvals.active_head(execution.case_id) != head
            ):
                return unavailable("source_changed")
            return ReconciliationAssessment(
                execution_id, setting_result, symptom_result, "observed_unqualified", ids
            )
        except Exception:
            return unavailable("source_unavailable")

    def _bound(
        self,
        execution: RepairExecutionClaim,
        proposal: RepairProposal,
        review: RepairApprovalClaim,
        head: RepairPlanHead,
        token: AuthorizationToken,
    ) -> bool:
        if len(proposal.operations) != 1:
            return False
        operation = proposal.operations[0]
        match = _SID.fullmatch(operation.target.locator)
        if match is None:
            return False
        if any(int(part) > 0xFFFFFFFF for part in match.group(1).split("-")[4:]):
            return False
        target_scope = _digest(operation.target.model_dump(mode="json"))
        return (
            proposal.kind is ActionKind.REPAIR
            and operation.kind is ActionKind.REPAIR
            and operation.code is ActionCode.DISABLE_WININET_PROXY
            and operation.target.kind is TargetKind.WININET_USER_PROXY
            and len(proposal.preconditions) == 1
            and proposal.preconditions[0].code is PreconditionCode.TARGET_VERSION_MATCHES
            and proposal.preconditions[0].target == operation.target
            and not proposal.preconditions[0].evidence
            and len(proposal.verification.checks) == 1
            and proposal.verification.checks[0].code == "connectivity_restored"
            and not proposal.verification.checks[0].evidence
            and proposal.verification.minimum_passes == 1
            and proposal.risk.level is RiskLevel.MODERATE
            and proposal.risk.disruption is DisruptionLevel.NETWORK_INTERRUPTION
            and not proposal.risk.data_loss_possible
            and not proposal.risk.requires_reboot
            and execution.state
            in {RepairExecutionState.APPLYING, RepairExecutionState.INTERRUPTED_UNCERTAIN}
            and execution.proposal_id
            == proposal.proposal_id
            == review.proposal_id
            == head.proposal_id
            and review.claim_id == execution.claim_id
            and execution.case_id
            == proposal.case_id
            == review.case_id
            == head.case_id
            == token.case_id
            and execution.case_state_version
            == proposal.case_state_version
            == head.case_state_version
            == token.case_state_version
            and execution.proposal_digest
            == proposal.digest()
            == review.proposal_digest
            == head.proposal_digest
            == token.proposal_digest
            and execution.target_scope_digest == target_scope
            and proposal.plan_version == head.plan_version == token.plan_version
            and execution.authorization_id == token.token_id
            and hmac.compare_digest(execution.authorization_digest, _authorization_digest(token))
            and token.operation_digests == proposal.operation_digests()
            and token.consent_reference == review.consent_reference
            and token.issued_at <= execution.claimed_at < token.expires_at
            and self._tokens.verify(token)
        )

    @staticmethod
    def _journal_bound(
        journal: ProxyRepairRecord,
        execution: RepairExecutionClaim,
        review: RepairApprovalClaim,
        token: AuthorizationToken,
        locator: str,
    ) -> bool:
        recorded_ids = (
            journal.before_evidence_id,
            journal.after_evidence_id,
            journal.control_evidence_id,
        )
        return (
            journal.token_id == execution.authorization_id
            and journal.proposal_digest == execution.proposal_digest
            and journal.case_id == execution.case_id
            and journal.target_digest == hashlib.sha256(locator.encode()).hexdigest()
            and journal.consent_reference == review.consent_reference
            and journal.reviewer_id == token.reviewer_id
            and journal.authorization_digest == hashlib.sha256(token.signature.encode()).hexdigest()
            and (
                journal.state != "verified"
                or (all(item is not None for item in recorded_ids) and len(set(recorded_ids)) == 3)
            )
            and journal.state
            in {"applying", "uncertain", "verified", "applied_unverified", "rolled_back"}
        )

    @staticmethod
    def _check_connectivity(
        evidence: ConnectivityEvidence, scope: EvidenceScope, route: str, passed: bool | None
    ) -> bool:
        return (
            evidence.execution_id == scope.execution_id
            and evidence.case_id == scope.case_id
            and evidence.user_sid == scope.user_sid
            and evidence.check_id == scope.check_id
            and evidence.registered_endpoint_digest == scope.registered_endpoint_digest
            and evidence.route == route
            and evidence.destination_scope == "external"
            and evidence.route_proven
            and (passed is None or evidence.passed is passed)
            and evidence.passed is (evidence.verdict is ConnectivityVerdict.EXPECTED_204)
        )
