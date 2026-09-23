"""Separately consented application boundary for an injected repair runner.

No investigation or model provider receives this route. A trusted local consent
broker shows the exact proposal and yields one process-local review witness.
The runner is injected deliberately; this module never constructs a native writer.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Protocol, cast

from systemsense.actions.contracts import (
    ActionAuthorizationError,
    ActionGate,
    AuthorizationAuthority,
    AuthorizationToken,
    AuthorizedAction,
    HumanConsent,
    RepairProposal,
)
from systemsense.actions.wininet_proxy import ProxyRepairResult
from systemsense.application.interactive_consent import InteractiveConsentBroker, WindowsPrincipal
from systemsense.domain.time import ensure_utc, utc_now
from systemsense.storage.repair_approvals import RepairApprovalClaim, RepairApprovalRepository


class RepairRunner(Protocol):
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
    ) -> ProxyRepairResult: ...


class CancellationDisposition(StrEnum):
    ACCEPTED_BEFORE_WRITE = "accepted_before_write"
    TOO_LATE_TO_PREVENT_WRITE = "too_late_to_prevent_write"


@dataclass(frozen=True, slots=True)
class RepairExecutionReceipt:
    """Durable attempt identity only; reload journal and independent outcome separately."""

    execution_id: str
    proposal_id: str
    proposal_digest: str
    token_id: str


class RepairApprovalRoute:
    """One exact proposal, one human review, and at most one execution attempt."""

    def __init__(
        self,
        *,
        proposal: RepairProposal,
        runner: RepairRunner,
        secret: bytes,
        consent_broker: InteractiveConsentBroker,
        current_binding: Callable[[], tuple[int, str]],
        approval_repository: RepairApprovalRepository,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._proposal = proposal
        self._runner = runner
        self._authority = AuthorizationAuthority(secret=secret)
        self._gate = ActionGate(secret=secret)
        self._consent_broker = consent_broker
        self._current_binding = current_binding
        self._clock = clock
        self._approval_repository = approval_repository
        self._lock = threading.Lock()
        self._write_gate_lock = threading.Lock()
        self._cancelled = threading.Event()
        self._write_committed = False
        self._consumed = False
        self._approved_principal: WindowsPrincipal | None = None

    def review_record(self) -> dict[str, object]:
        """Return the complete immutable proposal and digest for human review."""

        return {
            "proposal": self._proposal.model_dump(mode="json"),
            "proposal_digest": self._proposal.digest(),
        }

    def cancel(self) -> CancellationDisposition:
        """Acknowledge cancellation only if the local write gate is still closed.

        Once the gate opens, a caller must wait for journal/oracle reconciliation;
        the native write may already have happened.
        """

        with self._write_gate_lock:
            if self._write_committed:
                return CancellationDisposition.TOO_LATE_TO_PREVENT_WRITE
            self._cancelled.set()
            return CancellationDisposition.ACCEPTED_BEFORE_WRITE

    def _enter_write(self) -> bool:
        with self._write_gate_lock:
            if self._cancelled.is_set():
                return False
            try:
                if (
                    self._approved_principal is None
                    or self._consent_broker.current_principal() != self._approved_principal
                    or self._current_binding()
                    != (self._proposal.case_state_version, self._proposal.plan_version)
                    or ensure_utc(self._clock()) >= self._proposal.expires_at
                ):
                    return False
            except (ActionAuthorizationError, OSError, RuntimeError, ValueError):
                return False
            self._write_committed = True
            return True

    def approve(self) -> RepairExecutionReceipt:
        with self._lock:
            if self._consumed:
                raise ActionAuthorizationError("review already consumed")
            if self._cancelled.is_set():
                raise ActionAuthorizationError("review was cancelled")
            now = ensure_utc(self._clock())
            if now >= self._proposal.expires_at:
                raise ActionAuthorizationError("review is expired")
            binding = self._current_binding()
            if binding != (self._proposal.case_state_version, self._proposal.plan_version):
                raise ActionAuthorizationError("case binding changed before review")
            witness = self._consent_broker.confirm(self._proposal)
            now = ensure_utc(self._clock())
            if self._cancelled.is_set() or now >= self._proposal.expires_at:
                raise ActionAuthorizationError("review was cancelled or expired")
            if self._current_binding() != binding:
                raise ActionAuthorizationError("case binding changed during review")
            reviewer_id = self._consent_broker.consume(witness, self._proposal)
            HumanConsent(
                reviewer_id=reviewer_id,
                consent_reference=witness.reference,
                case_id=self._proposal.case_id,
                case_state_version=binding[0],
                plan_version=binding[1],
                proposal_digest=self._proposal.digest(),
                operation_digests=self._proposal.operation_digests(),
                expires_at=self._proposal.expires_at,
                reviewed=True,
            )

            def make_action(review: RepairApprovalClaim, exact: RepairProposal) -> AuthorizedAction:
                consent = HumanConsent(
                    reviewer_id=reviewer_id,
                    consent_reference=review.consent_reference,
                    case_id=exact.case_id,
                    case_state_version=binding[0],
                    plan_version=binding[1],
                    proposal_digest=exact.digest(),
                    operation_digests=exact.operation_digests(),
                    expires_at=exact.expires_at,
                    reviewed=True,
                )
                token = self._authority.issue(exact, consent=consent, issued_at=now)
                return self._gate.authorize(
                    exact,
                    token,
                    current_state_version=binding[0],
                    current_plan_version=binding[1],
                    now=now,
                )

            _review, execution, action = self._approval_repository.claim_and_promote(
                self._proposal.proposal_id,
                case_id=self._proposal.case_id,
                acknowledged_digest=self._proposal.digest(),
                consent_reference=witness.reference,
                make_action=make_action,
                verify_authorization=self._authority.verify,
            )
            self._approved_principal = witness.principal
            self._consumed = True
        try:
            runner_result = self._runner.execute(
                self._proposal,
                action.token,
                state_version=binding[0],
                plan_version=binding[1],
                cancelled=self._cancelled.is_set,
                write_permitted=self._enter_write,
                now=now,
                execution_id=execution.execution_id,
                verify_authorization=self._authority.verify,
            )
            if not isinstance(cast(object, runner_result), ProxyRepairResult):
                raise ActionAuthorizationError("repair runner result is invalid")
            return RepairExecutionReceipt(
                execution_id=execution.execution_id,
                proposal_id=execution.proposal_id,
                proposal_digest=execution.proposal_digest,
                token_id=execution.authorization_id,
            )
        except Exception as runner_error:
            # The claim is durable already. Even a refusal before the journal starts
            # must remain non-retryable until an independent terminal assessment.
            try:
                self._approval_repository.mark_execution_interrupted(execution.execution_id)
            except Exception as persistence_error:
                raise ExceptionGroup(
                    "repair failed and interrupted-state persistence failed",
                    [runner_error, persistence_error],
                ) from None
            raise
