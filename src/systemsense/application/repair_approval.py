"""Separately consented application boundary for an injected repair runner.

No investigation or model provider receives this route. A trusted application
surface must show ``review_record`` and obtain the matching digest from a human.
The runner is injected deliberately; this module never constructs a native writer.
"""

from __future__ import annotations

import threading
from collections.abc import Callable
from datetime import datetime
from enum import StrEnum
from typing import Protocol

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


class RepairApprovalRoute:
    """One exact proposal, one human review, and at most one execution attempt."""

    def __init__(
        self,
        *,
        proposal: RepairProposal,
        runner: RepairRunner,
        secret: bytes,
        reviewer_identity: Callable[[], str],
        current_binding: Callable[[], tuple[int, str]],
        approval_repository: RepairApprovalRepository,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._proposal = proposal
        self._runner = runner
        self._authority = AuthorizationAuthority(secret=secret)
        self._gate = ActionGate(secret=secret)
        self._reviewer_identity = reviewer_identity
        self._current_binding = current_binding
        self._clock = clock
        self._approval_repository = approval_repository
        self._lock = threading.Lock()
        self._write_gate_lock = threading.Lock()
        self._cancelled = threading.Event()
        self._write_committed = False
        self._consumed = False

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
            self._write_committed = True
            return True

    def approve(self, *, acknowledged_digest: str) -> ProxyRepairResult:
        with self._lock:
            if self._consumed:
                raise ActionAuthorizationError("review already consumed")
            if self._cancelled.is_set():
                raise ActionAuthorizationError("review was cancelled")
            now = ensure_utc(self._clock())
            if now >= self._proposal.expires_at:
                raise ActionAuthorizationError("review is expired")
            if acknowledged_digest != self._proposal.digest():
                raise ActionAuthorizationError("acknowledged digest does not match proposal")
            binding = self._current_binding()
            if binding != (self._proposal.case_state_version, self._proposal.plan_version):
                raise ActionAuthorizationError("case binding changed before review")
            reviewer_id = self._reviewer_identity()
            # Validate trusted identity and consent fields before consuming a
            # durable review. Token issuance stays inside the atomic DB step.
            HumanConsent(
                reviewer_id=reviewer_id,
                consent_reference="consent_preflight",
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
                acknowledged_digest=acknowledged_digest,
                make_action=make_action,
                verify_authorization=self._authority.verify,
            )
            self._consumed = True
        return self._runner.execute(
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
