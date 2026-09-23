"""Durable admission for exact, server-created repair proposals.

This store does not authenticate a reviewer, mint authority, or execute actions.
The application must perform trusted human confirmation before claiming a review.
"""

from __future__ import annotations

import hmac
import json
import re
import sqlite3
from collections.abc import Callable, Generator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from hashlib import sha256
from uuid import uuid4

from systemsense.actions.contracts import (
    ActionAuthorizationError,
    ActionCode,
    ActionKind,
    AuthorizationToken,
    AuthorizedAction,
    RepairProposal,
    TargetKind,
)
from systemsense.domain.ids import CaseId
from systemsense.domain.time import ensure_utc, utc_now
from systemsense.storage.sqlite_store import SQLiteStore


class RepairApprovalState(StrEnum):
    CLAIMED = "claimed"
    INTERRUPTED_UNCERTAIN = "interrupted_uncertain"


@dataclass(frozen=True, slots=True)
class RepairApprovalClaim:
    claim_id: str
    proposal_id: str
    case_id: CaseId
    proposal_digest: str
    consent_reference: str
    state: RepairApprovalState
    claimed_at: datetime
    updated_at: datetime


@dataclass(frozen=True, slots=True)
class RepairPlanHead:
    """Read-only exact proposal binding, not an execution lease or permission."""

    case_id: CaseId
    proposal_id: str
    proposal_digest: str
    case_state_version: int
    plan_version: str
    activated_at: datetime


class RepairExecutionState(StrEnum):
    PREPARED = "prepared"
    APPLYING = "applying"
    INTERRUPTED_UNCERTAIN = "interrupted_uncertain"


@dataclass(frozen=True, slots=True)
class RepairExecutionClaim:
    execution_id: str
    claim_id: str
    proposal_id: str
    case_id: CaseId
    proposal_digest: str
    case_state_version: int
    target_scope_digest: str
    authorization_id: str
    authorization_digest: str
    state: RepairExecutionState
    claimed_at: datetime
    updated_at: datetime


def _canonical_json(proposal: RepairProposal) -> str:
    return json.dumps(proposal.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))


def _digest(value: object) -> str:
    return sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def _target_scope(proposal: RepairProposal) -> tuple[str, tuple[str, ...]]:
    if len(proposal.operations) != 1:
        raise ActionAuthorizationError("execution requires one canonical WinINet SID target")
    operation = proposal.operations[0]
    target = operation.target
    sid = re.fullmatch(
        r"wininet_proxy:S-1-5-21-((?:0|[1-9][0-9]*)-){3}(?:0|[1-9][0-9]*)",
        target.locator,
    )
    if (
        proposal.kind is not ActionKind.REPAIR
        or operation.code is not ActionCode.DISABLE_WININET_PROXY
        or operation.kind is not ActionKind.REPAIR
        or target.kind is not TargetKind.WININET_USER_PROXY
        or sid is None
        or any(int(part) > 0xFFFFFFFF for part in target.locator.split(":", 1)[1].split("-")[4:])
    ):
        raise ActionAuthorizationError("execution requires one canonical WinINet SID target")
    return _digest(target.model_dump(mode="json")), (_digest(target.locator),)


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


class RepairApprovalRepository:
    """One immutable proposal and at most one review claim per proposal ID."""

    def __init__(self, store: SQLiteStore, *, clock: Callable[[], datetime] = utc_now) -> None:
        self._store = store
        self._clock = clock
        self._owned_admission_transaction = False
        self._require_durable_connection()

    def register_server_proposal(
        self, proposal: RepairProposal, *, current_plan_version: str
    ) -> None:
        """Persist only a proposal constructed by the trusted application layer."""

        with self._store.transaction():
            self._require_durable_connection()
            now = ensure_utc(self._clock())
            if now >= proposal.expires_at:
                raise ActionAuthorizationError("repair proposal is expired")
            if now < proposal.created_at:
                raise ActionAuthorizationError("repair proposal has a future creation time")
            if proposal.plan_version != current_plan_version:
                raise ActionAuthorizationError("repair proposal plan binding changed")
            self._check_case_state(proposal.case_id, proposal.case_state_version)
            try:
                self._store.connection.execute(
                    "INSERT INTO repair_proposals "
                    "(proposal_id, case_id, case_state_version, plan_version, created_at, "
                    "expires_at, proposal_digest, proposal_json) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        proposal.proposal_id,
                        str(proposal.case_id),
                        proposal.case_state_version,
                        proposal.plan_version,
                        proposal.created_at.isoformat(),
                        proposal.expires_at.isoformat(),
                        proposal.digest(),
                        _canonical_json(proposal),
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise ActionAuthorizationError("repair proposal already registered") from error
            try:
                changed = self._store.connection.execute(
                    "UPDATE repair_plan_heads SET active_proposal_id=?, "
                    "active_proposal_digest=?, case_state_version=?, activated_at=? "
                    "WHERE case_id=?",
                    (
                        proposal.proposal_id,
                        proposal.digest(),
                        proposal.case_state_version,
                        now.isoformat(),
                        str(proposal.case_id),
                    ),
                ).rowcount
                if changed == 0:
                    self._store.connection.execute(
                        "INSERT INTO repair_plan_heads "
                        "(case_id, active_proposal_id, active_proposal_digest, "
                        "case_state_version, activated_at) VALUES (?, ?, ?, ?, ?)",
                        (
                            str(proposal.case_id),
                            proposal.proposal_id,
                            proposal.digest(),
                            proposal.case_state_version,
                            now.isoformat(),
                        ),
                    )
            except sqlite3.IntegrityError as error:
                raise ActionAuthorizationError("repair plan head binding failed") from error

    def proposal(self, proposal_id: str) -> RepairProposal | None:
        row = self._store.connection.execute(
            "SELECT case_id, case_state_version, plan_version, created_at, expires_at, "
            "proposal_digest, proposal_json FROM repair_proposals WHERE proposal_id=?",
            (proposal_id,),
        ).fetchone()
        if row is None:
            return None
        try:
            proposal = RepairProposal.model_validate_json(str(row[6]))
        except ValueError as error:
            raise ActionAuthorizationError("stored repair proposal is invalid") from error
        if (
            proposal.proposal_id != proposal_id
            or str(proposal.case_id) != row[0]
            or proposal.case_state_version != row[1]
            or proposal.plan_version != row[2]
            or proposal.created_at.isoformat() != row[3]
            or proposal.expires_at.isoformat() != row[4]
            or not hmac.compare_digest(proposal.digest(), str(row[5]))
            or _canonical_json(proposal) != row[6]
        ):
            raise ActionAuthorizationError("stored repair proposal binding is invalid")
        return proposal

    def active_head(self, case_id: CaseId) -> RepairPlanHead | None:
        """Read the current exact binding; this alone grants no action authority."""

        with self._store.read_snapshot():
            row = self._store.connection.execute(
                "SELECT active_proposal_id, active_proposal_digest, "
                "case_state_version, activated_at FROM repair_plan_heads WHERE case_id=?",
                (str(case_id),),
            ).fetchone()
            if row is None:
                return None
            proposal = self.proposal(str(row[0]))
            if (
                proposal is None
                or proposal.case_id != case_id
                or proposal.case_state_version != row[2]
                or not hmac.compare_digest(proposal.digest(), str(row[1]))
            ):
                raise ActionAuthorizationError("stored repair plan head binding is invalid")
            self._check_case_state(case_id, proposal.case_state_version)
            return RepairPlanHead(
                case_id=case_id,
                proposal_id=proposal.proposal_id,
                proposal_digest=proposal.digest(),
                case_state_version=proposal.case_state_version,
                plan_version=proposal.plan_version,
                activated_at=ensure_utc(datetime.fromisoformat(str(row[3]))),
            )

    def claim_review(
        self,
        proposal_id: str,
        *,
        case_id: CaseId,
        acknowledged_digest: str,
        consent_reference: str | None = None,
    ) -> RepairApprovalClaim:
        """Atomically consume one review; human authentication belongs upstream."""

        with self._atomic():
            self._require_durable_connection()
            now = ensure_utc(self._clock())
            proposal = self.proposal(proposal_id)
            if proposal is None:
                raise ActionAuthorizationError("repair proposal is unavailable")
            if proposal.case_id != case_id:
                raise ActionAuthorizationError("repair proposal case binding does not match")
            if not hmac.compare_digest(proposal.digest(), acknowledged_digest):
                raise ActionAuthorizationError("acknowledged repair proposal digest does not match")
            head = self.active_head(case_id)
            if (
                head is None
                or head.proposal_id != proposal_id
                or not hmac.compare_digest(head.proposal_digest, proposal.digest())
                or head.case_state_version != proposal.case_state_version
            ):
                raise ActionAuthorizationError("repair proposal is not active")
            if now >= proposal.expires_at or now < proposal.created_at:
                raise ActionAuthorizationError("repair proposal is expired or not yet valid")
            self._check_case_state(case_id, proposal.case_state_version)
            if (
                consent_reference is not None
                and re.fullmatch(r"consent_[a-zA-Z0-9_.-]+", consent_reference) is None
            ):
                raise ActionAuthorizationError("invalid consent reference")
            claim = RepairApprovalClaim(
                claim_id=f"claim_{uuid4().hex}",
                proposal_id=proposal_id,
                case_id=case_id,
                proposal_digest=proposal.digest(),
                consent_reference=consent_reference or f"consent_{uuid4().hex}",
                state=RepairApprovalState.CLAIMED,
                claimed_at=now,
                updated_at=now,
            )
            try:
                self._store.connection.execute(
                    "INSERT INTO repair_approval_claims "
                    "(claim_id, proposal_id, case_id, proposal_digest, consent_reference, "
                    "state, claimed_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        claim.claim_id,
                        claim.proposal_id,
                        str(claim.case_id),
                        claim.proposal_digest,
                        claim.consent_reference,
                        claim.state.value,
                        claim.claimed_at.isoformat(),
                        claim.updated_at.isoformat(),
                    ),
                )
            except sqlite3.IntegrityError as error:
                raise ActionAuthorizationError("repair proposal already claimed") from error
        return claim

    def claim_and_promote(
        self,
        proposal_id: str,
        *,
        case_id: CaseId,
        acknowledged_digest: str,
        make_action: Callable[[RepairApprovalClaim, RepairProposal], AuthorizedAction],
        verify_authorization: Callable[[AuthorizationToken], bool],
    ) -> tuple[RepairApprovalClaim, RepairExecutionClaim, AuthorizedAction]:
        """Consume review and reserve execution in one durable write transaction.

        The trusted callback derives only an authorization token. It must not
        access a device or network; any failure rolls back the review claim.
        """

        if self._store.connection.in_transaction or self._owned_admission_transaction:
            raise ActionAuthorizationError("repair admission cannot join an active transaction")
        with self._store.transaction():
            self._owned_admission_transaction = True
            try:
                self._require_durable_connection()
                review = self.claim_review(
                    proposal_id,
                    case_id=case_id,
                    acknowledged_digest=acknowledged_digest,
                )
                proposal = self.proposal(proposal_id)
                assert proposal is not None
                action = make_action(review, proposal)
                execution = self.promote_execution(
                    review.claim_id,
                    action=action,
                    verify_authorization=verify_authorization,
                )
                return review, execution, action
            finally:
                self._owned_admission_transaction = False

    def claim(self, claim_id: str) -> RepairApprovalClaim | None:
        row = self._store.connection.execute(
            "SELECT proposal_id, case_id, proposal_digest, consent_reference, "
            "state, claimed_at, updated_at FROM repair_approval_claims WHERE claim_id=?",
            (claim_id,),
        ).fetchone()
        if row is None:
            return None
        proposal = self.proposal(str(row[0]))
        if (
            proposal is None
            or str(proposal.case_id) != row[1]
            or not hmac.compare_digest(proposal.digest(), str(row[2]))
        ):
            raise ActionAuthorizationError("stored repair approval binding is invalid")
        return RepairApprovalClaim(
            claim_id=claim_id,
            proposal_id=str(row[0]),
            case_id=CaseId(root=str(row[1])),
            proposal_digest=str(row[2]),
            consent_reference=str(row[3]),
            state=RepairApprovalState(str(row[4])),
            claimed_at=ensure_utc(datetime.fromisoformat(str(row[5]))),
            updated_at=ensure_utc(datetime.fromisoformat(str(row[6]))),
        )

    def mark_interrupted(self, claim_id: str) -> RepairApprovalClaim:
        """Record unknown downstream outcome, without replay or target unlock."""

        with self._store.transaction():
            self._require_durable_connection()
            now = ensure_utc(self._clock())
            current = self.claim(claim_id)
            if current is None or current.state is not RepairApprovalState.CLAIMED:
                raise ActionAuthorizationError(
                    "repair approval is unavailable or already interrupted"
                )
            if now < current.claimed_at:
                raise ActionAuthorizationError("interruption time is before claim")
            changed = self._store.connection.execute(
                "UPDATE repair_approval_claims SET state='interrupted_uncertain', updated_at=? "
                "WHERE claim_id=? AND state='claimed'",
                (now.isoformat(), claim_id),
            ).rowcount
            if changed != 1:
                raise ActionAuthorizationError(
                    "repair approval is unavailable or already interrupted"
                )
            record = self.claim(claim_id)
            assert record is not None
        return record

    def promote_execution(
        self,
        claim_id: str,
        *,
        action: AuthorizedAction,
        verify_authorization: Callable[[AuthorizationToken], bool] | None = None,
    ) -> RepairExecutionClaim:
        """Commit one prepared claim; an exact recheck must start it once.

        The verifier must belong to the trusted human-authorization boundary.
        This storage method does not authenticate a person or perform a write.
        """

        with self._atomic():
            self._require_durable_connection()
            now = ensure_utc(self._clock())
            _claim, proposal = self._check_execution_binding(
                claim_id, action, verify_authorization, now
            )
            if self._store.connection.execute(
                "SELECT 1 FROM repair_execution_claims WHERE claim_id=?", (claim_id,)
            ).fetchone():
                raise ActionAuthorizationError("repair approval already promoted for execution")
            target_scope_digest, target_keys = _target_scope(proposal)
            execution = RepairExecutionClaim(
                execution_id=f"execution_{uuid4().hex}",
                claim_id=claim_id,
                proposal_id=proposal.proposal_id,
                case_id=proposal.case_id,
                proposal_digest=proposal.digest(),
                case_state_version=proposal.case_state_version,
                target_scope_digest=target_scope_digest,
                authorization_id=action.token.token_id,
                authorization_digest=_authorization_digest(action.token),
                state=RepairExecutionState.PREPARED,
                claimed_at=now,
                updated_at=now,
            )
            try:
                self._store.connection.execute(
                    "INSERT INTO repair_execution_claims "
                    "(execution_id, claim_id, proposal_id, case_id, proposal_digest, "
                    "case_state_version, target_scope_digest, authorization_id, "
                    "authorization_digest, state, claimed_at, updated_at) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        execution.execution_id,
                        execution.claim_id,
                        execution.proposal_id,
                        str(execution.case_id),
                        execution.proposal_digest,
                        execution.case_state_version,
                        execution.target_scope_digest,
                        execution.authorization_id,
                        execution.authorization_digest,
                        execution.state.value,
                        execution.claimed_at.isoformat(),
                        execution.updated_at.isoformat(),
                    ),
                )
                self._store.connection.executemany(
                    "INSERT INTO repair_execution_target_locks (target_key, execution_id) "
                    "VALUES (?, ?)",
                    [(key, execution.execution_id) for key in target_keys],
                )
            except sqlite3.IntegrityError as error:
                raise ActionAuthorizationError(
                    "repair execution already claimed or target reserved"
                ) from error
        return execution

    @contextmanager
    def _atomic(self) -> Generator[None]:
        """Join a trusted outer transaction without committing it early."""

        connection = self._store.connection
        if not connection.in_transaction:
            with self._store.transaction():
                yield
            return
        if not self._owned_admission_transaction:
            raise ActionAuthorizationError("repair admission cannot join an active transaction")
        connection.execute("SAVEPOINT repair_approval_nested")
        try:
            yield
        except BaseException:
            connection.execute("ROLLBACK TO repair_approval_nested")
            connection.execute("RELEASE repair_approval_nested")
            raise
        else:
            connection.execute("RELEASE repair_approval_nested")

    def recheck_execution(
        self,
        execution_id: str,
        *,
        action: AuthorizedAction,
        verify_authorization: Callable[[AuthorizationToken], bool] | None = None,
    ) -> RepairExecutionClaim:
        """Commit the one-shot applying transition before a future OS write.

        A database trigger fences head supersession while the execution is
        unresolved. This method itself has no OS write authority.
        """

        with self._store.transaction():
            self._require_durable_connection()
            execution = self.execution(execution_id)
            if execution is None:
                raise ActionAuthorizationError("repair execution is unavailable")
            if execution.state is not RepairExecutionState.PREPARED:
                raise ActionAuthorizationError("repair execution already started or unavailable")
            claim, proposal = self._check_execution_binding(
                execution.claim_id,
                action,
                verify_authorization,
                ensure_utc(self._clock()),
            )
            target_scope_digest, target_keys = _target_scope(proposal)
            locked = {
                str(row[0])
                for row in self._store.connection.execute(
                    "SELECT target_key FROM repair_execution_target_locks WHERE execution_id=?",
                    (execution_id,),
                )
            }
            if (
                execution.claim_id != claim.claim_id
                or execution.proposal_id != proposal.proposal_id
                or execution.case_id != proposal.case_id
                or not hmac.compare_digest(execution.proposal_digest, proposal.digest())
                or execution.case_state_version != proposal.case_state_version
                or not hmac.compare_digest(execution.target_scope_digest, target_scope_digest)
                or execution.authorization_id != action.token.token_id
                or not hmac.compare_digest(
                    execution.authorization_digest, _authorization_digest(action.token)
                )
                or locked != set(target_keys)
            ):
                raise ActionAuthorizationError("repair execution exact binding is invalid")
            now = ensure_utc(self._clock())
            changed = self._store.connection.execute(
                "UPDATE repair_execution_claims SET state='applying', updated_at=? "
                "WHERE execution_id=? AND state='prepared'",
                (now.isoformat(), execution_id),
            ).rowcount
            if changed != 1:
                raise ActionAuthorizationError("repair execution already started or unavailable")
            started = self.execution(execution_id)
            assert started is not None
            return started

    def execution(self, execution_id: str) -> RepairExecutionClaim | None:
        row = self._store.connection.execute(
            "SELECT claim_id, proposal_id, case_id, proposal_digest, case_state_version, "
            "target_scope_digest, authorization_id, authorization_digest, state, "
            "claimed_at, updated_at FROM repair_execution_claims WHERE execution_id=?",
            (execution_id,),
        ).fetchone()
        if row is None:
            return None
        claim = self.claim(str(row[0]))
        if claim is None or claim.proposal_id != row[1] or str(claim.case_id) != row[2]:
            raise ActionAuthorizationError("stored repair execution binding is invalid")
        return RepairExecutionClaim(
            execution_id=execution_id,
            claim_id=str(row[0]),
            proposal_id=str(row[1]),
            case_id=CaseId(root=str(row[2])),
            proposal_digest=str(row[3]),
            case_state_version=int(row[4]),
            target_scope_digest=str(row[5]),
            authorization_id=str(row[6]),
            authorization_digest=str(row[7]),
            state=RepairExecutionState(str(row[8])),
            claimed_at=ensure_utc(datetime.fromisoformat(str(row[9]))),
            updated_at=ensure_utc(datetime.fromisoformat(str(row[10]))),
        )

    def mark_execution_interrupted(self, execution_id: str) -> RepairExecutionClaim:
        """Record unknown outcome without unlocking targets or enabling retry."""

        with self._store.transaction():
            self._require_durable_connection()
            current = self.execution(execution_id)
            if current is None or current.state not in {
                RepairExecutionState.PREPARED,
                RepairExecutionState.APPLYING,
            }:
                raise ActionAuthorizationError("repair execution is unavailable")
            now = ensure_utc(self._clock())
            if now < current.claimed_at:
                raise ActionAuthorizationError("interruption time is before execution claim")
            changed = self._store.connection.execute(
                "UPDATE repair_execution_claims SET state='interrupted_uncertain', updated_at=? "
                "WHERE execution_id=? AND state IN ('prepared', 'applying')",
                (now.isoformat(), execution_id),
            ).rowcount
            if changed != 1:
                raise ActionAuthorizationError("repair execution is unavailable")
            updated = self.execution(execution_id)
            assert updated is not None
            return updated

    def _check_execution_binding(
        self,
        claim_id: str,
        action: AuthorizedAction,
        verify_authorization: Callable[[AuthorizationToken], bool] | None,
        now: datetime,
    ) -> tuple[RepairApprovalClaim, RepairProposal]:
        if verify_authorization is None:
            raise ActionAuthorizationError("authorization verification is unavailable")
        if not verify_authorization(action.token):
            raise ActionAuthorizationError("authorization token is invalid")
        claim = self.claim(claim_id)
        if claim is None or claim.state is not RepairApprovalState.CLAIMED:
            raise ActionAuthorizationError("repair approval is unavailable")
        proposal = self.proposal(claim.proposal_id)
        assert proposal is not None
        token = action.token
        if (
            action.proposal != proposal
            or claim.case_id != proposal.case_id
            or not hmac.compare_digest(claim.proposal_digest, proposal.digest())
            or token.case_id != proposal.case_id
            or token.case_state_version != proposal.case_state_version
            or token.plan_version != proposal.plan_version
            or not hmac.compare_digest(token.proposal_digest, proposal.digest())
            or token.operation_digests != proposal.operation_digests()
            or token.consent_reference != claim.consent_reference
            or not token.reviewer_id.startswith("human:")
        ):
            raise ActionAuthorizationError("repair authorization exact binding is invalid")
        if now < token.issued_at or now >= token.expires_at:
            raise ActionAuthorizationError("repair authorization is expired or not yet valid")
        if now < proposal.created_at or now >= proposal.expires_at:
            raise ActionAuthorizationError("repair proposal is expired or not yet valid")
        head = self.active_head(proposal.case_id)
        if (
            head is None
            or head.proposal_id != proposal.proposal_id
            or not hmac.compare_digest(head.proposal_digest, proposal.digest())
            or head.case_state_version != proposal.case_state_version
        ):
            raise ActionAuthorizationError("repair proposal is not active")
        self._check_case_state(proposal.case_id, proposal.case_state_version)
        return claim, proposal

    def _check_case_state(self, case_id: CaseId, expected_version: int) -> None:
        row = self._store.connection.execute(
            "SELECT state_version FROM cases WHERE case_id=?", (str(case_id),)
        ).fetchone()
        if row is None or row[0] != expected_version:
            raise ActionAuthorizationError("repair proposal case binding is stale")

    def _require_durable_connection(self) -> None:
        row = self._store.connection.execute("PRAGMA synchronous").fetchone()
        if row is None or row[0] != 2:
            raise RuntimeError("repair approval storage requires SQLite synchronous=FULL")
        if self._store.journal_mode().lower() != "wal":
            raise RuntimeError("repair approval storage requires SQLite journal_mode=WAL")
        if not self._store.foreign_keys_enabled():
            raise RuntimeError("repair approval storage requires SQLite foreign_keys=ON")
