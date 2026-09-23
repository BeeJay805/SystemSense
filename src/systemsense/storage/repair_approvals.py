"""Durable admission for exact, server-created repair proposals.

This store does not authenticate a reviewer, mint authority, or execute actions.
The application must perform trusted human confirmation before claiming a review.
"""

from __future__ import annotations

import hmac
import json
import sqlite3
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from uuid import uuid4

from systemsense.actions.contracts import ActionAuthorizationError, RepairProposal
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


def _canonical_json(proposal: RepairProposal) -> str:
    return json.dumps(proposal.model_dump(mode="json"), sort_keys=True, separators=(",", ":"))


class RepairApprovalRepository:
    """One immutable proposal and at most one review claim per proposal ID."""

    def __init__(self, store: SQLiteStore, *, clock: Callable[[], datetime] = utc_now) -> None:
        self._store = store
        self._clock = clock
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
    ) -> RepairApprovalClaim:
        """Atomically consume one review; human authentication belongs upstream."""

        with self._store.transaction():
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
            claim = RepairApprovalClaim(
                claim_id=f"claim_{uuid4().hex}",
                proposal_id=proposal_id,
                case_id=case_id,
                proposal_digest=proposal.digest(),
                consent_reference=f"consent_{uuid4().hex}",
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
