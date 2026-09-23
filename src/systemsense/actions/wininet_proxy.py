"""Exact, consented current-user proxy repair and durable replay boundary.

No application route or native Windows writer calls this runner yet. The backend
interface has no registry-path, command, or URL parameter.
"""

from __future__ import annotations

import hashlib
import re
import sqlite3
from collections.abc import Callable
from contextlib import closing
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from pathlib import Path
from typing import Protocol

from systemsense.actions.contracts import (
    ActionAuthorizationError,
    ActionCode,
    ActionGate,
    AuthorizationToken,
    DisruptionLevel,
    RepairProposal,
    RiskLevel,
    TargetKind,
)
from systemsense.domain.ids import CaseId, EvidenceId
from systemsense.domain.time import ensure_utc, utc_now

_SID = re.compile(r"wininet_proxy:(S-1-5-21-(?:[0-9]+-){3}[0-9]+)")
_PARAMS = {
    "expected_proxy_enabled",
    "expected_proxy_server",
    "new_proxy_enabled",
    "new_proxy_server",
    "connectivity_check_id",
}


@dataclass(frozen=True, slots=True)
class ProxyState:
    user_sid: str
    enabled: bool
    server: str
    observed_at: datetime


class ConnectivityVerdict(StrEnum):
    EXPECTED_204 = "expected_204"
    WININET_CONNECTIVITY_FAILURE = "wininet_connectivity_failure"
    UNEXPECTED_HTTP = "unexpected_http"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class ConnectivityObservation:
    check_id: str
    passed: bool
    observed_at: datetime
    evidence_id: EvidenceId
    path: str
    destination_scope: str
    verdict: ConnectivityVerdict


class ProxyBackend(Protocol):
    def current_user_sid(self) -> str: ...
    def read(self) -> ProxyState: ...
    def set_enabled(self, value: bool) -> None: ...


class ConnectivityOracle(Protocol):
    """Runs an internally registered check, never a caller-supplied URL."""

    def supports(self, check_id: str) -> bool: ...
    def check(self, check_id: str) -> ConnectivityObservation: ...
    def check_direct_control(self, check_id: str) -> ConnectivityObservation: ...


class ProxyRepairOutcome(StrEnum):
    VERIFIED = "verified"
    CANCELLED = "cancelled"
    PRECONDITION_FAILED = "precondition_failed"
    APPLIED_UNVERIFIED = "applied_unverified"
    ROLLED_BACK = "rolled_back"
    UNCERTAIN = "uncertain"


class ProxyRecoveryDisposition(StrEnum):
    CLAIMED_PENDING = "claimed_pending"
    ORIGINAL_OBSERVED = "original_observed"
    INTENDED_OBSERVED = "intended_observed"
    DIVERGED = "diverged"
    UNAVAILABLE = "unavailable"


@dataclass(frozen=True, slots=True)
class ProxyRecoveryAssessment:
    """Read-only post-interruption observation, never a repair outcome."""

    disposition: ProxyRecoveryDisposition
    journal_state: str
    observed_at: datetime | None


@dataclass(frozen=True, slots=True)
class ProxyRepairResult:
    outcome: ProxyRepairOutcome
    before_evidence_id: EvidenceId | None = None
    after_evidence_id: EvidenceId | None = None
    control_evidence_id: EvidenceId | None = None


@dataclass(frozen=True, slots=True)
class ProxyRepairRecord:
    token_id: str
    proposal_digest: str
    reviewer_id: str
    consent_reference: str
    state: str
    before_evidence_id: EvidenceId | None
    after_evidence_id: EvidenceId | None
    control_evidence_id: EvidenceId | None
    case_id: CaseId | None
    target_digest: str | None
    authorization_digest: str | None
    updated_at: datetime


class ProxyRepairJournal:
    """Claim a token and target on disk before attempting any change."""

    def __init__(self, path: Path, *, clock: Callable[[], datetime] = utc_now) -> None:
        self.path = path
        self._clock = clock
        path.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as db:
            db.execute(
                "CREATE TABLE IF NOT EXISTS proxy_repairs ("
                "token_id TEXT PRIMARY KEY, proposal_digest TEXT NOT NULL, "
                "target_hash TEXT NOT NULL, state TEXT NOT NULL, updated_at TEXT NOT NULL, "
                "before_evidence_id TEXT, after_evidence_id TEXT, control_evidence_id TEXT, "
                "reviewer_id TEXT, consent_reference TEXT, case_id TEXT, "
                "authorization_digest TEXT)"
            )
            columns = {
                str(row[1]) for row in db.execute("PRAGMA table_info(proxy_repairs)").fetchall()
            }
            for column in (
                "before_evidence_id",
                "after_evidence_id",
                "control_evidence_id",
                "reviewer_id",
                "consent_reference",
                "case_id",
                "authorization_digest",
            ):
                if column not in columns:
                    db.execute(f"ALTER TABLE proxy_repairs ADD COLUMN {column} TEXT")
            db.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS active_proxy_target "
                "ON proxy_repairs(target_hash) "
                "WHERE state IN ('claimed', 'applying', 'uncertain')"
            )

    def _connect(self) -> sqlite3.Connection:
        db = sqlite3.connect(self.path, timeout=5, isolation_level=None)
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        return db

    def claim(self, token: AuthorizationToken, digest: str, locator: str, now: datetime) -> None:
        target_hash = hashlib.sha256(locator.encode()).hexdigest()
        with closing(self._connect()) as db:
            try:
                db.execute("BEGIN IMMEDIATE")
                db.execute(
                    "INSERT INTO proxy_repairs "
                    "(token_id, proposal_digest, target_hash, state, updated_at, "
                    "reviewer_id, consent_reference, case_id, authorization_digest) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        token.token_id,
                        digest,
                        target_hash,
                        "claimed",
                        now.isoformat(),
                        token.reviewer_id,
                        token.consent_reference,
                        str(token.case_id),
                        hashlib.sha256(token.signature.encode()).hexdigest(),
                    ),
                )
                db.execute("COMMIT")
            except sqlite3.IntegrityError as error:
                db.execute("ROLLBACK")
                raise ActionAuthorizationError(
                    "authorization token already consumed or target action unresolved"
                ) from error

    def transition(
        self,
        token_id: str,
        state: str,
        *,
        before_evidence_id: EvidenceId | None = None,
        after_evidence_id: EvidenceId | None = None,
        control_evidence_id: EvidenceId | None = None,
    ) -> None:
        predecessor = {
            "applying": "claimed",
            "cancelled": "claimed",
            "precondition_failed": "claimed",
            "verified": "applying",
            "applied_unverified": "applying",
            "rolled_back": "applying",
            "uncertain": "applying",
        }.get(state)
        if predecessor is None:
            raise ValueError("invalid journal state")
        if state == "verified" and (
            before_evidence_id is None
            or after_evidence_id is None
            or control_evidence_id is None
            or len(
                {
                    str(before_evidence_id),
                    str(after_evidence_id),
                    str(control_evidence_id),
                }
            )
            != 3
        ):
            raise ValueError("verified outcome requires distinct path and control evidence")
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            changed = db.execute(
                "UPDATE proxy_repairs SET state=?, updated_at=?, "
                "before_evidence_id=COALESCE(?, before_evidence_id), "
                "after_evidence_id=COALESCE(?, after_evidence_id), "
                "control_evidence_id=COALESCE(?, control_evidence_id) "
                "WHERE token_id=? AND state=?",
                (
                    state,
                    ensure_utc(self._clock()).isoformat(),
                    str(before_evidence_id) if before_evidence_id else None,
                    str(after_evidence_id) if after_evidence_id else None,
                    str(control_evidence_id) if control_evidence_id else None,
                    token_id,
                    predecessor,
                ),
            ).rowcount
            if changed != 1:
                db.execute("ROLLBACK")
                raise ActionAuthorizationError("invalid action journal transition")
            db.execute("COMMIT")

    def status(self, token_id: str) -> str | None:
        with closing(self._connect()) as db:
            row = db.execute(
                "SELECT state FROM proxy_repairs WHERE token_id=?", (token_id,)
            ).fetchone()
        return str(row[0]) if row else None

    def record(self, token_id: str) -> ProxyRepairRecord | None:
        with closing(self._connect()) as db:
            row = db.execute(
                "SELECT proposal_digest, state, before_evidence_id, after_evidence_id, "
                "reviewer_id, consent_reference, control_evidence_id, "
                "case_id, target_hash, authorization_digest, updated_at "
                "FROM proxy_repairs WHERE token_id=?",
                (token_id,),
            ).fetchone()
        if row is None:
            return None
        return ProxyRepairRecord(
            token_id=token_id,
            proposal_digest=str(row[0]),
            state=str(row[1]),
            before_evidence_id=EvidenceId(root=str(row[2])) if row[2] is not None else None,
            after_evidence_id=EvidenceId(root=str(row[3])) if row[3] is not None else None,
            reviewer_id=str(row[4]),
            consent_reference=str(row[5]),
            control_evidence_id=EvidenceId(root=str(row[6])) if row[6] is not None else None,
            case_id=CaseId(root=str(row[7])) if row[7] is not None else None,
            target_digest=str(row[8]) if row[8] is not None else None,
            authorization_digest=str(row[9]) if row[9] is not None else None,
            updated_at=ensure_utc(datetime.fromisoformat(str(row[10]))),
        )


@dataclass(frozen=True, slots=True)
class _Plan:
    sid: str
    server: str
    check_id: str


def _admit(proposal: RepairProposal, oracle: ConnectivityOracle) -> _Plan:
    if len(proposal.operations) != 1:
        raise ActionAuthorizationError("proxy repair requires one operation")
    operation = proposal.operations[0]
    sid = _SID.fullmatch(operation.target.locator)
    if (
        operation.code is not ActionCode.DISABLE_WININET_PROXY
        or operation.target.kind is not TargetKind.WININET_USER_PROXY
        or sid is None
    ):
        raise ActionAuthorizationError("unsupported proxy operation or target")
    params = {item.name: item.value for item in operation.parameters}
    server = params.get("expected_proxy_server")
    check_id = params.get("connectivity_check_id")
    if (
        set(params) != _PARAMS
        or params["expected_proxy_enabled"] is not True
        or params["new_proxy_enabled"] is not False
        or type(server) is not str
        or not server
        or len(server) > 512
        or params["new_proxy_server"] != server
        or type(check_id) is not str
        or re.fullmatch(r"[a-z][a-z0-9_.-]{0,63}", check_id) is None
        or not oracle.supports(check_id)
    ):
        raise ActionAuthorizationError("unsupported proxy parameters or check")
    if (
        len(proposal.verification.checks) != 1
        or proposal.verification.checks[0].code != "connectivity_restored"
        or proposal.verification.checks[0].evidence
        or proposal.verification.minimum_passes != 1
        or len(proposal.preconditions) != 1
        or proposal.preconditions[0].code.value != "target_version_matches"
        or proposal.preconditions[0].target != operation.target
        or proposal.preconditions[0].evidence
    ):
        raise ActionAuthorizationError("missing exact precondition or verification")
    if (
        proposal.risk.level is not RiskLevel.MODERATE
        or proposal.risk.disruption is not DisruptionLevel.NETWORK_INTERRUPTION
        or proposal.risk.data_loss_possible
        or proposal.risk.requires_reboot
    ):
        raise ActionAuthorizationError("proxy repair risk disclosure does not match action")
    return _Plan(sid.group(1), server, check_id)


class ProxyRepairRunner:
    """Execute only a disabled-user-proxy action through injected boundaries."""

    def __init__(
        self,
        *,
        gate: ActionGate,
        journal: ProxyRepairJournal,
        backend: ProxyBackend,
        oracle: ConnectivityOracle,
        current_binding: Callable[[], tuple[int, str]],
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self.gate = gate
        self.journal = journal
        self.backend = backend
        self.oracle = oracle
        self.current_binding = current_binding
        self.clock = clock

    def inspect_interrupted(
        self,
        proposal: RepairProposal,
        token_id: str,
        *,
        now: datetime | None = None,
    ) -> ProxyRecoveryAssessment:
        """Classify a pending action without writing, replaying, or unlocking it.

        The journal can show that a write was *possible*, not that it completed.
        Even an observed intended value is not independent symptom recovery.
        Callers must separately prove the original executor has stopped before
        considering any terminal reconciliation or new authorization.
        """

        record = self.journal.record(token_id)
        if record is None or record.state not in {"claimed", "applying", "uncertain"}:
            raise ActionAuthorizationError("action is not pending reconciliation")
        plan = _admit(proposal, self.oracle)
        target_digest = hashlib.sha256(proposal.operations[0].target.locator.encode()).hexdigest()
        if (
            record.proposal_digest != proposal.digest()
            or record.case_id != proposal.case_id
            or record.target_digest != target_digest
            or record.authorization_digest is None
        ):
            raise ActionAuthorizationError("interrupted action binding does not match")
        if record.state == "claimed":
            return ProxyRecoveryAssessment(
                ProxyRecoveryDisposition.CLAIMED_PENDING, record.state, None
            )
        if (
            record.before_evidence_id is None
            or record.control_evidence_id is None
            or record.before_evidence_id == record.control_evidence_id
        ):
            return ProxyRecoveryAssessment(ProxyRecoveryDisposition.UNAVAILABLE, record.state, None)
        current = ensure_utc(now or self.clock())
        try:
            sid = self.backend.current_user_sid()
            snapshot = self.backend.read()
            observed_at = ensure_utc(snapshot.observed_at)
        except Exception:
            return ProxyRecoveryAssessment(ProxyRecoveryDisposition.UNAVAILABLE, record.state, None)
        if (
            sid != plan.sid
            or snapshot.user_sid != plan.sid
            or type(snapshot.enabled) is not bool
            or not current - timedelta(seconds=5) <= observed_at <= current + timedelta(seconds=5)
            or observed_at < record.updated_at
        ):
            return ProxyRecoveryAssessment(ProxyRecoveryDisposition.UNAVAILABLE, record.state, None)
        if snapshot.server != plan.server:
            disposition = ProxyRecoveryDisposition.DIVERGED
        elif snapshot.enabled:
            disposition = ProxyRecoveryDisposition.ORIGINAL_OBSERVED
        else:
            disposition = ProxyRecoveryDisposition.INTENDED_OBSERVED
        return ProxyRecoveryAssessment(disposition, record.state, observed_at)

    def execute(
        self,
        proposal: RepairProposal,
        token: AuthorizationToken,
        *,
        state_version: int,
        plan_version: str,
        now: datetime | None = None,
        cancelled: Callable[[], bool] | None = None,
        write_permitted: Callable[[], bool] | None = None,
    ) -> ProxyRepairResult:
        is_cancelled = cancelled or (lambda: False)
        current = ensure_utc(now or self.clock())
        initial_binding = self.current_binding()
        if initial_binding != (state_version, plan_version):
            raise ActionAuthorizationError("case binding changed before authorization")
        self.gate.authorize(
            proposal,
            token,
            current_state_version=initial_binding[0],
            current_plan_version=initial_binding[1],
            now=current,
        )
        plan = _admit(proposal, self.oracle)
        self.journal.claim(token, proposal.digest(), proposal.operations[0].target.locator, current)
        before_id: EvidenceId | None = None
        after_id: EvidenceId | None = None
        control_id: EvidenceId | None = None
        attempted = False

        def result(outcome: ProxyRepairOutcome) -> ProxyRepairResult:
            return ProxyRepairResult(outcome, before_id, after_id, control_id)

        try:
            if is_cancelled():
                self.journal.transition(token.token_id, "cancelled")
                return result(ProxyRepairOutcome.CANCELLED)
            before = self.backend.read()
            if (
                self.backend.current_user_sid() != plan.sid
                or before.user_sid != plan.sid
                or before.enabled is not True
                or before.server != plan.server
                or not current - timedelta(seconds=5)
                <= before.observed_at
                <= current + timedelta(seconds=5)
            ):
                self.journal.transition(token.token_id, "precondition_failed")
                return result(ProxyRepairOutcome.PRECONDITION_FAILED)
            before_check = self.oracle.check(plan.check_id)
            before_id = before_check.evidence_id
            if (
                before_check.check_id != plan.check_id
                or before_check.path != "wininet_current_user"
                or before_check.destination_scope != "external"
                or before_check.verdict is not ConnectivityVerdict.WININET_CONNECTIVITY_FAILURE
                or not current - timedelta(seconds=5)
                <= before_check.observed_at
                <= current + timedelta(seconds=10)
                or before_check.observed_at < before.observed_at
                or before_check.passed
            ):
                self.journal.transition(
                    token.token_id, "precondition_failed", before_evidence_id=before_id
                )
                return result(ProxyRepairOutcome.PRECONDITION_FAILED)
            control_check = self.oracle.check_direct_control(plan.check_id)
            control_id = control_check.evidence_id
            if (
                control_check.check_id != plan.check_id
                or control_check.path != "wininet_direct_control"
                or control_check.destination_scope != "external"
                or control_check.verdict is not ConnectivityVerdict.EXPECTED_204
                or control_check.evidence_id == before_id
                or not control_check.passed
                or not before_check.observed_at
                <= control_check.observed_at
                <= current + timedelta(seconds=10)
            ):
                self.journal.transition(
                    token.token_id,
                    "precondition_failed",
                    before_evidence_id=before_id,
                    control_evidence_id=control_id,
                )
                return result(ProxyRepairOutcome.PRECONDITION_FAILED)
            # The oracle may block or another process may change settings while
            # it runs. Revalidate both consent and live state next to the write.
            latest = self.backend.read()
            write_started_at = ensure_utc(self.clock())
            write_binding = self.current_binding()
            self.gate.authorize(
                proposal,
                token,
                current_state_version=write_binding[0],
                current_plan_version=write_binding[1],
                now=write_started_at,
            )
            if (
                self.backend.current_user_sid() != plan.sid
                or latest.user_sid != plan.sid
                or latest.enabled is not True
                or latest.server != plan.server
                or not write_started_at - timedelta(seconds=5)
                <= latest.observed_at
                <= write_started_at + timedelta(seconds=5)
                or not write_started_at - timedelta(seconds=5)
                <= before_check.observed_at
                <= control_check.observed_at
                <= write_started_at
            ):
                self.journal.transition(
                    token.token_id,
                    "precondition_failed",
                    before_evidence_id=before_id,
                    control_evidence_id=control_id,
                )
                return result(ProxyRepairOutcome.PRECONDITION_FAILED)
            if is_cancelled():
                self.journal.transition(
                    token.token_id,
                    "cancelled",
                    before_evidence_id=before_id,
                    control_evidence_id=control_id,
                )
                return result(ProxyRepairOutcome.CANCELLED)
            self.journal.transition(
                token.token_id,
                "applying",
                before_evidence_id=before_id,
                control_evidence_id=control_id,
            )
            attempted = True
            # Cancellation is cooperative at safe points, not atomic with the
            # writer. Once applying is durable, interruption stays uncertain.
            if is_cancelled() or (write_permitted is not None and not write_permitted()):
                self.journal.transition(token.token_id, "uncertain")
                return result(ProxyRepairOutcome.UNCERTAIN)
            self.backend.set_enabled(False)
            after = self.backend.read()
            if (
                after.user_sid != plan.sid
                or after.enabled is not False
                or after.server != before.server
                or after.observed_at <= before.observed_at
            ):
                self.journal.transition(token.token_id, "uncertain")
                return result(ProxyRepairOutcome.UNCERTAIN)
            after_check = self.oracle.check(plan.check_id)
            after_id = after_check.evidence_id
            if (
                after_check.check_id == before_check.check_id
                and after_check.path == before_check.path
                and after_check.destination_scope == before_check.destination_scope
                and after_check.verdict is ConnectivityVerdict.EXPECTED_204
                and after_check.evidence_id != before_check.evidence_id
                and after_check.observed_at > before_check.observed_at
                and after_check.observed_at > after.observed_at
                and after_check.observed_at
                <= write_started_at
                + timedelta(seconds=proposal.expected_effect.maximum_duration_seconds)
                and after_check.passed
            ):
                final_state = self.backend.read()
                if (
                    self.backend.current_user_sid() != plan.sid
                    or final_state.user_sid != plan.sid
                    or final_state.enabled is not False
                    or final_state.server != plan.server
                    or final_state.observed_at < after.observed_at
                ):
                    self.journal.transition(token.token_id, "uncertain", after_evidence_id=after_id)
                    return result(ProxyRepairOutcome.UNCERTAIN)
                self.journal.transition(
                    token.token_id,
                    "verified",
                    before_evidence_id=before_id,
                    after_evidence_id=after_id,
                    control_evidence_id=control_id,
                )
                return result(ProxyRepairOutcome.VERIFIED)
            if proposal.rollback.supported and not proposal.rollback.requires_new_consent:
                # Roll back only if the current state still matches our own write.
                current_state = self.backend.read()
                if (
                    self.backend.current_user_sid() != plan.sid
                    or current_state.user_sid != after.user_sid
                    or current_state.enabled != after.enabled
                    or current_state.server != after.server
                ):
                    self.journal.transition(token.token_id, "uncertain", after_evidence_id=after_id)
                    return result(ProxyRepairOutcome.UNCERTAIN)
                self.backend.set_enabled(True)
                restored = self.backend.read()
                if (
                    self.backend.current_user_sid() == plan.sid
                    and restored.user_sid == plan.sid
                    and restored.enabled is True
                    and restored.server == before.server
                ):
                    self.journal.transition(
                        token.token_id, "rolled_back", after_evidence_id=after_id
                    )
                    return result(ProxyRepairOutcome.ROLLED_BACK)
                self.journal.transition(token.token_id, "uncertain", after_evidence_id=after_id)
                return result(ProxyRepairOutcome.UNCERTAIN)
            self.journal.transition(
                token.token_id, "applied_unverified", after_evidence_id=after_id
            )
            return result(ProxyRepairOutcome.APPLIED_UNVERIFIED)
        except Exception:
            # An interrupted or partially applied write is never replayed.
            self.journal.transition(
                token.token_id,
                "uncertain" if attempted else "precondition_failed",
                before_evidence_id=before_id,
                after_evidence_id=after_id,
                control_evidence_id=control_id,
            )
            return result(
                ProxyRepairOutcome.UNCERTAIN
                if attempted
                else ProxyRepairOutcome.PRECONDITION_FAILED
            )
