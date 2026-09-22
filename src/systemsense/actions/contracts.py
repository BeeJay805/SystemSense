"""Typed proposal and authorization contracts for future state-changing actions.

The investigation boundary remains read-only.  These contracts describe a
separate, deliberately unimplemented boundary: a future executor may consume
an :class:`AuthorizedAction`, but a proposal or model response can never create
one without an independently issued, exact-scope consent token.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field, replace
from datetime import datetime
from enum import StrEnum
from hashlib import sha256
from typing import Literal, Protocol, Self, runtime_checkable
from uuid import uuid4

from pydantic import Field, field_validator, model_validator

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import CaseId, EvidenceId, TargetId
from systemsense.domain.time import UtcDateTime, ensure_utc, utc_now


class ActionKind(StrEnum):
    """The separately governed category of a proposed state change."""

    EXPERIMENT = "experiment"
    REPAIR = "repair"


class TargetKind(StrEnum):
    SERVICE = "service"
    PROCESS = "process"
    DEVICE = "device"
    DRIVER = "driver"
    FILE = "file"
    REGISTRY_VALUE = "registry_value"
    NETWORK_ADAPTER = "network_adapter"


class ActionCode(StrEnum):
    COLLECT_DIAGNOSTIC_SAMPLE = "collect_diagnostic_sample"
    RESTART_SERVICE = "restart_service"
    RESTART_PROCESS = "restart_process"
    RESET_NETWORK_ADAPTER = "reset_network_adapter"
    ROLLBACK_DRIVER = "rollback_driver"
    RESTORE_FILE = "restore_file"
    REPAIR_SERVICE_CONFIGURATION = "repair_service_configuration"


class RiskLevel(StrEnum):
    LOW = "low"
    MODERATE = "moderate"
    HIGH = "high"


class DisruptionLevel(StrEnum):
    NONE = "none"
    PROCESS_RESTART = "process_restart"
    SERVICE_RESTART = "service_restart"
    NETWORK_INTERRUPTION = "network_interruption"
    REBOOT = "reboot"
    DATA_CHANGE = "data_change"


class PreconditionCode(StrEnum):
    EVIDENCE_PRESENT = "evidence_present"
    TARGET_EXISTS = "target_exists"
    TARGET_VERSION_MATCHES = "target_version_matches"
    NO_CONCURRENT_ACTION = "no_concurrent_action"


class ActionAuthorizationError(ValueError):
    """A proposal failed the independent authorization boundary."""

    def __init__(self, reason: str) -> None:
        self.reason = reason
        super().__init__(reason)


class ExactTarget(FrozenModel):
    """A single registered target, never a pattern or a collection."""

    target_id: TargetId
    kind: TargetKind
    locator: str = Field(min_length=1, max_length=512)
    scope: Literal["exact"] = "exact"

    @field_validator("locator")
    @classmethod
    def locator_must_not_be_broad(cls, value: str) -> str:
        if any(marker in value for marker in ("*", "?", "...")):
            raise ValueError("exact target locator cannot contain a wildcard")
        return value


class OperationParameter(FrozenModel):
    """A small typed argument for a registered action code.

    Action parameters are data, not commands.  The executor is responsible for
    mapping a registered code and these values to an implementation; no shell,
    executable, script, URL, or free-form query is representable here.
    """

    name: str = Field(min_length=1, max_length=80, pattern=r"^[a-z][a-z0-9_]*$")
    value: str | int | float | bool

    @field_validator("name")
    @classmethod
    def name_must_not_be_authority_bearing(cls, value: str) -> str:
        if value in {"command", "shell", "executable", "script", "query", "url", "glob"}:
            raise ValueError("arbitrary execution or broadening parameters are forbidden")
        return value


class ActionOperation(FrozenModel):
    """One exact registered operation against one exact target."""

    operation_id: str = Field(min_length=1, max_length=120, pattern=r"^[a-z][a-z0-9_.-]*$")
    code: ActionCode
    kind: ActionKind
    target: ExactTarget
    parameters: tuple[OperationParameter, ...] = ()

    @model_validator(mode="after")
    def unique_parameters(self) -> Self:
        names = [parameter.name for parameter in self.parameters]
        if len(names) != len(set(names)):
            raise ValueError("operation parameters must be unique")
        if (
            self.code is ActionCode.COLLECT_DIAGNOSTIC_SAMPLE
            and self.kind is not ActionKind.EXPERIMENT
        ):
            raise ValueError("diagnostic samples are experiment operations")
        if (
            self.code is not ActionCode.COLLECT_DIAGNOSTIC_SAMPLE
            and self.kind is ActionKind.EXPERIMENT
        ):
            raise ValueError("state-changing operation is not a diagnostic experiment")
        return self


class EvidenceRequirement(FrozenModel):
    """A specific persisted observation required before an action."""

    evidence_id: EvidenceId
    max_age_seconds: int = Field(gt=0, le=31_536_000)
    required_fact: str = Field(min_length=1, max_length=200)


class Precondition(FrozenModel):
    code: PreconditionCode
    evidence: tuple[EvidenceRequirement, ...] = ()
    target: ExactTarget | None = None

    @model_validator(mode="after")
    def validate_required_context(self) -> Self:
        if self.code is PreconditionCode.EVIDENCE_PRESENT and not self.evidence:
            raise ValueError("evidence_present requires evidence requirements")
        if (
            self.code
            in {
                PreconditionCode.TARGET_EXISTS,
                PreconditionCode.TARGET_VERSION_MATCHES,
            }
            and self.target is None
        ):
            raise ValueError("target precondition requires an exact target")
        return self


class ExpectedEffect(FrozenModel):
    summary: str = Field(min_length=1, max_length=1000)
    success_indicators: tuple[str, ...] = Field(min_length=1, max_length=16)
    maximum_duration_seconds: int = Field(default=300, gt=0, le=86_400)


class ProposalRisk(FrozenModel):
    level: RiskLevel
    disruption: DisruptionLevel
    summary: str = Field(min_length=1, max_length=500)
    data_loss_possible: bool = False
    requires_reboot: bool = False


class VerificationCheck(FrozenModel):
    code: str = Field(min_length=1, max_length=120, pattern=r"^[a-z][a-z0-9_.-]*$")
    evidence: tuple[EvidenceRequirement, ...] = ()


class VerificationPlan(FrozenModel):
    checks: tuple[VerificationCheck, ...] = Field(min_length=1, max_length=32)
    minimum_passes: int = Field(default=1, ge=1)

    @model_validator(mode="after")
    def pass_count_is_bounded(self) -> Self:
        if self.minimum_passes > len(self.checks):
            raise ValueError("minimum verification passes cannot exceed checks")
        return self


class RollbackLimits(FrozenModel):
    supported: bool
    max_attempts: int = Field(ge=0, le=3)
    limits: str = Field(min_length=1, max_length=500)
    requires_new_consent: bool = True

    @model_validator(mode="after")
    def supported_has_attempt(self) -> Self:
        if self.supported and self.max_attempts == 0:
            raise ValueError("supported rollback requires an attempt limit")
        if not self.supported and self.max_attempts != 0:
            raise ValueError("unsupported rollback cannot have attempts")
        return self


class ActionProposal(FrozenModel):
    """Common immutable proposal fields shared by experiments and repairs."""

    schema_version: Literal[1] = 1
    proposal_id: str = Field(min_length=1, max_length=120, pattern=r"^proposal_[0-9a-f]{32}$")
    kind: ActionKind
    case_id: CaseId
    case_state_version: int = Field(ge=0)
    plan_version: str = Field(min_length=1, max_length=120, pattern=r"^[a-zA-Z0-9_.:-]+$")
    created_at: UtcDateTime
    expires_at: UtcDateTime
    operations: tuple[ActionOperation, ...] = Field(min_length=1, max_length=32)
    preconditions: tuple[Precondition, ...] = Field(min_length=1, max_length=32)
    expected_effect: ExpectedEffect
    risk: ProposalRisk
    verification: VerificationPlan
    rollback: RollbackLimits

    @model_validator(mode="after")
    def validate_proposal(self) -> Self:
        if self.expires_at <= self.created_at:
            raise ValueError("proposal expiry must be after creation")
        ids = [operation.operation_id for operation in self.operations]
        if len(ids) != len(set(ids)):
            raise ValueError("proposal operation IDs must be unique")
        if any(operation.kind is not self.kind for operation in self.operations):
            raise ValueError("operation kind must match proposal kind")
        if self.kind is ActionKind.REPAIR and self.rollback.supported is False:
            # A repair may be irreversible, but that fact must be explicit in
            # the stated limits; the non-empty limits field provides that audit.
            if not self.rollback.limits:
                raise ValueError("irreversible repair must state rollback limits")
        return self

    def digest(self) -> str:
        """Hash the complete proposal, including its exact operation scope."""

        return _digest_json(self.model_dump(mode="json"))

    def operation_digests(self) -> tuple[str, ...]:
        return tuple(
            _digest_json(operation.model_dump(mode="json")) for operation in self.operations
        )


class DiagnosticExperimentProposal(ActionProposal):
    @model_validator(mode="after")
    def must_be_experiment(self) -> Self:
        if self.kind is not ActionKind.EXPERIMENT:
            raise ValueError("experiment proposal kind must be experiment")
        return self


class RepairProposal(ActionProposal):
    @model_validator(mode="after")
    def must_be_repair(self) -> Self:
        if self.kind is not ActionKind.REPAIR:
            raise ValueError("repair proposal kind must be repair")
        return self


type AnyActionProposal = DiagnosticExperimentProposal | RepairProposal


class HumanConsent(FrozenModel):
    """An independently recorded exact-scope human approval.

    This record is input to an authorization authority; it is not produced by
    a decision or reasoning provider.  The gate later verifies the signed token
    minted from this record.
    """

    reviewer_id: str = Field(min_length=7, max_length=120, pattern=r"^human:[a-zA-Z0-9_.-]+$")
    consent_reference: str = Field(
        min_length=1,
        max_length=120,
        pattern=r"^consent_[a-zA-Z0-9_.-]+$",
    )
    case_id: CaseId
    case_state_version: int = Field(ge=0)
    plan_version: str = Field(min_length=1, max_length=120)
    proposal_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    operation_digests: tuple[str, ...] = Field(min_length=1, max_length=32)
    expires_at: UtcDateTime
    reviewed: bool = False


@dataclass(frozen=True, slots=True)
class AuthorizationToken:
    """Opaque signed exact-scope authorization minted outside model providers."""

    token_id: str
    proposal_digest: str
    operation_digests: tuple[str, ...]
    case_id: CaseId
    case_state_version: int
    plan_version: str
    reviewer_id: str
    issued_at: datetime
    expires_at: datetime
    signature: str = field(repr=False)


class AuthorizationAuthority:
    """Mint and verify consent tokens using a process-local secret.

    An application should keep this authority in a human-consent boundary and
    never provide it to a model provider.  A proposal alone contains no token,
    signature, or permission to call an executor.
    """

    def __init__(self, *, secret: bytes) -> None:
        if len(secret) < 16:
            raise ValueError("authorization secret must be at least 16 bytes")
        self._secret = secret

    def issue(
        self,
        proposal: AnyActionProposal,
        *,
        consent: HumanConsent,
        issued_at: datetime | None = None,
    ) -> AuthorizationToken:
        now = ensure_utc(issued_at or utc_now())
        if not consent.reviewed:
            raise ActionAuthorizationError("unreviewed consent cannot authorize an operation")
        if consent.proposal_digest != proposal.digest():
            raise ActionAuthorizationError("consent proposal does not match proposal")
        if consent.operation_digests != proposal.operation_digests():
            raise ActionAuthorizationError("consent operation scope does not match proposal")
        if consent.case_id != proposal.case_id:
            raise ActionAuthorizationError("consent case does not match proposal")
        if consent.case_state_version != proposal.case_state_version:
            raise ActionAuthorizationError("consent state binding does not match proposal")
        if consent.plan_version != proposal.plan_version:
            raise ActionAuthorizationError("consent plan binding does not match proposal")
        if consent.expires_at <= now or proposal.expires_at <= now:
            raise ActionAuthorizationError("consent or proposal is expired")

        token = AuthorizationToken(
            token_id=f"token_{uuid4().hex}",
            proposal_digest=proposal.digest(),
            operation_digests=proposal.operation_digests(),
            case_id=proposal.case_id,
            case_state_version=proposal.case_state_version,
            plan_version=proposal.plan_version,
            reviewer_id=consent.reviewer_id,
            issued_at=now,
            expires_at=min(consent.expires_at, proposal.expires_at),
            signature="",
        )
        return replace(token, signature=self._sign(token))

    def verify(self, token: AuthorizationToken) -> bool:
        return hmac.compare_digest(token.signature, self._sign(token))

    def _sign(self, token: AuthorizationToken) -> str:
        claims = {
            "token_id": token.token_id,
            "proposal_digest": token.proposal_digest,
            "operation_digests": token.operation_digests,
            "case_id": str(token.case_id),
            "case_state_version": token.case_state_version,
            "plan_version": token.plan_version,
            "reviewer_id": token.reviewer_id,
            "issued_at": token.issued_at.isoformat(),
            "expires_at": token.expires_at.isoformat(),
        }
        payload = json.dumps(claims, sort_keys=True, separators=(",", ":")).encode()
        return hmac.new(self._secret, payload, sha256).hexdigest()


@dataclass(frozen=True, slots=True)
class AuthorizedAction:
    """Capability handed to a future executor only after gate approval."""

    proposal: AnyActionProposal
    token: AuthorizationToken
    authorized_at: datetime


@runtime_checkable
class ActionExecutor(Protocol):
    """Future executor interface; no implementation is shipped here."""

    def execute(self, action: AuthorizedAction) -> ActionExecutionResult: ...


class ActionExecutionResult(FrozenModel):
    """Typed result shape for a future executor's post-action report."""

    succeeded: bool
    verification_summary: str = Field(min_length=1, max_length=1000)
    evidence_ids: tuple[EvidenceId, ...] = ()
    rollback_available: bool = False


class ActionGate:
    """Independent exact-scope authorization gate for future execution."""

    def __init__(self, *, secret: bytes) -> None:
        self._authority = AuthorizationAuthority(secret=secret)

    def authorize(
        self,
        proposal: AnyActionProposal,
        token: AuthorizationToken | None,
        *,
        current_state_version: int,
        current_plan_version: str,
        now: datetime | None = None,
    ) -> AuthorizedAction:
        current = ensure_utc(now or utc_now())
        if token is None:
            raise ActionAuthorizationError("missing authorization token")
        if not self._authority.verify(token):
            raise ActionAuthorizationError("invalid authorization token")
        if current >= token.expires_at or current >= proposal.expires_at:
            raise ActionAuthorizationError("authorization is expired")
        if (
            proposal.case_state_version != current_state_version
            or token.case_state_version != current_state_version
        ):
            raise ActionAuthorizationError("authorization state binding is stale")
        if (
            proposal.plan_version != current_plan_version
            or token.plan_version != current_plan_version
        ):
            raise ActionAuthorizationError("authorization plan binding does not match")
        if token.case_id != proposal.case_id:
            raise ActionAuthorizationError("authorization case binding does not match")
        if token.operation_digests != proposal.operation_digests():
            raise ActionAuthorizationError("authorization operation scope is broadened or changed")
        if token.proposal_digest != proposal.digest():
            raise ActionAuthorizationError("authorization proposal scope does not match")
        return AuthorizedAction(proposal=proposal, token=token, authorized_at=current)


def _digest_json(value: object) -> str:
    canonical = json.dumps(value, sort_keys=True, separators=(",", ":"), default=str).encode()
    return hashlib.sha256(canonical).hexdigest()
