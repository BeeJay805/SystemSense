"""Local-only cloud-session egress contract with an in-process test transport.

Neither these types nor the fake transport open a socket. Production credentials,
user authorization, TLS, retention, and tenant isolation require separate gates.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import math
import re
import secrets
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from typing import Literal, Protocol

from pydantic import Field, StrictFloat, StrictInt, model_validator

from systemsense.decision.candidates import (
    CandidateDecisionGapV1,
    CandidateDecisionRequestV1,
    CandidateDecisionResponseV1,
)
from systemsense.decision.frontier_ranker import FrontierRankRequestV1
from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import CaseId, EvidenceId, JsonValue
from systemsense.domain.time import UtcDateTime
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.reasoning.contracts import ReasoningRequest, ReasoningResponse

type AdvisoryRequest = CandidateDecisionRequestV1 | ReasoningRequest
type AdvisoryResponse = CandidateDecisionResponseV1 | CandidateDecisionGapV1 | ReasoningResponse

type MetricName = Literal[
    "cpu_percent",
    "memory_percent",
    "memory_used_bytes",
    "gpu_utilization_percent",
    "gpu_memory_used_bytes",
    "disk_busy_percent",
    "frame_time_ms",
    "network_latency_ms",
]

_METRIC_UNITS: dict[str, Literal["percent", "bytes", "milliseconds"]] = {
    "cpu_percent": "percent",
    "memory_percent": "percent",
    "memory_used_bytes": "bytes",
    "gpu_utilization_percent": "percent",
    "gpu_memory_used_bytes": "bytes",
    "disk_busy_percent": "percent",
    "frame_time_ms": "milliseconds",
    "network_latency_ms": "milliseconds",
}
_PERCENT_METRICS = frozenset(
    {"cpu_percent", "memory_percent", "gpu_utilization_percent", "disk_busy_percent"}
)
_MAX_DELTA_BYTES = 65_536
_MAX_ATOMS = 128
_MAX_SESSION_DELTAS = 256
_MAX_FAKE_SESSIONS = 128
_MAX_QUESTION_BYTES = 32_768
_MAX_FRONTIER_QUESTION_BYTES = 131_072
_ENTITY_ID = re.compile(r"(?<![A-Za-z0-9_])entity_[0-9a-f]{32}(?![A-Za-z0-9_])")


class CloudSessionError(RuntimeError):
    """Cloud advisory boundary rejected a local export or remote receipt."""


class CloudExportApprovalV1(FrozenModel):
    """A scope description; a trusted local verifier must authorize it on every export."""

    schema_version: Literal[1] = 1
    case_id: CaseId
    expires_at: UtcDateTime
    approved_evidence_ids: tuple[EvidenceId, ...] = Field(min_length=1, max_length=128)
    approved_metrics: tuple[MetricName, ...] = Field(min_length=1, max_length=8)
    approved_objective_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    approved_candidate_descriptions_sha256: str | None = Field(
        default=None, pattern=r"^[0-9a-f]{64}$"
    )
    training_export_allowed: Literal[False] = False

    @model_validator(mode="after")
    def unique_scope(self) -> CloudExportApprovalV1:
        if len(set(self.approved_evidence_ids)) != len(self.approved_evidence_ids):
            raise ValueError("approval repeats evidence ID")
        if len(set(self.approved_metrics)) != len(self.approved_metrics):
            raise ValueError("approval repeats metric")
        return self


class CloudFrontierExportApprovalV2(FrozenModel):
    """Separate consent for exact, session-projected mixed-frontier question bytes.

    The V1 metric grant never implies this richer export. A trusted local
    verifier must reauthorize this exact payload on projection and receipt.
    """

    schema_version: Literal[2] = 2
    case_id: CaseId
    expires_at: UtcDateTime
    approved_evidence_ids: tuple[EvidenceId, ...] = Field(max_length=128)
    approved_payload_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    training_export_allowed: Literal[False] = False

    @model_validator(mode="after")
    def unique_evidence(self) -> CloudFrontierExportApprovalV2:
        if len(set(self.approved_evidence_ids)) != len(self.approved_evidence_ids):
            raise ValueError("V2 approval repeats evidence ID")
        return self


class CloudFrontierChoiceV2(FrozenModel):
    choice_ref: str = Field(pattern=r"^ref_v1_[0-9a-f]{32}$")
    kind: Literal["retrieve_evidence", "measure", "review_branch", "consult_deep"]
    reference_ref: str = Field(pattern=r"^ref_v1_[0-9a-f]{32}$")
    meaning: dict[str, JsonValue]


class CloudFrontierPacketV2(FrozenModel):
    evidence_ref: str = Field(pattern=r"^ref_v1_[0-9a-f]{32}$")
    page_ref: str = Field(pattern=r"^ref_v1_[0-9a-f]{32}$")
    fragment_ref: str = Field(pattern=r"^ref_v1_[0-9a-f]{32}$")
    description: str = Field(min_length=1, max_length=1200)


class CloudFrontierPayloadV2(FrozenModel):
    schema_version: Literal[2] = 2
    provider_id: str = Field(min_length=1, max_length=120)
    provider_version: str = Field(min_length=1, max_length=120)
    model_weight_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    symptom: str = Field(min_length=1, max_length=1000)
    hypothesis_briefs: tuple[str, ...] = Field(default=(), max_length=8)
    evidence_serializer: Literal["semantic_fact_packets_v1"] = "semantic_fact_packets_v1"
    items: tuple[CloudFrontierChoiceV2, ...] = Field(min_length=1, max_length=32)
    evidence_packets: tuple[CloudFrontierPacketV2, ...] = Field(default=(), max_length=64)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(_canonical(self.model_dump(mode="json"))).hexdigest()


class CloudFrontierQuestionV2(FrozenModel):
    schema_version: Literal[2] = 2
    tenant_id: str
    device_id: str
    session_id: str
    case_ref: str
    based_on_sequence: int = Field(ge=1)
    deadline_at: UtcDateTime
    payload: CloudFrontierPayloadV2

    @property
    def sha256(self) -> str:
        return hashlib.sha256(_canonical(self.model_dump(mode="json"))).hexdigest()


class CloudFrontierAdvisoryReceiptV2(FrozenModel):
    schema_version: Literal[2] = 2
    tenant_id: str
    device_id: str
    session_id: str
    case_ref: str
    based_on_sequence: int = Field(ge=1)
    question_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ranked_choice_refs: tuple[str, ...] = Field(min_length=1, max_length=32)
    considered_choice_refs: tuple[str, ...] = Field(min_length=1, max_length=32)
    signature: str = Field(pattern=r"^[0-9a-f]{64}$")


class CloudFrontierRankingV2(FrozenModel):
    """Locally mapped advisory order; no task admission or machine authority."""

    schema_version: Literal[2] = 2
    case_id: CaseId
    question_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    ranked_item_ids: tuple[str, ...] = Field(min_length=1, max_length=32)
    advisory_only: Literal[True] = True


class CloudSessionBindingV1(FrozenModel):
    schema_version: Literal[1] = 1
    tenant_id: str = Field(pattern=r"^tenant_v1_[0-9a-f]{32}$")
    device_id: str = Field(pattern=r"^device_v1_[0-9a-f]{32}$")
    session_id: str = Field(pattern=r"^sess_v1_[0-9a-f]{32}$")
    case_ref: str = Field(pattern=r"^ref_v1_[0-9a-f]{32}$")
    expires_at: UtcDateTime


class CloudEvidenceAtomV1(FrozenModel):
    schema_version: Literal[1] = 1
    evidence_ref: str = Field(pattern=r"^ref_v1_[0-9a-f]{32}$")
    probe_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$", max_length=120)
    metric: MetricName
    value: StrictInt | StrictFloat | None
    unit: Literal["percent", "bytes", "milliseconds"]
    observed_at: UtcDateTime
    captured_at: UtcDateTime
    status: EvidenceContextStatus

    @model_validator(mode="after")
    def validate_metric(self) -> CloudEvidenceAtomV1:
        if self.unit != _METRIC_UNITS[self.metric]:
            raise ValueError("metric unit mismatch")
        if self.value is None:
            if self.status is EvidenceContextStatus.OBSERVED:
                raise ValueError("observed metric needs a value")
        elif not math.isfinite(self.value) or self.value < 0:
            raise ValueError("metric must be finite and nonnegative")
        elif self.metric in _PERCENT_METRICS and self.value > 100:
            raise ValueError("percentage metric exceeds 100")
        elif self.status not in {EvidenceContextStatus.OBSERVED, EvidenceContextStatus.PARTIAL}:
            raise ValueError("unavailable metric cannot carry a value")
        return self


class CloudEvidenceDeltaV1(FrozenModel):
    schema_version: Literal[1] = 1
    tenant_id: str
    device_id: str
    session_id: str
    case_ref: str
    sequence: int = Field(ge=1)
    atoms: tuple[CloudEvidenceAtomV1, ...] = Field(min_length=1, max_length=_MAX_ATOMS)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(_canonical(self.model_dump(mode="json"))).hexdigest()


class CloudDeltaAckV1(FrozenModel):
    schema_version: Literal[1] = 1
    tenant_id: str
    device_id: str
    session_id: str
    case_ref: str
    sequence: int = Field(ge=1)
    delta_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    signature: str = Field(pattern=r"^[0-9a-f]{64}$")


class CloudAdvisoryReceiptV1(FrozenModel):
    """Authenticated advisory only; it cannot contain an action authorization."""

    schema_version: Literal[1] = 1
    tenant_id: str
    device_id: str
    session_id: str
    case_ref: str
    based_on_sequence: int = Field(ge=1)
    question_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    response: AdvisoryResponse
    signature: str = Field(pattern=r"^[0-9a-f]{64}$")


class CloudQuestionChoiceV1(FrozenModel):
    """A locally advertised choice, never an OS selector supplied by the cloud."""

    choice_id: str = Field(min_length=1, max_length=120, pattern=r"^[a-z][a-z0-9_.-]*$")
    cost_ms: int = Field(gt=0, le=120_000)
    resource_class: ResourceClass
    description: str | None = Field(default=None, min_length=1, max_length=240)


class CloudAdvisoryQuestionV1(FrozenModel):
    """The entire permitted cloud-bound question; no raw local request is sent."""

    schema_version: Literal[1] = 1
    tenant_id: str
    device_id: str
    session_id: str
    case_ref: str
    based_on_sequence: int = Field(ge=1)
    role: Literal["fast_decision", "reasoning"]
    state_version: int = Field(ge=0)
    correlation_ref: str = Field(pattern=r"^ref_v1_[0-9a-f]{32}$")
    deadline_at: UtcDateTime
    objective_text: str | None = Field(default=None, min_length=1, max_length=2000)
    evidence_refs: tuple[str, ...] = Field(default=(), max_length=128)
    candidates: tuple[CloudQuestionChoiceV1, ...] = Field(min_length=1, max_length=128)

    @property
    def sha256(self) -> str:
        return hashlib.sha256(_canonical(self.model_dump(mode="json"))).hexdigest()


class CloudDeltaTransport(Protocol):
    """A future authenticated transport adapter, not an endpoint or network client."""

    def accept(self, delta: CloudEvidenceDeltaV1, *, credential: bytes) -> CloudDeltaAckV1: ...


type ApprovalVerifier = Callable[[CloudExportApprovalV1], bool]


class CloudSession:
    """Build bounded deltas locally; never replay an uncertain unacknowledged send."""

    def __init__(
        self,
        *,
        approval: CloudExportApprovalV1,
        binding: CloudSessionBindingV1,
        credential: bytes,
        pseudonym_key: bytes,
        approval_verifier: ApprovalVerifier,
        now: Callable[[], datetime],
    ) -> None:
        self._approval = approval
        self.binding = binding
        self._credential = credential
        self._pseudonym_key = pseudonym_key
        self._approval_verifier = approval_verifier
        self._now = now
        self._next_sequence = 1
        self._pending: CloudEvidenceDeltaV1 | None = None
        self._send_attempted = False
        self._last_atoms_sha256: str | None = None
        self._acked_evidence_refs: set[str] = set()
        self._accepted_advisory_questions: set[str] = set()

    @classmethod
    def open(
        cls,
        *,
        approval: CloudExportApprovalV1,
        tenant_id: str,
        device_id: str,
        credential: bytes,
        approval_verifier: ApprovalVerifier,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> CloudSession:
        if len(credential) < 16:
            raise CloudSessionError("cloud credential is missing or too short")
        if now() >= approval.expires_at or not approval_verifier(approval):
            raise CloudSessionError("case export approval is absent or expired")
        pseudonym_key = secrets.token_bytes(32)
        binding = CloudSessionBindingV1(
            tenant_id=tenant_id,
            device_id=device_id,
            session_id=f"sess_v1_{secrets.token_hex(16)}",
            case_ref=_pseudonym(pseudonym_key, str(approval.case_id)),
            expires_at=min(approval.expires_at, now() + timedelta(minutes=15)),
        )
        return cls(
            approval=approval,
            binding=binding,
            credential=credential,
            pseudonym_key=pseudonym_key,
            approval_verifier=approval_verifier,
            now=now,
        )

    def prepare_delta(self, contexts: Sequence[EvidenceContext]) -> CloudEvidenceDeltaV1:
        self._require_approval()
        if self._next_sequence > _MAX_SESSION_DELTAS:
            raise CloudSessionError("cloud case session delta limit reached")
        approved_ids = set(self._approval.approved_evidence_ids)
        if len(contexts) > 256:
            raise CloudSessionError("evidence input exceeds export bound")
        atoms: list[CloudEvidenceAtomV1] = []
        for context in contexts:
            if context.evidence_id not in approved_ids:
                continue
            for metric in self._approval.approved_metrics:
                present = metric in context.facts
                if not present and context.status is EvidenceContextStatus.OBSERVED:
                    continue
                raw = context.facts[metric] if present else None
                if raw is not None and (isinstance(raw, bool) or not isinstance(raw, (int, float))):
                    raise CloudSessionError("approved metric has an unsafe value type")
                try:
                    atoms.append(
                        CloudEvidenceAtomV1(
                            evidence_ref=_pseudonym(self._pseudonym_key, str(context.evidence_id)),
                            probe_id=context.probe_id,
                            metric=metric,
                            value=raw,
                            unit=_METRIC_UNITS[metric],
                            observed_at=context.observed_at,
                            captured_at=context.captured_at,
                            status=context.status,
                        )
                    )
                except ValueError as error:
                    raise CloudSessionError("approved metric failed typed validation") from error
                if len(atoms) > _MAX_ATOMS:
                    raise CloudSessionError("export atom count exceeds bound")
        if not atoms:
            raise CloudSessionError("no approved typed evidence to export")
        atoms_sha256 = hashlib.sha256(
            _canonical([atom.model_dump(mode="json") for atom in atoms])
        ).hexdigest()
        if self._pending is None and atoms_sha256 == self._last_atoms_sha256:
            raise CloudSessionError("approved evidence is unchanged since the last delta")
        delta = CloudEvidenceDeltaV1(
            tenant_id=self.binding.tenant_id,
            device_id=self.binding.device_id,
            session_id=self.binding.session_id,
            case_ref=self.binding.case_ref,
            sequence=self._next_sequence,
            atoms=tuple(atoms),
        )
        if len(_canonical(delta.model_dump(mode="json"))) > _MAX_DELTA_BYTES:
            raise CloudSessionError("export delta exceeds byte bound")
        if self._pending is not None:
            if delta != self._pending:
                raise CloudSessionError("an unacknowledged delta cannot be replaced or replayed")
            return self._pending
        self._pending = delta
        return delta

    def accept_ack(self, ack: CloudDeltaAckV1) -> None:
        self._require_approval()
        pending = self._pending
        if pending is None or (
            ack.tenant_id != pending.tenant_id
            or ack.device_id != pending.device_id
            or ack.session_id != pending.session_id
            or ack.case_ref != pending.case_ref
            or ack.sequence != pending.sequence
            or ack.delta_sha256 != pending.sha256
        ):
            raise CloudSessionError("cloud delta acknowledgement does not match pending export")
        expected_signature = hmac.new(
            self._credential, _ack_content(ack), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(ack.signature, expected_signature):
            raise CloudSessionError("cloud delta acknowledgement signature mismatch")
        self._acked_evidence_refs.update(atom.evidence_ref for atom in pending.atoms)
        self._last_atoms_sha256 = hashlib.sha256(
            _canonical([atom.model_dump(mode="json") for atom in pending.atoms])
        ).hexdigest()
        self._pending = None
        self._send_attempted = False
        self._next_sequence += 1

    def send_delta(
        self, contexts: Sequence[EvidenceContext], transport: CloudDeltaTransport
    ) -> CloudDeltaAckV1:
        if self._send_attempted:
            raise CloudSessionError("unacknowledged send requires explicit reconciliation")
        delta = self.prepare_delta(contexts)
        self._send_attempted = True
        try:
            ack = transport.accept(delta, credential=self._credential)
        except Exception as error:
            raise CloudSessionError(
                "cloud delta outcome is uncertain; no automatic replay"
            ) from error
        self.accept_ack(ack)
        return ack

    def accept_advisory(
        self, receipt: CloudAdvisoryReceiptV1, *, request: AdvisoryRequest
    ) -> AdvisoryResponse:
        """Authenticate transport provenance, then apply existing local response validation."""

        self._require_approval()
        if (
            receipt.tenant_id != self.binding.tenant_id
            or receipt.device_id != self.binding.device_id
            or receipt.session_id != self.binding.session_id
            or receipt.case_ref != self.binding.case_ref
            or receipt.based_on_sequence != self._next_sequence - 1
        ):
            raise CloudSessionError("cloud advisory binding or evidence sequence mismatch")
        question = self.project_question(request)
        if receipt.question_sha256 != question.sha256:
            raise CloudSessionError("cloud advisory projected question digest mismatch")
        expected_signature = hmac.new(
            self._credential, _advisory_content(receipt), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(receipt.signature, expected_signature):
            raise CloudSessionError("cloud advisory signature mismatch")
        accepted: AdvisoryResponse | None = None
        try:
            if isinstance(request, CandidateDecisionRequestV1) and isinstance(
                receipt.response, (CandidateDecisionResponseV1, CandidateDecisionGapV1)
            ):
                accepted = receipt.response.validate_against(request)
            elif isinstance(request, ReasoningRequest) and isinstance(
                receipt.response, ReasoningResponse
            ):
                accepted = receipt.response.validate_against(request)
        except ValueError as error:
            raise CloudSessionError("cloud advisory local response validation failed") from error
        if accepted is None:
            raise CloudSessionError("cloud advisory local response type does not match request")
        if question.sha256 in self._accepted_advisory_questions:
            raise CloudSessionError("cloud advisory receipt replay rejected")
        self._accepted_advisory_questions.add(question.sha256)
        return accepted

    def project_question(self, request: AdvisoryRequest) -> CloudAdvisoryQuestionV1:
        """Export typed choices and exact-granted text, never raw model request fields."""

        self._require_approval()
        if self._next_sequence <= 1:
            raise CloudSessionError("cloud advisory needs acknowledged approved evidence")
        if request.case_id != self._approval.case_id:
            raise CloudSessionError("cloud advisory request case is not approved")
        if not set(request.evidence_ids).issubset(self._approval.approved_evidence_ids):
            raise CloudSessionError("cloud advisory evidence is not approved for export")
        evidence_refs = tuple(
            _pseudonym(self._pseudonym_key, str(evidence_id))
            for evidence_id in request.evidence_ids
        )
        if not set(evidence_refs).issubset(self._acked_evidence_refs):
            raise CloudSessionError("cloud advisory evidence was not exported and acknowledged")
        if request.deadline_at <= self._now():
            raise CloudSessionError("cloud advisory request deadline expired")
        if isinstance(request, CandidateDecisionRequestV1):
            role: Literal["fast_decision", "reasoning"] = "fast_decision"
            objective = request.symptom
            choices = tuple(
                (item.candidate_id, item.description, item.cost_ms, item.resource_class)
                for item in request.available_candidates
            )
        else:
            role = "reasoning"
            objective = request.objective
            choices = tuple(
                (item.probe_id, item.description, item.cost_ms, item.resource_class)
                for item in request.available_probes
            )
        approved_objective = self._approval.approved_objective_sha256
        if (
            approved_objective is not None
            and hashlib.sha256(objective.encode("utf-8")).hexdigest() != approved_objective
        ):
            raise CloudSessionError("approved objective text changed")
        approved_descriptions = self._approval.approved_candidate_descriptions_sha256
        if (
            approved_descriptions is not None
            and hashlib.sha256(
                _canonical([[choice_id, description] for choice_id, description, _, _ in choices])
            ).hexdigest()
            != approved_descriptions
        ):
            raise CloudSessionError("approved candidate descriptions changed")
        question = CloudAdvisoryQuestionV1(
            tenant_id=self.binding.tenant_id,
            device_id=self.binding.device_id,
            session_id=self.binding.session_id,
            case_ref=self.binding.case_ref,
            based_on_sequence=self._next_sequence - 1,
            role=role,
            state_version=request.state_version,
            correlation_ref=_pseudonym(self._pseudonym_key, request.correlation_id),
            deadline_at=request.deadline_at,
            objective_text=objective if approved_objective is not None else None,
            evidence_refs=evidence_refs,
            candidates=tuple(
                CloudQuestionChoiceV1(
                    choice_id=choice_id,
                    cost_ms=cost_ms,
                    resource_class=resource_class,
                    description=description if approved_descriptions is not None else None,
                )
                for choice_id, description, cost_ms, resource_class in choices
            ),
        )
        if len(_canonical(question.model_dump(mode="json"))) > _MAX_QUESTION_BYTES:
            raise CloudSessionError("cloud advisory question exceeds byte bound")
        return question

    def preview_frontier_payload(self, request: FrontierRankRequestV1) -> CloudFrontierPayloadV2:
        """Build an in-memory, pseudonymized preview for an exact V2 user grant."""

        self._require_approval()
        request = FrontierRankRequestV1.model_validate(request.model_dump(mode="json"))
        if request.case_id != self._approval.case_id:
            raise CloudSessionError("frontier question case is not approved")
        if self._next_sequence <= 1:
            raise CloudSessionError("frontier question needs acknowledged approved evidence")
        if request.deadline_at <= self._now():
            raise CloudSessionError("frontier question deadline expired")
        approved_ids = {str(value) for value in self._approval.approved_evidence_ids}
        choices: list[CloudFrontierChoiceV2] = []
        for item, semantic in zip(request.items, request.item_semantics, strict=True):
            if item.reference.evidence_id is not None:
                evidence_id = str(item.reference.evidence_id)
                if evidence_id not in approved_ids:
                    raise CloudSessionError("frontier item evidence is not approved for export")
                if _pseudonym(self._pseudonym_key, evidence_id) not in self._acked_evidence_refs:
                    raise CloudSessionError(
                        "frontier item evidence was not exported and acknowledged"
                    )
            meaning = semantic.model_dump(
                mode="json",
                exclude={
                    "schema_version",
                    "item_id",
                    "case_id",
                    "reference_id",
                    "source_record_sha256",
                    "relation_id",
                },
            )
            meaning["source_record_ref"] = _pseudonym(
                self._pseudonym_key, semantic.source_record_sha256
            )
            if semantic.relation_id is not None:
                meaning["relation_ref"] = _pseudonym(self._pseudonym_key, semantic.relation_id)
            for label in ("target_label", "relation_source_label", "relation_target_label"):
                value = meaning.get(label)
                if isinstance(value, str):
                    meaning[label] = _ENTITY_ID.sub(
                        lambda match: _pseudonym(self._pseudonym_key, match.group()), value
                    )
            meaning["cost_ms"] = item.cost_ms
            meaning["prerequisite_refs"] = [
                _pseudonym(self._pseudonym_key, value) for value in item.prerequisite_ids
            ]
            meaning["versions"] = item.versions.model_dump(mode="json")
            choices.append(
                CloudFrontierChoiceV2(
                    choice_ref=_pseudonym(self._pseudonym_key, item.item_id),
                    kind=item.reference.kind,
                    reference_ref=_pseudonym(self._pseudonym_key, semantic.reference_id),
                    meaning=meaning,
                )
            )
        packets: list[CloudFrontierPacketV2] = []
        for packet in request.evidence_packets:
            if packet.evidence_id not in approved_ids:
                raise CloudSessionError("frontier packet evidence is not approved for export")
            evidence_ref = _pseudonym(self._pseudonym_key, packet.evidence_id)
            if evidence_ref not in self._acked_evidence_refs:
                raise CloudSessionError(
                    "frontier packet evidence was not exported and acknowledged"
                )
            description = json.loads(packet.description)
            description["evidence_id"] = evidence_ref
            description["page_id"] = _pseudonym(self._pseudonym_key, packet.page_id)
            if "relation_ids" in description:
                description["relation_ids"] = [
                    _pseudonym(self._pseudonym_key, value) for value in description["relation_ids"]
                ]
            packets.append(
                CloudFrontierPacketV2(
                    evidence_ref=evidence_ref,
                    page_ref=_pseudonym(self._pseudonym_key, packet.page_id),
                    fragment_ref=_pseudonym(self._pseudonym_key, packet.fragment_id),
                    description=_canonical(description).decode("utf-8"),
                )
            )
        payload = CloudFrontierPayloadV2(
            provider_id=request.provider.provider_id,
            provider_version=request.provider.provider_version,
            model_weight_sha256=request.model_weight_sha256,
            symptom=request.symptom,
            hypothesis_briefs=request.hypothesis_briefs,
            items=tuple(choices),
            evidence_packets=tuple(packets),
        )
        # Typed semantic packets can carry an identifier again as a *value*.
        # Reject such echoes instead of assuming field-level pseudonymization
        # covered free-text and nested fact values.
        raw_ids = {
            str(request.case_id),
            *(item.item_id for item in request.items),
            *(semantic.reference_id for semantic in request.item_semantics),
            *(semantic.source_record_sha256 for semantic in request.item_semantics),
            *(packet.evidence_id for packet in request.evidence_packets),
            *(packet.page_id for packet in request.evidence_packets),
            *(packet.fragment_id for packet in request.evidence_packets),
        }
        raw_ids.update(
            semantic.relation_id
            for semantic in request.item_semantics
            if semantic.relation_id is not None
        )
        serialized = payload.model_dump_json()
        if any(raw_id in serialized for raw_id in raw_ids) or _ENTITY_ID.search(serialized):
            raise CloudSessionError("frontier payload contains a raw identifier")
        return payload

    def project_frontier_question(
        self,
        request: FrontierRankRequestV1,
        *,
        approval: CloudFrontierExportApprovalV2 | None,
        approval_verifier: Callable[[CloudFrontierExportApprovalV2], bool],
    ) -> CloudFrontierQuestionV2:
        """Export only a locally reviewed exact V2 projection, never the raw request."""

        payload = self.preview_frontier_payload(request)
        if (
            approval is None
            or approval.case_id != request.case_id
            or self._now() >= approval.expires_at
            or not approval_verifier(approval)
            or payload.sha256 != approval.approved_payload_sha256
            or not (
                {packet.evidence_id for packet in request.evidence_packets}
                | {
                    str(item.reference.evidence_id)
                    for item in request.items
                    if item.reference.evidence_id is not None
                }
            ).issubset({str(value) for value in approval.approved_evidence_ids})
        ):
            raise CloudSessionError("frontier V2 approval is absent, expired, or does not match")
        question = CloudFrontierQuestionV2(
            tenant_id=self.binding.tenant_id,
            device_id=self.binding.device_id,
            session_id=self.binding.session_id,
            case_ref=self.binding.case_ref,
            based_on_sequence=self._next_sequence - 1,
            deadline_at=request.deadline_at,
            payload=payload,
        )
        if len(_canonical(question.model_dump(mode="json"))) > _MAX_FRONTIER_QUESTION_BYTES:
            raise CloudSessionError("frontier question exceeds byte bound")
        return question

    def accept_frontier_advisory(
        self,
        receipt: CloudFrontierAdvisoryReceiptV2,
        *,
        request: FrontierRankRequestV1,
        approval: CloudFrontierExportApprovalV2 | None,
        approval_verifier: Callable[[CloudFrontierExportApprovalV2], bool],
    ) -> CloudFrontierRankingV2:
        """Authenticate and map a complete remote ranking back to offered local IDs."""

        question = self.project_frontier_question(
            request, approval=approval, approval_verifier=approval_verifier
        )
        if (
            receipt.tenant_id != question.tenant_id
            or receipt.device_id != question.device_id
            or receipt.session_id != question.session_id
            or receipt.case_ref != question.case_ref
            or receipt.based_on_sequence != question.based_on_sequence
            or receipt.question_sha256 != question.sha256
        ):
            raise CloudSessionError("frontier advisory question or session binding mismatch")
        expected_signature = hmac.new(
            self._credential, _frontier_advisory_content(receipt), hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(receipt.signature, expected_signature):
            raise CloudSessionError("frontier advisory signature mismatch")
        offered = tuple(item.choice_ref for item in question.payload.items)
        ranked = receipt.ranked_choice_refs
        if (
            len(ranked) != len(offered)
            or set(ranked) != set(offered)
            or len(set(ranked)) != len(ranked)
            or receipt.considered_choice_refs != offered
        ):
            raise CloudSessionError("frontier advisory ranking escapes offered choices")
        if question.sha256 in self._accepted_advisory_questions:
            raise CloudSessionError("frontier advisory receipt replay rejected")
        self._accepted_advisory_questions.add(question.sha256)
        local = {ref: item.item_id for ref, item in zip(offered, request.items, strict=True)}
        return CloudFrontierRankingV2(
            case_id=request.case_id,
            question_sha256=question.sha256,
            ranked_item_ids=tuple(local[ref] for ref in ranked),
        )

    def _require_approval(self) -> None:
        if self._now() >= self._approval.expires_at or not self._approval_verifier(self._approval):
            raise CloudSessionError("case export approval is absent or expired")
        if self._now() >= self.binding.expires_at:
            raise CloudSessionError("cloud case session expired")


class InProcessCloudTransport:
    """Deterministic contract fake. Never use it as a production auth server."""

    def __init__(self, *, now: Callable[[], datetime] = lambda: datetime.now(UTC)) -> None:
        self._now = now
        self._sessions: dict[str, tuple[CloudSessionBindingV1, bytes, int]] = {}
        self._accepted: dict[str, list[CloudEvidenceDeltaV1]] = {}

    def register(self, binding: CloudSessionBindingV1, *, credential: bytes) -> None:
        if (
            binding.session_id in self._sessions
            or len(self._sessions) >= _MAX_FAKE_SESSIONS
            or len(credential) < 16
        ):
            raise CloudSessionError("session registration failed")
        self._sessions[binding.session_id] = (binding, credential, 1)
        self._accepted[binding.session_id] = []

    def accept(self, delta: CloudEvidenceDeltaV1, *, credential: bytes) -> CloudDeltaAckV1:
        registered = self._sessions.get(delta.session_id)
        if registered is None:
            raise CloudSessionError("cloud session is unknown")
        binding, expected_credential, next_sequence = registered
        if not hmac.compare_digest(credential, expected_credential):
            raise CloudSessionError("cloud credential rejected")
        if self._now() >= binding.expires_at:
            raise CloudSessionError("cloud session expired")
        if (
            delta.tenant_id != binding.tenant_id
            or delta.device_id != binding.device_id
            or delta.case_ref != binding.case_ref
        ):
            raise CloudSessionError("cloud session binding mismatch")
        if delta.sequence != next_sequence:
            raise CloudSessionError("cloud delta sequence mismatch")
        if delta.sequence > _MAX_SESSION_DELTAS or len(delta.atoms) > _MAX_ATOMS:
            raise CloudSessionError("cloud delta exceeds session bound")
        if len(_canonical(delta.model_dump(mode="json"))) > _MAX_DELTA_BYTES:
            raise CloudSessionError("cloud delta exceeds byte bound")
        self._accepted[delta.session_id].append(delta)
        self._sessions[delta.session_id] = (binding, expected_credential, next_sequence + 1)
        unsigned = CloudDeltaAckV1(
            tenant_id=delta.tenant_id,
            device_id=delta.device_id,
            session_id=delta.session_id,
            case_ref=delta.case_ref,
            sequence=delta.sequence,
            delta_sha256=delta.sha256,
            signature="0" * 64,
        )
        return unsigned.model_copy(
            update={
                "signature": hmac.new(
                    expected_credential, _ack_content(unsigned), hashlib.sha256
                ).hexdigest()
            }
        )

    def approved_context(
        self, binding: CloudSessionBindingV1, *, credential: bytes
    ) -> tuple[CloudEvidenceAtomV1, ...]:
        """Both fake advisory roles see the same approved incremental context."""

        registered = self._sessions.get(binding.session_id)
        if registered is None or registered[0] != binding:
            raise CloudSessionError("cloud context session binding mismatch")
        if not hmac.compare_digest(credential, registered[1]):
            raise CloudSessionError("cloud credential rejected")
        if self._now() >= binding.expires_at:
            raise CloudSessionError("cloud session expired")
        return tuple(atom for delta in self._accepted[binding.session_id] for atom in delta.atoms)

    def issue_advisory(
        self,
        binding: CloudSessionBindingV1,
        *,
        credential: bytes,
        question: CloudAdvisoryQuestionV1,
        response: AdvisoryResponse,
    ) -> CloudAdvisoryReceiptV1:
        """Exercise the response contract after an accepted local fake delta."""

        registered = self._sessions.get(binding.session_id)
        if registered is None or registered[0] != binding or registered[2] < 2:
            raise CloudSessionError("cloud advisory session has no accepted evidence")
        if not hmac.compare_digest(credential, registered[1]):
            raise CloudSessionError("cloud credential rejected")
        if self._now() >= binding.expires_at:
            raise CloudSessionError("cloud session expired")
        if (
            question.tenant_id != binding.tenant_id
            or question.device_id != binding.device_id
            or question.session_id != binding.session_id
            or question.case_ref != binding.case_ref
            or question.based_on_sequence != registered[2] - 1
        ):
            raise CloudSessionError("cloud advisory question binding mismatch")
        unsigned = CloudAdvisoryReceiptV1(
            tenant_id=binding.tenant_id,
            device_id=binding.device_id,
            session_id=binding.session_id,
            case_ref=binding.case_ref,
            based_on_sequence=registered[2] - 1,
            question_sha256=question.sha256,
            response=response,
            signature="0" * 64,
        )
        return unsigned.model_copy(
            update={
                "signature": hmac.new(
                    registered[1], _advisory_content(unsigned), hashlib.sha256
                ).hexdigest()
            }
        )

    def issue_frontier_advisory(
        self,
        binding: CloudSessionBindingV1,
        *,
        credential: bytes,
        question: CloudFrontierQuestionV2,
        ranked_choice_refs: tuple[str, ...],
        considered_choice_refs: tuple[str, ...],
    ) -> CloudFrontierAdvisoryReceiptV2:
        """Sign a local fake frontier response; client still validates all choices."""

        registered = self._sessions.get(binding.session_id)
        if registered is None or registered[0] != binding or registered[2] < 2:
            raise CloudSessionError("cloud frontier session has no accepted evidence")
        if not hmac.compare_digest(credential, registered[1]):
            raise CloudSessionError("cloud credential rejected")
        if self._now() >= binding.expires_at:
            raise CloudSessionError("cloud session expired")
        if (
            question.tenant_id != binding.tenant_id
            or question.device_id != binding.device_id
            or question.session_id != binding.session_id
            or question.case_ref != binding.case_ref
            or question.based_on_sequence != registered[2] - 1
        ):
            raise CloudSessionError("cloud frontier question binding mismatch")
        unsigned = CloudFrontierAdvisoryReceiptV2(
            tenant_id=binding.tenant_id,
            device_id=binding.device_id,
            session_id=binding.session_id,
            case_ref=binding.case_ref,
            based_on_sequence=registered[2] - 1,
            question_sha256=question.sha256,
            ranked_choice_refs=ranked_choice_refs,
            considered_choice_refs=considered_choice_refs,
            signature="0" * 64,
        )
        return unsigned.model_copy(
            update={
                "signature": hmac.new(
                    registered[1], _frontier_advisory_content(unsigned), hashlib.sha256
                ).hexdigest()
            }
        )


def _pseudonym(key: bytes, value: str) -> str:
    return f"ref_v1_{hmac.new(key, value.encode('utf-8'), hashlib.sha256).hexdigest()[:32]}"


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _advisory_content(receipt: CloudAdvisoryReceiptV1) -> bytes:
    return _canonical(receipt.model_dump(mode="json", exclude={"signature"}))


def _frontier_advisory_content(receipt: CloudFrontierAdvisoryReceiptV2) -> bytes:
    return _canonical(receipt.model_dump(mode="json", exclude={"signature"}))


def _ack_content(ack: CloudDeltaAckV1) -> bytes:
    return _canonical(ack.model_dump(mode="json", exclude={"signature"}))
