"""The cloud boundary is executable locally without opening a network socket."""

import hashlib
import json
from datetime import UTC, datetime, timedelta

import pytest

from systemsense.cloud.session import CloudDeltaAckV1, CloudEvidenceDeltaV1
from systemsense.domain.ids import CaseId, EvidenceId, JsonValue
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus

NOW = datetime(2026, 9, 23, 12, tzinfo=UTC)
TENANT_ID = "tenant_v1_" + "a" * 32
DEVICE_ID = "device_v1_" + "b" * 32


def _context(
    evidence_id: EvidenceId,
    *,
    facts: dict[str, JsonValue] | None = None,
    summary: str = "C:\\Users\\Brennen\\private\\password=secret",
) -> EvidenceContext:
    return EvidenceContext(
        evidence_id=evidence_id,
        observed_at=NOW,
        captured_at=NOW,
        probe_id="core.resources",
        summary=summary,
        facts={"cpu_percent": 72.5, **(facts or {})},
        status=EvidenceContextStatus.OBSERVED,
    )


def test_session_projects_only_approved_typed_metrics_and_pseudonyms() -> None:
    from systemsense.cloud.session import CloudExportApprovalV1, CloudSession

    case_id = CaseId.new()
    evidence_id = EvidenceId.new()
    approval = CloudExportApprovalV1(
        case_id=case_id,
        expires_at=NOW + timedelta(minutes=5),
        approved_evidence_ids=(evidence_id,),
        approved_metrics=("cpu_percent",),
    )
    session = CloudSession.open(
        approval=approval,
        tenant_id=TENANT_ID,
        device_id=DEVICE_ID,
        credential=b"test-session-secret",
        approval_verifier=lambda value: value == approval,
        now=lambda: NOW,
    )
    context = _context(
        evidence_id,
        facts={"password": "secret", "username": "Brennen", "memory_used_bytes": 1000},
    )

    delta = session.prepare_delta((context,))
    rendered = delta.model_dump_json()

    assert delta.sequence == 1
    assert len(delta.atoms) == 1
    assert delta.atoms[0].metric == "cpu_percent"
    assert delta.atoms[0].value == 72.5
    assert delta.atoms[0].evidence_ref.startswith("ref_v1_")
    for private in ("Brennen", "private", "password", "secret", str(evidence_id)):
        assert private not in rendered
    assert "memory_used_bytes" not in rendered
    assert session.prepare_delta((context,)) == delta


def test_device_binding_requires_an_opaque_pseudonym_not_a_host_name() -> None:
    from systemsense.cloud.session import CloudExportApprovalV1, CloudSession

    evidence_id = EvidenceId.new()
    approval = CloudExportApprovalV1(
        case_id=CaseId.new(),
        expires_at=NOW + timedelta(minutes=1),
        approved_evidence_ids=(evidence_id,),
        approved_metrics=("cpu_percent",),
    )
    with pytest.raises(ValueError, match="device_id"):
        CloudSession.open(
            approval=approval,
            tenant_id=TENANT_ID,
            device_id="brennen-laptop",
            credential=b"test-session-secret",
            approval_verifier=lambda _value: True,
            now=lambda: NOW,
        )


def test_case_scoped_approval_is_checked_before_each_export() -> None:
    from systemsense.cloud.session import CloudExportApprovalV1, CloudSession, CloudSessionError

    evidence_id = EvidenceId.new()
    approval = CloudExportApprovalV1(
        case_id=CaseId.new(),
        expires_at=NOW + timedelta(minutes=1),
        approved_evidence_ids=(evidence_id,),
        approved_metrics=("cpu_percent",),
    )
    approved = True

    def verify(_approval: CloudExportApprovalV1) -> bool:
        return approved

    session = CloudSession.open(
        approval=approval,
        tenant_id=TENANT_ID,
        device_id=DEVICE_ID,
        credential=b"test-session-secret",
        approval_verifier=verify,
        now=lambda: NOW,
    )
    approved = False
    with pytest.raises(CloudSessionError, match="approval"):
        session.prepare_delta((_context(evidence_id),))


def test_session_expires_after_short_lived_binding_even_with_longer_approval() -> None:
    from systemsense.cloud.session import CloudExportApprovalV1, CloudSession, CloudSessionError

    evidence_id = EvidenceId.new()
    now = NOW
    approval = CloudExportApprovalV1(
        case_id=CaseId.new(),
        expires_at=NOW + timedelta(hours=1),
        approved_evidence_ids=(evidence_id,),
        approved_metrics=("cpu_percent",),
    )
    session = CloudSession.open(
        approval=approval,
        tenant_id=TENANT_ID,
        device_id=DEVICE_ID,
        credential=b"test-session-secret",
        approval_verifier=lambda _value: True,
        now=lambda: now,
    )
    assert session.binding.expires_at == NOW + timedelta(minutes=15)
    now = NOW + timedelta(minutes=16)
    with pytest.raises(CloudSessionError, match="expired"):
        session.prepare_delta((_context(evidence_id),))


def test_export_rejects_secret_in_an_approved_numeric_slot_without_advancing_sequence() -> None:
    from systemsense.cloud.session import CloudExportApprovalV1, CloudSession, CloudSessionError

    evidence_id = EvidenceId.new()
    approval = CloudExportApprovalV1(
        case_id=CaseId.new(),
        expires_at=NOW + timedelta(minutes=1),
        approved_evidence_ids=(evidence_id,),
        approved_metrics=("cpu_percent",),
    )
    session = CloudSession.open(
        approval=approval,
        tenant_id=TENANT_ID,
        device_id=DEVICE_ID,
        credential=b"test-session-secret",
        approval_verifier=lambda _value: True,
        now=lambda: NOW,
    )

    with pytest.raises(CloudSessionError, match="metric"):
        session.prepare_delta((_context(evidence_id, facts={"cpu_percent": "secret"}),))
    assert session.prepare_delta((_context(evidence_id),)).sequence == 1


def test_approved_denied_measurement_exports_typed_gap_without_private_text() -> None:
    from systemsense.cloud.session import CloudExportApprovalV1, CloudSession

    evidence_id = EvidenceId.new()
    approval = CloudExportApprovalV1(
        case_id=CaseId.new(),
        expires_at=NOW + timedelta(minutes=1),
        approved_evidence_ids=(evidence_id,),
        approved_metrics=("cpu_percent",),
    )
    session = CloudSession.open(
        approval=approval,
        tenant_id=TENANT_ID,
        device_id=DEVICE_ID,
        credential=b"test-session-secret",
        approval_verifier=lambda _value: True,
        now=lambda: NOW,
    )
    denied = EvidenceContext(
        evidence_id=evidence_id,
        observed_at=NOW,
        captured_at=NOW,
        probe_id="core.resources",
        summary="access denied for Brennen",
        facts={},
        status=EvidenceContextStatus.DENIED,
        limitations=("C:\\Users\\Brennen\\private",),
    )

    delta = session.prepare_delta((denied,))

    assert delta.atoms[0].status is EvidenceContextStatus.DENIED
    assert delta.atoms[0].value is None
    assert "Brennen" not in delta.model_dump_json()


@pytest.mark.parametrize("unsafe", [True, float("nan"), -1, 1000])
def test_export_rejects_invalid_approved_measurement_values(unsafe: JsonValue) -> None:
    from systemsense.cloud.session import CloudExportApprovalV1, CloudSession, CloudSessionError

    evidence_id = EvidenceId.new()
    approval = CloudExportApprovalV1(
        case_id=CaseId.new(),
        expires_at=NOW + timedelta(minutes=1),
        approved_evidence_ids=(evidence_id,),
        approved_metrics=("cpu_percent",),
    )
    session = CloudSession.open(
        approval=approval,
        tenant_id=TENANT_ID,
        device_id=DEVICE_ID,
        credential=b"test-session-secret",
        approval_verifier=lambda _value: True,
        now=lambda: NOW,
    )

    with pytest.raises(CloudSessionError, match="metric"):
        session.prepare_delta((_context(evidence_id, facts={"cpu_percent": unsafe}),))


def test_fake_transport_binds_identity_credential_and_sequence() -> None:
    from systemsense.cloud.session import (
        CloudExportApprovalV1,
        CloudSession,
        CloudSessionError,
        InProcessCloudTransport,
    )

    evidence_id = EvidenceId.new()
    approval = CloudExportApprovalV1(
        case_id=CaseId.new(),
        expires_at=NOW + timedelta(minutes=1),
        approved_evidence_ids=(evidence_id,),
        approved_metrics=("cpu_percent",),
    )
    session = CloudSession.open(
        approval=approval,
        tenant_id=TENANT_ID,
        device_id=DEVICE_ID,
        credential=b"test-session-secret",
        approval_verifier=lambda _value: True,
        now=lambda: NOW,
    )
    transport = InProcessCloudTransport(now=lambda: NOW)
    transport.register(session.binding, credential=b"test-session-secret")
    first = session.prepare_delta((_context(evidence_id),))

    with pytest.raises(CloudSessionError, match="credential"):
        transport.accept(first, credential=b"wrong")
    ack = transport.accept(first, credential=b"test-session-secret")
    with pytest.raises(CloudSessionError, match="signature"):
        session.accept_ack(ack.model_copy(update={"signature": "0" * 64}))
    session.accept_ack(ack)
    with pytest.raises(CloudSessionError, match="sequence"):
        transport.accept(first, credential=b"test-session-secret")
    with pytest.raises(CloudSessionError, match="sequence"):
        transport.accept(
            first.model_copy(update={"sequence": 3}), credential=b"test-session-secret"
        )
    with pytest.raises(CloudSessionError, match="binding"):
        transport.accept(
            first.model_copy(update={"tenant_id": "tenant-two", "sequence": 2}),
            credential=b"test-session-secret",
        )
    second = session.prepare_delta((_context(evidence_id, facts={"cpu_percent": 64}),))
    assert second.sequence == 2


def test_identical_observation_is_not_sent_as_an_incremental_delta_twice() -> None:
    from systemsense.cloud.session import (
        CloudExportApprovalV1,
        CloudSession,
        CloudSessionError,
        InProcessCloudTransport,
    )

    evidence_id = EvidenceId.new()
    context = _context(evidence_id)
    approval = CloudExportApprovalV1(
        case_id=CaseId.new(),
        expires_at=NOW + timedelta(minutes=1),
        approved_evidence_ids=(evidence_id,),
        approved_metrics=("cpu_percent",),
    )
    session = CloudSession.open(
        approval=approval,
        tenant_id=TENANT_ID,
        device_id=DEVICE_ID,
        credential=b"test-session-secret",
        approval_verifier=lambda _value: True,
        now=lambda: NOW,
    )
    transport = InProcessCloudTransport(now=lambda: NOW)
    transport.register(session.binding, credential=b"test-session-secret")
    session.send_delta((context,), transport)

    with pytest.raises(CloudSessionError, match="unchanged"):
        session.prepare_delta((context,))


def test_approved_session_caps_total_incremental_deltas() -> None:
    from systemsense.cloud.session import (
        CloudExportApprovalV1,
        CloudSession,
        CloudSessionError,
        InProcessCloudTransport,
    )

    evidence_id = EvidenceId.new()
    approval = CloudExportApprovalV1(
        case_id=CaseId.new(),
        expires_at=NOW + timedelta(minutes=1),
        approved_evidence_ids=(evidence_id,),
        approved_metrics=("cpu_percent",),
    )
    session = CloudSession.open(
        approval=approval,
        tenant_id=TENANT_ID,
        device_id=DEVICE_ID,
        credential=b"test-session-secret",
        approval_verifier=lambda _value: True,
        now=lambda: NOW,
    )
    transport = InProcessCloudTransport(now=lambda: NOW)
    transport.register(session.binding, credential=b"test-session-secret")
    for sequence in range(1, 257):
        session.send_delta(
            (_context(evidence_id, facts={"cpu_percent": sequence % 101}),), transport
        )
    assert (
        len(transport.approved_context(session.binding, credential=b"test-session-secret")) == 256
    )
    with pytest.raises(CloudSessionError, match="session delta limit"):
        session.prepare_delta((_context(evidence_id, facts={"cpu_percent": 99}),))


def test_unacknowledged_delta_is_not_silently_replayed_or_replaced() -> None:
    from systemsense.cloud.session import CloudExportApprovalV1, CloudSession, CloudSessionError

    evidence_id = EvidenceId.new()
    approval = CloudExportApprovalV1(
        case_id=CaseId.new(),
        expires_at=NOW + timedelta(minutes=1),
        approved_evidence_ids=(evidence_id,),
        approved_metrics=("cpu_percent",),
    )
    session = CloudSession.open(
        approval=approval,
        tenant_id=TENANT_ID,
        device_id=DEVICE_ID,
        credential=b"test-session-secret",
        approval_verifier=lambda _value: True,
        now=lambda: NOW,
    )
    first = session.prepare_delta((_context(evidence_id),))
    with pytest.raises(CloudSessionError, match="unacknowledged"):
        session.prepare_delta((_context(evidence_id, facts={"cpu_percent": 43}),))
    assert session.prepare_delta((_context(evidence_id),)) == first


def test_session_pseudonyms_are_stable_only_within_one_approved_session() -> None:
    from systemsense.cloud.session import CloudExportApprovalV1, CloudSession

    evidence_id = EvidenceId.new()
    approval = CloudExportApprovalV1(
        case_id=CaseId.new(),
        expires_at=NOW + timedelta(minutes=1),
        approved_evidence_ids=(evidence_id,),
        approved_metrics=("cpu_percent",),
    )

    def open_session() -> CloudSession:
        return CloudSession.open(
            approval=approval,
            tenant_id=TENANT_ID,
            device_id=DEVICE_ID,
            credential=b"test-session-secret",
            approval_verifier=lambda _value: True,
            now=lambda: NOW,
        )

    first, second = open_session(), open_session()
    context = _context(evidence_id)
    assert (
        first.prepare_delta((context,)).atoms[0].evidence_ref
        != second.prepare_delta((context,)).atoms[0].evidence_ref
    )
    assert first.binding.case_ref != second.binding.case_ref


def test_expired_approval_and_failed_transport_leave_no_new_export() -> None:
    from systemsense.cloud.session import CloudExportApprovalV1, CloudSession, CloudSessionError

    evidence_id = EvidenceId.new()
    now = NOW
    approval = CloudExportApprovalV1(
        case_id=CaseId.new(),
        expires_at=NOW + timedelta(minutes=1),
        approved_evidence_ids=(evidence_id,),
        approved_metrics=("cpu_percent",),
    )
    session = CloudSession.open(
        approval=approval,
        tenant_id=TENANT_ID,
        device_id=DEVICE_ID,
        credential=b"test-session-secret",
        approval_verifier=lambda _value: True,
        now=lambda: now,
    )

    class BrokenTransport:
        def accept(self, delta: CloudEvidenceDeltaV1, *, credential: bytes) -> CloudDeltaAckV1:
            del delta, credential
            raise TimeoutError("connection lost after send")

    with pytest.raises(CloudSessionError, match="uncertain"):
        session.send_delta((_context(evidence_id),), BrokenTransport())
    now = NOW + timedelta(minutes=2)
    with pytest.raises(CloudSessionError, match="approval"):
        session.prepare_delta((_context(evidence_id),))


def test_uncertain_send_requires_reconciliation_and_never_automatically_retries() -> None:
    from systemsense.cloud.session import CloudExportApprovalV1, CloudSession, CloudSessionError

    evidence_id = EvidenceId.new()
    approval = CloudExportApprovalV1(
        case_id=CaseId.new(),
        expires_at=NOW + timedelta(minutes=1),
        approved_evidence_ids=(evidence_id,),
        approved_metrics=("cpu_percent",),
    )
    session = CloudSession.open(
        approval=approval,
        tenant_id=TENANT_ID,
        device_id=DEVICE_ID,
        credential=b"test-session-secret",
        approval_verifier=lambda _value: True,
        now=lambda: NOW,
    )
    calls = 0

    class LostAck:
        def accept(self, delta: CloudEvidenceDeltaV1, *, credential: bytes) -> CloudDeltaAckV1:
            nonlocal calls
            del delta, credential
            calls += 1
            raise TimeoutError("ack lost")

    transport = LostAck()
    with pytest.raises(CloudSessionError, match="uncertain"):
        session.send_delta((_context(evidence_id),), transport)
    with pytest.raises(CloudSessionError, match="reconciliation"):
        session.send_delta((_context(evidence_id),), transport)
    assert calls == 1


def test_signed_advisory_is_bound_to_session_ack_request_and_local_contract() -> None:
    from systemsense.cloud.session import (
        CloudExportApprovalV1,
        CloudSession,
        CloudSessionError,
        InProcessCloudTransport,
    )
    from systemsense.decision.candidates import (
        AdmittedCandidateRefV1,
        CandidateDecisionGapV1,
        CandidateDecisionRequestV1,
    )
    from systemsense.decision.contracts import ProviderIdentity
    from systemsense.domain.probes import SafetyClass
    from systemsense.orchestration.scheduler import ResourceClass

    evidence_id = EvidenceId.new()
    case_id = CaseId.new()
    approval = CloudExportApprovalV1(
        case_id=case_id,
        expires_at=NOW + timedelta(minutes=1),
        approved_evidence_ids=(evidence_id,),
        approved_metrics=("cpu_percent",),
    )
    session = CloudSession.open(
        approval=approval,
        tenant_id=TENANT_ID,
        device_id=DEVICE_ID,
        credential=b"test-session-secret",
        approval_verifier=lambda _value: True,
        now=lambda: NOW,
    )
    transport = InProcessCloudTransport(now=lambda: NOW)
    transport.register(session.binding, credential=b"test-session-secret")
    exported = session.prepare_delta((_context(evidence_id),))
    session.accept_ack(transport.accept(exported, credential=b"test-session-secret"))
    request = CandidateDecisionRequestV1(
        case_id=case_id,
        state_version=2,
        correlation_id="corr-1",
        deadline_at=NOW + timedelta(seconds=30),
        symptom="slow PDF",
        evidence_ids=(evidence_id,),
        available_candidates=(
            AdmittedCandidateRefV1(
                candidate_id="cand_v1_" + "a" * 32,
                probe_id="core.resources",
                description="Read CPU",
                manifest_sha256="b" * 64,
                invocation_sha256="c" * 64,
                cost_ms=100,
                resource_class=ResourceClass.CPU,
                safety_class=SafetyClass.R0,
            ),
        ),
        budget_ms=1000,
        max_candidates=1,
    )
    response = CandidateDecisionGapV1(
        provider=ProviderIdentity(
            provider_id="cloud-fast", provider_version="test-1", role="fast_decision"
        ),
        case_id=case_id,
        state_version=2,
        correlation_id="corr-1",
        deadline_at=request.deadline_at,
        reason_code="ranker_unavailable",
    )
    question = session.project_question(request)
    rendered_question = question.model_dump_json()
    assert "slow PDF" not in rendered_question
    assert "Read CPU" not in rendered_question
    assert str(evidence_id) not in rendered_question
    assert question.candidates[0].choice_id == request.available_candidates[0].candidate_id
    with pytest.raises(CloudSessionError, match="credential"):
        transport.approved_context(session.binding, credential=b"wrong")
    receipt = transport.issue_advisory(
        session.binding,
        credential=b"test-session-secret",
        question=question,
        response=response,
    )

    assert (
        transport.approved_context(session.binding, credential=b"test-session-secret")
        == exported.atoms
    )
    assert session.accept_advisory(receipt, request=request) == response
    with pytest.raises(CloudSessionError, match="replay"):
        session.accept_advisory(receipt, request=request)
    with pytest.raises(CloudSessionError, match="binding"):
        session.accept_advisory(receipt.model_copy(update={"tenant_id": "other"}), request=request)
    with pytest.raises(CloudSessionError, match="signature"):
        session.accept_advisory(receipt.model_copy(update={"signature": "0" * 64}), request=request)
    with pytest.raises(CloudSessionError, match="question"):
        session.accept_advisory(
            receipt,
            request=request.model_copy(update={"state_version": 3}),
        )
    forged = response.model_copy(update={"case_id": CaseId.new()})
    forged_receipt = transport.issue_advisory(
        session.binding,
        credential=b"test-session-secret",
        question=question,
        response=forged,
    )
    with pytest.raises(CloudSessionError, match="local response"):
        session.accept_advisory(forged_receipt, request=request)


def test_advisory_rejects_request_referencing_evidence_outside_export_approval() -> None:
    from systemsense.cloud.session import (
        CloudExportApprovalV1,
        CloudSession,
        CloudSessionError,
        InProcessCloudTransport,
    )
    from systemsense.decision.candidates import (
        AdmittedCandidateRefV1,
        CandidateDecisionGapV1,
        CandidateDecisionRequestV1,
    )
    from systemsense.decision.contracts import ProviderIdentity
    from systemsense.domain.probes import SafetyClass
    from systemsense.orchestration.scheduler import ResourceClass

    approved_id, unapproved_id = EvidenceId.new(), EvidenceId.new()
    case_id = CaseId.new()
    approval = CloudExportApprovalV1(
        case_id=case_id,
        expires_at=NOW + timedelta(minutes=1),
        approved_evidence_ids=(approved_id,),
        approved_metrics=("cpu_percent",),
    )
    session = CloudSession.open(
        approval=approval,
        tenant_id=TENANT_ID,
        device_id=DEVICE_ID,
        credential=b"test-session-secret",
        approval_verifier=lambda _value: True,
        now=lambda: NOW,
    )
    transport = InProcessCloudTransport(now=lambda: NOW)
    transport.register(session.binding, credential=b"test-session-secret")
    session.accept_ack(
        transport.accept(
            session.prepare_delta((_context(approved_id),)), credential=b"test-session-secret"
        )
    )
    request = CandidateDecisionRequestV1(
        case_id=case_id,
        state_version=1,
        correlation_id="corr-2",
        deadline_at=NOW + timedelta(seconds=30),
        symptom="slow PDF",
        evidence_ids=(approved_id, unapproved_id),
        available_candidates=(
            AdmittedCandidateRefV1(
                candidate_id="cand_v1_" + "a" * 32,
                probe_id="core.resources",
                description="Read CPU",
                manifest_sha256="b" * 64,
                invocation_sha256="c" * 64,
                cost_ms=100,
                resource_class=ResourceClass.CPU,
                safety_class=SafetyClass.R0,
            ),
        ),
        budget_ms=1000,
        max_candidates=1,
    )
    response = CandidateDecisionGapV1(
        provider=ProviderIdentity(
            provider_id="cloud-fast", provider_version="test-1", role="fast_decision"
        ),
        case_id=case_id,
        state_version=1,
        correlation_id="corr-2",
        deadline_at=request.deadline_at,
        reason_code="ranker_unavailable",
    )
    # The local request includes an evidence ID outside the approved cloud scope.
    # A projected question must fail before any fake transport call.
    with pytest.raises(CloudSessionError, match="not approved"):
        session.project_question(request)
    question = session.project_question(request.model_copy(update={"evidence_ids": (approved_id,)}))
    receipt = transport.issue_advisory(
        session.binding,
        credential=b"test-session-secret",
        question=question,
        response=response,
    )
    with pytest.raises(CloudSessionError, match="not approved"):
        session.accept_advisory(receipt, request=request)


def test_deep_brain_receipt_uses_same_approved_session_and_local_validation() -> None:
    from systemsense.cloud.session import (
        CloudExportApprovalV1,
        CloudSession,
        InProcessCloudTransport,
    )
    from systemsense.decision.contracts import ProbeCapability, ProviderIdentity
    from systemsense.domain.probes import SafetyClass
    from systemsense.orchestration.scheduler import ResourceClass
    from systemsense.reasoning.contracts import (
        ReasoningRequest,
        ReasoningResponse,
        ReasoningStatus,
    )

    evidence_id, case_id = EvidenceId.new(), CaseId.new()
    approval = CloudExportApprovalV1(
        case_id=case_id,
        expires_at=NOW + timedelta(minutes=1),
        approved_evidence_ids=(evidence_id,),
        approved_metrics=("cpu_percent",),
    )
    session = CloudSession.open(
        approval=approval,
        tenant_id=TENANT_ID,
        device_id=DEVICE_ID,
        credential=b"test-session-secret",
        approval_verifier=lambda _value: True,
        now=lambda: NOW,
    )
    transport = InProcessCloudTransport(now=lambda: NOW)
    transport.register(session.binding, credential=b"test-session-secret")
    session.send_delta((_context(evidence_id),), transport)
    request = ReasoningRequest(
        case_id=case_id,
        state_version=3,
        correlation_id="Brennen.private_case",
        deadline_at=NOW + timedelta(seconds=30),
        objective="slow PDF",
        evidence_ids=(evidence_id,),
        evidence_context=(_context(evidence_id, summary="approved local-only context"),),
        available_probes=(
            ProbeCapability(
                probe_id="core.resources",
                description="Read resources",
                cost_ms=100,
                resource_class=ResourceClass.CPU,
                safety_class=SafetyClass.R0,
            ),
        ),
        budget_ms=1000,
        max_probes=1,
    )
    response = ReasoningResponse(
        provider=ProviderIdentity(
            provider_id="cloud-reasoner", provider_version="test-1", role="reasoning"
        ),
        case_id=case_id,
        state_version=3,
        correlation_id="Brennen.private_case",
        deadline_at=request.deadline_at,
        status=ReasoningStatus.UNAVAILABLE,
        summary="No supported diagnosis",
        considered_evidence_ids=(evidence_id,),
    )
    question = session.project_question(request)
    assert question.role == "reasoning"
    assert "slow PDF" not in question.model_dump_json()
    assert "Brennen" not in question.model_dump_json()
    assert "approved local-only context" not in question.model_dump_json()
    assert question.correlation_ref.startswith("ref_v1_")
    receipt = transport.issue_advisory(
        session.binding,
        credential=b"test-session-secret",
        question=question,
        response=response,
    )

    assert session.accept_advisory(receipt, request=request) == response


def test_exact_text_grant_exports_only_the_approved_objective_and_candidate_descriptions() -> None:
    from systemsense.cloud.session import (
        CloudExportApprovalV1,
        CloudSession,
        CloudSessionError,
        InProcessCloudTransport,
    )
    from systemsense.decision.contracts import ProbeCapability
    from systemsense.domain.probes import SafetyClass
    from systemsense.orchestration.scheduler import ResourceClass
    from systemsense.reasoning.contracts import ReasoningRequest

    objective = "PDF viewer uses CPU"
    descriptions = [["core.resources", "Read resources"]]
    description_bytes = json.dumps(descriptions, sort_keys=True, separators=(",", ":")).encode()
    evidence_id, case_id = EvidenceId.new(), CaseId.new()
    approval = CloudExportApprovalV1(
        case_id=case_id,
        expires_at=NOW + timedelta(minutes=1),
        approved_evidence_ids=(evidence_id,),
        approved_metrics=("cpu_percent",),
        approved_objective_sha256=hashlib.sha256(objective.encode()).hexdigest(),
        approved_candidate_descriptions_sha256=hashlib.sha256(description_bytes).hexdigest(),
    )
    session = CloudSession.open(
        approval=approval,
        tenant_id=TENANT_ID,
        device_id=DEVICE_ID,
        credential=b"test-session-secret",
        approval_verifier=lambda _value: True,
        now=lambda: NOW,
    )
    transport = InProcessCloudTransport(now=lambda: NOW)
    transport.register(session.binding, credential=b"test-session-secret")
    session.send_delta((_context(evidence_id),), transport)
    request = ReasoningRequest(
        case_id=case_id,
        state_version=1,
        correlation_id="reasoning-2",
        deadline_at=NOW + timedelta(seconds=30),
        objective=objective,
        evidence_ids=(evidence_id,),
        available_probes=(
            ProbeCapability(
                probe_id="core.resources",
                description="Read resources",
                cost_ms=100,
                resource_class=ResourceClass.CPU,
                safety_class=SafetyClass.R0,
            ),
        ),
        budget_ms=1000,
        max_probes=1,
    )

    question = session.project_question(request)

    assert question.objective_text == objective
    assert question.candidates[0].description == "Read resources"
    with pytest.raises(CloudSessionError, match="approved objective"):
        session.project_question(request.model_copy(update={"objective": "changed symptom"}))


def test_frontier_v2_exact_grant_projects_semantics_and_validates_remote_order() -> None:
    from systemsense.cloud.session import (
        CloudExportApprovalV1,
        CloudFrontierExportApprovalV2,
        CloudSession,
        CloudSessionError,
        InProcessCloudTransport,
    )
    from systemsense.decision.contracts import ProviderIdentity
    from systemsense.decision.frontier_ranker import (
        FrontierItemSemanticV1,
        FrontierRankRequestV1,
        SemanticPacketRefV1,
    )
    from systemsense.decision.semantic_packets import evidence_packets
    from systemsense.evidence.graph import AssertionStatus, RelationKind
    from systemsense.storage.search_frontier import (
        FrontierItemV1,
        FrontierReferenceV1,
        FrontierStatus,
        RelevantVersionsV1,
    )

    evidence_id, case_id = EvidenceId.new(), CaseId.new()
    approval = CloudExportApprovalV1(
        case_id=case_id,
        expires_at=NOW + timedelta(minutes=5),
        approved_evidence_ids=(evidence_id,),
        approved_metrics=("cpu_percent",),
    )
    session = CloudSession.open(
        approval=approval,
        tenant_id=TENANT_ID,
        device_id=DEVICE_ID,
        credential=b"test-session-secret",
        approval_verifier=lambda value: value == approval,
        now=lambda: NOW,
    )
    transport = InProcessCloudTransport(now=lambda: NOW)
    transport.register(session.binding, credential=b"test-session-secret")
    context = _context(evidence_id, summary="private source", facts={"gpu.clock": 450})
    session.send_delta((context,), transport)
    packet = SemanticPacketRefV1.model_validate(evidence_packets((context,))[0])
    graph_source_id = "entity_" + "3" * 32
    graph_target_id = "entity_" + "4" * 32
    items = (
        FrontierItemV1(
            item_id="fr_v1_" + "a" * 64,
            case_id=case_id,
            reference=FrontierReferenceV1(kind="retrieve_evidence", evidence_id=evidence_id),
            versions=RelevantVersionsV1(objective=1, evidence=1),
            status=FrontierStatus.REQUESTED,
            created_at=NOW,
        ),
        FrontierItemV1(
            item_id="fr_v1_" + "b" * 64,
            case_id=case_id,
            reference=FrontierReferenceV1(kind="measure", candidate_id="cand_v1_" + "c" * 32),
            versions=RelevantVersionsV1(objective=1, capabilities=1),
            status=FrontierStatus.REQUESTED,
            created_at=NOW,
        ),
        FrontierItemV1(
            item_id="fr_v1_" + "c" * 64,
            case_id=case_id,
            reference=FrontierReferenceV1(kind="review_branch", branch_id="branch_v1_" + "5" * 32),
            versions=RelevantVersionsV1(objective=1, graph=1),
            status=FrontierStatus.REQUESTED,
            created_at=NOW,
        ),
    )
    semantics = (
        FrontierItemSemanticV1(
            item_id=items[0].item_id,
            case_id=case_id,
            reference_id=str(evidence_id),
            source_kind="evidence_repository",
            source_record_sha256="d" * 64,
            source_recorded_at=NOW,
            source_time_quality="source_recorded",
            quality="observed",
            information_goal="What did this observation show?",
            target_scope="host",
            target_label="Computer",
        ),
        FrontierItemSemanticV1(
            item_id=items[1].item_id,
            case_id=case_id,
            reference_id="cand_v1_" + "c" * 32,
            source_kind="capability_registry",
            source_record_sha256="e" * 64,
            source_recorded_at=NOW,
            source_time_quality="source_recorded",
            quality="documented",
            information_goal="What are current GPU clocks?",
            target_scope="device",
            target_label="GPU",
        ),
        FrontierItemSemanticV1(
            item_id=items[2].item_id,
            case_id=case_id,
            reference_id="branch_v1_" + "5" * 32,
            source_kind="knowledge_graph",
            source_record_sha256="6" * 64,
            source_recorded_at=NOW,
            source_time_quality="source_recorded",
            quality="inferred",
            information_goal="Could this graph dependency explain low clocks?",
            target_scope="component",
            target_label=graph_target_id,
            relation_id="rel_" + "7" * 32,
            relation_kind=RelationKind.USES_DRIVER,
            relation_assertion_status=AssertionStatus.INFERRED,
            relation_source_label=graph_source_id,
            relation_target_label=graph_target_id,
        ),
    )
    request = FrontierRankRequestV1(
        case_id=case_id,
        provider=ProviderIdentity(
            provider_id="cloud-fast", provider_version="test-1", role="fast_decision"
        ),
        model_weight_sha256="f" * 64,
        deadline_at=NOW + timedelta(seconds=30),
        symptom="Private game runs slowly",
        items=items,
        item_semantics=semantics,
        evidence_packets=(packet,),
    )
    identifier_in_value = SemanticPacketRefV1.model_validate(
        evidence_packets((_context(evidence_id, facts={"gpu.clock": str(evidence_id)}),))[1]
    )
    with pytest.raises(CloudSessionError, match="raw identifier"):
        session.preview_frontier_payload(
            request.model_copy(update={"evidence_packets": (identifier_in_value,)})
        )
    preview = session.preview_frontier_payload(request)
    serialized = preview.model_dump_json()
    assert "What are current GPU clocks?" in serialized
    assert "cpu_percent" in serialized
    assert "Private game runs slowly" in serialized
    assert str(evidence_id) not in serialized
    assert items[0].item_id not in serialized
    assert graph_source_id not in serialized
    assert graph_target_id not in serialized
    for label in ("target_label", "relation_source_label", "relation_target_label"):
        projected_label = preview.items[2].meaning[label]
        assert isinstance(projected_label, str)
        assert projected_label.startswith("ref_v1_")
    unprojected_goal = semantics[2].model_copy(
        update={"information_goal": f"Does {graph_target_id} still matter?"}
    )
    with pytest.raises(CloudSessionError, match="raw identifier"):
        session.preview_frontier_payload(
            request.model_copy(update={"item_semantics": (*semantics[:2], unprojected_goal)})
        )
    assert semantics[0].source_record_sha256 not in serialized
    assert packet.page_id not in serialized
    assert packet.fragment_id not in serialized
    assert "private source" not in serialized
    with pytest.raises(CloudSessionError, match="V2 approval"):
        session.project_frontier_question(request, approval=None, approval_verifier=lambda _: True)
    frontier_approval = CloudFrontierExportApprovalV2(
        case_id=case_id,
        expires_at=NOW + timedelta(minutes=1),
        approved_evidence_ids=(evidence_id,),
        approved_payload_sha256=preview.sha256,
    )
    question = session.project_frontier_question(
        request,
        approval=frontier_approval,
        approval_verifier=lambda value: value == frontier_approval,
    )
    assert question.payload == preview
    offered = tuple(item.choice_ref for item in question.payload.items)
    with pytest.raises(CloudSessionError, match="V2 approval"):
        session.project_frontier_question(
            request.model_copy(update={"symptom": "A different symptom"}),
            approval=frontier_approval,
            approval_verifier=lambda _: True,
        )
    with pytest.raises(CloudSessionError, match="V2 approval"):
        session.project_frontier_question(
            request.model_copy(update={"model_weight_sha256": "1" * 64}),
            approval=frontier_approval,
            approval_verifier=lambda _: True,
        )
    with pytest.raises(CloudSessionError, match="V2 approval"):
        session.project_frontier_question(
            request, approval=frontier_approval, approval_verifier=lambda _: False
        )
    other_packet = SemanticPacketRefV1.model_validate(
        evidence_packets((_context(EvidenceId.new()),))[0]
    )
    with pytest.raises(CloudSessionError, match="not approved"):
        session.preview_frontier_payload(
            request.model_copy(update={"evidence_packets": (packet, other_packet)})
        )
    unapproved_id = EvidenceId.new()
    unapproved_item = items[0].model_copy(
        update={
            "reference": FrontierReferenceV1(kind="retrieve_evidence", evidence_id=unapproved_id)
        }
    )
    unapproved_semantic = semantics[0].model_copy(update={"reference_id": str(unapproved_id)})
    with pytest.raises(CloudSessionError, match="not approved"):
        session.preview_frontier_payload(
            request.model_copy(
                update={
                    "items": (unapproved_item, *items[1:]),
                    "item_semantics": (unapproved_semantic, *semantics[1:]),
                }
            )
        )
    receipt = transport.issue_frontier_advisory(
        session.binding,
        credential=b"test-session-secret",
        question=question,
        ranked_choice_refs=tuple(reversed(offered)),
        considered_choice_refs=offered,
    )
    with pytest.raises(CloudSessionError, match="signature"):
        session.accept_frontier_advisory(
            receipt.model_copy(update={"signature": "0" * 64}),
            request=request,
            approval=frontier_approval,
            approval_verifier=lambda _: True,
        )
    incomplete = transport.issue_frontier_advisory(
        session.binding,
        credential=b"test-session-secret",
        question=question,
        ranked_choice_refs=offered[:1],
        considered_choice_refs=offered,
    )
    with pytest.raises(CloudSessionError, match="offered choices"):
        session.accept_frontier_advisory(
            incomplete,
            request=request,
            approval=frontier_approval,
            approval_verifier=lambda _: True,
        )
    alien = transport.issue_frontier_advisory(
        session.binding,
        credential=b"test-session-secret",
        question=question,
        ranked_choice_refs=(offered[0], "ref_v1_" + "0" * 32),
        considered_choice_refs=offered,
    )
    with pytest.raises(CloudSessionError, match="offered choices"):
        session.accept_frontier_advisory(
            alien,
            request=request,
            approval=frontier_approval,
            approval_verifier=lambda _: True,
        )
    ranking = session.accept_frontier_advisory(
        receipt,
        request=request,
        approval=frontier_approval,
        approval_verifier=lambda value: value == frontier_approval,
    )
    assert ranking.ranked_item_ids == tuple(reversed(tuple(item.item_id for item in items)))
    with pytest.raises(CloudSessionError, match="replay"):
        session.accept_frontier_advisory(
            receipt,
            request=request,
            approval=frontier_approval,
            approval_verifier=lambda value: value == frontier_approval,
        )


def test_frontier_v2_grant_requires_digest_shape() -> None:
    from systemsense.cloud.session import CloudFrontierExportApprovalV2

    # V2 is a separate explicit grant; changing even one projected byte invalidates it.
    with pytest.raises(ValueError, match="approved_payload_sha256"):
        CloudFrontierExportApprovalV2(
            case_id=CaseId.new(),
            expires_at=NOW + timedelta(minutes=1),
            approved_evidence_ids=(EvidenceId.new(),),
            approved_payload_sha256="bad",
        )
