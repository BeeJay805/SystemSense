from datetime import UTC, datetime, timedelta

import pytest

from systemsense.application.assessment import (
    AssessmentDisposition,
    ObservedClaimKind,
    assess_investigation,
)
from systemsense.application.investigation_state import InvestigationState
from systemsense.domain.ids import CaseId, EvidenceId
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.reasoning.contracts import Hypothesis, HypothesisStatus

NOW = datetime(2026, 9, 22, 12, 0, tzinfo=UTC)
LISTENER_EVIDENCE = EvidenceId(root="ev_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")


def _state(
    *,
    objective: str,
    hypothesis: Hypothesis,
    completed: tuple[str, ...],
) -> InvestigationState:
    return InvestigationState(
        case_id=CaseId(root="case_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        objective=objective,
        created_at=NOW,
        updated_at=NOW,
        deadline_at=NOW + timedelta(minutes=3),
        incident_start=NOW - timedelta(minutes=15),
        incident_end=NOW + timedelta(minutes=5),
        budget_ms=180_000,
        completed_probe_ids=completed,
        hypotheses=(hypothesis,),
    )


def _context(
    evidence_id: EvidenceId,
    probe_id: str,
    facts: dict[str, object],
    *,
    limitations: tuple[str, ...] = (),
) -> EvidenceContext:
    return EvidenceContext.model_validate(
        {
            "evidence_id": str(evidence_id),
            "observed_at": NOW.isoformat(),
            "captured_at": NOW.isoformat(),
            "probe_id": probe_id,
            "summary": "exact observed fixture",
            "facts": facts,
            "status": EvidenceContextStatus.OBSERVED.value,
            "limitations": limitations,
        }
    )


def _hypothesis(
    evidence_id: EvidenceId,
    *,
    statement: str = "A model-authored statement must not define the verified claim.",
    contradicting: tuple[EvidenceId, ...] = (),
    missing: tuple[EvidenceId, ...] = (),
    probes: tuple[str, ...] = (),
) -> Hypothesis:
    return Hypothesis(
        hypothesis_id="candidate",
        statement=statement,
        status=HypothesisStatus.UNRESOLVED,
        supporting_evidence_ids=(evidence_id,),
        contradicting_evidence_ids=contradicting,
        missing_evidence_ids=missing,
        distinguishing_probe_ids=probes,
    )


def test_exact_listener_owner_can_complete_without_endorsing_model_causality() -> None:
    state = _state(
        objective="Which process owns port 18765?",
        hypothesis=_hypothesis(
            LISTENER_EVIDENCE,
            statement="The GPU caused the problem and also owns the port.",
            probes=("network.listeners",),
        ),
        completed=("network.listeners",),
    )
    context = _context(
        LISTENER_EVIDENCE,
        "network.listeners",
        {
            "listeners": [
                {
                    "protocol": "tcp4",
                    "local_address": "127.0.0.1",
                    "local_port": 18765,
                    "pid": 4242,
                    "process_name": "systemsense-preview.exe",
                    "process_creation_time": NOW.isoformat(),
                    "owner_status": "available",
                }
            ],
            "omitted_listener_count": 0,
            "collection_status": "available",
        },
    )

    result = assess_investigation(state=state, context=(context,), relationships=())

    assert result.disposition is AssessmentDisposition.SUPPORTED_OBSERVED_EXPLANATION
    assert result.claim_kind is ObservedClaimKind.LISTENER_OWNER
    assert result.evidence_ids == (LISTENER_EVIDENCE,)
    assert "18765" in result.explanation
    assert "4242" in result.explanation
    assert "systemsense-preview.exe" in result.explanation
    assert "GPU" not in result.explanation
    assert result.root_cause_proven is False


@pytest.mark.parametrize(
    "objective",
    [
        "Which process owns 127.0.0.1:18765 and include PID and creation time?",
        "Which process owns the listening endpoint 127.0.0.1:18765? "
        "Identify its observed PID and creation time.",
        "Which process owns the listener at 127.0.0.1:18765?",
    ],
)
def test_exact_listener_owner_can_request_precise_identity_fields(objective: str) -> None:
    state = _state(
        objective=objective,
        hypothesis=_hypothesis(LISTENER_EVIDENCE, probes=("network.listeners",)),
        completed=("network.listeners",),
    )
    context = _context(
        LISTENER_EVIDENCE,
        "network.listeners",
        {
            "listeners": [
                {
                    "protocol": "tcp4",
                    "local_address": "127.0.0.1",
                    "local_port": 18765,
                    "pid": 4242,
                    "process_name": "owner.exe",
                    "process_creation_time": NOW.isoformat(),
                    "owner_status": "available",
                }
            ]
        },
    )

    result = assess_investigation(state=state, context=(context,), relationships=())

    assert result.disposition is AssessmentDisposition.SUPPORTED_OBSERVED_EXPLANATION


def test_listener_owner_does_not_complete_a_mixed_action_goal() -> None:
    state = _state(
        objective="Which process owns port 18765 and fix the performance issue?",
        hypothesis=_hypothesis(LISTENER_EVIDENCE, probes=("network.listeners",)),
        completed=("network.listeners",),
    )
    context = _context(
        LISTENER_EVIDENCE,
        "network.listeners",
        {
            "listeners": [
                {
                    "protocol": "tcp4",
                    "local_address": "127.0.0.1",
                    "local_port": 18765,
                    "pid": 4242,
                    "process_name": "owner.exe",
                    "process_creation_time": NOW.isoformat(),
                    "owner_status": "available",
                }
            ]
        },
    )

    result = assess_investigation(state=state, context=(context,), relationships=())

    assert result.disposition is AssessmentDisposition.UNRESOLVED


def test_listener_owner_requires_an_explicit_owner_question() -> None:
    state = _state(
        objective="Which process used the most memory while port 18765 was active?",
        hypothesis=_hypothesis(LISTENER_EVIDENCE, probes=("network.listeners",)),
        completed=("network.listeners",),
    )
    context = _context(
        LISTENER_EVIDENCE,
        "network.listeners",
        {
            "listeners": [
                {
                    "protocol": "tcp4",
                    "local_address": "127.0.0.1",
                    "local_port": 18765,
                    "pid": 4242,
                    "process_name": "owner.exe",
                    "process_creation_time": NOW.isoformat(),
                    "owner_status": "available",
                }
            ]
        },
    )

    result = assess_investigation(state=state, context=(context,), relationships=())

    assert result.disposition is AssessmentDisposition.UNRESOLVED


def test_listener_owner_does_not_answer_a_causal_process_question() -> None:
    state = _state(
        objective="Which process owns port 18765, and why did it crash?",
        hypothesis=_hypothesis(LISTENER_EVIDENCE, probes=("network.listeners",)),
        completed=("network.listeners",),
    )
    context = _context(
        LISTENER_EVIDENCE,
        "network.listeners",
        {
            "listeners": [
                {
                    "protocol": "tcp4",
                    "local_address": "127.0.0.1",
                    "local_port": 18765,
                    "pid": 4242,
                    "process_name": "owner.exe",
                    "process_creation_time": NOW.isoformat(),
                    "owner_status": "available",
                }
            ],
            "omitted_listener_count": 0,
        },
    )

    result = assess_investigation(state=state, context=(context,), relationships=())

    assert result.disposition is AssessmentDisposition.UNRESOLVED


def test_address_qualified_listener_question_matches_the_exact_endpoint_only() -> None:
    state = _state(
        objective="Which process owns 127.0.0.1:18765?",
        hypothesis=_hypothesis(LISTENER_EVIDENCE, probes=("network.listeners",)),
        completed=("network.listeners",),
    )
    context = _context(
        LISTENER_EVIDENCE,
        "network.listeners",
        {
            "listeners": [
                {
                    "protocol": "tcp4",
                    "local_address": "0.0.0.0",
                    "local_port": 18765,
                    "pid": 1111,
                    "process_name": "wrong-address.exe",
                    "process_creation_time": NOW.isoformat(),
                    "owner_status": "available",
                },
                {
                    "protocol": "tcp4",
                    "local_address": "127.0.0.1",
                    "local_port": 18765,
                    "pid": 4242,
                    "process_name": "exact-owner.exe",
                    "process_creation_time": NOW.isoformat(),
                    "owner_status": "available",
                },
            ],
            "omitted_listener_count": 9,
        },
    )

    result = assess_investigation(state=state, context=(context,), relationships=())

    assert result.disposition is AssessmentDisposition.SUPPORTED_OBSERVED_EXPLANATION
    assert "exact-owner.exe" in result.explanation
    assert "wrong-address.exe" not in result.explanation
    assert any("not establish" in limitation for limitation in result.limitations)


def test_listener_claim_allows_additional_valid_current_citations() -> None:
    second_evidence = EvidenceId(root="ev_ffffffffffffffffffffffffffffffff")
    hypothesis = Hypothesis(
        hypothesis_id="candidate",
        statement="Advisory text.",
        status=HypothesisStatus.UNRESOLVED,
        supporting_evidence_ids=(LISTENER_EVIDENCE, second_evidence),
        distinguishing_probe_ids=("network.listeners",),
    )
    state = _state(
        objective="Which process owns port 18765?",
        hypothesis=hypothesis,
        completed=("network.listeners",),
    )
    listener_context = _context(
        LISTENER_EVIDENCE,
        "network.listeners",
        {
            "listeners": [
                {
                    "protocol": "tcp4",
                    "local_address": "127.0.0.1",
                    "local_port": 18765,
                    "pid": 4242,
                    "process_name": "owner.exe",
                    "process_creation_time": NOW.isoformat(),
                    "owner_status": "available",
                }
            ]
        },
    )
    second_context = _context(second_evidence, "system.snapshot", {"hostname": "fixture"})

    result = assess_investigation(
        state=state, context=(listener_context, second_context), relationships=()
    )

    assert result.disposition is AssessmentDisposition.SUPPORTED_OBSERVED_EXPLANATION


@pytest.mark.parametrize(
    "facts",
    [
        {
            "listeners.180": {
                "protocol": "tcp4",
                "local_address": "127.0.0.1",
                "local_port": 18765,
                "pid": 4242,
                "process_name": "rehydrated.exe",
                "process_creation_time": NOW.isoformat(),
                "owner_status": "available",
            },
            "omitted_listener_count": 0,
        },
        {
            "fact_abc123": {
                "source_path": "nested.unsafe listener path.0",
                "value": {
                    "protocol": "tcp4",
                    "local_address": "127.0.0.1",
                    "local_port": 18765,
                    "pid": 4242,
                    "process_name": "rehydrated.exe",
                    "process_creation_time": NOW.isoformat(),
                    "owner_status": "available",
                },
            },
            "omitted_listener_count": 0,
        },
    ],
)
def test_listener_claim_accepts_complete_rehydrated_target_rows(
    facts: dict[str, object],
) -> None:
    state = _state(
        objective="Which process owns 127.0.0.1:18765?",
        hypothesis=_hypothesis(LISTENER_EVIDENCE, probes=("network.listeners",)),
        completed=("network.listeners",),
    )
    context = _context(LISTENER_EVIDENCE, "network.listeners", facts)

    result = assess_investigation(state=state, context=(context,), relationships=())

    assert result.disposition is AssessmentDisposition.SUPPORTED_OBSERVED_EXPLANATION
    assert "rehydrated.exe" in result.explanation


@pytest.mark.parametrize("gap", ["probe", "contradiction", "missing", "historical"])
def test_listener_completion_rejects_unresolved_gaps(gap: str) -> None:
    contradiction = (
        (EvidenceId(root="ev_bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),) if gap == "contradiction" else ()
    )
    missing = (EvidenceId(root="ev_cccccccccccccccccccccccccccccccc"),) if gap == "missing" else ()
    state = _state(
        objective="process listening on port 18765",
        hypothesis=_hypothesis(
            LISTENER_EVIDENCE,
            contradicting=contradiction,
            missing=missing,
            probes=("network.listeners",),
        ),
        completed=() if gap == "probe" else ("network.listeners",),
    )
    context = _context(
        LISTENER_EVIDENCE,
        "network.listeners",
        {
            "listeners": [
                {
                    "protocol": "tcp4",
                    "local_address": "0.0.0.0",
                    "local_port": 18765,
                    "pid": 7,
                    "process_name": "owner.exe",
                    "process_creation_time": NOW.isoformat(),
                    "owner_status": "available",
                }
            ],
            "omitted_listener_count": 0,
        },
        limitations=("Historical observation; freshness requires review.",)
        if gap == "historical"
        else (),
    )

    result = assess_investigation(state=state, context=(context,), relationships=())

    assert result.disposition is AssessmentDisposition.UNRESOLVED
    assert result.root_cause_proven is False


def test_exact_device_problem_code_is_a_finding_not_root_cause_proof() -> None:
    evidence_id = EvidenceId(root="ev_dddddddddddddddddddddddddddddddd")
    state = _state(
        objective=r"What problem is reported for PCI\VEN_1234&DEV_ABCD?",
        hypothesis=_hypothesis(evidence_id, probes=("devices.snapshot",)),
        completed=("devices.snapshot",),
    )
    context = _context(
        evidence_id,
        "devices.snapshot",
        {
            "devices": [
                {
                    "instance_id": r"PCI\VEN_1234&DEV_ABCD",
                    "name": "Fixture adapter",
                    "problem_code": 28,
                }
            ]
        },
    )

    result = assess_investigation(state=state, context=(context,), relationships=())

    assert result.disposition is AssessmentDisposition.SUPPORTED_OBSERVED_EXPLANATION
    assert result.claim_kind is ObservedClaimKind.DEVICE_PROBLEM_CODE
    assert "problem code 28" in result.explanation
    assert result.root_cause_proven is False


def test_device_problem_code_does_not_answer_a_causal_crash_question() -> None:
    evidence_id = EvidenceId(root="ev_dddddddddddddddddddddddddddddddd")
    state = _state(
        objective=r"What problem code does PCI\VEN_1234&DEV_ABCD report, and why did it crash?",
        hypothesis=_hypothesis(evidence_id, probes=("devices.snapshot",)),
        completed=("devices.snapshot",),
    )
    context = _context(
        evidence_id,
        "devices.snapshot",
        {
            "devices": [
                {
                    "instance_id": r"PCI\VEN_1234&DEV_ABCD",
                    "name": "Fixture adapter",
                    "problem_code": 28,
                }
            ]
        },
    )

    result = assess_investigation(state=state, context=(context,), relationships=())

    assert result.disposition is AssessmentDisposition.UNRESOLVED


def test_device_problem_code_requires_an_explicit_status_question() -> None:
    evidence_id = EvidenceId(root="ev_dddddddddddddddddddddddddddddddd")
    state = _state(
        objective=r"What driver version is installed for PCI\VEN_1234&DEV_ABCD?",
        hypothesis=_hypothesis(evidence_id, probes=("devices.snapshot",)),
        completed=("devices.snapshot",),
    )
    context = _context(
        evidence_id,
        "devices.snapshot",
        {
            "devices": [
                {
                    "instance_id": r"PCI\VEN_1234&DEV_ABCD",
                    "name": "Fixture adapter",
                    "problem_code": 28,
                }
            ]
        },
    )

    result = assess_investigation(state=state, context=(context,), relationships=())

    assert result.disposition is AssessmentDisposition.UNRESOLVED


def test_device_problem_code_does_not_complete_a_mixed_diagnostic_goal() -> None:
    evidence_id = EvidenceId(root="ev_dddddddddddddddddddddddddddddddd")
    state = _state(
        objective=(
            r"What problem code is reported for PCI\VEN_1234&DEV_ABCD and identify the reason "
            "for low FPS?"
        ),
        hypothesis=_hypothesis(evidence_id, probes=("devices.snapshot",)),
        completed=("devices.snapshot",),
    )
    context = _context(
        evidence_id,
        "devices.snapshot",
        {
            "devices": [
                {
                    "instance_id": r"PCI\VEN_1234&DEV_ABCD",
                    "name": "Fixture adapter",
                    "problem_code": 28,
                }
            ]
        },
    )

    result = assess_investigation(state=state, context=(context,), relationships=())

    assert result.disposition is AssessmentDisposition.UNRESOLVED


def test_generic_correlated_gpu_theory_cannot_complete() -> None:
    evidence_id = EvidenceId(root="ev_eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
    state = _state(
        objective="Why did the application freeze?",
        hypothesis=_hypothesis(evidence_id, statement="GPU use caused the freeze."),
        completed=("gpu.telemetry.sample",),
    )
    context = _context(
        evidence_id,
        "gpu.telemetry.sample",
        {"gpu_utilization_percent": 99},
    )

    result = assess_investigation(state=state, context=(context,), relationships=())

    assert result.disposition is AssessmentDisposition.UNRESOLVED
    assert result.claim_kind is None
    assert result.root_cause_proven is False
