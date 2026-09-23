from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from systemsense.decision.contracts import (
    DecisionRequest,
    DecisionResponse,
    DiagnosticPurpose,
    ProbeCapability,
    ProbeProposal,
    ProviderIdentity,
)
from systemsense.domain.ids import CaseId, EvidenceId, ExecutionId
from systemsense.domain.probes import (
    Privilege,
    ProbeLimits,
    ProbeManifest,
    ProbeSafety,
    SafetyClass,
)
from systemsense.evaluation.attention_labels import (
    AttentionSnapshot,
    ExpertAttentionLabel,
    ProbeOutcome,
    RedactionAttestation,
    RegisteredProbe,
    SplitKeys,
)
from systemsense.evaluation.attention_replay import (
    candidate_catalog_sha256,
    candidate_context_sha256,
    visible_evidence_sha256,
)
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.orchestration.scheduler import ResourceClass

NOW = datetime(2026, 9, 22, tzinfo=UTC)


def _manifest(probe_id: str) -> ProbeManifest:
    return ProbeManifest(
        probe_id=probe_id,
        version=1,
        implementation_id=f"builtin.{probe_id}",
        question=f"Read {probe_id}",
        safety=ProbeSafety(
            safety_class=SafetyClass.R1, privilege=Privilege.STANDARD, target_state_effect="none"
        ),
        input_model="ProbeInputV1",
        limits=ProbeLimits(timeout_ms=100, max_output_bytes=1024, max_records=10),
        category="windows",
    )


def _case() -> tuple[ExpertAttentionLabel, DecisionRequest, dict[str, ProbeManifest]]:
    manifests = {
        name: _manifest(name)
        for name in ("windows.eventlog", "windows.services", "windows.scheduled_tasks")
    }
    case_id = CaseId.new()
    evidence_id = EvidenceId.new()
    candidates = tuple(RegisteredProbe.from_manifest(item) for item in manifests.values())
    evidence = EvidenceContext(
        evidence_id=evidence_id,
        observed_at=NOW,
        captured_at=NOW,
        probe_id="windows.eventlog",
        summary="Application launch event",
        facts={"event.id": 1000},
        status=EvidenceContextStatus.OBSERVED,
    )
    request = DecisionRequest(
        case_id=case_id,
        state_version=4,
        correlation_id="replay_1",
        deadline_at=NOW + timedelta(minutes=1),
        symptom="application launch failure",
        evidence_ids=(evidence_id,),
        evidence_context=(evidence,),
        available_probes=tuple(
            ProbeCapability(
                probe_id=name,
                description="bounded read-only probe",
                cost_ms=10,
                resource_class=ResourceClass.CPU,
            )
            for name in manifests
        ),
        budget_ms=10,
        max_probes=1,
    )
    label = ExpertAttentionLabel(
        schema_version=2,
        label_id="label_" + "1" * 32,
        split_keys=SplitKeys(case_id=case_id, machine_key="a" * 64, fault_family="startup"),
        snapshot=AttentionSnapshot(
            state_version=4,
            case_opened_at=NOW - timedelta(hours=1),
            captured_at=NOW,
            evidence_ids=(evidence_id,),
            candidate_probes=candidates,
            candidate_catalog_sha256=candidate_catalog_sha256(candidates),
            candidate_context_sha256=candidate_context_sha256(request),
            visible_evidence_sha256=visible_evidence_sha256(request),
        ),
        useful_probe_ids=("windows.eventlog",),
        negative_probe_ids=("windows.services",),
        abstain=False,
        outcomes=(
            ProbeOutcome(
                probe_id="windows.eventlog",
                execution_id=ExecutionId.new(),
                started_at=NOW + timedelta(seconds=1),
                finished_at=NOW + timedelta(seconds=8),
                evidence_ids=(EvidenceId.new(),),
                result="informative",
            ),
            ProbeOutcome(
                probe_id="windows.services",
                execution_id=ExecutionId.new(),
                started_at=NOW + timedelta(seconds=1),
                finished_at=NOW + timedelta(seconds=3),
                evidence_ids=(),
                result="uninformative",
            ),
        ),
        reviewer_id="expert_1",
        reviewed_at=NOW + timedelta(minutes=1),
        label_origin="human_expert",
        source_kind="live",
        synthetic=False,
        redaction=RedactionAttestation(
            method="identifiers_only", checked_by="expert_1", checked_at=NOW + timedelta(seconds=9)
        ),
    )
    return label, request, manifests


class _Provider:
    def __init__(self, ranked: tuple[str, ...]) -> None:
        self.ranked = ranked
        self.seen: list[DecisionRequest] = []

    @property
    def identity(self) -> ProviderIdentity:
        return ProviderIdentity(
            provider_id="test.provider", provider_version="1", role="fast_decision"
        )

    def decide(self, request: DecisionRequest) -> DecisionResponse:
        self.seen.append(request)
        proposals = tuple(
            ProbeProposal(
                probe_id=probe_id,
                purpose=DiagnosticPurpose.CHECK_COVERAGE,
                priority=1 - index * 0.1,
                estimated_cost_ms=10,
                resource_class=ResourceClass.CPU,
                dedupe_key=f"proposal.{index}",
            )
            for index, probe_id in enumerate(self.ranked)
        )
        return DecisionResponse(
            provider=self.identity,
            case_id=request.case_id,
            state_version=request.state_version,
            correlation_id=request.correlation_id,
            deadline_at=request.deadline_at,
            proposals=proposals,
        )


def test_replay_compares_providers_on_same_case_and_computes_labeled_metrics() -> None:
    from systemsense.evaluation.attention_replay import evaluate_attention_replay

    label, request, manifests = _case()
    first = _Provider(("windows.services",))
    second = _Provider(("windows.eventlog",))

    result = evaluate_attention_replay(
        splits={"heldout": (label,)},
        requests={label.label_id: request},
        manifests=manifests,
        providers={"negative_first": first, "useful_first": second},
        k=1,
    )

    assert first.seen == second.seen == [request]
    assert result.synthetic is False
    assert result.metrics["negative_first"].labeled_useful_probe_recall_at_k == 0
    assert result.metrics["useful_first"].labeled_useful_probe_recall_at_k == 1
    assert result.metrics["negative_first"].negative_top_k_suggestions == 1
    assert result.metrics["useful_first"].matched_recorded_outcome_seconds == 8
    assert result.metrics["negative_first"].matched_recorded_outcome_seconds is None
    coverage = result.candidate_adjudication.per_case[0]
    assert coverage.registered_candidate_count == 3
    assert coverage.observed_outcome_count == 2
    assert coverage.observed_outcome_fraction == pytest.approx(2 / 3)
    assert coverage.labeled_useful_candidate_count == 1
    assert coverage.unadjudicated_candidate_count == 1
    assert result.candidate_adjudication.registered_candidate_count == 3
    assert result.candidate_adjudication.observed_outcome_fraction == pytest.approx(2 / 3)


@pytest.mark.parametrize("binding", ["case", "state", "evidence", "candidates"])
def test_replay_fails_closed_when_request_does_not_match_label_snapshot(binding: str) -> None:
    from systemsense.evaluation.attention_replay import evaluate_attention_replay

    label, request, manifests = _case()
    if binding == "case":
        request = request.model_copy(update={"case_id": CaseId.new()})
    elif binding == "state":
        request = request.model_copy(update={"state_version": 3})
    elif binding == "evidence":
        request = request.model_copy(update={"evidence_ids": (EvidenceId.new(),)})
    else:
        request = request.model_copy(update={"available_probes": request.available_probes[:1]})

    with pytest.raises(ValueError, match=r"snapshot|candidate|evidence|case|state"):
        evaluate_attention_replay(
            splits={"heldout": (label,)},
            requests={label.label_id: request},
            manifests=manifests,
            providers={"provider": _Provider(("windows.eventlog",))},
            k=1,
        )


def test_replay_counts_unregistered_suggestions_and_rejects_synthetic_labels() -> None:
    from systemsense.evaluation.attention_replay import evaluate_attention_replay

    label, request, manifests = _case()
    provider = _Provider(("windows.eventlog", "windows.unknown"))
    request = request.model_copy(update={"max_probes": 2})
    result = evaluate_attention_replay(
        splits={"heldout": (label,)},
        requests={label.label_id: request},
        manifests=manifests,
        providers={"provider": provider},
        k=2,
    )
    assert result.metrics["provider"].unsupported_suggestions == 1


def test_unsupported_output_occupies_top_k_and_timing_is_absent_without_informative_match() -> None:
    from systemsense.evaluation.attention_replay import evaluate_attention_replay

    label, request, manifests = _case()
    provider = _Provider(("windows.unknown", "windows.eventlog"))
    request = request.model_copy(update={"max_probes": 2})
    result = evaluate_attention_replay(
        splits={"heldout": (label,)},
        requests={label.label_id: request},
        manifests=manifests,
        providers={"provider": provider},
        k=1,
    )

    metrics = result.metrics["provider"]
    assert metrics.unsupported_suggestions == 1
    assert metrics.labeled_useful_probe_recall_at_k == 0
    assert metrics.labeled_useful_probe_hits == 0
    assert metrics.negative_top_k_suggestions == 0
    assert metrics.matched_recorded_outcome_seconds is None
    assert metrics.matched_recorded_outcome_cases == 0
    assert result.label_hash_validation == "consistency_only"
    assert result.label_authenticity == "not_verified"

    synthetic = label.model_copy(update={"synthetic": True})
    with pytest.raises(ValueError, match=r"human expert|synthetic"):
        evaluate_attention_replay(
            splits={"heldout": (synthetic,)},
            requests={synthetic.label_id: request},
            manifests=manifests,
            providers={"provider": _Provider(("windows.eventlog",))},
            k=1,
        )


def test_replay_rejects_visible_evidence_content_tampering_and_v1_protocol_labels() -> None:
    from systemsense.evaluation.attention_replay import evaluate_attention_replay

    label, request, manifests = _case()
    altered_evidence = request.evidence_context[0].model_copy(update={"summary": "tampered"})
    altered = request.model_copy(update={"evidence_context": (altered_evidence,)})
    with pytest.raises(ValueError, match="visible evidence"):
        evaluate_attention_replay(
            splits={"heldout": (label,)},
            requests={label.label_id: altered},
            manifests=manifests,
            providers={"provider": _Provider(("windows.eventlog",))},
            k=1,
        )
    historical = label.model_copy(update={"schema_version": 1})
    with pytest.raises(ValueError, match=r"version 2|protocol-only"):
        evaluate_attention_replay(
            splits={"heldout": (historical,)},
            requests={historical.label_id: request},
            manifests=manifests,
            providers={"provider": _Provider(("windows.eventlog",))},
            k=1,
        )


def test_v2_catalog_digest_tampering_and_split_overlap_are_rejected() -> None:
    from systemsense.evaluation.attention_replay import evaluate_attention_replay

    label, request, manifests = _case()
    altered_snapshot = label.snapshot.model_copy(update={"candidate_catalog_sha256": "0" * 64})
    altered_label = label.model_copy(update={"snapshot": altered_snapshot})
    with pytest.raises(ValueError, match="candidate catalog digest"):
        evaluate_attention_replay(
            splits={"heldout": (altered_label,)},
            requests={altered_label.label_id: request},
            manifests=manifests,
            providers={"provider": _Provider(("windows.eventlog",))},
            k=1,
        )

    altered_capabilities = (
        request.available_probes[0].model_copy(update={"cost_ms": 11}),
        *request.available_probes[1:],
    )
    altered_request = request.model_copy(update={"available_probes": altered_capabilities})
    with pytest.raises(ValueError, match="candidate context digest"):
        evaluate_attention_replay(
            splits={"heldout": (label,)},
            requests={label.label_id: altered_request},
            manifests=manifests,
            providers={"provider": _Provider(("windows.eventlog",))},
            k=1,
        )

    second, second_request, second_manifests = _case()
    assert manifests == second_manifests
    second = second.model_copy(update={"label_id": "label_" + "2" * 32})
    with pytest.raises(ValueError, match="group crosses splits"):
        evaluate_attention_replay(
            splits={"train": (label,), "heldout": (second,)},
            requests={label.label_id: request, second.label_id: second_request},
            manifests=manifests,
            providers={"provider": _Provider(("windows.eventlog",))},
            k=1,
        )
