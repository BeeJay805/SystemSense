from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest

from systemsense.decision.contracts import (
    DecisionPresentationTrace,
    DecisionRequest,
    FastHypothesisCheck,
    ProbeCapability,
    ResourceClass,
    presentation_payload_sha256,
)
from systemsense.decision.laya import LayaDecisionProvider, eligible_laya_candidates
from systemsense.decision.semantic_packets import SERIALIZER_ID, evidence_packets
from systemsense.domain.ids import CaseId, EvidenceId, JsonValue
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.inference.laya_runtime import (
    LayaAttentionMicrobatch,
    LayaAttentionResult,
    LayaCachedOrigin,
    LayaQuestionPresentation,
    LayaRuntimeError,
    LayaWorkerPresentation,
)

NOW = datetime.now(UTC)


def test_default_request_deadline_tracks_request_time(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(_request.__globals__, "NOW", datetime.now(UTC) - timedelta(minutes=2))
    assert _request().deadline_at > datetime.now(UTC) + timedelta(seconds=50)


class _Ranker:
    def __init__(self, result: LayaAttentionResult | Exception) -> None:
        self.result = result
        self.calls: list[dict[str, object]] = []

    def attend(
        self,
        *,
        state: dict[str, object],
        evidence: tuple[dict[str, str], ...],
        candidates: tuple[dict[str, str], ...],
        timeout_seconds: float,
    ) -> LayaAttentionResult:
        self.calls.append(
            {
                "state": state,
                "evidence": evidence,
                "candidates": candidates,
                "timeout_seconds": timeout_seconds,
            }
        )
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _evidence_microbatch(
    fragment_id: str,
    *,
    truncated: bool = False,
    cached: bool = False,
    state_truncated: bool = False,
    split_questions: bool = False,
) -> LayaAttentionMicrobatch:
    if cached:
        return LayaAttentionMicrobatch(
            phase="evidence",
            batch_index=0,
            candidate_ids=(fragment_id,),
            cache_hit_ids=(fragment_id,),
            cached_origins=(LayaCachedOrigin(item_id=fragment_id, presentation_sha256="a" * 64),),
        )
    question = LayaQuestionPresentation(
        question_id="q0",
        item_id=fragment_id,
        question_sha256="b" * 64,
        instruction_tokens=100,
        instruction_presented_tokens=90 if truncated else 100,
        criteria_tokens=20,
        criteria_presented_tokens=20,
        state_presented_tokens=80,
    )
    questions = (
        (
            question,
            question.model_copy(update={"question_id": "q1"}),
        )
        if split_questions
        else (question,)
    )
    return LayaAttentionMicrobatch(
        phase="evidence",
        batch_index=0,
        candidate_ids=(fragment_id,),
        inference_ids=(fragment_id,),
        worker_presentation=LayaWorkerPresentation(
            presentation_sha256="c" * 64,
            fitted_state_sha256="d" * 64,
            questions_sha256="e" * 64,
            presented_item_ids=(fragment_id,),
            fitted_state_tokens=80,
            state_tokens_original=80,
            state_fields_omitted=1 if state_truncated else 0,
            state_list_items_omitted=0,
            questions=questions,
        ),
    )


def _capability(
    probe_id: str,
    *,
    description: str,
    keywords: frozenset[str] = frozenset(),
    cost_ms: int = 100,
) -> ProbeCapability:
    return ProbeCapability(
        probe_id=probe_id,
        description=description,
        keywords=keywords,
        baseline_priority=0.5,
        cost_ms=cost_ms,
        resource_class=ResourceClass.CPU,
    )


def _request(*, deadline_at: datetime | None = None, budget_ms: int = 500) -> DecisionRequest:
    evidence_id = EvidenceId.new()
    return DecisionRequest(
        case_id=CaseId.new(),
        state_version=2,
        correlation_id="corr_laya",
        deadline_at=deadline_at or datetime.now(UTC) + timedelta(minutes=1),
        symptom="application fails to launch",
        evidence_ids=(evidence_id,),
        evidence_context=(
            EvidenceContext(
                evidence_id=evidence_id,
                observed_at=NOW,
                captured_at=NOW,
                probe_id="core.system",
                summary="The application process exited during initialization.",
                facts={"exit.code": 1},
                status=EvidenceContextStatus.OBSERVED,
            ),
        ),
        completed_probe_ids=frozenset({"core.system"}),
        available_probes=(
            _capability("core.system", description="system snapshot", cost_ms=50),
            _capability(
                "application.snapshot",
                description="application process and failure snapshot",
                keywords=frozenset({"application", "launch"}),
                cost_ms=125,
            ),
            _capability(
                "eventlog.application",
                description="application event log errors",
                keywords=frozenset({"application"}),
                cost_ms=200,
            ),
        ),
        budget_ms=budget_ms,
        max_probes=2,
    )


def test_provider_uses_rank_order_but_rebuilds_every_trusted_catalog_field() -> None:
    request = _request()
    ranker = _Ranker(
        LayaAttentionResult(
            ranked_probe_ids=("eventlog.application", "application.snapshot"),
            ranked_evidence_ids=(str(request.evidence_ids[0]),),
            considered_probe_ids=("eventlog.application", "application.snapshot"),
            considered_evidence_ids=(str(request.evidence_ids[0]),),
            ranked_attention_page_ids=(f"{request.evidence_ids[0]}:0",),
            considered_attention_page_ids=(f"{request.evidence_ids[0]}:0",),
            attention_notes=("ordinal_relevance_only",),
        )
    )
    provider = LayaDecisionProvider(ranker=ranker, timeout_seconds=5)

    response = provider.decide(request)

    assert response.provider.provider_id == "laya-local-decision"
    assert [proposal.probe_id for proposal in response.proposals] == [
        "eventlog.application",
        "application.snapshot",
    ]
    assert [proposal.estimated_cost_ms for proposal in response.proposals] == [200, 125]
    assert all(proposal.resource_class is ResourceClass.CPU for proposal in response.proposals)
    assert response.proposals[0].priority > response.proposals[1].priority
    assert response.ranked_evidence_ids == request.evidence_ids
    assert response.ranked_attention_page_ids == (f"{request.evidence_ids[0]}:0",)
    assert response.considered_evidence_count == 1
    assert response.considered_evidence_ids == request.evidence_ids
    assert response.attention_notes == ("ordinal_relevance_only",)
    assert response.validate_against(request) == response
    sent_ids = [item["probe_id"] for item in ranker.calls[0]["candidates"]]  # type: ignore[index]
    assert "core.system" not in sent_ids


def test_laya_ranks_id_but_binding_comes_only_from_single_catalog_target() -> None:
    handle = "proc_" + "a" * 32
    capability = _capability(
        "application.target_pressure", description="selected process counters"
    ).model_copy(
        update={
            "observable_ids": ("application.target_pressure",),
            "target_handles": (handle,),
        }
    )
    request = _request().model_copy(
        update={"available_probes": (capability,), "completed_probe_ids": frozenset()}
    )
    attention = LayaAttentionResult(
        ranked_probe_ids=(capability.probe_id,),
        considered_probe_ids=(capability.probe_id,),
    )

    response = LayaDecisionProvider(ranker=_Ranker(attention)).decide(request)

    assert not response.degraded
    assert len(response.proposals) == 1
    assert response.proposals[0].schema_version == 2
    assert response.proposals[0].measurement_need is not None
    assert response.proposals[0].measurement_need.target_handle == handle
    assert response.proposals[0].measurement_need.observable == capability.observable_ids[0]
    assert response.proposals[0].measurement_need.window is None

    ambiguous = capability.model_copy(update={"target_handles": (handle, "proc_" + "b" * 32)})
    no_probe_attention = LayaAttentionResult(ranked_probe_ids=(), considered_probe_ids=())
    response = LayaDecisionProvider(ranker=_Ranker(no_probe_attention)).decide(
        request.model_copy(update={"available_probes": (ambiguous,)})
    )
    assert response.proposals == ()

    broad = capability.model_copy(update={"target_handles": (), "observable_ids": ()})
    response = LayaDecisionProvider(ranker=_Ranker(attention)).decide(
        request.model_copy(update={"available_probes": (broad,)})
    )
    assert response.proposals[0].schema_version == 1
    assert response.proposals[0].measurement_need is None


def test_provider_falls_back_explicitly_on_unavailable_or_invalid_ranking() -> None:
    for result in (
        LayaRuntimeError("offline worker unavailable"),
        LayaRuntimeError("Laya host RAM admission rejected cold worker start"),
        LayaAttentionResult(
            ranked_probe_ids=("unknown.probe", "application.snapshot"),
            considered_probe_ids=("unknown.probe", "application.snapshot"),
        ),
        LayaAttentionResult(
            ranked_probe_ids=("application.snapshot", "application.snapshot"),
            considered_probe_ids=("application.snapshot",),
        ),
    ):
        provider = LayaDecisionProvider(ranker=_Ranker(result))
        response = provider.decide(_request())
        assert response.degraded is True
        assert response.provider.provider_id == "keyword-baseline"
        assert response.stop_reason is not None
        assert response.stop_reason.startswith("laya_invalid_or_unavailable:")
        assert "LayaRuntimeError" in response.stop_reason
        if isinstance(result, LayaRuntimeError) and "RAM" in str(result):
            assert "RAM" in response.stop_reason
        assert provider.status.available is False


def test_fake_ranker_metadata_is_not_attested_as_worker_presentation() -> None:
    request = _request()
    result = LayaAttentionResult(
        ranked_probe_ids=("eventlog.application", "application.snapshot"),
        considered_probe_ids=("eventlog.application", "application.snapshot"),
        microbatches=(
            LayaAttentionMicrobatch(
                phase="probe",
                batch_index=0,
                candidate_ids=("eventlog.application", "application.snapshot"),
                cache_hit_ids=("eventlog.application", "application.snapshot"),
                cached_origins=(
                    LayaCachedOrigin(item_id="eventlog.application", presentation_sha256="a" * 64),
                    LayaCachedOrigin(item_id="application.snapshot", presentation_sha256="b" * 64),
                ),
            ),
        ),
    )
    response = LayaDecisionProvider(ranker=_Ranker(result)).decide(request)
    assert response.provider.provider_id == "laya-local-decision"
    assert response.presentation_trace is None


def test_laya_escalates_only_when_deadline_left_a_presented_page_unconsidered() -> None:
    base = _request()
    unseen = EvidenceId.new()
    second = base.evidence_context[0].model_copy(update={"evidence_id": unseen})
    request = base.model_copy(
        update={
            "evidence_ids": (*base.evidence_ids, unseen),
            "attention_context": (*base.evidence_context, second),
        }
    )
    first_id = str(base.evidence_ids[0])
    result = LayaAttentionResult(
        ranked_probe_ids=("eventlog.application", "application.snapshot"),
        considered_probe_ids=("eventlog.application", "application.snapshot"),
        ranked_evidence_ids=(first_id,),
        considered_evidence_ids=(first_id,),
        ranked_attention_page_ids=(f"{first_id}:0",),
        considered_attention_page_ids=(f"{first_id}:0",),
        attention_notes=("coverage_limited=true",),
    )
    response = LayaDecisionProvider(ranker=_Ranker(result)).decide(request)
    assert response.requires_reasoning is True
    assert len(response.signals) == 1
    assert response.signals[0].kind.value == "coverage_gap"
    assert response.signals[0].evidence_ids == ()
    assert response.considered_evidence_ids == base.evidence_ids
    assert response.validate_against(request) == response

    not_deadline_limited = result.model_copy(
        update={"attention_notes": ("coverage_limited=false",)}
    )
    no_signal = LayaDecisionProvider(ranker=_Ranker(not_deadline_limited)).decide(request)
    assert no_signal.requires_reasoning is False
    assert no_signal.signals == ()
    all_pages = result.model_copy(
        update={
            "considered_attention_page_ids": (f"{first_id}:0", f"{unseen}:1"),
            "considered_evidence_ids": (first_id, str(unseen)),
        }
    )
    no_gap = LayaDecisionProvider(ranker=_Ranker(all_pages)).decide(request)
    assert no_gap.requires_reasoning is False
    assert no_gap.signals == ()


def test_decision_request_accepts_bounded_fact_expectation_for_fast_review() -> None:
    base = _request()
    payload = base.model_dump(mode="python")
    payload["schema_version"] = 3
    payload["hypothesis_briefs"] = ("The device reports no problem code.",)
    payload["hypothesis_checks"] = (
        {
            "hypothesis_index": 0,
            "probe_id": "core.system",
            "fact_name": "device.problem_code",
            "expected_value": 0,
            "observed_after": NOW - timedelta(seconds=1),
        },
    )

    request = DecisionRequest.model_validate(payload)

    assert request.hypothesis_checks[0].expected_value == 0


def test_laya_flags_exact_new_fact_conflicting_with_typed_hypothesis_expectation() -> None:
    base = _request()
    contradictory = EvidenceContext(
        evidence_id=EvidenceId.new(),
        observed_at=NOW,
        captured_at=NOW,
        probe_id="core.system",
        summary="The exact device reports a problem code.",
        facts={"device.problem_code": 10},
        status=EvidenceContextStatus.OBSERVED,
        case_scope="current_case",
        incident_relevant=True,
    )
    request = DecisionRequest.model_validate(
        {
            **base.model_dump(mode="python"),
            "schema_version": 3,
            "evidence_ids": (*base.evidence_ids, contradictory.evidence_id),
            "evidence_context": (*base.evidence_context, contradictory),
            "hypothesis_briefs": ("The device should report no problem code.",),
            "hypothesis_checks": (
                FastHypothesisCheck(
                    hypothesis_index=0,
                    probe_id="core.system",
                    fact_name="device.problem_code",
                    expected_value=0,
                    observed_after=NOW - timedelta(seconds=1),
                ),
            ),
        }
    )
    result = LayaAttentionResult(
        ranked_probe_ids=("application.snapshot", "eventlog.application"),
        considered_probe_ids=("application.snapshot", "eventlog.application"),
        ranked_evidence_ids=(str(contradictory.evidence_id),),
        considered_evidence_ids=(str(contradictory.evidence_id),),
        considered_attention_page_ids=(f"{contradictory.evidence_id}:1",),
        microbatches=(
            _evidence_microbatch(
                next(
                    item["fragment_id"]
                    for item in LayaDecisionProvider.evidence_fragments_for_laya(request)
                    if item["page_id"] == f"{contradictory.evidence_id}:1"
                )
            ),
        ),
    )

    ranker = _Ranker(result)
    response = LayaDecisionProvider(ranker=ranker).decide(request)

    assert response.requires_reasoning is True
    assert len(response.signals) == 1
    assert response.signals[0].kind.value == "contradiction_suspected"
    assert response.signals[0].evidence_ids == (contradictory.evidence_id,)
    assert response.signals[0].hypothesis_index == 0
    assert response.validate_against(request) == response
    state = cast(dict[str, object], ranker.calls[0]["state"])
    assert state["hypothesis_checks"] == [
        {
            "hypothesis_index": 0,
            "probe_id": "core.system",
            "fact_name": "device.problem_code",
            "expected_value": 0,
        }
    ]


def test_laya_presents_later_decisive_fact_as_exact_semantic_packet() -> None:
    base = _request()
    evidence = EvidenceContext(
        evidence_id=EvidenceId.new(),
        observed_at=NOW,
        captured_at=NOW,
        probe_id="core.system",
        summary="Twenty-five ordinary counters and a device fault.",
        facts={
            **{f"routine.{index:02}": index for index in range(25)},
            "device.problem_code": 10,
        },
        status=EvidenceContextStatus.OBSERVED,
        case_scope="current_case",
        incident_relevant=True,
    )
    request = DecisionRequest.model_validate(
        {
            **base.model_dump(mode="python"),
            "schema_version": 3,
            "evidence_ids": (evidence.evidence_id,),
            "evidence_context": (evidence,),
            "hypothesis_briefs": ("The device has no problem code.",),
            "hypothesis_checks": (
                FastHypothesisCheck(
                    hypothesis_index=0,
                    probe_id="core.system",
                    fact_name="device.problem_code",
                    expected_value=0,
                    observed_after=NOW - timedelta(seconds=1),
                ),
            ),
        }
    )
    decisive_fragment_id = evidence_packets((evidence,), priority_paths=("device.problem_code",))[
        0
    ]["fragment_id"]
    attention = LayaAttentionResult(
        ranked_probe_ids=("application.snapshot", "eventlog.application"),
        considered_probe_ids=("application.snapshot", "eventlog.application"),
        considered_evidence_ids=(str(evidence.evidence_id),),
        considered_attention_page_ids=(f"{evidence.evidence_id}:0",),
        microbatches=(_evidence_microbatch(decisive_fragment_id),),
    )
    ranker = _Ranker(attention)

    response = LayaDecisionProvider(ranker=ranker).decide(request)

    sent = cast(tuple[dict[str, str], ...], ranker.calls[0]["evidence"])
    assert len(sent) == 26
    assert sent[0]["fragment_id"] == decisive_fragment_id
    assert json.loads(sent[0]["description"])["projection"] == SERIALIZER_ID
    assert response.signals[0].kind.value == "contradiction_suspected"


def test_laya_does_not_confuse_stale_attention_packet_with_latest_source() -> None:
    base = _request()
    evidence = EvidenceContext(
        evidence_id=EvidenceId.new(),
        observed_at=NOW,
        captured_at=NOW,
        probe_id="core.system",
        summary="Current device fault.",
        facts={"device.problem_code": 10},
        status=EvidenceContextStatus.OBSERVED,
        case_scope="current_case",
        incident_relevant=True,
    )
    stale = evidence.model_copy(
        update={
            "observed_at": NOW - timedelta(minutes=2),
            "captured_at": NOW - timedelta(minutes=2),
        }
    )
    request = DecisionRequest.model_validate(
        {
            **base.model_dump(mode="python"),
            "schema_version": 3,
            "evidence_ids": (evidence.evidence_id,),
            "evidence_context": (evidence,),
            "attention_context": (stale,),
            "hypothesis_briefs": ("The device has no problem code.",),
            "hypothesis_checks": (
                FastHypothesisCheck(
                    hypothesis_index=0,
                    probe_id="core.system",
                    fact_name="device.problem_code",
                    expected_value=0,
                    observed_after=NOW - timedelta(seconds=1),
                ),
            ),
        }
    )
    fragment_id = evidence_packets((stale,), priority_paths=("device.problem_code",))[0][
        "fragment_id"
    ]
    attention = LayaAttentionResult(
        ranked_probe_ids=("application.snapshot", "eventlog.application"),
        considered_probe_ids=("application.snapshot", "eventlog.application"),
        considered_evidence_ids=(str(evidence.evidence_id),),
        considered_attention_page_ids=(f"{evidence.evidence_id}:0",),
        microbatches=(_evidence_microbatch(fragment_id),),
    )

    response = LayaDecisionProvider(ranker=_Ranker(attention)).decide(request)

    assert not response.signals


def test_v2_trace_binds_ordered_semantic_packets_and_v1_history_remains_readable() -> None:
    request = _request()
    response = LayaDecisionProvider(
        ranker=_Ranker(
            LayaAttentionResult(
                ranked_probe_ids=("application.snapshot", "eventlog.application"),
                considered_probe_ids=("application.snapshot", "eventlog.application"),
            )
        )
    ).decide(request)
    packets = evidence_packets(request.evidence_context)
    probe_ids = tuple(item.probe_id for item in eligible_laya_candidates(request))
    batches = (
        LayaAttentionMicrobatch(
            phase="evidence",
            batch_index=0,
            candidate_ids=tuple(item["fragment_id"] for item in packets),
            cache_hit_ids=tuple(item["fragment_id"] for item in packets),
            cached_origins=tuple(
                LayaCachedOrigin(item_id=item["fragment_id"], presentation_sha256="a" * 64)
                for item in packets
            ),
        ),
        LayaAttentionMicrobatch(
            phase="probe",
            batch_index=0,
            candidate_ids=probe_ids,
            cache_hit_ids=probe_ids,
            cached_origins=tuple(
                LayaCachedOrigin(item_id=item, presentation_sha256="b" * 64) for item in probe_ids
            ),
        ),
    )
    payload: dict[str, JsonValue] = {
        "evidence_serializer": SERIALIZER_ID,
        "ordered_fragments": [
            {
                "fragment_id": item["fragment_id"],
                "description_sha256": hashlib.sha256(item["description"].encode()).hexdigest(),
            }
            for item in packets
        ],
        "ordered_probes": [
            {
                "probe_id": item.probe_id,
                "description_sha256": hashlib.sha256(item.description.encode()).hexdigest(),
            }
            for item in eligible_laya_candidates(request)
        ],
        "microbatches": [item.model_dump(mode="json") for item in batches],
    }
    trace = DecisionPresentationTrace(
        provider=response.provider,
        format_id="laya-worker-attention-v2",
        payload=payload,
        payload_sha256=presentation_payload_sha256(payload),
    )
    assert response.model_copy(update={"presentation_trace": trace}).validate_against(request)
    wrong: dict[str, JsonValue] = {
        **payload,
        "ordered_fragments": [{"fragment_id": "wrong", "description_sha256": "0" * 64}],
    }
    wrong_trace = DecisionPresentationTrace(
        provider=response.provider,
        format_id="laya-worker-attention-v2",
        payload=wrong,
        payload_sha256=presentation_payload_sha256(wrong),
    )
    with pytest.raises(ValueError):
        response.model_copy(update={"presentation_trace": wrong_trace}).validate_against(request)

    historical: dict[str, JsonValue] = {"microbatches": [batches[1].model_dump(mode="json")]}
    historical_trace = DecisionPresentationTrace(
        provider=response.provider,
        format_id="laya-worker-attention-v1",
        payload=historical,
        payload_sha256=presentation_payload_sha256(historical),
    )
    assert response.model_copy(update={"presentation_trace": historical_trace}).validate_against(
        request
    )


@pytest.mark.parametrize(
    "mode", ["no_trace", "worker_truncated", "cache", "state_truncated", "split_questions"]
)
def test_laya_abstains_without_proof_worker_saw_exact_conflicting_fact(mode: str) -> None:
    base = _request()
    evidence = EvidenceContext(
        evidence_id=EvidenceId.new(),
        observed_at=NOW,
        captured_at=NOW,
        probe_id="core.system",
        summary="A device problem code observation.",
        facts={"device.problem_code": 10},
        status=EvidenceContextStatus.OBSERVED,
        case_scope="current_case",
        incident_relevant=True,
    )
    request = DecisionRequest.model_validate(
        {
            **base.model_dump(mode="python"),
            "schema_version": 3,
            "evidence_ids": (evidence.evidence_id,),
            "evidence_context": (evidence,),
            "hypothesis_briefs": ("The device should report no problem code.",),
            "hypothesis_checks": (
                FastHypothesisCheck(
                    hypothesis_index=0,
                    probe_id="core.system",
                    fact_name="device.problem_code",
                    expected_value=0,
                    observed_after=NOW - timedelta(seconds=1),
                ),
            ),
        }
    )
    fragment_id = evidence_packets((evidence,), priority_paths=("device.problem_code",))[0][
        "fragment_id"
    ]
    microbatches = {
        "no_trace": (),
        "worker_truncated": (_evidence_microbatch(fragment_id, truncated=True),),
        "cache": (_evidence_microbatch(fragment_id, cached=True),),
        "state_truncated": (_evidence_microbatch(fragment_id, state_truncated=True),),
        "split_questions": (_evidence_microbatch(fragment_id, split_questions=True),),
    }[mode]
    result = LayaAttentionResult(
        ranked_probe_ids=("application.snapshot", "eventlog.application"),
        considered_probe_ids=("application.snapshot", "eventlog.application"),
        considered_evidence_ids=(str(evidence.evidence_id),),
        considered_attention_page_ids=(f"{evidence.evidence_id}:0",),
        microbatches=microbatches,
    )

    response = LayaDecisionProvider(ranker=_Ranker(result)).decide(request)

    assert response.signals == ()
    assert response.requires_reasoning is False


def test_laya_requests_deep_review_after_two_coordinator_stagnant_rounds() -> None:
    base = _request()
    request = DecisionRequest.model_validate(
        {
            **base.model_dump(mode="python"),
            "schema_version": 3,
            "stagnant_rounds": 2,
        }
    )
    result = LayaAttentionResult(
        ranked_probe_ids=("application.snapshot", "eventlog.application"),
        considered_probe_ids=("application.snapshot", "eventlog.application"),
        considered_evidence_ids=(str(request.evidence_ids[0]),),
    )

    response = LayaDecisionProvider(ranker=_Ranker(result)).decide(request)

    assert response.requires_reasoning is True
    assert tuple(item.kind.value for item in response.signals) == ("no_progress_suspected",)
    assert response.signals[0].evidence_ids == ()
    assert response.validate_against(request) == response


@pytest.mark.parametrize("mode", ["omitted", "later_page", "truncated_scalar"])
def test_laya_abstains_when_exact_conflicting_fact_was_not_on_considered_preview(
    mode: str,
) -> None:
    base = _request()
    fact_name = "device.status" if mode == "truncated_scalar" else "device.problem_code"
    actual = "driver problem " * 30 if mode == "truncated_scalar" else 10
    expected = "healthy" if mode == "truncated_scalar" else 0
    evidence = EvidenceContext(
        evidence_id=EvidenceId.new(),
        observed_at=NOW,
        captured_at=NOW,
        probe_id="core.system",
        summary="A device status observation.",
        facts={fact_name: actual},
        status=EvidenceContextStatus.OBSERVED,
        case_scope="current_case",
        incident_relevant=True,
    )
    first_page = (
        evidence
        if mode == "truncated_scalar"
        else evidence.model_copy(update={"facts": {"other.fact": 1}})
    )
    pages = (first_page, evidence) if mode == "later_page" else (first_page,)
    request = DecisionRequest.model_validate(
        {
            **base.model_dump(mode="python"),
            "schema_version": 3,
            "evidence_ids": (evidence.evidence_id,),
            "evidence_context": (evidence,),
            "attention_context": pages,
            "hypothesis_briefs": ("A typed device status expectation.",),
            "hypothesis_checks": (
                FastHypothesisCheck(
                    hypothesis_index=0,
                    probe_id="core.system",
                    fact_name=fact_name,
                    expected_value=expected,
                    observed_after=NOW - timedelta(seconds=1),
                ),
            ),
        }
    )
    result = LayaAttentionResult(
        ranked_probe_ids=("application.snapshot", "eventlog.application"),
        considered_probe_ids=("application.snapshot", "eventlog.application"),
        considered_evidence_ids=(str(evidence.evidence_id),),
        considered_attention_page_ids=(f"{evidence.evidence_id}:0",),
        microbatches=(
            _evidence_microbatch(
                LayaDecisionProvider.evidence_fragments_for_laya(request)[0]["fragment_id"]
            ),
        ),
    )

    response = LayaDecisionProvider(ranker=_Ranker(result)).decide(request)

    assert response.signals == ()
    assert response.requires_reasoning is False


@pytest.mark.parametrize("change", ["future", "historical", "partial", "unconsidered", "matching"])
def test_laya_does_not_call_uncertain_or_unseen_fact_a_contradiction(change: str) -> None:
    base = _request()
    observed_at = NOW + timedelta(minutes=1) if change == "future" else NOW
    evidence = EvidenceContext(
        evidence_id=EvidenceId.new(),
        observed_at=observed_at,
        captured_at=observed_at,
        probe_id="core.system",
        summary="A device status observation.",
        facts={"device.problem_code": 10},
        status=(
            EvidenceContextStatus.PARTIAL if change == "partial" else EvidenceContextStatus.OBSERVED
        ),
        case_scope="historical" if change == "historical" else "current_case",
        incident_relevant=True,
    )
    request = DecisionRequest.model_validate(
        {
            **base.model_dump(mode="python"),
            "schema_version": 3,
            "evidence_ids": (*base.evidence_ids, evidence.evidence_id),
            "evidence_context": (*base.evidence_context, evidence),
            "hypothesis_briefs": ("A typed device status expectation.",),
            "hypothesis_checks": (
                FastHypothesisCheck(
                    hypothesis_index=0,
                    probe_id="core.system",
                    fact_name="device.problem_code",
                    expected_value=10 if change == "matching" else 0,
                    observed_after=NOW - timedelta(seconds=1),
                ),
            ),
        }
    )
    result = LayaAttentionResult(
        ranked_probe_ids=("application.snapshot", "eventlog.application"),
        considered_probe_ids=("application.snapshot", "eventlog.application"),
        considered_evidence_ids=() if change == "unconsidered" else (str(evidence.evidence_id),),
    )

    response = LayaDecisionProvider(ranker=_Ranker(result)).decide(request)

    assert response.signals == ()
    assert response.requires_reasoning is False


def test_provider_obeys_deadline_budget_and_covers_all_candidates() -> None:
    expired_ranker = _Ranker(
        LayaAttentionResult(
            ranked_probe_ids=("application.snapshot",),
            considered_probe_ids=("application.snapshot",),
        )
    )
    expired = LayaDecisionProvider(ranker=expired_ranker).decide(
        _request(deadline_at=NOW - timedelta(seconds=1))
    )
    assert expired.degraded is True
    assert expired_ranker.calls == []

    ranker = _Ranker(
        LayaAttentionResult(
            ranked_probe_ids=("eventlog.application", "application.snapshot"),
            considered_probe_ids=("eventlog.application", "application.snapshot"),
        )
    )
    response = LayaDecisionProvider(ranker=ranker).decide(_request(budget_ms=150))
    assert len(ranker.calls[0]["candidates"]) == 2  # type: ignore[arg-type]
    assert sum(item.estimated_cost_ms for item in response.proposals) <= 150


def test_provider_still_ranks_attention_context_when_no_probe_is_eligible() -> None:
    base = _request()
    request = base.model_copy(
        update={
            "completed_probe_ids": frozenset(
                {"core.system", "application.snapshot", "eventlog.application"}
            ),
            "preferred_probe_ids": ("eventlog.application",),
            "attention_context": base.evidence_context,
        }
    )
    attention_id = str(request.attention_context[0].evidence_id)
    ranker = _Ranker(
        LayaAttentionResult(
            ranked_evidence_ids=(attention_id,),
            considered_evidence_ids=(attention_id,),
            attention_notes=("ordinal_relevance_only",),
        )
    )

    response = LayaDecisionProvider(ranker=ranker).decide(request)

    assert response.provider.provider_id == "laya-local-decision"
    assert response.proposals == ()
    assert response.considered_evidence_count == 1
    assert ranker.calls[0]["candidates"] == ()
    assert ranker.calls[0]["state"]["preferred_probe_ids"] == ["eventlog.application"]  # type: ignore[index]
    assert ranker.calls[0]["evidence"]  # type: ignore[index]


def test_attention_only_request_skips_probe_scoring_and_proposals() -> None:
    request = _request().model_copy(update={"attention_only": True})
    evidence_id = str(request.evidence_ids[0])
    ranker = _Ranker(
        LayaAttentionResult(
            ranked_evidence_ids=(evidence_id,),
            considered_evidence_ids=(evidence_id,),
            ranked_attention_page_ids=(f"{evidence_id}:0",),
            considered_attention_page_ids=(f"{evidence_id}:0",),
            attention_notes=("ordinal_relevance_only",),
        )
    )

    response = LayaDecisionProvider(ranker=ranker).decide(request)

    assert response.provider.provider_id == "laya-local-decision"
    assert response.proposals == ()
    assert ranker.calls[0]["candidates"] == ()


def test_state_preserves_graph_mechanisms_instead_of_slicing_packet_json() -> None:
    request = _request().model_copy(
        update={
            "reference_context": (
                {
                    "pack_id": "windows-diagnostics",
                    "nodes": [
                        {
                            "node_id": "kn_process_startup",
                            "label": "Process startup",
                            "aliases": ["launch"],
                            "padding": "x" * 1000,
                        },
                        {
                            "node_id": "kn_eventlog_application",
                            "label": "Application event log",
                            "aliases": [],
                        },
                    ],
                    "relations": [
                        {
                            "relation_id": "kr_startup.eventlog",
                            "source_node_id": "kn_process_startup",
                            "target_node_id": "kn_eventlog_application",
                            "relationship": "can_contribute_to",
                            "mechanism": "Loader failures can terminate a process during startup.",
                            "conditions": ["process exits before its window appears"],
                            "distinguishing_probe_ids": ["eventlog.application"],
                            "limitations": ["an event does not by itself prove cause"],
                        }
                    ],
                },
            )
        }
    )

    ranker = _Ranker(
        LayaAttentionResult(
            ranked_probe_ids=("eventlog.application", "application.snapshot"),
            considered_probe_ids=("eventlog.application", "application.snapshot"),
        )
    )
    LayaDecisionProvider(ranker=ranker).decide(request)
    state = cast(dict[str, object], ranker.calls[0]["state"])
    assert isinstance(state, dict)

    assert tuple(state)[:3] == (
        "reference_knowledge",
        "machine_relationships",
        "preferred_probe_ids",
    )
    references = cast(list[dict[str, object]], state["reference_knowledge"])
    assert isinstance(references, list)
    assert references[0]["mechanism"] == ("Loader failures can terminate a process during startup.")
    assert references[0]["source"] == "Process startup"
    assert references[0]["distinguishing_probe_ids"] == ["eventlog.application"]


def test_semantic_packets_cover_many_pages_and_keep_late_alarm_visible() -> None:
    base = _request()
    evidence_id = base.evidence_ids[0]
    pages = tuple(
        EvidenceContext(
            evidence_id=evidence_id,
            observed_at=NOW - timedelta(minutes=index),
            captured_at=NOW,
            probe_id="eventlog.application",
            summary="Routine activity " + "context " * 80,
            facts={
                **{f"routine.{fact}": "detail " * 45 for fact in range(12)},
                "critical.failure": "LATE_DISK_FAILURE" if index == 38 else "none",
            },
            status=EvidenceContextStatus.PARTIAL if index == 38 else EvidenceContextStatus.OBSERVED,
            limitations=("Some source records were unavailable",) if index == 38 else (),
        )
        for index in range(39)
    )
    request = base.model_copy(update={"attention_context": pages})

    ranker = _Ranker(LayaAttentionResult())
    LayaDecisionProvider(ranker=ranker).decide(request)
    fragments = cast(tuple[dict[str, str], ...], ranker.calls[0]["evidence"])
    first_batch_pages = {fragment["page_id"] for fragment in fragments[:20]}
    late_page_id = f"{evidence_id}:38"

    assert len(fragments) == 256
    assert len(first_batch_pages) == 20
    assert late_page_id in first_batch_pages
    late = next(fragment for fragment in fragments if fragment["page_id"] == late_page_id)
    packet = json.loads(late["description"])
    assert late["fragment_id"].startswith(f"{late_page_id}:fact:")
    assert packet["projection"] == SERIALIZER_ID
    assert late["page_id"] == late_page_id
    assert late["evidence_id"] == str(evidence_id)
    assert packet["observed_at"] == pages[38].observed_at.isoformat()
    assert packet["captured_at"] == pages[38].captured_at.isoformat()
    assert packet["status"] == "partial"
    assert packet["redaction_applied"] is True
    assert packet["metric"] == "critical.failure"
    assert packet["value"] == "LATE_DISK_FAILURE"
    assert "Some source records were unavailable" in packet["limitations"]
    assert packet["facts_omitted"] > 0
    assert len(late["description"]) <= 800
    state = cast(dict[str, object], ranker.calls[0]["state"])
    assert SERIALIZER_ID in cast(list[str], state["coverage_notes"])


def test_packet_reserves_room_for_alarm_when_optional_text_is_maximal() -> None:
    base = _request()
    alarm_key = "critical." + "x" * 111
    alarm = EvidenceContext(
        evidence_id=base.evidence_ids[0],
        observed_at=NOW,
        captured_at=NOW,
        probe_id="a" * 120,
        summary="s" * 1000,
        facts={alarm_key: "DISK_FAILURE"},
        status=EvidenceContextStatus.PARTIAL,
        limitations=("l" * 240,) * 3,
    )
    request = base.model_copy(update={"attention_context": (*base.evidence_context * 255, alarm)})
    ranker = _Ranker(LayaAttentionResult())

    LayaDecisionProvider(ranker=ranker).decide(request)

    fragments = cast(tuple[dict[str, str], ...], ranker.calls[0]["evidence"])
    late = next(item for item in fragments if item["page_id"].endswith(":255"))
    packet = json.loads(late["description"])
    assert packet["metric"] == alarm_key
    assert packet["value"] == "DISK_FAILURE"
    assert packet["value_quality"] == "exact"
    assert packet["facts_omitted"] == 0
    assert packet["limitations_omitted"] > 0
    assert late["page_id"] == f"{base.evidence_ids[0]}:255"
    assert late["evidence_id"] == str(base.evidence_ids[0])
    assert packet["redaction_applied"] is True
    assert len(json.dumps(packet, ensure_ascii=False, separators=(",", ":"))) <= 800

    long_alarm = alarm.model_copy(update={"facts": {alarm_key: "DISK_FAILURE" + "x" * 500}})
    long_request = base.model_copy(update={"attention_context": (long_alarm,)})
    long_ranker = _Ranker(LayaAttentionResult())
    LayaDecisionProvider(ranker=long_ranker).decide(long_request)
    long_fragment = cast(tuple[dict[str, str], ...], long_ranker.calls[0]["evidence"])[0]
    long_packet = json.loads(long_fragment["description"])
    assert long_packet["value_quality"] == "truncated"
    assert long_packet["metric"] == alarm_key
    assert "value" not in long_packet
    assert len(long_fragment["description"]) <= 800
