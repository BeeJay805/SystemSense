"""Mixed-frontier attention ranks opaque references, never executable selectors."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from typing import Literal, cast

import pytest

from systemsense.decision.contracts import ProviderIdentity
from systemsense.decision.frontier_ranker import (
    FrontierItemSemanticV1,
    FrontierRankRequestV1,
    MixedFrontierRanker,
    SemanticPacketRefV1,
)
from systemsense.decision.semantic_packets import evidence_packets
from systemsense.domain.ids import CaseId, EvidenceId
from systemsense.domain.time import utc_now
from systemsense.evidence.graph import AssertionStatus, RelationKind
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.inference.laya_runtime import (
    LayaAttentionMicrobatch,
    LayaAttentionResult,
    LayaQuestionPresentation,
    LayaRuntimeError,
    LayaWorkerPresentation,
)
from systemsense.storage.search_frontier import (
    FrontierItemV1,
    FrontierReferenceV1,
    FrontierStatus,
    RelevantVersionsV1,
)

_CASE = CaseId(root="case_" + "a" * 32)
_NOW = datetime.now(UTC)
_PROVIDER = ProviderIdentity(
    provider_id="laya-frontier-decision", provider_version="1", role="fast_decision"
)
_MODEL_SHA = "b" * 64


def _item(index: int, kind: str, *, evidence_version: int = 1) -> FrontierItemV1:
    reference_values: dict[str, object] = {"kind": kind}
    if kind == "retrieve_evidence":
        reference_values["evidence_id"] = EvidenceId(root=f"ev_{index:032x}")
    elif kind == "measure":
        reference_values["candidate_id"] = f"cand_v1_{index:032x}"
    elif kind == "review_branch":
        reference_values["branch_id"] = f"branch_v1_{index:032x}"
    else:
        reference_values["question_id"] = f"question_v1_{index:032x}"
    return FrontierItemV1(
        item_id=f"fr_v1_{index:064x}",
        case_id=_CASE,
        reference=FrontierReferenceV1.model_validate(reference_values),
        versions=RelevantVersionsV1(objective=1, evidence=evidence_version),
        status=FrontierStatus.REQUESTED,
        created_at=_NOW,
    )


def _request(*, evidence_version: int = 1) -> FrontierRankRequestV1:
    context = EvidenceContext(
        evidence_id=EvidenceId(root="ev_" + "f" * 32),
        observed_at=_NOW,
        captured_at=_NOW,
        probe_id="synthetic.snapshot",
        summary="Synthetic observation",
        facts={"gpu.clock": {"value": 450, "unit": "MHz"}},
        status=EvidenceContextStatus.OBSERVED,
        case_scope="current_case",
        incident_relevant=True,
    )
    packet = evidence_packets((context,))[0]
    items = tuple(
        _item(index, kind, evidence_version=evidence_version)
        for index, kind in enumerate(
            ("retrieve_evidence", "measure", "review_branch", "consult_deep"), start=1
        )
    )
    details: tuple[
        tuple[
            Literal[
                "evidence_repository",
                "capability_registry",
                "knowledge_graph",
                "reasoning_question",
            ],
            Literal["observed", "documented", "inferred", "limited", "proposed"],
            str,
            Literal[
                "host",
                "device",
                "application",
                "network_adapter",
                "service",
                "component",
                "unknown",
            ],
            str,
        ],
        ...,
    ] = (
        (
            "evidence_repository",
            "observed",
            "What does the WLAN configuration show?",
            "network_adapter",
            "WLAN adapter",
        ),
        (
            "capability_registry",
            "documented",
            "What are current GPU clocks under load?",
            "device",
            "GPU",
        ),
        (
            "knowledge_graph",
            "inferred",
            "Does this driver relationship warrant inspection?",
            "component",
            "Display driver",
        ),
        (
            "reasoning_question",
            "proposed",
            "Which hypothesis best explains the evidence?",
            "host",
            "Current case",
        ),
    )
    semantics = tuple(
        FrontierItemSemanticV1(
            item_id=item.item_id,
            case_id=_CASE,
            reference_id=(
                str(item.reference.evidence_id)
                if item.reference.evidence_id is not None
                else item.reference.candidate_id
                or item.reference.branch_id
                or item.reference.question_id
                or ""
            ),
            source_kind=source_kind,
            source_record_sha256="a" * 64,
            source_recorded_at=_NOW,
            source_time_quality="source_recorded",
            quality=quality,
            information_goal=goal,
            target_scope=scope,
            target_label=label,
            relation_id="rel_" + "f" * 32 if item.reference.kind == "review_branch" else None,
            relation_kind=(
                RelationKind.USES_DRIVER if item.reference.kind == "review_branch" else None
            ),
            relation_assertion_status=(
                AssertionStatus.INFERRED if item.reference.kind == "review_branch" else None
            ),
            relation_source_label=(
                "Application" if item.reference.kind == "review_branch" else None
            ),
            relation_target_label=(
                "Display driver" if item.reference.kind == "review_branch" else None
            ),
        )
        for item, (source_kind, quality, goal, scope, label) in zip(items, details, strict=True)
    )
    return FrontierRankRequestV1(
        case_id=_CASE,
        provider=_PROVIDER,
        model_weight_sha256=_MODEL_SHA,
        deadline_at=utc_now() + timedelta(minutes=5),
        symptom="A game is slow",
        hypothesis_briefs=("GPU clocks may be low",),
        items=items,
        item_semantics=semantics,
        evidence_packets=(SemanticPacketRefV1.model_validate(packet),),
    )


def _presentation(ids: tuple[str, ...]) -> LayaWorkerPresentation:
    return LayaWorkerPresentation(
        presentation_sha256="a" * 64,
        fitted_state_sha256="b" * 64,
        questions_sha256="c" * 64,
        presented_item_ids=ids,
        fitted_state_tokens=40,
        state_tokens_original=40,
        state_fields_omitted=0,
        state_list_items_omitted=0,
        questions=tuple(
            LayaQuestionPresentation(
                question_id=f"q{index}",
                item_id=item,
                question_sha256="d" * 64,
                instruction_tokens=10,
                instruction_presented_tokens=10,
                criteria_tokens=2,
                criteria_presented_tokens=2,
                state_presented_tokens=40,
            )
            for index, item in enumerate(ids)
        ),
    )


class _Ranker:
    def __init__(self, *, partial: bool = False, reordered_considered: bool = False) -> None:
        self.calls: list[dict[str, object]] = []
        self.partial = partial
        self.reordered_considered = reordered_considered

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
                "timeout": timeout_seconds,
            }
        )
        item_ids = tuple(item["probe_id"] for item in candidates)
        fragment_ids = tuple(item["fragment_id"] for item in evidence)
        return LayaAttentionResult(
            ranked_probe_ids=tuple(reversed(item_ids)),
            considered_probe_ids=(
                item_ids[:-1]
                if self.partial
                else tuple(reversed(item_ids))
                if self.reordered_considered
                else item_ids
            ),
            considered_attention_page_ids=tuple(item["page_id"] for item in evidence),
            attention_notes=(
                "coverage_limited=false",
                "state_truncated_batches=0",
                "instruction_truncated_items=0",
            ),
            microbatches=(
                LayaAttentionMicrobatch(
                    phase="evidence",
                    batch_index=0,
                    candidate_ids=fragment_ids,
                    inference_ids=fragment_ids,
                    worker_presentation=_presentation(fragment_ids),
                ),
                LayaAttentionMicrobatch(
                    phase="probe",
                    batch_index=0,
                    candidate_ids=item_ids,
                    inference_ids=item_ids,
                    worker_presentation=_presentation(item_ids),
                ),
            ),
        )


def test_mixed_frontier_ranks_only_supplied_ids_with_full_coverage() -> None:
    request = _request()
    ranker = _Ranker()
    adapter = MixedFrontierRanker(ranker=ranker, provider=_PROVIDER, model_weight_sha256=_MODEL_SHA)
    assert adapter.provider == _PROVIDER
    assert adapter.model_weight_sha256 == _MODEL_SHA

    result = adapter.rank(request)

    expected = tuple(item.item_id for item in request.items)
    assert result.ranked_item_ids == tuple(reversed(expected))
    assert result.considered_item_ids == expected
    assert result.coverage_complete is True
    assert result.model_abstained is False
    assert result.ranking_source == "laya"
    assert result.degraded_reason is None
    candidates = cast(tuple[dict[str, str], ...], ranker.calls[0]["candidates"])
    assert {item["probe_id"] for item in candidates} == set(expected)
    assert all("target_handle" not in item["description"] for item in candidates)
    descriptions = [json.loads(item["description"]) for item in candidates]
    assert descriptions[0]["target_label"] == "WLAN adapter"
    assert "WLAN configuration" in descriptions[0]["information_goal"]
    assert descriptions[1]["target_label"] == "GPU"
    assert "GPU clocks" in descriptions[1]["information_goal"]
    assert descriptions[2]["relation_kind"] == "uses_driver"
    assert descriptions[2]["relation_assertion_status"] == "inferred"
    assert descriptions[2]["relation_source_label"] == "Application"
    assert descriptions[2]["relation_target_label"] == "Display driver"
    assert descriptions[2]["relation_is_causal_proof"] is False


def test_opt_in_frontier_capture_keeps_worker_trace_and_skips_rank_cache() -> None:
    class CapturingRanker(_Ranker):
        def attend(self, **kwargs: object) -> LayaAttentionResult:
            self.calls.append(kwargs)
            return _Ranker.attend(
                self,
                state=cast(dict[str, object], kwargs["state"]),
                evidence=cast(tuple[dict[str, str], ...], kwargs["evidence"]),
                candidates=cast(tuple[dict[str, str], ...], kwargs["candidates"]),
                timeout_seconds=cast(float, kwargs["timeout_seconds"]),
            )

    request = _request()
    ranker = CapturingRanker()
    adapter = MixedFrontierRanker(ranker=ranker, provider=_PROVIDER, model_weight_sha256=_MODEL_SHA)
    captured: list[tuple[str, int]] = []

    first = adapter.rank(
        request,
        capture_worker_batch=lambda phase, index, _call, _proof: captured.append((phase, index)),
    )
    second = adapter.rank(
        request,
        capture_worker_batch=lambda phase, index, _call, _proof: captured.append((phase, index)),
    )

    assert first.cache_hit is False
    assert second.cache_hit is False
    assert first.presentation_trace is not None
    assert first.presentation_trace.microbatches[1].phase == "probe"
    assert len(ranker.calls) == 4  # Each call is recorded by the override and base helper.
    assert ranker.calls[0]["capture_model_input"] is True
    assert callable(ranker.calls[0]["capture_exact_worker_call"])


def test_frontier_trace_must_match_persisted_rank_order() -> None:
    request = _request()
    adapter = MixedFrontierRanker(
        ranker=_Ranker(), provider=_PROVIDER, model_weight_sha256=_MODEL_SHA
    )
    response = adapter.rank(request)
    assert response.presentation_trace is not None
    forged_trace = response.presentation_trace.model_copy(
        update={"ranked_probe_ids": tuple(reversed(response.ranked_item_ids))}
    )

    with pytest.raises(ValueError, match="trace"):
        response.model_copy(update={"presentation_trace": forged_trace}).validate_against(request)


def test_partial_attention_falls_back_without_laundering_model_rank() -> None:
    request = _request()
    adapter = MixedFrontierRanker(
        ranker=_Ranker(partial=True), provider=_PROVIDER, model_weight_sha256=_MODEL_SHA
    )

    result = adapter.rank(request)

    assert result.ranked_item_ids == tuple(item.item_id for item in request.items)
    assert result.ranking_source == "deterministic_fallback"
    assert result.model_abstained is True
    assert result.coverage_complete is False
    assert result.degraded_reason == "incomplete_model_coverage"


def test_complete_reordered_worker_coverage_is_not_mistaken_for_missing_items() -> None:
    request = _request()
    adapter = MixedFrontierRanker(
        ranker=_Ranker(reordered_considered=True),
        provider=_PROVIDER,
        model_weight_sha256=_MODEL_SHA,
    )

    result = adapter.rank(request)

    assert result.ranking_source == "laya"
    assert result.coverage_complete is True
    assert result.model_abstained is False


def test_exact_context_cache_invalidates_on_versions_order_and_packet_content() -> None:
    request = _request()
    ranker = _Ranker()
    adapter = MixedFrontierRanker(ranker=ranker, provider=_PROVIDER, model_weight_sha256=_MODEL_SHA)

    assert adapter.rank(request).cache_hit is False
    assert adapter.rank(request).cache_hit is True
    assert len(ranker.calls) == 1
    assert adapter.rank(_request(evidence_version=2)).cache_hit is False
    assert (
        adapter.rank(
            request.model_copy(
                update={
                    "items": tuple(reversed(request.items)),
                    "item_semantics": tuple(reversed(request.item_semantics)),
                }
            )
        ).cache_hit
        is False
    )
    altered = request.evidence_packets[0].model_copy(
        update={"description": request.evidence_packets[0].description.replace("450", "451")}
    )
    assert (
        adapter.rank(request.model_copy(update={"evidence_packets": (altered,)})).cache_hit is False
    )
    richer = request.item_semantics[1].model_copy(
        update={"information_goal": "What are GPU clocks and power limits under load?"}
    )
    changed_semantics = (
        request.item_semantics[0],
        richer,
        *request.item_semantics[2:],
    )
    assert (
        adapter.rank(request.model_copy(update={"item_semantics": changed_semantics})).cache_hit
        is False
    )
    assert len(ranker.calls) == 5


def test_semantic_descriptions_are_required_ordered_and_case_bound() -> None:
    request = _request()
    adapter = MixedFrontierRanker(
        ranker=_Ranker(), provider=_PROVIDER, model_weight_sha256=_MODEL_SHA
    )
    with pytest.raises(ValueError, match="semantic"):
        adapter.rank(request.model_copy(update={"item_semantics": request.item_semantics[:-1]}))
    with pytest.raises(ValueError, match="semantic"):
        adapter.rank(
            request.model_copy(update={"item_semantics": tuple(reversed(request.item_semantics))})
        )
    wrong_case = request.item_semantics[0].model_copy(
        update={"case_id": CaseId(root="case_" + "c" * 32)}
    )
    with pytest.raises(ValueError, match="semantic"):
        adapter.rank(
            request.model_copy(update={"item_semantics": (wrong_case, *request.item_semantics[1:])})
        )
    wrong_source = request.item_semantics[1].model_copy(
        update={"reference_id": "cand_v1_" + "9" * 32}
    )
    with pytest.raises(ValueError, match="semantic"):
        adapter.rank(
            request.model_copy(
                update={
                    "item_semantics": (
                        request.item_semantics[0],
                        wrong_source,
                        *request.item_semantics[2:],
                    )
                }
            )
        )


def test_missing_source_time_is_explicit_not_fabricated() -> None:
    request = _request()
    unavailable_time = request.item_semantics[1].model_copy(
        update={"source_recorded_at": None, "source_time_quality": "not_available"}
    )
    changed = (request.item_semantics[0], unavailable_time, *request.item_semantics[2:])
    ranker = _Ranker()
    adapter = MixedFrontierRanker(ranker=ranker, provider=_PROVIDER, model_weight_sha256=_MODEL_SHA)
    assert (
        adapter.rank(request.model_copy(update={"item_semantics": changed})).ranking_source
        == "laya"
    )
    candidates = cast(tuple[dict[str, str], ...], ranker.calls[0]["candidates"])
    description = json.loads(candidates[1]["description"])
    assert description["source_recorded_at"] is None
    assert description["source_time_quality"] == "not_available"
    with pytest.raises(ValueError, match="time quality"):
        adapter.rank(
            request.model_copy(
                update={
                    "item_semantics": (
                        request.item_semantics[0],
                        unavailable_time.model_copy(
                            update={"source_time_quality": "source_recorded"}
                        ),
                        *request.item_semantics[2:],
                    )
                }
            )
        )


def test_missing_worker_and_expired_deadline_abstain_deterministically() -> None:
    request = _request()
    unavailable = MixedFrontierRanker(
        ranker=None, provider=_PROVIDER, model_weight_sha256=_MODEL_SHA
    )
    assert unavailable.rank(request).degraded_reason == "worker_unavailable"
    ranker = _Ranker()
    adapter = MixedFrontierRanker(ranker=ranker, provider=_PROVIDER, model_weight_sha256=_MODEL_SHA)
    expired = request.model_copy(update={"deadline_at": utc_now() - timedelta(seconds=1)})
    result = adapter.rank(expired)
    assert result.degraded_reason == "deadline_expired"
    assert not ranker.calls


@pytest.mark.parametrize(
    ("error", "reason", "diagnostic"),
    (
        (
            LayaRuntimeError("Laya attention deadline expired before full coverage"),
            "deadline_expired",
            "laya_failure=deadline",
        ),
        (
            LayaRuntimeError("Laya worker returned an invalid ranking"),
            "worker_error",
            "laya_failure=protocol",
        ),
        (
            RuntimeError("private machine-specific material must not escape"),
            "worker_error",
            "laya_failure=unexpected",
        ),
        (
            LayaRuntimeError(
                "Laya worker rejected its bounded request",
                failure_code="capture_tensor_limit",
                failure_bytes=150_000,
            ),
            "worker_error",
            "laya_failure=capture_tensor_limit",
        ),
    ),
)
def test_worker_failure_has_bounded_safe_diagnostic(
    error: Exception, reason: str, diagnostic: str
) -> None:
    class FailingRanker(_Ranker):
        def attend(self, **_kwargs: object) -> LayaAttentionResult:
            raise error

    response = MixedFrontierRanker(
        ranker=FailingRanker(), provider=_PROVIDER, model_weight_sha256=_MODEL_SHA
    ).rank(_request())

    assert response.degraded_reason == reason
    assert response.attention_notes == (
        (diagnostic, "laya_failure_bytes=150000")
        if diagnostic == "laya_failure=capture_tensor_limit"
        else (diagnostic,)
    )
    assert "private" not in response.model_dump_json()


def test_scope_and_packet_identity_reject_ambiguous_or_unsafe_inputs() -> None:
    request = _request()
    adapter = MixedFrontierRanker(
        ranker=_Ranker(), provider=_PROVIDER, model_weight_sha256=_MODEL_SHA
    )
    nonrequested = request.items[0].model_copy(update={"status": FrontierStatus.CLAIMED})
    with pytest.raises(ValueError, match="non-requested"):
        adapter.rank(request.model_copy(update={"items": (nonrequested, *request.items[1:])}))
    other_case = request.items[0].model_copy(update={"case_id": CaseId(root="case_" + "c" * 32)})
    with pytest.raises(ValueError, match="another case"):
        adapter.rank(request.model_copy(update={"items": (other_case, *request.items[1:])}))
    malformed_packet = request.evidence_packets[0].model_copy(
        update={"fragment_id": "unrelated:fact:0"}
    )
    with pytest.raises(ValueError, match="provenance"):
        adapter.rank(request.model_copy(update={"evidence_packets": (malformed_packet,)}))
    shifted_packet = request.evidence_packets[0].model_copy(
        update={"description": request.evidence_packets[0].description.replace("+00:00", "+02:00")}
    )
    with pytest.raises(ValueError, match="timestamps"):
        adapter.rank(request.model_copy(update={"evidence_packets": (shifted_packet,)}))


def test_response_contract_rejects_fallback_with_model_order() -> None:
    request = _request()
    adapter = MixedFrontierRanker(ranker=None, provider=_PROVIDER, model_weight_sha256=_MODEL_SHA)
    response = adapter.rank(request)
    with pytest.raises(ValueError, match="fallback"):
        response.model_copy(
            update={"ranked_item_ids": tuple(reversed(response.ranked_item_ids))}
        ).validate_against(request)
