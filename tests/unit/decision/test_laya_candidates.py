"""Laya ranks opaque candidate instances without gaining invocation authority."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from systemsense.decision.candidates import (
    AdmittedCandidateRefV1,
    CandidateDecisionGapV1,
    CandidateDecisionRequestV1,
    CandidateDecisionResponseV1,
)
from systemsense.decision.laya import LayaDecisionProvider
from systemsense.decision.provider import CandidateDecisionProvider
from systemsense.decision.semantic_packets import SERIALIZER_ID, evidence_packets
from systemsense.domain.ids import CaseId, EvidenceId
from systemsense.domain.probes import SafetyClass
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.inference.laya_runtime import (
    LayaAttentionMicrobatch,
    LayaAttentionResult,
    LayaCachedOrigin,
    LayaRuntimeConfig,
    LayaRuntimeError,
    LayaSubprocessRuntime,
)
from systemsense.orchestration.scheduler import ResourceClass


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
        self.calls.append({"state": state, "evidence": evidence, "candidates": candidates})
        if isinstance(self.result, Exception):
            raise self.result
        return self.result


def _request() -> CandidateDecisionRequestV1:
    candidates = tuple(
        AdmittedCandidateRefV1(
            candidate_id="cand_v1_" + suffix * 32,
            probe_id="application.target_pressure",
            description=f"Observed application target {index}",
            manifest_sha256="a" * 64,
            invocation_sha256=suffix * 64,
            cost_ms=1000,
            resource_class=ResourceClass.PROCESS,
            safety_class=SafetyClass.R1,
        )
        for index, suffix in enumerate(("a", "b"), start=1)
    )
    return CandidateDecisionRequestV1(
        case_id=CaseId.new(),
        state_version=4,
        correlation_id="candidate:4",
        deadline_at=datetime.now(UTC) + timedelta(seconds=10),
        symptom="PDF application is slow",
        available_candidates=candidates,
        budget_ms=2000,
        max_candidates=1,
    )


def _attention(ids: tuple[str, ...]) -> LayaAttentionResult:
    return LayaAttentionResult(
        ranked_probe_ids=tuple(reversed(ids)),
        considered_probe_ids=ids,
        microbatches=(
            LayaAttentionMicrobatch(
                phase="probe", batch_index=0, candidate_ids=ids, inference_ids=ids
            ),
        ),
    )


def test_candidate_instances_share_probe_but_laya_ranks_exact_ids() -> None:
    request = _request()
    ids = tuple(item.candidate_id for item in request.available_candidates)
    ranker = _Ranker(_attention(ids))

    provider: CandidateDecisionProvider = LayaDecisionProvider(ranker=ranker)
    result = provider.decide_candidates(request)

    assert isinstance(result, CandidateDecisionResponseV1)
    assert result.ranked_candidate_ids == tuple(reversed(ids))
    assert result.proposals[0].candidate_id == ids[1]
    assert len(result.proposals) == 1
    assert ranker.calls[0]["candidates"] == (
        {"probe_id": ids[0], "description": "Observed application target 1"},
        {"probe_id": ids[1], "description": "Observed application target 2"},
    )
    state = ranker.calls[0]["state"]
    assert isinstance(state, dict)
    assert state["decision_contract"] == "candidate_decision_v1"
    assert state["candidate_manifest_sha256"] == request.candidate_manifest_sha256
    assert result.presentation_trace is None  # A fake ranker is not worker attestation.


def test_score_ordered_considered_ids_still_cover_offered_candidates() -> None:
    request = _request()
    ids = tuple(item.candidate_id for item in request.available_candidates)
    attention = _attention(ids).model_copy(update={"considered_probe_ids": tuple(reversed(ids))})

    result = LayaDecisionProvider(ranker=_Ranker(attention)).decide_candidates(request)

    assert isinstance(result, CandidateDecisionResponseV1)
    assert result.ranked_candidate_ids == tuple(reversed(ids))
    assert result.considered_candidate_ids == ids


@pytest.mark.parametrize(
    "ranked,considered,batched",
    [
        (("unknown", "other"), None, None),
        (("duplicate", "duplicate"), None, None),
        (("missing",), None, None),
        (None, ("missing",), None),
        (None, None, ("wrong-order",)),
    ],
)
def test_invalid_permutation_coverage_or_microbatch_fails_closed(
    ranked: tuple[str, ...] | None,
    considered: tuple[str, ...] | None,
    batched: tuple[str, ...] | None,
) -> None:
    request = _request()
    ids = tuple(item.candidate_id for item in request.available_candidates)
    attention = LayaAttentionResult(
        ranked_probe_ids=ranked if ranked is not None else ids,
        considered_probe_ids=considered if considered is not None else ids,
        microbatches=(
            LayaAttentionMicrobatch(
                phase="probe",
                batch_index=0,
                candidate_ids=batched if batched is not None else ids,
                inference_ids=batched if batched is not None else ids,
            ),
        ),
    )

    result = LayaDecisionProvider(ranker=_Ranker(attention)).decide_candidates(request)

    assert isinstance(result, CandidateDecisionGapV1)
    assert not hasattr(result, "proposals")


def test_unavailable_ranker_is_explicit_gap_and_new_namespace_changes_cache_key() -> None:
    request = _request()
    provider = LayaDecisionProvider(ranker=_Ranker(LayaRuntimeError("worker down")))
    gap = provider.decide_candidates(request)
    assert isinstance(gap, CandidateDecisionGapV1)
    assert gap.reason_code == "ranker_unavailable"

    ids = tuple(item.candidate_id for item in request.available_candidates)
    batch = tuple(
        {"probe_id": item.candidate_id, "description": item.description}
        for item in request.available_candidates
    )
    cache_key = LayaSubprocessRuntime._cache_key  # pyright: ignore[reportPrivateUsage]
    legacy = cache_key(
        "probe", {"attention_kind": "probe_relevance"}, ids[0], batch[0]["description"], batch=batch
    )
    vnext = cache_key(
        "probe",
        {
            "attention_kind": "probe_relevance",
            "decision_contract": "candidate_decision_v1",
            "candidate_manifest_sha256": request.candidate_manifest_sha256,
        },
        ids[0],
        batch[0]["description"],
        batch=batch,
    )
    assert legacy != vnext
    assert vnext != cache_key(
        "probe",
        {
            "attention_kind": "probe_relevance",
            "decision_contract": "candidate_decision_v1",
            "candidate_manifest_sha256": request.candidate_manifest_sha256,
        },
        ids[0],
        batch[0]["description"],
        batch=tuple(reversed(batch)),
    )
    changed = (
        {**batch[0], "description": "Different privacy projection"},
        batch[1],
    )
    assert vnext != cache_key(
        "probe",
        {
            "attention_kind": "probe_relevance",
            "decision_contract": "candidate_decision_v1",
            "candidate_manifest_sha256": request.candidate_manifest_sha256,
        },
        ids[0],
        changed[0]["description"],
        batch=changed,
    )


def test_cache_hit_without_worker_origin_digest_is_rejected() -> None:
    request = _request()
    ids = tuple(item.candidate_id for item in request.available_candidates)
    attention = LayaAttentionResult(
        ranked_probe_ids=ids,
        considered_probe_ids=ids,
        microbatches=(
            LayaAttentionMicrobatch(
                phase="probe",
                batch_index=0,
                candidate_ids=ids,
                cache_hit_ids=ids,
                cached_origins=tuple(LayaCachedOrigin(item_id=item) for item in ids),
            ),
        ),
    )

    result = LayaDecisionProvider(ranker=_Ranker(attention)).decide_candidates(request)

    assert isinstance(result, CandidateDecisionGapV1)
    assert result.reason_code == "invalid_result"


def test_partial_evidence_batches_do_not_create_complete_trace(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = _request()
    evidence_ids = (EvidenceId.new(), EvidenceId.new())
    now = datetime.now(UTC)
    contexts = tuple(
        EvidenceContext(
            evidence_id=evidence_id,
            observed_at=now,
            captured_at=now,
            probe_id="core.system",
            summary=f"Observation {index}",
            status=EvidenceContextStatus.OBSERVED,
        )
        for index, evidence_id in enumerate(evidence_ids)
    )
    request = base.model_copy(update={"evidence_ids": evidence_ids, "evidence_context": contexts})
    ids = tuple(item.candidate_id for item in request.available_candidates)
    projected = evidence_packets(contexts)
    first_fragment = projected[0]["fragment_id"]
    partial = LayaAttentionResult(
        ranked_probe_ids=ids,
        considered_probe_ids=ids,
        considered_evidence_ids=(str(evidence_ids[0]),),
        microbatches=(
            LayaAttentionMicrobatch(
                phase="evidence",
                batch_index=0,
                candidate_ids=(first_fragment,),
                cache_hit_ids=(first_fragment,),
                cached_origins=(
                    LayaCachedOrigin(item_id=first_fragment, presentation_sha256="a" * 64),
                ),
            ),
            LayaAttentionMicrobatch(
                phase="probe",
                batch_index=0,
                candidate_ids=ids,
                cache_hit_ids=ids,
                cached_origins=tuple(
                    LayaCachedOrigin(item_id=item, presentation_sha256="b" * 64) for item in ids
                ),
            ),
        ),
    )
    # A real-runtime instance with a replaced attend method exercises only
    # trace construction; no subprocess or model is launched by this test.
    ranker = LayaSubprocessRuntime(
        LayaRuntimeConfig(interpreter_path=tmp_path / "python.exe", model_path=tmp_path)
    )
    current = [partial]

    def attend(**_kwargs: object) -> LayaAttentionResult:
        return current[0]

    monkeypatch.setattr(ranker, "attend", attend)
    response = LayaDecisionProvider(ranker=ranker).decide_candidates(request)
    assert isinstance(response, CandidateDecisionResponseV1)
    assert response.presentation_trace is None

    wrong = partial.model_copy(
        update={
            "microbatches": (
                partial.microbatches[0].model_copy(update={"candidate_ids": ("wrong-fragment",)}),
                partial.microbatches[1],
            )
        }
    )
    current[0] = wrong
    assert isinstance(
        LayaDecisionProvider(ranker=ranker).decide_candidates(request), CandidateDecisionGapV1
    )

    second_fragment = projected[1]["fragment_id"]
    full = partial.model_copy(
        update={
            "considered_evidence_ids": tuple(str(item) for item in evidence_ids),
            "microbatches": (
                LayaAttentionMicrobatch(
                    phase="evidence",
                    batch_index=0,
                    candidate_ids=(first_fragment, second_fragment),
                    cache_hit_ids=(first_fragment, second_fragment),
                    cached_origins=(
                        LayaCachedOrigin(item_id=first_fragment, presentation_sha256="a" * 64),
                        LayaCachedOrigin(item_id=second_fragment, presentation_sha256="c" * 64),
                    ),
                ),
                partial.microbatches[1],
            ),
        }
    )
    current[0] = full
    complete = LayaDecisionProvider(ranker=ranker).decide_candidates(request)
    assert isinstance(complete, CandidateDecisionResponseV1)
    assert complete.presentation_trace is not None
    assert complete.presentation_trace.format_id == "laya-worker-candidate-attention-v2"
    assert complete.presentation_trace.payload["evidence_serializer"] == SERIALIZER_ID
    assert complete.presentation_trace.payload["evidence_fragments"] == [
        first_fragment,
        second_fragment,
    ]
