from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from typing import cast

import pytest

from systemsense.decision.contracts import DecisionRequest, ProbeCapability
from systemsense.domain.ids import CaseId, EvidenceId
from systemsense.evaluation.teacher_drafts import (
    LocalOllamaTeacher,
    TeacherAttentionDraft,
    TeacherPrivacyReview,
    generate_teacher_draft,
    prepare_teacher_prompt,
    teacher_candidate_window_count,
)
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.inference.settings import LocalInferenceConfig
from systemsense.orchestration.scheduler import ResourceClass

NOW = datetime(2026, 9, 23, tzinfo=UTC)


def _request(*, attention_only: bool = False) -> DecisionRequest:
    evidence_id = EvidenceId.new()
    context = EvidenceContext(
        evidence_id=evidence_id,
        observed_at=NOW,
        captured_at=NOW,
        probe_id="windows.network",
        summary="Proxy setting observed",
        facts={"proxy.enabled": True},
        status=EvidenceContextStatus.OBSERVED,
    )
    return DecisionRequest(
        case_id=CaseId.new(),
        state_version=2,
        correlation_id="teacher_1",
        deadline_at=NOW + timedelta(minutes=1),
        symptom="browser cannot reach owned endpoint",
        evidence_ids=(evidence_id,),
        evidence_context=(context,),
        attention_only=attention_only,
        completed_probe_ids=frozenset({"windows.old"}),
        available_probes=tuple(
            ProbeCapability(
                probe_id=probe_id,
                description=f"Inspect {probe_id}",
                cost_ms=10,
                resource_class=ResourceClass.CPU,
            )
            for probe_id in ("windows.proxy", "windows.dns", "windows.old")
        ),
        budget_ms=20,
        max_probes=2,
    )


class _Teacher:
    def __init__(self, result: dict[str, object]) -> None:
        self.result = result
        self.prompt: str | None = None
        self.schema: dict[str, object] | None = None

    def complete(self, *, prompt: str, schema: dict[str, object]) -> dict[str, object]:
        self.prompt = prompt
        self.schema = schema
        assert schema["type"] == "object"
        return self.result


def _review(request: DecisionRequest) -> TeacherPrivacyReview:
    return TeacherPrivacyReview(
        prompt_sha256=sha256(prepare_teacher_prompt(request).encode("utf-8")).hexdigest(),
        reviewer_id="test_reviewer",
        reviewed_at=NOW,
    )


def test_teacher_draft_binds_exact_request_and_only_eligible_ids() -> None:
    request = _request()
    evidence_id = str(request.evidence_ids[0])
    teacher = _Teacher(
        {
            "ranked_probe_ids": ["windows.proxy", "windows.dns"],
            "cited_evidence_ids": [evidence_id],
            "abstain": False,
        }
    )
    draft = generate_teacher_draft(
        request=request,
        teacher=teacher,
        model_id="qwen3.8:27b",
        model_digest="a" * 64,
        generated_at=NOW,
        synthetic=True,
        privacy_review=_review(request),
    )
    assert draft.label_origin == "local_model_weak"
    assert draft.ranked_probe_ids == ("windows.proxy", "windows.dns")
    assert draft.eligible_candidate_ids == ("windows.dns", "windows.proxy")
    assert draft.cited_evidence_ids == (request.evidence_ids[0],)
    assert draft.export_reviewed is False
    assert teacher.prompt is not None
    payload = json.loads(teacher.prompt)
    assert [candidate["probe_id"] for candidate in payload["candidates"]] == list(
        draft.eligible_candidate_ids
    )
    assert "windows.old" not in str(payload["candidates"])
    draft.validate_against(request)


@pytest.mark.parametrize(
    "result",
    [
        {"ranked_probe_ids": ["windows.proxy"], "cited_evidence_ids": [], "abstain": False},
        {
            "ranked_probe_ids": ["windows.proxy", "windows.proxy"],
            "cited_evidence_ids": [],
            "abstain": False,
        },
        {
            "ranked_probe_ids": ["windows.proxy", "windows.shell"],
            "cited_evidence_ids": [],
            "abstain": False,
        },
        {
            "ranked_probe_ids": ["windows.proxy", "windows.dns"],
            "cited_evidence_ids": ["ev_" + "0" * 32],
            "abstain": False,
        },
    ],
)
def test_teacher_draft_rejects_unbound_or_incomplete_rankings(result: dict[str, object]) -> None:
    request = _request()
    with pytest.raises(ValueError):
        generate_teacher_draft(
            request=request,
            teacher=_Teacher(result),
            model_id="qwen3.8:27b",
            model_digest="a" * 64,
            generated_at=NOW,
            synthetic=True,
            privacy_review=_review(request),
        )


def test_teacher_draft_rejects_tampered_request() -> None:
    request = _request()
    draft = generate_teacher_draft(
        request=request,
        teacher=_Teacher(
            {
                "ranked_probe_ids": ["windows.proxy", "windows.dns"],
                "cited_evidence_ids": [],
                "abstain": True,
            }
        ),
        model_id="qwen3.8:27b",
        model_digest="a" * 64,
        generated_at=NOW,
        synthetic=True,
        privacy_review=_review(request),
    )
    altered = request.model_copy(update={"symptom": "different problem"})
    with pytest.raises(ValueError, match="request"):
        draft.validate_against(altered)

    forged_digest = "f" * 64
    forged = draft.model_copy(
        update={
            "teacher_prompt_sha256": forged_digest,
            "privacy_review": TeacherPrivacyReview(
                prompt_sha256=forged_digest,
                reviewer_id="test_reviewer",
                reviewed_at=NOW,
            ),
        }
    )
    with pytest.raises(ValueError, match="reviewed prompt"):
        forged.validate_against(request)


def test_attention_only_is_not_training_input() -> None:
    with pytest.raises(ValueError, match="attention_only"):
        generate_teacher_draft(
            request=_request(attention_only=True),
            teacher=_Teacher({}),
            model_id="qwen3.8:27b",
            model_digest="a" * 64,
            generated_at=NOW,
            synthetic=True,
        )


@pytest.mark.parametrize("synthetic", [False, True])
def test_teacher_input_requires_separate_privacy_review(synthetic: bool) -> None:
    with pytest.raises(ValueError, match="privacy review"):
        generate_teacher_draft(
            request=_request(),
            teacher=_Teacher({}),
            model_id="qwen3.8:27b",
            model_digest="a" * 64,
            generated_at=NOW,
            synthetic=synthetic,
        )


def test_real_teacher_review_is_bound_to_exact_prompt() -> None:
    request = _request()
    prompt_digest = sha256(prepare_teacher_prompt(request).encode("utf-8")).hexdigest()
    review = TeacherPrivacyReview(
        prompt_sha256=prompt_digest,
        reviewer_id="privacy_reviewer",
        reviewed_at=NOW,
    )
    teacher = _Teacher({"ranked_probe_ids": ["windows.dns", "windows.proxy"], "abstain": True})
    draft = generate_teacher_draft(
        request=request,
        teacher=teacher,
        model_id="qwen3.8:27b",
        model_digest="a" * 64,
        generated_at=NOW,
        synthetic=False,
        privacy_review=review,
    )
    assert draft.teacher_prompt_sha256 == prompt_digest
    assert draft.privacy_review == review
    assert teacher.prompt is not None
    with pytest.raises(ValueError, match="privacy review"):
        generate_teacher_draft(
            request=request.model_copy(update={"symptom": "altered symptom"}),
            teacher=teacher,
            model_id="qwen3.8:27b",
            model_digest="a" * 64,
            generated_at=NOW,
            synthetic=False,
            privacy_review=review,
        )


def test_obvious_sensitive_text_fails_before_teacher_call() -> None:
    request = _request().model_copy(update={"symptom": "password=visible-secret"})
    teacher = _Teacher({})
    with pytest.raises(ValueError, match="sensitive"):
        generate_teacher_draft(
            request=request,
            teacher=teacher,
            model_id="qwen3.8:27b",
            model_digest="a" * 64,
            generated_at=NOW,
            synthetic=True,
        )
    assert teacher.prompt is None


def test_weak_draft_cannot_be_parsed_as_expert_label() -> None:
    from pydantic import ValidationError

    from systemsense.evaluation.attention_labels import ExpertAttentionLabel

    draft = TeacherAttentionDraft(
        request_sha256="a" * 64,
        visible_evidence_sha256="b" * 64,
        candidate_context_sha256="c" * 64,
        model_id="qwen3.8:27b",
        model_digest="d" * 64,
        generated_at=NOW,
        synthetic=True,
        teacher_prompt_sha256="e" * 64,
        privacy_review=TeacherPrivacyReview(
            prompt_sha256="e" * 64, reviewer_id="test_reviewer", reviewed_at=NOW
        ),
        eligible_candidate_ids=("windows.proxy",),
        ranked_probe_ids=("windows.proxy",),
        cited_evidence_ids=(),
        abstain=False,
    )
    with pytest.raises(ValidationError):
        ExpertAttentionLabel.model_validate(draft.model_dump(mode="json"))


def test_local_teacher_requires_exact_pinned_identity() -> None:
    config = LocalInferenceConfig(
        enabled=True,
        reasoning_model="qwen3.8:27b",
        reasoning_digest="a" * 64,
    )
    with pytest.raises(ValueError, match="exact local model"):
        LocalOllamaTeacher(config=config, model_id="qwen3.8:27b", model_digest="b" * 64)
    with pytest.raises(ValueError, match="exact local model"):
        LocalOllamaTeacher(
            config=config.model_copy(update={"enabled": False}),
            model_id="qwen3.8:27b",
            model_digest="a" * 64,
        )


def test_teacher_windows_cover_every_candidate_without_global_rank_claim() -> None:
    request = _request().model_copy(
        update={
            "available_probes": tuple(
                ProbeCapability(
                    probe_id=f"probe.{index:02d}",
                    description=f"Inspect area {index}",
                    cost_ms=10,
                    resource_class=ResourceClass.CPU,
                )
                for index in range(23)
            ),
            "completed_probe_ids": frozenset(),
        }
    )
    assert teacher_candidate_window_count(request) == 2
    first = json.loads(prepare_teacher_prompt(request, window_index=0))
    second = json.loads(prepare_teacher_prompt(request, window_index=1))
    first_ids = [item["probe_id"] for item in first["candidates"]]
    second_ids = [item["probe_id"] for item in second["candidates"]]
    assert len(first_ids) == 20
    assert len(second_ids) == 3
    assert len(set(first_ids + second_ids)) == 23
    assert first["candidate_windows_total"] == second["candidate_windows_total"] == 2
    teacher = _Teacher(
        {"ranked_probe_ids": list(reversed(second_ids)), "cited_evidence_ids": [], "abstain": True}
    )
    review = TeacherPrivacyReview(
        prompt_sha256=sha256(prepare_teacher_prompt(request, window_index=1).encode()).hexdigest(),
        reviewer_id="test_reviewer",
        reviewed_at=NOW,
    )
    draft = generate_teacher_draft(
        request=request,
        teacher=teacher,
        model_id="qwen3.5:4b",
        model_digest="b" * 64,
        generated_at=NOW,
        synthetic=True,
        privacy_review=review,
        window_index=1,
    )
    assert draft.candidate_window_index == 1
    assert draft.candidate_windows_total == 2
    assert draft.eligible_candidate_ids == tuple(second_ids)
    assert teacher.schema is not None
    properties = teacher.schema["properties"]
    assert isinstance(properties, dict)
    ranking_schema = cast(dict[str, object], properties["ranked_probe_ids"])
    assert ranking_schema["minItems"] == ranking_schema["maxItems"] == 3
    assert ranking_schema["uniqueItems"] is True
    assert ranking_schema["items"] == {"type": "string", "enum": second_ids}
    draft.validate_against(request)
    with pytest.raises(ValueError):
        generate_teacher_draft(
            request=request,
            teacher=teacher,
            model_id="qwen3.5:4b",
            model_digest="b" * 64,
            generated_at=NOW,
            synthetic=True,
            privacy_review=review,
            window_index=2,
        )
