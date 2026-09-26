from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from dataclasses import asdict, replace
from datetime import UTC, datetime, timedelta
from typing import Any, cast

import pytest

from benchmarks import laya_training_loader as loader
from systemsense.decision.semantic_packets import SERIALIZER_ID
from systemsense.evaluation.training_admission import (
    CandidateTarget,
    PrivacyReviewReceipt,
    TrainingExample,
    TrainingExport,
    TrainingInput,
    training_content_sha256,
    training_corpus_sha256,
)
from systemsense.inference.laya_runtime import (
    LayaAttentionMicrobatch,
    LayaAttentionResult,
    LayaCachedOrigin,
    LayaQuestionPresentation,
    LayaWorkerPresentation,
)


def test_test_only_head_rehearsal_rejects_unauthenticated_pair_before_forward() -> None:
    pair = loader.SyntheticRehearsalPair(
        "snapshot-one",
        "compare",
        0,
        "useful",
        "negative",
        "a" * 64,
        "b" * 64,
        "train",
        "episode-one",
    )
    batch = loader.ExactFixtureBatch("snapshot-one", "compare", 0, {}, {})
    with pytest.raises(ValueError, match="authenticated synthetic fixture pair"):
        loader.rehearse_exact_head_fixture(
            (batch,),
            (pair,),
            tokenizer=cast(loader.Tokenizer, object()),
            cfg={},
            qualification={},
            model=object(),
            verify_fixture_proof=lambda _pair: False,
            seed=17,
            model_proof_mode="synthetic_fixture",
        )


def test_test_only_head_rehearsal_runs_exact_tensors_loss_and_resume(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    torch = pytest.importorskip("torch")
    from benchmarks.laya_presentation_parity import ModelBatch, QuestionPresentation

    class TinyHead(torch.nn.Module):
        def __init__(self) -> None:
            super().__init__()  # pyright: ignore[reportUnknownMemberType]
            self.head = torch.nn.Parameter(torch.tensor([0.8, -0.2]))

        def forward(
            self,
            input_ids: Any,
            attention_mask: Any,
            marker_pos: Any,
            marker_mask: Any,
            qtype: Any,
            *,
            detach_encoder: bool,
        ) -> tuple[Any, None]:
            assert detach_encoder is True
            assert input_ids.tolist() == [[11, 12], [21, 22]]
            assert attention_mask.tolist() == [[1, 1], [1, 1]]
            assert marker_pos.tolist() == [[0, 1], [0, 1]]
            assert marker_mask.tolist() == [[True, True], [True, True]]
            assert qtype.tolist() == [2, 2]
            return torch.stack((torch.zeros_like(self.head), self.head), dim=1), None

    presentation = QuestionPresentation(1, 1, 1, 1, 1, 1)
    model_batch = ModelBatch(
        ("item_0_piece_0", "item_1_piece_0"),
        ((11, 12), (21, 22)),
        ((1, 1), (1, 1)),
        ((0, 1), (0, 1)),
        ((True, True), (True, True)),
        (2, 2),
        (presentation, presentation),
    )

    def reconstruct(*_args: object, **_kwargs: object) -> tuple[ModelBatch, tuple[()], int]:
        return model_batch, (), 2

    monkeypatch.setattr(
        loader,
        "reconstruct_exact_worker_call",
        reconstruct,
    )
    exact: dict[str, object] = {
        "schema_version": 2,
        "state": {"test_only": True},
        "questions": [
            {"question_id": "item_0_piece_0", "item_id": "useful", "question": {"type": "noul"}},
            {"question_id": "item_1_piece_0", "item_id": "negative", "question": {"type": "noul"}},
        ],
        "state_coverage": {},
        "model_input": {
            "input_ids": [[11, 12], [21, 22]],
            "attention_mask": [[1, 1], [1, 1]],
            "marker_pos": [[0, 1], [0, 1]],
            "marker_mask": [[True, True], [True, True]],
            "qtype": [2, 2],
        },
    }
    batches = tuple(
        loader.ExactFixtureBatch(f"snapshot-{index}", "compare", 0, exact, {}) for index in range(2)
    )
    pairs = tuple(
        loader.SyntheticRehearsalPair(
            f"snapshot-{index}",
            "compare",
            0,
            "useful",
            "negative",
            "a" * 64,
            "b" * 64,
            "train" if index == 0 else "development",
            f"episode-{index}",
        )
        for index in range(2)
    )
    model = TinyHead()
    original = model.head.detach().clone()
    prior_grad = torch.tensor([0.25, -0.5])
    model.head.grad = prior_grad.clone()
    qualification: dict[str, object] = {"status": "pass", **loader.EXPECTED_HEAD_REHEARSAL_PINS}
    first = loader.rehearse_exact_head_fixture(
        batches,
        pairs,
        tokenizer=cast(loader.Tokenizer, object()),
        cfg={},
        qualification=qualification,
        model=model,
        verify_fixture_proof=lambda _pair: True,
        seed=17,
        max_batches=1,
        model_proof_mode="synthetic_fixture",
    )
    assert first["status"] == "fixture_only"
    assert first["train_pairs"] == 1
    assert first["development_pairs"] == 0
    final = loader.rehearse_exact_head_fixture(
        batches,
        pairs,
        tokenizer=cast(loader.Tokenizer, object()),
        cfg={},
        qualification=qualification,
        model=model,
        verify_fixture_proof=lambda _pair: True,
        seed=17,
        resume=cast(dict[str, object], first["checkpoint"]),
        model_proof_mode="synthetic_fixture",
    )
    assert final["train_pairs"] == 1
    assert final["development_pairs"] == 1
    assert final["synthetic_development_pairwise_win_rate"] == 1.0
    assert final["model_proof_mode"] == "synthetic_fixture"
    assert final["weight_updates_performed"] is False
    assert final["parameters_sha256_before"] == final["parameters_sha256_after"]
    assert torch.equal(model.head.detach(), original)
    assert torch.equal(model.head.grad, prior_grad)
    altered = dict(cast(dict[str, object], first["checkpoint"]))
    altered["train_pairs"] = 99
    with pytest.raises(ValueError, match="fixture resume identity"):
        loader.rehearse_exact_head_fixture(
            batches,
            pairs,
            tokenizer=cast(loader.Tokenizer, object()),
            cfg={},
            qualification=qualification,
            model=model,
            verify_fixture_proof=lambda _pair: True,
            seed=17,
            resume=altered,
            model_proof_mode="synthetic_fixture",
        )
    sealed = (replace(pairs[0], split="sealed_test"), pairs[1])
    with pytest.raises(ValueError, match="sealed test"):
        loader.rehearse_exact_head_fixture(
            batches,
            sealed,
            tokenizer=cast(loader.Tokenizer, object()),
            cfg={},
            qualification=qualification,
            model=model,
            verify_fixture_proof=lambda _pair: True,
            seed=17,
            model_proof_mode="synthetic_fixture",
        )
    for invalid in ("other", "", None):
        with pytest.raises(ValueError, match="fixture split"):
            loader.rehearse_exact_head_fixture(
                batches,
                (replace(pairs[0], split=cast(Any, invalid)), pairs[1]),
                tokenizer=cast(loader.Tokenizer, object()),
                cfg={},
                qualification=qualification,
                model=model,
                verify_fixture_proof=lambda _pair: True,
                seed=17,
                model_proof_mode="synthetic_fixture",
            )
    with pytest.raises(ValueError, match="source group leakage"):
        loader.rehearse_exact_head_fixture(
            batches,
            (pairs[0], replace(pairs[1], source_group_id=pairs[0].source_group_id)),
            tokenizer=cast(loader.Tokenizer, object()),
            cfg={},
            qualification=qualification,
            model=model,
            verify_fixture_proof=lambda _pair: True,
            seed=17,
            model_proof_mode="synthetic_fixture",
        )
    with pytest.raises(ValueError, match="pinned model proof"):
        loader.rehearse_exact_head_fixture(
            batches[:1],
            pairs[:1],
            tokenizer=cast(loader.Tokenizer, object()),
            cfg={},
            qualification=qualification,
            model=model,
            verify_fixture_proof=lambda _pair: True,
            seed=17,
            model_proof_mode="pinned_laya",
        )

    def nonfinite_gradient(gradient: Any) -> Any:
        return gradient * float("inf")

    hook = model.head.register_hook(nonfinite_gradient)
    try:
        with pytest.raises(ValueError, match="head gradient nonfinite"):
            loader.rehearse_exact_head_fixture(
                batches[:1],
                pairs[:1],
                tokenizer=cast(loader.Tokenizer, object()),
                cfg={},
                qualification=qualification,
                model=model,
                verify_fixture_proof=lambda _pair: True,
                seed=17,
                model_proof_mode="synthetic_fixture",
            )
    finally:
        hook.remove()
    assert torch.equal(model.head.grad, prior_grad)


class _Tokenizer:
    cls_token_id = 101
    sep_token_id = 102
    pad_token_id = 0
    mask_token_id = 1
    mask_token = "[MASK]"

    def __call__(self, text: str, *, add_special_tokens: bool = False) -> dict[str, object]:
        assert not add_special_tokens
        return {"input_ids": [len(word) for word in text.split()]}


def _export(*, evidence: tuple[dict[str, str], ...] = ()) -> TrainingExport:
    example = TrainingExample(
        label_id="label_" + "1" * 32,
        case_id="case_" + "2" * 32,
        split="train",
        snapshot_id="decision_snapshot_" + "3" * 32,
        request_sha256="b" * 64,
        laya_projection_sha256="c" * 64,
        input=TrainingInput(
            state={"symptom": "synthetic"},
            evidence=evidence,
            candidates=({"probe_id": "probe.one", "description": "Inspect synthetic probe"},),
        ),
        targets=(CandidateTarget(probe_id="probe.one", utility="unknown", loss_mask=False),),
        abstain_target=False,
        training_content_sha256="0" * 64,
        reviewer_authorization_id="synthetic-review",
        export_authorization_id="synthetic-consent",
        retention_until=datetime.now(UTC) + timedelta(days=1),
    )
    example = example.model_copy(
        update={"training_content_sha256": training_content_sha256(example)}
    )
    receipt = PrivacyReviewReceipt(
        payload_sha256=hashlib.sha256(example.model_dump_json().encode()).hexdigest(),
        reviewer_id="synthetic_reviewer",
        reviewed_at=datetime.now(UTC),
        review_id="synthetic-privacy",
    )
    return TrainingExport(examples=(example,), privacy_reviews=(receipt,))


def _capture(export: TrainingExport) -> dict[str, object]:
    example = export.examples[0]
    question: dict[str, object] = {
        "type": "noul",
        "instructions": "Inspect synthetic probe",
        "criteria": {"false": "not useful", "true": "useful"},
    }
    batch: dict[str, object] = {
        "schema_version": 1,
        "snapshot_id": example.snapshot_id,
        "request_sha256": example.request_sha256,
        "phase": "probe",
        "batch_index": 0,
        "candidate_ids": ["probe.one"],
        "trace": {
            "payload": {
                "microbatches": [
                    {"phase": "probe", "batch_index": 0, "candidate_ids": ["probe.one"]}
                ]
            }
        },
        "exact_worker_call": {
            "state": {"symptom": "synthetic"},
            "questions": [
                {
                    "question_id": "item_0_piece_0",
                    "item_id": "probe.one",
                    "question": question,
                }
            ],
        },
    }
    return {
        "schema_version": 1,
        "corpus_sha256": training_corpus_sha256(export),
        "examples": [
            {
                "snapshot_id": example.snapshot_id,
                "request_sha256": example.request_sha256,
                "batches": [batch],
            }
        ],
    }


def _projection_fields(export: TrainingExport) -> dict[str, object]:
    example = export.examples[0]
    return {
        "evidence_serializer": SERIALIZER_ID,
        "ordered_fragments": [
            {
                "fragment_id": item["fragment_id"],
                "description_sha256": hashlib.sha256(item["description"].encode()).hexdigest(),
            }
            for item in example.input.evidence
        ],
        "ordered_probes": [
            {
                "probe_id": item["probe_id"],
                "description_sha256": hashlib.sha256(item["description"].encode()).hexdigest(),
            }
            for item in example.input.candidates
        ],
    }


def _model_input_sha256(payload: dict[str, object]) -> str:
    call = cast(dict[str, object], payload["exact_worker_call"])
    questions = {
        cast(str, row["question_id"]): cast(dict[str, object], row["question"])
        for row in cast(list[dict[str, object]], call["questions"])
    }
    model_batch = loader.predict_model_batch(
        tokenizer=_Tokenizer(),
        state=cast(dict[str, object], call["state"]),
        questions=questions,
        max_len=64,
        head_max_len=32,
    )
    serialized = json.dumps(asdict(model_batch), ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(serialized.encode()).hexdigest()


def test_reconstruction_keeps_question_order_and_never_admits_training(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    export = _export()
    manifest = _capture(export)
    called: list[dict[str, object]] = []

    def parity(batch: dict[str, object], **_kwargs: object) -> dict[str, object]:
        called.append(batch)
        return {
            "status": "pass",
            "trainable": False,
            "model_input_sha256": _model_input_sha256(batch),
        }

    monkeypatch.setattr(loader, "verify_exact_batch", parity)
    rebuilt = loader.reconstruct_training_inputs(
        export,
        manifest,
        expected_corpus_sha256=training_corpus_sha256(export),
        tokenizer=_Tokenizer(),
        cfg={"max_len": 64, "head_max_len": 32},
        qualification={},
    )
    assert len(called) == 1
    assert len(rebuilt) == 1
    assert rebuilt[0].candidate_ids == ("probe.one",)
    assert rebuilt[0].question_to_candidate == (("item_0_piece_0", "probe.one"),)
    assert rebuilt[0].model_batch.input_ids
    assert rebuilt[0].trainable is False


def test_reconstruction_rejects_parity_failure(monkeypatch: pytest.MonkeyPatch) -> None:
    export = _export()
    manifest = _capture(export)

    def failed_parity(_batch: dict[str, object], **_kwargs: object) -> dict[str, object]:
        return {"status": "fail", "trainable": False}

    monkeypatch.setattr(loader, "verify_exact_batch", failed_parity)
    with pytest.raises(ValueError, match="parity failed"):
        loader.reconstruct_training_inputs(
            export,
            manifest,
            expected_corpus_sha256=training_corpus_sha256(export),
            tokenizer=_Tokenizer(),
            cfg={"max_len": 64, "head_max_len": 32},
            qualification={},
        )


def test_reconstruction_rejects_model_batch_that_differs_from_parity_digest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    export = _export()
    manifest = _capture(export)

    def stale_parity(_batch: dict[str, object], **_kwargs: object) -> dict[str, object]:
        return {
            "status": "pass",
            "trainable": False,
            "model_input_sha256": "d" * 64,
        }

    monkeypatch.setattr(loader, "verify_exact_batch", stale_parity)
    with pytest.raises(ValueError, match="model input digest"):
        loader.reconstruct_training_inputs(
            export,
            manifest,
            expected_corpus_sha256=training_corpus_sha256(export),
            tokenizer=_Tokenizer(),
            cfg={"max_len": 64, "head_max_len": 32},
            qualification={},
        )


def test_loader_rejects_missing_corpus_capture() -> None:
    with pytest.raises(ValueError, match="corpus capture"):
        loader.validate_capture_manifest(
            {"schema_version": 1, "corpus_sha256": "a" * 64, "examples": []},
            expected_corpus_sha256="a" * 64,
            expected_examples=(("snapshot-1", "b" * 64, ("probe.one",)),),
        )


def test_v1_manifest_cannot_claim_evidence_input_coverage() -> None:
    export = _export(
        evidence=(
            {
                "evidence_id": "ev.one",
                "page_id": "ev.one:0",
                "fragment_id": "fragment.one",
                "description": "Synthetic packet",
            },
        )
    )
    with pytest.raises(ValueError, match="v1 cannot establish evidence coverage"):
        loader.reconstruct_training_inputs(
            export,
            _capture(export),
            expected_corpus_sha256=training_corpus_sha256(export),
            tokenizer=_Tokenizer(),
            cfg={"max_len": 64, "head_max_len": 32},
            qualification={},
        )


def test_loader_rejects_reordered_and_uncovered_candidates() -> None:
    manifest: dict[str, object] = {
        "schema_version": 1,
        "corpus_sha256": "a" * 64,
        "examples": [
            {
                "snapshot_id": "snapshot-1",
                "request_sha256": "b" * 64,
                "batches": [
                    {
                        "schema_version": 1,
                        "snapshot_id": "snapshot-1",
                        "request_sha256": "b" * 64,
                        "phase": "probe",
                        "batch_index": 0,
                        "candidate_ids": ["probe.two", "probe.one"],
                        "trace": {
                            "payload": {
                                "microbatches": [
                                    {
                                        "phase": "probe",
                                        "batch_index": 0,
                                        "candidate_ids": ["probe.two", "probe.one"],
                                    }
                                ]
                            }
                        },
                        "exact_worker_call": {"state": {}, "questions": []},
                    }
                ],
            }
        ],
    }
    with pytest.raises(ValueError, match="candidate order"):
        loader.validate_capture_manifest(
            manifest,
            expected_corpus_sha256="a" * 64,
            expected_examples=(("snapshot-1", "b" * 64, ("probe.one", "probe.two")),),
        )
    batch = cast(
        list[dict[str, object]], cast(list[dict[str, object]], manifest["examples"])[0]["batches"]
    )[0]
    batch["candidate_ids"] = ["probe.one", "probe.two"]
    with pytest.raises(ValueError, match="worker trace"):
        loader.validate_capture_manifest(
            manifest,
            expected_corpus_sha256="a" * 64,
            expected_examples=(("snapshot-1", "b" * 64, ("probe.one", "probe.two")),),
        )
    trace = cast(dict[str, object], batch["trace"])
    trace_payload = cast(dict[str, object], trace["payload"])
    trace_batch = cast(list[dict[str, object]], trace_payload["microbatches"])[0]
    trace_batch["candidate_ids"] = ["probe.one", "probe.two"]
    accepted = loader.validate_capture_manifest(
        manifest,
        expected_corpus_sha256="a" * 64,
        expected_examples=(("snapshot-1", "b" * 64, ("probe.one", "probe.two")),),
    )
    assert accepted[0].candidate_ids == ("probe.one", "probe.two")
    cast(list[dict[str, object]], manifest["examples"])[0]["batches"] = []
    with pytest.raises(ValueError, match="batch"):
        loader.validate_capture_manifest(
            manifest,
            expected_corpus_sha256="a" * 64,
            expected_examples=(("snapshot-1", "b" * 64, ("probe.one", "probe.two")),),
        )


def test_assembly_requires_complete_consented_actual_batches(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    export = _export()
    source = _capture(export)
    example = export.examples[0]
    source_examples = cast(list[dict[str, object]], source["examples"])
    batch = cast(list[dict[str, object]], source_examples[0]["batches"])[0]
    trace = cast(dict[str, object], batch["trace"])
    trace_payload = cast(dict[str, object], trace["payload"])
    trace_payload.update(_projection_fields(export))
    trace_batch = cast(list[dict[str, object]], trace_payload["microbatches"])[0]
    proof = LayaWorkerPresentation(
        presentation_sha256="e" * 64,
        fitted_state_sha256="a" * 64,
        questions_sha256="b" * 64,
        presented_item_ids=("probe.one",),
        fitted_state_tokens=4,
        state_tokens_original=4,
        state_fields_omitted=0,
        state_list_items_omitted=0,
        questions=(
            LayaQuestionPresentation(
                question_id="item_0_piece_0",
                item_id="probe.one",
                question_sha256="c" * 64,
                instruction_tokens=1,
                instruction_presented_tokens=1,
                criteria_tokens=1,
                criteria_presented_tokens=1,
                state_presented_tokens=4,
            ),
        ),
    )
    attention = LayaAttentionResult(
        microbatches=(
            LayaAttentionMicrobatch(
                phase="probe",
                batch_index=0,
                candidate_ids=("probe.one",),
                inference_ids=("probe.one",),
                worker_presentation=proof,
            ),
        )
    )
    trace_batch.clear()
    trace_batch.update(attention.microbatches[0].model_dump(mode="json"))
    call = cast(dict[str, object], batch["exact_worker_call"])
    checks: list[dict[str, object]] = []

    def parity(payload: dict[str, object], **_kwargs: object) -> dict[str, object]:
        checks.append(payload)
        return {"status": "pass", "trainable": False, "model_input_sha256": "f" * 64}

    monkeypatch.setattr(loader, "verify_exact_batch", parity)
    authorization = loader.CaptureAuthorization(
        snapshot_id=example.snapshot_id,
        request_sha256=example.request_sha256,
        privacy_receipt_sha256="d" * 64,
        reviewed_payload_sha256=loader.capture_review_sha256(
            example.snapshot_id, example.request_sha256, trace, (call,)
        ),
        local_training_consent=True,
        exact_payload_reviewed=True,
    )
    assembled = loader.assemble_training_capture_manifest(
        export,
        snapshots=((example.snapshot_id, example.request_sha256, trace, attention),),
        captured_calls={(example.snapshot_id, "probe", 0): call},
        authorizations=(authorization,),
        tokenizer=_Tokenizer(),
        cfg={"max_len": 64, "head_max_len": 32},
        qualification={},
    )
    assert len(checks) == 1
    assert assembled["schema_version"] == 2
    assert assembled["corpus_sha256"] == training_corpus_sha256(export)
    assert loader.validate_capture_manifest(
        assembled,
        expected_corpus_sha256=training_corpus_sha256(export),
        expected_examples=((example.snapshot_id, example.request_sha256, ("probe.one",)),),
        expected_evidence=((),),
    )
    assembled_example = cast(list[dict[str, object]], assembled["examples"])[0]
    assembled_batch = cast(list[dict[str, object]], assembled_example["batches"])[0]
    assembled_call = cast(dict[str, object], assembled_batch["exact_worker_call"])
    original_state = assembled_call["state"]
    assembled_call["state"] = {"changed": True}
    with pytest.raises(ValueError, match="reviewed capture payload"):
        loader.validate_capture_manifest(
            assembled,
            expected_corpus_sha256=training_corpus_sha256(export),
            expected_examples=((example.snapshot_id, example.request_sha256, ("probe.one",)),),
            expected_evidence=((),),
        )
    assembled_call["state"] = original_state
    with pytest.raises(ValueError, match="capture incomplete"):
        loader.assemble_training_capture_manifest(
            export,
            snapshots=((example.snapshot_id, example.request_sha256, trace, attention),),
            captured_calls={},
            authorizations=(authorization,),
            tokenizer=_Tokenizer(),
            cfg={},
            qualification={},
        )
    with pytest.raises(ValueError, match="consent"):
        loader.assemble_training_capture_manifest(
            export,
            snapshots=((example.snapshot_id, example.request_sha256, trace, attention),),
            captured_calls={(example.snapshot_id, "probe", 0): call},
            authorizations=(replace(authorization, local_training_consent=False),),
            tokenizer=_Tokenizer(),
            cfg={},
            qualification={},
        )
    with pytest.raises(ValueError, match="reviewed capture payload"):
        loader.assemble_training_capture_manifest(
            export,
            snapshots=((example.snapshot_id, example.request_sha256, trace, attention),),
            captured_calls={
                (example.snapshot_id, "probe", 0): {**call, "state": {"changed": True}}
            },
            authorizations=(authorization,),
            tokenizer=_Tokenizer(),
            cfg={},
            qualification={},
        )
    with pytest.raises(ValueError, match="actual attention"):
        loader.assemble_training_capture_manifest(
            export,
            snapshots=(
                (example.snapshot_id, example.request_sha256, trace, LayaAttentionResult()),
            ),
            captured_calls={(example.snapshot_id, "probe", 0): call},
            authorizations=(authorization,),
            tokenizer=_Tokenizer(),
            cfg={},
            qualification={},
        )
    cached = LayaAttentionResult(
        microbatches=(
            LayaAttentionMicrobatch(
                phase="probe",
                batch_index=0,
                candidate_ids=("probe.one",),
                cache_hit_ids=("probe.one",),
                cached_origins=(
                    LayaCachedOrigin(
                        item_id="probe.one",
                        presentation_sha256="e" * 64,
                    ),
                ),
            ),
        )
    )
    cached_trace: dict[str, object] = {
        "payload": {
            **_projection_fields(export),
            "microbatches": [cached.microbatches[0].model_dump(mode="json")],
        }
    }
    with pytest.raises(ValueError, match="cached origin"):
        loader.assemble_training_capture_manifest(
            export,
            snapshots=((example.snapshot_id, example.request_sha256, cached_trace, cached),),
            captured_calls={(example.snapshot_id, "probe", 0): call},
            authorizations=(authorization,),
            tokenizer=_Tokenizer(),
            cfg={},
            qualification={},
        )
    evidence = LayaAttentionResult(
        microbatches=(
            LayaAttentionMicrobatch(
                phase="evidence",
                batch_index=0,
                candidate_ids=("fragment.one",),
                inference_ids=("fragment.one",),
            ),
            attention.microbatches[0],
        )
    )
    evidence_trace: dict[str, object] = {
        "payload": {
            **_projection_fields(export),
            "microbatches": [batch.model_dump(mode="json") for batch in evidence.microbatches],
        }
    }
    with pytest.raises(ValueError, match="worker capture incomplete"):
        loader.assemble_training_capture_manifest(
            export,
            snapshots=((example.snapshot_id, example.request_sha256, evidence_trace, evidence),),
            captured_calls={(example.snapshot_id, "probe", 0): call},
            authorizations=(authorization,),
            tokenizer=_Tokenizer(),
            cfg={},
            qualification={},
        )


def test_schema_two_assembles_and_reconstructs_evidence_then_probe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    evidence = (
        {
            "evidence_id": "ev.one",
            "page_id": "ev.one:0",
            "fragment_id": "fragment.one",
            "description": "Synthetic evidence packet",
        },
    )
    export = _export(evidence=evidence)
    example = export.examples[0]

    def proof(item_id: str) -> LayaWorkerPresentation:
        return LayaWorkerPresentation(
            presentation_sha256="e" * 64,
            fitted_state_sha256="a" * 64,
            questions_sha256="b" * 64,
            presented_item_ids=(item_id,),
            fitted_state_tokens=4,
            state_tokens_original=4,
            state_fields_omitted=0,
            state_list_items_omitted=0,
            questions=(
                LayaQuestionPresentation(
                    question_id="item_0_piece_0",
                    item_id=item_id,
                    question_sha256="c" * 64,
                    instruction_tokens=1,
                    instruction_presented_tokens=1,
                    criteria_tokens=1,
                    criteria_presented_tokens=1,
                    state_presented_tokens=4,
                ),
            ),
        )

    attention = LayaAttentionResult(
        microbatches=(
            LayaAttentionMicrobatch(
                phase="evidence",
                batch_index=0,
                candidate_ids=("fragment.one",),
                inference_ids=("fragment.one",),
                worker_presentation=proof("fragment.one"),
            ),
            LayaAttentionMicrobatch(
                phase="probe",
                batch_index=0,
                candidate_ids=("probe.one",),
                inference_ids=("probe.one",),
                worker_presentation=proof("probe.one"),
            ),
        )
    )
    trace: dict[str, object] = {
        "payload": {
            **_projection_fields(export),
            "microbatches": [batch.model_dump(mode="json") for batch in attention.microbatches],
        }
    }
    calls: dict[tuple[str, str, int], dict[str, object]] = {
        (example.snapshot_id, "evidence", 0): {
            "state": {"attention_kind": "evidence_relevance"},
            "questions": [
                {
                    "question_id": "item_0_piece_0",
                    "item_id": "fragment.one",
                    "question": {
                        "type": "noul",
                        "instructions": "Evidence",
                        "criteria": {"false": "no", "true": "yes"},
                    },
                }
            ],
            "state_coverage": {
                "state_tokens_original": 4,
                "state_fields_omitted": 0,
                "state_list_items_omitted": 0,
            },
        },
        (example.snapshot_id, "probe", 0): {
            "state": {"attention_kind": "probe_relevance"},
            "questions": [
                {
                    "question_id": "item_0_piece_0",
                    "item_id": "probe.one",
                    "question": {
                        "type": "noul",
                        "instructions": "Probe",
                        "criteria": {"false": "no", "true": "yes"},
                    },
                }
            ],
            "state_coverage": {
                "state_tokens_original": 4,
                "state_fields_omitted": 0,
                "state_list_items_omitted": 0,
            },
        },
    }
    seen: list[tuple[str, int]] = []

    def parity(payload: dict[str, object], **_kwargs: object) -> dict[str, object]:
        seen.append((cast(str, payload["phase"]), cast(int, payload["batch_index"])))
        return {
            "status": "pass",
            "trainable": False,
            "model_input_sha256": _model_input_sha256(payload),
        }

    monkeypatch.setattr(loader, "verify_exact_batch", parity)
    authorization = loader.CaptureAuthorization(
        snapshot_id=example.snapshot_id,
        request_sha256=example.request_sha256,
        privacy_receipt_sha256="d" * 64,
        reviewed_payload_sha256=loader.capture_review_sha256(
            example.snapshot_id, example.request_sha256, trace, tuple(calls.values())
        ),
        local_training_consent=True,
        exact_payload_reviewed=True,
    )
    manifest = loader.assemble_training_capture_manifest(
        export,
        snapshots=((example.snapshot_id, example.request_sha256, trace, attention),),
        captured_calls=calls,
        authorizations=(authorization,),
        tokenizer=_Tokenizer(),
        cfg={"max_len": 64, "head_max_len": 32},
        qualification={},
    )
    assert manifest["schema_version"] == 2
    assert seen == [("evidence", 0), ("probe", 0)]
    rebuilt = loader.reconstruct_training_inputs(
        export,
        manifest,
        expected_corpus_sha256=training_corpus_sha256(export),
        tokenizer=_Tokenizer(),
        cfg={"max_len": 64, "head_max_len": 32},
        qualification={},
    )
    assert [(row.phase, row.candidate_ids) for row in rebuilt] == [
        ("evidence", ("fragment.one",)),
        ("probe", ("probe.one",)),
    ]
    wrong_source = deepcopy(trace)
    wrong_payload = cast(dict[str, object], wrong_source["payload"])
    wrong_fragments = cast(list[dict[str, object]], wrong_payload["ordered_fragments"])
    wrong_fragments[0]["description_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="projection binding"):
        loader.assemble_training_capture_manifest(
            export,
            snapshots=((example.snapshot_id, example.request_sha256, wrong_source, attention),),
            captured_calls=calls,
            authorizations=(
                replace(
                    authorization,
                    reviewed_payload_sha256=loader.capture_review_sha256(
                        example.snapshot_id,
                        example.request_sha256,
                        wrong_source,
                        tuple(calls.values()),
                    ),
                ),
            ),
            tokenizer=_Tokenizer(),
            cfg={},
            qualification={},
        )
    missing = deepcopy(manifest)
    missing_example = cast(list[dict[str, object]], missing["examples"])[0]
    cast(list[dict[str, object]], missing_example["batches"]).pop(0)
    with pytest.raises(ValueError, match="evidence order or coverage"):
        loader.validate_capture_manifest(
            missing,
            expected_corpus_sha256=training_corpus_sha256(export),
            expected_examples=((example.snapshot_id, example.request_sha256, ("probe.one",)),),
            expected_evidence=(("fragment.one",),),
        )
    reordered = deepcopy(manifest)
    reordered_example = cast(list[dict[str, object]], reordered["examples"])[0]
    cast(list[dict[str, object]], reordered_example["batches"]).reverse()
    with pytest.raises(ValueError, match="corpus batch identity"):
        loader.validate_capture_manifest(
            reordered,
            expected_corpus_sha256=training_corpus_sha256(export),
            expected_examples=((example.snapshot_id, example.request_sha256, ("probe.one",)),),
            expected_evidence=(("fragment.one",),),
        )
    unreviewed = deepcopy(manifest)
    cast(list[dict[str, object]], unreviewed["examples"])[0].pop("exact_payload_reviewed")
    with pytest.raises(ValueError, match="consent or privacy review"):
        loader.reconstruct_training_inputs(
            export,
            unreviewed,
            expected_corpus_sha256=training_corpus_sha256(export),
            tokenizer=_Tokenizer(),
            cfg={"max_len": 64, "head_max_len": 32},
            qualification={},
        )
