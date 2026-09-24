from __future__ import annotations

import hashlib
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest

from benchmarks import laya_training_loader as loader
from systemsense.evaluation.training_admission import (
    CandidateTarget,
    PrivacyReviewReceipt,
    TrainingExample,
    TrainingExport,
    TrainingInput,
    training_content_sha256,
    training_corpus_sha256,
)


class _Tokenizer:
    cls_token_id = 101
    sep_token_id = 102
    pad_token_id = 0
    mask_token_id = 1
    mask_token = "[MASK]"

    def __call__(self, text: str, *, add_special_tokens: bool = False) -> dict[str, object]:
        assert not add_special_tokens
        return {"input_ids": [len(word) for word in text.split()]}


def _export() -> TrainingExport:
    example = TrainingExample(
        label_id="label_" + "1" * 32,
        case_id="case_" + "2" * 32,
        split="train",
        snapshot_id="decision_snapshot_" + "3" * 32,
        request_sha256="b" * 64,
        laya_projection_sha256="c" * 64,
        input=TrainingInput(
            state={"symptom": "synthetic"},
            evidence=(),
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


def test_reconstruction_keeps_question_order_and_never_admits_training(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    export = _export()
    manifest = _capture(export)
    called: list[dict[str, object]] = []

    def parity(batch: dict[str, object], **_kwargs: object) -> dict[str, object]:
        called.append(batch)
        return {"status": "pass", "trainable": False, "model_input_sha256": "d" * 64}

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


def test_loader_rejects_missing_corpus_capture() -> None:
    with pytest.raises(ValueError, match="corpus capture"):
        loader.validate_capture_manifest(
            {"schema_version": 1, "corpus_sha256": "a" * 64, "examples": []},
            expected_corpus_sha256="a" * 64,
            expected_examples=(("snapshot-1", "b" * 64, ("probe.one",)),),
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
