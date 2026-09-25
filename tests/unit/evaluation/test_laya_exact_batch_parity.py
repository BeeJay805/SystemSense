from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from benchmarks import laya_exact_batch_parity as exact
from benchmarks.laya_presentation_parity import ModelBatch


def test_worker_source_pin_is_stable_across_windows_line_endings(tmp_path: Path) -> None:
    source = tmp_path / "worker.py"
    source.write_bytes(b"first\nsecond\n")
    expected = exact.worker_source_sha256(source)
    source.write_bytes(b"first\r\nsecond\r\n")
    assert exact.worker_source_sha256(source) == expected
    source.write_bytes(b"first\r\nchanged\r\n")
    assert exact.worker_source_sha256(source) != expected


def test_exact_parity_pin_matches_current_laya_worker_source() -> None:
    worker = (
        Path(__file__).resolve().parents[3] / "src" / "systemsense" / "inference" / "laya_worker.py"
    )
    assert exact.worker_source_sha256(worker) == exact.EXPECTED_WORKER_SHA256


class _Tokenizer:
    cls_token_id = 101
    sep_token_id = 102
    pad_token_id = 0
    mask_token_id = 1
    mask_token = "[MASK]"

    def __call__(self, text: str, *, add_special_tokens: bool = False) -> dict[str, object]:
        assert not add_special_tokens
        return {"input_ids": [len(word) for word in text.split()]}


def _payload() -> dict[str, object]:
    from systemsense.inference import laya_worker

    tokenizer = _Tokenizer()
    state: dict[str, object] = {"symptom": "synthetic wifi", "attention_kind": "probe_relevance"}
    question: dict[str, object] = {
        "type": "noul",
        "instructions": "Inspect synthetic adapter",
        "criteria": {
            "false": "not useful for the current uncertainty",
            "true": "useful for the current uncertainty",
        },
    }
    questions = {"item_0_piece_0": question}
    coverage = {
        "state_tokens_original": 4,
        "state_fields_omitted": 0,
        "state_list_items_omitted": 0,
    }
    presentation = laya_worker._presentation(  # pyright: ignore[reportPrivateUsage]
        cast(Any, SimpleNamespace(tok=tokenizer, cfg={"max_len": 64, "head_max_len": 32})),
        state,
        questions,
        {"item_0_piece_0": "network.adapter"},
        coverage,
    )
    batch = {
        "phase": "probe",
        "batch_index": 0,
        "candidate_ids": ["network.adapter"],
        "inference_ids": ["network.adapter"],
        "cache_hit_ids": [],
        "cached_origins": [],
        "worker_presentation": presentation,
    }
    trace: dict[str, object] = {"payload": {"microbatches": [batch]}}
    trace_sha = hashlib.sha256(
        json.dumps(trace, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    return {
        "schema_version": 1,
        "snapshot_id": "synthetic-snapshot",
        "request_sha256": "a" * 64,
        "trace_sha256": trace_sha,
        "privacy_receipt_sha256": "b" * 64,
        "trace": trace,
        "phase": "probe",
        "batch_index": 0,
        "exact_worker_call": {
            "state": state,
            "questions": [
                {
                    "question_id": "item_0_piece_0",
                    "item_id": "network.adapter",
                    "question": question,
                }
            ],
            "state_coverage": coverage,
        },
    }


def _qualification() -> dict[str, object]:
    return {
        "status": "pass",
        "package_version": exact.EXPECTED_PACKAGE_VERSION,
        "model_revision": exact.EXPECTED_MODEL_REVISION,
        "upstream_common_sha256": exact.EXPECTED_COMMON_SHA256,
        "upstream_agent_sha256": exact.EXPECTED_AGENT_SHA256,
        "tokenizer_sha256": exact.EXPECTED_TOKENIZER_SHA256,
        "model_config_sha256": exact.EXPECTED_CONFIG_SHA256,
        "worker_sha256": exact.EXPECTED_WORKER_SHA256,
    }


def _upstream(*, predicted: ModelBatch, **_kwargs: object) -> ModelBatch:
    return predicted


def test_exact_batch_report_is_hash_only_and_never_trainable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(exact, "_upstream_model_batch", _upstream)
    report = exact.verify_exact_batch(
        _payload(),
        tokenizer=_Tokenizer(),
        cfg={"max_len": 64, "head_max_len": 32},
        qualification=_qualification(),
    )

    assert report["status"] == "pass"
    assert report["trainable"] is False
    assert report["cache_origin_status"] == "not_applicable"
    assert len(cast(str, report["model_input_sha256"])) == 64
    serialized = json.dumps(report)
    assert "synthetic wifi" not in serialized
    assert "Inspect synthetic" not in serialized


def test_schema_two_evidence_batch_uses_same_exact_worker_builder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(exact, "_upstream_model_batch", _upstream)
    payload = _payload()
    payload["schema_version"] = 2
    payload["phase"] = "evidence"
    trace = cast(dict[str, object], payload["trace"])
    trace_payload = cast(dict[str, object], trace["payload"])
    batch = cast(list[dict[str, object]], trace_payload["microbatches"])[0]
    batch["phase"] = "evidence"
    payload["trace_sha256"] = hashlib.sha256(
        json.dumps(trace, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    report = exact.verify_exact_batch(
        payload,
        tokenizer=_Tokenizer(),
        cfg={"max_len": 64, "head_max_len": 32},
        qualification=_qualification(),
    )
    assert report["status"] == "pass"
    assert report["phase"] == "evidence"
    assert report["schema_version"] == 2
    assert report["trainable"] is False
    payload["schema_version"] = 1
    with pytest.raises(ValueError, match="identity"):
        exact.verify_exact_batch(
            payload,
            tokenizer=_Tokenizer(),
            cfg={"max_len": 64, "head_max_len": 32},
            qualification=_qualification(),
        )


def test_exact_batch_rejects_corrupt_question_and_tensor(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(exact, "_upstream_model_batch", _upstream)
    payload = _payload()
    call = cast(dict[str, object], payload["exact_worker_call"])
    questions = cast(list[dict[str, object]], call["questions"])
    questions[0]["question"] = {
        **cast(dict[str, object], questions[0]["question"]),
        "instructions": "Inspect corrupted adapter",
    }
    with pytest.raises(ValueError, match="worker presentation mismatch"):
        exact.verify_exact_batch(
            payload,
            tokenizer=_Tokenizer(),
            cfg={"max_len": 64, "head_max_len": 32},
            qualification=_qualification(),
        )

    payload = _payload()

    def wrong_upstream(*, predicted: ModelBatch, **_kwargs: object) -> ModelBatch:
        from dataclasses import replace

        first = predicted.input_ids[0]
        return replace(predicted, input_ids=((first[0] + 1, *first[1:]),))

    monkeypatch.setattr(exact, "_upstream_model_batch", wrong_upstream)
    report = exact.verify_exact_batch(
        payload,
        tokenizer=_Tokenizer(),
        cfg={"max_len": 64, "head_max_len": 32},
        qualification=_qualification(),
    )
    assert report["status"] == "fail"
    assert report["mismatched_fields"] == ["input_ids"]
    assert report["trainable"] is False


def test_captured_worker_tensor_must_equal_independent_installed_builder(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(exact, "_upstream_model_batch", _upstream)
    payload = _payload()
    call = cast(dict[str, object], payload["exact_worker_call"])
    trace = cast(dict[str, object], payload["trace"])
    trace_payload = cast(dict[str, object], trace["payload"])
    batches = cast(list[dict[str, object]], trace_payload["microbatches"])
    presentation = cast(dict[str, object], batches[0]["worker_presentation"])
    reconstructed, differences, _count = exact.reconstruct_exact_worker_call(
        call,
        presentation,
        tokenizer=_Tokenizer(),
        cfg={"max_len": 64, "head_max_len": 32},
        qualification=_qualification(),
    )
    assert differences == ()
    tensors = asdict(reconstructed)
    call["schema_version"] = 2
    call["model_input"] = {
        key: tensors[key]
        for key in ("input_ids", "attention_mask", "marker_pos", "marker_mask", "qtype")
    }
    presentation["model_input_sha256"] = hashlib.sha256(
        b"systemsense.laya.model_input.v1\0"
        + json.dumps(
            call["model_input"], ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
    ).hexdigest()
    payload["trace_sha256"] = hashlib.sha256(
        json.dumps(trace, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    passing = exact.verify_exact_batch(
        payload,
        tokenizer=_Tokenizer(),
        cfg={"max_len": 64, "head_max_len": 32},
        qualification=_qualification(),
    )
    assert passing["status"] == "pass"
    bad_input = cast(dict[str, object], call["model_input"])
    ids = cast(tuple[tuple[int, ...], ...], bad_input["input_ids"])
    bad_input["input_ids"] = ((ids[0][0] + 1, *ids[0][1:]),)
    with pytest.raises(ValueError, match="model input digest"):
        exact.verify_exact_batch(
            payload,
            tokenizer=_Tokenizer(),
            cfg={"max_len": 64, "head_max_len": 32},
            qualification=_qualification(),
        )
    call["unexpected"] = "not model input"
    with pytest.raises(ValueError, match="capture fields"):
        exact.verify_exact_batch(
            payload,
            tokenizer=_Tokenizer(),
            cfg={"max_len": 64, "head_max_len": 32},
            qualification=_qualification(),
        )


def test_exact_batch_rejects_cache_without_durable_origin(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(exact, "_upstream_model_batch", _upstream)
    payload = _payload()
    trace = cast(dict[str, object], payload["trace"])
    trace_payload = cast(dict[str, object], trace["payload"])
    batch = cast(list[dict[str, object]], trace_payload["microbatches"])[0]
    batch["cache_hit_ids"] = ["network.adapter"]
    batch["inference_ids"] = []
    batch["cached_origins"] = [{"item_id": "network.adapter", "presentation_sha256": "c" * 64}]
    payload["trace_sha256"] = hashlib.sha256(
        json.dumps(trace, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()
    with pytest.raises(ValueError, match="cache origin"):
        exact.verify_exact_batch(
            payload,
            tokenizer=_Tokenizer(),
            cfg={"max_len": 64, "head_max_len": 32},
            qualification=_qualification(),
        )


def test_exact_batch_rejects_missing_receipt_and_unpinned_source(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(exact, "_upstream_model_batch", _upstream)
    payload = _payload()
    del payload["privacy_receipt_sha256"]
    with pytest.raises(ValueError, match="privacy receipt"):
        exact.verify_exact_batch(
            payload,
            tokenizer=_Tokenizer(),
            cfg={"max_len": 64, "head_max_len": 32},
            qualification=_qualification(),
        )

    qualification = _qualification()
    qualification["upstream_common_sha256"] = "0" * 64
    with pytest.raises(ValueError, match="pinned artifact"):
        exact.verify_exact_batch(
            _payload(),
            tokenizer=_Tokenizer(),
            cfg={"max_len": 64, "head_max_len": 32},
            qualification=qualification,
        )
