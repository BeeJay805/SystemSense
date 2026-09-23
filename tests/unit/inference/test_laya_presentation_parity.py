from __future__ import annotations

import json
import os
import subprocess
from dataclasses import replace
from pathlib import Path
from typing import cast

import pytest

from benchmarks.laya_presentation_parity import (
    ModelBatch,
    QuestionPresentation,
    compare_batches,
    compare_worker_presentation,
    predict_model_batch,
    run_negative_controls,
    synthetic_cases,
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


def _question(instructions: str) -> dict[str, object]:
    return {
        "type": "noul",
        "instructions": instructions,
        "criteria": {"false": "no", "true": "yes"},
    }


def test_predict_model_batch_matches_exact_short_sequence_and_masks() -> None:
    batch = predict_model_batch(
        tokenizer=_Tokenizer(),
        state={"symptom": "wifi"},
        questions={"first": _question("Ping"), "second": _question("Ping twice")},
        max_len=18,
        head_max_len=20,
    )

    assert batch.question_ids == ("first", "second")
    assert batch.input_ids == (
        (101, 4, 9, 4, 102, 1, 6, 2, 1, 5, 3, 102, 11, 7, 102, 0),
        (101, 4, 9, 4, 5, 102, 1, 6, 2, 1, 5, 3, 102, 11, 7, 102),
    )
    assert batch.attention_mask == ((1,) * 15 + (0,), (1,) * 16)
    assert batch.marker_pos == ((5, 8), (6, 9))
    assert batch.marker_mask == ((True, True), (True, True))
    assert batch.qtype == (2, 2)
    assert batch.questions[0].state_presented_tokens == 2


def test_prediction_sanitizes_mask_token_and_detects_state_truncation() -> None:
    batch = predict_model_batch(
        tokenizer=_Tokenizer(),
        state={"symptom": "[MASK] wifi"},
        questions={"first": _question("Ping [MASK]")},
        max_len=14,
        head_max_len=20,
    )

    assert batch.questions[0].state_original_tokens == 3
    assert batch.questions[0].state_presented_tokens == 1
    assert batch.questions[0].instruction_original_tokens == 3
    assert batch.questions[0].instruction_presented_tokens == 3
    assert batch.marker_pos == ((5, 8),)
    assert batch.input_ids[0][-1] == 102


def test_comparison_detects_token_marker_mask_order_and_truncation_mutations() -> None:
    reference = ModelBatch(
        question_ids=("q0", "q1"),
        input_ids=((11, 12, 0), (11, 12, 13)),
        attention_mask=((1, 1, 0), (1, 1, 1)),
        marker_pos=((1, 0), (2, 0)),
        marker_mask=((True, False), (True, False)),
        qtype=(2, 2),
        questions=(
            QuestionPresentation(3, 2, 2, 2, 3, 2),
            QuestionPresentation(3, 3, 2, 2, 3, 3),
        ),
    )
    assert compare_batches(reference, reference) == ()

    variants = (
        replace(reference, input_ids=((99, 12, 0), reference.input_ids[1])),
        replace(reference, marker_pos=((0, 0), reference.marker_pos[1])),
        replace(reference, marker_mask=((False, False), reference.marker_mask[1])),
        replace(reference, attention_mask=((0, 1, 0), reference.attention_mask[1])),
        replace(reference, question_ids=("q1", "q0")),
        replace(
            reference,
            questions=(
                replace(reference.questions[0], state_presented_tokens=1),
                reference.questions[1],
            ),
        ),
    )
    assert all(compare_batches(reference, variant) for variant in variants)
    assert run_negative_controls(reference).keys() == {
        "input_ids",
        "marker_pos",
        "marker_mask",
        "attention_mask",
        "question_order",
        "state_truncation",
    }
    assert all(run_negative_controls(reference).values())


def test_worker_metadata_comparison_rejects_false_full_presentation_claim() -> None:
    predicted = predict_model_batch(
        tokenizer=_Tokenizer(),
        state={"symptom": "wifi"},
        questions={"q0": _question("Ping"), "q1": _question("Retry")},
        max_len=16,
        head_max_len=20,
    )
    worker_report: dict[str, object] = {
        "fitted_state_tokens": 2,
        "questions": [
            {
                "question_id": qid,
                "instruction_tokens": item.instruction_original_tokens,
                "instruction_presented_tokens": item.instruction_presented_tokens,
                "criteria_tokens": item.criteria_original_tokens,
                "criteria_presented_tokens": item.criteria_presented_tokens,
                "state_presented_tokens": item.state_presented_tokens,
            }
            for qid, item in zip(predicted.question_ids, predicted.questions, strict=True)
        ],
    }
    assert compare_worker_presentation(predicted, worker_report) == ()
    details = cast(list[dict[str, object]], worker_report["questions"])
    bad: dict[str, object] = {
        **worker_report,
        "questions": [
            {**details[0], "state_presented_tokens": 99},
            details[1],
        ],
    }
    assert compare_worker_presentation(predicted, bad) == ("q0:state_presented_tokens",)


def test_synthetic_case_set_is_bounded_and_contains_truncation_controls() -> None:
    cases = synthetic_cases()
    assert 2 <= len(cases) <= 5
    assert len({case.case_id for case in cases}) == len(cases)
    assert all(1 <= len(case.candidates) <= 20 for case in cases)
    assert any("[MASK]" in str(case.state) for case in cases)
    assert any(len(str(case.state)) > 5000 for case in cases)
    assert any(len(case.candidates[0][1]) > 5000 for case in cases)


@pytest.mark.skipif(
    os.environ.get("SYSTEMSENSE_RUN_LAYA_PARITY") != "1",
    reason="pinned local Laya parity is explicitly opt-in",
)
def test_pinned_laya_cli_matches_exact_model_inputs() -> None:
    interpreter = os.environ.get("SYSTEMSENSE_LAYA_PARITY_INTERPRETER")
    model_path = os.environ.get("SYSTEMSENSE_LAYA_PARITY_MODEL_PATH")
    assert interpreter is not None and model_path is not None
    script = Path(__file__).resolve().parents[3] / "benchmarks" / "laya_presentation_parity.py"
    environment = {
        **os.environ,
        "HF_HUB_OFFLINE": "1",
        "TRANSFORMERS_OFFLINE": "1",
        "CUDA_VISIBLE_DEVICES": "",
    }
    completed = subprocess.run(
        [interpreter, "-I", str(script), "--model-path", model_path],
        capture_output=True,
        text=True,
        check=False,
        timeout=90,
        env=environment,
    )
    assert completed.returncode == 0, completed.stderr
    report = json.loads(completed.stdout)
    assert report["schema_version"] == 1
    assert report["status"] == "pass"
    assert report["qualification_scope"] == "synthetic_serializer_parity_only"
    assert report["case_count"] >= 3
    assert all(report["negative_controls"].values())
    assert report["boundary_vector_count"] >= 2
    assert all(vector["status"] == "pass" for vector in report["boundary_vectors"])
    assert any(vector["state_truncated"] for vector in report["boundary_vectors"])
    assert any(vector["instruction_truncated"] for vector in report["boundary_vectors"])
    assert "Synthetic Wi-Fi" not in completed.stdout
