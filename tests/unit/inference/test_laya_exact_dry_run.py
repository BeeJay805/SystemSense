from __future__ import annotations

import hashlib
import json
from dataclasses import asdict
from pathlib import Path
from typing import Literal, cast

import pytest
from pydantic import TypeAdapter

from benchmarks import laya_exact_batch_parity as exact
from benchmarks.laya_presentation_parity import ModelBatch, QuestionPresentation
from systemsense.evaluation.frontier_pilot_export import (
    ControlledWorkerFixturePilot,
    ControlledWorkerPilotExample,
    FrontierPilotExample,
    FrontierWorkerBatchReceipt,
    FrontierWorkerReceipt,
    PilotItemOutcome,
)


def _call() -> dict[str, object]:
    return {
        "schema_version": 2,
        "state": {"symptom": "synthetic"},
        "state_coverage": {},
        "questions": [
            {
                "question_id": "item_0_piece_0",
                "item_id": "probe.one",
                "question": {"type": "noul", "instructions": "synthetic"},
            }
        ],
        "model_input": {
            "input_ids": [[1, 2]],
            "attention_mask": [[1, 1]],
            "marker_pos": [[1]],
            "marker_mask": [[True]],
            "qtype": [2],
        },
    }


def test_forward_dry_run_requires_exact_tensor_and_finite_answer() -> None:
    call = _call()
    captured = cast(dict[str, object], call["model_input"])

    def good(
        _state: dict[str, object], _questions: dict[str, dict[str, object]]
    ) -> tuple[dict[str, object], dict[str, object] | None, str | None]:
        return {"answers": {"item_0_piece_0": {"noul": 0.5}}}, captured, None

    assert exact.dry_run_worker_forward(call, predict=good) == 1

    def stale(
        _state: dict[str, object], _questions: dict[str, dict[str, object]]
    ) -> tuple[dict[str, object], dict[str, object] | None, str | None]:
        return (
            {"answers": {"item_0_piece_0": {"noul": 0.5}}},
            {**captured, "input_ids": [[9, 9]]},
            None,
        )

    with pytest.raises(ValueError, match="forward tensor mismatch"):
        exact.dry_run_worker_forward(call, predict=stale)

    def wrong_dtype(
        _state: dict[str, object], _questions: dict[str, dict[str, object]]
    ) -> tuple[dict[str, object], dict[str, object] | None, str | None]:
        return (
            {"answers": {"item_0_piece_0": {"noul": 0.5}}},
            {**captured, "marker_mask": [[1]]},
            None,
        )

    with pytest.raises(ValueError, match="forward tensor mismatch"):
        exact.dry_run_worker_forward(call, predict=wrong_dtype)

    def nonfinite(
        _state: dict[str, object], _questions: dict[str, dict[str, object]]
    ) -> tuple[dict[str, object], dict[str, object] | None, str | None]:
        return {"answers": {"item_0_piece_0": {"noul": float("nan")}}}, captured, None

    with pytest.raises(ValueError, match="forward answer invalid"):
        exact.dry_run_worker_forward(call, predict=nonfinite)


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def _pilot(*, invent_unrun_label: bool = False) -> ControlledWorkerFixturePilot:
    examples: list[ControlledWorkerPilotExample] = []
    for number in range(2):
        snapshot_id = f"snapshot-{number}"
        entries = (
            ("evidence", 0, ("fragment:one",)),
            ("probe", 0, ("retrieve:one", "measure:two")),
            ("compare", 0, ("retrieve:one", "measure:two")),
        )
        batches: list[FrontierWorkerBatchReceipt] = []
        attention_batches: list[dict[str, object]] = []
        calls: list[tuple[str, int, str]] = []
        for phase, index, ids in entries:
            call = _call()
            call["state"] = {"attention_kind": phase}
            call["questions"] = [
                {
                    "question_id": f"item_{i}_piece_0",
                    "item_id": item_id,
                    "question": {"type": "noul", "instructions": "synthetic"},
                }
                for i, item_id in enumerate(ids)
            ]
            call["model_input"] = {
                "input_ids": [[1, 2] for _ in ids],
                "attention_mask": [[1, 1] for _ in ids],
                "marker_pos": [[1] for _ in ids],
                "marker_mask": [[True] for _ in ids],
                "qtype": [2 for _ in ids],
            }
            call_json = json.dumps(call, separators=(",", ":"), ensure_ascii=False)
            batches.append(
                FrontierWorkerBatchReceipt(
                    cast(Literal["evidence", "probe", "compare"], phase),
                    index,
                    ids,
                    "c" * 64,
                    call_json,
                    _sha(call_json),
                )
            )
            attention_batches.append(
                {
                    "phase": phase,
                    "batch_index": index,
                    "candidate_ids": ids,
                    "inference_ids": ids,
                    "cache_hit_ids": [],
                    "cached_origins": [],
                    "worker_presentation": {"presentation_sha256": "c" * 64},
                }
            )
            calls.append((phase, index, call_json))
        attention = {"microbatches": attention_batches}
        request_json = json.dumps(
            {
                "items": [{"item_id": "retrieve:one"}, {"item_id": "measure:two"}],
                "evidence_packets": [{"fragment_id": "fragment:one"}],
                "model_weight_sha256": "a" * 64,
            },
            separators=(",", ":"),
        )
        response_json = json.dumps({"presentation_trace": attention}, separators=(",", ":"))
        receipt_json = '{"receipt":"synthetic"}'
        reviewed = _sha(
            _canonical((request_json, response_json, receipt_json, attention, tuple(calls)))
        )
        pins = tuple(
            (name, "a" * 64)
            for name in (
                "model_weight_sha256",
                "package_wheel_sha256",
                "tokenizer_sha256",
                "model_config_sha256",
                "upstream_common_sha256",
                "upstream_agent_sha256",
                "worker_sha256",
            )
        )
        worker = FrontierWorkerReceipt(
            1,
            snapshot_id,
            _sha(request_json),
            _sha(response_json),
            _sha(receipt_json),
            _sha(_canonical(attention)),
            reviewed,
            "synthetic-review",
            "synthetic-consent",
            pins,
            tuple(batches),
        )
        fixture = FrontierPilotExample(
            snapshot_id,
            f"case-{number}",
            1,
            "pilot_train",
            f"machine-{number}",
            "software",
            f"fault-{number}",
            "retrieve:one",
            request_json,
            _sha(request_json),
            response_json,
            _sha(response_json),
            receipt_json,
            _sha(receipt_json),
            (),
            _sha(_canonical((request_json, response_json, receipt_json))),
            "synthetic-review",
            "synthetic-consent",
            (
                PilotItemOutcome("retrieve:one", "useful", "useful", "d" * 64, "synthetic"),
                PilotItemOutcome(
                    "measure:two",
                    "useful" if invent_unrun_label else "unrun",
                    "useful" if invent_unrun_label else "unknown",
                    None,
                    None,
                ),
            ),
        )
        examples.append(
            ControlledWorkerPilotExample(
                fixture, "e" * 64, "f" * 64, worker, _sha(worker.to_json())
            )
        )
    export_sha = _sha(_canonical([asdict(item.fixture) for item in examples]))
    pilot_sha = _sha(
        _canonical(
            (
                export_sha,
                tuple(
                    (
                        item.fixture.snapshot_id,
                        item.source_artifact_sha256,
                        item.draft_sha256,
                        item.worker_receipt_sha256,
                    )
                    for item in examples
                ),
            )
        )
    )
    return ControlledWorkerFixturePilot(
        1, "caller_checked_fixture_claim", False, False, "not_verified", tuple(examples), pilot_sha
    )


def test_mixed_frontier_dry_run_preserves_retrieve_measure_compare_and_unknown_masks(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    pilot = TypeAdapter(ControlledWorkerFixturePilot).validate_json(
        json.dumps(asdict(_pilot()), ensure_ascii=False)
    )
    seen: list[str] = []

    def reconstruct(
        call: dict[str, object], _presentation: dict[str, object], **_kwargs: object
    ) -> tuple[ModelBatch, tuple[str, ...], int]:
        model_input = cast(dict[str, object], call["model_input"])
        questions = cast(list[dict[str, object]], call["questions"])
        return (
            ModelBatch(
                tuple(cast(str, row["question_id"]) for row in questions),
                tuple(tuple(row) for row in cast(list[list[int]], model_input["input_ids"])),
                tuple(tuple(row) for row in cast(list[list[int]], model_input["attention_mask"])),
                tuple(tuple(row) for row in cast(list[list[int]], model_input["marker_pos"])),
                tuple(tuple(row) for row in cast(list[list[bool]], model_input["marker_mask"])),
                tuple(cast(list[int], model_input["qtype"])),
                tuple(QuestionPresentation(1, 1, 1, 1, 1, 1) for _ in questions),
            ),
            (),
            len(questions),
        )

    monkeypatch.setattr(exact, "reconstruct_exact_worker_call", reconstruct)

    def predict(
        state: dict[str, object], questions: dict[str, dict[str, object]]
    ) -> tuple[dict[str, object], dict[str, object] | None, str | None]:
        phase = cast(str, state["attention_kind"])
        seen.append(phase)
        batch = next(
            batch
            for example in pilot.examples
            for batch in example.worker_receipt.batches
            if batch.phase == phase
        )
        call = json.loads(batch.exact_worker_call_json)
        return {"answers": {key: {"noul": 0.5} for key in questions}}, call["model_input"], None

    qualification: dict[str, object] = {
        "status": "pass",
        **dict(pilot.examples[0].worker_receipt.artifact_pins),
    }
    report = exact.dry_run_frontier_pilot(
        pilot,
        tokenizer=cast(exact.Tokenizer, object()),
        cfg={},
        qualification=qualification,
        predict=predict,
    )
    assert seen == ["evidence", "probe", "compare"] * 2
    assert report["forward_batches"] == 6
    assert report["unknown_masked"] == 2
    assert report["supervised_pairs"] == 0
    assert report["trainable"] is False
    assert "synthetic" not in str(report)
    seen.clear()
    with pytest.raises(ValueError, match="unrun frontier alternative"):
        exact.dry_run_frontier_pilot(
            _pilot(invent_unrun_label=True),
            tokenizer=cast(exact.Tokenizer, object()),
            cfg={},
            qualification=qualification,
            predict=predict,
        )
    assert seen == []


def test_weight_digest_rejects_changed_local_file(tmp_path: Path) -> None:
    weight = tmp_path / "model.safetensors"
    weight.write_bytes(b"synthetic pinned weights")
    expected = hashlib.sha256(weight.read_bytes()).hexdigest()
    assert (
        exact.verify_weight_digest(weight, expected_sha256=expected, expected_bytes=24) == expected
    )
    weight.write_bytes(b"synthetic changed weights")
    with pytest.raises(ValueError, match="weight digest mismatch"):
        exact.verify_weight_digest(weight, expected_sha256=expected, expected_bytes=24)
