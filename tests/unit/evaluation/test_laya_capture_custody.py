from __future__ import annotations

import hashlib
import json
from copy import deepcopy
from types import SimpleNamespace
from typing import cast

import pytest

from benchmarks import laya_training_loader as loader
from systemsense.evaluation.training_admission import TrainingExport
from systemsense.inference.laya_runtime import (
    LayaAttentionMicrobatch,
    LayaQuestionPresentation,
    LayaWorkerPresentation,
)
from systemsense.storage.decision_snapshots import DecisionSnapshotRepository
from tests.unit.evaluation import test_laya_training_loader as fixtures


def _digest(kind: str, value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(f"systemsense.laya.{kind}.v1\0".encode() + encoded.encode()).hexdigest()


def _source(
    *, evidence: tuple[dict[str, str], ...] = ()
) -> tuple[TrainingExport, SimpleNamespace, dict[str, object], LayaWorkerPresentation]:
    export = fixtures._export(evidence=evidence)  # pyright: ignore[reportPrivateUsage]
    example = export.examples[0]
    question = {
        "type": "noul",
        "instructions": "Inspect synthetic probe",
        "criteria": {"true": "yes", "false": "no"},
    }
    questions: list[dict[str, object]] = [
        {"question_id": "item_0_piece_0", "item_id": "probe.one", "question": question}
    ]
    state: dict[str, object] = {"attention_kind": "probe_relevance"}
    call: dict[str, object] = {
        "state": state,
        "questions": questions,
        "state_coverage": {
            "state_tokens_original": 3,
            "state_fields_omitted": 0,
            "state_list_items_omitted": 0,
        },
    }
    proof = LayaWorkerPresentation(
        presentation_sha256="e" * 64,
        fitted_state_sha256=_digest("state", state),
        questions_sha256=_digest("questions", questions),
        presented_item_ids=("probe.one",),
        fitted_state_tokens=3,
        state_tokens_original=3,
        state_fields_omitted=0,
        state_list_items_omitted=0,
        questions=(
            LayaQuestionPresentation(
                question_id="item_0_piece_0",
                item_id="probe.one",
                question_sha256=_digest("question", question),
                instruction_tokens=1,
                instruction_presented_tokens=1,
                criteria_tokens=1,
                criteria_presented_tokens=1,
                state_presented_tokens=3,
            ),
        ),
    )
    batch = LayaAttentionMicrobatch(
        phase="probe",
        batch_index=0,
        candidate_ids=("probe.one",),
        inference_ids=("probe.one",),
        worker_presentation=proof,
    )
    trace = SimpleNamespace(
        format_id="laya-worker-attention-v2",
        payload={
            **fixtures._projection_fields(export),  # pyright: ignore[reportPrivateUsage]
            "microbatches": [batch.model_dump(mode="json")],
        },
    )
    snapshot = SimpleNamespace(
        snapshot_id=example.snapshot_id,
        case_id=example.case_id,
        request_sha256=example.request_sha256,
        laya_projection_sha256=example.laya_projection_sha256,
        laya_state=example.input.state,
        laya_evidence=example.input.evidence,
        laya_candidates=example.input.candidates,
        presentation_trace=SimpleNamespace(
            trace=trace,
            probe_candidates_complete=True,
            evidence_pages_complete=True,
            worker_presentations_complete=True,
            cache_origins_complete=True,
            worker_inference_present=True,
        ),
    )
    return export, snapshot, call, proof


def _repository(snapshot: SimpleNamespace) -> DecisionSnapshotRepository:
    class FakeRepository:
        def snapshots(self, *, case_id: str, limit: int = 100) -> tuple[object, ...]:
            assert case_id == snapshot.case_id
            assert limit >= 1
            return (snapshot,)

    return cast(DecisionSnapshotRepository, FakeRepository())


def test_durable_custody_binds_readback_to_exact_callback_without_admission() -> None:
    export, snapshot, call, proof = _source()
    capture = loader.EphemeralWorkerCapture()
    capture.callback("probe", 0, call, proof)
    report = loader.verify_durable_capture_custody(
        export,
        repository=_repository(snapshot),
        captures={export.examples[0].snapshot_id: capture},
    )
    assert report["schema_version"] == 1
    assert report["status"] == "pass"
    assert report["trainable"] is False
    assert report["privacy_receipt_authenticated"] is False
    assert report["callback_provenance_authenticated"] is False
    assert "exact_worker_call" not in str(report)


def test_durable_custody_rejects_swapped_snapshot_and_callback() -> None:
    export, snapshot, call, proof = _source()
    capture = loader.EphemeralWorkerCapture()
    capture.callback("probe", 0, call, proof)
    with pytest.raises(ValueError, match="projection"):
        loader.verify_durable_capture_custody(
            export,
            repository=_repository(
                SimpleNamespace(**{**vars(snapshot), "laya_state": {"changed": True}})
            ),
            captures={export.examples[0].snapshot_id: capture},
        )
    wrong_call = {**call, "state": {"changed": True}}
    wrong_capture = loader.EphemeralWorkerCapture()
    with pytest.raises(ValueError, match="state digest"):
        wrong_capture.callback("probe", 0, wrong_call, proof)
    with pytest.raises(ValueError, match="incomplete"):
        loader.verify_durable_capture_custody(
            export,
            repository=_repository(snapshot),
            captures={export.examples[0].snapshot_id: wrong_capture},
        )


def test_durable_custody_rejects_reordered_worker_callbacks() -> None:
    evidence = (
        {
            "evidence_id": "ev.one",
            "page_id": "ev.one:0",
            "fragment_id": "fragment.one",
            "description": "Synthetic packet",
        },
    )
    export, snapshot, probe_call, probe_proof = _source(evidence=evidence)
    evidence_call = deepcopy(probe_call)
    evidence_questions = cast(list[dict[str, object]], evidence_call["questions"])
    evidence_questions[0]["item_id"] = "fragment.one"
    evidence_proof = probe_proof.model_copy(
        update={
            "questions_sha256": _digest("questions", evidence_questions),
            "presented_item_ids": ("fragment.one",),
            "questions": (probe_proof.questions[0].model_copy(update={"item_id": "fragment.one"}),),
        }
    )
    evidence_batch = LayaAttentionMicrobatch(
        phase="evidence",
        batch_index=0,
        candidate_ids=("fragment.one",),
        inference_ids=("fragment.one",),
        worker_presentation=evidence_proof,
    )
    snapshot.presentation_trace.trace.payload["microbatches"].insert(
        0, evidence_batch.model_dump(mode="json")
    )
    capture = loader.EphemeralWorkerCapture()
    capture.callback("probe", 0, probe_call, probe_proof)
    capture.callback("evidence", 0, evidence_call, evidence_proof)
    with pytest.raises(ValueError, match="order"):
        loader.verify_durable_capture_custody(
            export,
            repository=_repository(snapshot),
            captures={export.examples[0].snapshot_id: capture},
        )
