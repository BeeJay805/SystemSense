"""V1, local-only reconstruction of a reviewed export's exact Laya probe inputs.

This is a preparation and parity boundary, not training admission. The persisted
export is preworker-only; callers must supply every privacy-reviewed worker call.
No receipt in these JSON files authenticates a reviewer, consent, or a label.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import cast

from benchmarks.laya_exact_batch_parity import verify_exact_batch
from benchmarks.laya_presentation_parity import ModelBatch, Tokenizer, predict_model_batch
from systemsense.evaluation.training_admission import (
    TrainingExport,
    training_corpus_sha256,
    verified_export_payloads,
)

SCHEMA_VERSION = 1
_MAX_EXAMPLES = 500
_MAX_BATCHES = 32


@dataclass(frozen=True)
class CapturedExample:
    snapshot_id: str
    request_sha256: str
    candidate_ids: tuple[str, ...]
    batches: tuple[dict[str, object], ...]


@dataclass(frozen=True)
class ReconstructedBatch:
    """Tensor-ready input with explicit non-admission and ordered target identity."""

    snapshot_id: str
    batch_index: int
    candidate_ids: tuple[str, ...]
    question_to_candidate: tuple[tuple[str, str], ...]
    model_batch: ModelBatch
    model_input_sha256: str
    trainable: bool = False


def _mapping(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} invalid")
    raw = cast(dict[object, object], value)
    if any(not isinstance(key, str) for key in raw):
        raise ValueError(f"{name} invalid")
    return cast(dict[str, object], value)


def _digest(value: object, name: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError(f"{name} invalid")
    return value


def _rows(value: object, name: str, *, maximum: int) -> list[object]:
    if not isinstance(value, list) or not 1 <= len(cast(list[object], value)) <= maximum:
        raise ValueError(f"{name} missing or exceeds bound")
    return cast(list[object], value)


def _candidate_ids(value: object) -> tuple[str, ...]:
    rows = _rows(value, "candidate order", maximum=20)
    if any(not isinstance(row, str) or not row for row in rows):
        raise ValueError("candidate order invalid")
    result = tuple(cast(list[str], rows))
    if len(set(result)) != len(result):
        raise ValueError("candidate order duplicated")
    return result


def validate_capture_manifest(
    manifest: dict[str, object],
    *,
    expected_corpus_sha256: str,
    expected_examples: tuple[tuple[str, str, tuple[str, ...]], ...],
) -> tuple[CapturedExample, ...]:
    """Bind all captured probe batches to a complete, ordered reviewed export.

    The caller must derive ``expected_examples`` from a verified TrainingExport.
    This function verifies structural coverage; exact tensors are checked by
    ``reconstruct_training_inputs`` against the pinned installed builder.
    """

    if manifest.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("capture schema unsupported")
    if _digest(manifest.get("corpus_sha256"), "corpus digest") != _digest(
        expected_corpus_sha256, "expected corpus digest"
    ):
        raise ValueError("corpus digest mismatch")
    if not 1 <= len(expected_examples) <= _MAX_EXAMPLES:
        raise ValueError("expected corpus empty or exceeds bound")
    supplied = manifest.get("examples")
    if not isinstance(supplied, list) or len(cast(list[object], supplied)) != len(
        expected_examples
    ):
        raise ValueError("corpus capture incomplete")
    supplied_rows = cast(list[object], supplied)
    captured: list[CapturedExample] = []
    for raw, (snapshot_id, request_sha, expected_ids) in zip(
        supplied_rows, expected_examples, strict=True
    ):
        row = _mapping(raw, "corpus capture")
        if row.get("snapshot_id") != snapshot_id or row.get("request_sha256") != request_sha:
            raise ValueError("corpus capture identity mismatch")
        if not expected_ids or len(set(expected_ids)) != len(expected_ids):
            raise ValueError("expected candidate order invalid")
        raw_batches = _rows(row.get("batches"), "corpus batch", maximum=_MAX_BATCHES)
        batches: list[dict[str, object]] = []
        ordered_ids: list[str] = []
        for index, batch_raw in enumerate(raw_batches):
            batch = _mapping(batch_raw, "corpus batch")
            if (
                batch.get("schema_version") != 1
                or batch.get("snapshot_id") != snapshot_id
                or batch.get("request_sha256") != request_sha
                or batch.get("phase") != "probe"
                or batch.get("batch_index") != index
            ):
                raise ValueError("corpus batch identity mismatch")
            batch_ids = _candidate_ids(batch.get("candidate_ids"))
            trace = _mapping(batch.get("trace"), "exact worker trace")
            trace_payload = _mapping(trace.get("payload"), "exact worker trace payload")
            trace_batches = _rows(
                trace_payload.get("microbatches"), "exact worker trace batch", maximum=_MAX_BATCHES
            )
            trace_rows = tuple(
                _mapping(trace_batch, "exact worker trace batch") for trace_batch in trace_batches
            )
            matching = [
                trace_batch
                for trace_batch in trace_rows
                if trace_batch.get("phase") == "probe" and trace_batch.get("batch_index") == index
            ]
            if len(matching) != 1 or matching[0].get("candidate_ids") != list(batch_ids):
                raise ValueError("candidate order differs from worker trace")
            ordered_ids.extend(batch_ids)
            batches.append(batch)
        if tuple(ordered_ids) != expected_ids:
            raise ValueError("candidate order or coverage mismatch")
        captured.append(CapturedExample(snapshot_id, request_sha, expected_ids, tuple(batches)))
    return tuple(captured)


def reconstruct_training_inputs(
    export: TrainingExport,
    manifest: dict[str, object],
    *,
    expected_corpus_sha256: str,
    tokenizer: Tokenizer,
    cfg: dict[str, object],
    qualification: dict[str, object],
) -> tuple[ReconstructedBatch, ...]:
    """Check whole-corpus coverage and exact builder parity, then return inputs.

    The result is never admitted for training. Independent receipt authentication,
    real outcome labels, and a separate admission decision remain required.
    """

    verified_export_payloads(export)
    if training_corpus_sha256(export) != expected_corpus_sha256:
        raise ValueError("corpus digest mismatch")
    expected: list[tuple[str, str, tuple[str, ...]]] = []
    for example in export.examples:
        ids = tuple(candidate["probe_id"] for candidate in example.input.candidates)
        if tuple(target.probe_id for target in example.targets) != ids:
            raise ValueError("label target order does not match candidates")
        expected.append((example.snapshot_id, example.request_sha256, ids))
    captures = validate_capture_manifest(
        manifest,
        expected_corpus_sha256=expected_corpus_sha256,
        expected_examples=tuple(expected),
    )
    max_len, head_max_len = cfg.get("max_len"), cfg.get("head_max_len")
    if (
        not isinstance(max_len, int)
        or isinstance(max_len, bool)
        or not isinstance(head_max_len, int)
        or isinstance(head_max_len, bool)
    ):
        raise ValueError("pinned token limits unavailable")
    rebuilt: list[ReconstructedBatch] = []
    for capture in captures:
        for batch in capture.batches:
            report = verify_exact_batch(
                batch, tokenizer=tokenizer, cfg=cfg, qualification=qualification
            )
            if report["status"] != "pass" or report["trainable"] is not False:
                raise ValueError("exact worker batch parity failed")
            call = _mapping(batch.get("exact_worker_call"), "exact worker call")
            state = _mapping(call.get("state"), "exact worker state")
            question_rows = _rows(call.get("questions"), "exact worker questions", maximum=128)
            questions: dict[str, dict[str, object]] = {}
            mapping: list[tuple[str, str]] = []
            for raw_question in question_rows:
                row = _mapping(raw_question, "exact worker question")
                question_id, item_id = row.get("question_id"), row.get("item_id")
                if not isinstance(question_id, str) or not isinstance(item_id, str):
                    raise ValueError("exact worker question identity invalid")
                if question_id in questions:
                    raise ValueError("exact worker question identity duplicated")
                questions[question_id] = _mapping(row.get("question"), "exact worker question")
                mapping.append((question_id, item_id))
            batch_ids = _candidate_ids(batch.get("candidate_ids"))
            if tuple(dict.fromkeys(item_id for _, item_id in mapping)) != batch_ids:
                raise ValueError("exact worker question order mismatch")
            model_batch = predict_model_batch(
                tokenizer=tokenizer,
                state=state,
                questions=questions,
                max_len=max_len,
                head_max_len=head_max_len,
            )
            rebuilt.append(
                ReconstructedBatch(
                    snapshot_id=capture.snapshot_id,
                    batch_index=cast(int, batch["batch_index"]),
                    candidate_ids=batch_ids,
                    question_to_candidate=tuple(mapping),
                    model_batch=model_batch,
                    model_input_sha256=cast(str, report["model_input_sha256"]),
                )
            )
    return tuple(rebuilt)
