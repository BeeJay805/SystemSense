"""Opt-in synthetic parity qualification for the pinned Laya input serializer.

This file intentionally has only standard-library imports at module import time, so the
isolated Laya Python interpreter can run it without installing SystemSense. It never
loads model weights or performs inference.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib
import importlib.util
import json
import os
import sys
from collections.abc import Callable
from dataclasses import asdict, dataclass, replace
from importlib import metadata
from pathlib import Path
from types import ModuleType
from typing import Protocol, cast

REPORT_SCHEMA_VERSION = 1
SYNTHETIC_CASE_SET_VERSION = 1
EXPECTED_PACKAGE_VERSION = "0.3.5"
EXPECTED_MODEL_REVISION = "f9ab0b228f0fc0f14d873dbc99038f135c2da1b2"


class Tokenizer(Protocol):
    cls_token_id: int
    sep_token_id: int
    pad_token_id: int
    mask_token_id: int
    mask_token: str

    def __call__(self, text: str, *, add_special_tokens: bool = False) -> dict[str, object]: ...


class _Tensor(Protocol):
    def tolist(self) -> object: ...


class _TokenizerFactory(Protocol):
    def from_pretrained(
        self, model_path: str, *, local_files_only: bool, trust_remote_code: bool
    ) -> Tokenizer: ...


@dataclass(frozen=True)
class QuestionPresentation:
    instruction_original_tokens: int
    instruction_presented_tokens: int
    criteria_original_tokens: int
    criteria_presented_tokens: int
    state_original_tokens: int
    state_presented_tokens: int


@dataclass(frozen=True)
class ModelBatch:
    """Exact integer/bool tensors the decision model receives, represented as tuples."""

    question_ids: tuple[str, ...]
    input_ids: tuple[tuple[int, ...], ...]
    attention_mask: tuple[tuple[int, ...], ...]
    marker_pos: tuple[tuple[int, ...], ...]
    marker_mask: tuple[tuple[bool, ...], ...]
    qtype: tuple[int, ...]
    questions: tuple[QuestionPresentation, ...]


@dataclass(frozen=True)
class SyntheticCase:
    case_id: str
    state: dict[str, object]
    candidates: tuple[tuple[str, str], ...]


def synthetic_cases() -> tuple[SyntheticCase, ...]:
    """Versioned, bounded text vectors; no machine or customer observations."""

    return (
        SyntheticCase(
            "short-two-candidates",
            {
                "symptom": "Synthetic Wi-Fi disconnects after sleep",
                "attention_kind": "probe_relevance",
            },
            (
                ("network.adapter", "Inspect local adapter state"),
                ("network.events", "Read recent adapter events"),
            ),
        ),
        SyntheticCase(
            "mask-and-unicode",
            {
                "symptom": "Synthetic café printer [MASK] queue",
                "attention_kind": "probe_relevance",
            },
            (
                ("printer.queue", "Read [MASK] queue state"),
                ("printer.driver", "Inspect driver metadata for café printer"),
            ),
        ),
        SyntheticCase(
            "bounded-state-and-chunks",
            {
                "symptom": "Synthetic game frame pacing",
                "attention_kind": "probe_relevance",
                "coverage_notes": [
                    f"synthetic-not-real-observation-{index:02d}-" + "x" * 200
                    for index in range(30)
                ],
            },
            (
                (
                    "graphics.driver",
                    "Inspect synthetic graphics driver version and clock-limit reasons",
                ),
                ("graphics.clocks", "Read clock limit reasons"),
            ),
        ),
    )


def _token_ids(tokenizer: Tokenizer, text: str) -> list[int]:
    raw = tokenizer(text, add_special_tokens=False).get("input_ids")
    if not isinstance(raw, list) or any(
        not isinstance(item, int) for item in cast(list[object], raw)
    ):
        raise ValueError("tokenizer did not return flat integer token IDs")
    return cast(list[int], raw)


def predict_model_batch(
    *,
    tokenizer: Tokenizer,
    state: dict[str, object],
    questions: dict[str, dict[str, object]],
    max_len: int,
    head_max_len: int,
) -> ModelBatch:
    """Predict Laya's fixed `noul` tensors independently of its installed source.

    This mirrors the bounded worker's presentation claims. The qualification compares
    these values to the *installed* upstream build_sequence/collate_items results.
    """

    if not 1 <= len(questions) <= 128 or not 8 <= max_len <= 8192 or not 8 <= head_max_len <= 8192:
        raise ValueError("parity input exceeds its synthetic bounds")
    state_ids = _token_ids(
        tokenizer, json.dumps(state, ensure_ascii=False).replace(tokenizer.mask_token, " ")
    )
    rows: list[tuple[int, ...]] = []
    markers_by_row: list[tuple[int, ...]] = []
    details: list[QuestionPresentation] = []
    for question in questions.values():
        if question.get("type") != "noul":
            raise ValueError("only the SystemSense noul question contract is qualified")
        criteria_raw = question.get("criteria")
        if not isinstance(criteria_raw, dict):
            raise ValueError("unexpected SystemSense criteria")
        criteria = cast(dict[str, object], criteria_raw)
        if set(criteria) != {"false", "true"}:
            raise ValueError("unexpected SystemSense criteria")
        instructions = question.get("instructions")
        if not isinstance(instructions, str) or any(
            not isinstance(criteria[label], str) for label in ("false", "true")
        ):
            raise ValueError("unexpected SystemSense question")
        head = _token_ids(
            tokenizer,
            f"noul question: {instructions.replace(tokenizer.mask_token, ' ')}",
        )
        options = [
            [
                tokenizer.mask_token_id,
                *_token_ids(
                    tokenizer,
                    f" {label}: {str(criteria[label]).replace(tokenizer.mask_token, ' ')}",
                )[:48],
            ]
            for label in ("false", "true")
        ]
        raw_option_count = sum(map(len, options))
        option_budget = head_max_len - raw_option_count
        if option_budget < 16:
            per_option = max(4, (head_max_len - 16) // 2)
            options = [option[:per_option] for option in options]
            option_budget = head_max_len - sum(map(len, options))
        head_presented = head[: max(8, option_budget)]
        sequence = [tokenizer.cls_token_id, *head_presented, tokenizer.sep_token_id]
        markers: list[int] = []
        for option in options:
            markers.append(len(sequence))
            sequence.extend(option)
        sequence.append(tokenizer.sep_token_id)
        room = max(0, max_len - len(sequence) - 1)
        state_presented = state_ids[:room]
        sequence.extend(state_presented)
        sequence.append(tokenizer.sep_token_id)
        rows.append(tuple(sequence[:max_len]))
        markers_by_row.append(tuple(marker for marker in markers if marker < max_len))
        details.append(
            QuestionPresentation(
                instruction_original_tokens=len(head),
                instruction_presented_tokens=len(head_presented),
                criteria_original_tokens=raw_option_count,
                criteria_presented_tokens=sum(map(len, options)),
                state_original_tokens=len(state_ids),
                state_presented_tokens=len(state_presented),
            )
        )
    width = max(map(len, rows))
    marker_width = max(map(len, markers_by_row))
    return ModelBatch(
        question_ids=tuple(questions),
        input_ids=tuple(row + (tokenizer.pad_token_id,) * (width - len(row)) for row in rows),
        attention_mask=tuple((1,) * len(row) + (0,) * (width - len(row)) for row in rows),
        marker_pos=tuple(
            markers + (0,) * (marker_width - len(markers)) for markers in markers_by_row
        ),
        marker_mask=tuple(
            (True,) * len(markers) + (False,) * (marker_width - len(markers))
            for markers in markers_by_row
        ),
        qtype=(2,) * len(rows),
        questions=tuple(details),
    )


def compare_batches(predicted: ModelBatch, upstream: ModelBatch) -> tuple[str, ...]:
    """Return only differing field names; never return model-visible content."""

    return tuple(
        field
        for field in (
            "question_ids",
            "input_ids",
            "attention_mask",
            "marker_pos",
            "marker_mask",
            "qtype",
            "questions",
        )
        if getattr(predicted, field) != getattr(upstream, field)
    )


def compare_worker_presentation(
    predicted: ModelBatch, report: dict[str, object]
) -> tuple[str, ...]:
    """Check the worker's runtime presentation claims against exact prediction."""

    differences: list[str] = []
    if (
        not predicted.questions
        or report.get("fitted_state_tokens") != predicted.questions[0].state_original_tokens
    ):
        differences.append("fitted_state_tokens")
    raw_details = report.get("questions")
    if not isinstance(raw_details, list):
        return (*differences, "question_count")
    detail_items = cast(list[object], raw_details)
    if len(detail_items) != len(predicted.questions):
        return (*differences, "question_count")
    for question_id, expected, raw in zip(
        predicted.question_ids, predicted.questions, detail_items, strict=True
    ):
        if not isinstance(raw, dict):
            differences.append(f"{question_id}:invalid_question")
            continue
        detail = cast(dict[str, object], raw)
        if detail.get("question_id") != question_id:
            differences.append(f"{question_id}:question_order")
        for field, count in (
            ("instruction_tokens", expected.instruction_original_tokens),
            ("instruction_presented_tokens", expected.instruction_presented_tokens),
            ("criteria_tokens", expected.criteria_original_tokens),
            ("criteria_presented_tokens", expected.criteria_presented_tokens),
            ("state_presented_tokens", expected.state_presented_tokens),
        ):
            if detail.get(field) != count:
                differences.append(f"{question_id}:{field}")
    return tuple(differences)


def run_negative_controls(reference: ModelBatch) -> dict[str, bool]:
    """Prove the comparator rejects one-cell corruptions in each critical surface."""

    if len(reference.question_ids) < 2 or not reference.input_ids[0]:
        raise ValueError("negative controls need two nonempty synthetic questions")
    q0, q1, *rest = reference.question_ids
    first_ids = reference.input_ids[0]
    first_att = reference.attention_mask[0]
    first_marker = reference.marker_pos[0]
    first_mask = reference.marker_mask[0]
    corruptions = {
        "input_ids": replace(
            reference,
            input_ids=((first_ids[0] + 1, *first_ids[1:]), *reference.input_ids[1:]),
        ),
        "marker_pos": replace(
            reference,
            marker_pos=((first_marker[0] + 1, *first_marker[1:]), *reference.marker_pos[1:]),
        ),
        "marker_mask": replace(
            reference,
            marker_mask=((not first_mask[0], *first_mask[1:]), *reference.marker_mask[1:]),
        ),
        "attention_mask": replace(
            reference,
            attention_mask=((1 - first_att[0], *first_att[1:]), *reference.attention_mask[1:]),
        ),
        "question_order": replace(reference, question_ids=(q1, q0, *rest)),
        "state_truncation": replace(
            reference,
            questions=(
                replace(
                    reference.questions[0],
                    state_presented_tokens=reference.questions[0].state_presented_tokens + 1,
                ),
                *reference.questions[1:],
            ),
        ),
    }
    return {
        name: bool(compare_batches(reference, altered)) for name, altered in corruptions.items()
    }


def _sha256_json(value: object) -> str:
    serialized = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()


def _load_worker_source() -> ModuleType:
    path = (
        Path(__file__).resolve().parents[1] / "src" / "systemsense" / "inference" / "laya_worker.py"
    )
    spec = importlib.util.spec_from_file_location("systemsense_laya_worker_parity", path)
    if spec is None or spec.loader is None:
        raise RuntimeError("SystemSense worker source is unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _matrix(
    raw: object, *, boolean: bool
) -> tuple[tuple[int, ...], ...] | tuple[tuple[bool, ...], ...]:
    if not isinstance(raw, list):
        raise ValueError("upstream collator returned an invalid tensor")
    rows = cast(list[object], raw)
    converted: list[tuple[int, ...] | tuple[bool, ...]] = []
    for row in rows:
        if not isinstance(row, list):
            raise ValueError("upstream collator returned an invalid tensor")
        cells = cast(list[object], row)
        if boolean:
            if any(not isinstance(cell, bool) for cell in cells):
                raise ValueError("upstream marker mask is not boolean")
            converted.append(tuple(cast(list[bool], cells)))
        else:
            if any(not isinstance(cell, int) or isinstance(cell, bool) for cell in cells):
                raise ValueError("upstream token tensor is not integer")
            converted.append(tuple(cast(list[int], cells)))
    return cast(tuple[tuple[int, ...], ...] | tuple[tuple[bool, ...], ...], tuple(converted))


def _vector(raw: object) -> tuple[int, ...]:
    if not isinstance(raw, list):
        raise ValueError("upstream qtype tensor is invalid")
    values = cast(list[object], raw)
    if any(not isinstance(value, int) or isinstance(value, bool) for value in values):
        raise ValueError("upstream qtype tensor is not integer")
    return tuple(cast(list[int], values))


def _upstream_model_batch(
    *,
    tokenizer: Tokenizer,
    state: dict[str, object],
    questions: dict[str, dict[str, object]],
    max_len: int,
    head_max_len: int,
    predicted: ModelBatch,
) -> ModelBatch:
    common = importlib.import_module("laya.common")
    agent_module = importlib.import_module("laya.agent")
    upstream_agent = agent_module.Agent
    to_internal = cast(
        Callable[[dict[str, object]], dict[str, object]], upstream_agent._to_internal
    )
    build_sequence = cast(Callable[..., tuple[list[int], list[int]]], common.build_sequence)
    collate_items = cast(
        Callable[[list[list[dict[str, object]]], int], dict[str, _Tensor]],
        common.collate_items,
    )
    rows: list[dict[str, object]] = []
    details: list[QuestionPresentation] = []
    for predicted_detail, question in zip(predicted.questions, questions.values(), strict=True):
        internal = to_internal(question)
        sequence, markers = build_sequence(tokenizer, state, internal, max_len, head_max_len)
        empty_sequence, _ = build_sequence(tokenizer, "", internal, max_len, head_max_len)
        rows.append({"ids": sequence, "markers": markers, "qtype": 2})
        details.append(
            replace(
                predicted_detail,
                state_presented_tokens=max(0, len(sequence) - len(empty_sequence)),
            )
        )
    tensors = collate_items([rows], tokenizer.pad_token_id)
    return ModelBatch(
        question_ids=tuple(questions),
        input_ids=cast(
            tuple[tuple[int, ...], ...], _matrix(tensors["input_ids"].tolist(), boolean=False)
        ),
        attention_mask=cast(
            tuple[tuple[int, ...], ...], _matrix(tensors["attention_mask"].tolist(), boolean=False)
        ),
        marker_pos=cast(
            tuple[tuple[int, ...], ...], _matrix(tensors["marker_pos"].tolist(), boolean=False)
        ),
        marker_mask=cast(
            tuple[tuple[bool, ...], ...], _matrix(tensors["marker_mask"].tolist(), boolean=True)
        ),
        qtype=_vector(tensors["qtype"].tolist()),
        questions=tuple(details),
    )


class _CaptureAgent:
    def __init__(self, tokenizer: Tokenizer, cfg: dict[str, object]) -> None:
        self.tok = tokenizer
        self.cfg = cfg
        self.state: dict[str, object] | None = None
        self.questions: dict[str, dict[str, object]] | None = None

    def predict(
        self, state: dict[str, object], questions: dict[str, dict[str, object]]
    ) -> dict[str, object]:
        self.state = state
        self.questions = questions
        return {"answers": {key: {"noul": 0.5} for key in questions}}


def _qualify_case(
    case: SyntheticCase,
    *,
    tokenizer: Tokenizer,
    cfg: dict[str, object],
    worker_handle: Callable[[object, dict[str, object]], dict[str, object]],
) -> tuple[dict[str, object], dict[str, bool]]:
    agent = _CaptureAgent(tokenizer, cfg)
    request: dict[str, object] = {
        "protocol_version": 1,
        "request_id": case.case_id,
        "state": case.state,
        "candidates": [
            {"probe_id": item_id, "description": description}
            for item_id, description in case.candidates
        ],
    }
    response = worker_handle(agent, request)
    state, questions = agent.state, agent.questions
    if state is None or questions is None:
        raise RuntimeError("SystemSense worker did not hand a presentation to Laya")
    max_len, head_max_len = cfg.get("max_len"), cfg.get("head_max_len")
    if not isinstance(max_len, int) or not isinstance(head_max_len, int):
        raise ValueError("pinned Laya token limits are invalid")
    predicted = predict_model_batch(
        tokenizer=tokenizer,
        state=state,
        questions=questions,
        max_len=max_len,
        head_max_len=head_max_len,
    )
    upstream = _upstream_model_batch(
        tokenizer=tokenizer,
        state=state,
        questions=questions,
        max_len=max_len,
        head_max_len=head_max_len,
        predicted=predicted,
    )
    presentation_raw = response.get("presentation")
    if not isinstance(presentation_raw, dict):
        raise ValueError("SystemSense worker omitted presentation provenance")
    presentation = cast(dict[str, object], presentation_raw)
    differences = (
        *compare_batches(predicted, upstream),
        *compare_worker_presentation(predicted, presentation),
    )
    negative_controls = run_negative_controls(predicted)
    return (
        {
            "case_id": case.case_id,
            "status": "pass" if not differences and all(negative_controls.values()) else "fail",
            "question_count": len(questions),
            "presentation_sha256": presentation.get("presentation_sha256"),
            "model_input_sha256": _sha256_json(asdict(upstream)),
            "state_fields_omitted": presentation.get("state_fields_omitted"),
            "state_list_items_omitted": presentation.get("state_list_items_omitted"),
            "state_truncated_questions": sum(
                detail.state_presented_tokens < detail.state_original_tokens
                for detail in upstream.questions
            ),
            "instruction_truncated_questions": sum(
                detail.instruction_presented_tokens < detail.instruction_original_tokens
                for detail in upstream.questions
            ),
            "mismatched_fields": list(differences),
        },
        negative_controls,
    )


def _qualify_boundary_vectors(tokenizer: Tokenizer) -> list[dict[str, object]]:
    """Exercise actual upstream clipping separately from the worker's anti-clipping fit."""

    vectors: tuple[tuple[str, dict[str, object], dict[str, dict[str, object]], int, int], ...] = (
        (
            "state-truncation",
            {"symptom": "synthetic " + "state-token " * 400},
            {
                "q0": {
                    "type": "noul",
                    "instructions": "Read adapter",
                    "criteria": {"false": "not useful", "true": "useful"},
                },
                "q1": {
                    "type": "noul",
                    "instructions": "Read events",
                    "criteria": {"false": "not useful", "true": "useful"},
                },
            },
            64,
            32,
        ),
        (
            "head-and-option-truncation",
            {"symptom": "synthetic head boundary"},
            {
                "q0": {
                    "type": "noul",
                    "instructions": "inspect " * 200,
                    "criteria": {"false": "negative " * 100, "true": "positive " * 100},
                },
                "q1": {
                    "type": "noul",
                    "instructions": "compare " * 200,
                    "criteria": {"false": "no " * 100, "true": "yes " * 100},
                },
            },
            64,
            32,
        ),
    )
    reports: list[dict[str, object]] = []
    for vector_id, state, questions, max_len, head_max_len in vectors:
        predicted = predict_model_batch(
            tokenizer=tokenizer,
            state=state,
            questions=questions,
            max_len=max_len,
            head_max_len=head_max_len,
        )
        upstream = _upstream_model_batch(
            tokenizer=tokenizer,
            state=state,
            questions=questions,
            max_len=max_len,
            head_max_len=head_max_len,
            predicted=predicted,
        )
        differences = compare_batches(predicted, upstream)
        reports.append(
            {
                "vector_id": vector_id,
                "route": "serializer_edge_only",
                "status": "pass" if not differences else "fail",
                "question_count": len(questions),
                "state_truncated": any(
                    detail.state_presented_tokens < detail.state_original_tokens
                    for detail in upstream.questions
                ),
                "instruction_truncated": any(
                    detail.instruction_presented_tokens < detail.instruction_original_tokens
                    for detail in upstream.questions
                ),
                "mismatched_fields": list(differences),
                "model_input_sha256": _sha256_json(asdict(upstream)),
            }
        )
    return reports


def qualify_local_install(model_path: Path) -> dict[str, object]:
    """Read only a pinned local tokenizer and official source; never load weights."""

    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    os.environ["CUDA_VISIBLE_DEVICES"] = ""
    if metadata.version("laya") != EXPECTED_PACKAGE_VERSION:
        raise ValueError("installed Laya package differs from the pinned version")
    resolved = model_path.resolve(strict=True)
    manifest_raw = json.loads((resolved / "INSTALL-MANIFEST.json").read_text(encoding="utf-8"))
    if not isinstance(manifest_raw, dict):
        raise ValueError("Laya install manifest is invalid")
    manifest = cast(dict[str, object], manifest_raw)
    if (
        manifest.get("model_revision") != EXPECTED_MODEL_REVISION
        or manifest.get("package_version") != EXPECTED_PACKAGE_VERSION
    ):
        raise ValueError("Laya install manifest differs from the pinned artifact")
    config_raw = json.loads((resolved / "rl_agent_config.json").read_text(encoding="utf-8"))
    if not isinstance(config_raw, dict):
        raise ValueError("Laya model configuration is invalid")
    cfg = cast(dict[str, object], config_raw)
    with contextlib.redirect_stdout(sys.stderr):
        tokenizer_factory = cast(
            _TokenizerFactory, importlib.import_module("transformers").AutoTokenizer
        )
        tokenizer = tokenizer_factory.from_pretrained(
            str(resolved / "tokenizer"), local_files_only=True, trust_remote_code=False
        )
        worker = _load_worker_source()
        worker_handle = cast(
            Callable[[object, dict[str, object]], dict[str, object]], worker._handle
        )
        case_results = [
            _qualify_case(case, tokenizer=tokenizer, cfg=cfg, worker_handle=worker_handle)
            for case in synthetic_cases()
        ]
        boundary_vectors = _qualify_boundary_vectors(tokenizer)
    common_path = Path(cast(str, importlib.import_module("laya.common").__file__)).resolve()
    agent_path = Path(cast(str, importlib.import_module("laya.agent").__file__)).resolve()
    negative_controls = {
        name: all(controls[name] for _result, controls in case_results)
        for name in case_results[0][1]
    }
    status = (
        "pass"
        if all(result["status"] == "pass" for result, _controls in case_results)
        and all(vector["status"] == "pass" for vector in boundary_vectors)
        and all(negative_controls.values())
        else "fail"
    )
    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "synthetic_case_set_version": SYNTHETIC_CASE_SET_VERSION,
        "qualification_scope": "synthetic_serializer_parity_only",
        "status": status,
        "package_version": EXPECTED_PACKAGE_VERSION,
        "model_revision": EXPECTED_MODEL_REVISION,
        "upstream_common_sha256": hashlib.sha256(common_path.read_bytes()).hexdigest(),
        "upstream_agent_sha256": hashlib.sha256(agent_path.read_bytes()).hexdigest(),
        "tokenizer_sha256": hashlib.sha256(
            (resolved / "tokenizer" / "tokenizer.json").read_bytes()
        ).hexdigest(),
        "model_config_sha256": hashlib.sha256(
            (resolved / "rl_agent_config.json").read_bytes()
        ).hexdigest(),
        "case_count": len(case_results),
        "boundary_vector_count": len(boundary_vectors),
        "boundary_vectors": boundary_vectors,
        "question_count": sum(cast(int, result["question_count"]) for result, _ in case_results),
        "negative_controls": negative_controls,
        "cases": [result for result, _controls in case_results],
        "limitations": [
            "Synthetic serializer parity only; no model weights or neural forward pass loaded.",
            "Does not evaluate attention ranking, calibration, diagnosis, privacy, "
            "or training admissibility.",
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-path", type=Path, required=True)
    args = parser.parse_args()
    report = qualify_local_install(args.model_path)
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
