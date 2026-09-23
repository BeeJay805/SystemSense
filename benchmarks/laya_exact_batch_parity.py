"""Offline, non-admitting parity check for one exact Laya worker-boundary batch.

Input must be a separately privacy-reviewed local payload captured at the call to
``agent.predict``. A preworker decision snapshot cannot substitute for it. This
tool does not persist or print model-visible text, load weights, or admit training.
Cached batches fail closed until their original exact payload is durably linked.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib
import json
import os
import re
import sys
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from typing import cast

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from benchmarks import laya_presentation_parity as parity
from benchmarks.laya_presentation_parity import (
    EXPECTED_MODEL_REVISION,
    EXPECTED_PACKAGE_VERSION,
    Tokenizer,
    compare_batches,
    compare_worker_presentation,
    predict_model_batch,
    qualify_local_install,
)

_load_worker_source = parity._load_worker_source  # pyright: ignore[reportPrivateUsage]
_sha256_json = cast(Callable[[object], str], parity._sha256_json)  # pyright: ignore[reportPrivateUsage]
_upstream_model_batch = cast(
    Callable[..., parity.ModelBatch],
    parity._upstream_model_batch,  # pyright: ignore[reportPrivateUsage]
)

SCHEMA_VERSION = 1
EXPECTED_COMMON_SHA256 = "f231d42fcec84da203222fcaa89c083b22776e00341e66e118183d754e1dcabf"
EXPECTED_AGENT_SHA256 = "128567096446c5d39af8e4a3a7c4dd9e32a134a1b099ce5a5eed383beeff1b89"
EXPECTED_TOKENIZER_SHA256 = "6c8aaa9a542084f2457eab775d4eeb51f92a70c0fd9de28d5edb0ddec3c08d30"
EXPECTED_CONFIG_SHA256 = "ebf0cd524d92342a6be5e48e9fca3d7c2babfb5a56ccd79d2171ef5d8c7f7be8"
EXPECTED_WORKER_SHA256 = "4caa8c42d40e385f7bea47009895e4a63fdf2f99ebc68f4fa164a421b269be84"
_PINNED: dict[str, str] = {
    "package_version": EXPECTED_PACKAGE_VERSION,
    "model_revision": EXPECTED_MODEL_REVISION,
    "upstream_common_sha256": EXPECTED_COMMON_SHA256,
    "upstream_agent_sha256": EXPECTED_AGENT_SHA256,
    "tokenizer_sha256": EXPECTED_TOKENIZER_SHA256,
    "model_config_sha256": EXPECTED_CONFIG_SHA256,
    "worker_sha256": EXPECTED_WORKER_SHA256,
}


def _mapping(value: object, name: str) -> dict[str, object]:
    if not isinstance(value, dict):
        raise ValueError(f"{name} is invalid")
    typed = cast(dict[object, object], value)
    if any(not isinstance(key, str) for key in typed):
        raise ValueError(f"{name} is invalid")
    return cast(dict[str, object], typed)


def _digest(value: object, name: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise ValueError(f"{name} is missing or invalid")
    return value


def _trace_sha256(trace: dict[str, object]) -> str:
    raw = json.dumps(
        trace, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _question_rows(value: object) -> tuple[dict[str, dict[str, object]], dict[str, str]]:
    if not isinstance(value, list) or not 1 <= len(cast(list[object], value)) <= 128:
        raise ValueError("exact worker questions unavailable")
    questions: dict[str, dict[str, object]] = {}
    question_to_id: dict[str, str] = {}
    for raw in cast(list[object], value):
        row = _mapping(raw, "exact worker question")
        question_id, item_id = row.get("question_id"), row.get("item_id")
        if (
            not isinstance(question_id, str)
            or not re.fullmatch(r"item_[0-9]+_piece_[0-9]+", question_id)
            or not isinstance(item_id, str)
            or not item_id
            or question_id in questions
        ):
            raise ValueError("exact worker question identity invalid")
        questions[question_id] = _mapping(row.get("question"), "exact worker question")
        question_to_id[question_id] = item_id
    return questions, question_to_id


def verify_exact_batch(
    payload: dict[str, object],
    *,
    tokenizer: Tokenizer,
    cfg: dict[str, object],
    qualification: dict[str, object],
) -> dict[str, object]:
    """Compare exact supplied worker call to installed builder; never admit training.

    The caller must obtain the payload through a separate authenticated privacy
    review. A receipt digest binds the report but is not itself authentication.
    """

    if payload.get("schema_version") != SCHEMA_VERSION:
        raise ValueError("exact worker payload schema unsupported")
    snapshot_id = payload.get("snapshot_id")
    if not isinstance(snapshot_id, str) or not 1 <= len(snapshot_id) <= 256:
        raise ValueError("snapshot identity missing")
    request_sha = _digest(payload.get("request_sha256"), "request digest")
    privacy_sha = _digest(payload.get("privacy_receipt_sha256"), "privacy receipt")
    trace = _mapping(payload.get("trace"), "snapshot trace")
    trace_sha = _digest(payload.get("trace_sha256"), "trace digest")
    if _trace_sha256(trace) != trace_sha:
        raise ValueError("snapshot trace digest mismatch")
    if qualification.get("status") != "pass" or any(
        qualification.get(name) != expected for name, expected in _PINNED.items()
    ):
        raise ValueError("pinned artifact qualification failed")
    trace_payload = _mapping(trace.get("payload"), "snapshot trace payload")
    batches = trace_payload.get("microbatches")
    if not isinstance(batches, list) or not 1 <= len(cast(list[object], batches)) <= 32:
        raise ValueError("snapshot trace batches unavailable")
    phase, batch_index = payload.get("phase"), payload.get("batch_index")
    if phase != "probe" or not isinstance(batch_index, int) or isinstance(batch_index, bool):
        raise ValueError("probe batch identity missing")
    matching: list[dict[str, object]] = []
    for raw in cast(list[object], batches):
        item = _mapping(raw, "snapshot trace batch")
        if item.get("phase") == phase and item.get("batch_index") == batch_index:
            matching.append(item)
    if len(matching) != 1:
        raise ValueError("probe batch trace binding missing")
    batch = matching[0]
    candidate_ids_raw = batch.get("candidate_ids")
    inference_ids_raw = batch.get("inference_ids")
    candidate_ids = (
        cast(list[object], candidate_ids_raw) if isinstance(candidate_ids_raw, list) else None
    )
    inference_ids = (
        cast(list[object], inference_ids_raw) if isinstance(inference_ids_raw, list) else None
    )
    if (
        batch.get("cache_hit_ids") != []
        or batch.get("cached_origins") != []
        or candidate_ids is None
        or inference_ids is None
        or not 1 <= len(candidate_ids) <= 20
        or candidate_ids != inference_ids
        or any(not isinstance(item, str) or not item for item in candidate_ids)
        or len(set(cast(list[str], candidate_ids))) != len(candidate_ids)
    ):
        raise ValueError("cache origin unavailable or batch partition invalid")
    presentation = _mapping(batch.get("worker_presentation"), "worker presentation")
    call = _mapping(payload.get("exact_worker_call"), "exact worker call")
    state = _mapping(call.get("state"), "exact worker state")
    questions, question_to_id = _question_rows(call.get("questions"))
    coverage = _mapping(call.get("state_coverage"), "exact worker coverage")
    if list(dict.fromkeys(question_to_id.values())) != candidate_ids:
        raise ValueError("worker questions do not cover probe batch")
    max_len, head_max_len = cfg.get("max_len"), cfg.get("head_max_len")
    if not isinstance(max_len, int) or not isinstance(head_max_len, int):
        raise ValueError("pinned token limits unavailable")
    worker = _load_worker_source()
    worker_presentation = cast(Callable[..., dict[str, object]], worker._presentation)
    reconstructed = worker_presentation(
        SimpleNamespace(tok=tokenizer, cfg=cfg), state, questions, question_to_id, coverage
    )
    if reconstructed != presentation:
        raise ValueError("worker presentation mismatch")
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
    differences = (
        *compare_batches(predicted, upstream),
        *compare_worker_presentation(predicted, presentation),
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "qualification_scope": "one_exact_worker_batch_serializer_parity_only",
        "status": "pass" if not differences else "fail",
        "trainable": False,
        "privacy_receipt_authenticated": False,
        "snapshot_id": snapshot_id,
        "request_sha256": request_sha,
        "trace_sha256": trace_sha,
        "privacy_receipt_sha256": privacy_sha,
        "phase": phase,
        "batch_index": batch_index,
        "cache_origin_status": "not_applicable",
        "presentation_sha256": presentation["presentation_sha256"],
        "model_input_sha256": _sha256_json(asdict(upstream)),
        "question_count": len(questions),
        "state_truncated_questions": sum(
            detail.state_presented_tokens < detail.state_original_tokens
            for detail in upstream.questions
        ),
        "instruction_truncated_questions": sum(
            detail.instruction_presented_tokens < detail.instruction_original_tokens
            for detail in upstream.questions
        ),
        "mismatched_fields": list(differences),
        "artifact_sha256": {name: qualification[name] for name in _PINNED},
        "limitations": [
            "One supplied batch only; not corpus coverage or training admission.",
            "Supplied trace and snapshot identity are not independently read back from storage.",
            "Privacy receipt identity is bound, not independently authenticated here.",
            "Cached origins and preworker-only inputs are unsupported and rejected.",
        ],
    }


def _local_qualification(
    model_path: Path,
) -> tuple[Tokenizer, dict[str, object], dict[str, object]]:
    qualification = qualify_local_install(model_path)
    worker_path = Path(cast(str, _load_worker_source().__file__))
    qualification["worker_sha256"] = hashlib.sha256(worker_path.read_bytes()).hexdigest()
    resolved = model_path.resolve(strict=True)
    cfg = _mapping(
        json.loads((resolved / "rl_agent_config.json").read_text(encoding="utf-8")), "config"
    )
    tokenizer_factory = importlib.import_module("transformers").AutoTokenizer
    tokenizer = cast(
        Tokenizer,
        tokenizer_factory.from_pretrained(
            str(resolved / "tokenizer"), local_files_only=True, trust_remote_code=False
        ),
    )
    return tokenizer, cfg, qualification


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model-path", type=Path, required=True)
    parser.add_argument("--exact-batch-json", type=Path, required=True)
    args = parser.parse_args()
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    os.environ["CUDA_VISIBLE_DEVICES"] = ""
    try:
        if args.exact_batch_json.stat().st_size > 4 * 1024 * 1024:
            raise ValueError("exact worker payload exceeds local bound")
        payload = _mapping(
            json.loads(args.exact_batch_json.read_text(encoding="utf-8")), "exact worker payload"
        )
        with contextlib.redirect_stdout(sys.stderr):
            tokenizer, cfg, qualification = _local_qualification(args.model_path)
            report = verify_exact_batch(
                payload, tokenizer=tokenizer, cfg=cfg, qualification=qualification
            )
    except (OSError, RuntimeError, TypeError, ValueError, KeyError):
        # Never echo sensitive payload content or library exceptions to stdout/stderr.
        print('{"status":"error","trainable":false,"reason":"parity_input_rejected"}')
        return 2
    print(json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    return 0 if report["status"] == "pass" else 1


if __name__ == "__main__":
    raise SystemExit(main())
