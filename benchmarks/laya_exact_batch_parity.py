"""Offline parity check and optional mixed-frontier CPU forward dry run.

Input must be a separately privacy-reviewed local payload captured at the call to
``agent.predict``. A preworker decision snapshot cannot substitute for it. This
tool does not persist or print model-visible text or admit training. The pilot
dry run loads pinned weights and validates supplied worker receipts before forward.
The pilot path covers evidence, probe and compare phases. The single-batch path
retains its original schema limits. Cached batches require an exact origin.
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import importlib
import json
import math
import os
import re
import sys
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING, cast

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

if TYPE_CHECKING:
    from systemsense.evaluation.frontier_pilot_export import ControlledWorkerFixturePilot

_load_worker_source = parity._load_worker_source  # pyright: ignore[reportPrivateUsage]
_sha256_json = cast(Callable[[object], str], parity._sha256_json)  # pyright: ignore[reportPrivateUsage]
_upstream_model_batch = cast(
    Callable[..., parity.ModelBatch],
    parity._upstream_model_batch,  # pyright: ignore[reportPrivateUsage]
)

SCHEMA_VERSION = 2
EXPECTED_COMMON_SHA256 = "f231d42fcec84da203222fcaa89c083b22776e00341e66e118183d754e1dcabf"
EXPECTED_AGENT_SHA256 = "128567096446c5d39af8e4a3a7c4dd9e32a134a1b099ce5a5eed383beeff1b89"
EXPECTED_TOKENIZER_SHA256 = "6c8aaa9a542084f2457eab775d4eeb51f92a70c0fd9de28d5edb0ddec3c08d30"
EXPECTED_CONFIG_SHA256 = "ebf0cd524d92342a6be5e48e9fca3d7c2babfb5a56ccd79d2171ef5d8c7f7be8"
EXPECTED_WORKER_SHA256 = "0fb9dae9d8b2c3931652662f3572dcbc81f8105df5e2a0c966bd67c82f0c6437"
_PINNED: dict[str, str] = {
    "package_version": EXPECTED_PACKAGE_VERSION,
    "model_revision": EXPECTED_MODEL_REVISION,
    "upstream_common_sha256": EXPECTED_COMMON_SHA256,
    "upstream_agent_sha256": EXPECTED_AGENT_SHA256,
    "tokenizer_sha256": EXPECTED_TOKENIZER_SHA256,
    "model_config_sha256": EXPECTED_CONFIG_SHA256,
    "worker_sha256": EXPECTED_WORKER_SHA256,
}


def _sha_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def dry_run_worker_forward(
    call: dict[str, object],
    *,
    predict: Callable[
        [dict[str, object], dict[str, dict[str, object]]],
        tuple[dict[str, object], dict[str, object] | None, str | None],
    ],
) -> int:
    """Run one exact captured call and check actual collator tensors and finite answers."""

    if call.get("schema_version") != 2 or set(call) != {
        "schema_version",
        "state",
        "questions",
        "state_coverage",
        "model_input",
    }:
        raise ValueError("schema-2 model input capture required")
    state = _mapping(call.get("state"), "exact worker state")
    rows = call.get("questions")
    questions, _ = _question_rows(rows)
    captured = _mapping(call.get("model_input"), "captured model input")
    result, actual, issue = predict(state, questions)
    if issue is not None or actual is None or _sha256_json(actual) != _sha256_json(captured):
        raise ValueError("forward tensor mismatch")
    answers = _mapping(result.get("answers"), "forward answers")
    if set(answers) != set(questions):
        raise ValueError("forward answer invalid")
    for question_id in questions:
        answer = _mapping(answers[question_id], "forward answer")
        value = answer.get("noul")
        if (
            isinstance(value, bool)
            or not isinstance(value, (int, float))
            or not math.isfinite(value)
        ):
            raise ValueError("forward answer invalid")
    return len(questions)


def dry_run_frontier_pilot(
    pilot: ControlledWorkerFixturePilot,
    *,
    tokenizer: Tokenizer,
    cfg: dict[str, object],
    qualification: dict[str, object],
    predict: Callable[
        [dict[str, object], dict[str, dict[str, object]]],
        tuple[dict[str, object], dict[str, object] | None, str | None],
    ],
) -> dict[str, object]:
    """Verify the existing mixed-frontier pilot receipts and forward exact calls."""

    if (
        not 2 <= len(pilot.examples) <= 4
        or pilot.training_admissible is not False
        or pilot.worker_token_parity != "not_verified"
        or qualification.get("status") != "pass"
    ):
        raise ValueError("frontier pilot or local model qualification invalid")
    export_sha = _sha_text(_canonical([asdict(item.fixture) for item in pilot.examples]))
    pilot_sha = _sha_text(
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
                    for item in pilot.examples
                ),
            )
        )
    )
    if pilot_sha != pilot.pilot_sha256:
        raise ValueError("frontier pilot digest mismatch")
    all_digests: list[str] = []
    total_questions = unknown = observed = 0
    for entry in pilot.examples:
        fixture, worker = entry.fixture, entry.worker_receipt
        request = _mapping(json.loads(fixture.request_json), "frontier request")
        response = _mapping(json.loads(fixture.response_json), "frontier response")
        trace = _mapping(response.get("presentation_trace"), "frontier attention")
        trace_batches = trace.get("microbatches")
        if not isinstance(trace_batches, list):
            raise ValueError("frontier attention coverage mismatch")
        trace_rows = cast(list[object], trace_batches)
        if len(trace_rows) != len(worker.batches):
            raise ValueError("frontier attention coverage mismatch")
        if (
            entry.worker_receipt_sha256 != _sha_text(worker.to_json())
            or worker.snapshot_id != fixture.snapshot_id
            or worker.request_sha256 != fixture.request_sha256
            or worker.response_sha256 != fixture.response_sha256
            or worker.packet_receipt_sha256 != fixture.receipt_sha256
            or worker.attention_sha256 != _sha_text(_canonical(trace))
            or fixture.request_sha256 != _sha_text(fixture.request_json)
            or fixture.response_sha256 != _sha_text(fixture.response_json)
            or fixture.receipt_sha256 != _sha_text(fixture.receipt_json)
            or fixture.payload_sha256
            != _sha_text(
                _canonical((fixture.request_json, fixture.response_json, fixture.receipt_json))
            )
            or worker.privacy_review_id != fixture.privacy_review_id
            or worker.consent_id != fixture.consent_id
        ):
            raise ValueError("frontier source or worker digest mismatch")
        pins = dict(worker.artifact_pins)
        if len(pins) != len(worker.artifact_pins) or any(
            pins.get(name) != qualification.get(name)
            for name in (
                "model_weight_sha256",
                "package_wheel_sha256",
                "tokenizer_sha256",
                "model_config_sha256",
                "upstream_common_sha256",
                "upstream_agent_sha256",
                "worker_sha256",
            )
        ):
            raise ValueError("frontier artifact pins mismatch")
        if request.get("model_weight_sha256") != pins["model_weight_sha256"]:
            raise ValueError("frontier model weight binding mismatch")
        item_rows = request.get("items")
        evidence_rows = request.get("evidence_packets")
        if not isinstance(item_rows, list) or not isinstance(evidence_rows, list):
            raise ValueError("frontier request items unavailable")
        item_ids = tuple(
            _mapping(row, "frontier item").get("item_id") for row in cast(list[object], item_rows)
        )
        fragment_ids = tuple(
            _mapping(row, "frontier evidence").get("fragment_id")
            for row in cast(list[object], evidence_rows)
        )
        if (
            any(not isinstance(value, str) or not value for value in (*item_ids, *fragment_ids))
            or len(set(item_ids)) != len(item_ids)
            or len(set(fragment_ids)) != len(fragment_ids)
            or tuple(outcome.item_id for outcome in fixture.item_outcomes) != item_ids
        ):
            raise ValueError("frontier target identity mismatch")
        seen: dict[str, list[str]] = {"evidence": [], "probe": [], "compare": []}
        next_index = {"evidence": 0, "probe": 0, "compare": 0}
        phase_order = {"evidence": 0, "probe": 1, "compare": 2}
        last_phase = 0
        ordered_calls: list[tuple[str, int, str]] = []
        forward_calls: list[tuple[dict[str, object], int]] = []
        for batch, raw_trace in zip(worker.batches, trace_rows, strict=True):
            trace_row = _mapping(raw_trace, "frontier attention batch")
            phase, index = batch.phase, batch.batch_index
            proof = _mapping(trace_row.get("worker_presentation"), "worker presentation")
            if (
                phase_order[phase] < last_phase
                or index != next_index[phase]
                or trace_row.get("phase") != phase
                or trace_row.get("batch_index") != index
                or trace_row.get("candidate_ids") != list(batch.candidate_ids)
                or trace_row.get("inference_ids") != list(batch.candidate_ids)
                or trace_row.get("cache_hit_ids") != []
                or trace_row.get("cached_origins") != []
                or proof.get("presentation_sha256") != batch.presentation_sha256
                or _sha_text(batch.exact_worker_call_json) != batch.exact_worker_call_sha256
            ):
                raise ValueError("frontier worker batch binding mismatch")
            last_phase = phase_order[phase]
            next_index[phase] += 1
            call = _mapping(json.loads(batch.exact_worker_call_json), "exact worker call")
            _questions, question_to_id = _question_rows(call.get("questions"))
            if tuple(dict.fromkeys(question_to_id.values())) != batch.candidate_ids:
                raise ValueError("frontier worker question order mismatch")
            upstream, differences, count = reconstruct_exact_worker_call(
                call, proof, tokenizer=tokenizer, cfg=cfg, qualification=qualification
            )
            captured = _mapping(call.get("model_input"), "captured model input")
            expected = asdict(upstream)
            if differences or any(
                _sha256_json(captured.get(name)) != _sha256_json(expected[name])
                for name in ("input_ids", "attention_mask", "marker_pos", "marker_mask", "qtype")
            ):
                raise ValueError("frontier worker tensor parity mismatch")
            forward_calls.append((call, count))
            all_digests.append(_sha256_json(expected))
            seen[phase].extend(batch.candidate_ids)
            ordered_calls.append((phase, index, batch.exact_worker_call_json))
        if (
            tuple(seen["evidence"]) != fragment_ids
            or tuple(seen["probe"]) != item_ids
            or any(item not in item_ids for item in seen["compare"])
            or worker.reviewed_payload_sha256
            != _sha_text(
                _canonical(
                    (
                        fixture.request_json,
                        fixture.response_json,
                        fixture.receipt_json,
                        trace,
                        tuple(ordered_calls),
                    )
                )
            )
        ):
            raise ValueError("frontier pilot worker coverage or review digest mismatch")
        for outcome in fixture.item_outcomes:
            if outcome.item_id == fixture.selected_item_id and outcome.status != "unrun":
                if outcome.oracle_receipt_sha256 is None or outcome.checked_by is None:
                    raise ValueError("frontier observed outcome lacks oracle receipt")
                observed += 1
            elif (
                outcome.status != "unrun"
                or outcome.utility != "unknown"
                or outcome.oracle_receipt_sha256 is not None
                or outcome.checked_by is not None
            ):
                raise ValueError("unrun frontier alternative has invented label")
            else:
                unknown += 1
        for call, count in forward_calls:
            if dry_run_worker_forward(call, predict=predict) != count:
                raise ValueError("frontier worker forward count mismatch")
            total_questions += count
    return {
        "schema_version": 1,
        "status": "pass",
        "scope": "controlled_mixed_frontier_fixture_forward_only",
        "trainable": False,
        "weight_updates_performed": False,
        "privacy_receipt_authenticated": False,
        "pilot_sha256": pilot.pilot_sha256,
        "forward_batches": len(all_digests),
        "forward_questions": total_questions,
        "observed_selected": observed,
        "unknown_masked": unknown,
        "supervised_pairs": 0,
        "model_input_sha256": all_digests,
        "source_artifact_sha256": {
            name: qualification[name] for name in _PINNED if name in qualification
        },
        "limitations": [
            "Fixture, privacy and consent callback issuers are not authenticated by this file.",
            "Only the selected action has an outcome; unrun alternatives stay unknown.",
            "Fixture forward parity does not establish Windows accuracy or training admission.",
        ],
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


def worker_source_sha256(path: Path) -> str:
    """Pin source semantics across Git LF and Windows CRLF materialization."""

    return hashlib.sha256(path.read_bytes().replace(b"\r\n", b"\n")).hexdigest()


def verify_weight_digest(path: Path, *, expected_sha256: str, expected_bytes: int) -> str:
    """Read and pin the actual local weight bytes before and after the dry run."""

    expected_sha256 = _digest(expected_sha256, "expected weight digest")
    if expected_bytes <= 0 or path.is_symlink() or not path.is_file():
        raise ValueError("weight file invalid")
    actual = hashlib.sha256()
    size = 0
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            size += len(block)
            if size > expected_bytes:
                raise ValueError("weight digest mismatch")
            actual.update(block)
    if size != expected_bytes or actual.hexdigest() != expected_sha256:
        raise ValueError("weight digest mismatch")
    return expected_sha256


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


def reconstruct_exact_worker_call(
    call: dict[str, object],
    presentation: dict[str, object],
    *,
    tokenizer: Tokenizer,
    cfg: dict[str, object],
    qualification: dict[str, object],
) -> tuple[parity.ModelBatch, tuple[str, ...], int]:
    """Rebuild one captured worker invocation; no consent or label is inferred."""

    if qualification.get("status") != "pass" or any(
        qualification.get(name) != expected for name, expected in _PINNED.items()
    ):
        raise ValueError("pinned artifact qualification failed")
    state = _mapping(call.get("state"), "exact worker state")
    questions, question_to_id = _question_rows(call.get("questions"))
    coverage = _mapping(call.get("state_coverage"), "exact worker coverage")
    captured_digest = presentation.get("model_input_sha256")
    if call.get("schema_version") == 2:
        model_input = _mapping(call.get("model_input"), "captured model input")
        encoded = json.dumps(
            model_input, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode("utf-8")
        expected_digest = hashlib.sha256(b"systemsense.laya.model_input.v1\0" + encoded).hexdigest()
        if captured_digest != expected_digest:
            raise ValueError("worker model input digest mismatch")
    elif captured_digest is not None:
        raise ValueError("worker model input digest has no schema-2 capture")
    core_presentation = {
        key: value for key, value in presentation.items() if key != "model_input_sha256"
    }
    max_len, head_max_len = cfg.get("max_len"), cfg.get("head_max_len")
    if not isinstance(max_len, int) or not isinstance(head_max_len, int):
        raise ValueError("pinned token limits unavailable")
    worker = _load_worker_source()
    worker_presentation = cast(Callable[..., dict[str, object]], worker._presentation)
    reconstructed = worker_presentation(
        SimpleNamespace(tok=tokenizer, cfg=cfg), state, questions, question_to_id, coverage
    )
    if reconstructed != core_presentation:
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
        *compare_worker_presentation(predicted, core_presentation),
    )
    return upstream, differences, len(questions)


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

    schema_version = payload.get("schema_version")
    if schema_version not in (1, SCHEMA_VERSION) or type(schema_version) is not int:
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
    trace_payload = _mapping(trace.get("payload"), "snapshot trace payload")
    batches = trace_payload.get("microbatches")
    if not isinstance(batches, list) or not 1 <= len(cast(list[object], batches)) <= 32:
        raise ValueError("snapshot trace batches unavailable")
    phase, batch_index = payload.get("phase"), payload.get("batch_index")
    if (
        phase not in (("probe",) if schema_version == 1 else ("evidence", "probe"))
        or not isinstance(batch_index, int)
        or isinstance(batch_index, bool)
    ):
        raise ValueError("worker batch identity missing")
    matching: list[dict[str, object]] = []
    for raw in cast(list[object], batches):
        item = _mapping(raw, "snapshot trace batch")
        if item.get("phase") == phase and item.get("batch_index") == batch_index:
            matching.append(item)
    if len(matching) != 1:
        raise ValueError("worker batch trace binding missing")
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
    capture_version = call.get("schema_version", 1)
    if type(capture_version) is not int or capture_version not in (1, 2):
        raise ValueError("exact worker capture schema unsupported")
    required_call_fields = {"state", "questions", "state_coverage"}
    if capture_version == 2:
        required_call_fields |= {"schema_version", "model_input"}
    if set(call) != required_call_fields:
        raise ValueError("exact worker capture fields unsupported")
    _questions, question_to_id = _question_rows(call.get("questions"))
    if list(dict.fromkeys(question_to_id.values())) != candidate_ids:
        raise ValueError("worker questions do not cover probe batch")
    upstream, differences, question_count = reconstruct_exact_worker_call(
        call,
        presentation,
        tokenizer=tokenizer,
        cfg=cfg,
        qualification=qualification,
    )
    captured_input: dict[str, object] | None = None
    if capture_version == 2:
        captured_input = _mapping(call.get("model_input"), "captured model input")
        required = ("input_ids", "attention_mask", "marker_pos", "marker_mask", "qtype")
        if set(captured_input) != set(required):
            raise ValueError("captured model input incomplete")
        expected_input = asdict(upstream)
        for field in required:
            actual_json = json.dumps(captured_input[field], separators=(",", ":"))
            expected_json = json.dumps(expected_input[field], separators=(",", ":"))
            if actual_json != expected_json:
                differences = (*differences, f"captured_{field}")
    return {
        "schema_version": schema_version,
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
        "captured_model_input_sha256": (
            _sha256_json(captured_input) if captured_input is not None else None
        ),
        "question_count": question_count,
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
    # Git may materialize CRLF on Windows. Pin the same source text across
    # checkouts while still detecting any substantive worker-code change.
    qualification["worker_sha256"] = worker_source_sha256(worker_path)
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
    inputs = parser.add_mutually_exclusive_group(required=True)
    inputs.add_argument("--exact-batch-json", type=Path)
    inputs.add_argument("--frontier-pilot-json", type=Path)
    args = parser.parse_args()
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    os.environ["CUDA_VISIBLE_DEVICES"] = ""
    try:
        if args.frontier_pilot_json is not None:
            from pydantic import TypeAdapter

            from systemsense.evaluation.frontier_pilot_export import ControlledWorkerFixturePilot
            from systemsense.inference.laya_runtime import LayaRuntimeConfig
            from systemsense.inference.laya_worker import (
                _load_agent,  # pyright: ignore[reportPrivateUsage]
                _predict_with_model_input_capture,  # pyright: ignore[reportPrivateUsage]
            )

            pilot_path = cast(Path, args.frontier_pilot_json)
            if pilot_path.stat().st_size > 16 * 1024 * 1024:
                raise ValueError("frontier pilot exceeds local bound")
            pilot = TypeAdapter(ControlledWorkerFixturePilot).validate_json(pilot_path.read_bytes())
            config = LayaRuntimeConfig(
                interpreter_path=Path(sys.executable).resolve(),
                model_path=args.model_path.resolve(strict=True),
            )
            install = config.validate_install()
            weight_path = config.model_path / "model.safetensors"
            verify_weight_digest(
                weight_path,
                expected_sha256=install.weight_sha256,
                expected_bytes=install.weight_bytes,
            )
            with (
                open(os.devnull, "w", encoding="utf-8") as sink,
                contextlib.redirect_stdout(sink),
                contextlib.redirect_stderr(sink),
            ):
                tokenizer, cfg, qualification = _local_qualification(args.model_path)
                qualification["model_weight_sha256"] = install.weight_sha256
                qualification["package_wheel_sha256"] = install.package_wheel_sha256
                agent, _release = _load_agent(config.model_path, 2, "cpu", 1536, "float32")
                cast(Callable[[], object], agent.model.eval)()  # type: ignore[attr-defined]
                torch = importlib.import_module("torch")
                with cast(
                    Callable[[], contextlib.AbstractContextManager[object]],
                    torch.inference_mode,
                )():
                    report = dry_run_frontier_pilot(
                        pilot,
                        tokenizer=tokenizer,
                        cfg=cfg,
                        qualification=qualification,
                        predict=lambda state, questions: _predict_with_model_input_capture(
                            agent, state, questions
                        ),
                    )
            verify_weight_digest(
                weight_path,
                expected_sha256=install.weight_sha256,
                expected_bytes=install.weight_bytes,
            )
            report["model_weight_sha256"] = install.weight_sha256
            print(json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
            return 0
        if args.exact_batch_json is None:
            raise ValueError("exact batch path missing")
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
