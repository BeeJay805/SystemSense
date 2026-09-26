"""Local-only reconstruction of reviewed Laya evidence and probe worker inputs.

This is a preparation and parity boundary, not training admission. The persisted
export is preworker-only; callers must supply every privacy-reviewed worker call.
No receipt in these JSON files authenticates a reviewer, consent, or a label.
"""

from __future__ import annotations

import hashlib
import importlib
import json
import os
import re
import time
from collections.abc import Callable, Mapping
from copy import deepcopy
from dataclasses import asdict, dataclass
from typing import Any, Literal, cast

from benchmarks.laya_exact_batch_parity import (
    reconstruct_exact_worker_call,
    verify_exact_batch,
)
from benchmarks.laya_presentation_parity import ModelBatch, Tokenizer, predict_model_batch
from systemsense.decision.semantic_packets import SERIALIZER_ID
from systemsense.evaluation.training_admission import (
    TrainingExport,
    training_corpus_sha256,
    verified_export_payloads,
)
from systemsense.inference.laya_runtime import (
    LayaAttentionResult,
    LayaWorkerPresentation,
    _verify_exact_worker_capture,  # pyright: ignore[reportPrivateUsage]
)
from systemsense.storage.decision_snapshots import DecisionSnapshotRepository

SCHEMA_VERSION = 2
_MAX_EXAMPLES = 500
_MAX_BATCHES = 32


@dataclass(frozen=True)
class CapturedExample:
    snapshot_id: str
    request_sha256: str
    candidate_ids: tuple[str, ...]
    batches: tuple[dict[str, object], ...]
    evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class CaptureAuthorization:
    """Caller claims for local capture; this object does not authenticate consent."""

    snapshot_id: str
    request_sha256: str
    privacy_receipt_sha256: str
    reviewed_payload_sha256: str
    local_training_consent: bool
    exact_payload_reviewed: bool


@dataclass(frozen=True)
class ReconstructedBatch:
    """Tensor-ready input with explicit non-admission and ordered target identity."""

    snapshot_id: str
    batch_index: int
    candidate_ids: tuple[str, ...]
    question_to_candidate: tuple[tuple[str, str], ...]
    model_batch: ModelBatch
    model_input_sha256: str
    phase: str = "probe"
    trainable: bool = False


@dataclass(frozen=True)
class ExactFixtureBatch:
    """An opt-in captured worker call, not authenticated corpus custody."""

    snapshot_id: str
    phase: Literal["probe", "compare"]
    batch_index: int
    exact_worker_call: dict[str, object]
    worker_presentation: dict[str, object]


@dataclass(frozen=True)
class SyntheticRehearsalPair:
    """Test-only ranking labels with fixture proofs, never observed outcomes."""

    snapshot_id: str
    phase: Literal["probe", "compare"]
    batch_index: int
    useful_candidate_id: str
    uninformative_candidate_id: str
    positive_fixture_sha256: str
    negative_fixture_sha256: str
    split: Literal["train", "development", "sealed_test"]
    source_group_id: str


EXPECTED_HEAD_REHEARSAL_PINS = {
    "model_weight_sha256": "4fa56de72383a9d3efa9cfa78955733c81b9fc8067a587ca4beb82c78107a24e"
}
EXPECTED_PINNED_MODEL_PARAMETER_SHA256 = (
    "22f0705ee644e1ac16750eecd24582d559df3414e85ad3b733aeae4c12b17042"
)


def _fixture_parameter_sha256(model: Any, torch: Any) -> str:
    digest = hashlib.sha256()
    for name, parameter in model.named_parameters():
        raw = parameter.detach().cpu().contiguous()
        digest.update(name.encode("utf-8"))
        digest.update(str(tuple(raw.shape)).encode("ascii"))
        digest.update(str(raw.dtype).encode("ascii"))
        digest.update(raw.view(torch.uint8).numpy().tobytes())
    return digest.hexdigest()


def rehearse_exact_head_fixture(
    batches: tuple[ExactFixtureBatch, ...],
    pairs: tuple[SyntheticRehearsalPair, ...],
    *,
    tokenizer: Tokenizer,
    cfg: dict[str, object],
    qualification: dict[str, object],
    model: object,
    verify_fixture_proof: Callable[[SyntheticRehearsalPair], bool],
    seed: int,
    model_proof_mode: Literal["pinned_laya", "synthetic_fixture"],
    max_batches: int | None = None,
    resume: dict[str, object] | None = None,
) -> dict[str, object]:
    """Exercise exact Laya tensors and head loss on explicitly fake fixture labels.

    The fake labels are authenticated by the caller only for this test fixture. This
    report never admits training or writes a checkpoint containing model weights.
    """

    if not pairs or any(not verify_fixture_proof(pair) for pair in pairs):
        raise ValueError("authenticated synthetic fixture pair required")
    if any(pair.split == "sealed_test" for pair in pairs):
        raise ValueError("sealed test is not part of the fixture rehearsal")
    if any(pair.split not in ("train", "development") for pair in pairs):
        raise ValueError("fixture split must be train or development")
    group_splits: dict[str, str] = {}
    for pair in pairs:
        if type(pair.source_group_id) is not str or not pair.source_group_id.strip():
            raise ValueError("fixture source group identity required")
        prior_split = group_splits.setdefault(pair.source_group_id, pair.split)
        if prior_split != pair.split:
            raise ValueError("fixture source group leakage across splits")
    if (
        type(seed) is not int
        or type(max_batches) not in (int, type(None))
        or (max_batches is not None and max_batches < 1)
        or qualification.get("status") != "pass"
        or any(
            qualification.get(key) != value for key, value in EXPECTED_HEAD_REHEARSAL_PINS.items()
        )
        or len(batches) != len(pairs)
        or not batches
        or model_proof_mode not in ("pinned_laya", "synthetic_fixture")
    ):
        raise ValueError("pinned fixture rehearsal input invalid")
    prepared: list[tuple[ModelBatch, int, int, str, int]] = []
    input_rows: list[object] = []
    seen: set[tuple[str, str, int]] = set()
    for batch, pair in zip(batches, pairs, strict=True):
        identity = (batch.snapshot_id, batch.phase, batch.batch_index)
        if (
            identity in seen
            or identity != (pair.snapshot_id, pair.phase, pair.batch_index)
            or pair.useful_candidate_id == pair.uninformative_candidate_id
            or any(
                re.fullmatch(r"[0-9a-f]{64}", value) is None
                for value in (pair.positive_fixture_sha256, pair.negative_fixture_sha256)
            )
            or pair.positive_fixture_sha256 == pair.negative_fixture_sha256
        ):
            raise ValueError("fixture pair is not same-batch comparison")
        seen.add(identity)
        call = batch.exact_worker_call
        if call.get("schema_version") != 2:
            raise ValueError("exact captured worker call required")
        raw_questions = call.get("questions")
        if not isinstance(raw_questions, list):
            raise ValueError("exact captured worker questions required")
        questions = [
            _mapping(row, "exact captured worker question")
            for row in cast(list[object], raw_questions)
        ]
        ids = [row.get("item_id") for row in questions]
        if (
            len(ids) != len(set(ids))
            or pair.useful_candidate_id not in ids
            or pair.uninformative_candidate_id not in ids
            or any(
                _mapping(row.get("question"), "question").get("type") != "noul" for row in questions
            )
        ):
            raise ValueError("fixture pair lacks unique noul questions")
        rebuilt, differences, count = reconstruct_exact_worker_call(
            call,
            batch.worker_presentation,
            tokenizer=tokenizer,
            cfg=cfg,
            qualification=qualification,
        )
        captured = _mapping(call.get("model_input"), "captured model input")
        if (
            differences
            or count != len(ids)
            or any(
                json.dumps(captured.get(name), separators=(",", ":"))
                != json.dumps(asdict(rebuilt)[name], separators=(",", ":"))
                for name in ("input_ids", "attention_mask", "marker_pos", "marker_mask", "qtype")
            )
        ):
            raise ValueError("fixture exact worker tensor mismatch")
        if any(
            qtype != 2 or sum(mask) != 2
            for qtype, mask in zip(rebuilt.qtype, rebuilt.marker_mask, strict=True)
        ):
            raise ValueError("fixture requires two-option noul questions")
        prepared.append(
            (
                rebuilt,
                ids.index(pair.useful_candidate_id),
                ids.index(pair.uninformative_candidate_id),
                pair.split,
                len(ids) - 2,
            )
        )
        input_rows.append((identity, call, batch.worker_presentation, asdict(pair)))
    input_sha = hashlib.sha256(
        json.dumps(
            input_rows, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
        ).encode("utf-8")
    ).hexdigest()
    torch = cast(Any, importlib.import_module("torch"))
    if not hasattr(model, "forward") or not hasattr(model, "named_parameters"):
        raise ValueError("pinned Laya model unavailable")
    typed_model = cast(Any, model)
    psutil = cast(Any, importlib.import_module("psutil"))
    process = psutil.Process(os.getpid())
    rss_before = cast(int, process.memory_info().rss)
    invocation_start_ns = time.perf_counter_ns()
    before = _fixture_parameter_sha256(typed_model, torch)
    if model_proof_mode == "pinned_laya" and (
        type(typed_model).__module__ != "laya.common"
        or type(typed_model).__name__ != "DecisionModel"
        or before != EXPECTED_PINNED_MODEL_PARAMETER_SHA256
    ):
        raise ValueError("pinned model proof failed")
    state: dict[str, object] = {
        "input_sha256": input_sha,
        "parameters_sha256": before,
        "seed": seed,
        "model_proof_mode": model_proof_mode,
        "next_batch": 0,
        "train_pairs": 0,
        "train_loss_sum": 0.0,
        "development_pairs": 0,
        "development_hits": 0,
        "unknown_masked": 0,
    }
    if resume is not None:
        if (
            set(resume) != set(state)
            or resume.get("input_sha256") != input_sha
            or resume.get("parameters_sha256") != before
            or resume.get("seed") != seed
            or resume.get("model_proof_mode") != model_proof_mode
            or type(resume.get("next_batch")) is not int
            or not 0 <= cast(int, resume["next_batch"]) <= len(prepared)
        ):
            raise ValueError("fixture resume identity mismatch")
        cursor = cast(int, resume["next_batch"])
        expected = (
            rehearse_exact_head_fixture(
                batches,
                pairs,
                tokenizer=tokenizer,
                cfg=cfg,
                qualification=qualification,
                model=model,
                verify_fixture_proof=verify_fixture_proof,
                seed=seed,
                model_proof_mode=model_proof_mode,
                max_batches=cursor,
            )["checkpoint"]
            if cursor
            else state
        )
        if resume != expected:
            raise ValueError("fixture resume identity mismatch")
        state = dict(resume)
    start = cast(int, state["next_batch"])
    stop = len(prepared) if max_batches is None else min(len(prepared), start + max_batches)
    parameters = cast(list[tuple[str, Any]], list(typed_model.named_parameters()))
    if not parameters:
        raise ValueError("pinned Laya model has no parameters")
    encoder_flags = [
        (parameter, parameter.requires_grad)
        for name, parameter in parameters
        if name.startswith("encoder.")
    ]
    original_gradients = [
        (
            parameter,
            parameter.grad,
            parameter.grad.detach().clone() if parameter.grad is not None else None,
        )
        for _name, parameter in parameters
    ]
    was_training = cast(bool, typed_model.training)
    device = parameters[0][1].device
    cuda = str(device).startswith("cuda")
    if cuda:
        torch.cuda.reset_peak_memory_stats(device)
    try:
        typed_model.eval()
        for parameter, _gradient, _value in original_gradients:
            parameter.grad = None
        for parameter, _flag in encoder_flags:
            parameter.requires_grad_(False)
        for index in range(start, stop):
            batch, useful, negative, split, unknown = prepared[index]
            tensors = (
                torch.tensor(batch.input_ids, dtype=torch.long, device=device),
                torch.tensor(batch.attention_mask, dtype=torch.long, device=device),
                torch.tensor(batch.marker_pos, dtype=torch.long, device=device),
                torch.tensor(batch.marker_mask, dtype=torch.bool, device=device),
                torch.tensor(batch.qtype, dtype=torch.long, device=device),
            )
            logits, _act = typed_model(*tensors, detach_encoder=True)
            if logits.shape[0] != len(batch.question_ids) or logits.shape[1] != 2:
                raise ValueError("fixture Laya head output invalid")
            # Pinned DecisionModel.forward returns raw marker logits.
            scores = logits[:, 1].float() - logits[:, 0].float()
            loss = torch.nn.functional.softplus(scores[negative] - scores[useful])
            if not bool(torch.isfinite(loss).item()):
                raise ValueError("fixture pair loss nonfinite")
            if split == "train":
                if not loss.requires_grad:
                    raise ValueError("fixture head has no trainable gradient")
                loss.backward()
                head_grads = [
                    parameter.grad
                    for name, parameter in parameters
                    if not name.startswith("encoder.") and parameter.requires_grad
                ]
                if not head_grads or not any(gradient is not None for gradient in head_grads):
                    raise ValueError("fixture head gradient absent")
                if any(
                    gradient is not None and not bool(torch.isfinite(gradient).all().item())
                    for gradient in head_grads
                ):
                    raise ValueError("fixture head gradient nonfinite")
                if any(
                    parameter.grad is not None
                    for name, parameter in parameters
                    if name.startswith("encoder.")
                ):
                    raise ValueError("fixture encoder gradient unexpectedly present")
                state["train_pairs"] = cast(int, state["train_pairs"]) + 1
                state["train_loss_sum"] = cast(float, state["train_loss_sum"]) + float(loss.item())
                for parameter, _gradient, _value in original_gradients:
                    parameter.grad = None
            elif split == "development":
                state["development_pairs"] = cast(int, state["development_pairs"]) + 1
                state["development_hits"] = cast(int, state["development_hits"]) + int(
                    bool((scores[useful] > scores[negative]).item())
                )
            state["unknown_masked"] = cast(int, state["unknown_masked"]) + unknown
            state["next_batch"] = index + 1
    finally:
        with torch.no_grad():
            for parameter, gradient, value in original_gradients:
                if gradient is not None and value is not None:
                    gradient.copy_(value)
                parameter.grad = gradient
        for parameter, flag in encoder_flags:
            parameter.requires_grad_(flag)
        typed_model.train(was_training)
    if cuda:
        torch.cuda.synchronize(device)
    cuda_peak_allocated = cast(int, torch.cuda.max_memory_allocated(device)) if cuda else None
    cuda_peak_reserved = cast(int, torch.cuda.max_memory_reserved(device)) if cuda else None
    after = _fixture_parameter_sha256(typed_model, torch)
    if before != after:
        raise ValueError("fixture model parameters changed")
    elapsed_ms = (time.perf_counter_ns() - invocation_start_ns) / 1_000_000
    rss_after = cast(int, process.memory_info().rss)
    dev_pairs = cast(int, state["development_pairs"])
    return {
        "status": "fixture_only",
        "trainable": False,
        "weight_updates_performed": False,
        "train_pairs": state["train_pairs"],
        "train_loss_mean": (
            cast(float, state["train_loss_sum"]) / cast(int, state["train_pairs"])
            if cast(int, state["train_pairs"])
            else None
        ),
        "development_pairs": dev_pairs,
        "synthetic_development_pairwise_win_rate": (
            cast(int, state["development_hits"]) / dev_pairs if dev_pairs else None
        ),
        "model_proof_mode": model_proof_mode,
        "held_out_performance_claim": False,
        "unknown_masked": state["unknown_masked"],
        "parameters_sha256_before": before,
        "parameters_sha256_after": after,
        "elapsed_ms": elapsed_ms,
        "rss_before_bytes": rss_before,
        "rss_after_bytes": rss_after,
        "cuda_peak_allocated_bytes": cuda_peak_allocated,
        "cuda_peak_reserved_bytes": cuda_peak_reserved,
        "seed_role": "resume_identity_only_no_stochastic_fit",
        "checkpoint": state,
    }


@dataclass(frozen=True)
class EphemeralProbeParity:
    """One in-memory probe batch; this is not corpus custody or training admission."""

    candidate_ids: tuple[str, ...]
    model_batch: ModelBatch
    model_input_sha256: str
    trainable: bool = False


class EphemeralWorkerCapture:
    """Opt-in, in-memory callback sink. No plaintext is written or printed here.

    A caller must pass ``callback`` to Laya ``attend``. This does not establish
    user consent or authenticate a privacy reviewer.
    """

    def __init__(self) -> None:
        self._calls: dict[tuple[str, int], tuple[dict[str, object], LayaWorkerPresentation]] = {}
        self._order: list[tuple[str, int]] = []

    def callback(
        self,
        phase: str,
        batch_index: int,
        call: dict[str, object],
        presentation: LayaWorkerPresentation,
    ) -> None:
        if phase not in ("evidence", "probe") or type(batch_index) is not int or batch_index < 0:
            raise ValueError("worker callback identity invalid")
        key = (phase, batch_index)
        if key in self._calls or len(self._calls) >= _MAX_BATCHES:
            raise ValueError("worker callback duplicated or exceeds bound")
        _verify_exact_worker_capture(call, presentation)
        self._calls[key] = (deepcopy(call), presentation)
        self._order.append(key)

    def clear(self) -> None:
        self._calls.clear()
        self._order.clear()


def verify_durable_capture_custody(
    export: TrainingExport,
    *,
    repository: DecisionSnapshotRepository,
    captures: Mapping[str, EphemeralWorkerCapture],
) -> dict[str, object]:
    """Match callback bytes to durable snapshot readback; return hashes only.

    This verifies local continuity, not callback provenance against an untrusted
    caller or independent consent and privacy-review authorization. Captured
    plaintext is cleared on success and failure.
    """

    try:
        verified_export_payloads(export)
        if set(captures) != {example.snapshot_id for example in export.examples}:
            raise ValueError("worker capture incomplete or unmatched")
        reports: list[dict[str, object]] = []
        for example in export.examples:
            matches = tuple(
                item
                for item in repository.snapshots(case_id=example.case_id, limit=500)
                if item.snapshot_id == example.snapshot_id
            )
            if len(matches) != 1:
                raise ValueError("durable decision snapshot unavailable")
            snapshot = matches[0]
            if (
                snapshot.case_id != example.case_id
                or snapshot.request_sha256 != example.request_sha256
                or snapshot.laya_projection_sha256 != example.laya_projection_sha256
                or snapshot.laya_state != example.input.state
                or snapshot.laya_evidence != example.input.evidence
                or snapshot.laya_candidates != example.input.candidates
            ):
                raise ValueError("durable decision projection differs from export")
            readback = snapshot.presentation_trace
            if readback is None or (
                not readback.probe_candidates_complete
                or not readback.evidence_pages_complete
                or not readback.worker_presentations_complete
                or not readback.cache_origins_complete
                or not readback.worker_inference_present
                or readback.trace.format_id != "laya-worker-attention-v2"
            ):
                raise ValueError("durable worker trace incomplete")
            trace = readback.trace
            _verify_projection_binding(
                {"payload": trace.payload}, example.input.evidence, example.input.candidates
            )
            raw_batches = _rows(
                trace.payload.get("microbatches"), "worker trace", maximum=_MAX_BATCHES
            )
            capture = captures[example.snapshot_id]
            expected_keys: set[tuple[str, int]] = set()
            expected_order: list[tuple[str, int]] = []
            phase_ids: dict[str, list[str]] = {"evidence": [], "probe": []}
            next_index = {"evidence": 0, "probe": 0}
            probe_started = False
            digests: list[str] = []
            for raw in raw_batches:
                batch = _mapping(raw, "worker trace batch")
                phase, index = batch.get("phase"), batch.get("batch_index")
                if (
                    not isinstance(phase, str)
                    or phase not in next_index
                    or type(index) is not int
                    or index != next_index[phase]
                    or (phase == "evidence" and probe_started)
                ):
                    raise ValueError("durable worker batch order invalid")
                next_index[phase] += 1
                if phase == "probe":
                    probe_started = True
                key = (phase, index)
                expected_keys.add(key)
                expected_order.append(key)
                if key not in capture._calls:  # pyright: ignore[reportPrivateUsage]
                    raise ValueError("worker callback incomplete")
                call, presentation = capture._calls[key]  # pyright: ignore[reportPrivateUsage]
                candidate_ids = _candidate_ids(batch.get("candidate_ids"))
                if (
                    batch.get("inference_ids") != list(candidate_ids)
                    or batch.get("cache_hit_ids") != []
                    or batch.get("cached_origins") != []
                    or batch.get("worker_presentation") != presentation.model_dump(mode="json")
                ):
                    raise ValueError("worker callback differs from durable trace")
                question_rows = _rows(call.get("questions"), "worker questions", maximum=128)
                seen_ids = tuple(
                    dict.fromkeys(
                        _mapping(row, "worker question").get("item_id") for row in question_rows
                    )
                )
                if seen_ids != candidate_ids:
                    raise ValueError("worker callback candidate coverage mismatch")
                phase_ids[phase].extend(candidate_ids)
                digests.append(
                    hashlib.sha256(
                        json.dumps(
                            call, ensure_ascii=False, separators=(",", ":"), allow_nan=False
                        ).encode("utf-8")
                    ).hexdigest()
                )
            if set(capture._calls) != expected_keys:  # pyright: ignore[reportPrivateUsage]
                raise ValueError("worker callback incomplete or unmatched")
            if capture._order != expected_order:  # pyright: ignore[reportPrivateUsage]
                raise ValueError("worker callback order differs from durable trace")
            if tuple(phase_ids["evidence"]) != tuple(
                item["fragment_id"] for item in example.input.evidence
            ) or tuple(phase_ids["probe"]) != tuple(
                item["probe_id"] for item in example.input.candidates
            ):
                raise ValueError("worker callback coverage differs from export")
            reports.append({"snapshot_id": example.snapshot_id, "callback_sha256": digests})
        return {
            "schema_version": 1,
            "status": "pass",
            "trainable": False,
            "privacy_receipt_authenticated": False,
            "consent_authenticated": False,
            "callback_provenance_authenticated": False,
            "corpus_sha256": training_corpus_sha256(export),
            "snapshots": reports,
        }
    finally:
        for capture in captures.values():
            capture.clear()


def verify_ephemeral_probe_batch(
    attention: LayaAttentionResult,
    *,
    batch_index: int,
    exact_worker_call: dict[str, object],
    worker_presentation: LayaWorkerPresentation,
    tokenizer: Tokenizer,
    cfg: dict[str, object],
    qualification: dict[str, object],
) -> EphemeralProbeParity:
    """Check one opt-in live capture against its actual attention batch in memory."""

    matched = tuple(
        batch
        for batch in attention.microbatches
        if batch.phase == "probe" and batch.batch_index == batch_index
    )
    if len(matched) != 1:
        raise ValueError("probe batch identity missing or duplicated")
    batch = matched[0]
    if (
        batch.cache_hit_ids
        or batch.cached_origins
        or batch.inference_ids != batch.candidate_ids
        or batch.worker_presentation != worker_presentation
    ):
        raise ValueError("live capture does not match an all-inference probe batch")
    rows = _rows(exact_worker_call.get("questions"), "worker questions", maximum=128)
    identities: list[str] = []
    for raw in rows:
        row = _mapping(raw, "worker question")
        item_id = row.get("item_id")
        if not isinstance(item_id, str) or not item_id:
            raise ValueError("worker question identity invalid")
        if item_id not in identities:
            identities.append(item_id)
    if tuple(identities) != batch.candidate_ids:
        raise ValueError("worker question order does not match live candidates")
    model_batch, differences, _question_count = reconstruct_exact_worker_call(
        exact_worker_call,
        worker_presentation.model_dump(mode="json"),
        tokenizer=tokenizer,
        cfg=cfg,
        qualification=qualification,
    )
    if differences:
        raise ValueError("live worker-token parity failed")
    serialized = json.dumps(asdict(model_batch), ensure_ascii=False, separators=(",", ":"))
    return EphemeralProbeParity(
        candidate_ids=batch.candidate_ids,
        model_batch=model_batch,
        model_input_sha256=hashlib.sha256(serialized.encode("utf-8")).hexdigest(),
    )


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


def capture_review_sha256(
    snapshot_id: str,
    request_sha256: str,
    trace: dict[str, object],
    calls: tuple[dict[str, object], ...],
) -> str:
    """Digest the exact plaintext bundle a local reviewer must approve."""

    encoded = json.dumps(
        {
            "snapshot_id": snapshot_id,
            "request_sha256": request_sha256,
            "trace": trace,
            "calls": calls,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def _verify_projection_binding(
    trace: dict[str, object],
    evidence: tuple[dict[str, str], ...],
    candidates: tuple[dict[str, str], ...],
) -> None:
    payload = _mapping(trace.get("payload"), "snapshot trace payload")
    expected_fragments = [
        {
            "fragment_id": item["fragment_id"],
            "description_sha256": hashlib.sha256(item["description"].encode("utf-8")).hexdigest(),
        }
        for item in evidence
    ]
    expected_probes = [
        {
            "probe_id": item["probe_id"],
            "description_sha256": hashlib.sha256(item["description"].encode("utf-8")).hexdigest(),
        }
        for item in candidates
    ]
    if (
        payload.get("evidence_serializer") != SERIALIZER_ID
        or payload.get("ordered_fragments") != expected_fragments
        or payload.get("ordered_probes") != expected_probes
    ):
        raise ValueError("worker trace projection binding mismatch")


def assemble_training_capture_manifest(
    export: TrainingExport,
    *,
    snapshots: tuple[tuple[str, str, dict[str, object], LayaAttentionResult], ...],
    captured_calls: Mapping[tuple[str, str, int], dict[str, object]],
    authorizations: tuple[CaptureAuthorization, ...],
    tokenizer: Tokenizer,
    cfg: dict[str, object],
    qualification: dict[str, object],
) -> dict[str, object]:
    """Assemble a local, non-admitting manifest from complete opt-in worker calls.

    The caller must independently authenticate the consent and plaintext review,
    read snapshots back from storage, and keep this raw result off stdout and Git.
    Cached origins fail closed. V2 records both evidence and probe phases.
    """

    verified_export_payloads(export)
    if (
        not 1 <= len(export.examples) <= _MAX_EXAMPLES
        or len(snapshots) != len(export.examples)
        or len(authorizations) != len(export.examples)
    ):
        raise ValueError("corpus capture incomplete")
    expected_keys: set[tuple[str, str, int]] = set()
    examples: list[dict[str, object]] = []
    for example, (snapshot_id, request_sha, trace, attention), authorization in zip(
        export.examples, snapshots, authorizations, strict=True
    ):
        if (
            snapshot_id != example.snapshot_id
            or request_sha != example.request_sha256
            or authorization.snapshot_id != snapshot_id
            or authorization.request_sha256 != request_sha
        ):
            raise ValueError("snapshot or consent identity mismatch")
        if (
            authorization.local_training_consent is not True
            or authorization.exact_payload_reviewed is not True
        ):
            raise ValueError("capture consent or privacy review incomplete")
        privacy_sha = _digest(authorization.privacy_receipt_sha256, "privacy receipt")
        reviewed_sha = _digest(authorization.reviewed_payload_sha256, "reviewed payload")
        trace_payload = _mapping(trace.get("payload"), "snapshot trace payload")
        _verify_projection_binding(trace, example.input.evidence, example.input.candidates)
        trace_batches = _rows(
            trace_payload.get("microbatches"), "snapshot trace batch", maximum=_MAX_BATCHES
        )
        if trace_batches != [batch.model_dump(mode="json") for batch in attention.microbatches]:
            raise ValueError("snapshot trace differs from actual attention")
        review_calls: list[dict[str, object]] = []
        next_index = {"evidence": 0, "probe": 0}
        probe_started = False
        for raw in trace_batches:
            batch = _mapping(raw, "snapshot trace batch")
            phase = batch.get("phase")
            if (
                not isinstance(phase, str)
                or phase not in next_index
                or (phase == "evidence" and probe_started)
            ):
                raise ValueError("worker phase order invalid")
            if phase == "probe":
                probe_started = True
            if batch.get("cache_hit_ids") or batch.get("cached_origins"):
                raise ValueError("cached origin unsupported")
            index = batch.get("batch_index")
            if type(index) is not int or index != next_index[phase]:
                raise ValueError("worker batch order invalid")
            next_index[phase] += 1
            key = (snapshot_id, phase, index)
            if key not in captured_calls:
                raise ValueError("worker capture incomplete or duplicated")
            review_calls.append(captured_calls[key])
        if reviewed_sha != capture_review_sha256(
            snapshot_id, request_sha, trace, tuple(review_calls)
        ):
            raise ValueError("reviewed capture payload mismatch")
        batch_rows: list[dict[str, object]] = []
        ordered_ids: dict[str, list[str]] = {"evidence": [], "probe": []}
        for raw in trace_batches:
            batch = _mapping(raw, "snapshot trace batch")
            phase, index = batch.get("phase"), batch.get("batch_index")
            if not isinstance(phase, str) or phase not in ordered_ids or type(index) is not int:
                raise ValueError("worker batch identity invalid")
            candidate_ids = _candidate_ids(batch.get("candidate_ids"))
            if (
                batch.get("inference_ids") != list(candidate_ids)
                or batch.get("cache_hit_ids") != []
                or batch.get("cached_origins") != []
                or not isinstance(batch.get("worker_presentation"), dict)
            ):
                raise ValueError("cached origin or worker presentation unavailable")
            key = (snapshot_id, phase, index)
            if key in expected_keys or key not in captured_calls:
                raise ValueError("worker capture incomplete or duplicated")
            expected_keys.add(key)
            payload: dict[str, object] = {
                "schema_version": SCHEMA_VERSION,
                "snapshot_id": snapshot_id,
                "request_sha256": request_sha,
                "privacy_receipt_sha256": privacy_sha,
                "trace": trace,
                "trace_sha256": hashlib.sha256(
                    json.dumps(
                        trace,
                        sort_keys=True,
                        separators=(",", ":"),
                        ensure_ascii=False,
                        allow_nan=False,
                    ).encode("utf-8")
                ).hexdigest(),
                "phase": phase,
                "batch_index": index,
                "candidate_ids": list(candidate_ids),
                "exact_worker_call": captured_calls[key],
            }
            report = verify_exact_batch(
                payload, tokenizer=tokenizer, cfg=cfg, qualification=qualification
            )
            if report.get("status") != "pass" or report.get("trainable") is not False:
                raise ValueError("exact worker batch parity failed")
            batch_rows.append(payload)
            ordered_ids[phase].extend(candidate_ids)
        if (
            not batch_rows
            or tuple(ordered_ids["probe"])
            != tuple(candidate["probe_id"] for candidate in example.input.candidates)
            or tuple(ordered_ids["evidence"])
            != tuple(fragment["fragment_id"] for fragment in example.input.evidence)
        ):
            raise ValueError("worker candidate coverage mismatch")
        examples.append(
            {
                "snapshot_id": snapshot_id,
                "request_sha256": request_sha,
                "reviewed_payload_sha256": reviewed_sha,
                "local_training_consent": True,
                "exact_payload_reviewed": True,
                "batches": batch_rows,
            }
        )
    if set(captured_calls) != expected_keys:
        raise ValueError("worker capture contains unmatched batches")
    manifest: dict[str, object] = {
        "schema_version": SCHEMA_VERSION,
        "corpus_sha256": training_corpus_sha256(export),
        "examples": examples,
    }
    validate_capture_manifest(
        manifest,
        expected_corpus_sha256=cast(str, manifest["corpus_sha256"]),
        expected_examples=tuple(
            (
                example.snapshot_id,
                example.request_sha256,
                tuple(candidate["probe_id"] for candidate in example.input.candidates),
            )
            for example in export.examples
        ),
        expected_evidence=tuple(
            tuple(fragment["fragment_id"] for fragment in example.input.evidence)
            for example in export.examples
        ),
    )
    return manifest


def validate_capture_manifest(
    manifest: dict[str, object],
    *,
    expected_corpus_sha256: str,
    expected_examples: tuple[tuple[str, str, tuple[str, ...]], ...],
    expected_evidence: tuple[tuple[str, ...], ...] | None = None,
) -> tuple[CapturedExample, ...]:
    """Bind all captured worker batches to a complete, ordered reviewed export.

    The caller must derive ``expected_examples`` from a verified TrainingExport.
    This function verifies structural coverage; exact tensors are checked by
    ``reconstruct_training_inputs`` against the pinned installed builder.
    """

    schema_version = manifest.get("schema_version")
    if type(schema_version) is not int or schema_version not in (1, SCHEMA_VERSION):
        raise ValueError("capture schema unsupported")
    if schema_version == SCHEMA_VERSION and (
        expected_evidence is None or len(expected_evidence) != len(expected_examples)
    ):
        raise ValueError("expected evidence coverage unavailable")
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
    for example_index, (raw, (snapshot_id, request_sha, expected_ids)) in enumerate(
        zip(supplied_rows, expected_examples, strict=True)
    ):
        row = _mapping(raw, "corpus capture")
        if row.get("snapshot_id") != snapshot_id or row.get("request_sha256") != request_sha:
            raise ValueError("corpus capture identity mismatch")
        if schema_version == SCHEMA_VERSION and (
            row.get("local_training_consent") is not True
            or row.get("exact_payload_reviewed") is not True
            or "reviewed_payload_sha256" not in row
        ):
            raise ValueError("capture consent or privacy review incomplete")
        if not expected_ids or len(set(expected_ids)) != len(expected_ids):
            raise ValueError("expected candidate order invalid")
        raw_batches = _rows(row.get("batches"), "corpus batch", maximum=_MAX_BATCHES)
        batches: list[dict[str, object]] = []
        ordered_ids: dict[str, list[str]] = {"evidence": [], "probe": []}
        next_index = {"evidence": 0, "probe": 0}
        probe_started = False
        for batch_raw in raw_batches:
            batch = _mapping(batch_raw, "corpus batch")
            phase, index = batch.get("phase"), batch.get("batch_index")
            if (
                batch.get("schema_version") != schema_version
                or batch.get("snapshot_id") != snapshot_id
                or batch.get("request_sha256") != request_sha
                or not isinstance(phase, str)
                or phase not in (("probe",) if schema_version == 1 else ("evidence", "probe"))
                or type(index) is not int
                or index != next_index[phase]
                or (phase == "evidence" and probe_started)
            ):
                raise ValueError("corpus batch identity mismatch")
            next_index[phase] += 1
            if phase == "probe":
                probe_started = True
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
                if trace_batch.get("phase") == phase and trace_batch.get("batch_index") == index
            ]
            if len(matching) != 1 or matching[0].get("candidate_ids") != list(batch_ids):
                raise ValueError("candidate order differs from worker trace")
            ordered_ids[phase].extend(batch_ids)
            batches.append(batch)
        if tuple(ordered_ids["probe"]) != expected_ids:
            raise ValueError("candidate order or coverage mismatch")
        evidence_ids = () if expected_evidence is None else expected_evidence[example_index]
        if schema_version == SCHEMA_VERSION and tuple(ordered_ids["evidence"]) != evidence_ids:
            raise ValueError("evidence order or coverage mismatch")
        if schema_version == 1 and evidence_ids:
            raise ValueError("v1 cannot establish evidence coverage")
        if schema_version == SCHEMA_VERSION:
            traces = tuple(_mapping(batch.get("trace"), "exact worker trace") for batch in batches)
            if any(trace != traces[0] for trace in traces[1:]):
                raise ValueError("worker trace differs across batches")
            trace_payload = _mapping(traces[0].get("payload"), "exact worker trace payload")
            trace_batches = _rows(
                trace_payload.get("microbatches"), "exact worker trace batch", maximum=_MAX_BATCHES
            )
            captured_identity = [
                (batch["phase"], batch["batch_index"], batch["candidate_ids"]) for batch in batches
            ]
            trace_identity = [
                (batch.get("phase"), batch.get("batch_index"), batch.get("candidate_ids"))
                for batch in (_mapping(raw, "exact worker trace batch") for raw in trace_batches)
            ]
            if captured_identity != trace_identity:
                raise ValueError("worker trace batch coverage mismatch")
        if "reviewed_payload_sha256" in row:
            reviewed_sha = _digest(row["reviewed_payload_sha256"], "reviewed payload")
            traces = tuple(_mapping(batch.get("trace"), "exact worker trace") for batch in batches)
            if any(
                trace != traces[0] for trace in traces[1:]
            ) or reviewed_sha != capture_review_sha256(
                snapshot_id,
                request_sha,
                traces[0],
                tuple(
                    _mapping(batch.get("exact_worker_call"), "exact worker call")
                    for batch in batches
                ),
            ):
                raise ValueError("reviewed capture payload mismatch")
        captured.append(
            CapturedExample(snapshot_id, request_sha, expected_ids, tuple(batches), evidence_ids)
        )
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
    expected_evidence: list[tuple[str, ...]] = []
    for example in export.examples:
        ids = tuple(candidate["probe_id"] for candidate in example.input.candidates)
        if tuple(target.probe_id for target in example.targets) != ids:
            raise ValueError("label target order does not match candidates")
        expected.append((example.snapshot_id, example.request_sha256, ids))
        expected_evidence.append(
            tuple(fragment["fragment_id"] for fragment in example.input.evidence)
        )
    captures = validate_capture_manifest(
        manifest,
        expected_corpus_sha256=expected_corpus_sha256,
        expected_examples=tuple(expected),
        expected_evidence=tuple(expected_evidence),
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
    for capture, example in zip(captures, export.examples, strict=True):
        if manifest.get("schema_version") == SCHEMA_VERSION:
            _verify_projection_binding(
                _mapping(capture.batches[0].get("trace"), "exact worker trace"),
                example.input.evidence,
                example.input.candidates,
            )
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
            serialized = json.dumps(
                asdict(model_batch), ensure_ascii=False, separators=(",", ":"), allow_nan=False
            )
            model_input_sha256 = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
            if model_input_sha256 != _digest(
                report.get("model_input_sha256"), "model input digest"
            ):
                raise ValueError("reconstructed model input digest differs from parity result")
            rebuilt.append(
                ReconstructedBatch(
                    snapshot_id=capture.snapshot_id,
                    batch_index=cast(int, batch["batch_index"]),
                    candidate_ids=batch_ids,
                    question_to_candidate=tuple(mapping),
                    model_batch=model_batch,
                    model_input_sha256=model_input_sha256,
                    phase=cast(str, batch["phase"]),
                )
            )
    return tuple(rebuilt)
