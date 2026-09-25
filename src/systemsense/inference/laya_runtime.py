"""Pinned, offline subprocess boundary for the local Laya decision model."""

from __future__ import annotations

import hashlib
import json
import os
import queue
import subprocess
import threading
import time
import uuid
import warnings
from _thread import LockType
from collections import OrderedDict
from collections.abc import Callable
from pathlib import Path
from typing import Any, Literal, Protocol, cast

import psutil
from pydantic import Field, model_validator

from systemsense.domain.evidence import FrozenModel
from systemsense.inference.control import current_cancellation
from systemsense.inference.host_lease import WorkerIdentity
from systemsense.inference.tree_host_lease import TreeCustody

LAYA_PACKAGE_VERSION = "0.3.5"
LAYA_PACKAGE_WHEEL_SHA256 = "4c57f64cbaf893bb5c7b4affddc2bf21a819f55df51941689f11868583be2903"
LAYA_MODEL_REPOSITORY = "convaiinnovations/laya-typed-decisions"
LAYA_MODEL_REVISION = "f9ab0b228f0fc0f14d873dbc99038f135c2da1b2"
LAYA_MODEL_WEIGHT_SHA256 = "4fa56de72383a9d3efa9cfa78955733c81b9fc8067a587ca4beb82c78107a24e"
LAYA_MODEL_WEIGHT_BYTES = 842_609_220
LAYA_PROTOCOL_VERSION = 1
LAYA_COLD_RAM_REQUIRED_BYTES = 5 * 1024**3
_CREATE_SUSPENDED = 0x00000004


LayaFailureCode = Literal[
    "worker_rejected",
    "capture_response_limit",
    "capture_tensor_limit",
    "state_fit_limit",
    "instruction_fit_limit",
    "question_expansion_limit",
    "model_output_invalid",
    "invalid_envelope",
    "invalid_ranking",
    "invalid_scores",
    "invalid_token_provenance",
    "invalid_presentation",
    "invalid_exact_capture",
]


class LayaRuntimeError(RuntimeError):
    """The isolated Laya worker was unavailable or violated its bounded protocol."""

    def __init__(
        self,
        message: str,
        *,
        failure_code: LayaFailureCode | None = None,
        failure_bytes: int | None = None,
    ) -> None:
        super().__init__(message)
        self.failure_code: LayaFailureCode | None = failure_code
        self.failure_bytes = (
            failure_bytes if type(failure_bytes) is int and 0 < failure_bytes <= 262_144 else None
        )


class LayaInstallManifest(FrozenModel):
    schema_version: int = 1
    model_repository: Literal["convaiinnovations/laya-typed-decisions"]
    model_revision: str
    weight_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    weight_bytes: int
    package_version: str
    package_wheel_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    license: Literal["Apache-2.0"]
    torch_version: str
    transformers_version: str
    device_policy: Literal["cpu_only", "cpu_and_cuda"]
    acquired_at: str


class LayaQuestionPresentation(FrozenModel):
    question_id: str = Field(min_length=1, max_length=40)
    item_id: str = Field(min_length=1, max_length=256)
    question_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    instruction_tokens: int = Field(ge=0)
    instruction_presented_tokens: int = Field(ge=0)
    criteria_tokens: int = Field(ge=0)
    criteria_presented_tokens: int = Field(ge=0)
    state_presented_tokens: int = Field(ge=0)

    @model_validator(mode="after")
    def presented_within_original(self) -> LayaQuestionPresentation:
        if (
            self.instruction_presented_tokens > self.instruction_tokens
            or self.criteria_presented_tokens > self.criteria_tokens
        ):
            raise ValueError("Laya presentation token counts are inconsistent")
        return self


class LayaWorkerPresentation(FrozenModel):
    """Hash-only description of one actual fitted worker call."""

    schema_version: Literal[1] = 1
    presentation_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    fitted_state_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    questions_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    model_input_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")
    presented_item_ids: tuple[str, ...] = Field(min_length=1, max_length=20)
    fitted_state_tokens: int = Field(ge=0)
    state_tokens_original: int = Field(ge=0)
    state_fields_omitted: int = Field(ge=0)
    state_list_items_omitted: int = Field(ge=0)
    questions: tuple[LayaQuestionPresentation, ...] = Field(min_length=1, max_length=128)

    @model_validator(mode="after")
    def verify_coverage(self) -> LayaWorkerPresentation:
        if (
            len(set(self.presented_item_ids)) != len(self.presented_item_ids)
            or set(self.presented_item_ids) != {item.item_id for item in self.questions}
            or len({item.question_id for item in self.questions}) != len(self.questions)
            or any(
                item.state_presented_tokens > self.fitted_state_tokens for item in self.questions
            )
        ):
            raise ValueError("Laya worker presentation coverage is inconsistent")
        return self


def _capture_digest(kind: str, value: object) -> str:
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(f"systemsense.laya.{kind}.v1\0".encode() + encoded.encode()).hexdigest()


def _verify_exact_worker_capture(
    call: dict[str, object], presentation: LayaWorkerPresentation
) -> None:
    """Bind an opt-in raw capture to the worker's ordinary hash-only attestation."""

    fields = set(call)
    if fields == {"state", "questions", "state_coverage"}:
        if presentation.model_input_sha256 is not None:
            raise ValueError("exact worker model input digest without a tensor capture")
    elif fields == {"schema_version", "state", "questions", "state_coverage", "model_input"}:
        if call["schema_version"] != 2 or type(call["schema_version"]) is not int:
            raise ValueError("exact worker capture schema invalid")
        _verify_model_input(call["model_input"], len(presentation.questions))
        if (
            presentation.model_input_sha256 is None
            or _capture_digest("model_input", call["model_input"])
            != presentation.model_input_sha256
        ):
            raise ValueError("exact worker model input digest mismatch")
    else:
        raise ValueError("exact worker capture has unexpected fields")
    state, questions, coverage = call["state"], call["questions"], call["state_coverage"]
    if (
        not isinstance(state, dict)
        or not isinstance(questions, list)
        or not isinstance(coverage, dict)
    ):
        raise ValueError("exact worker capture shape invalid")
    state = cast(dict[str, object], state)
    questions = cast(list[object], questions)
    coverage = cast(dict[str, object], coverage)
    if _capture_digest("state", state) != presentation.fitted_state_sha256:
        raise ValueError("exact worker state digest mismatch")
    if _capture_digest("questions", questions) != presentation.questions_sha256:
        raise ValueError("exact worker questions digest mismatch")
    if len(questions) != len(presentation.questions):
        raise ValueError("exact worker question coverage mismatch")
    for raw, attested in zip(questions, presentation.questions, strict=True):
        if not isinstance(raw, dict):
            raise ValueError("exact worker question invalid")
        raw = cast(dict[str, object], raw)
        if set(raw) != {"question_id", "item_id", "question"}:
            raise ValueError("exact worker question invalid")
        if (
            raw["question_id"] != attested.question_id
            or raw["item_id"] != attested.item_id
            or _capture_digest("question", raw["question"]) != attested.question_sha256
        ):
            raise ValueError("exact worker question digest mismatch")
    for key, expected in (
        ("state_tokens_original", presentation.state_tokens_original),
        ("state_fields_omitted", presentation.state_fields_omitted),
        ("state_list_items_omitted", presentation.state_list_items_omitted),
    ):
        if coverage.get(key) != expected:
            raise ValueError("exact worker coverage mismatch")


def _verify_model_input(value: object, question_count: int) -> None:
    """Validate bounded tensor shape; installed-builder parity is a separate gate."""

    if not isinstance(value, dict) or set(cast(dict[object, object], value)) != {
        "input_ids",
        "attention_mask",
        "marker_pos",
        "marker_mask",
        "qtype",
    }:
        raise ValueError("exact worker model input invalid")
    model_input = cast(dict[str, object], value)
    if len(json.dumps(model_input, separators=(",", ":")).encode()) > 128_000:
        raise ValueError("exact worker model input exceeds bound")
    rows: dict[str, list[list[object]]] = {}
    for name in ("input_ids", "attention_mask", "marker_pos", "marker_mask"):
        raw = model_input[name]
        if not isinstance(raw, list):
            raise ValueError("exact worker model input rows invalid")
        raw_rows = cast(list[object], raw)
        if len(raw_rows) != question_count or any(not isinstance(row, list) for row in raw_rows):
            raise ValueError("exact worker model input rows invalid")
        rows[name] = cast(list[list[object]], raw_rows)
    qtype = model_input["qtype"]
    if not isinstance(qtype, list) or qtype != [2] * question_count:
        raise ValueError("exact worker model input question type invalid")
    for index in range(question_count):
        ids = rows["input_ids"][index]
        mask = rows["attention_mask"][index]
        markers = rows["marker_pos"][index]
        marker_mask = rows["marker_mask"][index]
        if (
            not 1 <= len(ids) <= 8192
            or len(mask) != len(ids)
            or not 1 <= len(markers) <= 32
            or len(marker_mask) != len(markers)
            or any(type(cell) is not int or cell < 0 for cell in ids)
            or any(type(cell) is not int or cell not in (0, 1) for cell in mask)
            or any(type(cell) is not int or cell < 0 or cell >= len(ids) for cell in markers)
            or any(type(cell) is not bool for cell in marker_mask)
        ):
            raise ValueError("exact worker model input shape invalid")


class LayaCachedOrigin(FrozenModel):
    item_id: str = Field(min_length=1, max_length=256)
    presentation_sha256: str | None = Field(default=None, pattern=r"^[0-9a-f]{64}$")


class LayaAttentionMicrobatch(FrozenModel):
    phase: Literal["evidence", "probe", "compare"]
    batch_index: int = Field(ge=0)
    candidate_ids: tuple[str, ...] = Field(min_length=1, max_length=20)
    inference_ids: tuple[str, ...] = Field(default=(), max_length=20)
    cache_hit_ids: tuple[str, ...] = Field(default=(), max_length=20)
    cached_origins: tuple[LayaCachedOrigin, ...] = Field(default=(), max_length=20)
    worker_presentation: LayaWorkerPresentation | None = None

    @model_validator(mode="after")
    def verify_partition(self) -> LayaAttentionMicrobatch:
        if (
            len(set(self.candidate_ids)) != len(self.candidate_ids)
            or set(self.inference_ids) & set(self.cache_hit_ids)
            or set(self.inference_ids) | set(self.cache_hit_ids) != set(self.candidate_ids)
            or tuple(item.item_id for item in self.cached_origins) != self.cache_hit_ids
            or (
                self.worker_presentation is not None
                and tuple(self.worker_presentation.presented_item_ids) != self.inference_ids
            )
        ):
            raise ValueError("Laya microbatch inference/cache partition is inconsistent")
        return self


class LayaAttentionResult(FrozenModel):
    """Ordinal attention over caller-owned IDs, with explicit coverage metadata."""

    ranked_probe_ids: tuple[str, ...] = ()
    ranked_evidence_ids: tuple[str, ...] = ()
    considered_probe_ids: tuple[str, ...] = ()
    considered_evidence_ids: tuple[str, ...] = ()
    ranked_attention_page_ids: tuple[str, ...] = ()
    considered_attention_page_ids: tuple[str, ...] = ()
    attention_notes: tuple[str, ...] = ()
    microbatches: tuple[LayaAttentionMicrobatch, ...] = ()


class LayaRuntimeConfig(FrozenModel):
    """Paths and limits for a separately installed Laya runtime."""

    interpreter_path: Path
    model_path: Path
    device: Literal["cpu", "cuda"] = "cpu"
    precision: Literal["float32", "float16"] = "float32"
    cuda_device_index: int = Field(default=0, ge=0, le=15)
    min_free_vram_mb: int = Field(default=1536, ge=1024, le=16_384)
    threads: int = Field(default=2, ge=1, le=4)
    max_request_bytes: int = Field(default=262_144, ge=4096, le=1_048_576)
    max_response_bytes: int = Field(default=196_608, ge=1024, le=262_144)
    max_candidates_per_batch: int = Field(default=20, ge=1, le=20)

    def model_post_init(self, _context: object) -> None:
        if not self.interpreter_path.is_absolute() or not self.model_path.is_absolute():
            raise ValueError("Laya interpreter and model paths must be absolute")
        if self.device != "cuda" and self.precision != "float32":
            raise ValueError("reduced Laya precision is admitted only for CUDA")

    def validate_install(self) -> LayaInstallManifest:
        required = (
            self.interpreter_path,
            self.model_path / "model.safetensors",
            self.model_path / "rl_agent_config.json",
            self.model_path / "tokenizer",
            self.model_path / "encoder",
        )
        if any(not path.exists() for path in required):
            raise LayaRuntimeError("Laya local install is incomplete")
        manifest_path = self.model_path / "INSTALL-MANIFEST.json"
        try:
            raw = cast(object, json.loads(manifest_path.read_text(encoding="utf-8")))
            manifest = LayaInstallManifest.model_validate(raw)
        except (OSError, json.JSONDecodeError, ValueError) as error:
            raise LayaRuntimeError("Laya pinned manifest is missing or invalid") from error
        if (
            manifest.model_revision != LAYA_MODEL_REVISION
            or manifest.weight_sha256 != LAYA_MODEL_WEIGHT_SHA256
            or manifest.weight_bytes != LAYA_MODEL_WEIGHT_BYTES
            or manifest.package_version != LAYA_PACKAGE_VERSION
            or manifest.package_wheel_sha256 != LAYA_PACKAGE_WHEEL_SHA256
        ):
            raise LayaRuntimeError("Laya pinned manifest does not match the admitted artifact")
        if self.device == "cuda" and manifest.device_policy != "cpu_and_cuda":
            raise LayaRuntimeError("Laya install is not admitted for CUDA execution")
        return manifest


class _BinaryInput(Protocol):
    def write(self, payload: bytes) -> int: ...

    def flush(self) -> None: ...

    def close(self) -> None: ...


class _BinaryOutput(Protocol):
    def readline(self, limit: int = -1) -> bytes: ...


class _Process(Protocol):
    @property
    def pid(self) -> int: ...

    @property
    def stdin(self) -> _BinaryInput | None: ...

    @property
    def stdout(self) -> _BinaryOutput | None: ...

    @property
    def returncode(self) -> int | None: ...

    def poll(self) -> int | None: ...

    def terminate(self) -> None: ...

    def wait(self, timeout: float | None = None) -> int: ...

    def kill(self) -> None: ...


type PopenFactory = Callable[..., _Process]


class _WorkerJob(Protocol):
    def assign_suspended(self, worker: Any) -> None: ...

    def resume_assigned(self, worker: Any) -> None: ...

    def is_assigned_worker(self, worker: Any) -> bool: ...

    def wait_until_empty(self, timeout_seconds: float) -> bool: ...

    def terminate_processes(self) -> None: ...

    def close(self) -> None: ...


def _new_worker_job() -> _WorkerJob:
    from systemsense.orchestration.windows_probe_job import WindowsProbeJob

    return cast(_WorkerJob, WindowsProbeJob())


class LayaSubprocessRuntime:
    """Keep one warm worker and exchange bounded JSON-lines messages with it."""

    def __init__(
        self,
        config: LayaRuntimeConfig,
        *,
        popen_factory: PopenFactory | None = None,
        available_ram_reader: Callable[[], int | None] | None = None,
        process_identity_reader: Callable[[int], float] | None = None,
        startup_admission: Callable[[int, float], bool] | None = None,
        call_admission: Callable[[int, float], bool] | None = None,
        tree_custody_enabled: bool = False,
        job_factory: Callable[[], _WorkerJob] = _new_worker_job,
    ) -> None:
        if tree_custody_enabled and startup_admission is None:
            raise ValueError("tree custody requires startup admission")
        if tree_custody_enabled and os.name != "nt":
            raise ValueError("Windows Job custody requires Windows")
        self._config = config
        self._using_real_subprocess = popen_factory is None
        self._popen_factory = popen_factory or cast(PopenFactory, subprocess.Popen)
        self._available_ram_reader = available_ram_reader or _available_system_ram
        self._process_identity_reader = process_identity_reader or _process_created_at
        # In managed mode this callback must durably reserve the exact PID and
        # creation identity before returning True. Denial never sends a load token.
        self._startup_admission = startup_admission
        self._call_admission = call_admission
        self._tree_custody_enabled = tree_custody_enabled
        self._job_factory = job_factory
        self._job: _WorkerJob | None = None
        self._tree_custody: TreeCustody | None = None
        self._gated_startup = (
            self._using_real_subprocess
            or startup_admission is not None
            or call_admission is not None
        )
        self._process: _Process | None = None
        self._admitted_process: _Process | None = None
        self._owned_identity: tuple[int, float] | None = None
        self._retirement_pending = False
        self._responses: queue.Queue[bytes] = queue.Queue(maxsize=2)
        self._reader: threading.Thread | None = None
        self._active_write: tuple[_BinaryInput, threading.Event] | None = None
        self._lock = threading.Lock()
        self._attention_lock = threading.Lock()
        self._startup_guard = threading.Lock()
        self._startup: tuple[threading.Event, threading.Event, list[Exception]] | None = None
        self._last_relevance_scores: dict[str, float] = {}
        self._last_token_provenance: dict[str, int | bool] = {}
        self._last_worker_presentation: LayaWorkerPresentation | None = None
        self._timing_samples: list[dict[str, int]] = []
        self._score_cache: OrderedDict[str, tuple[float, str | None]] = OrderedDict()
        self._score_cache_limit = 4096

    @property
    def tree_custody(self) -> TreeCustody | None:
        return self._tree_custody

    def timing_samples(self) -> tuple[dict[str, int], ...]:
        """Return bounded opt-in timings; no case or model-visible content."""

        with self._lock:
            return tuple(dict(sample) for sample in self._timing_samples)

    def release_tree_custody(self) -> None:
        """Close an empty Job only after the caller has reconciled its lease."""

        with self._lock:
            job = self._job
            if job is None:
                return
            try:
                if not job.wait_until_empty(0):
                    raise LayaRuntimeError("Laya Job tree is not empty")
                job.close()
            except (OSError, RuntimeError, ValueError) as error:
                raise LayaRuntimeError("Laya Job custody could not be released") from error
            self._job = None
            self._tree_custody = None

    def prewarm(self, *, timeout_seconds: float) -> None:
        """Prove the pinned worker can answer before it receives a live case."""

        self.rank(
            state={"attention_kind": "probe_relevance", "symptom": "worker readiness"},
            candidates=(
                {"probe_id": "core.system", "description": "Read-only registered system snapshot"},
            ),
            timeout_seconds=timeout_seconds,
        )

    def rank(
        self,
        *,
        state: dict[str, object],
        candidates: tuple[dict[str, str], ...],
        timeout_seconds: float,
        capture_exact_worker_call: Callable[[dict[str, object], LayaWorkerPresentation], None]
        | None = None,
        capture_model_input: bool = False,
    ) -> tuple[str, ...]:
        profile_timing = os.environ.get("SYSTEMSENSE_PROFILE_TIMING") == "1"
        call_started_ns = time.perf_counter_ns() if profile_timing else 0
        deadline = time.monotonic() + timeout_seconds
        if timeout_seconds <= 0:
            raise LayaRuntimeError("Laya request deadline has expired")
        if not candidates or len(candidates) > self._config.max_candidates_per_batch:
            raise LayaRuntimeError("Laya candidate batch exceeds its bounded size")
        if capture_model_input and capture_exact_worker_call is None:
            raise LayaRuntimeError("model input capture requires an exact worker callback")
        probe_ids = tuple(candidate.get("probe_id", "") for candidate in candidates)
        if any(not probe_id for probe_id in probe_ids) or len(probe_ids) != len(set(probe_ids)):
            raise LayaRuntimeError("Laya candidates must have unique stable probe IDs")
        request_id = uuid.uuid4().hex
        request: dict[str, object] = {
            "protocol_version": LAYA_PROTOCOL_VERSION,
            "request_id": request_id,
            "state": state,
            "candidates": candidates,
        }
        if capture_exact_worker_call is not None:
            request["capture_exact_worker_call"] = True
        if capture_model_input:
            request["capture_model_input"] = True
        if profile_timing:
            request["profile_timing"] = True
        payload = (
            json.dumps(
                request,
                ensure_ascii=False,
                separators=(",", ":"),
            ).encode("utf-8")
            + b"\n"
        )
        if len(payload) > self._config.max_request_bytes:
            raise LayaRuntimeError("Laya request exceeds the configured byte limit")

        cancellation = current_cancellation()
        queue_started_ns = time.perf_counter_ns() if profile_timing else 0
        _acquire_until(
            self._lock, deadline, cancellation, "Laya request deadline expired waiting for worker"
        )
        acquired_ns = time.perf_counter_ns() if profile_timing else 0
        captured: tuple[dict[str, object], LayaWorkerPresentation] | None = None
        admission_finished_ns = 0
        request_sent_ns = 0
        response_received_ns = 0
        validated_ns = 0
        worker_timing: dict[str, int] | None = None
        try:
            process = self._ready_process(deadline, cancellation)
            if self._call_admission is not None:
                self._admit_rank_call(process, deadline, cancellation)
            admission_finished_ns = time.perf_counter_ns() if profile_timing else 0
            if process.stdin is None:
                self._discard_process()
                raise LayaRuntimeError("Laya worker stdin is unavailable")
            try:
                if deadline - time.monotonic() <= 0:
                    raise queue.Empty
                self._write_request(process.stdin, payload, deadline, cancellation)
                request_sent_ns = time.perf_counter_ns() if profile_timing else 0
                while True:
                    if cancellation is not None and cancellation.is_set():
                        self._discard_process()
                        raise LayaRuntimeError("Laya worker request was cancelled")
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise queue.Empty
                    try:
                        response_bytes = self._responses.get(timeout=min(0.1, remaining))
                        response_received_ns = time.perf_counter_ns() if profile_timing else 0
                        break
                    except queue.Empty:
                        continue
            except LayaRuntimeError:
                raise
            except (BrokenPipeError, OSError, queue.Empty) as error:
                self._discard_process()
                raise LayaRuntimeError("Laya worker exceeded its request deadline") from error
            if not response_bytes or len(response_bytes) > self._config.max_response_bytes:
                self._discard_process()
                raise LayaRuntimeError("Laya worker returned an invalid response")
            validation_stage: LayaFailureCode = "invalid_envelope"
            try:
                decoded = cast(object, json.loads(response_bytes))
                if not isinstance(decoded, dict):
                    raise ValueError
                response = cast(dict[str, object], decoded)
                if response.get("protocol_version") != LAYA_PROTOCOL_VERSION:
                    raise ValueError
                if response.get("request_id") != request_id:
                    raise ValueError
                if response.get("error") is not None:
                    reported_code = response.get("error_code")
                    allowed_rejections: dict[str, LayaFailureCode] = {
                        "capture_response_limit": "capture_response_limit",
                        "capture_tensor_limit": "capture_tensor_limit",
                        "state_fit_limit": "state_fit_limit",
                        "instruction_fit_limit": "instruction_fit_limit",
                        "question_expansion_limit": "question_expansion_limit",
                        "model_output_invalid": "model_output_invalid",
                    }
                    rejection_code: LayaFailureCode = (
                        allowed_rejections.get(reported_code, "worker_rejected")
                        if isinstance(reported_code, str)
                        else "worker_rejected"
                    )
                    size_field = (
                        "tensor_bytes"
                        if rejection_code == "capture_tensor_limit"
                        else "response_bytes"
                        if rejection_code == "capture_response_limit"
                        else None
                    )
                    failure_bytes = response.get(size_field) if size_field is not None else None
                    # A correctly correlated, fixed-code input-fit rejection
                    # invalidates this request, not the healthy warm worker.
                    if rejection_code not in {
                        "state_fit_limit",
                        "instruction_fit_limit",
                        "question_expansion_limit",
                    }:
                        self._discard_process()
                    raise LayaRuntimeError(
                        "Laya worker rejected its bounded request",
                        failure_code=rejection_code,
                        failure_bytes=failure_bytes if type(failure_bytes) is int else None,
                    )
                validation_stage = "invalid_ranking"
                ranked_raw = response.get("ranked_probe_ids")
                if not isinstance(ranked_raw, list):
                    raise ValueError
                ranked_items = cast(list[object], ranked_raw)
                if not all(isinstance(item, str) for item in ranked_items):
                    raise ValueError
                ranked = tuple(cast(str, item) for item in ranked_items)
                if len(ranked) != len(probe_ids) or set(ranked) != set(probe_ids):
                    raise ValueError
                validation_stage = "invalid_scores"
                scores_raw = response.get("relevance_scores")
                if scores_raw is None:
                    count = len(ranked)
                    scores = {
                        probe_id: (count - position) / count
                        for position, probe_id in enumerate(ranked)
                    }
                else:
                    if not isinstance(scores_raw, dict):
                        raise ValueError
                    score_items = cast(dict[object, object], scores_raw)
                    if set(score_items) != set(probe_ids):
                        raise ValueError
                    scores = {}
                    for probe_id, value in score_items.items():
                        if not isinstance(probe_id, str) or not isinstance(value, (int, float)):
                            raise ValueError
                        score = float(value)
                        if not 0 <= score <= 1:
                            raise ValueError
                        scores[probe_id] = score
                validation_stage = "invalid_token_provenance"
                provenance_raw = response.get("token_provenance")
                provenance: dict[str, int | bool] = {}
                if provenance_raw is not None:
                    if not isinstance(provenance_raw, dict):
                        raise ValueError
                    for key, value in cast(dict[object, object], provenance_raw).items():
                        if not isinstance(key, str) or not isinstance(value, (int, bool)):
                            raise ValueError
                        provenance[key] = value
                validation_stage = "invalid_presentation"
                presentation_raw = response.get("presentation")
                presentation = (
                    LayaWorkerPresentation.model_validate(presentation_raw)
                    if presentation_raw is not None
                    else None
                )
                if presentation is not None and presentation.presented_item_ids != probe_ids:
                    raise ValueError
                capture_status = response.get("capture_status")
                if capture_exact_worker_call is None:
                    if capture_status is not None:
                        raise ValueError
                elif capture_status not in (None, "complete", "response_limit", "tensor_limit"):
                    raise ValueError
                if capture_status == "tensor_limit" and not capture_model_input:
                    raise ValueError
                expected_input_digest = capture_model_input and capture_status != "tensor_limit"
                if presentation is not None and (
                    (presentation.model_input_sha256 is not None) != expected_input_digest
                ):
                    raise ValueError
                validation_stage = "invalid_exact_capture"
                exact_raw = response.get("exact_worker_call")
                if capture_exact_worker_call is None:
                    if exact_raw is not None:
                        raise ValueError
                elif capture_status in ("response_limit", "tensor_limit"):
                    if presentation is None or exact_raw is not None:
                        raise ValueError
                else:
                    if presentation is None or not isinstance(exact_raw, dict):
                        raise ValueError
                    exact = cast(dict[str, object], exact_raw)
                    _verify_exact_worker_capture(exact, presentation)
                    captured = (exact, presentation)
                if profile_timing:
                    timing_raw = response.get("timing_ns")
                    if isinstance(timing_raw, dict):
                        typed_timing = cast(dict[str, object], timing_raw)
                        expected = (
                            "tokenization_input_ns",
                            "model_forward_ns",
                            "response_presentation_ns",
                        )

                        def valid_timing(value: object) -> bool:
                            return (
                                isinstance(value, int)
                                and not isinstance(value, bool)
                                and value >= 0
                            )

                        if set(typed_timing) == set(expected) and all(
                            valid_timing(typed_timing[key]) for key in expected
                        ):
                            worker_timing = {key: cast(int, typed_timing[key]) for key in expected}
            except (UnicodeDecodeError, json.JSONDecodeError, TypeError, ValueError) as error:
                self._discard_process()
                raise LayaRuntimeError(
                    "Laya worker returned an invalid ranking", failure_code=validation_stage
                ) from error
            self._last_relevance_scores = scores
            self._last_token_provenance = provenance
            self._last_worker_presentation = presentation
            validated_ns = time.perf_counter_ns() if profile_timing else 0
        finally:
            if profile_timing:
                completed_ns = time.perf_counter_ns()
                sample = {
                    "candidate_count": len(probe_ids),
                    "completed": int(validated_ns > 0),
                    "worker_timing_valid": int(worker_timing is not None),
                    "request_setup_ns": max(0, queue_started_ns - call_started_ns),
                    "queue_wait_ns": max(0, acquired_ns - queue_started_ns),
                    "worker_admission_ns": max(0, admission_finished_ns - acquired_ns),
                    "request_write_ns": max(0, request_sent_ns - admission_finished_ns),
                    "worker_roundtrip_ns": max(0, response_received_ns - request_sent_ns),
                    "response_validation_ns": max(0, validated_ns - response_received_ns),
                    "total_ns": max(0, completed_ns - call_started_ns),
                    **(worker_timing or {}),
                }
                self._timing_samples.append(sample)
                del self._timing_samples[:-256]
            self._lock.release()
        # The only raw-content handoff is an explicit local caller callback,
        # outside the worker lock. It is never kept in runtime state.
        if capture_exact_worker_call is not None and captured is not None:
            try:
                capture_exact_worker_call(*captured)
            except (MemoryError, RecursionError, TypeError, ValueError, OSError) as error:
                warnings.warn(
                    f"Optional Laya capture was not recorded: {type(error).__name__}",
                    RuntimeWarning,
                    stacklevel=2,
                )
        return ranked

    def _write_request(
        self,
        pipe: _BinaryInput,
        payload: bytes,
        deadline: float,
        cancellation: threading.Event | None,
    ) -> None:
        """Bound a pipe write even when the worker is not yet reading its input."""

        sent = threading.Event()
        errors: list[Exception] = []

        def write() -> None:
            try:
                pipe.write(payload)
                pipe.flush()
            except Exception as error:
                errors.append(error)
            finally:
                sent.set()

        self._active_write = (pipe, sent)
        threading.Thread(target=write, daemon=True).start()
        while not sent.is_set():
            if cancellation is not None and cancellation.is_set():
                self._discard_process()
                raise LayaRuntimeError("Laya worker request was cancelled")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise queue.Empty
            sent.wait(timeout=min(0.02, remaining))
        self._active_write = None
        if errors:
            self._discard_process()
            raise LayaRuntimeError("Laya worker request write failed") from errors[0]
        if deadline - time.monotonic() <= 0:
            raise queue.Empty

    def attend(
        self,
        *,
        state: dict[str, object],
        evidence: tuple[dict[str, str], ...],
        candidates: tuple[dict[str, str], ...],
        timeout_seconds: float,
        capture_exact_worker_call: Callable[
            [str, int, dict[str, object], LayaWorkerPresentation], None
        ]
        | None = None,
        capture_model_input: bool = False,
    ) -> LayaAttentionResult:
        """Rank bounded batches; raw worker capture is opt-in and never persisted here."""

        deadline = time.monotonic() + timeout_seconds
        _acquire_until(
            self._attention_lock,
            deadline,
            current_cancellation(),
            "Laya attention deadline expired waiting for worker",
        )
        try:
            return self._attend_locked(
                state=state,
                evidence=evidence,
                candidates=candidates,
                timeout_seconds=_remaining_seconds(deadline),
                capture_exact_worker_call=capture_exact_worker_call,
                capture_model_input=capture_model_input,
            )
        finally:
            self._attention_lock.release()

    def _attend_locked(
        self,
        *,
        state: dict[str, object],
        evidence: tuple[dict[str, str], ...],
        candidates: tuple[dict[str, str], ...],
        timeout_seconds: float,
        capture_exact_worker_call: Callable[
            [str, int, dict[str, object], LayaWorkerPresentation], None
        ]
        | None = None,
        capture_model_input: bool = False,
    ) -> LayaAttentionResult:
        """Rank within batches, then compare their finalists on one bounded menu."""

        deadline = time.monotonic() + timeout_seconds
        evidence_deadline = time.monotonic() + timeout_seconds * (0.7 if candidates else 0.9)
        ranked_fragment_batches: list[tuple[str, ...]] = []
        fragment_scores: dict[str, float] = {}
        fragment_details: dict[str, dict[str, str]] = {}
        considered_evidence: list[str] = []
        considered_pages: list[str] = []
        page_fragment_totals: dict[str, int] = {}
        page_fragment_considered: dict[str, int] = {}
        cache_hits = 0
        cache_misses = 0
        token_reports: list[dict[str, int | bool]] = []
        microbatches: list[LayaAttentionMicrobatch] = []
        last_batch_seconds = 0.0
        coverage_limited = False
        evidence_batches_completed = 0
        evidence_state = {**state, "attention_kind": "evidence_relevance"}
        for item in evidence:
            page_id = item.get("page_id", item.get("evidence_id", ""))
            page_fragment_totals[page_id] = page_fragment_totals.get(page_id, 0) + 1
        for batch_index, batch in enumerate(
            _chunks(evidence, self._config.max_candidates_per_batch)
        ):
            remaining_evidence = evidence_deadline - time.monotonic()
            if remaining_evidence <= max(0.1, last_batch_seconds * 1.25):
                coverage_limited = True
                break
            fragment_to_evidence: dict[str, str] = {}
            fragment_to_page: dict[str, str] = {}
            rank_items: list[dict[str, str]] = []
            batch_scores: dict[str, float] = {}
            cache_origins: list[LayaCachedOrigin] = []
            for item in batch:
                evidence_id = item.get("evidence_id", "")
                page_id = item.get("page_id", evidence_id)
                fragment_id = item.get("fragment_id", "")
                description = item.get("description", "")
                if not evidence_id or not page_id or not fragment_id or not description:
                    raise LayaRuntimeError("Laya evidence fragments require stable IDs and content")
                fragment_to_evidence[fragment_id] = evidence_id
                fragment_to_page[fragment_id] = page_id
                fragment_details[fragment_id] = item
                cache_key = self._cache_key(
                    "evidence", evidence_state, fragment_id, description, batch=batch
                )
                # Exact-input custody requires a fresh worker call for every
                # microbatch; a cached score cannot reproduce its tensor trace.
                cached = None if capture_model_input else self._cache_get(cache_key)
                if cached is None:
                    rank_items.append({"probe_id": fragment_id, "description": description})
                    cache_misses += 1
                else:
                    batch_scores[fragment_id] = cached[0]
                    cache_origins.append(
                        LayaCachedOrigin(item_id=fragment_id, presentation_sha256=cached[1])
                    )
                    cache_hits += 1
            if rank_items and cache_origins:
                # Eviction may leave only part of an otherwise identical batch.
                # Rerun all items together; mixed worker presentations have no
                # justified common score scale.
                cache_hits -= len(cache_origins)
                cache_misses += len(cache_origins)
                rank_items = [
                    {"probe_id": item["fragment_id"], "description": item["description"]}
                    for item in batch
                ]
                batch_scores.clear()
                cache_origins.clear()
            batch_started = time.monotonic()
            worker_presentation: LayaWorkerPresentation | None = None
            if rank_items:
                try:
                    ranked_missing = self.rank(
                        state=evidence_state,
                        candidates=tuple(rank_items),
                        timeout_seconds=min(
                            _remaining_seconds(deadline), _remaining_seconds(evidence_deadline)
                        ),
                        capture_exact_worker_call=(
                            (
                                lambda call, proof, index=batch_index: capture_exact_worker_call(
                                    "evidence", index, call, proof
                                )
                            )
                            if capture_exact_worker_call is not None
                            else None
                        ),
                        capture_model_input=capture_model_input,
                    )
                except LayaRuntimeError as error:
                    if fragment_scores and not candidates and "deadline" in str(error).casefold():
                        coverage_limited = True
                        break
                    raise
                if self._last_token_provenance:
                    token_reports.append(self._last_token_provenance)
                worker_presentation = self._last_worker_presentation
                for fragment_id in ranked_missing:
                    score = self._last_relevance_scores[fragment_id]
                    batch_scores[fragment_id] = score
                    description = fragment_details[fragment_id]["description"]
                    self._cache_put(
                        self._cache_key(
                            "evidence", evidence_state, fragment_id, description, batch=batch
                        ),
                        score,
                        presentation_sha256=(
                            worker_presentation.presentation_sha256
                            if worker_presentation is not None
                            else None
                        ),
                    )
            microbatches.append(
                LayaAttentionMicrobatch(
                    phase="evidence",
                    batch_index=batch_index,
                    candidate_ids=tuple(item["fragment_id"] for item in batch),
                    inference_ids=tuple(item["probe_id"] for item in rank_items),
                    cache_hit_ids=tuple(item.item_id for item in cache_origins),
                    cached_origins=tuple(cache_origins),
                    worker_presentation=worker_presentation,
                )
            )
            last_batch_seconds = time.monotonic() - batch_started
            evidence_batches_completed += 1
            ranked = sorted(
                batch_scores,
                key=lambda fragment_id: -batch_scores[fragment_id],
            )
            ranked_fragment_batches.append(tuple(ranked))
            for fragment_id in ranked:
                evidence_id = fragment_to_evidence[fragment_id]
                page_id = fragment_to_page[fragment_id]
                score = batch_scores[fragment_id]
                fragment_scores[fragment_id] = score
                page_fragment_considered[page_id] = page_fragment_considered.get(page_id, 0) + 1
                if evidence_id not in considered_evidence:
                    considered_evidence.append(evidence_id)
                if page_id not in considered_pages:
                    considered_pages.append(page_id)

        ranked_probe_batches: list[tuple[str, ...]] = []
        probe_order: dict[str, int] = {}
        considered_probes: list[str] = []
        ranked_fragments = _interleave_batch_ranks(ranked_fragment_batches)
        ranked_evidence = tuple(
            dict.fromkeys(fragment_details[item]["evidence_id"] for item in ranked_fragments)
        )
        ranked_pages = tuple(
            dict.fromkeys(
                fragment_details[item].get("page_id", fragment_details[item]["evidence_id"])
                for item in ranked_fragments
            )
        )
        focused_evidence = ranked_evidence[:8]
        gap_fragment = next(
            (
                fragment_id
                for fragment_id in ranked_fragments
                if (status := _preview_status(fragment_details[fragment_id]["description"]))
                is not None
                and status != "observed"
            ),
            None,
        )
        focused_fragments = (
            [gap_fragment, *(item for item in ranked_fragments if item != gap_fragment)][:3]
            if gap_fragment is not None
            else ranked_fragments[:3]
        )
        ranked_evidence_context = [
            {
                "evidence_id": fragment_details[fragment_id]["evidence_id"],
                "page_id": fragment_details[fragment_id].get(
                    "page_id", fragment_details[fragment_id]["evidence_id"]
                ),
                "content": _focused_preview(fragment_details[fragment_id]["description"]),
            }
            for fragment_id in focused_fragments
        ]
        probe_state = {
            "ranked_evidence_context": ranked_evidence_context,
            **state,
            "attention_kind": "probe_relevance",
            "ranked_evidence_ids": focused_evidence,
        }
        for candidate in candidates:
            probe_id = candidate.get("probe_id", "")
            if not probe_id or probe_id in probe_order:
                raise LayaRuntimeError("Laya probes require unique stable IDs")
            probe_order[probe_id] = len(probe_order)
        for batch_index, batch in enumerate(
            _chunks(candidates, self._config.max_candidates_per_batch)
        ):
            batch_scores: dict[str, float] = {}
            misses: list[dict[str, str]] = []
            cache_origins = []
            for candidate in batch:
                probe_id = candidate["probe_id"]
                description = candidate["description"]
                cache_key = self._cache_key(
                    "probe", probe_state, probe_id, description, batch=batch
                )
                cached = None if capture_model_input else self._cache_get(cache_key)
                if cached is None:
                    misses.append(candidate)
                    cache_misses += 1
                else:
                    batch_scores[probe_id] = cached[0]
                    cache_origins.append(
                        LayaCachedOrigin(item_id=probe_id, presentation_sha256=cached[1])
                    )
                    cache_hits += 1
            if misses and cache_origins:
                cache_hits -= len(cache_origins)
                cache_misses += len(cache_origins)
                misses = list(batch)
                batch_scores.clear()
                cache_origins.clear()
            worker_presentation = None
            if misses:
                ranked_missing = self.rank(
                    state=probe_state,
                    candidates=tuple(misses),
                    timeout_seconds=_remaining_seconds(deadline),
                    capture_exact_worker_call=(
                        (
                            lambda call, proof, index=batch_index: capture_exact_worker_call(
                                "probe", index, call, proof
                            )
                        )
                        if capture_exact_worker_call is not None
                        else None
                    ),
                    capture_model_input=capture_model_input,
                )
                if self._last_token_provenance:
                    token_reports.append(self._last_token_provenance)
                worker_presentation = self._last_worker_presentation
                for probe_id in ranked_missing:
                    score = self._last_relevance_scores[probe_id]
                    batch_scores[probe_id] = score
                    candidate = next(item for item in misses if item["probe_id"] == probe_id)
                    self._cache_put(
                        self._cache_key(
                            "probe", probe_state, probe_id, candidate["description"], batch=batch
                        ),
                        score,
                        presentation_sha256=(
                            worker_presentation.presentation_sha256
                            if worker_presentation is not None
                            else None
                        ),
                    )
            microbatches.append(
                LayaAttentionMicrobatch(
                    phase="probe",
                    batch_index=batch_index,
                    candidate_ids=tuple(item["probe_id"] for item in batch),
                    inference_ids=tuple(item["probe_id"] for item in misses),
                    cache_hit_ids=tuple(item.item_id for item in cache_origins),
                    cached_origins=tuple(cache_origins),
                    worker_presentation=worker_presentation,
                )
            )
            ranked = sorted(batch_scores, key=lambda probe_id: -batch_scores[probe_id])
            ranked_probe_batches.append(tuple(ranked))
            for probe_id in ranked:
                considered_probes.append(probe_id)

        ranked_probes = _interleave_batch_ranks(ranked_probe_batches)
        comparison_batches = 0
        comparison_judgments = 0
        finalists = tuple(batch[0] for batch in ranked_probe_batches if batch)
        candidate_by_id = {item["probe_id"]: item for item in candidates}
        if len(finalists) > 1 and self._config.max_candidates_per_batch < 2:
            raise LayaRuntimeError("Laya candidate batch limit cannot compare finalists")
        while len(finalists) > 1:
            next_finalists: list[str] = []
            for comparison in _chunks(
                tuple(candidate_by_id[item_id] for item_id in finalists),
                self._config.max_candidates_per_batch,
            ):
                if len(comparison) == 1:
                    next_finalists.append(comparison[0]["probe_id"])
                    continue
                comparison_scores: dict[str, float] = {}
                cached_origins: list[LayaCachedOrigin] = []
                for item in comparison:
                    item_id = item["probe_id"]
                    key = self._cache_key(
                        "compare", probe_state, item_id, item["description"], batch=comparison
                    )
                    cached = None if capture_model_input else self._cache_get(key)
                    if cached is not None:
                        comparison_scores[item_id] = cached[0]
                        cached_origins.append(
                            LayaCachedOrigin(item_id=item_id, presentation_sha256=cached[1])
                        )
                # A partial hit cannot be mixed with scores from a new menu.
                if len(cached_origins) != len(comparison):
                    cached_origins.clear()
                    comparison_scores.clear()
                worker_presentation = None
                if not cached_origins:
                    compared = self.rank(
                        state=probe_state,
                        candidates=comparison,
                        timeout_seconds=_remaining_seconds(deadline),
                        capture_exact_worker_call=(
                            (
                                lambda call, proof, index=comparison_batches: (
                                    capture_exact_worker_call("compare", index, call, proof)
                                )
                            )
                            if capture_exact_worker_call is not None
                            else None
                        ),
                        capture_model_input=capture_model_input,
                    )
                    if self._last_token_provenance:
                        token_reports.append(self._last_token_provenance)
                    worker_presentation = self._last_worker_presentation
                    for item_id in compared:
                        comparison_scores[item_id] = self._last_relevance_scores[item_id]
                        item = candidate_by_id[item_id]
                        self._cache_put(
                            self._cache_key(
                                "compare",
                                probe_state,
                                item_id,
                                item["description"],
                                batch=comparison,
                            ),
                            comparison_scores[item_id],
                            presentation_sha256=(
                                worker_presentation.presentation_sha256
                                if worker_presentation is not None
                                else None
                            ),
                        )
                    cache_misses += len(comparison)
                else:
                    cache_hits += len(comparison)
                comparison_batches += 1
                comparison_judgments += len(comparison)
                microbatches.append(
                    LayaAttentionMicrobatch(
                        phase="compare",
                        batch_index=comparison_batches - 1,
                        candidate_ids=tuple(item["probe_id"] for item in comparison),
                        inference_ids=(
                            () if cached_origins else tuple(item["probe_id"] for item in comparison)
                        ),
                        cache_hit_ids=tuple(origin.item_id for origin in cached_origins),
                        cached_origins=tuple(cached_origins),
                        worker_presentation=worker_presentation,
                    )
                )
                next_finalists.append(max(comparison_scores, key=comparison_scores.__getitem__))
            finalists = tuple(next_finalists)
        if finalists:
            winner = finalists[0]
            # The tail is ordinal within original batches; only the first ID
            # has been compared across every batch's strongest candidate.
            ranked_probes = (winner, *(item for item in ranked_probes if item != winner))
        evidence_batches = (len(evidence) + self._config.max_candidates_per_batch - 1) // (
            self._config.max_candidates_per_batch
        )
        probe_batches = (len(candidates) + self._config.max_candidates_per_batch - 1) // (
            self._config.max_candidates_per_batch
        )
        complete_pages = sum(
            page_fragment_considered.get(page_id, 0) == total
            for page_id, total in page_fragment_totals.items()
        )
        partial_pages = sum(
            0 < page_fragment_considered.get(page_id, 0) < total
            for page_id, total in page_fragment_totals.items()
        )
        state_truncated_batches = sum(
            bool(report.get("state_truncated")) for report in token_reports
        )
        instruction_truncated_items = sum(
            int(report.get("instruction_truncated_items", 0)) for report in token_reports
        )
        state_fields_omitted = max(
            (int(report.get("state_fields_omitted", 0)) for report in token_reports),
            default=0,
        )
        state_list_items_omitted = max(
            (int(report.get("state_list_items_omitted", 0)) for report in token_reports),
            default=0,
        )
        state_tokens_original = max(
            (int(report.get("state_tokens_original", 0)) for report in token_reports),
            default=0,
        )
        minimum_state_tokens = min(
            (int(report.get("state_presented_tokens_min", 0)) for report in token_reports),
            default=0,
        )
        state_notes_raw = state.get("coverage_notes", ())
        if isinstance(state_notes_raw, (list, tuple)):
            state_note_items = cast(list[object] | tuple[object, ...], state_notes_raw)
            state_notes = tuple(note for note in state_note_items if isinstance(note, str))
        else:
            state_notes = ()
        page_coverage_notes = (
            (f"previews_considered={len(considered_pages)}_of_{len(page_fragment_totals)}",)
            if "evidence_pages_are_bounded_previews" in state_notes
            else (
                f"pages_complete={complete_pages}_of_{len(page_fragment_totals)}",
                f"pages_partial={partial_pages}",
            )
        )
        return LayaAttentionResult(
            ranked_probe_ids=ranked_probes,
            ranked_evidence_ids=ranked_evidence,
            considered_probe_ids=tuple(considered_probes),
            considered_evidence_ids=tuple(considered_evidence),
            ranked_attention_page_ids=ranked_pages,
            considered_attention_page_ids=tuple(considered_pages),
            attention_notes=(
                "ordinal_relevance_only",
                f"fragments_considered={len(fragment_scores)}_of_{len(evidence)}",
                *page_coverage_notes,
                f"coverage_limited={str(coverage_limited).lower()}",
                f"evidence_batches={evidence_batches_completed}_of_{evidence_batches}",
                f"probe_batches={probe_batches}",
                f"comparison_batches={comparison_batches}",
                f"comparison_judgments={comparison_judgments}",
                f"cache_hits={cache_hits}",
                f"cache_misses={cache_misses}",
                f"state_tokens_presented_min={minimum_state_tokens}",
                f"state_truncated_batches={state_truncated_batches}",
                f"instruction_truncated_items={instruction_truncated_items}",
                f"state_tokens_original_max={state_tokens_original}",
                f"state_omissions_max={state_fields_omitted}_fields_"
                f"{state_list_items_omitted}_items",
                *state_notes,
            ),
            microbatches=tuple(microbatches),
        )

    @staticmethod
    def _cache_key(
        kind: str,
        state: dict[str, object],
        item_id: str,
        description: str,
        *,
        batch: tuple[dict[str, str], ...],
    ) -> str:
        # A rank is meaningful only inside its exact worker presentation.
        # Include the full state and ordered batch so a changed context or
        # candidate set cannot reuse an incomparable per-item score.
        serialized = json.dumps(
            [kind, state, batch, item_id, description],
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
            default=str,
        ).encode("utf-8")
        return hashlib.sha256(serialized).hexdigest()

    def _cache_get(self, key: str) -> tuple[float, str | None] | None:
        value = self._score_cache.get(key)
        if value is not None:
            self._score_cache.move_to_end(key)
        return value

    def _cache_put(self, key: str, value: float, *, presentation_sha256: str | None) -> None:
        self._score_cache[key] = (value, presentation_sha256)
        self._score_cache.move_to_end(key)
        while len(self._score_cache) > self._score_cache_limit:
            self._score_cache.popitem(last=False)

    def close(self) -> None:
        """Return only after owned-worker exit is proven; otherwise retain ownership."""

        with self._lock:
            if self._startup is not None:
                done, abandoned, _errors = self._startup
                self._abandon_startup(done, abandoned)
                if not done.wait(timeout=1):
                    raise LayaRuntimeError("Laya worker startup exit could not be verified")
                self._startup = None
            self._discard_process()

    def _abandon_startup(self, done: threading.Event, abandoned: threading.Event) -> None:
        with self._startup_guard:
            abandoned.set()
            if self._process is not None:
                self._discard_process()

    def _ready_process(self, deadline: float, cancellation: threading.Event | None) -> _Process:
        """Start at most one cold worker and abandon it if the caller runs out of time."""

        if cancellation is not None and cancellation.is_set():
            raise LayaRuntimeError("Laya worker request was cancelled")
        if self._retirement_pending:
            self._discard_process()
        if self._startup is not None and self._startup[1].is_set():
            done, _, _ = self._startup
            if done.is_set():
                self._startup = None
            else:
                raise LayaRuntimeError("Laya cold worker startup was cancelled")
        if (
            self._startup is None
            and self._process is not None
            and self._process is self._admitted_process
            and self._process.poll() is None
        ):
            return self._process
        if self._startup is None:
            done = threading.Event()
            abandoned = threading.Event()
            errors: list[Exception] = []
            self._startup = (done, abandoned, errors)

            def start() -> None:
                try:
                    self._ensure_process(deadline, cancellation, abandoned)
                except Exception as error:
                    errors.append(error)
                finally:
                    try:
                        with self._startup_guard:
                            if abandoned.is_set():
                                self._discard_process()
                    except Exception as error:
                        errors.append(error)
                    finally:
                        done.set()

            threading.Thread(target=start, daemon=True).start()
        done, abandoned, errors = self._startup
        if abandoned.is_set() and not done.is_set():
            raise LayaRuntimeError("Laya cold worker startup is still cancelling")
        while not done.is_set():
            if cancellation is not None and cancellation.is_set():
                self._abandon_startup(done, abandoned)
                raise LayaRuntimeError("Laya worker request was cancelled")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._abandon_startup(done, abandoned)
                raise LayaRuntimeError("Laya cold worker exceeded its request deadline")
            done.wait(timeout=min(0.02, remaining))
        self._startup = None
        if cancellation is not None and cancellation.is_set():
            abandoned.set()
            self._discard_process()
            raise LayaRuntimeError("Laya worker request was cancelled")
        if abandoned.is_set() or deadline - time.monotonic() <= 0:
            abandoned.set()
            self._discard_process()
            raise LayaRuntimeError("Laya cold worker exceeded its request deadline")
        if errors:
            error = errors[0]
            if isinstance(error, LayaRuntimeError):
                raise error
            raise LayaRuntimeError("Laya cold worker startup failed") from error
        if self._process is None:
            raise LayaRuntimeError("Laya cold worker startup returned no process")
        return self._process

    def _ensure_process(
        self,
        deadline: float,
        cancellation: threading.Event | None,
        abandoned: threading.Event,
    ) -> _Process:
        if self._retirement_pending:
            self._discard_process()
        if (
            self._process is not None
            and self._process is self._admitted_process
            and self._process.poll() is None
        ):
            return self._process
        if self._process is not None:
            self._discard_process()
        try:
            available_ram = self._available_ram_reader()
        except Exception:  # A failed capacity reader must not start an optional worker.
            available_ram = None
        if available_ram is None or available_ram < LAYA_COLD_RAM_REQUIRED_BYTES:
            raise LayaRuntimeError("Laya host RAM admission rejected cold worker start")
        self._config.validate_install()
        if self._using_real_subprocess:
            _verify_weight_file(self._config.model_path / "model.safetensors")
        worker_path = Path(__file__).with_name("laya_worker.py").resolve()
        launch_id = uuid.uuid4().hex if self._gated_startup else None
        command = [
            str(self._config.interpreter_path),
            "-I",
            str(worker_path),
            "--model-path",
            str(self._config.model_path),
            "--threads",
            str(self._config.threads),
            "--device",
            self._config.device,
            "--precision",
            self._config.precision,
            "--min-free-vram-mb",
            str(self._config.min_free_vram_mb),
            "--max-request-bytes",
            str(self._config.max_request_bytes),
        ]
        if launch_id is not None:
            command.extend(("--await-load-admission", "--launch-id", launch_id))
        environment = os.environ.copy()
        environment.update(
            {
                "CUDA_VISIBLE_DEVICES": (
                    "" if self._config.device == "cpu" else str(self._config.cuda_device_index)
                ),
                "HF_HUB_OFFLINE": "1",
                "TRANSFORMERS_OFFLINE": "1",
                "USE_TF": "0",
                "TOKENIZERS_PARALLELISM": "false",
                "OMP_NUM_THREADS": str(self._config.threads),
                "MKL_NUM_THREADS": str(self._config.threads),
                "HTTP_PROXY": "",
                "HTTPS_PROXY": "",
                "ALL_PROXY": "",
                "NO_PROXY": "*",
            }
        )
        creationflags = 0
        if os.name == "nt":
            creationflags = subprocess.CREATE_NO_WINDOW | subprocess.BELOW_NORMAL_PRIORITY_CLASS
        if self._tree_custody_enabled:
            if self._job is not None:
                raise LayaRuntimeError("prior Laya Job custody has not been released")
            creationflags |= _CREATE_SUSPENDED
            self._job = self._job_factory()
        self._responses = queue.Queue(maxsize=2)
        try:
            self._process = self._popen_factory(
                command,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                env=environment,
                creationflags=creationflags,
            )
            if self._job is not None:
                job = self._job
                process = self._process
                job.assign_suspended(process)
                identity = WorkerIdentity(process.pid, self._process_identity_reader(process.pid))
                self._tree_custody = TreeCustody.create(job, process, identity)
                job.resume_assigned(process)
        except Exception:
            if self._job is not None:
                # A failed assignment or resume must not leave a runnable orphan.
                try:
                    self._job.terminate_processes()
                    if self._process is not None and self._process.poll() is None:
                        try:
                            self._process.kill()
                        except OSError:
                            pass
                        self._process.wait(timeout=1)
                    if self._job.wait_until_empty(1) and (
                        self._process is None or self._process.poll() is not None
                    ):
                        self._job.close()
                        self._job = None
                        self._tree_custody = None
                        self._process = None
                except Exception:
                    pass
            raise
        if self._process.stdin is None or self._process.stdout is None:
            self._discard_process()
            raise LayaRuntimeError("Laya worker pipes are unavailable")
        process = self._process
        responses = self._responses
        self._reader = threading.Thread(
            target=self._read_responses, args=(process, responses), daemon=True
        )
        self._reader.start()
        if launch_id is not None:
            try:
                self._admit_model_load(process, launch_id, deadline, cancellation, abandoned)
            except Exception:
                self._discard_process()
                raise
        else:
            self._admitted_process = process
        return process

    def _admit_rank_call(
        self,
        process: _Process,
        deadline: float,
        cancellation: threading.Event | None,
    ) -> None:
        callback = self._call_admission
        assert callback is not None
        try:
            pid, created_at = self._verify_owned_identity(process)
        except LayaRuntimeError:
            self._discard_process()
            raise
        finished = threading.Event()
        result: list[bool] = []
        errors: list[Exception] = []

        def check() -> None:
            try:
                result.append(callback(pid, created_at))
            except Exception as error:
                errors.append(error)
            finally:
                finished.set()

        threading.Thread(target=check, daemon=True).start()
        while not finished.is_set():
            if cancellation is not None and cancellation.is_set():
                self._discard_process()
                raise LayaRuntimeError("Laya worker call admission was cancelled")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self._discard_process()
                raise LayaRuntimeError("Laya worker call admission exceeded its deadline")
            finished.wait(timeout=min(0.02, remaining))
        if errors:
            self._discard_process()
            raise LayaRuntimeError("Laya worker call admission failed") from errors[0]
        if len(result) != 1 or result[0] is not True:
            self._discard_process()
            raise LayaRuntimeError("Laya worker call admission denied")
        try:
            self._verify_owned_identity(process)
        except LayaRuntimeError:
            self._discard_process()
            raise
        if cancellation is not None and cancellation.is_set():
            self._discard_process()
            raise LayaRuntimeError("Laya worker call admission was cancelled")
        if deadline - time.monotonic() <= 0:
            self._discard_process()
            raise LayaRuntimeError("Laya worker call admission exceeded its deadline")

    def _verify_owned_identity(self, process: _Process) -> tuple[int, float]:
        try:
            identity = (process.pid, self._process_identity_reader(process.pid))
            if (
                self._process is not process
                or self._admitted_process is not process
                or self._owned_identity != identity
                or process.poll() is not None
            ):
                raise ValueError("owned process identity changed")
        except Exception as error:
            raise LayaRuntimeError("Laya worker identity changed before rank write") from error
        return identity

    def _admit_model_load(
        self,
        process: _Process,
        launch_id: str,
        deadline: float,
        cancellation: threading.Event | None,
        abandoned: threading.Event,
    ) -> None:
        while True:
            if abandoned.is_set() or (cancellation is not None and cancellation.is_set()):
                raise LayaRuntimeError("Laya cold worker startup was cancelled")
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise LayaRuntimeError("Laya cold worker exceeded its request deadline")
            try:
                line = self._responses.get(timeout=min(0.02, remaining))
                break
            except queue.Empty:
                if process.poll() is not None:
                    raise LayaRuntimeError(
                        "Laya cold worker exited before model-load admission"
                    ) from None
        try:
            event = cast(object, json.loads(line))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise LayaRuntimeError("Laya worker sent an invalid startup event") from error
        if event != {
            "protocol_version": LAYA_PROTOCOL_VERSION,
            "event": "awaiting_admission",
            "launch_id": launch_id,
        }:
            raise LayaRuntimeError("Laya worker sent an invalid startup event")
        try:
            pid = process.pid
            created_at = self._process_identity_reader(pid)
            if pid <= 0 or created_at <= 0 or process.poll() is not None:
                raise ValueError("invalid or exited worker identity")
            admitted = (
                self._startup_admission(pid, created_at)
                if self._startup_admission is not None
                else True
            )
        except Exception as error:
            raise LayaRuntimeError("Laya worker process identity could not be admitted") from error
        if admitted is not True:
            raise LayaRuntimeError("Laya worker model-load admission denied")
        token = (
            json.dumps(
                {
                    "protocol_version": LAYA_PROTOCOL_VERSION,
                    "command": "admit_load",
                    "launch_id": launch_id,
                },
                separators=(",", ":"),
            ).encode()
            + b"\n"
        )
        with self._startup_guard:
            if (
                abandoned.is_set()
                or (cancellation is not None and cancellation.is_set())
                or deadline - time.monotonic() <= 0
                or process.poll() is not None
            ):
                raise LayaRuntimeError("Laya cold worker startup was cancelled")
            if process.stdin is None:
                raise LayaRuntimeError("Laya worker stdin is unavailable")
            try:
                process.stdin.write(token)
                process.stdin.flush()
            except OSError as error:
                raise LayaRuntimeError("Laya worker model-load release failed") from error
            self._admitted_process = process
            self._owned_identity = (pid, created_at)

    def _read_responses(self, process: _Process, responses: queue.Queue[bytes]) -> None:
        if process.stdout is None:
            return
        while True:
            try:
                line = process.stdout.readline(self._config.max_response_bytes + 1)
                responses.put(line, timeout=0.1)
            except (OSError, queue.Full):
                return
            if not line:
                return

    def _discard_process(self) -> None:
        process = self._process
        if process is None:
            return
        self._retirement_pending = True
        if self._job is not None:
            try:
                self._job.terminate_processes()
                if process.poll() is None:
                    try:
                        process.kill()
                    except OSError:
                        pass
                    process.wait(timeout=1)
                if not self._job.wait_until_empty(1):
                    raise LayaRuntimeError("Laya Job tree termination could not be verified")
                if process.poll() is None:
                    raise LayaRuntimeError("Laya worker termination could not be verified")
            except (OSError, RuntimeError, ValueError) as error:
                raise LayaRuntimeError("Laya Job tree termination could not be verified") from error
            self._process = None
            self._admitted_process = None
            self._owned_identity = None
            self._retirement_pending = False
            return
        try:
            if process.poll() is None:
                try:
                    process.terminate()
                except OSError:
                    pass  # The worker may have exited between poll and terminate.
                try:
                    process.wait(timeout=0.25)
                except (OSError, subprocess.TimeoutExpired):
                    pass
                if process.poll() is None:
                    try:
                        process.kill()
                    except OSError:
                        pass
                    try:
                        process.wait(timeout=1)
                    except (OSError, subprocess.TimeoutExpired):
                        pass
            if process.poll() is None:
                raise LayaRuntimeError("Laya worker termination could not be verified")
        except OSError as error:
            raise LayaRuntimeError("Laya worker termination could not be verified") from error
        self._process = None
        self._admitted_process = None
        self._owned_identity = None
        self._retirement_pending = False
        active_write, self._active_write = self._active_write, None
        try:
            if process.stdin is not None:
                if (
                    active_write is not None
                    and active_write[0] is process.stdin
                    and not active_write[1].is_set()
                ):
                    threading.Thread(target=process.stdin.close, daemon=True).start()
                else:
                    process.stdin.close()
        except OSError:
            pass


class LayaRanker(Protocol):
    def attend(
        self,
        *,
        state: dict[str, object],
        evidence: tuple[dict[str, str], ...],
        candidates: tuple[dict[str, str], ...],
        timeout_seconds: float,
    ) -> LayaAttentionResult: ...


def _available_system_ram() -> int | None:
    return psutil.virtual_memory().available


def _process_created_at(pid: int) -> float:
    return psutil.Process(pid).create_time()


def _acquire_until(
    lock: LockType,
    deadline: float,
    cancellation: threading.Event | None,
    deadline_message: str,
) -> None:
    """Bound queueing and observe cancellation before worker ownership."""

    while True:
        if cancellation is not None and cancellation.is_set():
            raise LayaRuntimeError("Laya worker request was cancelled")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise LayaRuntimeError(deadline_message)
        if lock.acquire(timeout=min(0.02, remaining)):
            if cancellation is not None and cancellation.is_set():
                lock.release()
                raise LayaRuntimeError("Laya worker request was cancelled")
            if deadline - time.monotonic() <= 0:
                lock.release()
                raise LayaRuntimeError(deadline_message)
            return


def _preview_status(description: str) -> str | None:
    try:
        source_raw: object = json.loads(description)
    except (TypeError, ValueError):
        return None
    if not isinstance(source_raw, dict):
        return None
    source = cast(dict[str, object], source_raw)
    projection = source.get("projection")
    if projection not in {
        "bounded_preview_not_full_page",
        "semantic_fact_packets_v1",
        "laya_semantic_v1",
    }:
        return None
    status = source.get("quality") if projection == "laya_semantic_v1" else source.get("status")
    return (
        status
        if isinstance(status, str)
        and status
        in {
            "observed",
            "partial",
            "missing",
            "unavailable",
            "denied",
            "stale",
            "truncated",
            "failed",
            "unsupported",
        }
        else None
    )


def _focused_preview(description: str) -> str:
    """Keep a preview's fact and provenance together in the probe state budget."""
    try:
        source_raw: object = json.loads(description)
    except (TypeError, ValueError):
        return description[:240]
    if not isinstance(source_raw, dict):
        return description[:240]
    source = cast(dict[str, object], source_raw)
    if source.get("projection") == "laya_semantic_v1":
        if len(description) <= 800:
            return description
        return json.dumps(
            {
                "projection": "laya_semantic_v1",
                "focus_unavailable": "oversized_packet",
                "quality": source.get("quality"),
                "value_quality": source.get("value_quality"),
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )
    if source.get("projection") == "semantic_fact_packets_v1":
        # A compact *structured* subset, never an arbitrary character slice.
        # The source packet has already bounded itself to 800 characters, so
        # retaining the exact value and unit here cannot silently change them.
        keys = (
            "packet_kind",
            "evidence_id",
            "page_id",
            "probe_id",
            "entity_hint",
            "relation_ids",
            "relation_ids_omitted",
            "metric",
            "value",
            "value_excerpt",
            "value_sha256",
            "value_original_bytes",
            "unit",
            "value_quality",
            "status",
            "case_scope",
            "incident_relevant",
            "observed_at",
            "captured_at",
            "redaction_applied",
            "facts_omitted",
            "limitations",
            "limitations_omitted",
        )
        packet = {key: source[key] for key in keys if key in source}
        packet["projection"] = "semantic_fact_packets_v1"
        focused = json.dumps(packet, ensure_ascii=False, separators=(",", ":"))
        if len(focused) <= 800:
            return focused
        return json.dumps(
            {
                "projection": "semantic_fact_packets_v1",
                "focus_unavailable": "oversized_packet",
                "status": source.get("status"),
                "value_quality": source.get("value_quality"),
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )
    if source.get("projection") != "bounded_preview_not_full_page":
        return description[:240]

    packet: dict[str, object] = {"preview": True}
    packet.update(
        {
            key: source[key]
            for key in ("status", "observed_at", "captured_at", "probe_id")
            if isinstance(source.get(key), str)
        }
    )
    packet["facts"] = {}
    facts_omitted = source.get("facts_omitted")
    packet["facts_omitted"] = facts_omitted if isinstance(facts_omitted, int) else 0
    values_truncated = source.get("fact_values_truncated")
    if isinstance(values_truncated, int) and values_truncated > 0:
        packet["fact_values_truncated"] = values_truncated

    def encode() -> str:
        return json.dumps(packet, ensure_ascii=False, separators=(",", ":"))

    if len(encode()) > 240:
        packet.pop("probe_id", None)
    facts_raw = source.get("facts")
    facts = cast(dict[str, object], facts_raw) if isinstance(facts_raw, dict) else None
    if facts is not None:
        selected = cast(dict[str, object], packet["facts"])
        for path, value in facts.items():
            selected[path] = value
            packet["facts_omitted"] = (
                (facts_omitted if isinstance(facts_omitted, int) else 0)
                + len(facts)
                - len(selected)
            )
            if len(encode()) > 240:
                packet.pop("probe_id", None)
            if len(encode()) > 240:
                del selected[path]
        packet["facts_omitted"] = (
            (facts_omitted if isinstance(facts_omitted, int) else 0) + len(facts) - len(selected)
        )
    return encode()


def _chunks(items: tuple[dict[str, str], ...], size: int) -> tuple[tuple[dict[str, str], ...], ...]:
    return tuple(items[index : index + size] for index in range(0, len(items), size))


def _interleave_batch_ranks(batches: list[tuple[str, ...]]) -> tuple[str, ...]:
    """Preserve ordinal rank without treating per-batch scores as comparable."""

    return tuple(
        batch[position]
        for position in range(max(map(len, batches), default=0))
        for batch in batches
        if position < len(batch)
    )


def _remaining_seconds(deadline: float) -> float:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise LayaRuntimeError("Laya attention deadline expired before full coverage")
    return remaining


def _verify_weight_file(
    path: Path,
    *,
    expected_bytes: int = LAYA_MODEL_WEIGHT_BYTES,
    expected_sha256: str = LAYA_MODEL_WEIGHT_SHA256,
) -> None:
    """Recheck the immutable artifact before a real worker can deserialize it."""

    try:
        if path.stat().st_size != expected_bytes:
            raise LayaRuntimeError("Laya weight size differs from the admitted artifact")
        digest = hashlib.sha256()
        with path.open("rb") as stream:
            while block := stream.read(1024 * 1024):
                digest.update(block)
    except OSError as error:
        raise LayaRuntimeError("Laya weights could not be verified") from error
    if digest.hexdigest() != expected_sha256:
        raise LayaRuntimeError("Laya weight hash differs from the admitted artifact")
