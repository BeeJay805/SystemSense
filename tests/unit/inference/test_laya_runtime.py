from __future__ import annotations

import io
import json
import queue
import subprocess
import threading
import time
from collections.abc import Callable
from hashlib import sha256
from pathlib import Path
from typing import Literal, cast

import pytest

from systemsense.inference.control import inference_cancellation
from systemsense.inference.laya_runtime import (
    LAYA_MODEL_REVISION,
    LAYA_MODEL_WEIGHT_SHA256,
    LayaQuestionPresentation,
    LayaRuntimeConfig,
    LayaRuntimeError,
    LayaSubprocessRuntime,
    LayaWorkerPresentation,
    PopenFactory,
    _focused_preview,  # pyright: ignore[reportPrivateUsage]
    _verify_weight_file,  # pyright: ignore[reportPrivateUsage]
)


def test_focused_semantic_packet_keeps_entity_and_grounded_relationship() -> None:
    packet = {
        "projection": "semantic_fact_packets_v1",
        "packet_kind": "fact",
        "evidence_id": "ev_" + "a" * 32,
        "page_id": "ev_" + "a" * 32 + ":0",
        "probe_id": "gpu.telemetry.sample",
        "entity_hint": "gpu-1",
        "relation_ids": ["rel_" + "b" * 32],
        "metric": "gpu.clock",
        "value": 450,
        "unit": "MHz",
        "value_quality": "exact",
        "status": "observed",
        "observed_at": "2026-09-23T12:00:00+00:00",
        "captured_at": "2026-09-23T12:00:01+00:00",
        "facts_omitted": 0,
    }
    focused = json.loads(_focused_preview(json.dumps(packet)))
    assert focused["entity_hint"] == "gpu-1"
    assert focused["relation_ids"] == ["rel_" + "b" * 32]
    assert focused["evidence_id"] == "ev_" + "a" * 32


def test_worker_presentation_allows_tokenizer_repacking_after_field_omission() -> None:
    """Removing a JSON field can change token merges and add one fitted token."""

    presentation = LayaWorkerPresentation(
        presentation_sha256="a" * 64,
        fitted_state_sha256="b" * 64,
        questions_sha256="c" * 64,
        presented_item_ids=("synthetic-page-0:preview:0",),
        fitted_state_tokens=52,
        state_tokens_original=51,
        state_fields_omitted=1,
        state_list_items_omitted=0,
        questions=(
            LayaQuestionPresentation(
                question_id="item_0_piece_0",
                item_id="synthetic-page-0:preview:0",
                question_sha256="d" * 64,
                instruction_tokens=88,
                instruction_presented_tokens=88,
                criteria_tokens=17,
                criteria_presented_tokens=17,
                state_presented_tokens=52,
            ),
        ),
    )

    assert presentation.fitted_state_tokens == 52


@pytest.mark.parametrize("operation", ["rank", "attend"])
def test_waiting_laya_request_honors_cancellation_before_lock_deadline(
    tmp_path: Path, operation: str
) -> None:
    class NotifyingLock:
        def __init__(self) -> None:
            self.inner = threading.Lock()
            self.waiting = threading.Event()

        def acquire(self, *, timeout: float = -1) -> bool:
            self.waiting.set()
            return self.inner.acquire(timeout=timeout)

        def release(self) -> None:
            self.inner.release()

    starts: list[int] = []

    def start(*_args: object, **_kwargs: object) -> _FakeProcess:
        starts.append(1)
        return _FakeProcess()

    runtime = LayaSubprocessRuntime(
        _config(tmp_path),
        popen_factory=cast(PopenFactory, start),
        available_ram_reader=lambda: 8 * 1024**3,
    )
    held_lock = NotifyingLock()
    original_lock = runtime._lock if operation == "rank" else runtime._attention_lock  # pyright: ignore[reportPrivateUsage]
    if operation == "rank":
        runtime._lock = held_lock  # type: ignore[assignment]  # pyright: ignore[reportPrivateUsage]
    else:
        runtime._attention_lock = held_lock  # type: ignore[assignment]  # pyright: ignore[reportPrivateUsage]
    held_lock.acquire()
    held_lock.waiting.clear()
    cancelled = threading.Event()
    errors: list[Exception] = []

    def request() -> None:
        try:
            with inference_cancellation(cancelled):
                if operation == "rank":
                    runtime.rank(
                        state={},
                        candidates=({"probe_id": "core.system", "description": "system"},),
                        timeout_seconds=0.6,
                    )
                else:
                    runtime.attend(
                        state={},
                        evidence=(),
                        candidates=({"probe_id": "core.system", "description": "system"},),
                        timeout_seconds=0.6,
                    )
        except Exception as error:
            errors.append(error)

    worker = threading.Thread(target=request, daemon=True)
    worker.start()
    try:
        assert held_lock.waiting.wait(timeout=1)
        cancelled.set()
        worker.join(timeout=2)
        assert not worker.is_alive()
        assert len(errors) == 1
        assert isinstance(errors[0], LayaRuntimeError)
        assert "cancelled" in str(errors[0])
        assert starts == []
    finally:
        held_lock.release()
        worker.join(timeout=1)
        if operation == "rank":
            runtime._lock = original_lock  # pyright: ignore[reportPrivateUsage]
        else:
            runtime._attention_lock = original_lock  # pyright: ignore[reportPrivateUsage]
        runtime.close()


class _FakeStdout:
    def __init__(self) -> None:
        self.lines: queue.Queue[bytes] = queue.Queue()

    def readline(self, _limit: int = -1) -> bytes:
        try:
            return self.lines.get(timeout=1)
        except queue.Empty:
            return b""


class _FakeStdin:
    def __init__(
        self,
        stdout: _FakeStdout,
        *,
        response: object | Callable[[dict[str, object]], object] | None = None,
    ) -> None:
        self.stdout = stdout
        self.response = response
        self.requests: list[dict[str, object]] = []

    def write(self, payload: bytes) -> int:
        request = json.loads(payload)
        self.requests.append(request)
        if request.get("command") == "admit_load":
            return len(payload)
        if callable(self.response):
            response = self.response(request)
        elif self.response is None:
            response = {
                "protocol_version": 1,
                "request_id": request["request_id"],
                "ranked_probe_ids": [item["probe_id"] for item in reversed(request["candidates"])],
            }
        else:
            response = self.response
        if response is not False:
            self.stdout.lines.put(json.dumps(response).encode() + b"\n")
        return len(payload)

    def flush(self) -> None:
        return None

    def close(self) -> None:
        return None


class _FakeProcess:
    def __init__(
        self, *, response: object | Callable[[dict[str, object]], object] | None = None
    ) -> None:
        self.stdout = _FakeStdout()
        self.stdin = _FakeStdin(self.stdout, response=response)
        self.stderr = io.BytesIO()
        self.returncode: int | None = None
        self.pid = 4242

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.returncode = 1
        self.stdout.lines.put(b"")

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        self.returncode = self.returncode or 0
        return self.returncode

    def kill(self) -> None:
        self.returncode = 1
        self.stdout.lines.put(b"")


def _factory(process: _FakeProcess) -> PopenFactory:
    def start(*_args: object, **_kwargs: object) -> _FakeProcess:
        return process

    return cast(PopenFactory, start)


def _config(
    tmp_path: Path,
    *,
    device: Literal["cpu", "cuda"] = "cpu",
    precision: Literal["float32", "float16"] = "float32",
) -> LayaRuntimeConfig:
    tmp_path.mkdir(parents=True, exist_ok=True)
    interpreter = tmp_path / "python.exe"
    interpreter.write_bytes(b"")
    model = tmp_path / "model"
    model.mkdir(exist_ok=True)
    (model / "model.safetensors").write_bytes(b"placeholder")
    (model / "rl_agent_config.json").write_text("{}", encoding="utf-8")
    (model / "tokenizer").mkdir(exist_ok=True)
    (model / "encoder").mkdir(exist_ok=True)
    (model / "INSTALL-MANIFEST.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "model_revision": LAYA_MODEL_REVISION,
                "weight_sha256": LAYA_MODEL_WEIGHT_SHA256,
                "package_version": "0.3.5",
                "package_wheel_sha256": (
                    "4c57f64cbaf893bb5c7b4affddc2bf21a819f55df51941689f11868583be2903"
                ),
                "license": "Apache-2.0",
                "model_repository": "convaiinnovations/laya-typed-decisions",
                "weight_bytes": 842_609_220,
                "torch_version": "2.14.0+cpu",
                "transformers_version": "5.17.0",
                "device_policy": "cpu_and_cuda",
                "acquired_at": "2026-09-22T12:56:33-07:00",
            }
        ),
        encoding="utf-8",
    )
    return LayaRuntimeConfig(
        interpreter_path=interpreter,
        model_path=model,
        device=device,
        precision=precision,
        max_candidates_per_batch=4 if device == "cuda" else 20,
    )


def test_config_requires_absolute_pinned_local_install(tmp_path: Path) -> None:
    config = _config(tmp_path)
    assert config.validate_install().model_revision == LAYA_MODEL_REVISION

    bad_manifest = config.model_path / "INSTALL-MANIFEST.json"
    manifest = json.loads(bad_manifest.read_text(encoding="utf-8"))
    manifest["weight_sha256"] = "0" * 64
    bad_manifest.write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(LayaRuntimeError, match="pinned manifest"):
        config.validate_install()

    with pytest.raises(ValueError, match="absolute"):
        LayaRuntimeConfig(interpreter_path=Path("python.exe"), model_path=config.model_path)

    with pytest.raises(ValueError, match="CUDA"):
        _config(tmp_path / "cpu-half", precision="float16")


def test_weight_verifier_rejects_size_or_hash_drift(tmp_path: Path) -> None:
    weight = tmp_path / "model.safetensors"
    payload = b"pinned local weight fixture"
    weight.write_bytes(payload)
    expected = sha256(payload).hexdigest()

    _verify_weight_file(
        weight,
        expected_bytes=len(payload),
        expected_sha256=expected,
    )

    weight.write_bytes(b"tampered local weight fixture")
    with pytest.raises(LayaRuntimeError, match=r"size|hash"):
        _verify_weight_file(
            weight,
            expected_bytes=len(payload),
            expected_sha256=expected,
        )


def test_runtime_keeps_one_cpu_worker_and_returns_only_an_ordered_id_list(
    tmp_path: Path,
) -> None:
    calls: list[tuple[list[str], dict[str, str]]] = []
    process = _FakeProcess()

    def start(command: list[str], **kwargs: object) -> _FakeProcess:
        calls.append((command, kwargs["env"]))  # type: ignore[index]
        return process

    config = _config(tmp_path)
    runtime = LayaSubprocessRuntime(
        config,
        popen_factory=cast(PopenFactory, start),
        available_ram_reader=lambda: 8 * 1024**3,
    )
    candidates = (
        {"probe_id": "core.system", "description": "system snapshot"},
        {"probe_id": "application.snapshot", "description": "application snapshot"},
    )
    ranked = runtime.rank(
        state={"symptom": "application does not launch"},
        candidates=candidates,
        timeout_seconds=1,
    )
    again = runtime.rank(state={"symptom": "retry"}, candidates=candidates, timeout_seconds=1)

    assert ranked == ("application.snapshot", "core.system")
    assert again == ranked
    assert len(calls) == 1
    command, environment = calls[0]
    assert command[0] == str(config.interpreter_path)
    assert "--model-path" in command
    assert environment["CUDA_VISIBLE_DEVICES"] == ""
    assert environment["HF_HUB_OFFLINE"] == "1"
    assert environment["TRANSFORMERS_OFFLINE"] == "1"
    assert environment["OMP_NUM_THREADS"] == "2"
    assert "probabilities" not in process.stdin.requests[0]
    runtime.close()


def test_exact_worker_call_capture_is_opt_in_ephemeral_and_digest_checked(tmp_path: Path) -> None:
    from systemsense.inference import laya_worker

    class Tokenizer:
        mask_token = "[MASK]"
        mask_token_id = 1

        def __call__(self, text: str, *, add_special_tokens: bool = False) -> dict[str, object]:
            return {"input_ids": [len(part) for part in text.split()]}

    class Agent:
        tok = Tokenizer()

        def __init__(self) -> None:
            self.cfg: dict[str, object] = {"max_len": 512, "head_max_len": 80}

        def predict(
            self, state: dict[str, object], questions: dict[str, dict[str, object]]
        ) -> dict[str, object]:
            return {"answers": {key: {"noul": 0.8} for key in questions}}

    process = _FakeProcess(
        response=lambda request: laya_worker._handle(  # pyright: ignore[reportPrivateUsage]
            cast(laya_worker._LayaAgent, Agent()),  # pyright: ignore[reportPrivateUsage]
            request,
        )
    )
    runtime = LayaSubprocessRuntime(
        _config(tmp_path),
        popen_factory=_factory(process),
        available_ram_reader=lambda: 8 * 1024**3,
    )
    captured: list[tuple[dict[str, object], LayaWorkerPresentation]] = []
    candidates = ({"probe_id": "probe.one", "description": "Inspect application"},)
    try:
        runtime.rank(
            state={"symptom": "private-path"},
            candidates=candidates,
            timeout_seconds=1,
        )
        assert process.stdin.requests[-1].get("capture_exact_worker_call") is None
        runtime.rank(
            state={"symptom": "private-path"},
            candidates=candidates,
            timeout_seconds=1,
            capture_exact_worker_call=lambda call, proof: captured.append((call, proof)),
        )
        assert process.stdin.requests[-1]["capture_exact_worker_call"] is True
        assert len(captured) == 1
        assert captured[0][0]["state"] == {"symptom": "private-path"}
        assert captured[0][1].fitted_state_sha256
        assert not hasattr(runtime, "_last_exact_worker_call")
    finally:
        runtime.close()


def test_attend_opt_in_capture_follows_actual_probe_microbatch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from benchmarks import laya_exact_batch_parity as exact
    from benchmarks import laya_training_loader as loader
    from systemsense.inference import laya_worker

    class Tokenizer:
        mask_token = "[MASK]"
        mask_token_id = 1
        cls_token_id = 101
        sep_token_id = 102
        pad_token_id = 0

        def __call__(self, text: str, *, add_special_tokens: bool = False) -> dict[str, object]:
            return {"input_ids": [len(part) for part in text.split()]}

    class Agent:
        tok = Tokenizer()

        def __init__(self) -> None:
            self.cfg: dict[str, object] = {"max_len": 512, "head_max_len": 80}

        def predict(
            self, state: dict[str, object], questions: dict[str, dict[str, object]]
        ) -> dict[str, object]:
            return {"answers": {key: {"noul": 0.8} for key in questions}}

    process = _FakeProcess(
        response=lambda request: laya_worker._handle(  # pyright: ignore[reportPrivateUsage]
            cast(laya_worker._LayaAgent, Agent()),  # pyright: ignore[reportPrivateUsage]
            request,
        )
    )
    runtime = LayaSubprocessRuntime(
        _config(tmp_path),
        popen_factory=_factory(process),
        available_ram_reader=lambda: 8 * 1024**3,
    )
    captures: list[tuple[str, int, dict[str, object], LayaWorkerPresentation]] = []
    try:
        result = runtime.attend(
            state={"symptom": "private-path"},
            evidence=(),
            candidates=(
                {"probe_id": "one", "description": "Check first"},
                {"probe_id": "two", "description": "Check second"},
            ),
            timeout_seconds=1,
            capture_exact_worker_call=lambda phase, index, call, proof: captures.append(
                (phase, index, call, proof)
            ),
        )
        assert len(captures) == 1
        phase, index, call, proof = captures[0]
        assert (phase, index) == ("probe", 0)
        assert result.microbatches[0].worker_presentation == proof
        assert result.microbatches[0].candidate_ids == ("one", "two")
        rows = cast(list[dict[str, object]], call["questions"])
        assert list(dict.fromkeys(row["item_id"] for row in rows)) == ["one", "two"]
        assert not hasattr(result, "exact_worker_call")

        def same_batch(**kwargs: object) -> object:
            return kwargs["predicted"]

        monkeypatch.setattr(exact, "_upstream_model_batch", same_batch)
        parity = loader.verify_ephemeral_probe_batch(
            result,
            batch_index=0,
            exact_worker_call=call,
            worker_presentation=proof,
            tokenizer=Tokenizer(),
            cfg={"max_len": 512, "head_max_len": 80},
            qualification={"status": "pass", **exact._PINNED},  # pyright: ignore[reportPrivateUsage]
        )
        assert parity.candidate_ids == ("one", "two")
        assert parity.model_batch.input_ids
        assert parity.trainable is False
        with pytest.raises(ValueError, match="presentation mismatch"):
            loader.verify_ephemeral_probe_batch(
                result,
                batch_index=0,
                exact_worker_call={**call, "state": {"symptom": "tampered"}},
                worker_presentation=proof,
                tokenizer=Tokenizer(),
                cfg={"max_len": 512, "head_max_len": 80},
                qualification={"status": "pass", **exact._PINNED},  # pyright: ignore[reportPrivateUsage]
            )
    finally:
        runtime.close()


def test_exact_capture_rejects_worker_content_not_bound_to_presentation(tmp_path: Path) -> None:
    from systemsense.inference import laya_worker

    class Tokenizer:
        mask_token = "[MASK]"
        mask_token_id = 1

        def __call__(self, text: str, *, add_special_tokens: bool = False) -> dict[str, object]:
            return {"input_ids": [len(part) for part in text.split()]}

    class Agent:
        tok = Tokenizer()

        def __init__(self) -> None:
            self.cfg: dict[str, object] = {"max_len": 512, "head_max_len": 80}

        def predict(
            self, state: dict[str, object], questions: dict[str, dict[str, object]]
        ) -> dict[str, object]:
            return {"answers": {key: {"noul": 0.8} for key in questions}}

    def tampered(request: dict[str, object]) -> dict[str, object]:
        response = laya_worker._handle(  # pyright: ignore[reportPrivateUsage]
            cast(laya_worker._LayaAgent, Agent()),  # pyright: ignore[reportPrivateUsage]
            request,
        )
        exact = cast(dict[str, object], response["exact_worker_call"])
        exact["state"] = {"symptom": "tampered"}
        return response

    process = _FakeProcess(response=tampered)
    runtime = LayaSubprocessRuntime(
        _config(tmp_path),
        popen_factory=_factory(process),
        available_ram_reader=lambda: 8 * 1024**3,
    )
    seen: list[dict[str, object]] = []
    try:
        with pytest.raises(LayaRuntimeError, match="invalid ranking"):
            runtime.rank(
                state={"symptom": "original"},
                candidates=({"probe_id": "one", "description": "Check first"},),
                timeout_seconds=1,
                capture_exact_worker_call=lambda call, _proof: seen.append(call),
            )
        assert seen == []
        assert process.returncode is not None
    finally:
        runtime.close()


def test_prewarm_uses_fixed_registered_probe_and_reuses_worker(tmp_path: Path) -> None:
    process = _FakeProcess()
    starts = 0

    def start(*_args: object, **_kwargs: object) -> _FakeProcess:
        nonlocal starts
        starts += 1
        return process

    runtime = LayaSubprocessRuntime(
        _config(tmp_path),
        popen_factory=cast(PopenFactory, start),
        available_ram_reader=lambda: 8 * 1024**3,
    )
    runtime.prewarm(timeout_seconds=1)
    assert len(process.stdin.requests) == 1
    request = process.stdin.requests[0]
    assert request["candidates"] == [
        {"probe_id": "core.system", "description": "Read-only registered system snapshot"}
    ]
    assert request["state"] == {"attention_kind": "probe_relevance", "symptom": "worker readiness"}
    assert runtime.rank(
        state={"symptom": "case"},
        candidates=({"probe_id": "core.system", "description": "system"},),
        timeout_seconds=1,
    ) == ("core.system",)
    assert starts == 1
    runtime.close()


def test_cold_worker_start_is_bounded_by_request_deadline(tmp_path: Path) -> None:
    process = _FakeProcess()
    starts = 0

    def slow_start(*_args: object, **_kwargs: object) -> _FakeProcess:
        nonlocal starts
        starts += 1
        time.sleep(0.15)
        return process

    runtime = LayaSubprocessRuntime(
        _config(tmp_path),
        popen_factory=cast(PopenFactory, slow_start),
        available_ram_reader=lambda: 8 * 1024**3,
    )
    started = time.monotonic()
    with pytest.raises(LayaRuntimeError, match="deadline"):
        runtime.rank(
            state={"symptom": "cold"},
            candidates=({"probe_id": "probe.one", "description": "probe"},),
            timeout_seconds=0.02,
        )
    assert time.monotonic() - started < 0.10
    time.sleep(0.20)
    assert starts == 1
    assert process.returncode == 1
    runtime.close()


def test_cancellation_abandons_cold_worker_without_waiting_for_startup(tmp_path: Path) -> None:
    process = _FakeProcess()

    def slow_start(*_args: object, **_kwargs: object) -> _FakeProcess:
        time.sleep(0.15)
        return process

    runtime = LayaSubprocessRuntime(
        _config(tmp_path),
        popen_factory=cast(PopenFactory, slow_start),
        available_ram_reader=lambda: 8 * 1024**3,
    )
    cancelled = threading.Event()
    threading.Timer(0.02, cancelled.set).start()
    started = time.monotonic()
    with inference_cancellation(cancelled), pytest.raises(LayaRuntimeError, match="cancelled"):
        runtime.rank(
            state={"symptom": "cold"},
            candidates=({"probe_id": "probe.one", "description": "probe"},),
            timeout_seconds=1,
        )
    assert time.monotonic() - started < 0.10
    time.sleep(0.20)
    assert process.returncode == 1
    runtime.close()


def test_worker_pipe_write_cannot_extend_request_deadline(tmp_path: Path) -> None:
    process = _FakeProcess()
    original_write = process.stdin.write

    def slow_write(payload: bytes) -> int:
        time.sleep(0.15)
        return original_write(payload)

    process.stdin.write = slow_write  # type: ignore[method-assign]
    runtime = LayaSubprocessRuntime(
        _config(tmp_path),
        popen_factory=_factory(process),
        available_ram_reader=lambda: 8 * 1024**3,
    )
    started = time.monotonic()
    with pytest.raises(LayaRuntimeError, match="deadline"):
        runtime.rank(
            state={"symptom": "slow pipe"},
            candidates=({"probe_id": "probe.one", "description": "probe"},),
            timeout_seconds=0.02,
        )
    assert time.monotonic() - started < 0.10
    assert process.returncode == 1


def test_timed_out_write_does_not_wait_for_blocked_pipe_close(tmp_path: Path) -> None:
    process = _FakeProcess()
    write_started = threading.Event()
    release_write = threading.Event()
    close_completed = threading.Event()

    def blocked_write(payload: bytes) -> int:
        del payload
        write_started.set()
        release_write.wait(timeout=0.4)
        return 0

    def blocked_close() -> None:
        release_write.wait(timeout=0.4)
        close_completed.set()

    process.stdin.write = blocked_write  # type: ignore[method-assign]
    process.stdin.close = blocked_close  # type: ignore[method-assign]
    runtime = LayaSubprocessRuntime(
        _config(tmp_path),
        popen_factory=_factory(process),
        available_ram_reader=lambda: 8 * 1024**3,
    )
    started = time.monotonic()
    with pytest.raises(LayaRuntimeError, match="deadline"):
        runtime.rank(
            state={},
            candidates=({"probe_id": "probe.one", "description": "probe"},),
            timeout_seconds=0.02,
        )
    assert write_started.is_set()
    assert time.monotonic() - started < 0.15
    assert process.returncode == 1
    release_write.set()
    assert close_completed.wait(timeout=1)


def test_retired_reader_cannot_feed_a_restarted_workers_response_queue(tmp_path: Path) -> None:
    old = _FakeProcess()
    replacement = _FakeProcess(response=False)
    old_readline = old.stdout.readline
    second_read_started = threading.Event()
    release_old_read = threading.Event()
    reads = 0

    def paused_old_read(limit: int = -1) -> bytes:
        nonlocal reads
        reads += 1
        if reads == 2:
            second_read_started.set()
            release_old_read.wait(timeout=1)
        return old_readline(limit)

    old.stdout.readline = paused_old_read  # type: ignore[method-assign]
    starts = 0

    def start(*_args: object, **_kwargs: object) -> _FakeProcess:
        nonlocal starts
        starts += 1
        if starts == 2:
            release_old_read.set()
            return replacement
        return old

    runtime = LayaSubprocessRuntime(
        _config(tmp_path),
        popen_factory=cast(PopenFactory, start),
        available_ram_reader=lambda: 8 * 1024**3,
    )
    candidates = ({"probe_id": "probe.one", "description": "probe"},)
    assert runtime.rank(state={}, candidates=candidates, timeout_seconds=1) == ("probe.one",)
    assert second_read_started.wait(timeout=1)
    runtime.close()
    with pytest.raises(LayaRuntimeError, match="deadline"):
        runtime.rank(state={}, candidates=candidates, timeout_seconds=0.1)
    assert starts == 2
    runtime.close()


def test_timed_out_startup_does_not_spawn_a_second_worker_while_first_is_pending(
    tmp_path: Path,
) -> None:
    launch_started = threading.Event()
    release_launch = threading.Event()
    processes: list[_FakeProcess] = []

    def start(*_args: object, **_kwargs: object) -> _FakeProcess:
        process = _FakeProcess()
        processes.append(process)
        launch_started.set()
        release_launch.wait(timeout=1)
        return process

    runtime = LayaSubprocessRuntime(
        _config(tmp_path),
        popen_factory=cast(PopenFactory, start),
        available_ram_reader=lambda: 8 * 1024**3,
    )
    candidates = ({"probe_id": "probe.one", "description": "probe"},)
    with pytest.raises(LayaRuntimeError, match="deadline"):
        runtime.rank(state={}, candidates=candidates, timeout_seconds=0.02)
    assert launch_started.is_set()
    with pytest.raises(LayaRuntimeError, match="cancell"):
        runtime.rank(state={}, candidates=candidates, timeout_seconds=0.02)
    assert len(processes) == 1
    release_launch.set()
    time.sleep(0.05)
    assert processes[0].returncode == 1
    assert runtime.rank(state={}, candidates=candidates, timeout_seconds=1) == ("probe.one",)
    assert len(processes) == 2
    runtime.close()


@pytest.mark.parametrize("device", ["cpu", "cuda"])
@pytest.mark.parametrize("available_ram", [None, 4 * 1024**3])
def test_cold_laya_worker_refuses_unknown_or_low_host_ram_before_spawn(
    tmp_path: Path,
    device: Literal["cpu", "cuda"],
    available_ram: int | None,
) -> None:
    starts: list[int] = []

    def start(*_args: object, **_kwargs: object) -> _FakeProcess:
        starts.append(1)
        return _FakeProcess()

    runtime = LayaSubprocessRuntime(
        _config(tmp_path, device=device),
        popen_factory=cast(PopenFactory, start),
        available_ram_reader=lambda: available_ram,
    )
    with pytest.raises(LayaRuntimeError, match="RAM"):
        runtime.rank(
            state={"symptom": "slow computer"},
            candidates=({"probe_id": "core.system", "description": "system"},),
            timeout_seconds=1,
        )
    assert starts == []


@pytest.mark.parametrize("device", ["cpu", "cuda"])
def test_laya_worker_rechecks_ram_before_restart_without_evicting_other_workloads(
    tmp_path: Path,
    device: Literal["cpu", "cuda"],
) -> None:
    available_ram = 8 * 1024**3
    starts: list[_FakeProcess] = []

    def start(*_args: object, **_kwargs: object) -> _FakeProcess:
        process = _FakeProcess()
        starts.append(process)
        return process

    runtime = LayaSubprocessRuntime(
        _config(tmp_path, device=device),
        popen_factory=cast(PopenFactory, start),
        available_ram_reader=lambda: available_ram,
    )
    candidates = ({"probe_id": "core.system", "description": "system"},)
    assert runtime.rank(state={"symptom": "slow"}, candidates=candidates, timeout_seconds=1)
    assert len(starts) == 1
    starts[0].returncode = 1
    available_ram = 4 * 1024**3

    with pytest.raises(LayaRuntimeError, match="RAM"):
        runtime.rank(state={"symptom": "still slow"}, candidates=candidates, timeout_seconds=1)
    assert len(starts) == 1
    runtime.close()


def test_laya_worker_fails_closed_if_ram_measurement_raises(tmp_path: Path) -> None:
    starts: list[int] = []

    def failed_reader() -> int | None:
        raise RuntimeError("memory source unavailable")

    def start(*_args: object, **_kwargs: object) -> _FakeProcess:
        starts.append(1)
        return _FakeProcess()

    runtime = LayaSubprocessRuntime(
        _config(tmp_path),
        popen_factory=cast(PopenFactory, start),
        available_ram_reader=failed_reader,
    )
    with pytest.raises(LayaRuntimeError, match="RAM"):
        runtime.rank(
            state={"symptom": "slow"},
            candidates=({"probe_id": "core.system", "description": "system"},),
            timeout_seconds=1,
        )
    assert starts == []


def test_cuda_runtime_is_explicit_bounded_and_keeps_hub_offline(tmp_path: Path) -> None:
    calls: list[tuple[list[str], dict[str, str]]] = []
    process = _FakeProcess()

    def start(command: list[str], **kwargs: object) -> _FakeProcess:
        calls.append((command, kwargs["env"]))  # type: ignore[index]
        return process

    config = _config(tmp_path, device="cuda", precision="float16")
    runtime = LayaSubprocessRuntime(
        config,
        popen_factory=cast(PopenFactory, start),
        available_ram_reader=lambda: 8 * 1024**3,
    )
    runtime.rank(
        state={"symptom": "freeze"},
        candidates=({"probe_id": "core.system", "description": "system"},),
        timeout_seconds=1,
    )

    command, environment = calls[0]
    assert command[command.index("--device") + 1] == "cuda"
    assert command[command.index("--precision") + 1] == "float16"
    assert command[command.index("--min-free-vram-mb") + 1] == "1536"
    assert environment["CUDA_VISIBLE_DEVICES"] == "0"
    assert environment["HF_HUB_OFFLINE"] == "1"
    runtime.close()


def test_runtime_terminates_worker_on_timeout_or_invalid_response(tmp_path: Path) -> None:
    class WarmableRuntime(LayaSubprocessRuntime):
        def start_worker_for_test(self) -> object:
            return self._ready_process(time.monotonic() + 1, None)

    timeout_process = _FakeProcess(response=False)
    timeout_runtime = WarmableRuntime(
        _config(tmp_path),
        popen_factory=_factory(timeout_process),
        available_ram_reader=lambda: 8 * 1024**3,
    )
    # A separate test covers cold-start deadlines. Start this worker first so
    # the short timeout tests response handling rather than startup scheduling.
    assert timeout_runtime.start_worker_for_test() is timeout_process
    with pytest.raises(LayaRuntimeError, match="deadline"):
        timeout_runtime.rank(
            state={"symptom": "slow"},
            candidates=({"probe_id": "core.system", "description": "system"},),
            timeout_seconds=0.01,
        )
    assert timeout_process.returncode == 1
    timeout_runtime.close()

    invalid_process = _FakeProcess(
        response={
            "protocol_version": 1,
            "request_id": "wrong",
            "ranked_probe_ids": ["unknown.probe"],
        }
    )
    invalid_runtime = LayaSubprocessRuntime(
        _config(tmp_path),
        popen_factory=_factory(invalid_process),
        available_ram_reader=lambda: 8 * 1024**3,
    )
    with pytest.raises(LayaRuntimeError, match="invalid"):
        invalid_runtime.rank(
            state={"symptom": "slow"},
            candidates=({"probe_id": "core.system", "description": "system"},),
            timeout_seconds=1,
        )
    invalid_runtime.close()


def test_unreaped_worker_retains_ownership_and_blocks_restart(tmp_path: Path) -> None:
    class UnreapableProcess(_FakeProcess):
        def __init__(self) -> None:
            super().__init__(response=False)
            self.terminate_calls = 0
            self.kill_calls = 0

        def terminate(self) -> None:
            self.terminate_calls += 1

        def wait(self, timeout: float | None = None) -> int:
            raise subprocess.TimeoutExpired("laya-worker", timeout or 0)

        def kill(self) -> None:
            self.kill_calls += 1

    process = UnreapableProcess()
    starts = 0

    def start(*_args: object, **_kwargs: object) -> _FakeProcess:
        nonlocal starts
        starts += 1
        return process

    runtime = LayaSubprocessRuntime(
        _config(tmp_path),
        popen_factory=cast(PopenFactory, start),
        available_ram_reader=lambda: 8 * 1024**3,
    )
    candidates = ({"probe_id": "probe.one", "description": "probe"},)
    with pytest.raises(LayaRuntimeError, match="termination could not be verified"):
        runtime.rank(state={}, candidates=candidates, timeout_seconds=0.1)
    assert process.terminate_calls == 1
    assert process.kill_calls == 1
    assert runtime._process is process  # pyright: ignore[reportPrivateUsage]
    with pytest.raises(LayaRuntimeError, match="termination could not be verified"):
        runtime.rank(state={}, candidates=candidates, timeout_seconds=0.1)
    assert starts == 1

    process.returncode = 1
    runtime.close()
    assert runtime._process is None  # pyright: ignore[reportPrivateUsage]


def test_managed_launch_records_identity_before_releasing_model_load(tmp_path: Path) -> None:
    process = _FakeProcess()
    order: list[str] = []

    def start(command: list[str], **_kwargs: object) -> _FakeProcess:
        launch_id = command[command.index("--launch-id") + 1]
        process.stdout.lines.put(
            json.dumps(
                {"protocol_version": 1, "event": "awaiting_admission", "launch_id": launch_id}
            ).encode()
            + b"\n"
        )
        return process

    def admit(pid: int, created_at: float) -> bool:
        assert (pid, created_at) == (4242, 123.0)
        assert process.stdin.requests == []
        order.append("identity_persisted")
        return True

    runtime = LayaSubprocessRuntime(
        _config(tmp_path),
        popen_factory=cast(PopenFactory, start),
        available_ram_reader=lambda: 8 * 1024**3,
        process_identity_reader=lambda _pid: 123.0,
        startup_admission=admit,
    )
    assert runtime.rank(
        state={},
        candidates=({"probe_id": "probe.one", "description": "probe"},),
        timeout_seconds=1,
    ) == ("probe.one",)
    assert order == ["identity_persisted"]
    assert process.stdin.requests[0]["command"] == "admit_load"
    assert process.stdin.requests[1]["candidates"] == [
        {"probe_id": "probe.one", "description": "probe"}
    ]
    runtime.close()


def test_tree_launch_assigns_before_resume_and_keeps_job_open_for_release(tmp_path: Path) -> None:
    process = _FakeProcess()
    events: list[str] = []

    class FakeJob:
        def __init__(self) -> None:
            self.assigned = False
            self.empty = False
            self.closed = False

        def assign_suspended(self, worker: object) -> None:
            assert worker is process
            events.append("assigned")
            self.assigned = True

        def resume_assigned(self, worker: object) -> None:
            assert worker is process and self.assigned
            events.append("resumed")

        def is_assigned_worker(self, worker: object) -> bool:
            return self.assigned and worker is process and not self.closed

        def wait_until_empty(self, timeout_seconds: float) -> bool:
            assert not self.closed
            assert timeout_seconds >= 0
            return self.empty

        def terminate_processes(self) -> None:
            events.append("terminated")
            self.empty = True
            process.returncode = 1

        def close(self) -> None:
            events.append("job_closed")
            self.closed = True

    job = FakeJob()

    def start(command: list[str], **kwargs: object) -> _FakeProcess:
        assert cast(int, kwargs["creationflags"]) & 0x00000004
        launch_id = command[command.index("--launch-id") + 1]
        process.stdout.lines.put(
            json.dumps(
                {"protocol_version": 1, "event": "awaiting_admission", "launch_id": launch_id}
            ).encode()
            + b"\n"
        )
        events.append("spawned")
        return process

    def admit(_pid: int, _created_at: float) -> bool:
        events.append("admitted")
        assert runtime.tree_custody is not None
        assert runtime.tree_custody.is_open()
        assert process.stdin.requests == []
        return True

    runtime = LayaSubprocessRuntime(
        _config(tmp_path),
        popen_factory=cast(PopenFactory, start),
        available_ram_reader=lambda: 8 * 1024**3,
        process_identity_reader=lambda _pid: 123.0,
        startup_admission=admit,
        tree_custody_enabled=True,
        job_factory=lambda: job,
    )
    assert runtime.rank(
        state={},
        candidates=({"probe_id": "probe.one", "description": "probe"},),
        timeout_seconds=1,
    ) == ("probe.one",)
    assert events[:4] == ["spawned", "assigned", "resumed", "admitted"]
    runtime.close()
    assert not job.closed
    assert runtime.tree_custody is not None and runtime.tree_custody.is_empty()
    runtime.release_tree_custody()
    assert job.closed


def test_tree_assignment_failure_kills_suspended_root_without_load_token(tmp_path: Path) -> None:
    process = _FakeProcess()

    class RejectingJob:
        closed = False

        def assign_suspended(self, worker: object) -> None:
            assert worker is process
            raise RuntimeError("assignment denied")

        def resume_assigned(self, worker: object) -> None:
            raise AssertionError(f"unexpected resume: {worker!r}")

        def is_assigned_worker(self, worker: object) -> bool:
            return worker is process and not self.closed

        def terminate_processes(self) -> None:
            pass

        def wait_until_empty(self, timeout_seconds: float) -> bool:
            assert timeout_seconds >= 0
            return True

        def close(self) -> None:
            self.closed = True

    job = RejectingJob()

    def start(_command: list[str], **_kwargs: object) -> _FakeProcess:
        return process

    runtime = LayaSubprocessRuntime(
        _config(tmp_path),
        popen_factory=cast(PopenFactory, start),
        available_ram_reader=lambda: 8 * 1024**3,
        startup_admission=lambda _pid, _created_at: True,
        tree_custody_enabled=True,
        job_factory=lambda: job,
    )
    with pytest.raises(LayaRuntimeError, match="startup failed"):
        runtime.rank(
            state={},
            candidates=({"probe_id": "probe.one", "description": "probe"},),
            timeout_seconds=1,
        )
    assert process.returncode == 1
    assert process.stdin.requests == []
    assert job.closed


def test_denied_managed_launch_never_releases_model_load(tmp_path: Path) -> None:
    process = _FakeProcess()

    def start(command: list[str], **_kwargs: object) -> _FakeProcess:
        launch_id = command[command.index("--launch-id") + 1]
        process.stdout.lines.put(
            json.dumps(
                {"protocol_version": 1, "event": "awaiting_admission", "launch_id": launch_id}
            ).encode()
            + b"\n"
        )
        return process

    runtime = LayaSubprocessRuntime(
        _config(tmp_path),
        popen_factory=cast(PopenFactory, start),
        available_ram_reader=lambda: 8 * 1024**3,
        process_identity_reader=lambda _pid: 123.0,
        startup_admission=lambda _pid, _created_at: False,
    )
    with pytest.raises(LayaRuntimeError, match="admission denied"):
        runtime.rank(
            state={},
            candidates=({"probe_id": "probe.one", "description": "probe"},),
            timeout_seconds=1,
        )
    assert process.stdin.requests == []
    assert process.returncode == 1


def test_late_admission_callback_cannot_release_cancelled_worker(tmp_path: Path) -> None:
    process = _FakeProcess()
    callback_entered = threading.Event()
    release_callback = threading.Event()
    callback_finished = threading.Event()

    def start(command: list[str], **_kwargs: object) -> _FakeProcess:
        launch_id = command[command.index("--launch-id") + 1]
        process.stdout.lines.put(
            json.dumps(
                {"protocol_version": 1, "event": "awaiting_admission", "launch_id": launch_id}
            ).encode()
            + b"\n"
        )
        return process

    def admit(_pid: int, _created_at: float) -> bool:
        callback_entered.set()
        release_callback.wait(timeout=1)
        callback_finished.set()
        return True

    runtime = LayaSubprocessRuntime(
        _config(tmp_path),
        popen_factory=cast(PopenFactory, start),
        available_ram_reader=lambda: 8 * 1024**3,
        process_identity_reader=lambda _pid: 123.0,
        startup_admission=admit,
    )
    try:
        with pytest.raises(LayaRuntimeError, match="deadline"):
            runtime.rank(
                state={},
                candidates=({"probe_id": "probe.one", "description": "probe"},),
                timeout_seconds=0.05,
            )
        assert callback_entered.is_set()
        assert process.returncode == 1
    finally:
        release_callback.set()
        assert callback_finished.wait(timeout=1)
        runtime.close()
    assert process.stdin.requests == []


def test_warm_worker_rechecks_call_admission_and_retires_on_denial(tmp_path: Path) -> None:
    process = _FakeProcess()
    decisions = iter((True, False))
    calls: list[tuple[int, float]] = []

    def start(command: list[str], **_kwargs: object) -> _FakeProcess:
        launch_id = command[command.index("--launch-id") + 1]
        process.stdout.lines.put(
            json.dumps(
                {"protocol_version": 1, "event": "awaiting_admission", "launch_id": launch_id}
            ).encode()
            + b"\n"
        )
        return process

    def admit_call(pid: int, created_at: float) -> bool:
        calls.append((pid, created_at))
        return next(decisions)

    runtime = LayaSubprocessRuntime(
        _config(tmp_path),
        popen_factory=cast(PopenFactory, start),
        available_ram_reader=lambda: 8 * 1024**3,
        process_identity_reader=lambda _pid: 123.0,
        call_admission=admit_call,
    )
    runtime.prewarm(timeout_seconds=1)
    assert calls == [(4242, 123.0)]
    with pytest.raises(LayaRuntimeError, match="call admission denied"):
        runtime.rank(
            state={},
            candidates=({"probe_id": "probe.one", "description": "probe"},),
            timeout_seconds=1,
        )
    assert calls == [(4242, 123.0), (4242, 123.0)]
    assert len(process.stdin.requests) == 2  # load token, then prewarm only
    assert process.returncode == 1


def test_call_admission_exception_retires_worker_without_rank_write(tmp_path: Path) -> None:
    process = _FakeProcess()

    def start(command: list[str], **_kwargs: object) -> _FakeProcess:
        launch_id = command[command.index("--launch-id") + 1]
        process.stdout.lines.put(
            json.dumps(
                {"protocol_version": 1, "event": "awaiting_admission", "launch_id": launch_id}
            ).encode()
            + b"\n"
        )
        return process

    def fail(_pid: int, _created_at: float) -> bool:
        raise RuntimeError("ledger unavailable")

    runtime = LayaSubprocessRuntime(
        _config(tmp_path),
        popen_factory=cast(PopenFactory, start),
        available_ram_reader=lambda: 8 * 1024**3,
        process_identity_reader=lambda _pid: 123.0,
        call_admission=fail,
    )
    with pytest.raises(LayaRuntimeError, match="call admission failed"):
        runtime.rank(
            state={},
            candidates=({"probe_id": "probe.one", "description": "probe"},),
            timeout_seconds=1,
        )
    assert len(process.stdin.requests) == 1  # load token only
    assert process.returncode == 1


def test_call_admission_rejects_identity_drift_before_rank_write(tmp_path: Path) -> None:
    process = _FakeProcess()
    observed_times = iter((123.0, 123.0, 124.0))

    def start(command: list[str], **_kwargs: object) -> _FakeProcess:
        launch_id = command[command.index("--launch-id") + 1]
        process.stdout.lines.put(
            json.dumps(
                {"protocol_version": 1, "event": "awaiting_admission", "launch_id": launch_id}
            ).encode()
            + b"\n"
        )
        return process

    runtime = LayaSubprocessRuntime(
        _config(tmp_path),
        popen_factory=cast(PopenFactory, start),
        available_ram_reader=lambda: 8 * 1024**3,
        process_identity_reader=lambda _pid: next(observed_times),
        call_admission=lambda _pid, _created_at: True,
    )
    with pytest.raises(LayaRuntimeError, match="identity changed"):
        runtime.rank(
            state={},
            candidates=({"probe_id": "probe.one", "description": "probe"},),
            timeout_seconds=1,
        )
    assert len(process.stdin.requests) == 1  # load token only
    assert process.returncode == 1


def test_call_admission_requires_literal_true(tmp_path: Path) -> None:
    process = _FakeProcess()

    def non_boolean_admission(_pid: int, _created_at: float) -> int:
        return 1

    def start(command: list[str], **_kwargs: object) -> _FakeProcess:
        launch_id = command[command.index("--launch-id") + 1]
        process.stdout.lines.put(
            json.dumps(
                {"protocol_version": 1, "event": "awaiting_admission", "launch_id": launch_id}
            ).encode()
            + b"\n"
        )
        return process

    runtime = LayaSubprocessRuntime(
        _config(tmp_path),
        popen_factory=cast(PopenFactory, start),
        available_ram_reader=lambda: 8 * 1024**3,
        process_identity_reader=lambda _pid: 123.0,
        call_admission=cast(Callable[[int, float], bool], non_boolean_admission),
    )
    with pytest.raises(LayaRuntimeError, match="call admission denied"):
        runtime.rank(
            state={},
            candidates=({"probe_id": "probe.one", "description": "probe"},),
            timeout_seconds=1,
        )
    assert len(process.stdin.requests) == 1


def test_close_does_not_claim_exit_while_child_spawn_is_unresolved(tmp_path: Path) -> None:
    launch_entered = threading.Event()
    release_launch = threading.Event()
    process = _FakeProcess()

    def start(*_args: object, **_kwargs: object) -> _FakeProcess:
        launch_entered.set()
        release_launch.wait(timeout=2)
        return process

    runtime = LayaSubprocessRuntime(
        _config(tmp_path),
        popen_factory=cast(PopenFactory, start),
        available_ram_reader=lambda: 8 * 1024**3,
    )
    try:
        with pytest.raises(LayaRuntimeError, match="deadline"):
            runtime.rank(
                state={},
                candidates=({"probe_id": "probe.one", "description": "probe"},),
                timeout_seconds=0.03,
            )
        assert launch_entered.is_set()
        with pytest.raises(LayaRuntimeError, match="startup exit could not be verified"):
            runtime.close()
    finally:
        release_launch.set()
        time.sleep(0.05)
        runtime.close()
    assert process.returncode == 1


def test_attention_covers_every_evidence_fragment_and_probe_batch(tmp_path: Path) -> None:
    process = _FakeProcess()
    runtime = LayaSubprocessRuntime(
        _config(tmp_path),
        popen_factory=_factory(process),
        available_ram_reader=lambda: 8 * 1024**3,
    )
    evidence = tuple(
        {
            "evidence_id": f"evd_{index:032x}",
            "fragment_id": f"evd_{index:032x}:{fragment}",
            "description": f"evidence {index} fragment {fragment}",
        }
        for index in range(3)
        for fragment in range(2)
    )
    candidates = tuple(
        {"probe_id": f"probe.{index}", "description": f"probe {index}"} for index in range(25)
    )

    attention = runtime.attend(
        state={"symptom": "intermittent freeze"},
        evidence=evidence,
        candidates=candidates,
        timeout_seconds=2,
    )

    assert set(attention.ranked_evidence_ids) == {f"evd_{index:032x}" for index in range(3)}
    assert set(attention.ranked_probe_ids) == {f"probe.{index}" for index in range(25)}
    assert set(attention.considered_probe_ids) == set(attention.ranked_probe_ids)
    assert set(attention.considered_evidence_ids) == set(attention.ranked_evidence_ids)
    assert len(process.stdin.requests) == 3  # one evidence batch plus two probe batches
    assert "probe_batches=2" in attention.attention_notes
    assert len(attention.microbatches) == 3
    assert all(batch.worker_presentation is None for batch in attention.microbatches)
    assert [len(batch.inference_ids) for batch in attention.microbatches] == [6, 20, 5]
    probe_state = process.stdin.requests[1]["state"]
    assert isinstance(probe_state, dict)
    focused_context = cast(list[dict[str, str]], probe_state["ranked_evidence_context"])
    assert isinstance(focused_context, list)
    assert focused_context[0]["content"].startswith("evidence")
    assert focused_context[0]["evidence_id"].startswith("evd_")

    repeated = runtime.attend(
        state={"symptom": "intermittent freeze"},
        evidence=evidence,
        candidates=candidates,
        timeout_seconds=2,
    )
    assert repeated.ranked_probe_ids == attention.ranked_probe_ids
    assert len(process.stdin.requests) == 3
    assert "cache_hits=31" in repeated.attention_notes
    assert all(not batch.inference_ids for batch in repeated.microbatches)
    assert sum(len(batch.cache_hit_ids) for batch in repeated.microbatches) == 31


def test_probe_ranking_receives_fact_with_timing_from_preview(tmp_path: Path) -> None:
    process = _FakeProcess()
    runtime = LayaSubprocessRuntime(
        _config(tmp_path),
        popen_factory=_factory(process),
        available_ram_reader=lambda: 8 * 1024**3,
    )
    preview = json.dumps(
        {
            "projection": "bounded_preview_not_full_page",
            "status": "partial",
            "facts_omitted": 4,
            "fact_values_truncated": 1,
            "probe_id": "disk.health",
            "observed_at": "2026-09-23T12:00:00+00:00",
            "captured_at": "2026-09-23T12:00:10+00:00",
            "redaction_applied": True,
            "summary": "routine metadata " * 7,
            "limitations": ["some counters unavailable"],
            "facts": {"disk.latency": {"value": 820, "unit": "ms"}},
        },
        separators=(",", ":"),
    )
    runtime.attend(
        state={"symptom": "disk stalls"},
        evidence=(
            {
                "evidence_id": "evd_" + "1" * 32,
                "page_id": "evd_" + "1" * 32 + ":0",
                "fragment_id": "evd_" + "1" * 32 + ":0:preview:0",
                "description": preview,
            },
        ),
        candidates=({"probe_id": "disk.snapshot", "description": "disk snapshot"},),
        timeout_seconds=2,
    )
    probe_state = process.stdin.requests[1]["state"]
    assert isinstance(probe_state, dict)
    focused = cast(list[dict[str, str]], probe_state["ranked_evidence_context"])
    content = focused[0]["content"]
    assert len(content) <= 240
    packet = json.loads(content)
    assert packet["facts"] == {"disk.latency": {"value": 820, "unit": "ms"}}
    assert packet["fact_values_truncated"] == 1
    assert packet["observed_at"] == "2026-09-23T12:00:00+00:00"
    assert packet["captured_at"] == "2026-09-23T12:00:10+00:00"
    assert packet["status"] == "partial"


def test_probe_focus_keeps_semantic_metric_value_unit_and_quality(tmp_path: Path) -> None:
    process = _FakeProcess()
    runtime = LayaSubprocessRuntime(
        _config(tmp_path),
        popen_factory=_factory(process),
        available_ram_reader=lambda: 8 * 1024**3,
    )
    description = json.dumps(
        {
            "projection": "semantic_fact_packets_v1",
            "packet_kind": "fact",
            "metric": "gpu.clock",
            "value": {"value": 450, "unit": "MHz"},
            "unit": "MHz",
            "value_quality": "exact",
            "status": "observed",
            "observed_at": "2026-09-23T12:00:00+00:00",
            "captured_at": "2026-09-23T12:00:10+00:00",
            "facts_omitted": 8,
        },
        separators=(",", ":"),
    )
    runtime.attend(
        state={"symptom": "GPU game is slow", "evidence_serializer": "semantic_fact_packets_v1"},
        evidence=(
            {
                "evidence_id": "evd_" + "1" * 32,
                "page_id": "evd_" + "1" * 32 + ":0",
                "fragment_id": "evd_" + "1" * 32 + ":0:fact:" + "a" * 64,
                "description": description,
            },
        ),
        candidates=({"probe_id": "gpu.snapshot", "description": "GPU snapshot"},),
        timeout_seconds=2,
    )
    probe_state = process.stdin.requests[1]["state"]
    assert isinstance(probe_state, dict)
    focused = cast(list[dict[str, str]], probe_state["ranked_evidence_context"])
    packet = json.loads(focused[0]["content"])
    assert packet["metric"] == "gpu.clock"
    assert packet["value"] == {"value": 450, "unit": "MHz"}
    assert packet["unit"] == "MHz"
    assert packet["value_quality"] == "exact"
    assert packet["observed_at"] == "2026-09-23T12:00:00+00:00"
    assert packet["facts_omitted"] == 8


@pytest.mark.parametrize("gap_status", ["unsupported", "stale"])
def test_probe_context_reserves_gap_preview_without_inventing_fact(
    tmp_path: Path, gap_status: str
) -> None:
    def response(request: dict[str, object]) -> object:
        raw_candidates = request["candidates"]
        assert isinstance(raw_candidates, list)
        candidates = cast(list[dict[str, str]], raw_candidates)
        ids = [item["probe_id"] for item in candidates]
        scores = {item_id: 1 - index * 0.1 for index, item_id in enumerate(ids)}
        return {
            "protocol_version": 1,
            "request_id": request["request_id"],
            "ranked_probe_ids": ids,
            "relevance_scores": scores,
        }

    process = _FakeProcess(response=response)
    runtime = LayaSubprocessRuntime(
        _config(tmp_path),
        popen_factory=_factory(process),
        available_ram_reader=lambda: 8 * 1024**3,
    )
    evidence = tuple(
        {
            "evidence_id": f"evd_{index + 1:032x}",
            "page_id": f"evd_{index + 1:032x}:0",
            "fragment_id": f"evd_{index + 1:032x}:0:preview:0",
            "description": json.dumps(
                {
                    "projection": "bounded_preview_not_full_page",
                    "status": gap_status if index == 3 else "observed",
                    "observed_at": "2026-09-23T12:00:00+00:00",
                    "captured_at": "2026-09-23T12:00:10+00:00",
                    "probe_id": "disk.health",
                    "facts": {} if index == 3 else {f"disk.counter_{index}": index},
                    "facts_omitted": 0,
                },
                separators=(",", ":"),
            ),
        }
        for index in range(4)
    )
    result = runtime.attend(
        state={"symptom": "disk stalls", "coverage_notes": ["evidence_pages_are_bounded_previews"]},
        evidence=evidence,
        candidates=({"probe_id": "disk.snapshot", "description": "registered disk snapshot"},),
        timeout_seconds=2,
    )
    assert result.ranked_probe_ids == ("disk.snapshot",)
    probe_state = process.stdin.requests[1]["state"]
    assert isinstance(probe_state, dict)
    focused = cast(list[dict[str, str]], probe_state["ranked_evidence_context"])
    assert len(focused) == 3
    assert focused[0]["evidence_id"] == evidence[3]["evidence_id"]
    gap = json.loads(focused[0]["content"])
    assert gap["status"] == gap_status
    assert gap["preview"] is True
    assert gap["facts"] == {}


def test_attention_preserves_worker_digest_and_cache_origin(tmp_path: Path) -> None:
    digest = "a" * 64

    def response(request: dict[str, object]) -> object:
        candidates = cast(list[dict[str, str]], request["candidates"])
        ids = [item["probe_id"] for item in candidates]
        return {
            "protocol_version": 1,
            "request_id": request["request_id"],
            "ranked_probe_ids": ids,
            "relevance_scores": {item: 0.8 for item in ids},
            "presentation": {
                "schema_version": 1,
                "presentation_sha256": digest,
                "fitted_state_sha256": "b" * 64,
                "questions_sha256": "c" * 64,
                "presented_item_ids": ids,
                "fitted_state_tokens": 12,
                "state_tokens_original": 12,
                "state_fields_omitted": 0,
                "state_list_items_omitted": 0,
                "questions": [
                    {
                        "question_id": f"item_{index}_piece_0",
                        "item_id": item,
                        "question_sha256": "d" * 64,
                        "instruction_tokens": 20,
                        "instruction_presented_tokens": 20,
                        "criteria_tokens": 16,
                        "criteria_presented_tokens": 16,
                        "state_presented_tokens": 12,
                    }
                    for index, item in enumerate(ids)
                ],
            },
        }

    process = _FakeProcess(response=response)
    runtime = LayaSubprocessRuntime(
        _config(tmp_path),
        popen_factory=_factory(process),
        available_ram_reader=lambda: 8 * 1024**3,
    )
    candidates = (
        {"probe_id": "probe.one", "description": "private symptom description"},
        {"probe_id": "probe.two", "description": "another private description"},
    )
    first = runtime.attend(
        state={"symptom": "private symptom"}, evidence=(), candidates=candidates, timeout_seconds=2
    )
    assert len(first.microbatches) == 1
    batch = first.microbatches[0]
    assert batch.inference_ids == ("probe.one", "probe.two")
    assert batch.worker_presentation is not None
    assert batch.worker_presentation.presentation_sha256 == digest
    assert "private" not in batch.model_dump_json()

    second = runtime.attend(
        state={"symptom": "private symptom"}, evidence=(), candidates=candidates, timeout_seconds=2
    )
    assert len(process.stdin.requests) == 1
    assert second.microbatches[0].inference_ids == ()
    assert second.microbatches[0].cache_hit_ids == ("probe.one", "probe.two")
    assert {origin.presentation_sha256 for origin in second.microbatches[0].cached_origins} == {
        digest
    }


def test_preview_attention_reports_preview_coverage_not_full_page_completion(
    tmp_path: Path,
) -> None:
    runtime = LayaSubprocessRuntime(
        _config(tmp_path),
        popen_factory=_factory(_FakeProcess()),
        available_ram_reader=lambda: 8 * 1024**3,
    )
    evidence = tuple(
        {
            "evidence_id": f"evd_{index:032x}",
            "page_id": f"evd_{index:032x}:{index}",
            "fragment_id": f"evd_{index:032x}:{index}:preview:0",
            "description": '{"projection":"bounded_preview_not_full_page","facts_omitted":12}',
        }
        for index in range(3)
    )

    attention = runtime.attend(
        state={"coverage_notes": ["evidence_pages_are_bounded_previews"]},
        evidence=evidence,
        candidates=(),
        timeout_seconds=2,
    )

    assert "previews_considered=3_of_3" in attention.attention_notes
    assert not any(note.startswith("pages_complete=") for note in attention.attention_notes)
    runtime.close()


def test_attention_interleaves_batch_ranks_without_comparing_scores(tmp_path: Path) -> None:
    def response(request: dict[str, object]) -> object:
        candidates = request["candidates"]
        assert isinstance(candidates, list)
        typed_candidates = cast(list[dict[str, str]], candidates)
        ids = [item["probe_id"] for item in typed_candidates]
        scores = {probe_id: (0.99 if probe_id == "probe.24" else 0.1) for probe_id in ids}
        return {
            "protocol_version": 1,
            "request_id": request["request_id"],
            "ranked_probe_ids": sorted(ids, key=lambda probe_id: -scores[probe_id]),
            "relevance_scores": scores,
        }

    runtime = LayaSubprocessRuntime(
        _config(tmp_path),
        popen_factory=_factory(_FakeProcess(response=response)),
        available_ram_reader=lambda: 8 * 1024**3,
    )
    candidates = tuple(
        {"probe_id": f"probe.{index}", "description": f"probe {index}"} for index in range(25)
    )

    attention = runtime.attend(
        state={"symptom": "freeze"}, evidence=(), candidates=candidates, timeout_seconds=2
    )

    assert attention.ranked_probe_ids[:4] == (
        "probe.0",
        "probe.24",
        "probe.1",
        "probe.20",
    )


def test_changed_batch_membership_cannot_mix_cached_and_fresh_scores(tmp_path: Path) -> None:
    process = _FakeProcess()
    runtime = LayaSubprocessRuntime(
        _config(tmp_path),
        popen_factory=_factory(process),
        available_ram_reader=lambda: 8 * 1024**3,
    )
    candidates = tuple(
        {"probe_id": f"probe.{index}", "description": f"probe {index}"} for index in range(3)
    )

    runtime.attend(
        state={"symptom": "freeze"}, evidence=(), candidates=candidates[:2], timeout_seconds=2
    )
    changed = runtime.attend(
        state={"symptom": "freeze"}, evidence=(), candidates=candidates, timeout_seconds=2
    )

    assert changed.microbatches[0].cache_hit_ids == ()
    assert changed.microbatches[0].inference_ids == ("probe.0", "probe.1", "probe.2")
    assert len(process.stdin.requests) == 2


def test_partial_batch_cache_eviction_reranks_full_batch(tmp_path: Path) -> None:
    process = _FakeProcess()
    runtime = LayaSubprocessRuntime(
        _config(tmp_path),
        popen_factory=_factory(process),
        available_ram_reader=lambda: 8 * 1024**3,
    )
    runtime._score_cache_limit = 1  # pyright: ignore[reportPrivateUsage]
    candidates = (
        {"probe_id": "probe.one", "description": "first"},
        {"probe_id": "probe.two", "description": "second"},
    )

    runtime.attend(
        state={"symptom": "freeze"}, evidence=(), candidates=candidates, timeout_seconds=2
    )
    repeated = runtime.attend(
        state={"symptom": "freeze"}, evidence=(), candidates=candidates, timeout_seconds=2
    )

    assert repeated.microbatches[0].cache_hit_ids == ()
    assert repeated.microbatches[0].inference_ids == ("probe.one", "probe.two")
    assert len(process.stdin.requests) == 2


def test_evidence_attention_interleaves_batch_ranks_without_comparing_scores(
    tmp_path: Path,
) -> None:
    def response(request: dict[str, object]) -> object:
        candidates = request["candidates"]
        assert isinstance(candidates, list)
        typed_candidates = cast(list[dict[str, str]], candidates)
        ids = [item["probe_id"] for item in typed_candidates]
        scores = {item: (0.99 if item.endswith(":24:preview:0") else 0.1) for item in ids}
        return {
            "protocol_version": 1,
            "request_id": request["request_id"],
            "ranked_probe_ids": sorted(ids, key=lambda item: -scores[item]),
            "relevance_scores": scores,
        }

    runtime = LayaSubprocessRuntime(
        _config(tmp_path),
        popen_factory=_factory(_FakeProcess(response=response)),
        available_ram_reader=lambda: 8 * 1024**3,
    )
    evidence = tuple(
        {
            "evidence_id": f"evd_{index:032x}",
            "page_id": f"evd_{index:032x}:{index}",
            "fragment_id": f"evd_{index:032x}:{index}:preview:0",
            "description": f"synthetic observation {index}",
        }
        for index in range(25)
    )

    attention = runtime.attend(
        state={"symptom": "freeze"}, evidence=evidence, candidates=(), timeout_seconds=2
    )

    assert attention.ranked_evidence_ids[:4] == (
        "evd_00000000000000000000000000000000",
        "evd_00000000000000000000000000000018",
        "evd_00000000000000000000000000000001",
        "evd_00000000000000000000000000000014",
    )
