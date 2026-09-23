from __future__ import annotations

import io
import json
import queue
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
    _verify_weight_file,  # pyright: ignore[reportPrivateUsage]
)


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


def test_attention_merges_relevance_scores_across_batches(tmp_path: Path) -> None:
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

    assert attention.ranked_probe_ids[0] == "probe.24"
