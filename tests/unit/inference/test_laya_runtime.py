from __future__ import annotations

import io
import json
import queue
from collections.abc import Callable
from hashlib import sha256
from pathlib import Path
from typing import Literal, cast

import pytest

from systemsense.inference.laya_runtime import (
    LAYA_MODEL_REVISION,
    LAYA_MODEL_WEIGHT_SHA256,
    LayaRuntimeConfig,
    LayaRuntimeError,
    LayaSubprocessRuntime,
    PopenFactory,
    _verify_weight_file,  # pyright: ignore[reportPrivateUsage]
)


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
    timeout_process = _FakeProcess(response=False)
    timeout_runtime = LayaSubprocessRuntime(
        _config(tmp_path),
        popen_factory=_factory(timeout_process),
        available_ram_reader=lambda: 8 * 1024**3,
    )
    with pytest.raises(LayaRuntimeError, match="deadline"):
        timeout_runtime.rank(
            state={"symptom": "slow"},
            candidates=({"probe_id": "core.system", "description": "system"},),
            timeout_seconds=0.01,
        )
    assert timeout_process.returncode == 1

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
