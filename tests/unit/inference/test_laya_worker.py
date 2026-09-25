from __future__ import annotations

import hashlib
import io
import json
import queue
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import cast

import pytest

from systemsense.inference import laya_worker


def test_worker_error_envelope_exposes_only_fixed_capture_limit_metadata() -> None:
    limited = laya_worker._worker_error_envelope(  # pyright: ignore[reportPrivateUsage]
        "request-1",
        laya_worker.LayaCaptureResponseLimitError(73_417),
    )
    unknown = laya_worker._worker_error_envelope(  # pyright: ignore[reportPrivateUsage]
        "request-2", ValueError("private machine path must not escape")
    )

    assert limited == {
        "protocol_version": 1,
        "request_id": "request-1",
        "error": "ValueError",
        "error_code": "capture_response_limit",
        "response_bytes": 73_417,
    }
    assert unknown == {
        "protocol_version": 1,
        "request_id": "request-2",
        "error": "ValueError",
        "error_code": "worker_value_error",
    }
    assert "private" not in json.dumps(unknown)
    tensor_limited = laya_worker._worker_error_envelope(  # pyright: ignore[reportPrivateUsage]
        "request-3", laya_worker.LayaCaptureTensorLimitError(72_000)
    )
    assert tensor_limited["error_code"] == "capture_tensor_limit"
    assert tensor_limited["tensor_bytes"] == 72_000


@pytest.mark.parametrize(
    ("error_message", "error_code"),
    (
        ("essential Laya state field does not fit: ranked_evidence_context", "state_fit_limit"),
        ("Laya could not fit evidence content in its instruction budget", "instruction_fit_limit"),
        ("Laya question expansion exceeds its provenance bound", "question_expansion_limit"),
        ("missing ranking", "model_output_invalid"),
    ),
)
def test_worker_error_envelope_classifies_known_bounded_failure(
    error_message: str, error_code: str
) -> None:
    response = laya_worker._worker_error_envelope(  # pyright: ignore[reportPrivateUsage]
        "request-1", ValueError(error_message)
    )

    assert response["error_code"] == error_code
    assert "ranked_evidence_context" not in json.dumps(response)


def test_oversized_opt_in_response_has_typed_size_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
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

    def oversized(
        agent: laya_worker._LayaAgent,  # pyright: ignore[reportPrivateUsage]
        state: dict[str, object],
        questions: dict[str, dict[str, object]],
    ) -> tuple[dict[str, object], dict[str, object]]:
        return agent.predict(state, questions), {"synthetic_tensor": [1] * 100_000}

    def formerly_oversized(
        agent: laya_worker._LayaAgent,  # pyright: ignore[reportPrivateUsage]
        state: dict[str, object],
        questions: dict[str, dict[str, object]],
    ) -> tuple[dict[str, object], dict[str, object]]:
        return agent.predict(state, questions), {"synthetic_tensor": [1] * 31_000}

    request: dict[str, object] = {
        "protocol_version": 1,
        "request_id": "bounded",
        "state": {"symptom": "synthetic game lag"},
        "candidates": [{"probe_id": "one", "description": "Inspect graphics"}],
        "capture_exact_worker_call": True,
        "capture_model_input": True,
    }
    monkeypatch.setattr(laya_worker, "_predict_with_model_input_capture", formerly_oversized)
    bounded = laya_worker._handle(  # pyright: ignore[reportPrivateUsage]
        cast(laya_worker._LayaAgent, Agent()),  # pyright: ignore[reportPrivateUsage]
        request,
    )
    assert len(json.dumps(bounded, ensure_ascii=False, separators=(",", ":")).encode()) > 60_000

    monkeypatch.setattr(laya_worker, "_predict_with_model_input_capture", oversized)
    with pytest.raises(laya_worker.LayaCaptureResponseLimitError) as failure:
        laya_worker._handle(  # pyright: ignore[reportPrivateUsage]
            cast(laya_worker._LayaAgent, Agent()),  # pyright: ignore[reportPrivateUsage]
            request,
        )
    assert 192_000 < failure.value.response_bytes <= 262_144


def test_worker_waits_for_parent_admission_before_loading_model(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    class Input:
        def __init__(self) -> None:
            self.lines: queue.Queue[bytes] = queue.Queue()

        def readline(self, _limit: int = -1) -> bytes:
            return self.lines.get(timeout=2)

    class Output(io.BytesIO):
        def __init__(self) -> None:
            super().__init__()
            self.flushed = threading.Event()

        def flush(self) -> None:
            self.flushed.set()

    input_pipe = Input()
    output_pipe = Output()
    loaded = threading.Event()
    errors: list[Exception] = []
    monkeypatch.setattr(laya_worker.sys, "stdin", SimpleNamespace(buffer=input_pipe))
    monkeypatch.setattr(laya_worker.sys, "stdout", SimpleNamespace(buffer=output_pipe))
    monkeypatch.setattr(
        laya_worker.sys,
        "argv",
        [
            "laya_worker.py",
            "--model-path",
            str(tmp_path),
            "--await-load-admission",
            "--launch-id",
            "test-launch",
        ],
    )

    def load(*_args: object) -> tuple[object, object]:
        loaded.set()
        return object(), lambda: None

    monkeypatch.setattr(laya_worker, "_load_agent", load)

    def run() -> None:
        try:
            assert laya_worker.main() == 0
        except Exception as error:
            errors.append(error)

    worker = threading.Thread(target=run, daemon=True)
    worker.start()
    assert output_pipe.flushed.wait(timeout=1)
    assert not loaded.is_set()
    input_pipe.lines.put(
        b'{"protocol_version":1,"command":"admit_load","launch_id":"test-launch"}\n'
    )
    assert loaded.wait(timeout=1)
    input_pipe.lines.put(b"")
    worker.join(timeout=1)
    assert not worker.is_alive()
    assert errors == []


class _Model:
    def __init__(self) -> None:
        self.dtypes: list[object] = []

    def to(self, *, dtype: object) -> None:
        self.dtypes.append(dtype)


class _Agent:
    def __init__(self) -> None:
        self.cfg: dict[str, object] = {}
        self.device = "cuda:0"
        self.dtype: object = "upstream"
        self.model = _Model()


class _Laya:
    def __init__(self, agent: _Agent) -> None:
        self.agent = agent

    def load(self, model_path: str, *, device: str) -> _Agent:
        assert Path(model_path).is_absolute()
        assert device == "cuda"
        return self.agent


class _Cuda:
    def __init__(self) -> None:
        self.cache_releases = 0

    def is_available(self) -> bool:
        return True

    def mem_get_info(self) -> tuple[int, int]:
        return 8 * 1024**3, 24 * 1024**3

    def empty_cache(self) -> None:
        self.cache_releases += 1


class _Torch:
    def __init__(self) -> None:
        self.cuda = _Cuda()
        self.float16 = object()
        self.threads: int | None = None
        self.interop_threads: int | None = None

    def set_num_threads(self, threads: int) -> None:
        self.threads = threads

    def set_num_interop_threads(self, threads: int) -> None:
        self.interop_threads = threads


def test_cuda_float16_precision_converts_weights_and_autocast_dtype(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    agent = _Agent()
    torch = _Torch()
    modules = {"laya": _Laya(agent), "torch": torch}
    versions = {"laya": "0.3.5", "transformers": "5.17.0", "torch": "2.10.0+cu128"}
    monkeypatch.setattr(laya_worker.metadata, "version", versions.__getitem__)
    monkeypatch.setattr(laya_worker.importlib, "import_module", modules.__getitem__)

    loaded, release = laya_worker._load_agent(  # pyright: ignore[reportPrivateUsage]
        tmp_path.resolve(), 2, "cuda", 1536, "float16"
    )

    assert loaded is cast(object, agent)
    assert agent.model.dtypes == [torch.float16]
    assert agent.dtype is torch.float16
    assert torch.cuda.cache_releases == 1
    release()
    assert torch.cuda.cache_releases == 2


def test_worker_reports_exact_fitted_presentation_without_raw_content() -> None:
    class Tokenizer:
        mask_token = "[MASK]"
        mask_token_id = 1

        def __call__(self, text: str, *, add_special_tokens: bool = False) -> dict[str, object]:
            return {"input_ids": [len(part) for part in text.split()]}

    class Agent:
        def __init__(self) -> None:
            self.cfg: dict[str, object] = {"max_len": 512, "head_max_len": 80}
            self.tok = Tokenizer()
            self.presented: list[tuple[dict[str, object], dict[str, dict[str, object]]]] = []

        def predict(
            self, state: dict[str, object], questions: dict[str, dict[str, object]]
        ) -> dict[str, object]:
            self.presented.append((state, questions))
            return {"answers": {key: {"noul": 0.8} for key in questions}}

    agent = Agent()
    secret = "private-user-path"
    request: dict[str, object] = {
        "protocol_version": 1,
        "request_id": "test-presentation",
        "state": {"symptom": secret, "coverage_notes": ["bounded"]},
        "candidates": [
            {"probe_id": "probe.one", "description": f"{secret} " * 350},
        ],
    }

    first = laya_worker._handle(cast(laya_worker._LayaAgent, agent), request)  # pyright: ignore[reportPrivateUsage]
    second = laya_worker._handle(cast(laya_worker._LayaAgent, agent), request)  # pyright: ignore[reportPrivateUsage]
    presentation = cast(dict[str, object], first["presentation"])
    second_presentation = cast(dict[str, object], second["presentation"])
    state, questions = agent.presented[0]
    assert presentation["schema_version"] == 1
    assert presentation["presentation_sha256"] == second_presentation["presentation_sha256"]
    assert (
        presentation["fitted_state_sha256"]
        == hashlib.sha256(
            b"systemsense.laya.state.v1\0"
            + json.dumps(state, ensure_ascii=False, separators=(",", ":")).encode()
        ).hexdigest()
    )
    details = cast(list[dict[str, object]], presentation["questions"])
    assert len(details) == len(questions) > 1
    assert all(item["item_id"] == "probe.one" for item in details)
    assert all(
        item["instruction_presented_tokens"] == item["instruction_tokens"] for item in details
    )
    assert secret not in json.dumps(presentation)
    altered = dict(request)
    altered["candidates"] = [{"probe_id": "probe.one", "description": "different " * 350}]
    changed = laya_worker._handle(cast(laya_worker._LayaAgent, agent), altered)  # pyright: ignore[reportPrivateUsage]
    changed_presentation = cast(dict[str, object], changed["presentation"])
    assert changed_presentation["presentation_sha256"] != presentation["presentation_sha256"]

    class MutatingAgent(Agent):
        def predict(
            self, state: dict[str, object], questions: dict[str, dict[str, object]]
        ) -> dict[str, object]:
            result = super().predict(state, questions)
            state["symptom"] = "modified after presentation fingerprint"
            return result

    with pytest.raises(ValueError, match="mutated"):
        laya_worker._handle(cast(laya_worker._LayaAgent, MutatingAgent()), request)  # pyright: ignore[reportPrivateUsage]


def test_exact_worker_call_requires_explicit_opt_in_and_matches_predict_input() -> None:
    class Tokenizer:
        mask_token = "[MASK]"
        mask_token_id = 1

        def __call__(self, text: str, *, add_special_tokens: bool = False) -> dict[str, object]:
            return {"input_ids": [len(part) for part in text.split()]}

    class Agent:
        tok = Tokenizer()

        def __init__(self) -> None:
            self.cfg: dict[str, object] = {"max_len": 512, "head_max_len": 80}
            self.seen: tuple[dict[str, object], dict[str, dict[str, object]]] | None = None

        def predict(
            self, state: dict[str, object], questions: dict[str, dict[str, object]]
        ) -> dict[str, object]:
            self.seen = (state, questions)
            return {"answers": {key: {"noul": 0.8} for key in questions}}

    agent = Agent()
    request: dict[str, object] = {
        "protocol_version": 1,
        "request_id": "private-capture",
        "state": {"symptom": "private-path"},
        "candidates": [{"probe_id": "probe.one", "description": "Inspect application"}],
    }
    ordinary = laya_worker._handle(cast(laya_worker._LayaAgent, agent), request)  # pyright: ignore[reportPrivateUsage]
    assert "exact_worker_call" not in ordinary
    opted = laya_worker._handle(  # pyright: ignore[reportPrivateUsage]
        cast(laya_worker._LayaAgent, agent),  # pyright: ignore[reportPrivateUsage]
        {**request, "capture_exact_worker_call": True},
    )
    exact = cast(dict[str, object], opted["exact_worker_call"])
    assert agent.seen is not None
    assert exact["state"] == agent.seen[0]
    assert [row["question"] for row in cast(list[dict[str, object]], exact["questions"])] == list(
        agent.seen[1].values()
    )
    assert "private-path" in json.dumps(exact)
    with pytest.raises(ValueError, match="capture flag"):
        laya_worker._handle(  # pyright: ignore[reportPrivateUsage]
            cast(laya_worker._LayaAgent, agent),  # pyright: ignore[reportPrivateUsage]
            {**request, "capture_exact_worker_call": "yes"},
        )


def test_opt_in_capture_contains_tensors_from_the_actual_collator(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class Tokenizer:
        mask_token = "[MASK]"
        mask_token_id = 1

        def __call__(self, text: str, *, add_special_tokens: bool = False) -> dict[str, object]:
            return {"input_ids": [len(part) for part in text.split()]}

    class Tensor:
        def __init__(self, values: object) -> None:
            self.values = values

        def tolist(self) -> object:
            return self.values

    exact = {
        "input_ids": [[101, 2, 102, 1, 8, 1, 7, 102, 4, 102]],
        "attention_mask": [[1] * 10],
        "marker_pos": [[3, 5]],
        "marker_mask": [[True, True]],
        "qtype": [2],
    }

    def collate(*_args: object) -> dict[str, Tensor]:
        return {name: Tensor(values) for name, values in exact.items()}

    agent_module = SimpleNamespace(collate_items=collate)
    original_import = laya_worker.importlib.import_module

    def import_module(name: str) -> object:
        return agent_module if name == "laya.agent" else original_import(name)

    monkeypatch.setattr(
        laya_worker.importlib,
        "import_module",
        import_module,
    )

    class Agent:
        tok = Tokenizer()

        def __init__(self) -> None:
            self.cfg: dict[str, object] = {"max_len": 512, "head_max_len": 80}

        def predict(
            self, state: dict[str, object], questions: dict[str, dict[str, object]]
        ) -> dict[str, object]:
            agent_module.collate_items([], 0)
            return {"answers": {key: {"noul": 0.8} for key in questions}}

    request: dict[str, object] = {
        "protocol_version": 1,
        "request_id": "tensor-capture",
        "state": {"symptom": "synthetic game lag"},
        "candidates": [{"probe_id": "probe.one", "description": "Inspect graphics"}],
    }
    ordinary = laya_worker._handle(cast(laya_worker._LayaAgent, Agent()), request)  # pyright: ignore[reportPrivateUsage]
    assert "exact_worker_call" not in ordinary
    captured = laya_worker._handle(  # pyright: ignore[reportPrivateUsage]
        cast(laya_worker._LayaAgent, Agent()),  # pyright: ignore[reportPrivateUsage]
        {**request, "capture_exact_worker_call": True, "capture_model_input": True},
    )
    call = cast(dict[str, object], captured["exact_worker_call"])
    assert call["schema_version"] == 2
    assert call["model_input"] == exact
    with pytest.raises(ValueError, match="model input capture requires exact worker capture"):
        laya_worker._handle(  # pyright: ignore[reportPrivateUsage]
            cast(laya_worker._LayaAgent, Agent()),  # pyright: ignore[reportPrivateUsage]
            {**request, "capture_model_input": True},
        )

    class FailingAgent(Agent):
        def predict(
            self, state: dict[str, object], questions: dict[str, dict[str, object]]
        ) -> dict[str, object]:
            agent_module.collate_items([], 0)
            raise RuntimeError("synthetic forward failure")

    with pytest.raises(RuntimeError, match="synthetic forward failure"):
        laya_worker._handle(  # pyright: ignore[reportPrivateUsage]
            cast(laya_worker._LayaAgent, FailingAgent()),  # pyright: ignore[reportPrivateUsage]
            {**request, "capture_exact_worker_call": True, "capture_model_input": True},
        )
    assert agent_module.collate_items is collate

    def oversized_collate(*_args: object) -> dict[str, Tensor]:
        return {
            "input_ids": Tensor([[1] * 40_000]),
            "attention_mask": Tensor([[1] * 40_000]),
            "marker_pos": Tensor([[1]]),
            "marker_mask": Tensor([[True]]),
            "qtype": Tensor([2]),
        }

    def admitted_collate(*_args: object) -> dict[str, Tensor]:
        return {
            "input_ids": Tensor([[1] * 16_000]),
            "attention_mask": Tensor([[1] * 16_000]),
            "marker_pos": Tensor([[1]]),
            "marker_mask": Tensor([[True]]),
            "qtype": Tensor([2]),
        }

    agent_module.collate_items = admitted_collate
    larger = laya_worker._handle(  # pyright: ignore[reportPrivateUsage]
        cast(laya_worker._LayaAgent, Agent()),  # pyright: ignore[reportPrivateUsage]
        {**request, "capture_exact_worker_call": True, "capture_model_input": True},
    )
    larger_call = cast(dict[str, object], larger["exact_worker_call"])
    assert len(json.dumps(larger_call["model_input"], separators=(",", ":")).encode()) > 48_000
    assert agent_module.collate_items is admitted_collate

    agent_module.collate_items = oversized_collate
    with pytest.raises(laya_worker.LayaCaptureTensorLimitError) as failure:
        laya_worker._handle(  # pyright: ignore[reportPrivateUsage]
            cast(laya_worker._LayaAgent, Agent()),  # pyright: ignore[reportPrivateUsage]
            {**request, "capture_exact_worker_call": True, "capture_model_input": True},
        )
    assert failure.value.tensor_bytes > 128_000
    assert agent_module.collate_items is oversized_collate
