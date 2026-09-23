from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import cast

import pytest

from systemsense.inference import laya_worker


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
