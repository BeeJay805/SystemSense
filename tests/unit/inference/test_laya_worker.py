from __future__ import annotations

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
