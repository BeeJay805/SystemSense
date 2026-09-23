from __future__ import annotations

import json
import socket
import time
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

import pytest

from systemsense.inference import ollama
from systemsense.inference.ollama import OllamaChatClient, OllamaTransport
from systemsense.inference.settings import LocalInferenceConfig

MODEL = "qwen3.8:27b"
DIGEST = "a" * 64


class PreloadTransport(OllamaTransport):
    def __init__(
        self,
        response: Mapping[str, Any] | Exception | bytes | None = None,
        *,
        endpoint: str = "http://127.0.0.1:11434/api/chat",
    ) -> None:
        super().__init__(connect=lambda _address, _timeout: socket.socket(), endpoint=endpoint)
        self.response = response or {
            "model": MODEL,
            "message": {"role": "assistant", "content": ""},
            "done_reason": "load",
            "done": True,
        }
        self.chat_calls: list[tuple[bytes, float, int]] = []
        self.show_calls: list[tuple[bytes, float, int]] = []
        self.tags_calls: list[tuple[float, int]] = []
        self.running_calls: list[tuple[float, int]] = []
        self.artifact_size = 1024
        self.resident_models: list[dict[str, object]] = [
            {"name": "other-local:latest", "digest": "b" * 64}
        ]

    def tags(self, *, timeout_seconds: float, max_response_bytes: int) -> bytes:
        self.tags_calls.append((timeout_seconds, max_response_bytes))
        return json.dumps(
            {
                "models": [
                    {
                        "name": MODEL,
                        "model": MODEL,
                        "size": self.artifact_size,
                        "digest": DIGEST,
                        "details": {"format": "gguf"},
                    }
                ]
            }
        ).encode()

    def show(self, body: bytes, *, timeout_seconds: float, max_response_bytes: int) -> bytes:
        self.show_calls.append((body, timeout_seconds, max_response_bytes))
        return json.dumps(
            {"details": {"format": "gguf"}, "model_info": {"architecture": "qwen"}}
        ).encode()

    def running(self, *, timeout_seconds: float, max_response_bytes: int) -> bytes:
        self.running_calls.append((timeout_seconds, max_response_bytes))
        return json.dumps({"models": self.resident_models}).encode()

    def post(self, body: bytes, *, timeout_seconds: float, max_response_bytes: int) -> bytes:
        self.chat_calls.append((body, timeout_seconds, max_response_bytes))
        if isinstance(self.response, Exception):
            raise self.response
        if isinstance(self.response, bytes):
            return self.response
        return json.dumps(self.response).encode()


def _client(
    transport: PreloadTransport,
    *,
    digest: str = DIGEST,
    keep_alive_seconds: int = 90,
    timeout_seconds: float = 5,
    allow_gpu: bool = False,
) -> OllamaChatClient:
    return OllamaChatClient(
        config=LocalInferenceConfig(
            enabled=True,
            reasoning_model=MODEL,
            reasoning_digest=digest,
            keep_alive_seconds=keep_alive_seconds,
            timeout_seconds=timeout_seconds,
            allow_gpu=allow_gpu,
        ),
        transport=transport,
    )


def test_preload_uses_exact_model_empty_messages_and_resource_admission(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = PreloadTransport()
    admitted: list[dict[str, object]] = []

    def record_admission(**kwargs: object) -> None:
        admitted.append(kwargs)

    monkeypatch.setattr(ollama, "admit_resources", record_admission)
    client = _client(transport)

    result = client.preload(model=MODEL, timeout_seconds=2)

    assert result.status == "ready"
    assert result.model == MODEL
    assert result.digest == DIGEST
    assert result.keep_alive_seconds == 90
    assert result.reason is None
    assert json.loads(transport.chat_calls[0][0]) == {
        "model": MODEL,
        "messages": [],
        "keep_alive": 90,
        "stream": False,
        "options": {"num_ctx": 8192, "num_thread": 4, "num_gpu": 0},
    }
    assert admitted and admitted[0]["artifact_bytes"] == 1024
    assert transport.running_calls
    assert transport.resident_models == [{"name": "other-local:latest", "digest": "b" * 64}]
    assert len(transport.chat_calls) == 1


def test_preload_never_returns_untrusted_response_content() -> None:
    transport = PreloadTransport(
        {
            "model": MODEL,
            "message": {"role": "assistant", "content": "unexpected generated text"},
            "done_reason": "load",
            "done": True,
        }
    )

    result = _client(transport).preload(model=MODEL, timeout_seconds=2)

    assert result.status == "degraded"
    assert result.reason == "invalid_preload_response"
    assert not hasattr(result, "content")


def test_gpu_prewarm_uses_configured_context_not_ollama_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = PreloadTransport()

    def admit(**_kwargs: object) -> None:
        return None

    def free_gpu(*, timeout_seconds: float) -> int:
        del timeout_seconds
        return 4 * 1024**3

    monkeypatch.setattr(ollama, "admit_resources", admit)
    monkeypatch.setattr(ollama, "gpu_free_memory", free_gpu)

    result = _client(transport, allow_gpu=True).preload(model=MODEL, timeout_seconds=2)

    assert result.status == "ready"
    body = json.loads(transport.chat_calls[0][0])
    assert body["options"] == {"num_ctx": 8192, "num_thread": 4}


def _resident_model(**overrides: object) -> dict[str, object]:
    entry: dict[str, object] = {
        "name": MODEL,
        "model": MODEL,
        "digest": DIGEST,
        "size": 1024,
        "size_vram": 1024,
        "context_length": 8192,
        "expires_at": (datetime.now(UTC) + timedelta(minutes=5)).isoformat(),
    }
    entry.update(overrides)
    return entry


def _gpu_admission(
    monkeypatch: pytest.MonkeyPatch, *, free_mib: int | None, ram_gib: int = 8
) -> None:
    def free_gpu(*, timeout_seconds: float) -> int | None:
        del timeout_seconds
        return None if free_mib is None else free_mib * 1024**2

    monkeypatch.setattr(ollama, "gpu_free_memory", free_gpu)
    monkeypatch.setattr(
        ollama.psutil, "virtual_memory", lambda: SimpleNamespace(available=ram_gib * 1024**3)
    )


def test_cpu_reuses_only_a_fresh_pinned_resident_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = PreloadTransport()
    transport.resident_models = [_resident_model(size_vram=0)]
    monkeypatch.setattr(
        ollama.psutil, "virtual_memory", lambda: SimpleNamespace(available=5 * 1024**3)
    )

    result = _client(transport).preload(model=MODEL, timeout_seconds=2)

    assert result.status == "ready"
    assert len(transport.chat_calls) == 1


@pytest.mark.parametrize(
    "resident_case",
    [
        {"digest": "b" * 64},
        {"model": "foreign:latest"},
        {"name": "foreign:latest"},
        {"expires_at": "2000-01-01T00:00:00+00:00"},
        "duplicate",
    ],
)
def test_cpu_residency_mismatch_does_not_bypass_cold_ram_reserve(
    monkeypatch: pytest.MonkeyPatch, resident_case: dict[str, object] | str
) -> None:
    transport = PreloadTransport()
    if resident_case == "duplicate":
        transport.resident_models = [_resident_model(size_vram=0), _resident_model(size_vram=0)]
    else:
        assert isinstance(resident_case, dict)
        transport.resident_models = [_resident_model(size_vram=0, **resident_case)]
    monkeypatch.setattr(
        ollama.psutil, "virtual_memory", lambda: SimpleNamespace(available=5 * 1024**3)
    )

    result = _client(transport).preload(model=MODEL, timeout_seconds=2)

    assert result.status == "degraded"
    assert result.reason == "resource_admission_failed"
    assert transport.chat_calls == []


def test_gpu_reuses_exact_pinned_resident_model_below_cold_reserve(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = PreloadTransport()
    transport.resident_models = [_resident_model()]
    _gpu_admission(monkeypatch, free_mib=1677)

    result = _client(transport, allow_gpu=True).preload(model=MODEL, timeout_seconds=2)

    assert result.status == "ready"
    assert len(transport.chat_calls) == 1


def test_gpu_reuses_pinned_model_when_running_size_differs_from_tag_artifact(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = PreloadTransport()
    transport.artifact_size = 17_741_872_154
    transport.resident_models = [_resident_model(size=17_299_081_787, size_vram=17_299_081_787)]
    _gpu_admission(monkeypatch, free_mib=1677)

    result = _client(transport, allow_gpu=True).preload(model=MODEL, timeout_seconds=2)

    assert result.status == "ready"
    assert len(transport.chat_calls) == 1


def test_gpu_completion_reuses_exact_pinned_resident_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = PreloadTransport(
        {"model": MODEL, "message": {"role": "assistant", "content": "{}"}, "done": True}
    )
    transport.resident_models = [_resident_model()]
    _gpu_admission(monkeypatch, free_mib=1677)

    result = _client(transport, allow_gpu=True).complete(
        model=MODEL, prompt="small", schema={"type": "object"}, timeout_seconds=2
    )

    assert result == {}
    assert len(transport.chat_calls) == 1


@pytest.mark.parametrize(
    ("resident_case", "free_mib", "ram_gib"),
    [
        ("absent", 1677, 8),  # A cold load still needs its full reserve.
        ({"digest": "b" * 64}, 1677, 8),
        ({"size_vram": 0}, 1677, 8),
        ({"context_length": 4096}, 1677, 8),
        ({"context_length": 16384}, 1677, 8),
        ({"size": 2048, "size_vram": 2048}, 1677, 8),
        ({"size": 0, "size_vram": 0}, 1677, 8),
        ({"size": 900, "size_vram": 800}, 1677, 8),
        ({"expires_at": "2000-01-01T00:00:00+00:00"}, 1677, 8),
        ({"expires_at": "invalid"}, 1677, 8),
        ({"expires_at": None}, 1677, 8),
        ("duplicate", 1677, 8),
        ({}, None, 8),
        ({}, 256, 8),
        ({}, 1677, 2),
    ],
)
def test_gpu_warm_reuse_fails_closed_when_residency_or_memory_is_unsafe(
    monkeypatch: pytest.MonkeyPatch,
    resident_case: dict[str, object] | str,
    free_mib: int | None,
    ram_gib: int,
) -> None:
    transport = PreloadTransport()
    if resident_case == "absent":
        transport.resident_models = []
    elif resident_case == "duplicate":
        transport.resident_models = [_resident_model(), _resident_model()]
    else:
        assert isinstance(resident_case, dict)
        transport.resident_models = [_resident_model(**resident_case)]
    _gpu_admission(monkeypatch, free_mib=free_mib, ram_gib=ram_gib)

    result = _client(transport, allow_gpu=True).preload(model=MODEL, timeout_seconds=2)

    assert result.status == "degraded"
    assert result.reason == "resource_admission_failed"
    assert transport.chat_calls == []


def test_gpu_reuse_does_not_touch_foreign_resident_model(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    transport = PreloadTransport()
    foreign = _resident_model(name="foreign:latest", model="foreign:latest", digest="b" * 64)
    own = _resident_model()
    transport.resident_models = [foreign, own]
    _gpu_admission(monkeypatch, free_mib=1677)

    result = _client(transport, allow_gpu=True).preload(model=MODEL, timeout_seconds=2)

    assert result.status == "ready"
    assert transport.resident_models == [foreign, own]
    assert len(transport.chat_calls) == 1


@pytest.mark.parametrize(
    "response",
    [
        {"model": MODEL, "message": {"role": "assistant", "content": ""}, "done": True},
        {
            "model": MODEL,
            "message": {"role": "assistant", "content": ""},
            "done_reason": "error",
            "done": True,
        },
        {
            "model": "different-model",
            "message": {"role": "assistant", "content": ""},
            "done_reason": "load",
            "done": True,
        },
        {
            "model": MODEL,
            "message": {"role": "assistant", "content": ""},
            "done_reason": "load",
            "done": True,
            "remote_host": "https://ollama.com",
        },
        b"not-json",
    ],
)
def test_preload_requires_a_complete_matching_load_response(response: object) -> None:
    transport = PreloadTransport(response=response)  # type: ignore[arg-type]

    result = _client(transport).preload(model=MODEL, timeout_seconds=2)

    assert result.status == "degraded"
    assert result.reason == "invalid_preload_response"


def test_preload_rejects_unpinned_models_before_runtime_contact() -> None:
    transport = PreloadTransport()

    result = _client(transport).preload(model="other-local:latest", timeout_seconds=2)

    assert result.status == "degraded"
    assert result.reason == "model_not_pinned"
    assert not transport.tags_calls and not transport.show_calls and not transport.chat_calls


def test_preload_rejects_unpinned_digest_before_chat() -> None:
    transport = PreloadTransport()

    result = _client(transport, digest="b" * 64).preload(model=MODEL, timeout_seconds=2)

    assert result.status == "degraded"
    assert result.reason == "model_verification_failed"
    assert not transport.chat_calls


def test_zero_keep_alive_is_rejected_without_sending_an_unload_request() -> None:
    transport = PreloadTransport()

    result = _client(transport, keep_alive_seconds=0).preload(model=MODEL, timeout_seconds=2)

    assert result.status == "degraded"
    assert result.reason == "keep_alive_not_positive"
    assert not transport.chat_calls


def test_preload_requires_transport_endpoint_to_match_configured_loopback() -> None:
    transport = PreloadTransport(endpoint="http://127.0.0.1:11435/api/chat")

    result = _client(transport).preload(model=MODEL, timeout_seconds=2)

    assert result.status == "degraded"
    assert result.reason == "local_transport_unverified"
    assert not transport.tags_calls and not transport.chat_calls


def test_preload_timeout_returns_degraded_without_raising() -> None:
    transport = PreloadTransport()
    original_post = transport.post

    def slow_post(body: bytes, *, timeout_seconds: float, max_response_bytes: int) -> bytes:
        time.sleep(0.03)
        return original_post(
            body,
            timeout_seconds=timeout_seconds,
            max_response_bytes=max_response_bytes,
        )

    transport.post = slow_post  # type: ignore[method-assign]
    started = time.monotonic()

    result = _client(transport).preload(model=MODEL, timeout_seconds=0.01)

    assert result.status == "degraded"
    assert result.reason == "timeout"
    assert time.monotonic() - started < 0.2


def test_preload_enforces_response_limit_even_with_custom_transport() -> None:
    transport = PreloadTransport(b"x" * 2048)
    client = OllamaChatClient(
        config=LocalInferenceConfig(
            enabled=True,
            reasoning_model=MODEL,
            reasoning_digest=DIGEST,
            keep_alive_seconds=30,
            max_response_bytes=1024,
        ),
        transport=transport,
    )

    result = client.preload(model=MODEL, timeout_seconds=2)

    assert result.status == "degraded"
    assert result.reason == "response_too_large"
