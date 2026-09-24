from __future__ import annotations

import json
import socket
import threading
import time
from collections.abc import Mapping
from typing import Any

import pytest
from pydantic import ValidationError

from systemsense.inference.ollama import (
    LocalInferenceError,
    OllamaChatClient,
    OllamaTransport,
)
from systemsense.inference.settings import LocalInferenceConfig


class RecordingTransport:
    def __init__(
        self,
        response: Mapping[str, Any] | Exception,
        *,
        show_response: Mapping[str, Any] | None = None,
        tags_response: Mapping[str, Any] | None = None,
    ) -> None:
        self.response = response
        self.show_response = show_response or {
            "details": {"format": "gguf"},
            "model_info": {"general.architecture": "test"},
        }
        self.tags_response = tags_response or {
            "models": [
                {
                    "name": "qwen3.8:27b",
                    "model": "qwen3.8:27b",
                    "size": 1024,
                    "digest": "a" * 64,
                    "details": {"format": "gguf"},
                },
                {
                    "name": "small-local:latest",
                    "model": "small-local:latest",
                    "size": 1024,
                    "digest": "b" * 64,
                    "details": {"format": "gguf"},
                },
            ]
        }
        self.calls: list[tuple[bytes, float, int]] = []
        self.show_calls: list[tuple[bytes, float, int]] = []
        self.tags_calls: list[tuple[float, int]] = []

    def tags(self, *, timeout_seconds: float, max_response_bytes: int) -> bytes:
        self.tags_calls.append((timeout_seconds, max_response_bytes))
        return json.dumps(self.tags_response).encode()

    def show(self, body: bytes, *, timeout_seconds: float, max_response_bytes: int) -> bytes:
        self.show_calls.append((body, timeout_seconds, max_response_bytes))
        return json.dumps(self.show_response).encode()

    def post(self, body: bytes, *, timeout_seconds: float, max_response_bytes: int) -> bytes:
        self.calls.append((body, timeout_seconds, max_response_bytes))
        if isinstance(self.response, Exception):
            raise self.response
        return json.dumps(self.response).encode()


def test_oversized_prompt_is_rejected_before_runtime_contact() -> None:
    transport = RecordingTransport({})
    client = OllamaChatClient(
        config=LocalInferenceConfig(
            enabled=True, reasoning_model="small-local", context_tokens=2048
        ),
        transport=transport,
    )
    with pytest.raises(LocalInferenceError, match="context budget"):
        client.complete(model="small-local", prompt="x" * 5000, schema={}, timeout_seconds=3)
    assert not transport.calls and not transport.tags_calls


def test_config_is_disabled_cpu_only_and_unloads_by_default() -> None:
    config = LocalInferenceConfig()
    assert config.enabled is False
    assert config.allow_gpu is False
    assert config.keep_alive_seconds == 0


def test_local_endpoint_can_use_a_separate_explicit_loopback_port() -> None:
    config = LocalInferenceConfig(endpoint="http://127.0.0.1:11435/api/chat")
    assert config.endpoint == "http://127.0.0.1:11435/api/chat"


def test_client_bounds_context_output_and_checks_pinned_artifact() -> None:
    transport = RecordingTransport(
        {"message": {"role": "assistant", "content": "{}"}, "done": True}
    )
    config = LocalInferenceConfig.model_validate(
        {
            "enabled": True,
            "reasoning_model": "qwen3.8:27b",
            "reasoning_digest": "b" * 64,
            "context_tokens": 8192,
            "output_tokens": 768,
        }
    )
    with pytest.raises(LocalInferenceError, match="digest"):
        OllamaChatClient(config=config, transport=transport).complete(
            model="qwen3.8:27b", prompt="small", schema={"type": "object"}, timeout_seconds=1
        )
    assert not transport.calls

    config = config.model_copy(update={"reasoning_digest": "a" * 64})
    OllamaChatClient(config=config, transport=transport).complete(
        model="qwen3.8:27b", prompt="small", schema={"type": "object"}, timeout_seconds=1
    )
    body = json.loads(transport.calls[0][0])
    assert body["options"]["num_ctx"] == 8192
    assert body["options"]["num_predict"] == 768
    assert body["think"] is False


def test_managed_call_denial_never_contacts_service() -> None:
    transport = RecordingTransport(
        {"message": {"role": "assistant", "content": "{}"}, "done": True}
    )
    calls: list[str] = []
    client = OllamaChatClient(
        config=LocalInferenceConfig(
            enabled=True,
            reasoning_model="qwen3.8:27b",
            reasoning_digest="a" * 64,
            allow_gpu=True,
        ),
        transport=transport,
        managed_call_admission=lambda: False,
        managed_abort=lambda: calls.append("abort") is None,
    )
    with pytest.raises(LocalInferenceError, match="managed service admission"):
        client.complete(model="qwen3.8:27b", prompt="small", schema={}, timeout_seconds=3)
    assert calls == ["abort"]
    assert not transport.tags_calls and not transport.show_calls and not transport.calls


def test_managed_client_requires_both_lifetime_hooks() -> None:
    config = LocalInferenceConfig(enabled=True, reasoning_model="qwen3.8:27b", allow_gpu=True)
    with pytest.raises(ValueError, match="both admission and abort"):
        OllamaChatClient(config=config, managed_call_admission=lambda: True)
    with pytest.raises(ValueError, match="both admission and abort"):
        OllamaChatClient(config=config, managed_abort=lambda: True)


def test_managed_call_rechecks_before_post_and_retires_on_denial() -> None:
    transport = RecordingTransport(
        {"message": {"role": "assistant", "content": "{}"}, "done": True}
    )
    admitted = iter((True, False))
    calls: list[str] = []
    client = OllamaChatClient(
        config=LocalInferenceConfig(
            enabled=True,
            reasoning_model="qwen3.8:27b",
            reasoning_digest="a" * 64,
            allow_gpu=True,
        ),
        transport=transport,
        managed_call_admission=lambda: next(admitted),
        managed_abort=lambda: calls.append("abort") is None,
    )
    with pytest.raises(LocalInferenceError, match="managed service admission"):
        client.complete(model="qwen3.8:27b", prompt="small", schema={}, timeout_seconds=3)
    assert transport.tags_calls and transport.show_calls
    assert not transport.calls
    assert calls == ["abort"]


def test_managed_transport_failure_retires_owned_service() -> None:
    transport = RecordingTransport(LocalInferenceError("inference timeout"))
    calls: list[str] = []
    client = OllamaChatClient(
        config=LocalInferenceConfig(
            enabled=True,
            reasoning_model="qwen3.8:27b",
            reasoning_digest="a" * 64,
            allow_gpu=True,
        ),
        transport=transport,
        managed_call_admission=lambda: True,
        managed_abort=lambda: calls.append("abort") is None,
    )
    with pytest.raises(LocalInferenceError, match="inference timeout"):
        client.complete(model="qwen3.8:27b", prompt="small", schema={}, timeout_seconds=3)
    assert transport.calls
    assert calls == ["abort"]


def test_managed_abort_failure_reports_unverified_cleanup() -> None:
    transport = RecordingTransport(LocalInferenceError("inference timeout"))

    def broken_abort() -> bool:
        raise RuntimeError("cleanup failed")

    client = OllamaChatClient(
        config=LocalInferenceConfig(
            enabled=True,
            reasoning_model="qwen3.8:27b",
            reasoning_digest="a" * 64,
            allow_gpu=True,
        ),
        transport=transport,
        managed_call_admission=lambda: True,
        managed_abort=broken_abort,
    )
    with pytest.raises(LocalInferenceError, match="managed service cleanup unverified"):
        client.complete(model="qwen3.8:27b", prompt="small", schema={}, timeout_seconds=3)


def test_managed_abort_must_confirm_verified_release() -> None:
    transport = RecordingTransport(LocalInferenceError("inference timeout"))
    client = OllamaChatClient(
        config=LocalInferenceConfig(
            enabled=True,
            reasoning_model="qwen3.8:27b",
            reasoning_digest="a" * 64,
            allow_gpu=True,
        ),
        transport=transport,
        managed_call_admission=lambda: True,
        managed_abort=lambda: False,
    )
    with pytest.raises(LocalInferenceError, match="managed service cleanup unverified"):
        client.complete(model="qwen3.8:27b", prompt="small", schema={}, timeout_seconds=3)


def test_large_local_model_inspection_does_not_raise_chat_output_limit() -> None:
    class BoundedInspectionTransport(RecordingTransport):
        def show(self, body: bytes, *, timeout_seconds: float, max_response_bytes: int) -> bytes:
            raw = super().show(
                body, timeout_seconds=timeout_seconds, max_response_bytes=max_response_bytes
            )
            if len(raw) > max_response_bytes:
                raise LocalInferenceError("Ollama response exceeds the configured byte limit")
            return raw

    transport = BoundedInspectionTransport(
        {"message": {"role": "assistant", "content": "{}"}, "done": True},
        show_response={
            "details": {"format": "gguf"},
            "model_info": {"general.architecture": "test"},
            "template": "x" * 83_000,
        },
    )
    config = LocalInferenceConfig(
        enabled=True,
        reasoning_model="qwen3.8:27b",
        reasoning_digest="a" * 64,
        max_response_bytes=65_536,
    )

    result = OllamaChatClient(config=config, transport=transport).complete(
        model="qwen3.8:27b", prompt="small", schema={"type": "object"}, timeout_seconds=3
    )

    assert result == {}
    assert transport.show_calls[0][2] > 83_000
    assert transport.calls[0][2] == 65_536


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("endpoint", "http://example.com:11434/api/chat", "fixed loopback"),
        ("endpoint", "http://localhost:11434/api/generate", "fixed loopback"),
        ("decision_model", "gemma4:cloud", "cloud"),
        ("reasoning_model", "gpt-oss:120b-cloud", "cloud"),
        ("decision_model", "gemma4:cloud-latest", "cloud"),
        ("reasoning_model", "gpt-oss-cloud:20b", "cloud"),
    ],
)
def test_config_rejects_remote_hosts_paths_and_cloud_models(
    field: str, value: str, message: str
) -> None:
    with pytest.raises(ValidationError, match=message):
        LocalInferenceConfig.model_validate({field: value})


def test_client_uses_schema_nonstreaming_cpu_and_bounded_keep_alive() -> None:
    transport = RecordingTransport(
        {"message": {"role": "assistant", "content": '{"probe_ids":[]}'}, "done": True}
    )
    config = LocalInferenceConfig(
        enabled=True,
        decision_model="qwen3.8:27b",
        timeout_seconds=3,
        max_response_bytes=4096,
    )
    client = OllamaChatClient(config=config, transport=transport)

    result = client.complete(
        model="qwen3.8:27b",
        prompt="Choose registered probes.",
        schema={"type": "object"},
        timeout_seconds=1.5,
    )

    assert result == {"probe_ids": []}
    assert len(transport.tags_calls) == 1
    assert transport.tags_calls[0][0] <= 1.5
    assert transport.tags_calls[0][1] == 4096
    assert json.loads(transport.show_calls[0][0]) == {
        "model": "qwen3.8:27b",
        "verbose": False,
    }
    body = json.loads(transport.calls[0][0])
    assert body["stream"] is False
    assert body["format"] == {"type": "object"}
    assert body["keep_alive"] == 0
    assert body["options"] == {
        "temperature": 0,
        "num_gpu": 0,
        "num_ctx": 8192,
        "num_predict": 1200,
        "num_thread": 4,
    }
    assert "tools" not in body
    assert 0 < transport.calls[0][1] <= transport.show_calls[0][1] <= 1.5


def test_client_shares_one_total_deadline_across_metadata_and_chat() -> None:
    class SlowTransport(RecordingTransport):
        def tags(self, *, timeout_seconds: float, max_response_bytes: int) -> bytes:
            time.sleep(0.03)
            return super().tags(
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )

        def show(self, body: bytes, *, timeout_seconds: float, max_response_bytes: int) -> bytes:
            time.sleep(0.03)
            return super().show(
                body,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )

        def post(self, body: bytes, *, timeout_seconds: float, max_response_bytes: int) -> bytes:
            time.sleep(0.03)
            return super().post(
                body,
                timeout_seconds=timeout_seconds,
                max_response_bytes=max_response_bytes,
            )

    transport = SlowTransport({"message": {"role": "assistant", "content": "{}"}, "done": True})
    client = OllamaChatClient(
        config=LocalInferenceConfig(enabled=True, decision_model="qwen3.8:27b"),
        transport=transport,
    )
    started = time.monotonic()

    with pytest.raises(LocalInferenceError, match="total deadline"):
        client.complete(
            model="qwen3.8:27b",
            prompt="small",
            schema={"type": "object"},
            timeout_seconds=0.075,
        )

    assert time.monotonic() - started < 0.2


def test_client_rejects_oversize_request_or_response() -> None:
    transport = RecordingTransport(
        {"message": {"role": "assistant", "content": "{}"}, "done": True}
    )
    config = LocalInferenceConfig(
        enabled=True,
        decision_model="small-local",
        max_request_bytes=1024,
        max_response_bytes=1024,
    )
    client = OllamaChatClient(config=config, transport=transport)
    with pytest.raises(LocalInferenceError, match="request body"):
        client.complete(
            model="small-local",
            prompt="x" * 2000,
            schema={"type": "object"},
            timeout_seconds=1,
        )
    assert transport.calls == []

    oversize = RecordingTransport(
        {"message": {"role": "assistant", "content": "x" * 2000}, "done": True}
    )
    with pytest.raises(LocalInferenceError, match="response content"):
        OllamaChatClient(config=config, transport=oversize).complete(
            model="small-local",
            prompt="small",
            schema={"type": "object"},
            timeout_seconds=1,
        )


def test_client_fails_closed_before_chat_for_remote_or_unverifiable_alias() -> None:
    for metadata in (
        {
            "remote_model": "gpt-oss:120b",
            "remote_host": "https://ollama.com:443",
            "details": {"format": ""},
        },
        {"details": {"format": ""}, "model_info": {}},
    ):
        transport = RecordingTransport(
            {"message": {"role": "assistant", "content": "{}"}, "done": True},
            show_response=metadata,
        )
        client = OllamaChatClient(
            config=LocalInferenceConfig(enabled=True, decision_model="local-alias"),
            transport=transport,
        )
        with pytest.raises(LocalInferenceError, match="local model"):
            client.complete(
                model="local-alias",
                prompt="small",
                schema={"type": "object"},
                timeout_seconds=1,
            )
        assert transport.calls == []


@pytest.mark.parametrize(
    "tags_response",
    [
        {"models": []},
        {
            "models": [
                {
                    "name": "local-alias:latest",
                    "model": "local-alias:latest",
                    "size": 1024,
                    "digest": "c" * 64,
                    "details": {"format": "gguf"},
                    "remote_model": "gpt-oss:120b",
                    "remote_host": "https://ollama.com:443",
                }
            ]
        },
        {
            "models": [
                {
                    "name": "local-alias:latest",
                    "model": "local-alias:latest",
                    "size": 0,
                    "digest": "not-a-local-artifact-digest",
                    "details": {"format": "gguf"},
                }
            ]
        },
    ],
)
def test_client_requires_a_matching_local_artifact_in_tags_before_show_or_chat(
    tags_response: Mapping[str, Any],
) -> None:
    transport = RecordingTransport(
        {"message": {"role": "assistant", "content": "{}"}, "done": True},
        tags_response=tags_response,
    )
    client = OllamaChatClient(
        config=LocalInferenceConfig(enabled=True, decision_model="local-alias"),
        transport=transport,
    )

    with pytest.raises(LocalInferenceError, match="local model artifact"):
        client.complete(
            model="local-alias",
            prompt="small",
            schema={"type": "object"},
            timeout_seconds=1,
        )

    assert transport.show_calls == []
    assert transport.calls == []


def _transport_with_response(response: bytes, *, drip_seconds: float = 0) -> OllamaTransport:
    client, server = socket.socketpair()

    def serve() -> None:
        with server:
            request = bytearray()
            while b"\r\n\r\n" not in request:
                request.extend(server.recv(4096))
            try:
                if not drip_seconds:
                    server.sendall(response)
                    return
                for byte in response:
                    server.sendall(bytes((byte,)))
                    time.sleep(drip_seconds)
            except OSError:
                pass

    threading.Thread(target=serve, daemon=True).start()

    def connect(_address: tuple[str, int], _timeout: float) -> socket.socket:
        return client

    return OllamaTransport(connect=connect)


def test_default_transport_rejects_redirected_response() -> None:
    transport = _transport_with_response(
        b"HTTP/1.1 302 Found\r\nLocation: http://example.com/stolen\r\nContent-Length: 0\r\n\r\n"
    )
    with pytest.raises(LocalInferenceError, match="redirect"):
        transport.post(b"{}", timeout_seconds=1, max_response_bytes=1024)


@pytest.mark.parametrize(
    "response",
    [
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\n{}\r\n0\r\n\r\n",
    ],
)
def test_default_transport_reads_bounded_fixed_and_chunked_json(response: bytes) -> None:
    transport = _transport_with_response(response)

    assert transport.post(b"{}", timeout_seconds=1, max_response_bytes=1024) == b"{}"


def test_default_transport_rejects_oversized_body_and_headers() -> None:
    oversized_body = b"x" * 1025
    body_transport = _transport_with_response(
        b"HTTP/1.1 200 OK\r\nContent-Length: 1025\r\n\r\n" + oversized_body
    )
    with pytest.raises(LocalInferenceError, match="byte limit"):
        body_transport.post(b"{}", timeout_seconds=1, max_response_bytes=1024)

    header_transport = _transport_with_response(
        b"HTTP/1.1 200 OK\r\nX-Oversized: " + b"x" * 70_000 + b"\r\n\r\n{}"
    )
    with pytest.raises(LocalInferenceError, match=r"wire limit|invalid HTTP response"):
        header_transport.post(b"{}", timeout_seconds=1, max_response_bytes=1024)


def test_default_transport_enforces_total_deadline_against_slow_trickle() -> None:
    body = b'{"message":{"content":"{}"},"done":true}'
    response = (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: "
        + str(len(body)).encode()
        + b"\r\n\r\n"
        + body
    )
    transport = _transport_with_response(response, drip_seconds=0.02)
    started = time.monotonic()

    with pytest.raises(LocalInferenceError, match=r"deadline|unavailable"):
        transport.post(b"{}", timeout_seconds=0.08, max_response_bytes=1024)

    assert time.monotonic() - started < 0.4
