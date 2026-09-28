"""Subscription advisory boundary; no real model calls in unit tests."""

import queue
import threading
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from systemsense.inference.codex import (
    CodexInferenceConfig,
    CodexJsonClient,
    _Session,  # pyright: ignore[reportPrivateUsage]
)
from systemsense.inference.control import inference_cancellation
from systemsense.inference.ollama import LocalInferenceError
from systemsense.reasoning.codex import CodexReasoningProvider
from tests.unit.reasoning.test_providers import _request  # pyright: ignore[reportPrivateUsage]


def test_subscription_inference_requires_explicit_enablement() -> None:
    with pytest.raises(ValueError, match="enable"):
        CodexJsonClient(CodexInferenceConfig(executable=Path("codex.exe")))


def test_codex_command_pins_subscription_and_disables_machine_tools(tmp_path: Path) -> None:
    client = CodexJsonClient(CodexInferenceConfig(enabled=True, executable=Path("codex.exe")))
    command = client.command(tmp_path)
    assert command[1] == "app-server"
    assert 'forced_login_method="chatgpt"' in command
    for key in (
        "shell_tool",
        "unified_exec",
        "apply_patch_freeform",
        "multi_agent_v2",
        "plugins",
        "hooks",
    ):
        assert f"features.{key}=false" in command
    assert "skills.include_instructions=false" in command


def test_codex_reasoner_preserves_shared_evidence_validation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    config = CodexInferenceConfig(enabled=True, executable=Path("codex.exe"))
    client = CodexJsonClient(config)

    def invalid(**kwargs: object) -> dict[str, object]:
        return {
            "summary": "Cause remains unknown",
            "hypotheses": [
                {
                    "hypothesis_id": "possible",
                    "statement": "Possible cause",
                    "supporting_evidence_ids": ["ev_fabricated"],
                }
            ],
        }

    monkeypatch.setattr(client, "complete", invalid)
    reasoner = CodexReasoningProvider(config, client=client)
    assert reasoner.identity.provider_id == "codex-subscription-reasoning"
    assert reasoner.investigate(_request()).degraded

    def valid(**kwargs: object) -> dict[str, object]:
        return {"summary": "Cause remains unknown", "hypotheses": []}

    monkeypatch.setattr(client, "complete", valid)
    response = reasoner.investigate(_request())
    assert not response.degraded
    assert response.provider == reasoner.identity
    assert "local model" not in response.summary


def test_codex_provider_rejects_disabled_or_different_client_config() -> None:
    disabled = CodexInferenceConfig(executable=Path("codex.exe"))
    with pytest.raises(ValueError, match="enable"):
        CodexReasoningProvider(disabled)
    config = disabled.model_copy(update={"enabled": True})
    different = CodexJsonClient(config.model_copy(update={"timeout_seconds": 30}))
    with pytest.raises(ValueError, match="differs"):
        CodexReasoningProvider(config, client=different)


def test_expired_request_never_reaches_subscription(monkeypatch: pytest.MonkeyPatch) -> None:
    config = CodexInferenceConfig(enabled=True, executable=Path("codex.exe"))
    client = CodexJsonClient(config)

    def forbidden(**kwargs: object) -> dict[str, object]:
        pytest.fail("expired request reached subscription inference")

    monkeypatch.setattr(client, "complete", forbidden)
    request = _request().model_copy(
        update={"deadline_at": datetime.now(UTC) - timedelta(seconds=1)}
    )
    assert CodexReasoningProvider(config, client=client).investigate(request).degraded


class FakeSession(_Session):
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, Any]]] = []
        self.replies: dict[str, dict[str, Any]] = {
            "initialize": {"userAgent": "test-runtime"},
            "account/read": {"account": {"type": "chatgpt"}},
            "config/read": {"config": {"mcp_servers": {"inherited_server": {}}}},
            "thread/start": {
                "thread": {"id": "t", "environments": [], "ephemeral": True},
                "model": "gpt-6-sol",
                "modelProvider": "openai",
                "sandbox": {"type": "readOnly", "networkAccess": False},
            },
            "mcpServerStatus/list": {
                "data": [
                    {
                        "runtimeStatus": "disabled",
                        "tools": {},
                        "resources": [],
                        "resourceTemplates": [],
                    }
                ],
                "nextCursor": None,
            },
            "turn/start": {"turn": {"id": "v"}},
        }
        self.text = '{"summary":"Cause unknown"}'
        self.events_seen = 0

    def check(self) -> None:
        pass

    def send(self, message: dict[str, Any]) -> None:
        pass

    def call(self, method: str, params: dict[str, Any]) -> dict[str, Any]:
        self.calls.append((method, params))
        return self.replies[method]

    def receive(self) -> dict[str, Any]:
        self.events_seen += 1
        if self.events_seen == 1:
            return {
                "method": "item/completed",
                "params": {
                    "threadId": "t",
                    "turnId": "v",
                    "item": {"type": "agentMessage", "phase": "final_answer", "text": self.text},
                },
            }
        return {
            "method": "turn/completed",
            "params": {"threadId": "t", "turn": {"id": "v", "status": "completed"}},
        }


def test_subscription_payload_only_sent_after_isolation_readback(tmp_path: Path) -> None:
    client = CodexJsonClient(CodexInferenceConfig(enabled=True, executable=Path("codex.exe")))
    session = FakeSession()
    result = client._investigate(session, tmp_path, b"synthetic evidence", {}, "gpt-6-sol")  # pyright: ignore[reportPrivateUsage]
    assert result == {"summary": "Cause unknown"}
    calls = dict(session.calls)
    start = calls["thread/start"]
    assert start["model"] == "gpt-6-sol" and start["allowProviderModelFallback"] is False
    assert start["environments"] == [] and start["selectedCapabilityRoots"] == []
    assert start["ephemeral"] is True and start["dynamicTools"] == []
    assert start["config"]["mcp_servers.inherited_server.enabled"] is False
    assert [name for name, _ in session.calls].index("mcpServerStatus/list") < [
        name for name, _ in session.calls
    ].index("turn/start")
    assert calls["turn/start"]["environments"] == []
    assert client.last_runtime["authentication"] == "chatgpt"


@pytest.mark.parametrize(
    "failure",
    [
        "api_key",
        "model",
        "provider",
        "environment",
        "mcp",
        "override",
        "api_route",
        "chatgpt_route",
    ],
)
def test_no_evidence_is_sent_when_preflight_fails(tmp_path: Path, failure: str) -> None:
    client = CodexJsonClient(CodexInferenceConfig(enabled=True, executable=Path("codex.exe")))
    session = FakeSession()
    if failure == "api_key":
        session.replies["account/read"]["account"]["type"] = "apiKey"
    elif failure == "model":
        session.replies["thread/start"]["model"] = "another-model"
    elif failure == "provider":
        session.replies["thread/start"]["modelProvider"] = "other"
    elif failure == "environment":
        session.replies["thread/start"]["thread"]["environments"] = [{"id": "host"}]
    elif failure == "mcp":
        session.replies["mcpServerStatus/list"]["data"][0]["tools"] = {"arbitrary": {}}
    elif failure == "override":
        session.replies["config/read"]["config"]["model_providers"] = {
            "openai": {"base_url": "custom"}
        }
    else:
        key = "openai_base_url" if failure == "api_route" else "chatgpt_base_url"
        session.replies["config/read"]["config"][key] = "https://custom.invalid"
    with pytest.raises(LocalInferenceError):
        client._investigate(session, tmp_path, b"private evidence", {}, "gpt-6-sol")  # pyright: ignore[reportPrivateUsage]
    assert not any(method == "turn/start" for method, _ in session.calls)


@pytest.mark.parametrize(
    "text", ["not JSON", "[]", "x" * 65_537], ids=["invalid", "array", "oversized"]
)
def test_subscription_rejects_invalid_or_oversized_output(tmp_path: Path, text: str) -> None:
    client = CodexJsonClient(CodexInferenceConfig(enabled=True, executable=Path("codex.exe")))
    session = FakeSession()
    session.text = text
    with pytest.raises(LocalInferenceError):
        client._investigate(session, tmp_path, b"evidence", {}, "gpt-6-sol")  # pyright: ignore[reportPrivateUsage]


def test_cancelled_or_invalid_deadline_never_launches_process() -> None:
    client = CodexJsonClient(CodexInferenceConfig(enabled=True, executable=Path("absent.exe")))
    event = threading.Event()
    event.set()
    with inference_cancellation(event), pytest.raises(LocalInferenceError, match="cancelled"):
        client.complete(model="gpt-6-sol", prompt="{}", schema={}, timeout_seconds=10)
    for timeout in (0, -1, float("nan"), float("inf")):
        with pytest.raises(LocalInferenceError, match="deadline"):
            client.complete(model="gpt-6-sol", prompt="{}", schema={}, timeout_seconds=timeout)


@pytest.mark.parametrize(
    "event",
    [
        {"method": "item/tool/call", "id": 10, "params": {}},
        {"method": "item/started", "params": {"item": {"type": "commandExecution"}}},
        {"method": "item/completed", "params": {"item": {"type": "mcpToolCall"}}},
    ],
    ids=["server_request", "command", "mcp"],
)
def test_pipe_session_never_executes_server_requests_or_tool_events(event: dict[str, Any]) -> None:
    session = object.__new__(_Session)
    session.events = queue.Queue()
    session.failure = threading.Event()
    session.check = lambda: None
    session.events.put(event)
    with pytest.raises(LocalInferenceError, match="unexpected"):
        session._receive()  # pyright: ignore[reportPrivateUsage]


def test_cancel_during_response_delivery_rejects_result() -> None:
    session = object.__new__(_Session)
    session.events = queue.Queue()
    session.failure = threading.Event()
    session.events.put({"id": 1, "result": {}})
    checks = 0

    def check() -> None:
        nonlocal checks
        checks += 1
        if checks == 2:
            raise LocalInferenceError("codex_cancelled")

    session.check = check
    with pytest.raises(LocalInferenceError, match="cancelled"):
        session._receive()  # pyright: ignore[reportPrivateUsage]
