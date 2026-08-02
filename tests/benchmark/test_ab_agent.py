from pathlib import Path
from typing import cast

import pytest

from benchmarks.ab.agent import OpenAIDebugger
from benchmarks.ab.contracts import ExperimentArm, ModelRunner
from benchmarks.ab.live_runner import PaidRunLockedError, authorize_paid_run
from benchmarks.ab.readiness import ExperimentConfig
from benchmarks.ab.tools import ToolManifest, shared_repair_tools
from benchmarks.models import BenchmarkFamily


class FakeTransport:
    def __init__(self) -> None:
        self.payloads: list[dict[str, object]] = []

    def create_response(self, payload: dict[str, object]) -> dict[str, object]:
        self.payloads.append(payload)
        if len(self.payloads) == 1:
            return {
                "id": "resp_1",
                "model": "gpt-5.6-sol-2026-07-01",
                "usage": {
                    "input_tokens": 10,
                    "output_tokens": 5,
                    "total_tokens": 15,
                    "input_tokens_details": {"cached_tokens": 0},
                    "output_tokens_details": {"reasoning_tokens": 2},
                },
                "output": [
                    {
                        "type": "function_call",
                        "call_id": "call_1",
                        "name": "run_powershell",
                        "arguments": '{"command":"Get-NetTCPConnection"}',
                    }
                ],
            }
        return {
            "id": "resp_2",
            "model": "gpt-5.6-sol-2026-07-01",
            "usage": {
                "input_tokens": 20,
                "output_tokens": 6,
                "total_tokens": 26,
                "input_tokens_details": {"cached_tokens": 5},
                "output_tokens_details": {"reasoning_tokens": 1},
            },
            "output": [
                {
                    "type": "message",
                    "role": "assistant",
                    "content": [
                        {
                            "type": "output_text",
                            "text": "The health check now passes.",
                        }
                    ],
                }
            ],
        }


class MalformedToolTransport:
    def create_response(self, payload: dict[str, object]) -> dict[str, object]:
        del payload
        return {
            "id": "resp_bad",
            "model": "gpt-5.6-sol-2026-07-01",
            "usage": {"input_tokens": 5, "output_tokens": 2, "total_tokens": 7},
            "output": [
                {
                    "type": "function_call",
                    "call_id": "call_bad",
                    "name": "run_powershell",
                    "arguments": "{not-json",
                }
            ],
        }


class FakeExecutor:
    def __init__(self) -> None:
        self.calls: list[tuple[str, dict[str, object]]] = []

    def execute(self, name: str, arguments: dict[str, object]) -> object:
        self.calls.append((name, arguments))
        return {"stdout": "port owner", "stderr": "", "exit_code": 0}


def _config() -> ExperimentConfig:
    return ExperimentConfig(
        experiment_id="port-conflict-canary",
        scenario_id="application.port_conflict",
        family=BenchmarkFamily.APPLICATION,
        scenario_hash="a" * 64,
        requested_model="gpt-5.6-sol",
        human_prompt="My local development app exits with a Windows socket error.",
        instructions="Diagnose, repair, and verify using only the provided tools.",
        max_api_rounds=4,
    )


def test_debugger_runs_function_loop_and_records_returned_model() -> None:
    transport = FakeTransport()
    executor = FakeExecutor()
    manifest = ToolManifest(
        arm=ExperimentArm.BASELINE,
        tools=shared_repair_tools(),
    )
    debugger = OpenAIDebugger(
        transport=transport,
        executor=executor,
        config=_config(),
        arm=ExperimentArm.BASELINE,
        tool_manifest=manifest,
        run_id="run-1",
        pair_id="pair-1",
    )

    trace = debugger.run()

    assert executor.calls == [("run_powershell", {"command": "Get-NetTCPConnection"})]
    second_input = cast("list[dict[str, object]]", transport.payloads[1]["input"])
    assert any(item.get("type") == "function_call_output" for item in second_input)
    assert trace.final_answer == "The health check now passes."
    assert trace.returned_models == ("gpt-5.6-sol-2026-07-01",)
    assert trace.usage.total_tokens == 41


def test_paid_gate_fails_before_key_or_transport_without_ready_artifact(
    tmp_path: Path,
) -> None:
    with pytest.raises(PaidRunLockedError, match="--allow-paid-run"):
        authorize_paid_run(
            ready_path=tmp_path / "missing.json",
            config=_config(),
            allow_paid_run=False,
            api_key=None,
        )


def test_responses_config_hash_remains_compatible_after_runner_support() -> None:
    config = _config()
    explicit = config.model_copy(update={"runner": ModelRunner.RESPONSES_API})

    assert config.config_hash() == explicit.config_hash()


def test_subscription_auth_can_pass_credential_gate_without_api_key(tmp_path: Path) -> None:
    with pytest.raises(PaidRunLockedError, match="readiness artifact is missing"):
        authorize_paid_run(
            ready_path=tmp_path / "missing.json",
            config=_config(),
            allow_paid_run=True,
            api_key=None,
            subscription_authenticated=True,
            expected_stage="canary",
        )


def test_malformed_tool_call_is_retained_as_a_failed_run() -> None:
    trace = OpenAIDebugger(
        transport=MalformedToolTransport(),
        executor=FakeExecutor(),
        config=_config(),
        arm=ExperimentArm.BASELINE,
        tool_manifest=ToolManifest(
            arm=ExperimentArm.BASELINE,
            tools=shared_repair_tools(),
        ),
        run_id="run-bad",
        pair_id="pair-bad",
    ).run()

    assert trace.response_count == 1
    assert trace.usage.total_tokens == 7
    assert trace.failure is not None
    assert "function call validation failed" in trace.failure
