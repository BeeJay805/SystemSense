import json
from pathlib import Path

from benchmarks.ab.codex_cli import (
    CodexCliDebugger,
    CodexProcessResult,
    parse_codex_jsonl,
)
from benchmarks.ab.contracts import ExperimentArm, ModelRunner
from benchmarks.ab.readiness import ExperimentConfig
from benchmarks.ab.tools import ToolManifest, codex_cli_repair_tools
from benchmarks.models import BenchmarkFamily

_EVENTS = [
    {"type": "thread.started", "thread_id": "thread_123"},
    {"type": "turn.started"},
    {
        "type": "item.completed",
        "item": {
            "id": "cmd_1",
            "type": "command_execution",
            "command": "Get-NetTCPConnection",
            "aggregated_output": "listener",
            "exit_code": 0,
            "status": "completed",
        },
    },
    {
        "type": "item.completed",
        "item": {
            "id": "mcp_1",
            "type": "mcp_tool_call",
            "server": "systemsense",
            "tool": "get_case_brief",
            "arguments": {"case_id": "case_1"},
            "result": {"content": "port 8000"},
            "status": "completed",
        },
    },
    {
        "type": "item.completed",
        "item": {
            "id": "msg_1",
            "type": "agent_message",
            "text": "Stopped the conflicting process and verified the port is free.",
        },
    },
    {
        "type": "turn.completed",
        "usage": {
            "input_tokens": 120,
            "cached_input_tokens": 40,
            "output_tokens": 30,
            "reasoning_output_tokens": 8,
        },
    },
]
_JSONL = "\n".join(json.dumps(event) for event in _EVENTS) + "\n"


class FakeProcess:
    def __init__(self, result: CodexProcessResult) -> None:
        self.result = result
        self.commands: list[tuple[str, ...]] = []

    def run(
        self,
        command: tuple[str, ...],
        *,
        working_directory: Path,
        environment: dict[str, str],
        timeout_seconds: int,
    ) -> CodexProcessResult:
        del working_directory, environment, timeout_seconds
        self.commands.append(command)
        return self.result


def _config() -> ExperimentConfig:
    return ExperimentConfig(
        experiment_id="port-conflict-codex-cli",
        scenario_id="application.port_conflict",
        family=BenchmarkFamily.APPLICATION,
        scenario_hash="a" * 64,
        requested_model="gpt-5.6-sol",
        runner=ModelRunner.CODEX_CLI,
        human_prompt="My local development app exits with a Windows socket error.",
        instructions="Diagnose, repair, and verify using only the provided tools.",
        max_elapsed_seconds=60,
    )


def test_codex_jsonl_parser_preserves_usage_actions_and_final_answer() -> None:
    parsed = parse_codex_jsonl(_JSONL, requested_model="gpt-5.6-sol")

    assert parsed.response["id"] == "thread_123"
    assert parsed.response["model"] == "gpt-5.6-sol"
    assert parsed.response["usage"] == {
        "input_tokens": 120,
        "input_tokens_details": {"cached_tokens": 40},
        "output_tokens": 30,
        "output_tokens_details": {"reasoning_tokens": 8},
        "total_tokens": 150,
    }
    assert parsed.final_answer.startswith("Stopped the conflicting process")
    assert [tool.name for tool in parsed.tools] == [
        "shell_command",
        "systemsense.get_case_brief",
    ]


def test_codex_debugger_records_native_cli_trace_without_api_credentials(
    tmp_path: Path,
) -> None:
    process = FakeProcess(
        CodexProcessResult(return_code=0, stdout=_JSONL, stderr="", elapsed_ms=1234)
    )
    manifest = ToolManifest(
        arm=ExperimentArm.BASELINE,
        tools=codex_cli_repair_tools(),
    )

    trace = CodexCliDebugger(
        executable=Path("codex.exe"),
        process=process,
        config=_config(),
        arm=ExperimentArm.BASELINE,
        tool_manifest=manifest,
        working_directory=tmp_path,
        run_id="run-1",
        pair_id="pair-1",
    ).run()

    assert trace.failure is None
    assert trace.response_count == 1
    assert trace.usage.total_tokens == 150
    assert trace.tool_call_count == 2
    assert trace.api_elapsed_ms == 1234
    command = process.commands[0]
    assert command[:3] == ("codex.exe", "exec", "--json")
    assert "--ephemeral" in command
    assert "--dangerously-bypass-approvals-and-sandbox" not in command


def test_codex_jsonl_parser_rejects_missing_usage() -> None:
    malformed = '{"type":"thread.started","thread_id":"thread_123"}\n'

    try:
        parse_codex_jsonl(malformed, requested_model="gpt-5.6-sol")
    except ValueError as error:
        assert "usage" in str(error)
    else:
        raise AssertionError("missing usage must fail closed")
