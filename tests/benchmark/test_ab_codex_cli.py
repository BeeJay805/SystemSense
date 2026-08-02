import json
import subprocess
from pathlib import Path

import pytest

from benchmarks.ab.codex_cli import (
    CodexCliDebugger,
    CodexProcessResult,
    SubprocessCodexProcess,
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
        self.environments: list[dict[str, str]] = []

    def run(
        self,
        command: tuple[str, ...],
        *,
        working_directory: Path,
        environment: dict[str, str],
        timeout_seconds: int,
    ) -> CodexProcessResult:
        del working_directory, timeout_seconds
        self.commands.append(command)
        self.environments.append(environment)
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
    assert parsed.response["returned_model_exact"] is False
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
    assert trace.agent_elapsed_ms == 1234
    assert trace.api_elapsed_ms is None
    assert trace.returned_models == ()
    assert all(tool.elapsed_ms is None for tool in trace.tools)
    command = process.commands[0]
    assert command[:3] == ("codex.exe", "exec", "--json")
    assert "--ephemeral" in command
    assert "--ignore-user-config" in command
    assert "tool_output_token_limit=2048" in command
    assert "--dangerously-bypass-approvals-and-sandbox" not in command
    assert "User report:" in command[-1]
    assert "\n" not in command[-1]


def test_codex_debugger_persists_raw_process_streams_on_the_host(tmp_path: Path) -> None:
    stdout_path = tmp_path / "run.raw.jsonl"
    stderr_path = tmp_path / "run.raw.stderr.txt"
    process = FakeProcess(
        CodexProcessResult(
            return_code=20,
            stdout='{"type":"thread.started","thread_id":"partial"}\n',
            stderr="guest timeout",
            elapsed_ms=60_000,
        )
    )

    CodexCliDebugger(
        executable=Path("codex.exe"),
        process=process,
        config=_config(),
        arm=ExperimentArm.BASELINE,
        tool_manifest=ToolManifest(
            arm=ExperimentArm.BASELINE,
            tools=codex_cli_repair_tools(),
        ),
        working_directory=tmp_path,
        run_id="run-raw",
        pair_id="pair-raw",
        raw_stdout_path=stdout_path,
        raw_stderr_path=stderr_path,
    ).run()

    assert stdout_path.read_text(encoding="utf-8").endswith('"partial"}\n')
    assert stderr_path.read_text(encoding="utf-8") == "guest timeout"


def test_treatment_injects_only_the_frozen_systemsense_server(tmp_path: Path) -> None:
    process = FakeProcess(
        CodexProcessResult(return_code=0, stdout=_JSONL, stderr="", elapsed_ms=1234)
    )
    trace = CodexCliDebugger(
        executable=Path("codex.exe"),
        process=process,
        config=_config(),
        arm=ExperimentArm.SYSTEMSENSE,
        tool_manifest=ToolManifest(
            arm=ExperimentArm.SYSTEMSENSE,
            tools=codex_cli_repair_tools(),
        ),
        working_directory=tmp_path,
        run_id="run-treatment",
        pair_id="pair-treatment",
        treatment_mcp_command=Path("C:\\frozen\\python.exe"),
        treatment_mcp_args=("-m", "systemsense.mcp_server"),
        environment={
            "SYSTEMSENSE_DATABASE_PATH": "C:\\data\\systemsense.db",
            "SYSTEMSENSE_AB_STATE_DIR": "C:\\hidden\\state",
        },
    ).run()

    assert trace.failure is None
    command = process.commands[0]
    assert 'mcp_servers.systemsense.command="C:\\\\frozen\\\\python.exe"' in command
    assert 'mcp_servers.systemsense.args=["-m","systemsense.mcp_server"]' in command
    assert "mcp_servers.systemsense.required=true" in command
    assert "mcp_servers.systemsense.startup_timeout_sec=120" in command
    assert process.environments[0]["SYSTEMSENSE_DATABASE_PATH"].endswith("systemsense.db")
    assert "SYSTEMSENSE_AB_STATE_DIR" not in process.environments[0]


def test_codex_trace_flags_benchmark_answer_leakage(tmp_path: Path) -> None:
    leaked_events = [
        *_EVENTS[:2],
        {
            "type": "item.completed",
            "item": {
                "id": "cmd_leak",
                "type": "command_execution",
                "command": "Get-ChildItem C:\\ -Recurse -ErrorAction SilentlyContinue",
                "aggregated_output": "C:\\SystemSense-AB\\run\\state\\fault.pid",
                "exit_code": 0,
                "status": "completed",
            },
        },
        *_EVENTS[-2:],
    ]
    process = FakeProcess(
        CodexProcessResult(
            return_code=0,
            stdout="\n".join(json.dumps(event) for event in leaked_events) + "\n",
            stderr="",
            elapsed_ms=100,
        )
    )
    trace = CodexCliDebugger(
        executable=Path("codex.exe"),
        process=process,
        config=_config(),
        arm=ExperimentArm.BASELINE,
        tool_manifest=ToolManifest(
            arm=ExperimentArm.BASELINE,
            tools=codex_cli_repair_tools(),
        ),
        working_directory=tmp_path,
        run_id="run-leak",
        pair_id="pair-leak",
    ).run()

    assert trace.benchmark_leakage_detected is True
    assert trace.benchmark_leakage_indicators == ("fault.pid", "systemsense-ab")


def test_codex_jsonl_parser_rejects_missing_usage() -> None:
    malformed = '{"type":"thread.started","thread_id":"thread_123"}\n'

    try:
        parse_codex_jsonl(malformed, requested_model="gpt-5.6-sol")
    except ValueError as error:
        assert "usage" in str(error)
    else:
        raise AssertionError("missing usage must fail closed")


def test_subprocess_codex_runner_closes_inherited_stdin(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_run(command: tuple[str, ...], **kwargs: object) -> subprocess.CompletedProcess[str]:
        captured.update(kwargs)
        return subprocess.CompletedProcess(command, 0, stdout="", stderr="")

    monkeypatch.setattr("benchmarks.ab.codex_cli.subprocess.run", fake_run)

    SubprocessCodexProcess().run(
        ("codex.exe", "exec", "--json", "prompt"),
        working_directory=tmp_path,
        environment={},
        timeout_seconds=30,
    )

    assert captured["stdin"] is subprocess.DEVNULL
