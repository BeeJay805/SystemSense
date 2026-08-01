"""ChatGPT-authenticated Codex CLI runner for subscription-backed A/B trials."""

from __future__ import annotations

import json
import os
import subprocess
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol, cast

from benchmarks.ab.contracts import ExperimentArm
from benchmarks.ab.readiness import ExperimentConfig
from benchmarks.ab.recorder import RunTrace, TraceRecorder
from benchmarks.ab.tools import ToolManifest


@dataclass(frozen=True)
class CodexProcessResult:
    return_code: int
    stdout: str
    stderr: str
    elapsed_ms: int


class CodexProcess(Protocol):
    def run(
        self,
        command: tuple[str, ...],
        *,
        working_directory: Path,
        environment: dict[str, str],
        timeout_seconds: int,
    ) -> CodexProcessResult: ...


class SubprocessCodexProcess:
    def run(
        self,
        command: tuple[str, ...],
        *,
        working_directory: Path,
        environment: dict[str, str],
        timeout_seconds: int,
    ) -> CodexProcessResult:
        started = time.perf_counter()
        creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        try:
            completed = subprocess.run(
                command,
                cwd=working_directory,
                env=environment,
                capture_output=True,
                check=False,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_seconds,
                creationflags=creation_flags,
            )
            return CodexProcessResult(
                return_code=completed.returncode,
                stdout=completed.stdout,
                stderr=completed.stderr,
                elapsed_ms=round((time.perf_counter() - started) * 1000),
            )
        except subprocess.TimeoutExpired as error:
            return CodexProcessResult(
                return_code=124,
                stdout=_text(error.stdout),
                stderr=(_text(error.stderr) + "\nCodex CLI timed out.").strip(),
                elapsed_ms=round((time.perf_counter() - started) * 1000),
            )


@dataclass(frozen=True)
class ParsedTool:
    call_id: str
    name: str
    arguments: dict[str, object]
    result: object


@dataclass(frozen=True)
class ParsedCodexRun:
    response: dict[str, object]
    tools: tuple[ParsedTool, ...]
    final_answer: str


class CodexCliDebugger:
    def __init__(
        self,
        *,
        executable: Path,
        config: ExperimentConfig,
        arm: ExperimentArm,
        tool_manifest: ToolManifest,
        working_directory: Path,
        run_id: str,
        pair_id: str,
        process: CodexProcess | None = None,
        environment: dict[str, str] | None = None,
    ) -> None:
        if tool_manifest.arm is not arm:
            raise ValueError("tool manifest arm does not match the run arm")
        self._executable = executable
        self._config = config
        self._arm = arm
        self._manifest = tool_manifest
        self._working_directory = working_directory
        self._run_id = run_id
        self._pair_id = pair_id
        self._process = process or SubprocessCodexProcess()
        self._environment = {**os.environ, **(environment or {})}
        self._environment.pop("OPENAI_API_KEY", None)
        self._environment.pop("CODEX_API_KEY", None)

    def run(self) -> RunTrace:
        started_at = datetime.now(UTC)
        recorder = TraceRecorder(
            run_id=self._run_id,
            pair_id=self._pair_id,
            experiment_id=self._config.experiment_id,
            scenario_id=self._config.scenario_id,
            family=self._config.family,
            arm=self._arm,
            requested_model=self._config.requested_model,
            prompt_hash=self._config.prompt_hash(),
            tool_manifest_hash=self._manifest.manifest_hash(),
            started_at=started_at,
        )
        result = self._process.run(
            self._command(),
            working_directory=self._working_directory,
            environment=self._environment,
            timeout_seconds=self._config.max_elapsed_seconds,
        )
        failure: str | None = None
        final_answer = ""
        try:
            parsed = parse_codex_jsonl(
                result.stdout,
                requested_model=self._config.requested_model,
            )
            recorder.record_response(parsed.response, elapsed_ms=result.elapsed_ms)
            for tool in parsed.tools:
                recorder.record_tool(
                    call_id=tool.call_id,
                    name=tool.name,
                    arguments=tool.arguments,
                    result=tool.result,
                    elapsed_ms=0,
                )
            final_answer = parsed.final_answer
        except (TypeError, ValueError) as error:
            failure = f"Codex JSONL validation failed: {type(error).__name__}: {error}"
        if result.return_code != 0:
            detail = result.stderr.strip()[:1000]
            failure = f"Codex CLI exited {result.return_code}: {detail}"
        elif not final_answer and failure is None:
            failure = "Codex CLI returned no final agent message"
        return recorder.finish(
            final_answer=final_answer,
            oracle_passed=None,
            collateral_change_detected=None,
            finished_at=datetime.now(UTC),
            failure=failure,
        )

    def _command(self) -> tuple[str, ...]:
        prompt = f"{self._config.instructions}\n\nUser report:\n{self._config.human_prompt}"
        command = (
            str(self._executable),
            "exec",
            "--json",
            "--ephemeral",
            "--skip-git-repo-check",
            "--ignore-rules",
            "--sandbox",
            "danger-full-access",
            "--model",
            self._config.requested_model,
            "-c",
            'model_reasoning_effort="medium"',
        )
        if self._arm is ExperimentArm.SYSTEMSENSE:
            command += ("-c", "mcp_servers.systemsense.required=true")
        return (
            *command,
            "-C",
            str(self._working_directory),
            prompt,
        )


def parse_codex_jsonl(value: str, *, requested_model: str) -> ParsedCodexRun:
    events: list[dict[str, object]] = []
    for line_number, raw_line in enumerate(value.splitlines(), start=1):
        line = raw_line.strip().lstrip("\ufeff")
        if not line:
            continue
        try:
            raw_event: object = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"line {line_number} is not JSON") from error
        if not isinstance(raw_event, dict):
            raise ValueError(f"line {line_number} is not a JSON object")
        events.append(cast("dict[str, object]", raw_event))
    thread_ids = [
        event.get("thread_id") for event in events if event.get("type") == "thread.started"
    ]
    if len(thread_ids) != 1 or not isinstance(thread_ids[0], str):
        raise ValueError("Codex stream must contain exactly one thread ID")
    completed = [event for event in events if event.get("type") == "turn.completed"]
    if len(completed) != 1:
        raise ValueError("Codex stream must contain exactly one completed turn with usage")
    usage = _usage(completed[0].get("usage"))
    tools: list[ParsedTool] = []
    final_answer = ""
    for event in events:
        if event.get("type") != "item.completed":
            continue
        raw_item = event.get("item")
        if not isinstance(raw_item, dict):
            raise ValueError("completed item is not an object")
        item = cast("dict[str, object]", raw_item)
        item_type = item.get("type")
        if item_type == "agent_message" and isinstance(item.get("text"), str):
            final_answer = str(item["text"])
        elif item_type == "command_execution":
            tools.append(_command_tool(item))
        elif item_type == "mcp_tool_call":
            tools.append(_mcp_tool(item))
        elif item_type in {"file_change", "web_search"}:
            tools.append(_generic_tool(item))
    response: dict[str, object] = {
        "id": thread_ids[0],
        "model": requested_model,
        "usage": usage,
        "output": [],
        "runner": "codex_cli",
        "returned_model_exact": False,
        "events": events,
    }
    return ParsedCodexRun(
        response=response,
        tools=tuple(tools),
        final_answer=final_answer,
    )


def codex_chatgpt_authenticated(executable: Path, *, working_directory: Path) -> bool:
    creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    completed = subprocess.run(
        (str(executable), "login", "status"),
        cwd=working_directory,
        capture_output=True,
        check=False,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        creationflags=creation_flags,
        env={
            key: value
            for key, value in os.environ.items()
            if key not in {"OPENAI_API_KEY", "CODEX_API_KEY"}
        },
    )
    status = f"{completed.stdout}\n{completed.stderr}"
    return completed.returncode == 0 and "Logged in using ChatGPT" in status


def codex_mcp_server_names(executable: Path, *, working_directory: Path) -> tuple[str, ...]:
    creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
    completed = subprocess.run(
        (str(executable), "mcp", "list", "--json"),
        cwd=working_directory,
        capture_output=True,
        check=False,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        creationflags=creation_flags,
        env={
            key: value
            for key, value in os.environ.items()
            if key not in {"OPENAI_API_KEY", "CODEX_API_KEY"}
        },
    )
    if completed.returncode != 0:
        raise RuntimeError(f"Codex MCP discovery failed: {completed.stderr.strip()[:1000]}")
    raw: object = json.loads(completed.stdout)
    if not isinstance(raw, list):
        raise RuntimeError("Codex MCP discovery returned a non-list response")
    names: list[str] = []
    for raw_item in cast("list[object]", raw):
        if not isinstance(raw_item, dict):
            raise RuntimeError("Codex MCP discovery returned an invalid item")
        item = cast("dict[str, object]", raw_item)
        name = item.get("name")
        enabled = item.get("enabled")
        if not isinstance(name, str) or not isinstance(enabled, bool):
            raise RuntimeError("Codex MCP discovery item is missing name or enabled")
        if enabled:
            names.append(name)
    return tuple(sorted(names))


def _usage(raw: object) -> dict[str, object]:
    if not isinstance(raw, dict):
        raise ValueError("completed turn usage is missing")
    usage = cast("dict[str, object]", raw)
    input_tokens = _nonnegative_int(usage.get("input_tokens"), "input_tokens")
    cached_tokens = _nonnegative_int(
        usage.get("cached_input_tokens"),
        "cached_input_tokens",
    )
    output_tokens = _nonnegative_int(usage.get("output_tokens"), "output_tokens")
    reasoning_tokens = _nonnegative_int(
        usage.get("reasoning_output_tokens"),
        "reasoning_output_tokens",
    )
    total_tokens = usage.get("total_tokens")
    total = (
        _nonnegative_int(total_tokens, "total_tokens")
        if total_tokens is not None
        else input_tokens + output_tokens
    )
    return {
        "input_tokens": input_tokens,
        "input_tokens_details": {"cached_tokens": cached_tokens},
        "output_tokens": output_tokens,
        "output_tokens_details": {"reasoning_tokens": reasoning_tokens},
        "total_tokens": total,
    }


def _command_tool(item: dict[str, object]) -> ParsedTool:
    call_id = _item_id(item)
    command = item.get("command")
    if not isinstance(command, str):
        raise ValueError("command execution is missing its command")
    result = {key: value for key, value in item.items() if key not in {"id", "type", "command"}}
    return ParsedTool(
        call_id=call_id,
        name="shell_command",
        arguments={"command": command},
        result=result,
    )


def _mcp_tool(item: dict[str, object]) -> ParsedTool:
    server = item.get("server")
    tool = item.get("tool")
    if not isinstance(server, str) or not isinstance(tool, str):
        raise ValueError("MCP call is missing server or tool identity")
    raw_arguments = item.get("arguments")
    arguments = (
        cast("dict[str, object]", raw_arguments)
        if isinstance(raw_arguments, dict)
        else {"raw_arguments": raw_arguments}
    )
    result = {
        key: value
        for key, value in item.items()
        if key not in {"id", "type", "server", "tool", "arguments"}
    }
    return ParsedTool(
        call_id=_item_id(item),
        name=f"{server}.{tool}",
        arguments=arguments,
        result=result,
    )


def _generic_tool(item: dict[str, object]) -> ParsedTool:
    item_type = item.get("type")
    if not isinstance(item_type, str):
        raise ValueError("completed action is missing its type")
    return ParsedTool(
        call_id=_item_id(item),
        name=item_type,
        arguments={},
        result=item,
    )


def _item_id(item: dict[str, object]) -> str:
    value = item.get("id")
    if not isinstance(value, str) or not value:
        raise ValueError("completed action is missing its ID")
    return value


def _nonnegative_int(value: object, name: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"Codex usage {name} is invalid")
    return value


def _text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value
