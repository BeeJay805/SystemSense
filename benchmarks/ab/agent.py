"""Fresh-session Responses API debugger loop."""

from __future__ import annotations

import json
import time
from datetime import UTC, datetime
from typing import Protocol, cast

from benchmarks.ab.contracts import ExperimentArm
from benchmarks.ab.readiness import ExperimentConfig
from benchmarks.ab.recorder import RunTrace, TraceRecorder
from benchmarks.ab.tools import ToolManifest


class ResponsesTransport(Protocol):
    def create_response(self, payload: dict[str, object]) -> dict[str, object]: ...


class ToolExecutor(Protocol):
    def execute(self, name: str, arguments: dict[str, object]) -> object: ...


class OpenAIDebugger:
    def __init__(
        self,
        *,
        transport: ResponsesTransport,
        executor: ToolExecutor,
        config: ExperimentConfig,
        arm: ExperimentArm,
        tool_manifest: ToolManifest,
        run_id: str,
        pair_id: str,
    ) -> None:
        if tool_manifest.arm is not arm:
            raise ValueError("tool manifest arm does not match the run arm")
        self._transport = transport
        self._executor = executor
        self._config = config
        self._arm = arm
        self._manifest = tool_manifest
        self._run_id = run_id
        self._pair_id = pair_id

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
        conversation: list[dict[str, object]] = [
            {"role": "user", "content": self._config.human_prompt}
        ]
        final_answer = ""
        failure: str | None = None
        tool_call_count = 0
        for _round in range(self._config.max_api_rounds):
            if (datetime.now(UTC) - started_at).total_seconds() > (
                self._config.max_elapsed_seconds
            ):
                failure = "maximum elapsed time reached"
                break
            payload: dict[str, object] = {
                "model": self._config.requested_model,
                "instructions": self._config.instructions,
                "input": conversation,
                "tools": [tool.responses_api_schema() for tool in self._manifest.tools],
                "max_output_tokens": self._config.max_output_tokens,
                "store": False,
            }
            response_started = time.perf_counter()
            try:
                response = self._transport.create_response(payload)
            except Exception as error:
                failure = _error_text("response request failed", error)
                break
            response_elapsed_ms = round((time.perf_counter() - response_started) * 1000)
            try:
                recorder.record_response(response, elapsed_ms=response_elapsed_ms)
                output = _output_items(response)
            except (TypeError, ValueError) as error:
                failure = _error_text("response validation failed", error)
                break
            calls = tuple(item for item in output if item.get("type") == "function_call")
            if calls:
                conversation.extend(output)
                tool_loop_failed = False
                for item in calls:
                    if tool_call_count >= self._config.max_tool_calls:
                        failure = (
                            "maximum tool calls reached: "
                            f"attempted {tool_call_count + 1}, "
                            f"limit {self._config.max_tool_calls}"
                        )
                        tool_loop_failed = True
                        break
                    try:
                        call_id, name, arguments = _function_call(item)
                    except (TypeError, ValueError) as error:
                        failure = _error_text("function call validation failed", error)
                        tool_loop_failed = True
                        break
                    tool_started = time.perf_counter()
                    try:
                        result = self._executor.execute(name, arguments)
                    except Exception as error:
                        result = {"error": _error_text("tool execution failed", error)}
                    tool_elapsed_ms = round((time.perf_counter() - tool_started) * 1000)
                    recorder.record_tool(
                        call_id=call_id,
                        name=name,
                        arguments=arguments,
                        result=result,
                        elapsed_ms=tool_elapsed_ms,
                    )
                    tool_call_count += 1
                    conversation.append(
                        {
                            "type": "function_call_output",
                            "call_id": call_id,
                            "output": json.dumps(
                                result,
                                allow_nan=False,
                                ensure_ascii=False,
                                separators=(",", ":"),
                                sort_keys=True,
                            ),
                        }
                    )
                if tool_loop_failed:
                    break
                continue
            final_answer = _text_output(output)
            if not final_answer:
                failure = "model returned neither a tool call nor final text"
            break
        else:
            failure = "maximum API rounds reached"

        return recorder.finish(
            final_answer=final_answer,
            oracle_passed=None,
            collateral_change_detected=None,
            finished_at=datetime.now(UTC),
            failure=failure,
        )


def _output_items(response: dict[str, object]) -> list[dict[str, object]]:
    raw = response.get("output")
    if not isinstance(raw, list):
        raise ValueError("response output is missing")
    output: list[dict[str, object]] = []
    for item in cast("list[object]", raw):
        if not isinstance(item, dict):
            raise ValueError("response output item is invalid")
        output.append(cast("dict[str, object]", item))
    return output


def _function_call(item: dict[str, object]) -> tuple[str, str, dict[str, object]]:
    call_id = item.get("call_id")
    name = item.get("name")
    raw_arguments = item.get("arguments")
    if not isinstance(call_id, str) or not isinstance(name, str):
        raise ValueError("function call identity is invalid")
    if not isinstance(raw_arguments, str):
        raise ValueError("function call arguments are invalid")
    arguments: object = json.loads(raw_arguments)
    if not isinstance(arguments, dict):
        raise ValueError("function call arguments must be an object")
    return call_id, name, cast("dict[str, object]", arguments)


def _text_output(output: list[dict[str, object]]) -> str:
    fragments: list[str] = []
    for item in output:
        if item.get("type") != "message":
            continue
        content = item.get("content")
        if not isinstance(content, list):
            continue
        for raw_part in cast("list[object]", content):
            part = raw_part
            if (
                isinstance(part, dict)
                and cast("dict[object, object]", part).get("type") == "output_text"
                and isinstance(cast("dict[object, object]", part).get("text"), str)
            ):
                fragments.append(str(cast("dict[object, object]", part)["text"]))
    return "\n".join(fragments).strip()


def _error_text(prefix: str, error: Exception) -> str:
    detail = f"{type(error).__name__}: {error}"
    return f"{prefix}: {detail[:1000]}"
