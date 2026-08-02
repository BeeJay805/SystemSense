"""Raw, auditable usage and tool trace recording."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import cast

from pydantic import Field

from benchmarks.ab.contracts import ExperimentArm, ExperimentModel
from benchmarks.models import BenchmarkFamily


class TokenUsage(ExperimentModel):
    input_tokens: int = Field(ge=0)
    cached_input_tokens: int = Field(ge=0)
    output_tokens: int = Field(ge=0)
    reasoning_tokens: int = Field(ge=0)
    total_tokens: int = Field(ge=0)

    def plus(self, other: TokenUsage) -> TokenUsage:
        return TokenUsage(
            input_tokens=self.input_tokens + other.input_tokens,
            cached_input_tokens=self.cached_input_tokens + other.cached_input_tokens,
            output_tokens=self.output_tokens + other.output_tokens,
            reasoning_tokens=self.reasoning_tokens + other.reasoning_tokens,
            total_tokens=self.total_tokens + other.total_tokens,
        )


class ResponseTrace(ExperimentModel):
    response_id: str
    returned_model: str
    returned_model_attested: bool = True
    elapsed_ms: int | None = Field(default=None, ge=0)
    usage: TokenUsage
    raw_response: dict[str, object]


class ToolTrace(ExperimentModel):
    call_id: str
    name: str
    arguments: dict[str, object]
    result: object
    result_bytes: int = Field(ge=0)
    elapsed_ms: int | None = Field(default=None, ge=0)


class RunTrace(ExperimentModel):
    schema_version: int = 2
    run_id: str
    pair_id: str
    experiment_id: str
    scenario_id: str
    family: BenchmarkFamily
    arm: ExperimentArm
    requested_model: str
    returned_models: tuple[str, ...]
    prompt_hash: str
    tool_manifest_hash: str
    started_at: datetime
    finished_at: datetime
    elapsed_ms: int = Field(ge=0)
    agent_elapsed_ms: int | None = Field(default=None, ge=0)
    api_elapsed_ms: int | None = Field(default=None, ge=0)
    oracle_elapsed_ms: int = Field(default=0, ge=0)
    collateral_check_elapsed_ms: int = Field(default=0, ge=0)
    usage: TokenUsage
    response_count: int = Field(ge=0)
    tool_call_count: int = Field(ge=0)
    tool_result_bytes: int = Field(ge=0)
    responses: tuple[ResponseTrace, ...]
    tools: tuple[ToolTrace, ...]
    final_answer: str
    oracle_passed: bool | None
    oracle_result: dict[str, object] | None = None
    collateral_change_detected: bool | None
    collateral_differences: tuple[str, ...] = ()
    benchmark_leakage_detected: bool = False
    benchmark_leakage_indicators: tuple[str, ...] = ()
    failure: str | None


class RecorderCalibration(ExperimentModel):
    passed: bool
    expected_total_tokens: int = Field(ge=0)
    observed_total_tokens: int = Field(ge=0)
    expected_tool_result_bytes: int = Field(ge=0)
    observed_tool_result_bytes: int = Field(ge=0)


class TraceRecorder:
    def __init__(
        self,
        *,
        run_id: str,
        pair_id: str,
        experiment_id: str,
        scenario_id: str,
        family: BenchmarkFamily,
        arm: ExperimentArm,
        requested_model: str,
        prompt_hash: str,
        tool_manifest_hash: str,
        started_at: datetime,
    ) -> None:
        self._run_id = run_id
        self._pair_id = pair_id
        self._experiment_id = experiment_id
        self._scenario_id = scenario_id
        self._family = family
        self._arm = arm
        self._requested_model = requested_model
        self._prompt_hash = prompt_hash
        self._tool_manifest_hash = tool_manifest_hash
        self._started_at = started_at
        self._responses: list[ResponseTrace] = []
        self._tools: list[ToolTrace] = []

    def record_response(
        self,
        raw_response: dict[str, object],
        *,
        elapsed_ms: int | None,
    ) -> None:
        response_id = raw_response.get("id")
        model = raw_response.get("model")
        if not isinstance(response_id, str) or not response_id:
            raise ValueError("response is missing its ID")
        if not isinstance(model, str) or not model:
            raise ValueError("response is missing its returned model ID")
        self._responses.append(
            ResponseTrace(
                response_id=response_id,
                returned_model=model,
                returned_model_attested=raw_response.get("returned_model_exact") is not False,
                elapsed_ms=elapsed_ms,
                usage=_usage(raw_response.get("usage")),
                raw_response=raw_response,
            )
        )

    def record_tool(
        self,
        *,
        call_id: str,
        name: str,
        arguments: dict[str, object],
        result: object,
        elapsed_ms: int | None,
    ) -> None:
        encoded = json.dumps(
            result,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        self._tools.append(
            ToolTrace(
                call_id=call_id,
                name=name,
                arguments=arguments,
                result=result,
                result_bytes=len(encoded),
                elapsed_ms=elapsed_ms,
            )
        )

    def finish(
        self,
        *,
        final_answer: str,
        oracle_passed: bool | None,
        collateral_change_detected: bool | None,
        finished_at: datetime,
        agent_elapsed_ms: int | None = None,
        benchmark_leakage_detected: bool = False,
        benchmark_leakage_indicators: tuple[str, ...] = (),
        failure: str | None = None,
    ) -> RunTrace:
        usage = TokenUsage(
            input_tokens=0,
            cached_input_tokens=0,
            output_tokens=0,
            reasoning_tokens=0,
            total_tokens=0,
        )
        for response in self._responses:
            usage = usage.plus(response.usage)
        returned_models = tuple(
            dict.fromkeys(
                response.returned_model
                for response in self._responses
                if response.returned_model_attested
            )
        )
        response_elapsed = tuple(response.elapsed_ms for response in self._responses)
        api_elapsed_ms = (
            sum(elapsed for elapsed in response_elapsed if elapsed is not None)
            if response_elapsed and all(elapsed is not None for elapsed in response_elapsed)
            else None
        )
        return RunTrace(
            run_id=self._run_id,
            pair_id=self._pair_id,
            experiment_id=self._experiment_id,
            scenario_id=self._scenario_id,
            family=self._family,
            arm=self._arm,
            requested_model=self._requested_model,
            returned_models=returned_models,
            prompt_hash=self._prompt_hash,
            tool_manifest_hash=self._tool_manifest_hash,
            started_at=self._started_at,
            finished_at=finished_at,
            elapsed_ms=max(
                0,
                round((finished_at - self._started_at).total_seconds() * 1000),
            ),
            agent_elapsed_ms=agent_elapsed_ms,
            api_elapsed_ms=api_elapsed_ms,
            usage=usage,
            response_count=len(self._responses),
            tool_call_count=len(self._tools),
            tool_result_bytes=sum(tool.result_bytes for tool in self._tools),
            responses=tuple(self._responses),
            tools=tuple(self._tools),
            final_answer=final_answer,
            oracle_passed=oracle_passed,
            collateral_change_detected=collateral_change_detected,
            benchmark_leakage_detected=benchmark_leakage_detected,
            benchmark_leakage_indicators=benchmark_leakage_indicators,
            failure=failure,
        )

    @staticmethod
    def write(trace: RunTrace, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(trace.model_dump_json(indent=2) + "\n", encoding="utf-8")


def _usage(raw: object) -> TokenUsage:
    usage = cast("dict[str, object]", raw) if isinstance(raw, dict) else {}
    raw_input_details = usage.get("input_tokens_details")
    input_details = (
        cast("dict[str, object]", raw_input_details) if isinstance(raw_input_details, dict) else {}
    )
    raw_output_details = usage.get("output_tokens_details")
    output_details = (
        cast("dict[str, object]", raw_output_details)
        if isinstance(raw_output_details, dict)
        else {}
    )
    input_tokens = _nonnegative_int(usage.get("input_tokens"))
    output_tokens = _nonnegative_int(usage.get("output_tokens"))
    return TokenUsage(
        input_tokens=input_tokens,
        cached_input_tokens=_nonnegative_int(input_details.get("cached_tokens")),
        output_tokens=output_tokens,
        reasoning_tokens=_nonnegative_int(output_details.get("reasoning_tokens")),
        total_tokens=_nonnegative_int(
            usage.get("total_tokens"),
            fallback=input_tokens + output_tokens,
        ),
    )


def _nonnegative_int(value: object, *, fallback: int = 0) -> int:
    if isinstance(value, int) and not isinstance(value, bool) and value >= 0:
        return value
    return fallback


def calibrate_recorder() -> RecorderCalibration:
    from datetime import UTC

    at = datetime(2026, 1, 1, tzinfo=UTC)
    recorder = TraceRecorder(
        run_id="calibration",
        pair_id="calibration",
        experiment_id="calibration",
        scenario_id="calibration.synthetic",
        family=BenchmarkFamily.APPLICATION,
        arm=ExperimentArm.BASELINE,
        requested_model="synthetic",
        prompt_hash="0" * 64,
        tool_manifest_hash="0" * 64,
        started_at=at,
    )
    recorder.record_response(
        {
            "id": "resp_calibration",
            "model": "synthetic",
            "usage": {
                "input_tokens": 11,
                "output_tokens": 7,
                "total_tokens": 18,
                "input_tokens_details": {"cached_tokens": 3},
                "output_tokens_details": {"reasoning_tokens": 2},
            },
            "output": [],
        },
        elapsed_ms=1,
    )
    result = {"exit_code": 0, "stdout": "ok"}
    recorder.record_tool(
        call_id="call_calibration",
        name="run_powershell",
        arguments={"command": "Write-Output ok"},
        result=result,
        elapsed_ms=1,
    )
    trace = recorder.finish(
        final_answer="calibration",
        oracle_passed=True,
        collateral_change_detected=False,
        finished_at=at,
    )
    expected_bytes = len(
        json.dumps(
            result,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )
    return RecorderCalibration(
        passed=trace.usage.total_tokens == 18 and trace.tool_result_bytes == expected_bytes,
        expected_total_tokens=18,
        observed_total_tokens=trace.usage.total_tokens,
        expected_tool_result_bytes=expected_bytes,
        observed_tool_result_bytes=trace.tool_result_bytes,
    )
