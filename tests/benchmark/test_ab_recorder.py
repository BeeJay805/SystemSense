import json
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

from benchmarks.ab.contracts import ExperimentArm
from benchmarks.ab.recorder import TraceRecorder
from benchmarks.models import BenchmarkFamily


def test_recorder_preserves_raw_metering_and_aggregates_billed_tokens(tmp_path: Path) -> None:
    recorder = TraceRecorder(
        run_id="run-1",
        pair_id="pair-1",
        experiment_id="experiment-1",
        scenario_id="application.port_conflict",
        family=BenchmarkFamily.APPLICATION,
        arm=ExperimentArm.SYSTEMSENSE,
        requested_model="gpt-5.6-sol",
        prompt_hash="a" * 64,
        tool_manifest_hash="b" * 64,
        started_at=datetime(2026, 7, 30, 12, 0, tzinfo=UTC),
    )
    recorder.record_response(
        {
            "id": "resp_1",
            "model": "gpt-5.6-sol-2026-07-01",
            "usage": {
                "input_tokens": 100,
                "input_tokens_details": {"cached_tokens": 40},
                "output_tokens": 25,
                "output_tokens_details": {"reasoning_tokens": 10},
                "total_tokens": 125,
            },
            "output": [],
        },
        elapsed_ms=1200,
    )
    recorder.record_response(
        {
            "id": "resp_2",
            "model": "gpt-5.6-sol-2026-07-01",
            "usage": {
                "input_tokens": 150,
                "input_tokens_details": {"cached_tokens": 80},
                "output_tokens": 30,
                "output_tokens_details": {"reasoning_tokens": 12},
                "total_tokens": 180,
            },
            "output": [],
        },
        elapsed_ms=900,
    )
    recorder.record_tool(
        call_id="call_1",
        name="run_powershell",
        arguments={"command": "Get-NetTCPConnection"},
        result={"stdout": "listener", "exit_code": 0},
        elapsed_ms=50,
    )
    trace = recorder.finish(
        final_answer="The conflicting process was stopped and the health check passed.",
        oracle_passed=True,
        collateral_change_detected=False,
        finished_at=datetime(2026, 7, 30, 12, 1, tzinfo=UTC),
    )
    output = tmp_path / "run-1.json"
    recorder.write(trace, output)
    reloaded = cast("dict[str, object]", json.loads(output.read_text(encoding="utf-8")))

    assert trace.usage.input_tokens == 250
    assert trace.usage.cached_input_tokens == 120
    assert trace.usage.output_tokens == 55
    assert trace.usage.reasoning_tokens == 22
    assert trace.usage.total_tokens == 305
    assert trace.api_elapsed_ms == 2100
    assert trace.tool_result_bytes > 0
    assert reloaded["run_id"] == "run-1"
    assert "Get-NetTCPConnection" in output.read_text(encoding="utf-8")
