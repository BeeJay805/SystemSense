import json
from pathlib import Path
from typing import cast

from typer.testing import CliRunner

from benchmarks.ab.cli import app
from benchmarks.ab.readiness import ExperimentConfig

_ROOT = Path(__file__).resolve().parents[2]
_SCENARIO = _ROOT / "benchmarks" / "ab" / "scenarios" / "port_conflict"


def test_init_freezes_real_scenario_prompt_and_hash(tmp_path: Path) -> None:
    output = tmp_path / "experiment.json"
    result = CliRunner().invoke(
        app,
        [
            "init",
            "--scenario",
            str(_SCENARIO),
            "--model",
            "gpt-5.6-sol",
            "--experiment-id",
            "port-conflict-canary",
            "--output",
            str(output),
        ],
    )

    assert result.exit_code == 0, result.output
    config = ExperimentConfig.model_validate_json(output.read_text(encoding="utf-8"))
    assert config.scenario_id == "application.port_conflict"
    assert config.requested_model == "gpt-5.6-sol"
    assert len(config.scenario_hash) == 64


def test_meter_check_is_synthetic_and_green() -> None:
    result = CliRunner().invoke(app, ["meter-check"])
    raw = cast("dict[str, object]", json.loads(result.output))

    assert result.exit_code == 0, result.output
    assert raw["passed"] is True
    assert raw["expected_total_tokens"] == raw["observed_total_tokens"]


def test_help_exposes_two_stage_paid_gates_and_analysis() -> None:
    result = CliRunner().invoke(app, ["--help"])

    assert result.exit_code == 0
    for command in ("build-ready", "run-arm", "finalize-arm", "analyze", "pilot-size"):
        assert command in result.output
