import json
from pathlib import Path
from typing import cast

from typer.testing import CliRunner

from benchmarks.ab.cli import app
from benchmarks.ab.contracts import (
    FINGERPRINT_STATE_KEYS,
    ExperimentArm,
    MachineFingerprint,
)
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
    assert "begin with open_case and get_case_brief" in config.instructions
    assert "Do not search outside" in config.instructions
    assert config.max_tool_calls == 20


def test_meter_check_is_synthetic_and_green() -> None:
    result = CliRunner().invoke(app, ["meter-check"])
    raw = cast("dict[str, object]", json.loads(result.output))

    assert result.exit_code == 0, result.output
    assert raw["passed"] is True
    assert raw["expected_total_tokens"] == raw["observed_total_tokens"]


def test_help_exposes_two_stage_paid_gates_and_analysis() -> None:
    result = CliRunner().invoke(app, ["--help"])

    assert result.exit_code == 0
    for command in (
        "build-ready",
        "run-arm",
        "run-vm-arm",
        "finalize-arm",
        "analyze",
        "pilot-size",
    ):
        assert command in result.output


def test_compare_fingerprints_serializes_mismatch_details(tmp_path: Path) -> None:
    state = {key: f"sha256:{key}" for key in FINGERPRINT_STATE_KEYS}
    inventory = {key: () for key in FINGERPRINT_STATE_KEYS}
    baseline = MachineFingerprint(
        arm=ExperimentArm.BASELINE,
        clone_id="clone-a",
        parent_snapshot_id="snapshot-1",
        state=state,
        inventory={**inventory, "services": ("Example|Auto|example.exe",)},
    )
    treatment = MachineFingerprint(
        arm=ExperimentArm.SYSTEMSENSE,
        clone_id="clone-b",
        parent_snapshot_id="snapshot-1",
        state={**state, "services": "sha256:changed"},
        inventory={**inventory, "services": ("Example|Manual|example.exe",)},
    )
    baseline_path = tmp_path / "baseline.json"
    treatment_path = tmp_path / "treatment.json"
    baseline_path.write_text(baseline.model_dump_json(), encoding="utf-8")
    treatment_path.write_text(treatment.model_dump_json(), encoding="utf-8")

    result = CliRunner().invoke(
        app,
        [
            "compare-fingerprints",
            "--baseline",
            str(baseline_path),
            "--systemsense",
            str(treatment_path),
        ],
    )

    assert result.exit_code == 1
    payload = cast("dict[str, object]", json.loads(result.output))
    assert payload["match"] is False
    assert payload["details"] == [
        {
            "category": "services",
            "left_only": ["Example|Auto|example.exe"],
            "right_only": ["Example|Manual|example.exe"],
        }
    ]
