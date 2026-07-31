import json
from pathlib import Path
from typing import cast

from typer.testing import CliRunner

from systemsense.cli import app


def _json(output: str) -> dict[str, object]:
    parsed: object = json.loads(output)
    assert isinstance(parsed, dict)
    return cast("dict[str, object]", parsed)


def test_case_create_then_show_returns_bounded_brief(tmp_path: Path) -> None:
    runner = CliRunner()
    environment = {"SYSTEMSENSE_DATA_DIR": str(tmp_path)}

    created = runner.invoke(
        app,
        [
            "case",
            "create",
            "--kind",
            "general",
            "--symptom",
            "Audio disappeared after update.",
            "--trait",
            "device",
        ],
        env=environment,
    )
    assert created.exit_code == 0, created.output
    created_data = _json(created.output)
    case = cast("dict[str, object]", created_data["case"])
    case_id = str(case["case_id"])

    shown = runner.invoke(
        app,
        ["case", "show", case_id, "--max-chars", "800"],
        env=environment,
    )

    assert shown.exit_code == 0, shown.output
    brief = _json(shown.output)
    assert len(cast("str", brief["text"])) <= 800


def test_inventory_show_and_doctor_work_without_optional_sources(tmp_path: Path) -> None:
    runner = CliRunner()
    environment = {"SYSTEMSENSE_DATA_DIR": str(tmp_path)}

    inventory = runner.invoke(app, ["inventory", "show"], env=environment)
    doctor = runner.invoke(app, ["doctor"], env=environment)

    assert inventory.exit_code == 0, inventory.output
    assert _json(inventory.output)["items"] == []
    assert doctor.exit_code == 0, doctor.output
    doctor_data = _json(doctor.output)
    assert doctor_data["database_integrity"] == "ok"
    assert "capabilities" in doctor_data


def test_help_lists_all_mvp_command_families() -> None:
    result = CliRunner().invoke(app, ["--help"])

    assert result.exit_code == 0
    for command in ("case", "inventory", "sentinel", "doctor", "mcp-check", "benchmark"):
        assert command in result.output


def test_mcp_check_initializes_real_stdio_server(tmp_path: Path) -> None:
    result = CliRunner().invoke(
        app,
        ["mcp-check"],
        env={"SYSTEMSENSE_DATA_DIR": str(tmp_path)},
    )

    assert result.exit_code == 0, result.output
    data = _json(result.output)
    assert data["status"] == "ready"
    assert data["transport"] == "stdio"
    assert data["instructions"] is True
    assert data["tools"] == [
        "get_case_brief",
        "get_coverage_map",
        "get_evidence",
        "inspect_more",
        "open_case",
        "query_case_evidence",
    ]


def test_benchmark_command_runs_local_quality_gated_suite() -> None:
    result = CliRunner().invoke(app, ["benchmark"])

    assert result.exit_code == 0, result.output
    assert "Quality-gated" in result.output
    assert "not measured Claude savings" in result.output
