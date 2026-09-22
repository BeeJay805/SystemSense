import json
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest
from typer.testing import CliRunner

from systemsense.application.investigator import Investigator
from systemsense.cli import app
from systemsense.decision.baseline import KeywordBaselineDecisionProvider
from systemsense.inference.factory import AdvisoryProviders
from systemsense.inference.profile import LocalInferenceProfile
from systemsense.inference.settings import LocalInferenceConfig
from systemsense.knowledge import ReferenceKnowledgeGraph
from systemsense.reasoning.deterministic import DeterministicReasoningProvider
from systemsense.storage.sqlite_store import SQLiteStore


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
    for command in ("case", "inventory", "sentinel", "doctor", "mcp-check"):
        assert command in result.output


def test_profile_option_is_available_to_investigate_and_serve() -> None:
    runner = CliRunner()

    investigate_help = runner.invoke(app, ["investigate", "--help"])
    serve_help = runner.invoke(app, ["serve", "--help"])

    assert investigate_help.exit_code == 0
    assert serve_help.exit_code == 0
    assert "--profile" in investigate_help.output
    assert "--profile" in serve_help.output


def test_explicit_missing_profile_fails_before_starting_application(tmp_path: Path) -> None:
    missing = tmp_path / "missing.json"

    investigate = CliRunner().invoke(
        app,
        ["investigate", "test", "--profile", str(missing)],
    )
    serve = CliRunner().invoke(app, ["serve", "--profile", str(missing)])

    assert investigate.exit_code == 2
    assert serve.exit_code == 2
    assert "does not exist" in investigate.output
    assert "does not exist" in serve.output


def test_investigate_profile_uses_profile_budget_and_closes_shared_providers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import systemsense.application.service as service_module
    import systemsense.inference.factory as factory_module
    import systemsense.inference.profile as profile_module

    events: list[str] = []
    captured: dict[str, object] = {}
    providers = AdvisoryProviders(
        decision=KeywordBaselineDecisionProvider(),
        reasoning=DeterministicReasoningProvider(),
        knowledge=ReferenceKnowledgeGraph.load_default(),
        _close_runtime=lambda: events.append("providers_closed"),
    )
    profile = LocalInferenceProfile(
        profile_id="fixture",
        investigation_budget_ms=180_000,
    )

    class _Service:
        def __init__(
            self,
            database: Path,
            *,
            factory: Callable[[SQLiteStore], Investigator],
            inference_status: dict[str, object],
        ) -> None:
            captured.update(
                database=database,
                factory=factory,
                inference_status=inference_status,
            )

        def start_case(self, objective: str, budget_ms: int, max_rounds: int) -> dict[str, object]:
            captured.update(objective=objective, budget_ms=budget_ms, max_rounds=max_rounds)
            return {"case_id": "case_fixture"}

        def wait(self) -> None:
            return None

        def get_case(self, case_id: str) -> dict[str, object]:
            return {"case_id": case_id, "status": "complete"}

        def close(self) -> None:
            events.append("service_closed")

    def load_profile(_path: Path | None = None) -> LocalInferenceProfile:
        return profile

    def load_providers(_config: LocalInferenceConfig, **_kwargs: object) -> AdvisoryProviders:
        return providers

    monkeypatch.setattr(profile_module, "load_inference_profile", load_profile)
    monkeypatch.setattr(factory_module, "load_advisory_providers", load_providers)
    monkeypatch.setattr(service_module, "ApplicationService", _Service)

    result = CliRunner().invoke(
        app,
        ["investigate", "why did it fail?", "--profile", str(tmp_path / "profile.json")],
        env={"SYSTEMSENSE_DATA_DIR": str(tmp_path)},
    )

    assert result.exit_code == 0, result.output
    assert captured["budget_ms"] == 180_000
    assert captured["inference_status"] == profile.inference_status()
    assert events == ["service_closed", "providers_closed"]


@pytest.mark.mcp
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
    tool_count = cast("int", data["tool_count"])
    tools = cast("list[str]", data["tools"])
    assert tool_count == len(tools)
    assert tool_count > 0
    assert tools == sorted(set(tools))
