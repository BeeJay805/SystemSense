import json
from collections.abc import Callable
from pathlib import Path
from typing import cast

import pytest
from typer.testing import CliRunner

from systemsense.application.investigator import Investigator
from systemsense.cli import app
from systemsense.decision.baseline import KeywordBaselineDecisionProvider
from systemsense.decision.catalog_attention import DeterministicCatalogFallback
from systemsense.inference.factory import AdvisoryProviders
from systemsense.inference.laya_runtime import LayaRuntimeError
from systemsense.inference.ollama import OllamaPreloadResult
from systemsense.inference.profile import LayaProfile, LocalInferenceProfile
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
    assert "--prewarm-laya" in serve_help.output
    assert "--prewarm-reason" in serve_help.output


@pytest.mark.parametrize("flag", ["--prewarm-laya", "--prewarm-reasoning"])
def test_model_prewarm_requires_a_compatible_local_profile(tmp_path: Path, flag: str) -> None:
    result = CliRunner().invoke(
        app,
        ["serve", flag],
        env={"SYSTEMSENSE_DATA_DIR": str(tmp_path)},
    )
    assert result.exit_code == 2
    assert "compatible local inference profile" in result.output


@pytest.mark.parametrize("warmup_fails", [False, True])
@pytest.mark.parametrize("reasoning_fails", [False, True])
@pytest.mark.parametrize("typed_feature", [False, True])
def test_serve_prewarm_reports_readiness_and_closes_provider(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    warmup_fails: bool,
    reasoning_fails: bool,
    typed_feature: bool,
) -> None:
    import systemsense.application.service as service_module
    import systemsense.inference.factory as factory_module
    import systemsense.inference.profile as profile_module
    import systemsense.interface.server as server_module

    events: list[str] = []
    captured: dict[str, object] = {}
    profile = LocalInferenceProfile.model_construct(
        schema_version=2 if typed_feature else 1,
        decision_provider="typed-feature" if typed_feature else "laya",
        profile_id="prewarm-test",
        inference=LocalInferenceConfig(
            enabled=True,
            reasoning_model="local-reasoner",
            reasoning_digest="1" * 64,
            allow_gpu=True,
        ),
        laya=LayaProfile.model_construct(
            enabled=not typed_feature,
            interpreter_path=tmp_path / "python.exe",
            model_path=tmp_path / "model",
            timeout_seconds=5,
        ),
    )

    class _Providers:
        decision = KeywordBaselineDecisionProvider()
        reasoning = DeterministicReasoningProvider()
        knowledge = ReferenceKnowledgeGraph.load_default()
        catalog_attention = DeterministicCatalogFallback()
        frontier_ranker = None

        def prewarm_laya(self, *, timeout_seconds: float) -> None:
            assert timeout_seconds == 5
            events.append("prewarm")
            if warmup_fails:
                raise LayaRuntimeError("Laya host RAM admission rejected cold worker start")

        def prewarm_reasoning(self, *, timeout_seconds: float) -> OllamaPreloadResult:
            assert timeout_seconds == 10
            events.append("prewarm_reasoning")
            return OllamaPreloadResult(
                status="degraded" if reasoning_fails else "ready",
                model="local-reasoner",
                digest=None if reasoning_fails else "1" * 64,
                keep_alive_seconds=90,
                reason="timeout" if reasoning_fails else None,
            )

        def close(self) -> None:
            events.append("providers_closed")

    class _Service:
        def __init__(
            self,
            _database: Path,
            *,
            factory: Callable[[SQLiteStore], Investigator],
            inference_status: dict[str, object],
            passive_factory: object,
        ) -> None:
            del passive_factory
            captured["inference_status"] = inference_status
            captured["factory"] = factory

        def close(self) -> None:
            events.append("service_closed")

    class _Server:
        def serve_forever(self, *, poll_interval: float) -> None:
            del poll_interval
            events.append("server_started")

        def server_close(self) -> None:
            events.append("server_closed")

    def load_providers(_config: LocalInferenceConfig, **kwargs: object) -> AdvisoryProviders:
        captured["provider_kwargs"] = kwargs
        return cast("AdvisoryProviders", _Providers())

    def load_profile(_path: Path | None = None) -> LocalInferenceProfile:
        return profile

    def serve_stub(_service: object, _port: int) -> _Server:
        return _Server()

    monkeypatch.setattr(profile_module, "load_inference_profile", load_profile)
    monkeypatch.setattr(factory_module, "load_advisory_providers", load_providers)
    monkeypatch.setattr(service_module, "ApplicationService", _Service)
    monkeypatch.setattr(server_module, "serve", serve_stub)

    arguments = ["serve", "--profile", str(tmp_path / "profile.json")]
    if not typed_feature:
        arguments.append("--prewarm-laya")
    arguments.append("--prewarm-reasoning")
    result = CliRunner().invoke(
        app,
        arguments,
        env={"SYSTEMSENSE_DATA_DIR": str(tmp_path)},
    )

    assert result.exit_code == 0, result.output
    output = _json(result.output)
    warmup: dict[str, str] | None = None
    if not typed_feature:
        warmup = cast("dict[str, str]", output["laya_prewarm"])
        assert warmup["status"] == ("degraded" if warmup_fails else "ready")
    else:
        assert "laya_prewarm" not in output
    reasoning_prewarm = cast("dict[str, str]", output["reasoning_prewarm"])
    assert reasoning_prewarm["status"] == ("degraded" if reasoning_fails else "ready")
    status = cast("dict[str, object]", captured["inference_status"])
    assert status["decision_status"] == "not_checked"
    assert status["reasoning_status"] == "not_checked"
    if not typed_feature:
        assert warmup is not None
        assert status["decision_prewarm"] == warmup
    else:
        assert "decision_prewarm" not in status
    assert status["reasoning_prewarm"] == reasoning_prewarm
    assert events == [
        *([] if typed_feature else ["prewarm"]),
        "prewarm_reasoning",
        "server_started",
        "server_closed",
        "service_closed",
        "providers_closed",
    ]
    options = cast("dict[str, object]", captured["provider_kwargs"])
    assert options["fast_provider"] == ("typed-feature" if typed_feature else "configured")
    assert (options["laya_config"] is None) is typed_feature
    factory = cast("Callable[[SQLiteStore], Investigator]", captured["factory"])
    with SQLiteStore(tmp_path / "serve-factory.db") as store:
        assert factory(store).catalog_attention is _Providers.catalog_attention


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


@pytest.mark.parametrize("typed_feature", [False, True])
def test_investigate_profile_uses_profile_budget_and_closes_shared_providers(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    typed_feature: bool,
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
        catalog_attention=DeterministicCatalogFallback(),
        _close_runtime=lambda: events.append("providers_closed"),
    )
    profile = LocalInferenceProfile.model_construct(
        schema_version=2 if typed_feature else 1,
        decision_provider="typed-feature" if typed_feature else "laya",
        profile_id="fixture",
        investigation_budget_ms=180_000,
        inference=LocalInferenceConfig(
            enabled=typed_feature,
            reasoning_model="qwen3.8:27b" if typed_feature else None,
            reasoning_digest="2" * 64 if typed_feature else None,
        ),
        laya=LayaProfile(),
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

    def load_providers(_config: LocalInferenceConfig, **kwargs: object) -> AdvisoryProviders:
        captured["provider_kwargs"] = kwargs
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
    options = cast("dict[str, object]", captured["provider_kwargs"])
    assert options["fast_provider"] == ("typed-feature" if typed_feature else "configured")
    assert options["laya_config"] is None
    assert events == ["service_closed", "providers_closed"]
    factory = cast("Callable[[SQLiteStore], Investigator]", captured["factory"])
    with SQLiteStore(tmp_path / "investigate-factory.db") as store:
        assert factory(store).catalog_attention is providers.catalog_attention


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
