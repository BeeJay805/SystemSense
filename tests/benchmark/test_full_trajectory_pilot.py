"""The toy pilot must run the public investigator and retain missing arms."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from benchmarks import full_trajectory_pilot as pilot
from benchmarks.full_trajectory_pilot import run_toy_suite, verify_toy_suite


def test_network_trajectory_runs_with_hidden_labels_separate(tmp_path: Path) -> None:
    output = tmp_path / "pilot"
    report = run_toy_suite(output, scenario_names=("wifi_dns",))
    assert report["classification"] == "synthetic_investigator_mechanics_only"
    assert report["planned_cases"] == 1
    assert report["arms"]["deterministic"]["completed"] == 1
    assert report["arms"]["current_default"]["unrun"] == 1
    assert report["runtime_request_parity_verified"] is False
    run = report["runs"][0]
    assert run["arm"] == "deterministic"
    assert run["status"] == "completed"
    assert run["provider_identities"]
    assert run["initial_input_sha256"] == report["planned_inputs"][0]["initial_input_sha256"]
    assert run["probe_attempts"]
    assert "scenario_id" not in json.dumps(report)
    assert "root_causes" not in json.dumps(report)
    visible_bytes = (output / "policy-visible/inputs.json").read_text(encoding="utf-8")
    assert "scenario_id" not in visible_bytes
    assert "dns_misconfiguration" not in visible_bytes
    assert "root_causes" not in visible_bytes
    labels = json.loads((output / "evaluator-only/outcomes.json").read_text(encoding="utf-8"))
    assert len(labels["cases"]) == 1
    assert labels["cases"][0]["scenario_id"] == "wifi_dns"
    assert labels["cases"][0]["root_causes"] == ["dns_misconfiguration"]
    assert labels["cases"][0]["diagnostic_performance_admissible"] is False
    database = output / "cases" / f"{run['case_id']}-deterministic.db"
    assert database.is_file()
    manifest = json.loads((output / "run-manifest.json").read_text(encoding="utf-8"))
    assert manifest["database_sha256"][run["case_id"]] == run["database_sha256"]
    assert manifest["policy_input_sha256"]
    assert manifest["runtime_request_parity_verified"] is False
    assert verify_toy_suite(output)["integrity_verified"] is True
    with sqlite3.connect(f"{database.as_uri()}?mode=ro", uri=True) as connection:
        assert connection.execute("select count(*) from investigation_steps").fetchone()[0] > 2
        assert connection.execute("select count(*) from probe_executions").fetchone()[0] >= 1


def test_full_toy_matrix_preserves_unknowns_and_family_groups(tmp_path: Path) -> None:
    report = run_toy_suite(tmp_path / "pilot")
    assert report["planned_cases"] == 14
    assert report["arms"]["deterministic"]["eligible"] == 14
    assert report["arms"]["current_default"]["unrun"] == 14
    assert report["paired_complete_cases"] == 0
    assert report["arms"]["deterministic"]["eligible_probe_opportunities"] == 53
    assert report["arms"]["deterministic"]["unrun_probe_opportunities"] == 43
    assert report["arms"]["deterministic"]["independently_supported_causal_answers"] == 0
    assert report["diagnostic_performance_admissible"] is False
    assert report["training_admissible"] is False
    plans = report["planned_inputs"]
    assert len({item["initial_input_sha256"] for item in plans[:7]}) == 1
    assert len({item["initial_input_sha256"] for item in plans[7:10]}) == 1
    assert len({item["initial_input_sha256"] for item in plans[10:]}) == 1
    assert {item["split"] for item in plans[:7]} == {"development"}
    assert {item["split"] for item in plans[10:]} == {"holdout"}
    labels = json.loads((tmp_path / "pilot/evaluator-only/outcomes.json").read_text())
    assert len(labels["cases"]) == 14
    assert any(item["scenario_id"] == "wifi_external" for item in labels["cases"])
    assert any(item["scenario_id"] == "wifi_irrelevant_abnormality" for item in labels["cases"])
    assert any(item["scenario_id"] == "wifi_missing_measurement" for item in labels["cases"])
    assert any(item["scenario_id"] == "pdf_healthy" for item in labels["cases"])
    assert all(item["diagnostic_performance_admissible"] is False for item in labels["cases"])
    missing = next(item for item in report["runs"] if item["case_id"] == "toy-network-browser-006")
    assert [attempt["probe_id"] for attempt in missing["probe_attempts"]] == [
        "core.system",
        "wifi.radio",
    ]
    assert missing["unrun_probe_opportunities"] == 3


def test_runner_requires_new_output_directory(tmp_path: Path) -> None:
    target = tmp_path / "pilot"
    run_toy_suite(target, scenario_names=("pdf_healthy",))
    with pytest.raises(FileExistsError):
        run_toy_suite(target, scenario_names=("pdf_healthy",))


def test_verify_rejects_changed_capture_without_reexecuting(tmp_path: Path) -> None:
    target = tmp_path / "pilot"
    run_toy_suite(target, scenario_names=("wifi_healthy",))
    visible_file = target / "policy-visible/inputs.json"
    visible_file.write_text(visible_file.read_text(encoding="utf-8") + "\n", encoding="utf-8")
    with pytest.raises(ValueError, match="artifact hash mismatch"):
        verify_toy_suite(target)


def test_one_failed_case_remains_in_denominator_and_next_case_runs(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = pilot._run_one  # pyright: ignore[reportPrivateUsage]

    def fail_first(database: Path, **kwargs: object) -> tuple[dict[str, object], dict[str, object]]:
        if kwargs["case_id"] == "toy-network-browser-001":
            raise RuntimeError("fixture setup failed")
        return original(database, **kwargs)  # pyright: ignore[reportArgumentType]

    monkeypatch.setattr(pilot, "_run_one", fail_first)
    report = run_toy_suite(tmp_path / "pilot", scenario_names=("wifi_healthy", "wifi_dns"))
    assert report["planned_cases"] == 2
    assert report["arms"]["deterministic"]["failed"] == 1
    assert report["arms"]["deterministic"]["completed"] == 1
    assert report["arms"]["deterministic"]["eligible_probe_opportunities"] == 8
    assert report["runs"][0]["failure_stage"] == "case_setup_or_readback"
    assert report["runs"][0]["failure_type"] == "RuntimeError"
    assert report["runs"][1]["status"] == "completed"
    assert report["arms"]["current_default"]["unrun"] == 2
