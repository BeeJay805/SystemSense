"""Regression checks for synthetic registered-probe custody and blind cases."""

from __future__ import annotations

import hashlib
import json
from collections import Counter
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, cast

import pytest

from benchmarks.overnight_cases import case_contract, load_cases, synthetic_probe_runner
from systemsense.orchestration.probes import ProbeRunStatus
from systemsense.packs.runtime import default_probe_definitions

_FIXTURES = Path(__file__).resolve().parents[3] / "benchmarks" / "fixtures"


def test_twelve_blind_cases_have_balanced_within_family_splits_and_frozen_contracts() -> None:
    recipes = load_cases()
    suite = json.loads((_FIXTURES / "overnight_suite.json").read_text(encoding="utf-8"))
    oracle = json.loads((_FIXTURES / "overnight_oracle.json").read_text(encoding="utf-8"))
    assert (
        oracle["suite_sha256"]
        == hashlib.sha256((_FIXTURES / "overnight_suite.json").read_bytes()).hexdigest()
    )

    assert len(recipes) == len(suite["cases"]) == len(oracle["cases"]) == 12
    assert set(recipes) == set(oracle["cases"]) == {row["case_id"] for row in suite["cases"]}
    assert Counter((row["family_group"], row["split"]) for row in suite["cases"]) == {
        (family, split): 2
        for family in ("network", "application", "performance")
        for split in ("development", "holdout")
    }
    for row in suite["cases"]:
        assert row["source"] == "synthetic"
        assert row["budget_ms"] == recipes[row["case_id"]]["budget_ms"]
        assert all(row[key] == value for key, value in case_contract(row["case_id"]).items())
        assert "split" not in recipes[row["case_id"]]
        assert "family" not in recipes[row["case_id"]]
        assert "hidden_simulated_cause" not in recipes[row["case_id"]]
        assert "verification" not in recipes[row["case_id"]].get("reported_task", {})
        assert oracle["cases"][row["case_id"]]["leak_markers"]


@pytest.mark.parametrize("case_id", tuple(load_cases()))
def test_all_registered_probes_are_replaced_without_changing_manifests(case_id: str) -> None:
    recipe = load_cases()[case_id]
    runner = synthetic_probe_runner(recipe)
    defaults = {item.manifest.probe_id: item for item in default_probe_definitions()}

    assert runner.probe_ids == frozenset(defaults)
    assert not runner.isolated_probe_ids
    for probe_id, definition in defaults.items():
        assert runner.manifest(probe_id) == definition.manifest
    for probe_id in ("core.system", "network.snapshot", "incident.events", "power.snapshot"):
        result = runner.run(probe_id, {})
        assert result.status is ProbeRunStatus.OK
        assert result.observation is not None
        assert "Synthetic fixture" in result.observation.limitations[0]


def test_network_proxy_state_is_local_configuration_not_reachability() -> None:
    runner = synthetic_probe_runner(load_cases()["case-7c2b80de4573"])
    connectivity = runner.run("network.connectivity", {}).observation
    configuration = runner.run("network.configuration", {}).observation
    assert connectivity is not None and configuration is not None
    connectivity_facts = cast(dict[str, Any], connectivity.facts)
    configuration_facts = cast(dict[str, Any], configuration.facts)
    assert connectivity_facts["connectivity"]["proxy"]["manual_enabled"] is True
    assert configuration_facts["proxy"]["enabled"] is True
    assert "reachability" in " ".join(connectivity.limitations)
    assert "reachability" not in connectivity.facts


def test_application_event_retains_other_target_and_source_time() -> None:
    runner = synthetic_probe_runner(load_cases()["case-a934ed27f3c1"])
    observation = runner.run("incident.events", {}).observation
    assert observation is not None
    event = cast(dict[str, Any], observation.facts)["events"][0]
    assert event["event_data"]["AppName"] == "OtherTool.exe"
    assert (
        datetime.fromisoformat(observation.captured_at.isoformat())
        - datetime.fromisoformat(event["observed_at"])
    ).total_seconds() >= 52 * 60


def test_initial_cpu_spike_and_later_sample_disagree_without_erasing_either() -> None:
    runner = synthetic_probe_runner(load_cases()["case-6db492a1c735"])
    first = runner.run("core.resources", {}).observation
    later = runner.run("pressure.sample", {}).observation
    assert first is not None and later is not None
    assert cast(dict[str, Any], first.facts)["resources"]["cpu_percent"] == 97
    assert [
        item["system_cpu_percent"]
        for item in cast(dict[str, Any], later.facts)["pressure"]["samples"]
    ] == [3] * 3


def test_denied_and_unsupported_stay_explicit_unknowns() -> None:
    network = synthetic_probe_runner(load_cases()["case-509ed3c4b780"])
    connectivity = network.run("network.connectivity", {}).observation
    assert connectivity is not None
    assert connectivity.facts["collection_status"] == "permission_denied"
    assert cast(dict[str, Any], connectivity.facts)["connectivity"]["proxy"] is None

    performance = synthetic_probe_runner(load_cases()["case-b3e7814a209c"])
    sample = performance.run("gpu.telemetry.sample", {}).observation
    assert sample is not None
    series = cast(dict[str, Any], sample.facts)["gpu_telemetry_sample"]
    assert series["status"] == "unsupported"
    assert all(not frame["gpus"] for frame in series["samples"])


def test_explicit_live_window_fails_closed_instead_of_fabricating_time_binding() -> None:
    runner = synthetic_probe_runner(load_cases()["case-6db492a1c735"])
    start = datetime.now(UTC)
    parameters = {
        "window_start": start.isoformat(),
        "window_end": (start + timedelta(seconds=10)).isoformat(),
    }
    for probe_id in ("pressure.sample", "gpu.telemetry.sample"):
        result = runner.run(probe_id, parameters)
        assert result.status is ProbeRunStatus.FAILED
        assert result.observation is None
        assert result.error is not None and "exact live sample window" in result.error
