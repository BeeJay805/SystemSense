"""Run frozen sequential toy cases through the public investigator path."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from benchmarks import sequential_investigator_episodes as episodes
from benchmarks.sequential_investigator_episodes import run_episode_suite, verify_episode_suite


def test_proxy_pair_executes_only_registered_toy_probes(tmp_path: Path) -> None:
    output = tmp_path / "episodes"
    report = run_episode_suite(output, case_ids=("toy-network-002", "toy-network-007"))
    assert report["planned_cases"] == 2
    assert len({run["initial_input_sha256"] for run in report["runs"]}) == 1
    assert all(run["executions"] for run in report["runs"])
    assert all(run["runtime_case_id"] for run in report["runs"])
    assert all(run["incident_window"]["start"] for run in report["runs"])
    assert all(run["target_binding_status"] == "unverified_toy_scope" for run in report["runs"])
    assert all("assessment" in run and "stop_reason" in run for run in report["runs"])
    for run in report["runs"]:
        offered = {item for snapshot in run["offered"] for item in snapshot["probe_ids"]}
        assert offered
        assert all(item["probe_id"] in offered for item in run["selected"])
        assert all(item["probe_id"] in offered for item in run["executions"])
        assert all(item["observed_at"] and item["captured_at"] for item in run["evidence"])
    policy = (output / "policy-visible/run-report.json").read_text(encoding="utf-8")
    labels = json.loads((output / "evaluator-only/outcomes.json").read_text(encoding="utf-8"))
    assert "wrong_browser_proxy" not in policy
    assert labels["cases"][0]["root_causes"] == ["wrong_browser_proxy"]
    assert labels["cases"][1]["root_causes"] == []
    assert verify_episode_suite(output)["integrity_verified"] is True


def test_verified_export_rejects_tampering(tmp_path: Path) -> None:
    output = tmp_path / "episodes"
    run_episode_suite(output, case_ids=("toy-application-002", "toy-application-007"))
    with pytest.raises(FileExistsError):
        run_episode_suite(output, case_ids=("toy-application-002",))
    report = output / "policy-visible/run-report.json"
    report.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="integrity"):
        verify_episode_suite(output)


def test_case_setup_failure_is_recorded_without_skipping_next_case(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    original = episodes._registered_case  # pyright: ignore[reportPrivateUsage]

    def fail_first(store: Any, *, initial: dict[str, Any], world: Any) -> Any:
        if world.case_id == "toy-network-002":
            raise RuntimeError("synthetic setup failure")
        return original(store, initial=initial, world=world)

    monkeypatch.setattr(episodes, "_registered_case", fail_first)
    output = tmp_path / "episodes"
    report = run_episode_suite(output, case_ids=("toy-network-002", "toy-network-007"))
    assert report["runs"][0]["failure_stage"] == "case_setup"
    assert report["runs"][0]["failure_type"] == "RuntimeError"
    assert report["runs"][0]["executions"] == []
    assert report["runs"][1]["runtime_complete"] is True
    labels = json.loads((output / "evaluator-only/outcomes.json").read_text(encoding="utf-8"))
    assert labels["cases"][0]["observed_effects"] == []
    assert verify_episode_suite(output)["integrity_verified"] is True


def test_assessment_only_claim_remains_unadjudicated() -> None:
    world = next(
        world
        for world in episodes._WORLDS  # pyright: ignore[reportPrivateUsage]
        if world.case_id == "toy-network-002"
    )
    run: dict[str, Any] = {
        "evidence": [],
        "executions": [],
        "hypotheses": [],
        "assessment": {
            "disposition": "supported_observed_explanation",
            "explanation": "The proxy caused the failure.",
        },
        "registered_probe_ids": [],
    }
    scored = episodes._score_after_run(run, world)  # pyright: ignore[reportPrivateUsage]
    assert scored["false_causal_claim_count"] is None
    assert scored["false_claim_review_reason"] == "assessment_or_hypothesis_not_adjudicated"
    run["assessment"] = None
    assert (
        episodes._score_after_run(run, world)[  # pyright: ignore[reportPrivateUsage]
            "false_causal_claim_count"
        ]
        == 0
    )
