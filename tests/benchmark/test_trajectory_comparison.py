"""The comparison runner executes available arms and retains every planned cell."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks import trajectory_comparison as comparison
from benchmarks.sequential_investigator_episodes import (
    _score_after_run,  # pyright: ignore[reportPrivateUsage]
)
from benchmarks.sequential_visible_matrix import _WORLDS  # pyright: ignore[reportPrivateUsage]
from benchmarks.trajectory_comparison import (
    ArmAdapter,
    freeze_sequential_comparison,
    run_comparison,
    verify_comparison,
)
from benchmarks.trajectory_protocol import Arm
from systemsense.inference.factory import load_advisory_providers
from systemsense.inference.settings import LocalInferenceConfig


def _deterministic() -> ArmAdapter:
    return ArmAdapter(
        provider_factory=lambda: load_advisory_providers(LocalInferenceConfig()),
        expected_mode="deterministic",
        scout_prefetch=False,
    )


def test_frozen_matrix_reserves_all_toy_cases_without_leaking_labels() -> None:
    protocol = freeze_sequential_comparison()
    assert len(protocol.cases) == 14
    assert {case.source for case in protocol.cases} == {"synthetic"}
    assert {case.split for case in protocol.cases} == {"development"}
    assert len({case.visible_input_sha256 for case in protocol.cases[:7]}) == 1
    assert len({case.ordered_tools_sha256 for case in protocol.cases[7:]}) == 1
    assert "wrong_browser_proxy" not in protocol.model_dump_json()
    assert "storage_saturation" not in protocol.model_dump_json()


def test_missing_arms_are_explicitly_unavailable_not_completed(tmp_path: Path) -> None:
    output = tmp_path / "comparison"
    protocol = freeze_sequential_comparison(("toy-network-002",))
    result = run_comparison(output, protocol=protocol, adapters={})
    assert len(result["attempts"]) == 4
    assert {item["status"] for item in result["attempts"]} == {"unavailable"}
    assert all(item["reason"] == "no_admitted_arm_adapter" for item in result["attempts"])
    assert result["score"]["complete_paired_cases"] == 0
    assert all(arm["unrun"] == 1 for arm in result["score"]["arms"].values())
    assert json.loads((output / "trajectories.json").read_text(encoding="utf-8")) == []


def test_deterministic_arm_runs_real_investigator_with_private_review(tmp_path: Path) -> None:
    output = tmp_path / "comparison"
    protocol = freeze_sequential_comparison(("toy-network-002", "toy-network-007"))
    result = run_comparison(
        output, protocol=protocol, adapters={Arm.DETERMINISTIC: _deterministic()}
    )
    attempts = result["attempts"]
    deterministic = [item for item in attempts if item["arm"] == Arm.DETERMINISTIC.value]
    assert len(attempts) == 8 and len(deterministic) == 2
    assert all(item["status"] == "completed" for item in deterministic)
    assert all(item["coverage"]["executions"] for item in deterministic)
    assert all(item["provider_identities"] for item in deterministic)
    assert all(
        item["provider_configuration"]["effective_mode"] == "deterministic"
        for item in deterministic
    )
    assert all(item["model_cost_usd"] == 0.0 for item in deterministic)
    assert all(item["host_impact_ms"] is None for item in deterministic)
    assert result["score"]["arms"][Arm.DETERMINISTIC.value]["completed"] == 2
    assert result["score"]["complete_paired_cases"] == 0
    assert result["by_family"]["toy_network_sequential"]["planned_cases"] == 2
    assert result["provider_pin_parity"]["toy-network-002"]["status"] == "unknown"
    assert result["runtime_parity_admissible"] is False
    assert all(
        item["status"] == "unavailable" for item in attempts if item["arm"] != Arm.DETERMINISTIC
    )
    public = (output / "attempts.json").read_text(encoding="utf-8")
    private = (output / "evaluator-only" / "reviews.json").read_text(encoding="utf-8")
    assert "wrong_browser_proxy" not in public
    assert "wrong_browser_proxy" in private
    assert verify_comparison(output)["integrity_verified"] is True
    reviews = json.loads(private)
    assert reviews[0]["review"]["cause_equivalence"]["supported_answer_inferred"] is False


def test_verifier_rejects_tampered_attempts(tmp_path: Path) -> None:
    output = tmp_path / "comparison"
    run_comparison(output, protocol=freeze_sequential_comparison(("toy-network-001",)))
    report = output / "attempts.json"
    report.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="integrity"):
        verify_comparison(output)


def test_bad_provider_mode_is_failure_not_false_arm_result(tmp_path: Path) -> None:
    output = tmp_path / "comparison"
    protocol = freeze_sequential_comparison(("toy-application-002",))
    wrong = ArmAdapter(
        provider_factory=lambda: load_advisory_providers(LocalInferenceConfig()),
        expected_mode="deep-only",
        scout_prefetch=False,
    )
    result = run_comparison(output, protocol=protocol, adapters={Arm.DEEP_ONLY: wrong})
    deep = next(item for item in result["attempts"] if item["arm"] == Arm.DEEP_ONLY)
    assert deep["status"] == "failed"
    assert deep["reason"] == "provider_factory:ValueError"
    assert deep["answer"] == {"hypotheses": [], "assessment": None}
    assert result["score"]["arms"][Arm.DEEP_ONLY.value]["failed"] == 1


def test_unavailable_measurement_is_observed_without_causal_guess(tmp_path: Path) -> None:
    result = run_comparison(
        tmp_path / "comparison",
        protocol=freeze_sequential_comparison(("toy-network-006",)),
    )
    run = result["attempts"][0]
    assert run["status"] == "completed"
    attribution = run["failure_attribution"]
    assert attribution["observation_unavailable"]["observed"] is True
    assert attribution["decisive_evidence_omitted"] == "unknown"
    assert attribution["deep_failure_given_sufficient_evidence"] == "unknown"
    assert attribution["policy_missed_useful_offered_action"] == "unknown"


def test_overlapping_probe_completions_keep_a_valid_time_series() -> None:
    run = {
        "executions": [
            {"execution_id": "first", "probe_id": "browser.route_attempt", "status": "ok"},
            {"execution_id": "second", "probe_id": "browser.direct_control", "status": "ok"},
        ]
    }
    review = {
        "observed_effects": [
            {"execution_id": "first", "utility": "useful", "finished_ms": 9},
            {"execution_id": "second", "utility": "negative", "finished_ms": 3},
        ]
    }
    choices = comparison._choices(run, review, 12)  # pyright: ignore[reportPrivateUsage]
    assert [item.item_id for item in choices] == [
        "browser.direct_control",
        "browser.route_attempt",
    ]
    assert [item.elapsed_ms for item in choices] == [3, 9]
    assert run["executions"][0]["execution_id"] == "first"


def test_joint_batch_utility_uses_frozen_menu_tie_order() -> None:
    world = next(item for item in _WORLDS if item.case_id == "toy-application-007")
    probe_ids = (
        "application.task_timing",
        "application.storage_latency",
        "application.renderer_mode",
        "application.external_control",
    )
    executions = [
        {
            "execution_id": f"exec-{index}",
            "probe_id": probe_id,
            "status": "ok",
            "state_version": 7,
            "finished_at": f"2026-09-27T00:00:00.{(10 - index) * 1000:06d}+00:00",
        }
        for index, probe_id in enumerate(probe_ids)
    ]
    evidence = [
        {
            "execution_id": f"exec-{index}",
            "statement_kind": "observed_fact",
            "facts": [
                {"name": "observation", "value": world.observations[index]},
                {"name": "measurement_status", "value": "observed"},
            ],
        }
        for index in range(len(probe_ids))
    ]
    run = {
        "case_id": world.case_id,
        "executions": executions,
        "evidence": evidence,
        "created_at": "2026-09-27T00:00:00+00:00",
        "registered_probe_ids": ["core.system", *probe_ids, "system.battery_wear"],
        "hypotheses": [],
        "assessment": None,
    }
    first = _score_after_run(run, world)
    reversed_run = {**run, "executions": list(reversed(executions))}
    second = _score_after_run(reversed_run, world)
    assert first["observed_effects"] == second["observed_effects"]
    assert [item["probe_id"] for item in first["observed_effects"]] == list(probe_ids)
    assert first["first_useful_evidence_ms"] == min(
        item["finished_ms"] for item in first["observed_effects"] if item["utility"] == "useful"
    )


def test_changed_protocol_is_rejected_before_output(tmp_path: Path) -> None:
    protocol = freeze_sequential_comparison(("toy-network-002",))
    altered = protocol.model_copy(update={"digest": "0" * 64})
    output = tmp_path / "comparison"
    with pytest.raises(ValueError, match="unchanged frozen"):
        run_comparison(output, protocol=altered)
    assert not output.exists()
