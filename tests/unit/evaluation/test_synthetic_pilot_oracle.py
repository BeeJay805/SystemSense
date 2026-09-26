"""A hidden fixture oracle scores observed information, never model preference."""

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest

from systemsense.domain.ids import JsonValue
from systemsense.storage.candidate_decision_snapshots import CandidateDecisionSnapshotRepository
from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration.synthetic_pilot_oracle import (
    PDF_PROCESS_PAIR_SCENARIO,
    PILOT_SCENARIOS,
    assess_selected_fact,
    selected_action_receipt,
    synthetic_probe_facts,
    synthetic_process_pressure_facts,
    write_synthetic_recipe_binding,
)
from tests.unit.application.test_frontier_policy import CASE
from tests.unit.evaluation.test_frontier_pilot_export import (
    _fixture_worker_capture,  # pyright: ignore[reportPrivateUsage]
    _snapshots,  # pyright: ignore[reportPrivateUsage]
)


def test_pilot_recipes_keep_hidden_cause_out_of_baseline() -> None:
    assert {scenario.kind for scenario in PILOT_SCENARIOS} == {
        "pressure_fault",
        "healthy_control",
        "external_outage",
    }
    for scenario in PILOT_SCENARIOS:
        baseline = synthetic_probe_facts(scenario, "core.resources")
        assert "pressure_percent" not in baseline
        assert "external_service_status" not in baseline
        measured = synthetic_probe_facts(scenario, "pressure.sample")
        assert measured["pressure_percent"] == scenario.pressure_percent
    assert (
        synthetic_probe_facts(PILOT_SCENARIOS[2], "network.connectivity")["external_service_status"]
        == "unavailable"
    )


def test_oracle_scores_only_new_linked_fact() -> None:
    scenario = PILOT_SCENARIOS[0]
    observed = synthetic_probe_facts(scenario, "pressure.sample")
    assert assess_selected_fact(scenario, "pressure.sample", observed, ()) == "useful"
    prior = (("pressure_percent", scenario.pressure_percent),)
    assert assess_selected_fact(scenario, "pressure.sample", observed, prior) == "uninformative"


def test_process_pair_handler_observes_two_distinct_targets() -> None:
    viewer = synthetic_process_pressure_facts(PDF_PROCESS_PAIR_SCENARIO, 4201)
    indexer = synthetic_process_pressure_facts(PDF_PROCESS_PAIR_SCENARIO, 4202)
    assert cast(dict[str, JsonValue], viewer["target_pressure"])["target_pid"] == 4201
    assert cast(dict[str, JsonValue], indexer["target_pressure"])["target_pid"] == 4202
    assert viewer != indexer
    with pytest.raises(ValueError, match="fixture target"):
        synthetic_process_pressure_facts(PDF_PROCESS_PAIR_SCENARIO, 9999)


def test_oracle_rejects_fixture_mismatch_and_does_not_infer_other_actions() -> None:
    scenario = PILOT_SCENARIOS[2]
    with pytest.raises(ValueError, match="hidden recipe"):
        assess_selected_fact(scenario, "pressure.sample", {"pressure_percent": 97}, ())
    assert (
        assess_selected_fact(
            scenario,
            "network.connectivity",
            synthetic_probe_facts(scenario, "network.connectivity"),
            (),
        )
        == "useful"
    )
    assert assess_selected_fact(scenario, "core.system", {}, ()) == "unknown"


def test_unlinked_actual_draft_does_not_become_a_negative_label(tmp_path: Path) -> None:
    binding_path = tmp_path / "hidden-recipe-binding.json"
    write_synthetic_recipe_binding(binding_path, str(CASE), PILOT_SCENARIOS[1])
    with SQLiteStore(tmp_path / "oracle.db") as store:
        snapshot_id, _ = _snapshots(store, laya=True)
        repository = CandidateDecisionSnapshotRepository(store)
        snapshot = repository.readback_frontier(snapshot_id)
        _attention, calls = _fixture_worker_capture(snapshot.request)
        repository.capture_frontier_worker_draft(snapshot_id, calls)
        receipt = selected_action_receipt(
            store, snapshot_id, PILOT_SCENARIOS[1], binding_path=binding_path
        )
        assert receipt.selected_status == "unknown"
        assert receipt.execution_id is None
        assert receipt.item_outcomes == ((snapshot.selected_item_id, "unknown"),)
        assert receipt.training_admissible is False
        with pytest.raises(ValueError, match="hidden recipe binding"):
            selected_action_receipt(
                store, snapshot_id, PILOT_SCENARIOS[2], binding_path=binding_path
            )
