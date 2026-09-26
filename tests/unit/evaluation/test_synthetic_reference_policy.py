"""The research reference sees frozen choices; the recipe stays with evaluation."""

from __future__ import annotations

import json
from copy import deepcopy
from pathlib import Path
from typing import cast

from systemsense.decision.frontier_ranker import FrontierRankRequestV1
from systemsense.storage.candidate_decision_snapshots import CandidateDecisionSnapshotRepository
from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration.synthetic_pilot_oracle import (
    PILOT_SCENARIOS,
    compare_visible_reference,
    evaluate_reference_measurement,
    reference_next_step,
    write_synthetic_recipe_binding,
)
from tests.unit.application.test_frontier_policy import CASE
from tests.unit.evaluation.test_frontier_pilot_export import (
    _fixture_worker_capture,  # pyright: ignore[reportPrivateUsage]
    _snapshots,  # pyright: ignore[reportPrivateUsage]
)


def _menu_with_deep_and_second_measurement(request: FrontierRankRequestV1) -> FrontierRankRequestV1:
    payload = deepcopy(request.model_dump(mode="json"))
    original_item = payload["items"][0]
    original_semantic = payload["item_semantics"][0]
    deep_id = "fr_v1_" + "d" * 64
    question_id = "question_v1_" + "d" * 32
    deep_item = {
        **original_item,
        "item_id": deep_id,
        "reference": {"schema_version": 1, "kind": "consult_deep", "question_id": question_id},
        "cost_ms": 0,
    }
    deep_semantic = cast(
        dict[str, object],
        {
            **original_semantic,
            "item_id": deep_id,
            "reference_id": question_id,
            "source_kind": "reasoning_question",
            "quality": "proposed",
            "information_goal": "Which explanation should be examined against available evidence?",
            "measurement_window": None,
            "measurement": None,
            "source_recorded_at": None,
            "source_time_quality": "not_available",
            "limitations": [],
        },
    )
    pressure_semantic = {
        **original_semantic,
        "target_scope": "host",
        "measurement": {
            **original_semantic["measurement"],
            "probe_id": "pressure.sample",
            "observable": "pressure.sample",
        },
        "information_goal": "Would a registered pressure sample explain the slow computer?",
    }
    network_id = "fr_v1_" + "e" * 64
    candidate_id = "cand_v1_" + "e" * 32
    network_item = {
        **original_item,
        "item_id": network_id,
        "reference": {**original_item["reference"], "candidate_id": candidate_id},
        "cost_ms": 2000,
    }
    network_semantic = {
        **original_semantic,
        "target_scope": "host",
        "item_id": network_id,
        "reference_id": candidate_id,
        "measurement": {
            **original_semantic["measurement"],
            "probe_id": "network.connectivity",
            "observable": "network.connectivity",
        },
        "information_goal": "Would a registered connectivity check explain the slow service?",
    }
    payload["items"] = [deep_item, original_item, network_item]
    payload["item_semantics"] = [deep_semantic, pressure_semantic, network_semantic]
    return FrontierRankRequestV1.model_validate(payload)


def test_reference_uses_offered_visible_measurements_and_symptom(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "reference.db") as store:
        snapshot_id, _ = _snapshots(store, laya=True)
        frozen = CandidateDecisionSnapshotRepository(store).readback_frontier(snapshot_id).request
        menu = _menu_with_deep_and_second_measurement(frozen)
    slow_computer = menu.model_copy(update={"symptom": "Investigate synthetic slow computer"})
    slow_service = menu.model_copy(update={"symptom": "Investigate synthetic slow service"})
    assert reference_next_step(slow_computer).selected_item_id == slow_computer.items[1].item_id
    assert reference_next_step(slow_service).selected_item_id == slow_service.items[2].item_id
    assert reference_next_step(slow_service).considered_item_ids == tuple(
        item.item_id for item in slow_service.items
    )
    choice = reference_next_step(slow_computer)
    assert evaluate_reference_measurement(slow_computer, choice, PILOT_SCENARIOS[0], ()) == (
        "useful"
    )
    assert (
        evaluate_reference_measurement(
            slow_computer,
            choice,
            PILOT_SCENARIOS[0],
            (("pressure_percent", PILOT_SCENARIOS[0].pressure_percent),),
        )
        == "uninformative"
    )


def test_visible_same_window_fact_reduces_repeat_priority(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "reference.db") as store:
        snapshot_id, _ = _snapshots(store, laya=True)
        frozen = CandidateDecisionSnapshotRepository(store).readback_frontier(snapshot_id).request
        menu = _menu_with_deep_and_second_measurement(frozen)
    payload = deepcopy(menu.model_dump(mode="json"))
    packet = payload["evidence_packets"][0]
    visible = json.loads(packet["description"])
    visible.update(
        packet_kind="fact",
        value_quality="exact",
        probe_id="pressure.sample",
        metric="pressure_percent",
        value=97,
    )
    packet["description"] = json.dumps(visible)
    payload["symptom"] = "Investigate synthetic slow computer"
    request = FrontierRankRequestV1.model_validate(payload)
    assert reference_next_step(request).selected_item_id == request.items[2].item_id


def test_reference_comparison_keeps_unrun_alternatives_unknown(tmp_path: Path) -> None:
    binding_path = tmp_path / "hidden-recipe-binding.json"
    scenario = PILOT_SCENARIOS[1]
    write_synthetic_recipe_binding(binding_path, str(CASE), scenario)
    with SQLiteStore(tmp_path / "comparison.db") as store:
        snapshot_id, _ = _snapshots(store, laya=True)
        repository = CandidateDecisionSnapshotRepository(store)
        snapshot = repository.readback_frontier(snapshot_id)
        _attention, calls = _fixture_worker_capture(snapshot.request)
        repository.capture_frontier_worker_draft(snapshot_id, calls)
        result = compare_visible_reference(store, snapshot_id, scenario, binding_path=binding_path)
        assert result.reference_item_id == snapshot.selected_item_id
        assert result.reference_status == "unknown"
        assert result.actual_status == "unknown"
        assert result.learning_candidate is False
        assert result.training_admissible is False
