"""Actual fake-transport serialization cannot hide the frozen title/order cues."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks.source_backed_paired_input_audit import (
    audit_paired_inputs,
    verify_paired_inputs,
)


def test_actual_adapter_pair_audit_keeps_confounds_and_failures_visible(tmp_path: Path) -> None:
    output = tmp_path / "paired-audit"
    assert audit_paired_inputs(output) == {
        "eligible_cells": 8,
        "capture_failures": 0,
        "pairs": 4,
        "comparison_admissible": False,
    }
    assert verify_paired_inputs(output)["integrity_verified"] is True
    blind_text = (output / "policy-visible" / "inputs.json").read_text(encoding="utf-8")
    assert "world_key" not in blind_text
    assert "selected_facts" not in blind_text
    blind = json.loads(blind_text)
    assert blind["eligible_cells"] == 8
    assert len(blind["cells"]) == 8
    assert blind["failures"] == []
    for cell in blind["cells"]:
        assert cell["status"] == "captured"
        original = cell["original"]
        reversed_input = cell["counterbalanced_adapter_only_not_executed"]
        task = original["task_context"]
        assert task["scope"] == "synthetic_fixture"
        assert "no Windows" in task["limitation"]
        assert original["laya_attend"]["state"]["task_context"] == task
        assert original["local_deep_prompt"]["task_context"] == task
        assert reversed_input["item_ids_in_order"] == list(reversed(original["item_ids_in_order"]))
        assert reversed_input["task_context"] == task
        assert {phase["phase"] for phase in original["laya_fitted_worker"]} >= {
            "evidence",
            "probe",
        }
        assert all(
            phase["state"]["task_context"] == task for phase in original["laya_fitted_worker"]
        )
        assert [
            item["item_id"] for item in original["local_deep_prompt"]["offered_items"]
        ] == original["item_ids_in_order"]

    evaluator = json.loads((output / "evaluator-only" / "pairs.json").read_text())
    assert evaluator["comparison_admissible"] is False
    assert len(evaluator["pairs"]) == 4
    for pair in evaluator["pairs"]:
        assert pair["raw_prechoice_request_parity"] == "mismatched"
        assert len(set(pair["raw_request_commitments"])) == 2
        assert pair["actual_adapter_payload_parity"] == "matched"
        assert pair["title_cues_relevance"] is True
        assert pair["ev49_position_zero_based"] == 0
        assert pair["ev50_position_zero_based"] == 1
        assert pair["source_ids_and_order_cue_identity"] is True
        assert pair["first_item_baseline_picks_ev49"] is True
        assert pair["lexical_title_baseline_picks_ev49"] is True
        assert pair["counterbalance_feasible_adapter_only"] is True
        assert pair["counterbalanced_ev49_position_zero_based"] == 3
        assert pair["counterbalanced_first_item_picks_ev49"] is False
        assert pair["counterbalance_removes_title_cue"] is False

    artifact = output / "policy-visible" / "inputs.json"
    artifact.write_bytes(artifact.read_bytes() + b" ")
    with pytest.raises(ValueError, match="audit artifact hash mismatch"):
        verify_paired_inputs(output)
