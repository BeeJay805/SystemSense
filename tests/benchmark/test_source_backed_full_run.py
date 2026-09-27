"""Keep the new full-run reachability and parity failure explicit."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks.source_backed_full_run import run_full_run_pilot, verify_full_run_pilot


def test_full_run_source_choices_and_prechoice_commitment_gate(tmp_path: Path) -> None:
    output = tmp_path / "full-run"
    result = run_full_run_pilot(output)
    assert result["cells"] == 8
    assert result["full_run_target_menus"] == 8
    assert result["comparison_admissible"] is False
    assert set(result["hidden_world_prechoice_parity"].values()) == {"mismatched"}
    assert verify_full_run_pilot(output)["integrity_verified"] is True

    attempts = json.loads((output / "attempts.json").read_text(encoding="utf-8"))
    expected = [f"ev_{index:032x}" for index in range(49, 53)]
    for case_key, checkpoint in attempts["checkpoints"].items():
        task = checkpoint["task_observation"]
        assert task["case_id"] == checkpoint["case_id"]
        assert task["collector_id"] == "fixture.task_baseline"
        assert task["classification"] == "fixture_simulated_task_observation"
        assert task["facts"]["synthetic_window_end_utc"] == task["observed_at"]
        assert task["facts"]["synthetic_window_start_utc"] < task["observed_at"]
        family = [cell for cell in attempts["cells"] if cell["case_key"] == case_key]
        assert len(family) == 4
        assert len({cell["initial_checkpoint_sha256"] for cell in family}) == 1
        assert all(cell["target_source_evidence_ids"] == expected for cell in family)
        assert all(cell["source_menu_evidence_ids"] == expected for cell in family)
        assert len({tuple(cell["source_menu_item_ids"]) for cell in family}) == 1
        assert {cell["selected_evidence_id"] for cell in family} == set(expected[:2])
        assert all(cell["status"] == "complete" for cell in family)
        assert all(cell["probe_attempt_count"] == 1 for cell in family)
        assert all(cell["preexisting_synthetic_source_count"] == 52 for cell in family)
        assert all(cell["preexisting_source_probe_execution_links"] == 0 for cell in family)
        assert all(
            cell["provider_call"]["state_version"] == cell["target_state_version"]
            for cell in family
        )
        assert all(cell["provider_call"]["degraded"] is False for cell in family)
        parity = attempts["parity"][case_key]
        assert parity["same_world_choice_parity"] is True
        assert parity["same_domain_menu_ids"] is True
        assert parity["hidden_world_prechoice_request_parity"] == "mismatched"
        assert parity["current_adapter_laya_payload_parity"] == "matched"
        assert parity["current_adapter_local_deep_payload_parity"] == "matched"
        assert len(set(parity["source_record_sha256_by_world"].values())) == 2
        assert parity["reason_if_mismatched"] == (
            "validated_rank_request_envelope_source_commitment_differs"
        )

    blind = json.loads((output / "policy-visible" / "requests.json").read_text(encoding="utf-8"))
    assert len(blind["cells"]) == 8
    assert "world_key" not in json.dumps(blind)
    assert "selected_facts" not in json.dumps(blind)
    assert "compatible_toy_causes" not in json.dumps(blind)

    reviews = json.loads((output / "evaluator-only" / "reviews.json").read_text(encoding="utf-8"))[
        "reviews"
    ]
    assert sorted(review["observed_effect"] for review in reviews) == [
        *(["does_not_reduce_compatible_toy_causes"] * 4),
        *(["reduces_compatible_toy_causes"] * 4),
    ]
    assert all(review["supported_causal_answer"] is False for review in reviews)

    attempts_path = output / "attempts.json"
    attempts_path.write_bytes(attempts_path.read_bytes() + b" ")
    with pytest.raises(ValueError, match="artifact hash mismatch"):
        verify_full_run_pilot(output)
