"""CPU-only checks for the prospective actual-model trial's fixture and gate."""

from __future__ import annotations

from pathlib import Path

import pytest

from benchmarks.actual_model_full_loop import run, select_trajectory
from benchmarks.source_task_relation_red import run_balanced_relation_probe
from benchmarks.two_turn_source_trajectory import TwoTurnReasoner


def test_full_loop_gate_uses_executed_later_evidence(tmp_path: Path) -> None:
    provider = TwoTurnReasoner()
    cells = run_balanced_relation_probe(
        tmp_path / "cases",
        domain_filter="network_browser",
        matched_indices=(49,),
        chosen_indices=(49,),
        reasoning_factory=lambda: provider,
        followup_direct_status="offline",
        allow_evicted_choice=True,
        case_budget_ms=180_000,
    )
    assert len(cells) == 1
    visible, indices = select_trajectory(
        provider.exchanges, selected_source_id=cells[0]["chosen_evidence_id"]
    )
    assert indices["first_index"] is not None
    assert indices["second_index"] is not None
    first, second = visible["first"], visible["second"]
    assert first is not None and second is not None
    assert first["request"]["budget_ms"] <= 180_000
    prediction = first["response"]["hypotheses"][0]["expected_facts"][0]
    assert prediction["probe_id"] == "fixture.direct_origin_after_source"
    assert prediction["fact_name"] == "direct_origin_status"
    assert prediction["expected_value"] == "online"
    assert not any(
        item["probe_id"] == "fixture.direct_origin_after_source"
        for item in first["request"]["evidence_context"]
    )
    observed_id = next(
        item["evidence_id"]
        for item in second["request"]["evidence_context"]
        if item["probe_id"] == "fixture.direct_origin_after_source"
    )
    assert observed_id in second["response"]["considered_evidence_ids"]

    # Check selection and later evidence remain eligible when Qwen issues no
    # optional expected fact. Prediction utility is a separate subscore.
    no_predictions = [
        (
            request.model_copy(update={"previous_hypotheses": ()}),
            response.model_copy(
                update={
                    "hypotheses": tuple(
                        hypothesis.model_copy(update={"expected_facts": ()})
                        for hypothesis in response.hypotheses
                    )
                }
            ),
        )
        for request, response in provider.exchanges
    ]
    _, no_prediction_indices = select_trajectory(
        no_predictions, selected_source_id=cells[0]["chosen_evidence_id"]
    )
    assert no_prediction_indices["first_index"] is not None
    assert no_prediction_indices["second_index"] is not None


def test_trial_refuses_to_reuse_output_directory(tmp_path: Path) -> None:
    output = tmp_path / "existing"
    output.mkdir()
    with pytest.raises(FileExistsError):
        run(
            output,
            profile_path=Path("examples/warm-local-development.profile.json"),
            outcome_file=tmp_path / "unused-outcome",
        )
