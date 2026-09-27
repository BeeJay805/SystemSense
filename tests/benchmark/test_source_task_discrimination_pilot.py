"""Freeze the sixteen synthetic source choices and honest comparison limits."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks.source_task_discrimination_pilot import run_pilot, verify_pilot


def test_source_discrimination_replay_and_custody(tmp_path: Path) -> None:
    output = tmp_path / "source-discrimination"
    result = run_pilot(output)
    assert result["eligible_scripted_choices"] == 16
    assert result["executed_scripted_choices"] == 16
    assert result["useful_evidence"] == 8
    assert result["wasted_retrievals"] == 8
    assert result["unknown_effects"] == 0
    assert result["capture_failures"] == result["review_failures"] == 0
    assert result["raw_commitment_mismatch_pairs"] == 8
    assert result["actual_adapter_visible_match_pairs"] == 8
    assert result["registered_synthetic_baseline_probe_attempts"] == 16
    assert result["postbaseline_source_probe_attempts"] == 0
    assert result["causal_claims_emitted"] == result["false_causal_claims"] == 0
    assert result["supported_causal_answers"] == 0
    assert result["actual_model_calls"] == 0
    assert result["comparison_admissible"] is False
    assert verify_pilot(output)["integrity_verified"] is True

    scores = result["baseline_selection_scores"]
    assert scores["first_item"]["useful"] == scores["first_item"]["wasted"] == 4
    assert scores["lexical_title_only_abstain"]["abstained"] == 8
    assert scores["lexical_title_tie_first"]["useful"] == 4
    assert scores["coverage_rule"]["useful"] == 8
    assert scores["coverage_rule"]["wasted"] == 0

    blind_path = output / "policy-visible" / "inputs.json"
    blind = json.loads(blind_path.read_text(encoding="utf-8"))
    blind_json = json.dumps(blind)
    assert len(blind["cells"]) == 16
    assert "world_key" not in blind_json
    assert "selected_record" not in blind_json
    assert "direct_same_origin_reachable" not in blind_json
    assert "viewer_render_p95_ms" not in blind_json
    assert "cpu_peak_percent" not in blind_json
    assert "storage_warning_count" not in blind_json

    attempts = json.loads((output / "evaluator-only" / "attempts.json").read_text())["cells"]
    reviews = json.loads((output / "evaluator-only" / "reviews.json").read_text())["reviews"]
    assert len({cell["world_key"] for cell in attempts}) == 4
    assert all(
        len({cell["checkpoint_sha256"] for cell in attempts if cell["domain"] == domain}) == 1
        for domain in ("network_browser", "application_performance")
    )
    assert {review["source_task_coverage_independent"] for review in reviews} == {
        "same_target_full_window",
        "different_target",
        "insufficient_window",
    }
    assert all(review["selected_retrieval_facts_verified"] for review in reviews)
    assert all(review["supported_causal_answer"] is False for review in reviews)
    assert sorted(
        tuple(review["toy_rivals_after"])
        for review in reviews
        if review["observed_effect"] == "reduces_toy_rivals"
    ) == sorted(
        (cause,)
        for cause in (
            "browser_profile_proxy_route",
            "external_origin_unreachable",
            "viewer_rendering_delay",
            "external_document_source_delay",
        )
        for _ in range(2)
    )

    blind_path.write_bytes(blind_path.read_bytes() + b" ")
    with pytest.raises(ValueError, match="pilot artifact hash mismatch"):
        verify_pilot(output)
