"""The new synthetic fixture must reach a real, source-bound frontier menu."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks.source_backed_frontier_pilot import (
    run_cpu_reachability,
    verify_cpu_reachability,
)


def test_two_domains_reach_same_four_source_choices_from_reset_states(tmp_path: Path) -> None:
    output = tmp_path / "source-backed"
    result = run_cpu_reachability(output)
    assert result["cells"] == 4
    assert result["source_menus"] == 4
    assert result["comparison_admissible"] is False
    assert verify_cpu_reachability(output)["integrity_verified"] is True
    protocol = json.loads((output / "protocol.json").read_text(encoding="utf-8"))
    assert protocol["expected_no_new_fact_pages_before_offer"] == 6
    assert protocol["no_new_fact_pages_are_accounted"] is True
    assert protocol["affected_task_bound"] is False
    assert (
        protocol["ordinary_full_run_reachability"]
        == "ranker_reached_in_separate_registered_probe_prototype"
    )
    assert protocol["ordinary_full_run_target_menu"] == "not_matched_in_that_prototype"
    assert protocol["timing_clock"]["name"] == "perf_counter"
    assert protocol["timing_clock"]["resolution_seconds"] <= 0.001
    assert protocol["representativeness"] == "catalog_paging_stress_not_ordinary_task_latency"

    attempts = json.loads((output / "attempts.json").read_text(encoding="utf-8"))["cells"]
    expected = [f"ev_{index:032x}" for index in range(49, 53)]
    for case_key in {cell["case_key"] for cell in attempts}:
        pair = [cell for cell in attempts if cell["case_key"] == case_key]
        assert len(pair) == 2
        assert {cell["policy"] for cell in pair} == {
            "scripted_ordinal_0",
            "scripted_ordinal_1",
        }
        assert all(cell["source_menu_evidence_ids"] == expected for cell in pair)
        assert all(len(set(cell["source_menu_item_ids"])) == 4 for cell in pair)
        assert all(cell["no_new_fact_pages_before_offer"] == 6 for cell in pair)
        assert all(cell["seeded_probe_attempts"] == 0 for cell in pair)
        assert all(0 < cell["no_new_fact_page_ms"] < cell["time_to_first_menu_ms"] for cell in pair)
        assert all(cell["time_to_first_menu_ms"] <= cell["total_cell_ms"] for cell in pair)
        assert {cell["selected_evidence_id"] for cell in pair} == set(expected[:2])
        for cell in pair:
            call = cell["provider_call"]
            assert call["role"] == "catalog_attention"
            assert call["provider_id"] == "scripted-source-frontier-v1"
            assert call["detail"] == "event_frontier_retrieval"
            assert call["degraded"] is False
            assert (
                call["state_version"]
                in cell["frontier_offer_counts"]["source_offer_state_versions"]
            )
            assert cell["rank_response"]["ranked_item_ids"][0] in cell["source_menu_item_ids"]
            assert len(cell["rank_request"]["items"]) == 4
            assert all(
                item["reference"]["kind"] == "retrieve_evidence"
                for item in cell["rank_request"]["items"]
            )
            request_json = json.dumps(cell["rank_request"], sort_keys=True)
            assert "127.0.0.1:9" not in request_json
            assert "viewer_render_p95_ms" not in request_json

    reviews = json.loads((output / "evaluator-only" / "reviews.json").read_text(encoding="utf-8"))[
        "reviews"
    ]
    assert sorted(item["observed_effect"] for item in reviews) == [
        "does_not_reduce_compatible_toy_causes",
        "does_not_reduce_compatible_toy_causes",
        "reduces_compatible_toy_causes",
        "reduces_compatible_toy_causes",
    ]
    assert all(item["supported_answer_inferred"] is False for item in reviews)
    assert all(
        item["affected_task_outcome"] == "synthetic_fact_only_real_task_unbound" for item in reviews
    )
    assert all(
        item["observed_effect_scope"] == "synthetic_recipe_compatibility_only" for item in reviews
    )
    assert "compatible_toy_causes" not in (output / "protocol.json").read_text(encoding="utf-8")


def test_verify_rejects_changed_public_attempt(tmp_path: Path) -> None:
    output = tmp_path / "source-backed"
    run_cpu_reachability(output)
    attempts = output / "attempts.json"
    attempts.write_bytes(attempts.read_bytes() + b" ")
    with pytest.raises(ValueError, match="artifact hash mismatch"):
        verify_cpu_reachability(output)
