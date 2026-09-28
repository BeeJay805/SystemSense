"""Prospective source-cited reasoning must survive a later bounded evidence packet."""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path

from benchmarks.two_turn_source_trajectory import run


def test_source_prediction_survives_actual_later_probe(tmp_path: Path) -> None:
    output = tmp_path / "two-turn"
    manifest = run(output)
    visible = json.loads((output / "policy-visible" / "trajectory.json").read_text())
    readback = json.loads((output / "evaluator-only" / "readback.json").read_text())

    first = visible["first"]
    assert manifest["first_present"] is True
    assert first is not None
    assert first["request"]["schema_version"] == 7
    assert len(first["request"]["prior_hypothesis_revision_refs"]) == 2
    followup = next(
        probe
        for probe in first["request"]["available_probes"]
        if probe["probe_id"] == "fixture.direct_origin_after_source"
    )
    assert followup["probe_version"] == 1
    assert followup["prediction_outputs"] == [
        {
            "schema_version": 1,
            "name": "direct_origin_status",
            "allowed_values": ["online", "offline"],
        }
    ]
    chosen = readback["chosen_evidence_id"]
    selected = next(
        source for source in first["request"]["selected_sources"] if source["evidence_id"] == chosen
    )
    assert selected["source_task_relation"]["status"] == "same_target_full_window"
    assert not any(
        item["probe_id"] == "fixture.direct_origin_after_source"
        for item in first["request"]["evidence_context"]
    )
    assert first["response"]["considered_evidence_ids"] == [chosen]
    predictions = [
        hypothesis["expected_facts"][0]["expected_value"]
        for hypothesis in first["response"]["hypotheses"]
    ]
    assert predictions == ["online", "offline"]
    assert all(
        hypothesis["expected_facts_observed_after"] is None
        for hypothesis in first["response"]["hypotheses"]
    )

    assert manifest["followup_executions"] == 1
    assert readback["followup_executions"][0]["status"] == "ok"
    accepted = next(
        event
        for event in readback["events"]
        if event["event"] == "deep_applied"
        and any(hypothesis["expected_facts"] for hypothesis in event["hypotheses"])
    )
    stamped = accepted["hypotheses"][0]["expected_facts_observed_after"]
    later = readback["followup_record"][0]
    assert later["facts"]
    assert (
        next(fact["value"] for fact in later["facts"] if fact["name"] == "direct_origin_status")
        == "offline"
    )
    assert datetime.fromisoformat(later["observed_at"]) > datetime.fromisoformat(stamped)
    assert manifest["prediction_contested_events"] >= 1

    # RED on 91e6bf2: the later request sees the fact but loses both prior
    # source-cited rivals when the 12-context brief fills with newer sources.
    second = visible["second"]
    assert second is not None
    assert len(second["request"]["previous_hypotheses"]) == 2
    followup_id = later["evidence_id"]
    assert followup_id in second["response"]["considered_evidence_ids"]
    assert any(
        followup_id in hypothesis["contradicting_evidence_ids"]
        for hypothesis in second["response"]["hypotheses"]
    )
    assert readback["terminal_assessment"] is None
    assert all(
        hypothesis["status"] != "supported" for hypothesis in readback["terminal_hypotheses"]
    )
