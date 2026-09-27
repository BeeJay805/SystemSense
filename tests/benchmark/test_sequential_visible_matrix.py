"""Sequential toy evidence stays visible; causal recipes stay evaluator-only."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks.sequential_visible_matrix import build_matrix, export_matrix, verify_export


def test_domains_share_initial_inputs_but_have_distinct_hidden_causes() -> None:
    matrix = build_matrix()
    for domain in ("network_browser", "application_performance"):
        rows = [case for case in matrix.visible if case["domain"] == domain]
        assert len(rows) >= 6
        assert len({case["initial_sha256"] for case in rows}) == 1
        assert len({case["case_id"] for case in rows}) == len(rows)
        assert all(case["stages"][0]["probe_id"] is None for case in rows)
        assert all(case["stages"][-1]["stage_index"] == 5 for case in rows)
        assert all("root_cause" not in json.dumps(case) for case in rows)
        assert all("recipe" not in json.dumps(case) for case in rows)
    assert len({tuple(row["root_causes"] or ()) for row in matrix.evaluator}) >= 4


def test_evaluator_replays_sequential_effects_and_unknowns() -> None:
    matrix = build_matrix()
    labels = {row["case_id"]: row for row in matrix.evaluator}
    visible = {row["case_id"]: row for row in matrix.visible}
    assert all(len(row["stages"]) == 6 for row in matrix.evaluator)
    for case_id, row in labels.items():
        assert [stage["visible_state_sha256"] for stage in row["stages"]] == [
            stage["visible_state_sha256"] for stage in visible[case_id]["stages"]
        ]
        assert all(stage["compatible_world_count"] >= 1 for stage in row["stages"])
        assert (
            row["stages"][-1]["compatible_world_count"]
            <= row["stages"][0]["compatible_world_count"]
        )
    unknown = [row for row in labels.values() if row["role"] == "unknown"]
    assert len(unknown) == 2
    assert all(row["causal_answer_review"] == "unknown" for row in unknown)
    assert all(row["root_causes"] is None for row in unknown)
    counter = [row for row in labels.values() if row["role"] == "counterevidence"]
    assert len(counter) == 2
    assert all(row["counterevidence_stage_indices"] for row in counter)


def test_export_is_read_only_replayable_and_tamper_detected(tmp_path: Path) -> None:
    output = tmp_path / "matrix"
    manifest = export_matrix(output)
    assert manifest["classification"] == "synthetic_mechanics_only"
    assert manifest["training_admissible"] is False
    assert verify_export(output)["integrity_verified"] is True
    policy_file = output / "policy-visible" / "sequential-states.json"
    data = json.loads(policy_file.read_text(encoding="utf-8"))
    assert len(data["cases"]) >= 12
    assert all("root_causes" not in json.dumps(case) for case in data["cases"])
    with pytest.raises(FileExistsError):
        export_matrix(output)
    policy_file.write_text("{}", encoding="utf-8")
    with pytest.raises(ValueError, match="integrity"):
        verify_export(output)
