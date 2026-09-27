"""A frozen retrieval output is scored after the evaluator labels are unsealed."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from benchmarks.score_sequential_retrieval import score_retrieval


def _write(path: Path, value: object) -> str:
    path.write_text(json.dumps(value, sort_keys=True), encoding="utf-8")
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _packet(ids: list[str]) -> dict[str, object]:
    return {
        "relation_ids": ids,
        "counterevidence_relation_ids": ids,
        "truncated": True,
        "omitted_relation_count": 2,
    }


def _inputs(tmp_path: Path) -> tuple[Path, Path, Path, dict[str, str]]:
    policy = tmp_path / "policy.json"
    labels = tmp_path / "labels.json"
    retrieval = tmp_path / "retrieval.json"
    cases: list[dict[str, Any]] = [
        {
            "case_id": case_id,
            "domain": "network_browser",
            "stages": [
                {"stage_index": 0, "visible_state_sha256": f"{case_id}-0"},
                {"stage_index": 1, "visible_state_sha256": f"{case_id}-1"},
            ],
        }
        for case_id in ("a", "b")
    ]
    policy_hash = _write(policy, {"cases": cases})
    label_hash = _write(
        labels,
        {
            "cases": [
                {
                    "case_id": "a",
                    "domain": "network_browser",
                    "root_causes": ["cause_a"],
                    "counterevidence_stage_indices": [],
                    "stages": [
                        {
                            "stage_index": 0,
                            "visible_state_sha256": "a-0",
                            "discriminated_by_latest_probe": None,
                        },
                        {
                            "stage_index": 1,
                            "visible_state_sha256": "a-1",
                            "discriminated_by_latest_probe": True,
                        },
                    ],
                },
                {
                    "case_id": "b",
                    "domain": "network_browser",
                    "root_causes": ["cause_b"],
                    "counterevidence_stage_indices": [1],
                    "stages": [
                        {
                            "stage_index": 0,
                            "visible_state_sha256": "b-0",
                            "discriminated_by_latest_probe": None,
                        },
                        {
                            "stage_index": 1,
                            "visible_state_sha256": "b-1",
                            "discriminated_by_latest_probe": False,
                        },
                    ],
                },
            ]
        },
    )
    records: list[dict[str, Any]] = []
    for case in cases:
        case_id = case["case_id"]
        for stage in case["stages"]:
            index = stage["stage_index"]
            all_ids = ["a"] if case_id == "a" and index else ["base"]
            reviewed_ids = ["reviewed"] if case_id == "a" or index else ["base_reviewed"]
            records.append(
                {
                    "case_id": case_id,
                    "domain": "network_browser",
                    "stage_index": index,
                    "visible_state_sha256": stage["visible_state_sha256"],
                    "all_relations": _packet(all_ids),
                    "reviewed_only": _packet(reviewed_ids),
                }
            )
    retrieval_hash = _write(retrieval, {"input_sha256": policy_hash, "records": records})
    return (
        policy,
        labels,
        retrieval,
        {
            "policy": policy_hash,
            "labels": label_hash,
            "retrieval": retrieval_hash,
        },
    )


def test_scores_responses_churn_and_final_collisions(tmp_path: Path) -> None:
    policy, labels, retrieval, expected = _inputs(tmp_path)
    result = score_retrieval(policy, labels, retrieval, expected_sha256=expected)
    assert result["stages"] == 4
    assert result["discriminating_followups"] == 1
    assert result["nondiscriminating_followups"] == 1
    assert result["arms"]["all_relations"]["changed_on_discriminating"] == 1
    assert result["arms"]["all_relations"]["changed_on_nondiscriminating"] == 0
    assert result["arms"]["all_relations"]["distinct_truth_pair_collisions"] == 0
    assert result["arms"]["reviewed_only"]["changed_on_discriminating"] == 0
    assert result["arms"]["reviewed_only"]["changed_on_nondiscriminating"] == 1
    assert result["arms"]["reviewed_only"]["distinct_truth_pair_collisions"] == 1
    assert result["arms"]["reviewed_only"]["counterevidence_packet_changes"] == 1
    assert result["diagnostic_performance_admissible"] is False


def test_rejects_tampered_or_incomplete_retrieval(tmp_path: Path) -> None:
    policy, labels, retrieval, expected = _inputs(tmp_path)
    with pytest.raises(ValueError, match="hash"):
        score_retrieval(policy, labels, retrieval, expected_sha256={**expected, "labels": "0" * 64})
    data = json.loads(retrieval.read_text(encoding="utf-8"))
    data["records"].pop()
    expected["retrieval"] = _write(retrieval, data)
    with pytest.raises(ValueError, match="stage"):
        score_retrieval(policy, labels, retrieval, expected_sha256=expected)
