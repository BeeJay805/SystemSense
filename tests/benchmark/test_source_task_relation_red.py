"""The source relation is earned from exact readback, never a title or ID cue."""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any, cast

from benchmarks.source_task_relation_red import run_balanced_relation_probe
from systemsense.decision.frontier_ranker import (
    FrontierRankRequestV1,
    _candidate_description,  # pyright: ignore[reportPrivateUsage]
)


def test_balanced_trusted_source_relation_in_real_frontier_menu(tmp_path: Path) -> None:
    cells = run_balanced_relation_probe(tmp_path / "source-relation")
    assert len(cells) == 8
    by_domain: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for cell in cells:
        by_domain[str(cell["domain"])].append(cell)
    assert set(by_domain) == {"network_browser", "application_performance"}
    for family in by_domain.values():
        assert len(family) == 4
        assert len({cell["checkpoint_sha256"] for cell in family}) == 1
        assert {cell["matched_evidence_id"] for cell in family} == {
            f"ev_{index:032x}" for index in (49, 50)
        }
        assert {cell["chosen_evidence_id"] for cell in family} == {
            f"ev_{index:032x}" for index in (49, 50)
        }
        assert {cell["menu"].index(cell["matched_evidence_id"]) for cell in family} == {0, 1}
    for cell in cells:
        request = cell["request"]
        assert isinstance(request, FrontierRankRequestV1)
        assert request.schema_version == 2
        assert request.task_context is not None
        assert cell["menu"] == [f"ev_{index:032x}" for index in range(49, 53)]
        assert cell["matched_evidence_id"] in cell["menu"]
        assert cell["chosen_evidence_id"] in cell["menu"]
        assert cell["alternative_evidence_id"] in cell["menu"]
        selected = cell["selected_readback"]
        alternative = cell["alternative_readback"]
        assert isinstance(selected, dict) and isinstance(alternative, dict)
        assert selected["evidence_id"] == cell["chosen_evidence_id"]
        assert alternative["evidence_id"] == cell["alternative_evidence_id"]
        assert selected["facts"] == alternative["facts"]
        assert selected["summary"] == alternative["summary"]
        assert selected["collector_id"] == alternative["collector_id"]
        assert selected["observed_at"] == alternative["observed_at"]
        assert selected["captured_at"] == alternative["captured_at"]
        assert selected["limitations"] == alternative["limitations"]
        locators = cast(dict[str, dict[str, object]], cell["source_locators"])
        expected_keys = {
            "case_id",
            "domain",
            "source_index",
            "target_handle",
            "coverage_start_utc",
            "coverage_end_utc",
        }
        assert all(set(locator) == expected_keys for locator in locators.values())
        task = request.task_context.model_visible()
        statuses: dict[str, str] = {}
        for item, semantic in zip(request.items, request.item_semantics, strict=True):
            if item.reference.kind != "retrieve_evidence":
                continue
            evidence_id = str(item.reference.evidence_id)
            if evidence_id not in locators:
                continue
            relation_value = semantic.model_dump(mode="json").get("source_task_relation")
            assert isinstance(relation_value, dict), "trusted source has no source-bound relation"
            relation = cast(dict[str, object], relation_value)
            assert relation.get("status") in {
                "same_target_full_window",
                "different_target",
                "insufficient_window",
            }
            assert relation.get("basis")
            statuses[evidence_id] = str(relation["status"])
            description = cast(
                dict[str, object], json.loads(_candidate_description(item, semantic))
            )
            model_relation = description.get("source_task_relation")
            assert isinstance(model_relation, dict)
            model_relation = cast(dict[str, object], model_relation)
            assert model_relation.get("status") == relation["status"]
        assert statuses[cell["matched_evidence_id"]] == "same_target_full_window"
        other = next(
            evidence_id for evidence_id in locators if evidence_id != cell["matched_evidence_id"]
        )
        expected_other = (
            "insufficient_window"
            if locators[other]["target_handle"] == task["target_handle"]
            else "different_target"
        )
        assert statuses[other] == expected_other
        assert task["target_handle"] == locators[cell["matched_evidence_id"]]["target_handle"]
        assert task["target_handle"] != locators[other]["target_handle"] or str(
            locators[other]["coverage_start_utc"]
        ) > str(task["window_start"])
        # Facts and evaluator metadata are not in the prechoice model envelope.
        request_json = json.dumps(request.model_dump(mode="json"))
        assert "private_source_result_unopened" not in request_json
        assert "matched_evidence_id" not in request_json
        assert "chosen_evidence_id" not in request_json
