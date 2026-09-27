"""Evaluator-only synthetic rival scoring from exact postretrieval source readback.

This rubric is limited to two fixture rivals per domain. It never proves a
causal answer about Windows, and it never uses the script choice or source ID
to decide whether an observation was useful.
"""

from __future__ import annotations

import hashlib
from datetime import datetime
from pathlib import Path
from typing import Any, Literal

from systemsense.decision.frontier_ranker import FrontierRankRequestV1
from systemsense.domain.evidence import EvidenceRecord
from systemsense.domain.ids import JsonValue, stable_source_id
from systemsense.storage.sqlite_store import SQLiteStore

_RIVALS = {
    "network_browser": ("browser_profile_proxy_route", "external_origin_unreachable"),
    "application_performance": ("viewer_rendering_delay", "external_document_source_delay"),
}


def _source_coverage(
    record: EvidenceRecord, task: EvidenceRecord
) -> Literal["same_target_full_window", "different_target", "insufficient_window", "unknown"]:
    """Recompute coverage from persisted source and task, not the rank semantic."""

    locator = record.source.locator
    facts = {fact.name: fact.value for fact in task.facts}
    source_index = locator.get("source_index")
    if (
        record.source.type != "fixture.task_coverage"
        or record.collector.id != "fixture.task_coverage"
        or record.collector.version != 1
        or record.extraction.parser != "fixture.task_coverage"
        or record.extraction.parser_version != 1
        or record.source.source_id != stable_source_id(record.source.type, locator)
        or set(locator)
        != {
            "case_id",
            "domain",
            "source_index",
            "target_handle",
            "coverage_start_utc",
            "coverage_end_utc",
        }
        or locator.get("case_id") != str(task.case_id)
        or not isinstance(source_index, int)
        or isinstance(source_index, bool)
        or source_index <= 0
    ):
        return "unknown"
    try:
        source_start = datetime.fromisoformat(str(locator["coverage_start_utc"]))
        source_end = datetime.fromisoformat(str(locator["coverage_end_utc"]))
        task_start = datetime.fromisoformat(str(facts["synthetic_window_start_utc"]))
        task_end = datetime.fromisoformat(str(facts["synthetic_window_end_utc"]))
    except (KeyError, TypeError, ValueError):
        return "unknown"
    if (
        source_start.tzinfo is None
        or source_end.tzinfo is None
        or not source_start <= source_end <= record.observed_at <= record.captured_at
        or task_end != task.observed_at
        or task_start > task_end
    ):
        return "unknown"
    if locator["target_handle"] != facts.get("target_handle"):
        return "different_target"
    if source_start > task_start or source_end < task_end:
        return "insufficient_window"
    return "same_target_full_window"


def _compatible_rivals(domain: str, facts: dict[str, JsonValue]) -> tuple[str, ...] | None:
    """Frozen toy observation patterns; ambiguity or malformed facts stay unknown."""

    if domain == "network_browser":
        if facts == {
            "browser_request_timed_out": True,
            "browser_proxy_enabled": True,
            "configured_proxy_reachable": False,
            "direct_same_origin_reachable": True,
        }:
            return ("browser_profile_proxy_route",)
        if facts == {
            "browser_request_timed_out": True,
            "browser_proxy_enabled": False,
            "configured_proxy_reachable": True,
            "direct_same_origin_reachable": False,
        }:
            return ("external_origin_unreachable",)
    elif domain == "application_performance":
        if facts == {
            "viewer_render_p95_ms": 430,
            "external_fetch_p95_ms": 40,
            "independent_document_open_ms": 35,
        }:
            return ("viewer_rendering_delay",)
        if facts == {
            "viewer_render_p95_ms": 40,
            "external_fetch_p95_ms": 430,
            "independent_document_open_ms": 35,
        }:
            return ("external_document_source_delay",)
    return None


def review_cell(cell: dict[str, Any]) -> dict[str, Any]:
    """Score the actual chosen source using persisted bytes and a bound task row."""

    request = cell["request"]
    if not isinstance(request, FrontierRankRequestV1) or request.task_context is None:
        raise ValueError("source review requires exact task reference")
    context = request.task_context
    with SQLiteStore(Path(cell["database"])) as store:
        task_row = store.evidence(
            case_id=str(context.case_id), evidence_id=str(context.evidence_id)
        )
        selected_row = store.evidence(
            case_id=str(context.case_id), evidence_id=str(cell["chosen_evidence_id"])
        )
        if task_row is None or selected_row is None:
            raise ValueError("selected source or task observation is missing")
        if hashlib.sha256(task_row.record_json.encode()).hexdigest() != context.record_sha256:
            raise ValueError("task source commitment changed")
        task = EvidenceRecord.model_validate_json(task_row.record_json)
        selected = EvidenceRecord.model_validate_json(selected_row.record_json)
    task_facts = {fact.name: fact.value for fact in task.facts}
    if (
        task.source.source_id != context.source_id
        or task.collector.id != context.collector_id
        or task.collector.version != context.collector_version
        or task.collector.execution_id != context.execution_id
        or task_facts.get("target_handle") != context.target_handle
        or task_facts.get("synthetic_window_start_utc") != context.window_start.isoformat()
        or task_facts.get("synthetic_window_end_utc") != context.window_end.isoformat()
        or task_facts.get("observed") != context.observed
        or task.observed_at != context.observed_at
        or task.captured_at != context.captured_at
        or selected.source.source_id != cell["selected_readback"]["source_id"]
        or selected.case_id != context.case_id
        or str(selected.evidence_id) != str(cell["chosen_evidence_id"])
        or selected.observed_at.isoformat() != selected_row.observed_at
        or selected.captured_at.isoformat() != selected_row.captured_at
        or selected_row.time_basis != "fixture_observed"
        or selected_row.time_quality != "exact"
    ):
        raise ValueError("selected source or task readback binding changed")
    selected_facts = {fact.name: fact.value for fact in selected.facts}
    retrieved_facts = {item["name"]: item["value"] for item in cell["selected_readback"]["facts"]}
    if retrieved_facts != selected_facts:
        raise ValueError("selected retrieval fact content differs from exact source")
    domain = str(cell["domain"])
    if selected.source.locator.get("domain") != domain:
        raise ValueError("source domain differs from frozen task domain")
    before = _RIVALS[domain]
    coverage = _source_coverage(selected, task)
    after = (
        _compatible_rivals(domain, selected_facts)
        if coverage == "same_target_full_window"
        else before
        if coverage in ("different_target", "insufficient_window")
        else None
    )
    effect = (
        "reduces_toy_rivals"
        if after is not None and len(after) == 1
        else "does_not_reduce_toy_rivals"
        if after is not None and len(after) == len(before)
        else "unknown"
    )
    assessment = cell["assessment"]
    claims = 0 if assessment is None or assessment["disposition"] == "unresolved" else 1
    return {
        "selected_evidence_id": str(selected.evidence_id),
        "source_record_sha256": hashlib.sha256(selected_row.record_json.encode()).hexdigest(),
        "task_record_sha256": context.record_sha256,
        "source_task_coverage_independent": coverage,
        "toy_rivals_before": before,
        "toy_rivals_after": after,
        "observed_effect": effect,
        "selected_retrieval_facts_verified": True,
        "causal_claims_emitted": claims,
        "false_causal_claims": 0 if claims == 0 else None,
        "supported_causal_answer": False,
        "claim_limit": "synthetic_rival_compatibility_only_no_causal_proof",
    }
