"""Read-only stage timing for a persisted mixed-frontier local investigation.

This report uses durable wall-clock timestamps, not an inference profiler. It
never turns an admitted-only sample into an all-attempt p95 or infers that a
configured model actually ran from its name. Keep raw case facts in the DB.
"""

from __future__ import annotations

import argparse
import json
import math
import sqlite3
from contextlib import closing
from datetime import datetime
from pathlib import Path
from typing import Any, cast
from urllib.parse import quote


def _elapsed_ms(start: str | None, end: str | None) -> float | None:
    if start is None or end is None:
        return None
    earlier = datetime.fromisoformat(start)
    later = datetime.fromisoformat(end)
    elapsed = (later - earlier).total_seconds() * 1000
    return round(elapsed, 3) if elapsed >= 0 else None


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    offset = (len(ordered) - 1) * fraction
    low = math.floor(offset)
    high = math.ceil(offset)
    return round(ordered[low] + (ordered[high] - ordered[low]) * (offset - low), 3)


def _summary(values: list[float]) -> dict[str, float | int | None]:
    return {
        "count": len(values),
        "min_ms": min(values) if values else None,
        "p50_ms": _percentile(values, 0.5),
        "p95_ms": _percentile(values, 0.95),
        "max_ms": max(values) if values else None,
    }


def _stored_ids(value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) for item in cast(list[object], value)
    ):
        raise ValueError("persisted presentation contains invalid item IDs")
    return tuple(cast(list[str], value))


def _presentation_work(
    response: dict[str, Any], *, offered_item_ids: tuple[str, ...]
) -> dict[str, int | None]:
    """Account for presented work without treating missing old traces as zero work.

    A finalist can be presented again in a comparison. It is extra compute,
    not another distinct offered candidate or proof of diagnostic utility.
    """

    empty: dict[str, int | None] = {
        "original_candidates": len(offered_item_ids),
        "microbatches": None,
        "comparison_microbatches": None,
        "worker_calls": None,
        "expanded_worker_questions": None,
        "inference_item_presentations": None,
        "candidate_inference_presentations": None,
        "distinct_offered_candidates_covered": None,
        "distinct_offered_candidates_inferred": None,
        "repeated_candidate_presentations": None,
        "cache_hit_presentations": None,
    }
    trace = response.get("presentation_trace")
    if not isinstance(trace, dict):
        return empty
    batches = cast(dict[str, object], trace).get("microbatches")
    if not isinstance(batches, list):
        return empty
    batches = cast(list[object], batches)
    offered = set(offered_item_ids)
    inference_ids: list[str] = []
    presented_candidates: set[str] = set()
    question_count = 0
    worker_calls = 0
    cache_hits = 0
    for batch in batches:
        if not isinstance(batch, dict):
            raise ValueError("persisted presentation contains an invalid microbatch")
        batch = cast(dict[str, object], batch)
        inferred = _stored_ids(batch.get("inference_ids"))
        cached = _stored_ids(batch.get("cache_hit_ids"))
        inference_ids.extend(inferred)
        presented_candidates.update(
            item_id for item_id in (*inferred, *cached) if item_id in offered
        )
        cache_hits += len(cached)
        presentation = batch.get("worker_presentation")
        if presentation is not None:
            if not isinstance(presentation, dict):
                raise ValueError("persisted worker presentation is invalid")
            questions = cast(dict[str, object], presentation).get("questions")
            if not isinstance(questions, list):
                raise ValueError("persisted worker presentation is invalid")
            worker_calls += 1
            question_count += len(cast(list[object], questions))
    candidate_inferences = [item_id for item_id in inference_ids if item_id in offered]
    return {
        "original_candidates": len(offered_item_ids),
        "microbatches": len(batches),
        "comparison_microbatches": sum(
            cast(dict[str, object], batch).get("phase") == "compare" for batch in batches
        ),
        "worker_calls": worker_calls,
        "expanded_worker_questions": question_count,
        "inference_item_presentations": len(inference_ids),
        "candidate_inference_presentations": len(candidate_inferences),
        "distinct_offered_candidates_covered": len(presented_candidates),
        "distinct_offered_candidates_inferred": len(set(candidate_inferences)),
        "repeated_candidate_presentations": len(candidate_inferences)
        - len(set(candidate_inferences)),
        "cache_hit_presentations": cache_hits,
    }


def _distinct_inferred_candidates(
    response: dict[str, Any], offered_item_ids: tuple[str, ...]
) -> set[str] | None:
    """Return only actual inferred frontier IDs; old untraced work is unknown."""

    trace = response.get("presentation_trace")
    if not isinstance(trace, dict):
        return None
    batches = cast(dict[str, object], trace).get("microbatches")
    if not isinstance(batches, list):
        return None
    offered = set(offered_item_ids)
    inferred: set[str] = set()
    for batch in cast(list[object], batches):
        if not isinstance(batch, dict):
            raise ValueError("persisted presentation contains an invalid microbatch")
        inferred.update(
            item_id
            for item_id in _stored_ids(cast(dict[str, object], batch).get("inference_ids"))
            if item_id in offered
        )
    return inferred


def _annotate_new_evidence(
    rankings: list[dict[str, object]], evidence: list[tuple[str, str]]
) -> None:
    """Show later persisted inputs without labelling them counterevidence."""

    previous_capture: datetime | None = None
    for ranking in rankings:
        frozen = datetime.fromisoformat(str(ranking["request_frozen_at"]))
        ranking["new_evidence_ids_since_previous_ranking"] = (
            None
            if previous_capture is None
            else [
                evidence_id
                for evidence_id, persisted_at in evidence
                if previous_capture < datetime.fromisoformat(persisted_at) <= frozen
            ]
        )
        previous_capture = datetime.fromisoformat(str(ranking["captured_at"]))


def _event_opportunities(connection: sqlite3.Connection, case_id: str) -> list[dict[str, Any]]:
    """Expose every source event and its actual investigator custody, including misses.

    A persisted event alone is not a model opportunity: intake may still be
    pending. A trigger is the durable eligible queue entry, while reservations
    and outcomes identify work actually attempted. Do not infer a model call
    from a reservation or a skipped decision from an unqueued source event.
    """

    turns_by_event: dict[str, list[dict[str, Any]]] = {}
    for row in connection.execute(
        "SELECT t.event_id,t.turn_id,t.reserved_at,o.completed_at,o.record_json "
        "FROM search_frontier_investigator_turns AS t "
        "LEFT JOIN search_frontier_investigator_turn_outcomes AS o "
        "ON o.turn_id=t.turn_id "
        "WHERE t.case_id=? ORDER BY t.reserved_at,t.turn_id",
        (case_id,),
    ):
        outcome = None if row["record_json"] is None else json.loads(str(row["record_json"]))
        turns_by_event.setdefault(str(row["event_id"]), []).append(
            {
                "turn_id": str(row["turn_id"]),
                "reserved_at": str(row["reserved_at"]),
                "completed_at": (None if row["completed_at"] is None else str(row["completed_at"])),
                "outcome": None if outcome is None else outcome.get("outcome"),
                "reason_code": None if outcome is None else outcome.get("reason_code"),
                "selected_item_ids": (
                    None if outcome is None else outcome.get("frontier_item_ids")
                ),
                "reserved_to_completed_ms": _elapsed_ms(
                    str(row["reserved_at"]),
                    None if row["completed_at"] is None else str(row["completed_at"]),
                ),
            }
        )
    opportunities: list[dict[str, Any]] = []
    for row in connection.execute(
        "SELECT e.event_id,e.kind,e.source_evidence_id,e.persisted_at,"
        "g.queued_at,a.acknowledged_at,s.started_at,"
        "c.closed_at,c.record_json AS closure_json,"
        "x.terminal_at,x.record_json AS terminal_json "
        "FROM search_frontier_events AS e "
        "LEFT JOIN search_frontier_investigator_triggers AS g ON g.event_id=e.event_id "
        "LEFT JOIN search_frontier_investigator_event_acks AS a ON a.event_id=e.event_id "
        "LEFT JOIN search_frontier_investigator_sessions AS s ON s.event_id=e.event_id "
        "LEFT JOIN search_frontier_investigator_turn_closures AS c ON c.event_id=e.event_id "
        "LEFT JOIN search_frontier_investigator_terminals AS x ON x.event_id=e.event_id "
        "WHERE e.case_id=? ORDER BY e.persisted_at,e.event_id",
        (case_id,),
    ):
        event_id = str(row["event_id"])
        queued_at = None if row["queued_at"] is None else str(row["queued_at"])
        closure = None if row["closure_json"] is None else json.loads(str(row["closure_json"]))
        terminal = None if row["terminal_json"] is None else json.loads(str(row["terminal_json"]))
        if queued_at is None:
            disposition = "not_intaken"
        elif closure is not None:
            disposition = "closed"
        elif terminal is not None:
            disposition = "terminal"
        elif row["started_at"] is not None:
            disposition = "active"
        else:
            disposition = "queued"
        turns = turns_by_event.get(event_id, [])
        for turn in turns:
            turn["queued_to_reserved_ms"] = _elapsed_ms(queued_at, turn["reserved_at"])
        opportunities.append(
            {
                "event_id": event_id,
                "kind": row["kind"],
                "source_evidence_id": row["source_evidence_id"],
                "persisted_at": str(row["persisted_at"]),
                "queued_at": queued_at,
                "intake_acknowledged_at": row["acknowledged_at"],
                "session_started_at": row["started_at"],
                "disposition": disposition,
                "persisted_to_queued_ms": _elapsed_ms(str(row["persisted_at"]), queued_at),
                "turns": turns,
                "closure_at": row["closed_at"],
                "closure_outcome": None if closure is None else closure.get("outcome"),
                "closure_reason_code": None if closure is None else closure.get("reason_code"),
                "terminal_at": row["terminal_at"],
                "terminal_outcome": None if terminal is None else terminal.get("outcome"),
                "terminal_reason_code": None if terminal is None else terminal.get("reason_code"),
            }
        )
    return opportunities


def trace_case(database: Path, case_id: str) -> dict[str, Any]:
    """Summarize exact durable stages without opening the store for writes."""

    if not database.is_file() or not case_id.startswith("case_"):
        raise ValueError("an existing case database and case ID are required")
    uri = "file:" + quote(database.resolve().as_posix(), safe="/:") + "?mode=ro"
    with closing(sqlite3.connect(uri, uri=True)) as connection:
        connection.row_factory = sqlite3.Row
        opportunities = _event_opportunities(connection, case_id)
        turn_rows = connection.execute(
            "SELECT t.turn_id,t.event_id,t.reserved_at,o.completed_at,o.record_json,"
            "e.persisted_at AS event_persisted_at,e.source_evidence_id,g.queued_at "
            "FROM search_frontier_investigator_turns AS t "
            "LEFT JOIN search_frontier_investigator_turn_outcomes AS o "
            "ON o.turn_id=t.turn_id "
            "LEFT JOIN search_frontier_events AS e ON e.event_id=t.event_id "
            "LEFT JOIN search_frontier_investigator_triggers AS g ON g.event_id=t.event_id "
            "WHERE t.case_id=? ORDER BY t.reserved_at,t.turn_id",
            (case_id,),
        ).fetchall()
        turns: list[dict[str, object]] = []
        turn_by_snapshot: dict[str, dict[str, object]] = {}
        previous_completion: str | None = None
        for row in turn_rows:
            outcome = None if row["record_json"] is None else json.loads(str(row["record_json"]))
            reserved_at = str(row["reserved_at"])
            completed_at = None if row["completed_at"] is None else str(row["completed_at"])
            event_persisted_at = (
                None if row["event_persisted_at"] is None else str(row["event_persisted_at"])
            )
            queued_at = None if row["queued_at"] is None else str(row["queued_at"])
            turn: dict[str, object] = {
                "turn_id": str(row["turn_id"]),
                "event_id": str(row["event_id"]),
                "source_evidence_id": row["source_evidence_id"],
                "event_persisted_at": event_persisted_at,
                "event_queued_at": queued_at,
                "reserved_at": reserved_at,
                "completed_at": completed_at,
                "outcome": None if outcome is None else outcome.get("outcome"),
                "candidate_snapshot_id": (
                    None if outcome is None else outcome.get("candidate_snapshot_id")
                ),
                "event_persisted_to_queued_ms": _elapsed_ms(event_persisted_at, queued_at),
                "event_queued_to_reserved_ms": _elapsed_ms(queued_at, reserved_at),
                "previous_turn_completed_to_reserved_ms": _elapsed_ms(
                    previous_completion, reserved_at
                ),
            }
            turns.append(turn)
            snapshot_id = turn["candidate_snapshot_id"]
            if isinstance(snapshot_id, str):
                turn_by_snapshot[snapshot_id] = turn
            previous_completion = completed_at
        snapshots = connection.execute(
            "SELECT snapshot_id,request_frozen_at,captured_at,request_json,response_json "
            "FROM candidate_decision_snapshots WHERE case_id=? "
            "ORDER BY request_frozen_at,snapshot_id",
            (case_id,),
        ).fetchall()
        rankings: list[dict[str, object]] = []
        snapshots_by_id: dict[str, sqlite3.Row] = {}
        inferred_candidate_ids: set[str] = set()
        all_candidate_presentations_known = True
        for snapshot in snapshots:
            snapshots_by_id[str(snapshot["snapshot_id"])] = snapshot
            request = json.loads(str(snapshot["request_json"]))
            response = json.loads(str(snapshot["response_json"]))
            offered_ids = tuple(str(item["item_id"]) for item in request["items"])
            if response["ranking_source"] == "laya" and response["degraded_reason"] is None:
                inferred = _distinct_inferred_candidates(response, offered_ids)
                if inferred is None:
                    all_candidate_presentations_known = False
                else:
                    inferred_candidate_ids.update(inferred)
            rankings.append(
                {
                    "snapshot_id": str(snapshot["snapshot_id"]),
                    "provider_id": request["provider"]["provider_id"],
                    "model_weight_sha256": request["model_weight_sha256"],
                    "ranking_source": response["ranking_source"],
                    "degraded_reason": response["degraded_reason"],
                    "attention_notes": response.get("attention_notes", []),
                    "considered_item_ids": response.get("considered_item_ids", []),
                    "candidate_kinds": [item["reference"]["kind"] for item in request["items"]],
                    "packet_count": len(request["evidence_packets"]),
                    "original_candidates": len(offered_ids),
                    "small_menu": len(offered_ids) <= 4,
                    "request_frozen_at": str(snapshot["request_frozen_at"]),
                    "captured_at": str(snapshot["captured_at"]),
                    "work": _presentation_work(response, offered_item_ids=offered_ids),
                    "frozen_to_snapshot_ms": _elapsed_ms(
                        str(snapshot["request_frozen_at"]), str(snapshot["captured_at"])
                    ),
                }
            )
        admitted = connection.execute(
            "SELECT a.admission_id,a.snapshot_id,a.candidate_id,a.admitted_at,"
            "p.trigger_execution_id,c.claimed_at,l.execution_id,x.started_at,x.finished_at,"
            "x.status AS execution_status "
            "FROM candidate_dispatch_admissions AS a "
            "LEFT JOIN candidate_followup_parents AS p ON p.admission_id=a.admission_id "
            "LEFT JOIN candidate_dispatch_claims AS c ON c.admission_id=a.admission_id "
            "LEFT JOIN candidate_decision_execution_links AS l "
            "ON l.snapshot_id=a.snapshot_id AND l.candidate_id=a.candidate_id "
            "LEFT JOIN probe_executions AS x ON x.execution_id=l.execution_id "
            "WHERE a.case_id=? ORDER BY a.admitted_at,a.admission_id",
            (case_id,),
        ).fetchall()
        measurements: list[dict[str, object]] = []
        admitted_latencies: list[float] = []
        for row in admitted:
            snapshot = snapshots_by_id.get(str(row["snapshot_id"]))
            selected_turn = turn_by_snapshot.get(str(row["snapshot_id"]))
            parent_id = row["trigger_execution_id"]
            persisted = None
            if parent_id is not None:
                source = connection.execute(
                    "SELECT MIN(t.persisted_at) FROM coordinator_events AS t "
                    "JOIN evidence AS e ON e.evidence_id=t.source_record_id "
                    "WHERE e.case_id=? AND e.execution_id=? AND t.kind='evidence'",
                    (case_id, str(parent_id)),
                ).fetchone()
                persisted = None if source is None or source[0] is None else str(source[0])
            admitted_at = str(row["admitted_at"])
            frozen_at = None if snapshot is None else str(snapshot["request_frozen_at"])
            captured_at = None if snapshot is None else str(snapshot["captured_at"])
            turn_reserved_at = None if selected_turn is None else str(selected_turn["reserved_at"])
            latency = _elapsed_ms(persisted, admitted_at)
            if latency is not None:
                admitted_latencies.append(latency)
            measurements.append(
                {
                    "admission_id": str(row["admission_id"]),
                    "snapshot_id": str(row["snapshot_id"]),
                    "candidate_id": str(row["candidate_id"]),
                    "source_persisted_at": persisted,
                    "turn_id": None if selected_turn is None else selected_turn["turn_id"],
                    "turn_event_id": None if selected_turn is None else selected_turn["event_id"],
                    "turn_reserved_at": turn_reserved_at,
                    "request_frozen_at": frozen_at,
                    "snapshot_captured_at": captured_at,
                    "admitted_at": admitted_at,
                    "claimed_at": row["claimed_at"],
                    "execution_id": row["execution_id"],
                    "execution_status": row["execution_status"],
                    "persisted_to_admitted_ms": latency,
                    "parent_persisted_to_turn_reserved_ms": _elapsed_ms(
                        persisted, turn_reserved_at
                    ),
                    "turn_reserved_to_request_frozen_ms": _elapsed_ms(turn_reserved_at, frozen_at),
                    "request_frozen_to_snapshot_ms": _elapsed_ms(frozen_at, captured_at),
                    "snapshot_to_admitted_ms": _elapsed_ms(captured_at, admitted_at),
                    "admitted_to_probe_start_ms": _elapsed_ms(
                        admitted_at,
                        None if row["started_at"] is None else str(row["started_at"]),
                    ),
                    "admitted_to_claimed_ms": _elapsed_ms(
                        admitted_at,
                        None if row["claimed_at"] is None else str(row["claimed_at"]),
                    ),
                    "claimed_to_probe_start_ms": _elapsed_ms(
                        None if row["claimed_at"] is None else str(row["claimed_at"]),
                        None if row["started_at"] is None else str(row["started_at"]),
                    ),
                    "probe_elapsed_ms": _elapsed_ms(
                        None if row["started_at"] is None else str(row["started_at"]),
                        None if row["finished_at"] is None else str(row["finished_at"]),
                    ),
                }
            )
        deep: list[dict[str, object]] = []
        for row in connection.execute(
            "SELECT request_sha256,status,reason,created_at,updated_at,result_json "
            "FROM deep_mailbox WHERE case_id=? ORDER BY created_at,request_sha256",
            (case_id,),
        ):
            result = None if row["result_json"] is None else json.loads(str(row["result_json"]))
            response = None if result is None else result.get("response")
            deep.append(
                {
                    "request_sha256": str(row["request_sha256"]),
                    "status": str(row["status"]),
                    "reason": str(row["reason"]),
                    "created_at": str(row["created_at"]),
                    "updated_at": str(row["updated_at"]),
                    "created_to_terminal_ms": _elapsed_ms(
                        str(row["created_at"]), str(row["updated_at"])
                    ),
                    "worker_started_at": None if result is None else result.get("started_at"),
                    "worker_finished_at": None if result is None else result.get("finished_at"),
                    "worker_elapsed_ms": None if result is None else result.get("elapsed_ms"),
                    "provider_identity": (
                        None if result is None else result.get("provider_identity")
                    ),
                    "response_provider": None if response is None else response.get("provider"),
                    "response_degraded": None if response is None else response.get("degraded"),
                    "failure_kind": None if result is None else result.get("failure_kind"),
                }
            )
        for ranking in rankings:
            ranking["deep_worker_overlap_request_sha256"] = [
                item["request_sha256"]
                for item in deep
                if isinstance(item["worker_started_at"], str)
                and isinstance(item["worker_finished_at"], str)
                and datetime.fromisoformat(item["worker_started_at"])
                < datetime.fromisoformat(str(ranking["captured_at"]))
                and datetime.fromisoformat(item["worker_finished_at"])
                > datetime.fromisoformat(str(ranking["request_frozen_at"]))
            ]
        evidence_events = connection.execute(
            "SELECT COUNT(*) FROM coordinator_events WHERE case_id=? AND kind='evidence'",
            (case_id,),
        ).fetchone()
        evidence_timeline = [
            (str(row["source_record_id"]), str(row["persisted_at"]))
            for row in connection.execute(
                "SELECT source_record_id,persisted_at FROM coordinator_events "
                "WHERE case_id=? AND kind='evidence' AND source_record_id IS NOT NULL "
                "ORDER BY persisted_at,sequence",
                (case_id,),
            )
        ]
        _annotate_new_evidence(rankings, evidence_timeline)
        provider_events = [
            {
                "persisted_at": str(row["persisted_at"]),
                **json.loads(str(row["event_json"])),
            }
            for row in connection.execute(
                "SELECT persisted_at,event_json FROM coordinator_events "
                "WHERE case_id=? AND kind='provider' ORDER BY sequence",
                (case_id,),
            )
        ]
    small_menu = [item for item in rankings if item["small_menu"]]
    small_laya_menu = [
        item
        for item in small_menu
        if item["ranking_source"] == "laya" and item["degraded_reason"] is None
    ]
    laya_rankings = [
        item
        for item in rankings
        if item["ranking_source"] == "laya" and item["degraded_reason"] is None
    ]
    active_rank_ms = sum(
        cast(float, item["frozen_to_snapshot_ms"])
        for item in laya_rankings
        if item["frozen_to_snapshot_ms"] is not None
    )
    rank_span_ms = (
        _elapsed_ms(
            str(laya_rankings[0]["request_frozen_at"]), str(laya_rankings[-1]["captured_at"])
        )
        if laya_rankings
        else None
    )
    return {
        "schema_version": 1,
        "case_id": case_id,
        "evidence_events": 0 if evidence_events is None else int(evidence_events[0]),
        "fast_turn_opportunities": opportunities,
        "fast_turn_opportunity_summary": {
            "source_events": len(opportunities),
            "eligible_queued_triggers": sum(
                item["queued_at"] is not None for item in opportunities
            ),
            "not_intaken": sum(item["disposition"] == "not_intaken" for item in opportunities),
            "queued_unreserved": sum(item["disposition"] == "queued" for item in opportunities),
            "reserved_turns": sum(len(item["turns"]) for item in opportunities),
            "completed_turns": sum(
                turn["outcome"] is not None for item in opportunities for turn in item["turns"]
            ),
            "unfinished_turns": sum(
                turn["outcome"] is None for item in opportunities for turn in item["turns"]
            ),
        },
        "turns": turns,
        "rankings": rankings,
        "small_menu_responsiveness": {
            "rankings": len(small_menu),
            "laya_rankings": len(small_laya_menu),
            "procedural_or_degraded_rankings": len(small_menu) - len(small_laya_menu),
            "frozen_to_snapshot_ms": _summary(
                [
                    cast(float, item["frozen_to_snapshot_ms"])
                    for item in small_laya_menu
                    if item["frozen_to_snapshot_ms"] is not None
                ]
            ),
        },
        "distinct_candidate_throughput": {
            "laya_rankings": len(laya_rankings),
            "distinct_inferred": (
                len(inferred_candidate_ids)
                if laya_rankings and all_candidate_presentations_known
                else None
            ),
            "active_ranking_ms": round(active_rank_ms, 3),
            "case_ranking_span_ms": rank_span_ms,
            "per_active_ranking_second": (
                round(1000 * len(inferred_candidate_ids) / active_rank_ms, 3)
                if laya_rankings and all_candidate_presentations_known and active_rank_ms > 0
                else None
            ),
            "per_case_ranking_span_second": (
                round(1000 * len(inferred_candidate_ids) / rank_span_ms, 3)
                if laya_rankings
                and all_candidate_presentations_known
                and rank_span_ms is not None
                and rank_span_ms > 0
                else None
            ),
            "diagnostic_utility_checked": False,
        },
        "provider_events": provider_events,
        "measurements": measurements,
        "admitted_only_persisted_to_admitted": _summary(admitted_latencies),
        "all_attempt_p95_ms": None,
        "deep": deep,
        "limitations": [
            "Durable wall-clock stages omit model queue/inference phase boundaries.",
            "Presentation counts describe model work, not useful candidate judgments. "
            "Repeated finalist comparisons are extra compute, not distinct candidates.",
            "Missing historical presentation traces have unknown, not zero, worker work.",
            "Durable triggers and turn outcomes expose missed opportunities, but do not "
            "prove each source event had a useful eligible model menu or identify every "
            "unreserved skip reason. Admitted-only p95 is not the target p95.",
            "A configured model ID or laya ranking_source alone does not prove "
            "exact worker/model execution.",
            "New-evidence IDs establish timing and custody, not that the values contradict a "
            "hypothesis or that the later selection was useful.",
            "This trace contains no independent diagnostic oracle or repair outcome.",
            "Active-ranking throughput excludes waits; case-ranking-span throughput includes "
            "between-rank waits but not cold startup or the complete case.",
        ],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path)
    parser.add_argument("case_id")
    args = parser.parse_args()
    print(json.dumps(trace_case(args.database, args.case_id), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
