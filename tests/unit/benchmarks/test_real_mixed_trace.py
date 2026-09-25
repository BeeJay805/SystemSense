"""The durable mixed trace reports work without inventing missing phases."""

import json
import sqlite3
from pathlib import Path

from benchmarks import real_mixed_trace


def test_presentation_work_counts_final_comparisons_without_double_counting_candidates() -> None:
    response = {
        "presentation_trace": {
            "microbatches": [
                {
                    "phase": "evidence",
                    "candidate_ids": ["fragment-a"],
                    "inference_ids": ["fragment-a"],
                    "cache_hit_ids": [],
                    "worker_presentation": {"questions": [{"question_id": "q-e"}]},
                },
                {
                    "phase": "probe",
                    "candidate_ids": ["a", "b"],
                    "inference_ids": ["a", "b"],
                    "cache_hit_ids": [],
                    "worker_presentation": {
                        "questions": [{"question_id": "q-a"}, {"question_id": "q-b"}]
                    },
                },
                {
                    "phase": "probe",
                    "candidate_ids": ["c", "d"],
                    "inference_ids": ["c", "d"],
                    "cache_hit_ids": [],
                    "worker_presentation": {
                        "questions": [{"question_id": "q-c"}, {"question_id": "q-d"}]
                    },
                },
                {
                    "phase": "compare",
                    "candidate_ids": ["b", "d"],
                    "inference_ids": ["b", "d"],
                    "cache_hit_ids": [],
                    "worker_presentation": {
                        "questions": [{"question_id": "q-b2"}, {"question_id": "q-d2"}]
                    },
                },
            ]
        }
    }

    work = real_mixed_trace._presentation_work(  # pyright: ignore[reportPrivateUsage]
        response, offered_item_ids=("a", "b", "c", "d")
    )

    assert work == {
        "original_candidates": 4,
        "microbatches": 4,
        "comparison_microbatches": 1,
        "worker_calls": 4,
        "expanded_worker_questions": 7,
        "inference_item_presentations": 7,
        "candidate_inference_presentations": 6,
        "distinct_offered_candidates_covered": 4,
        "distinct_offered_candidates_inferred": 4,
        "repeated_candidate_presentations": 2,
        "cache_hit_presentations": 0,
    }


def test_missing_presentation_trace_is_unknown_not_zero_model_work() -> None:
    work = real_mixed_trace._presentation_work(  # pyright: ignore[reportPrivateUsage]
        {}, offered_item_ids=("a", "b")
    )

    assert work["original_candidates"] == 2
    assert work["worker_calls"] is None
    assert work["microbatches"] is None
    assert work["expanded_worker_questions"] is None


def test_cache_hits_are_not_counted_as_new_model_judgments() -> None:
    work = real_mixed_trace._presentation_work(  # pyright: ignore[reportPrivateUsage]
        {
            "presentation_trace": {
                "microbatches": [
                    {
                        "phase": "probe",
                        "candidate_ids": ["a", "b"],
                        "inference_ids": ["b"],
                        "cache_hit_ids": ["a"],
                        "worker_presentation": {"questions": [{"question_id": "q-b"}]},
                    }
                ]
            }
        },
        offered_item_ids=("a", "b"),
    )

    assert work["cache_hit_presentations"] == 1
    assert work["inference_item_presentations"] == 1
    assert work["distinct_offered_candidates_covered"] == 2
    assert work["distinct_offered_candidates_inferred"] == 1
    assert work["repeated_candidate_presentations"] == 0


def test_distinct_throughput_excludes_repeated_finalists_and_nonoffered_ids() -> None:
    inferred = real_mixed_trace._distinct_inferred_candidates(  # pyright: ignore[reportPrivateUsage]
        {
            "presentation_trace": {
                "microbatches": [
                    {"inference_ids": ["a", "b", "evidence-packet"]},
                    {"inference_ids": ["b", "c"]},
                ]
            }
        },
        ("a", "b", "c"),
    )

    assert inferred == {"a", "b", "c"}


def test_later_evidence_custody_requires_persistence_before_next_freeze() -> None:
    rankings: list[dict[str, object]] = [
        {
            "request_frozen_at": "2026-01-01T00:00:00+00:00",
            "captured_at": "2026-01-01T00:00:01+00:00",
        },
        {
            "request_frozen_at": "2026-01-01T00:00:03+00:00",
            "captured_at": "2026-01-01T00:00:04+00:00",
        },
    ]
    evidence = [
        ("old", "2026-01-01T00:00:00.500000+00:00"),
        ("counter", "2026-01-01T00:00:02+00:00"),
        ("late", "2026-01-01T00:00:03.500000+00:00"),
    ]

    real_mixed_trace._annotate_new_evidence(  # pyright: ignore[reportPrivateUsage]
        rankings, evidence
    )

    assert rankings[0]["new_evidence_ids_since_previous_ranking"] is None
    assert rankings[1]["new_evidence_ids_since_previous_ranking"] == ["counter"]


def test_opportunity_report_keeps_queued_failed_timed_out_and_unintaken_events_distinct() -> None:
    with sqlite3.connect(":memory:") as connection:
        connection.row_factory = sqlite3.Row
        connection.executescript(
            "CREATE TABLE search_frontier_events ("
            "event_id TEXT,case_id TEXT,kind TEXT,source_evidence_id TEXT,persisted_at TEXT);"
            "CREATE TABLE search_frontier_investigator_triggers ("
            "event_id TEXT,queued_at TEXT);"
            "CREATE TABLE search_frontier_investigator_event_acks ("
            "event_id TEXT,acknowledged_at TEXT);"
            "CREATE TABLE search_frontier_investigator_sessions (event_id TEXT,started_at TEXT);"
            "CREATE TABLE search_frontier_investigator_turns ("
            "turn_id TEXT,event_id TEXT,case_id TEXT,reserved_at TEXT);"
            "CREATE TABLE search_frontier_investigator_turn_outcomes ("
            "turn_id TEXT,completed_at TEXT,record_json TEXT);"
            "CREATE TABLE search_frontier_investigator_turn_closures ("
            "event_id TEXT,closed_at TEXT,record_json TEXT);"
            "CREATE TABLE search_frontier_investigator_terminals ("
            "event_id TEXT,terminal_at TEXT,record_json TEXT);"
        )
        instant = "2026-01-01T00:00:00+00:00"
        for event_id in ("unintaken", "deferred", "failed", "timedout", "focused"):
            connection.execute(
                "INSERT INTO search_frontier_events VALUES (?,?,?,?,?)",
                (event_id, "case_test", "observation_added", event_id + "_evidence", instant),
            )
        for event_id in ("deferred", "failed", "timedout", "focused"):
            connection.execute(
                "INSERT INTO search_frontier_investigator_triggers VALUES (?,?)",
                (event_id, "2026-01-01T00:00:01+00:00"),
            )
            connection.execute(
                "INSERT INTO search_frontier_investigator_event_acks VALUES (?,?)",
                (event_id, "2026-01-01T00:00:01+00:00"),
            )
        for event_id, outcome, reason, selected in (
            ("failed", "gap", "policy_unavailable", []),
            ("timedout", "gap", "deadline_expired", []),
            ("focused", "focused_delivery", "focused_context_delivered", ["item_a"]),
        ):
            connection.execute(
                "INSERT INTO search_frontier_investigator_sessions VALUES (?,?)",
                (event_id, "2026-01-01T00:00:02+00:00"),
            )
            connection.execute(
                "INSERT INTO search_frontier_investigator_turns VALUES (?,?,?,?)",
                (event_id + "_turn", event_id, "case_test", "2026-01-01T00:00:03+00:00"),
            )
            connection.execute(
                "INSERT INTO search_frontier_investigator_turn_outcomes VALUES (?,?,?)",
                (
                    event_id + "_turn",
                    "2026-01-01T00:00:04+00:00",
                    json.dumps(
                        {"outcome": outcome, "reason_code": reason, "frontier_item_ids": selected}
                    ),
                ),
            )
        connection.execute(
            "INSERT INTO search_frontier_investigator_turn_closures VALUES (?,?,?)",
            (
                "timedout",
                "2026-01-01T00:00:05+00:00",
                json.dumps({"outcome": "gap", "reason_code": "deadline_expired"}),
            ),
        )

        opportunities = real_mixed_trace._event_opportunities(  # pyright: ignore[reportPrivateUsage]
            connection, "case_test"
        )

    by_id = {event["event_id"]: event for event in opportunities}
    assert [event["event_id"] for event in opportunities] == [
        "deferred",
        "failed",
        "focused",
        "timedout",
        "unintaken",
    ]
    assert by_id["unintaken"]["disposition"] == "not_intaken"
    assert by_id["deferred"]["disposition"] == "queued"
    assert by_id["deferred"]["turns"] == []
    assert by_id["failed"]["turns"][0]["reason_code"] == "policy_unavailable"
    assert by_id["timedout"]["disposition"] == "closed"
    assert by_id["timedout"]["closure_reason_code"] == "deadline_expired"
    assert by_id["focused"]["turns"][0]["selected_item_ids"] == ["item_a"]
    assert by_id["focused"]["turns"][0]["queued_to_reserved_ms"] == 2000.0


def test_read_only_case_report_includes_persisted_worker_work(tmp_path: Path) -> None:
    database = tmp_path / "trace.db"
    with sqlite3.connect(database) as connection:
        connection.executescript(
            "CREATE TABLE candidate_decision_snapshots ("
            "case_id TEXT,snapshot_id TEXT,request_frozen_at TEXT,captured_at TEXT,"
            "request_json TEXT,response_json TEXT);"
            "CREATE TABLE candidate_dispatch_admissions ("
            "case_id TEXT,admission_id TEXT,snapshot_id TEXT,candidate_id TEXT,admitted_at TEXT);"
            "CREATE TABLE candidate_followup_parents (admission_id TEXT,trigger_execution_id TEXT);"
            "CREATE TABLE candidate_dispatch_claims (admission_id TEXT,claimed_at TEXT);"
            "CREATE TABLE candidate_decision_execution_links ("
            "snapshot_id TEXT,candidate_id TEXT,execution_id TEXT);"
            "CREATE TABLE probe_executions ("
            "execution_id TEXT,started_at TEXT,finished_at TEXT,status TEXT);"
            "CREATE TABLE coordinator_events ("
            "case_id TEXT,kind TEXT,sequence INTEGER,persisted_at TEXT,event_json TEXT,"
            "source_record_id TEXT);"
            "CREATE TABLE evidence (evidence_id TEXT,case_id TEXT,execution_id TEXT);"
            "CREATE TABLE deep_mailbox ("
            "case_id TEXT,request_sha256 TEXT,status TEXT,reason TEXT,created_at TEXT,"
            "updated_at TEXT,result_json TEXT);"
            "CREATE TABLE search_frontier_investigator_turns ("
            "turn_id TEXT,event_id TEXT,case_id TEXT,reserved_at TEXT);"
            "CREATE TABLE search_frontier_investigator_turn_outcomes ("
            "turn_id TEXT,case_id TEXT,completed_at TEXT,record_json TEXT);"
            "CREATE TABLE search_frontier_events ("
            "event_id TEXT,case_id TEXT,kind TEXT,source_evidence_id TEXT,persisted_at TEXT);"
            "CREATE TABLE search_frontier_investigator_triggers ("
            "event_id TEXT,queued_at TEXT);"
            "CREATE TABLE search_frontier_investigator_event_acks ("
            "event_id TEXT,acknowledged_at TEXT);"
            "CREATE TABLE search_frontier_investigator_sessions ("
            "event_id TEXT,started_at TEXT);"
            "CREATE TABLE search_frontier_investigator_turn_closures ("
            "event_id TEXT,closed_at TEXT,record_json TEXT);"
            "CREATE TABLE search_frontier_investigator_terminals ("
            "event_id TEXT,terminal_at TEXT,record_json TEXT);"
        )
        request = {
            "provider": {"provider_id": "pinned-laya"},
            "model_weight_sha256": "a" * 64,
            "items": [{"item_id": "a", "reference": {"kind": "measure"}}],
            "evidence_packets": [],
        }
        response = {
            "ranking_source": "laya",
            "degraded_reason": None,
            "presentation_trace": {
                "microbatches": [
                    {
                        "phase": "probe",
                        "candidate_ids": ["a"],
                        "inference_ids": ["a"],
                        "cache_hit_ids": [],
                        "worker_presentation": {"questions": [{"question_id": "q-a"}]},
                    }
                ]
            },
        }
        connection.execute(
            "INSERT INTO candidate_decision_snapshots VALUES (?,?,?,?,?,?)",
            (
                "case_test",
                "snapshot_1",
                "2026-01-01T00:00:00+00:00",
                "2026-01-01T00:00:01+00:00",
                json.dumps(request),
                json.dumps(response),
            ),
        )

    report = real_mixed_trace.trace_case(database, "case_test")

    assert report["rankings"][0]["work"]["original_candidates"] == 1
    assert report["rankings"][0]["work"]["expanded_worker_questions"] == 1
    assert report["rankings"][0]["frozen_to_snapshot_ms"] == 1000.0
    assert report["all_attempt_p95_ms"] is None


def test_report_keeps_original_parent_clock_and_accounts_for_deferred_turn(tmp_path: Path) -> None:
    database = tmp_path / "delayed.db"
    with sqlite3.connect(database) as connection:
        connection.executescript(
            "CREATE TABLE candidate_decision_snapshots ("
            "case_id TEXT,snapshot_id TEXT,request_frozen_at TEXT,captured_at TEXT,"
            "request_json TEXT,response_json TEXT);"
            "CREATE TABLE candidate_dispatch_admissions ("
            "case_id TEXT,admission_id TEXT,snapshot_id TEXT,candidate_id TEXT,admitted_at TEXT);"
            "CREATE TABLE candidate_followup_parents (admission_id TEXT,trigger_execution_id TEXT);"
            "CREATE TABLE candidate_dispatch_claims (admission_id TEXT,claimed_at TEXT);"
            "CREATE TABLE candidate_decision_execution_links ("
            "snapshot_id TEXT,candidate_id TEXT,execution_id TEXT);"
            "CREATE TABLE probe_executions ("
            "execution_id TEXT,started_at TEXT,finished_at TEXT,status TEXT);"
            "CREATE TABLE coordinator_events ("
            "case_id TEXT,kind TEXT,sequence INTEGER,persisted_at TEXT,event_json TEXT,"
            "source_record_id TEXT);"
            "CREATE TABLE evidence (evidence_id TEXT,case_id TEXT,execution_id TEXT);"
            "CREATE TABLE deep_mailbox ("
            "case_id TEXT,request_sha256 TEXT,status TEXT,reason TEXT,created_at TEXT,"
            "updated_at TEXT,result_json TEXT);"
            "CREATE TABLE search_frontier_investigator_turns ("
            "turn_id TEXT,event_id TEXT,case_id TEXT,reserved_at TEXT);"
            "CREATE TABLE search_frontier_investigator_turn_outcomes ("
            "turn_id TEXT,case_id TEXT,completed_at TEXT,record_json TEXT);"
            "CREATE TABLE search_frontier_events ("
            "event_id TEXT,case_id TEXT,kind TEXT,source_evidence_id TEXT,persisted_at TEXT);"
            "CREATE TABLE search_frontier_investigator_triggers ("
            "event_id TEXT,queued_at TEXT);"
            "CREATE TABLE search_frontier_investigator_event_acks ("
            "event_id TEXT,acknowledged_at TEXT);"
            "CREATE TABLE search_frontier_investigator_sessions ("
            "event_id TEXT,started_at TEXT);"
            "CREATE TABLE search_frontier_investigator_turn_closures ("
            "event_id TEXT,closed_at TEXT,record_json TEXT);"
            "CREATE TABLE search_frontier_investigator_terminals ("
            "event_id TEXT,terminal_at TEXT,record_json TEXT);"
        )
        case = "case_test"
        times = {
            "parent": "2026-01-01T00:00:00+00:00",
            "event": "2026-01-01T00:00:00.100000+00:00",
            "queued": "2026-01-01T00:00:00.150000+00:00",
            "reserved": "2026-01-01T00:00:09+00:00",
            "frozen": "2026-01-01T00:00:09.100000+00:00",
            "captured": "2026-01-01T00:00:09.500000+00:00",
            "admitted": "2026-01-01T00:00:09.600000+00:00",
            "claimed": "2026-01-01T00:00:09.650000+00:00",
            "launched": "2026-01-01T00:00:09.800000+00:00",
        }
        request = {
            "provider": {"provider_id": "pinned-laya"},
            "model_weight_sha256": "a" * 64,
            "items": [{"item_id": "a", "reference": {"kind": "measure"}}],
            "evidence_packets": [],
        }
        response = {"ranking_source": "laya", "degraded_reason": None}
        connection.execute(
            "INSERT INTO candidate_decision_snapshots VALUES (?,?,?,?,?,?)",
            (
                case,
                "snapshot_1",
                times["frozen"],
                times["captured"],
                json.dumps(request),
                json.dumps(response),
            ),
        )
        connection.execute(
            "INSERT INTO candidate_dispatch_admissions VALUES (?,?,?,?,?)",
            (case, "admission_1", "snapshot_1", "candidate_1", times["admitted"]),
        )
        connection.execute(
            "INSERT INTO candidate_followup_parents VALUES (?,?)", ("admission_1", "parent_exec")
        )
        connection.execute(
            "INSERT INTO candidate_dispatch_claims VALUES (?,?)", ("admission_1", times["claimed"])
        )
        connection.execute(
            "INSERT INTO candidate_decision_execution_links VALUES (?,?,?)",
            ("snapshot_1", "candidate_1", "followup_exec"),
        )
        connection.execute(
            "INSERT INTO probe_executions VALUES (?,?,?,?)",
            ("followup_exec", times["launched"], times["launched"], "ok"),
        )
        connection.execute(
            "INSERT INTO evidence VALUES (?,?,?)", ("parent_ev", case, "parent_exec")
        )
        connection.execute(
            "INSERT INTO coordinator_events VALUES (?,?,?,?,?,?)",
            (case, "evidence", 1, times["parent"], "{}", "parent_ev"),
        )
        connection.execute(
            "INSERT INTO search_frontier_events VALUES (?,?,?,?,?)",
            ("event_1", case, "observation_added", "parent_ev", times["event"]),
        )
        connection.execute(
            "INSERT INTO search_frontier_investigator_triggers VALUES (?,?)",
            ("event_1", times["queued"]),
        )
        connection.execute(
            "INSERT INTO search_frontier_investigator_turns VALUES (?,?,?,?)",
            ("turn_1", "event_1", case, times["reserved"]),
        )
        connection.execute(
            "INSERT INTO search_frontier_investigator_turn_outcomes VALUES (?,?,?,?)",
            (
                "turn_1",
                case,
                times["admitted"],
                json.dumps(
                    {"outcome": "measurement_admitted", "candidate_snapshot_id": "snapshot_1"}
                ),
            ),
        )
        connection.execute(
            "INSERT INTO deep_mailbox VALUES (?,?,?,?,?,?,?)",
            (
                case,
                "deep_1",
                "applied",
                "source basis revalidated",
                times["parent"],
                times["admitted"],
                json.dumps(
                    {
                        "started_at": "2026-01-01T00:00:00.200000Z",
                        "finished_at": "2026-01-01T00:00:09.550000Z",
                        "provider_identity": {"provider_id": "actual-deep"},
                        "response": {"provider": {"provider_id": "actual-deep"}, "degraded": False},
                    }
                ),
            ),
        )

    report = real_mixed_trace.trace_case(database, "case_test")
    measurement = report["measurements"][0]
    assert measurement["persisted_to_admitted_ms"] == 9600.0
    assert measurement["parent_persisted_to_turn_reserved_ms"] == 9000.0
    assert measurement["turn_reserved_to_request_frozen_ms"] == 100.0
    assert measurement["request_frozen_to_snapshot_ms"] == 400.0
    assert measurement["snapshot_to_admitted_ms"] == 100.0
    assert measurement["admitted_to_probe_start_ms"] == 200.0
    assert report["turns"][0]["event_queued_to_reserved_ms"] == 8850.0
    assert report["rankings"][0]["original_candidates"] == 1
    assert report["rankings"][0]["small_menu"] is True
    assert report["rankings"][0]["deep_worker_overlap_request_sha256"] == ["deep_1"]
    assert report["small_menu_responsiveness"]["rankings"] == 1
    assert report["small_menu_responsiveness"]["frozen_to_snapshot_ms"]["p50_ms"] == 400.0
    assert report["distinct_candidate_throughput"]["distinct_inferred"] is None
