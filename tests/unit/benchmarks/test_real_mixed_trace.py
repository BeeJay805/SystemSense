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
