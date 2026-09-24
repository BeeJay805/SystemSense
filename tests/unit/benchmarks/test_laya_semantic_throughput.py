"""The runtime benchmark must not turn synthetic speed into utility claims."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from benchmarks.laya_semantic_throughput import (
    nearest_rank_percentile,
    packet_count_schedule,
    summarize_rank_calls,
    summarize_sweep,
    synthetic_workload,
    verify_attention,
    write_exclusive,
)
from systemsense.inference.laya_runtime import (
    LayaAttentionMicrobatch,
    LayaAttentionResult,
    LayaQuestionPresentation,
    LayaWorkerPresentation,
)


def _presentation(ids: tuple[str, ...]) -> LayaWorkerPresentation:
    return LayaWorkerPresentation(
        presentation_sha256="a" * 64,
        fitted_state_sha256="b" * 64,
        questions_sha256="c" * 64,
        presented_item_ids=ids,
        fitted_state_tokens=20,
        state_tokens_original=20,
        state_fields_omitted=0,
        state_list_items_omitted=0,
        questions=tuple(
            LayaQuestionPresentation(
                question_id=f"q{index}",
                item_id=item,
                question_sha256="d" * 64,
                instruction_tokens=10,
                instruction_presented_tokens=10,
                criteria_tokens=2,
                criteria_presented_tokens=2,
                state_presented_tokens=20,
            )
            for index, item in enumerate(ids)
        ),
    )


def test_workload_uses_versioned_semantic_packets_and_distinct_20_candidates() -> None:
    state_a, evidence_a, candidates_a = synthetic_workload(0)
    state_b, evidence_b, candidates_b = synthetic_workload(1)

    assert len(evidence_a) == 8
    assert len(candidates_a) == 20
    assert len({item["probe_id"] for item in candidates_a}) == 20
    assert set(item["probe_id"] for item in candidates_a).isdisjoint(
        item["probe_id"] for item in candidates_b
    )
    assert {item["fragment_id"] for item in evidence_a}.isdisjoint(
        item["fragment_id"] for item in evidence_b
    )
    assert state_a["evidence_serializer"] == "semantic_fact_packets_v1"
    assert all(
        json.loads(item["description"])["projection"] == "semantic_fact_packets_v1"
        for item in evidence_a
    )
    assert state_a != state_b


@pytest.mark.parametrize("packet_count", [4, 8, 16])
def test_sweep_workload_never_silently_drops_requested_packets(packet_count: int) -> None:
    _, evidence, candidates = synthetic_workload(7, packet_count=packet_count)
    assert len(evidence) == packet_count
    assert len({item["page_id"] for item in evidence}) == packet_count
    assert len(candidates) == 20


def test_sweep_schedule_counterbalances_packet_position() -> None:
    schedules = [packet_count_schedule(index) for index in range(3)]
    assert all(len(schedule) == 9 for schedule in schedules)
    assert all(sorted(schedule) == [4, 4, 4, 8, 8, 8, 16, 16, 16] for schedule in schedules)
    assert {schedule[0] for schedule in schedules} == {4, 8, 16}


def test_sweep_summary_keeps_failed_attempts_out_of_latency_denominator() -> None:
    attempts: list[dict[str, object]] = [
        {"batch_size": 4, "packet_count": 8, "status": "complete", "seconds": 0.3},
        {"batch_size": 4, "packet_count": 8, "status": "complete", "seconds": 0.4},
        {"batch_size": 4, "packet_count": 8, "status": "failed", "seconds": 0.1},
    ]
    summary = summarize_sweep(attempts)
    cell = summary["batch_4_packets_8"]
    assert cell["attempts"] == 3
    assert cell["valid"] == 2
    assert cell["p95_seconds"] == 0.4
    assert cell["p95_below_400ms_with_three_valid_runs"] is False


def test_rank_call_summary_requires_complete_two_phase_accounting() -> None:
    calls: list[dict[str, object]] = [
        {"phase": "evidence", "candidates": 4, "seconds": 0.1, "status": "complete"},
        {"phase": "evidence", "candidates": 4, "seconds": 0.1, "status": "complete"},
        {"phase": "probe", "candidates": 4, "seconds": 0.2, "status": "complete"},
        {"phase": "probe", "candidates": 4, "seconds": 0.2, "status": "complete"},
        {"phase": "probe", "candidates": 4, "seconds": 0.2, "status": "complete"},
        {"phase": "probe", "candidates": 4, "seconds": 0.2, "status": "complete"},
        {"phase": "probe", "candidates": 4, "seconds": 0.2, "status": "complete"},
    ]
    summary = summarize_rank_calls(calls, evidence_count=8, probe_count=20, batch_size=4)
    assert summary == {
        "worker_calls": 7,
        "evidence_worker_seconds": pytest.approx(0.2),
        "probe_worker_seconds": pytest.approx(1.0),
        "worker_call_seconds": pytest.approx(1.2),
    }
    with pytest.raises(ValueError, match="coverage"):
        summarize_rank_calls(calls[:-1], evidence_count=8, probe_count=20, batch_size=4)


def test_attention_requires_full_miss_and_coverage() -> None:
    _, evidence, candidates = synthetic_workload(0)
    evidence_ids = tuple(item["fragment_id"] for item in evidence)
    probe_ids = tuple(item["probe_id"] for item in candidates)
    result = LayaAttentionResult(
        considered_attention_page_ids=tuple(item["page_id"] for item in evidence),
        considered_probe_ids=probe_ids,
        microbatches=(
            LayaAttentionMicrobatch(
                phase="evidence",
                batch_index=0,
                candidate_ids=evidence_ids,
                inference_ids=evidence_ids,
                worker_presentation=_presentation(evidence_ids),
            ),
            LayaAttentionMicrobatch(
                phase="probe",
                batch_index=0,
                candidate_ids=probe_ids,
                inference_ids=probe_ids,
                worker_presentation=_presentation(probe_ids),
            ),
        ),
        attention_notes=(
            "coverage_limited=false",
            "state_truncated_batches=0",
            "instruction_truncated_items=0",
        ),
    )

    assert verify_attention(result, evidence, candidates)["judgments"] == 28
    bad = result.model_copy(
        update={
            "microbatches": (
                result.microbatches[0].model_copy(update={"cache_hit_ids": (evidence_ids[0],)}),
                result.microbatches[1],
            )
        }
    )
    with pytest.raises(ValueError, match="cache hit"):
        verify_attention(bad, evidence, candidates)
    with pytest.raises(ValueError, match="truncation"):
        verify_attention(
            result.model_copy(update={"attention_notes": ("state_truncated_batches=1",)}),
            evidence,
            candidates,
        )


def test_percentiles_and_exclusive_output(tmp_path: Path) -> None:
    assert nearest_rank_percentile([5.0, 1.0, 3.0], 50) == 3.0
    assert nearest_rank_percentile([5.0, 1.0, 3.0], 95) == 5.0
    target = tmp_path / "run.json"
    write_exclusive(target, {"status": "complete"})
    with pytest.raises(FileExistsError):
        write_exclusive(target, {"status": "failed"})
    assert json.loads(target.read_text()) == {"status": "complete"}
