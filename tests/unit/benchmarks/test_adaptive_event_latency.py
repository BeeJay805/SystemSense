"""Synthetic event-to-admission timing must count misses and real scheduler starts."""

import json
import sqlite3
from pathlib import Path

import pytest


def test_fast_provider_starts_followup_before_unrelated_slow_probe_finishes(
    tmp_path: Path,
) -> None:
    from benchmarks.adaptive_event_latency import FakeFastProvider, LatencyConfig, run_trial

    database = tmp_path / "fast.sqlite3"
    report = run_trial(
        LatencyConfig(
            event_count=4,
            queue_capacity=8,
            event_deadline_ms=1000,
            unrelated_probe_ms=500,
        ),
        FakeFastProvider(delay_ms=2),
        database_path=database,
    )

    assert report["kind"] == "synthetic_event_to_admission_v1"
    assert report["attempts"] == 4
    assert report["persisted"] == 4
    assert report["admitted"] == 4
    assert report["started"] == 4
    assert report["completed"] == 4
    assert report["misses"] == 0
    assert report["transport_ms"] == "not_applicable_local_fake"
    assert report["followup_before_unrelated_finish"] is True
    assert report["event_to_admission_ms"]["count"] == 4
    for phase in (
        "persistence",
        "queue",
        "inference",
        "validation",
        "admission",
        "start",
        "execution",
    ):
        assert report["phase_ms"][phase]["count"] == 4
        assert report["phase_ms"][phase]["p95"] >= 0
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM benchmark_events").fetchone()[0] == 4


def test_slow_provider_deadline_misses_remain_in_the_denominator(tmp_path: Path) -> None:
    from benchmarks.adaptive_event_latency import FakeSlowProvider, LatencyConfig, run_trial

    report = run_trial(
        LatencyConfig(
            event_count=4,
            queue_capacity=8,
            event_deadline_ms=15,
            unrelated_probe_ms=50,
        ),
        FakeSlowProvider(delay_ms=60),
        database_path=tmp_path / "slow.sqlite3",
    )

    assert report["attempts"] == 4
    assert report["persisted"] == 4
    assert report["admitted"] == 0
    assert report["completed"] == 0
    assert report["misses"] == 4
    assert sum(report["miss_reasons"].values()) == 4
    assert report["event_to_admission_ms"]["count"] == 0
    assert report["all_attempt_p95_ms"] is None
    assert len(report["attempts_detail"]) == 4
    assert any(item["phase_ms"]["inference"] is not None for item in report["attempts_detail"])


def test_backpressure_counts_every_persisted_event_even_when_queue_is_full(
    tmp_path: Path,
) -> None:
    from benchmarks.adaptive_event_latency import FakeSlowProvider, LatencyConfig, run_trial

    report = run_trial(
        LatencyConfig(
            event_count=32,
            queue_capacity=1,
            event_deadline_ms=1000,
            unrelated_probe_ms=100,
        ),
        FakeSlowProvider(delay_ms=30),
        database_path=tmp_path / "overload.sqlite3",
    )

    assert report["attempts"] == 32
    assert report["persisted"] == 32
    assert report["misses"] > 0
    assert report["miss_reasons"].get("queue_overload", 0) > 0
    assert report["admitted"] + report["misses"] == 32
    assert len(report["attempts_detail"]) == 32


def test_invalid_provider_choice_is_measured_as_validation_miss(tmp_path: Path) -> None:
    from benchmarks.adaptive_event_latency import FakeFastProvider, LatencyConfig, run_trial

    report = run_trial(
        LatencyConfig(
            event_count=5,
            queue_capacity=8,
            event_deadline_ms=1000,
            unrelated_probe_ms=100,
        ),
        FakeFastProvider(delay_ms=0, invalid_every=2),
        database_path=tmp_path / "invalid.sqlite3",
    )

    assert report["attempts"] == 5
    assert report["miss_reasons"].get("invalid_choice") == 2
    assert report["admitted"] == 3
    assert report["started"] == 3
    assert report["phase_ms"]["validation"]["count"] == 5


def test_default_temporary_database_is_closed_before_cleanup() -> None:
    from benchmarks.adaptive_event_latency import FakeFastProvider, LatencyConfig, run_trial

    report = run_trial(
        LatencyConfig(event_count=2, queue_capacity=2, unrelated_probe_ms=50),
        FakeFastProvider(delay_ms=0),
    )

    assert report["attempts"] == 2
    assert report["unexpected_harness_errors"] == []


def test_cli_output_is_exclusive_and_never_overwrites_a_prior_run(tmp_path: Path) -> None:
    from benchmarks.adaptive_event_latency import main

    output = tmp_path / "latency-run.json"
    args = [
        "--events",
        "2",
        "--queue-capacity",
        "2",
        "--unrelated-probe-ms",
        "50",
        "--provider-delay-ms",
        "0",
        "--output",
        str(output),
    ]
    main(args)
    before = output.read_bytes()

    assert json.loads(before)["attempts"] == 2
    with pytest.raises(FileExistsError):
        main(args)
    assert output.read_bytes() == before
