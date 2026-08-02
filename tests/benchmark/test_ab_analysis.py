from datetime import UTC, datetime

from benchmarks.ab.analysis import (
    RunOutcome,
    analyze_paired_runs,
    outcome_from_trace,
    recommend_final_pair_count,
)
from benchmarks.ab.contracts import ExperimentArm
from benchmarks.ab.recorder import TraceRecorder
from benchmarks.models import BenchmarkFamily


def _run(
    pair_id: str,
    arm: ExperimentArm,
    *,
    success: bool,
    elapsed_ms: int,
    tokens: int,
    collateral: bool = False,
    overhead_ms: int | None = 100,
) -> RunOutcome:
    return RunOutcome(
        pair_id=pair_id,
        scenario_id=f"scenario.{pair_id}",
        family=BenchmarkFamily.APPLICATION,
        arm=arm,
        oracle_passed=success,
        collateral_change_detected=collateral,
        elapsed_ms=elapsed_ms,
        total_tokens=tokens,
        tool_calls=2,
        systemsense_overhead_ms=overhead_ms if arm is ExperimentArm.SYSTEMSENSE else 0,
        benchmark_leakage_detected=False,
    )


def test_paired_analysis_requires_six_valid_pairs_for_a_savings_claim() -> None:
    runs = tuple(
        _run(
            pair_id,
            arm,
            success=True,
            elapsed_ms=1000 if arm is ExperimentArm.BASELINE else 500,
            tokens=100 if arm is ExperimentArm.BASELINE else 50,
        )
        for pair_id in ("a", "b", "c", "d", "e", "f")
        for arm in (ExperimentArm.BASELINE, ExperimentArm.SYSTEMSENSE)
    )

    report = analyze_paired_runs(
        runs,
        required_pair_count=6,
        bootstrap_resamples=500,
        random_seed=7,
    )

    assert report.pair_count == 6
    assert report.quality_valid_pair_count == 6
    assert report.baseline_success_rate == 1.0
    assert report.systemsense_success_rate == 1.0
    assert report.median_token_savings_pct == 50.0
    assert report.token_savings_ci95 == (50.0, 50.0)
    assert report.token_savings_claim_allowed is True
    assert report.time_savings_claim_allowed is True


def test_one_valid_pair_has_no_confidence_interval_or_overhead_estimate() -> None:
    runs = (
        _run("a", ExperimentArm.BASELINE, success=True, elapsed_ms=1000, tokens=100),
        _run(
            "a",
            ExperimentArm.SYSTEMSENSE,
            success=True,
            elapsed_ms=500,
            tokens=50,
            overhead_ms=None,
        ),
    )

    report = analyze_paired_runs(runs, bootstrap_resamples=200, random_seed=2)

    assert report.token_savings_ci95 is None
    assert report.time_savings_ci95 is None
    assert report.median_systemsense_overhead_ms is None
    assert report.token_savings_claim_allowed is False


def test_quality_regression_blocks_savings_claim_even_when_successful_pairs_are_fast() -> None:
    runs = (
        _run("a", ExperimentArm.BASELINE, success=True, elapsed_ms=1000, tokens=100),
        _run("a", ExperimentArm.SYSTEMSENSE, success=True, elapsed_ms=500, tokens=50),
        _run("b", ExperimentArm.BASELINE, success=True, elapsed_ms=1000, tokens=100),
        _run("b", ExperimentArm.SYSTEMSENSE, success=False, elapsed_ms=500, tokens=50),
    )

    report = analyze_paired_runs(runs, bootstrap_resamples=200, random_seed=2)

    assert report.quality_gate_passed is False
    assert report.token_savings_claim_allowed is False
    assert report.time_savings_claim_allowed is False


def test_benchmark_leakage_invalidates_pair_and_quality_gate() -> None:
    baseline = _run(
        "a",
        ExperimentArm.BASELINE,
        success=True,
        elapsed_ms=1000,
        tokens=100,
    ).model_copy(update={"benchmark_leakage_detected": True})
    systemsense = _run(
        "a",
        ExperimentArm.SYSTEMSENSE,
        success=True,
        elapsed_ms=500,
        tokens=50,
    )

    report = analyze_paired_runs(
        (baseline, systemsense),
        bootstrap_resamples=200,
        random_seed=2,
    )

    assert report.quality_gate_passed is False
    assert report.quality_valid_pair_count == 0
    assert report.token_savings_claim_allowed is False


def test_runner_failure_overrides_a_passing_hidden_oracle() -> None:
    recorder = TraceRecorder(
        run_id="run-failed",
        pair_id="pair-failed",
        experiment_id="experiment-failed",
        scenario_id="application.port_conflict",
        family=BenchmarkFamily.APPLICATION,
        arm=ExperimentArm.SYSTEMSENSE,
        requested_model="gpt-5.6-sol",
        prompt_hash="a" * 64,
        tool_manifest_hash="b" * 64,
        started_at=datetime(2026, 8, 1, tzinfo=UTC),
    )
    trace = recorder.finish(
        final_answer="The health check works.",
        oracle_passed=True,
        collateral_change_detected=False,
        finished_at=datetime(2026, 8, 1, 0, 0, 1, tzinfo=UTC),
        failure="Codex CLI exited 20",
    )

    outcome = outcome_from_trace(trace)

    assert outcome.oracle_passed is False
    assert outcome.runner_failed is True
    assert outcome.failure == "Codex CLI exited 20"


def test_incomplete_frozen_enrollment_blocks_claim() -> None:
    runs = (
        _run("a", ExperimentArm.BASELINE, success=True, elapsed_ms=1000, tokens=100),
        _run("a", ExperimentArm.SYSTEMSENSE, success=True, elapsed_ms=500, tokens=50),
        _run("b", ExperimentArm.BASELINE, success=True, elapsed_ms=1000, tokens=100),
        _run("b", ExperimentArm.SYSTEMSENSE, success=True, elapsed_ms=500, tokens=50),
    )

    report = analyze_paired_runs(
        runs,
        required_pair_count=3,
        bootstrap_resamples=200,
        random_seed=2,
    )

    assert report.enrollment_complete is False
    assert report.token_savings_claim_allowed is False


def test_pilot_sample_size_uses_observed_variance_and_failure_inflation() -> None:
    recommendation = recommend_final_pair_count(
        paired_savings_pct=(5.0, 10.0, 15.0, 20.0, 25.0, 30.0),
        observed_failure_rate=0.2,
        minimum_detectable_savings_pct=10.0,
        minimum_final_pairs=12,
    )

    assert recommendation.recommended_pairs >= 12
    assert recommendation.failure_adjusted_pairs >= recommendation.variance_based_pairs
    assert recommendation.observed_standard_deviation > 0
