import pytest

from benchmarks.ab.analysis import (
    RunOutcome,
    analyze_paired_runs,
    recommend_final_pair_count,
)
from benchmarks.ab.contracts import ExperimentArm
from benchmarks.models import BenchmarkFamily


def _run(
    pair_id: str,
    arm: ExperimentArm,
    *,
    success: bool,
    elapsed_ms: int,
    tokens: int,
    collateral: bool = False,
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
        systemsense_overhead_ms=100 if arm is ExperimentArm.SYSTEMSENSE else 0,
    )


def test_paired_analysis_keeps_failures_and_proves_positive_identical_savings() -> None:
    runs = (
        _run("a", ExperimentArm.BASELINE, success=True, elapsed_ms=1000, tokens=100),
        _run("a", ExperimentArm.SYSTEMSENSE, success=True, elapsed_ms=500, tokens=50),
        _run("b", ExperimentArm.BASELINE, success=True, elapsed_ms=2000, tokens=200),
        _run("b", ExperimentArm.SYSTEMSENSE, success=True, elapsed_ms=1000, tokens=100),
        _run("c", ExperimentArm.BASELINE, success=False, elapsed_ms=3000, tokens=300),
        _run("c", ExperimentArm.SYSTEMSENSE, success=True, elapsed_ms=2500, tokens=250),
    )

    report = analyze_paired_runs(runs, bootstrap_resamples=500, random_seed=7)

    assert report.pair_count == 3
    assert report.quality_valid_pair_count == 2
    assert report.baseline_success_rate == pytest.approx(2 / 3)
    assert report.systemsense_success_rate == 1.0
    assert report.median_token_savings_pct == 50.0
    assert report.token_savings_ci95 == (50.0, 50.0)
    assert report.token_savings_claim_allowed is True
    assert report.time_savings_claim_allowed is True


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
