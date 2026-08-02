"""Paired, quality-gated analysis for recorded model runs."""

from __future__ import annotations

import math
import random
import statistics
from collections import defaultdict
from collections.abc import Iterable
from statistics import NormalDist

from pydantic import Field

from benchmarks.ab.contracts import ExperimentArm, ExperimentModel
from benchmarks.ab.recorder import RunTrace
from benchmarks.ab.tools import SYSTEMSENSE_TOOL_NAMES
from benchmarks.models import BenchmarkFamily


class RunOutcome(ExperimentModel):
    pair_id: str = Field(min_length=1)
    scenario_id: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$")
    family: BenchmarkFamily
    arm: ExperimentArm
    oracle_passed: bool
    collateral_change_detected: bool
    elapsed_ms: int = Field(ge=1)
    total_tokens: int = Field(ge=0)
    tool_calls: int = Field(ge=0)
    systemsense_overhead_ms: int | None = Field(default=None, ge=0)
    benchmark_leakage_detected: bool = False
    runner_failed: bool = False
    failure: str | None = None


class PairedAnalysis(ExperimentModel):
    schema_version: int = 2
    pair_count: int = Field(ge=1)
    required_pair_count: int = Field(ge=2)
    enrollment_complete: bool
    quality_valid_pair_count: int = Field(ge=0)
    baseline_success_rate: float = Field(ge=0, le=1)
    systemsense_success_rate: float = Field(ge=0, le=1)
    baseline_collateral_change_rate: float = Field(ge=0, le=1)
    systemsense_collateral_change_rate: float = Field(ge=0, le=1)
    quality_gate_passed: bool
    median_token_savings_pct: float | None
    token_savings_ci95: tuple[float, float] | None
    median_time_savings_pct: float | None
    time_savings_ci95: tuple[float, float] | None
    median_tool_call_savings_pct: float | None
    median_systemsense_overhead_ms: float | None
    token_savings_claim_allowed: bool
    time_savings_claim_allowed: bool


class SampleSizeRecommendation(ExperimentModel):
    pilot_pair_count: int = Field(ge=2)
    observed_standard_deviation: float = Field(ge=0)
    minimum_detectable_savings_pct: float = Field(gt=0)
    alpha: float = Field(gt=0, lt=1)
    power: float = Field(gt=0, lt=1)
    variance_based_pairs: int = Field(ge=2)
    observed_failure_rate: float = Field(ge=0, lt=1)
    failure_adjusted_pairs: int = Field(ge=2)
    recommended_pairs: int = Field(ge=2)


def outcome_from_trace(trace: RunTrace) -> RunOutcome:
    if trace.oracle_passed is None:
        raise ValueError("trace has not been scored by the hidden oracle")
    if trace.collateral_change_detected is None:
        raise ValueError("trace has not been scored for collateral changes")
    systemsense_tools = tuple(tool for tool in trace.tools if tool.name in SYSTEMSENSE_TOOL_NAMES)
    systemsense_overhead_ms = (
        sum(tool.elapsed_ms for tool in systemsense_tools if tool.elapsed_ms is not None)
        if systemsense_tools and all(tool.elapsed_ms is not None for tool in systemsense_tools)
        else (0 if not systemsense_tools else None)
    )
    return RunOutcome(
        pair_id=trace.pair_id,
        scenario_id=trace.scenario_id,
        family=trace.family,
        arm=trace.arm,
        oracle_passed=trace.oracle_passed and trace.failure is None,
        collateral_change_detected=trace.collateral_change_detected,
        elapsed_ms=max(1, trace.elapsed_ms),
        total_tokens=trace.usage.total_tokens,
        tool_calls=trace.tool_call_count,
        systemsense_overhead_ms=systemsense_overhead_ms,
        benchmark_leakage_detected=trace.benchmark_leakage_detected,
        runner_failed=trace.failure is not None,
        failure=trace.failure,
    )


def analyze_paired_runs(
    runs: Iterable[RunOutcome],
    *,
    required_pair_count: int = 2,
    bootstrap_resamples: int = 10_000,
    random_seed: int = 0,
) -> PairedAnalysis:
    if required_pair_count < 2:
        raise ValueError("required_pair_count must be at least two")
    pairs = _pair_runs(runs)
    if bootstrap_resamples < 100:
        raise ValueError("bootstrap_resamples must be at least 100")
    baseline = tuple(pair[ExperimentArm.BASELINE] for pair in pairs)
    systemsense = tuple(pair[ExperimentArm.SYSTEMSENSE] for pair in pairs)
    baseline_success = sum(run.oracle_passed for run in baseline)
    systemsense_success = sum(run.oracle_passed for run in systemsense)
    baseline_collateral = sum(run.collateral_change_detected for run in baseline)
    systemsense_collateral = sum(run.collateral_change_detected for run in systemsense)
    leakage_free = not any(run.benchmark_leakage_detected for run in (*baseline, *systemsense))
    quality_gate = (
        systemsense_success >= baseline_success
        and systemsense_collateral <= baseline_collateral
        and leakage_free
    )
    valid = tuple(
        pair
        for pair in pairs
        if pair[ExperimentArm.BASELINE].oracle_passed
        and pair[ExperimentArm.SYSTEMSENSE].oracle_passed
        and not pair[ExperimentArm.BASELINE].collateral_change_detected
        and not pair[ExperimentArm.SYSTEMSENSE].collateral_change_detected
        and not pair[ExperimentArm.BASELINE].benchmark_leakage_detected
        and not pair[ExperimentArm.SYSTEMSENSE].benchmark_leakage_detected
    )
    token_savings = tuple(
        _savings(
            pair[ExperimentArm.BASELINE].total_tokens,
            pair[ExperimentArm.SYSTEMSENSE].total_tokens,
        )
        for pair in valid
    )
    time_savings = tuple(
        _savings(
            pair[ExperimentArm.BASELINE].elapsed_ms,
            pair[ExperimentArm.SYSTEMSENSE].elapsed_ms,
        )
        for pair in valid
    )
    tool_savings = tuple(
        _savings(
            pair[ExperimentArm.BASELINE].tool_calls,
            pair[ExperimentArm.SYSTEMSENSE].tool_calls,
        )
        for pair in valid
        if pair[ExperimentArm.BASELINE].tool_calls > 0
    )
    raw_overhead = tuple(pair[ExperimentArm.SYSTEMSENSE].systemsense_overhead_ms for pair in valid)
    overhead = (
        tuple(value for value in raw_overhead if value is not None)
        if all(value is not None for value in raw_overhead)
        else ()
    )
    token_ci = _bootstrap_median_ci(
        token_savings,
        resamples=bootstrap_resamples,
        seed=random_seed,
    )
    time_ci = _bootstrap_median_ci(
        time_savings,
        resamples=bootstrap_resamples,
        seed=random_seed + 1,
    )
    pair_count = len(pairs)
    enrollment_complete = pair_count >= required_pair_count
    claim_sample_valid = enrollment_complete and len(valid) >= max(6, required_pair_count)
    return PairedAnalysis(
        pair_count=pair_count,
        required_pair_count=required_pair_count,
        enrollment_complete=enrollment_complete,
        quality_valid_pair_count=len(valid),
        baseline_success_rate=baseline_success / pair_count,
        systemsense_success_rate=systemsense_success / pair_count,
        baseline_collateral_change_rate=baseline_collateral / pair_count,
        systemsense_collateral_change_rate=systemsense_collateral / pair_count,
        quality_gate_passed=quality_gate,
        median_token_savings_pct=_median(token_savings),
        token_savings_ci95=token_ci,
        median_time_savings_pct=_median(time_savings),
        time_savings_ci95=time_ci,
        median_tool_call_savings_pct=_median(tool_savings),
        median_systemsense_overhead_ms=_median(overhead),
        token_savings_claim_allowed=(
            quality_gate and claim_sample_valid and token_ci is not None and token_ci[0] > 0
        ),
        time_savings_claim_allowed=(
            quality_gate and claim_sample_valid and time_ci is not None and time_ci[0] > 0
        ),
    )


def recommend_final_pair_count(
    *,
    paired_savings_pct: tuple[float, ...],
    observed_failure_rate: float,
    minimum_detectable_savings_pct: float,
    minimum_final_pairs: int,
    alpha: float = 0.05,
    power: float = 0.8,
) -> SampleSizeRecommendation:
    if len(paired_savings_pct) < 2:
        raise ValueError("at least two pilot pairs are required")
    if not 0 <= observed_failure_rate < 1:
        raise ValueError("observed_failure_rate must be between 0 and 1")
    if minimum_detectable_savings_pct <= 0:
        raise ValueError("minimum_detectable_savings_pct must be positive")
    if minimum_final_pairs < 2:
        raise ValueError("minimum_final_pairs must be at least two")
    if not 0 < alpha < 1 or not 0 < power < 1:
        raise ValueError("alpha and power must be between zero and one")
    standard_deviation = statistics.stdev(paired_savings_pct)
    z_alpha = NormalDist().inv_cdf(1 - alpha / 2)
    z_power = NormalDist().inv_cdf(power)
    variance_based = max(
        2,
        math.ceil(((z_alpha + z_power) * standard_deviation / minimum_detectable_savings_pct) ** 2),
    )
    failure_adjusted = math.ceil(variance_based / (1 - observed_failure_rate))
    return SampleSizeRecommendation(
        pilot_pair_count=len(paired_savings_pct),
        observed_standard_deviation=standard_deviation,
        minimum_detectable_savings_pct=minimum_detectable_savings_pct,
        alpha=alpha,
        power=power,
        variance_based_pairs=variance_based,
        observed_failure_rate=observed_failure_rate,
        failure_adjusted_pairs=failure_adjusted,
        recommended_pairs=max(minimum_final_pairs, failure_adjusted),
    )


def _pair_runs(
    runs: Iterable[RunOutcome],
) -> tuple[dict[ExperimentArm, RunOutcome], ...]:
    grouped: defaultdict[str, dict[ExperimentArm, RunOutcome]] = defaultdict(dict)
    for run in runs:
        if run.arm in grouped[run.pair_id]:
            raise ValueError(f"duplicate {run.arm.value} run for pair {run.pair_id}")
        grouped[run.pair_id][run.arm] = run
    if not grouped:
        raise ValueError("at least one paired run is required")
    for pair_id, pair in grouped.items():
        if set(pair) != {ExperimentArm.BASELINE, ExperimentArm.SYSTEMSENSE}:
            raise ValueError(f"pair {pair_id} is incomplete")
        if pair[ExperimentArm.BASELINE].scenario_id != pair[ExperimentArm.SYSTEMSENSE].scenario_id:
            raise ValueError(f"pair {pair_id} scenario IDs differ")
    return tuple(grouped[pair_id] for pair_id in sorted(grouped))


def _savings(baseline: int, systemsense: int) -> float:
    if baseline <= 0:
        raise ValueError("baseline metric must be positive")
    return 100.0 * (baseline - systemsense) / baseline


def _median(values: tuple[float | int, ...]) -> float | None:
    return None if not values else float(statistics.median(values))


def _bootstrap_median_ci(
    values: tuple[float, ...],
    *,
    resamples: int,
    seed: int,
) -> tuple[float, float] | None:
    if len(values) < 2:
        return None
    generator = random.Random(seed)
    estimates = sorted(
        statistics.median(generator.choices(values, k=len(values))) for _sample in range(resamples)
    )
    lower = estimates[math.floor(0.025 * (resamples - 1))]
    upper = estimates[math.ceil(0.975 * (resamples - 1))]
    return float(lower), float(upper)
