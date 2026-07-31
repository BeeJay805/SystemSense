"""Quality scoring, savings calculations, and deterministic reporting."""

from __future__ import annotations

import math
import statistics
from collections.abc import Iterable

from benchmarks.models import (
    AggregateMetrics,
    ArmMeasurement,
    BenchmarkReport,
    BenchmarkScenario,
    CaseMetrics,
    Distribution,
    GroundTruth,
)


def evaluate_case(scenario: BenchmarkScenario, truth: GroundTruth) -> CaseMetrics:
    if scenario.scenario_id != truth.scenario_id:
        raise ValueError("scenario and ground truth IDs do not match")

    baseline_quality = _quality(scenario.baseline, truth)
    systemsense_quality = _quality(scenario.systemsense, truth)
    quality_regressed = systemsense_quality < baseline_quality
    return CaseMetrics(
        scenario_id=scenario.scenario_id,
        family=scenario.family,
        measurement_source=scenario.measurement_source,
        baseline_quality=baseline_quality,
        systemsense_quality=systemsense_quality,
        context_char_savings_pct=_savings(
            scenario.baseline.input_chars,
            scenario.systemsense.input_chars,
        ),
        token_savings_pct=_optional_savings(
            scenario.baseline.input_tokens,
            scenario.systemsense.input_tokens,
        ),
        time_savings_pct=_savings(
            scenario.baseline.elapsed_ms,
            scenario.systemsense.elapsed_ms + scenario.systemsense_overhead_ms,
        ),
        tool_call_savings_pct=_savings(
            scenario.baseline.tool_calls,
            scenario.systemsense.tool_calls,
        ),
        systemsense_overhead_ms=scenario.systemsense_overhead_ms,
        savings_valid=not quality_regressed,
        invalid_reason="diagnostic quality regressed" if quality_regressed else None,
    )


def build_report(
    cases: Iterable[tuple[BenchmarkScenario, GroundTruth]],
) -> BenchmarkReport:
    metrics = tuple(
        sorted(
            (evaluate_case(scenario, truth) for scenario, truth in cases),
            key=lambda item: item.scenario_id,
        )
    )
    if not metrics:
        raise ValueError("at least one benchmark case is required")
    valid = tuple(item for item in metrics if item.savings_valid)
    return BenchmarkReport(
        measurement_sources=tuple(
            sorted(
                {item.measurement_source for item in metrics},
                key=lambda source: source.value,
            )
        ),
        cases=metrics,
        aggregate=AggregateMetrics(
            case_count=len(metrics),
            valid_case_count=len(valid),
            invalid_case_ids=tuple(item.scenario_id for item in metrics if not item.savings_valid),
            context_char_savings_pct=_distribution(item.context_char_savings_pct for item in valid),
            token_savings_pct=_distribution(
                item.token_savings_pct for item in valid if item.token_savings_pct is not None
            ),
            time_savings_pct=_distribution(item.time_savings_pct for item in valid),
            tool_call_savings_pct=_distribution(item.tool_call_savings_pct for item in valid),
        ),
    )


def render_markdown(report: BenchmarkReport) -> str:
    fixture_only = all(
        source.value == "engineering_fixture" for source in report.measurement_sources
    )
    lines = [
        "# SystemSense benchmark report",
        "",
        (
            "This report uses deterministic engineering fixtures. These are not "
            "measured Claude savings."
            if fixture_only
            else "This report includes recorded model-run measurements."
        ),
        "",
        (
            "Quality-gated savings are valid only when SystemSense diagnostic "
            "quality is equal to or better than the manual baseline."
        ),
        "",
        (
            "| Case | Family | Quality baseline to SystemSense | Chars | Tokens | "
            "Time | Tools | Valid |"
        ),
        "|---|---|---:|---:|---:|---:|---:|:---:|",
    ]
    for item in report.cases:
        lines.append(
            "| "
            + " | ".join(
                (
                    item.scenario_id,
                    item.family.value,
                    f"{item.baseline_quality:.2f} to {item.systemsense_quality:.2f}",
                    _percent(item.context_char_savings_pct),
                    (
                        "not recorded"
                        if item.token_savings_pct is None
                        else _percent(item.token_savings_pct)
                    ),
                    _percent(item.time_savings_pct),
                    _percent(item.tool_call_savings_pct),
                    "yes" if item.savings_valid else "no",
                )
            )
            + " |"
        )
    lines.extend(("", "## Aggregate", ""))
    lines.append(
        f"- Valid cases: {report.aggregate.valid_case_count}/{report.aggregate.case_count}"
    )
    lines.append(
        "- Median context character savings: "
        + _distribution_median(report.aggregate.context_char_savings_pct)
    )
    lines.append(
        (
            "- Median fixture token-field savings: "
            if fixture_only
            else "- Median recorded token savings: "
        )
        + _distribution_median(report.aggregate.token_savings_pct)
    )
    lines.append(
        "- Median elapsed-time savings: " + _distribution_median(report.aggregate.time_savings_pct)
    )
    lines.append(
        "- Median tool-call savings: "
        + _distribution_median(report.aggregate.tool_call_savings_pct)
    )
    return "\n".join(lines)


def _quality(measurement: ArmMeasurement, truth: GroundTruth) -> float:
    required = set(truth.required_evidence_ids)
    evidence_recall = len(required & set(measurement.evidence_ids)) / len(required)
    diagnosis_correct = bool(set(measurement.diagnosis_codes) & set(truth.accepted_diagnosis_codes))
    return (0.4 * evidence_recall) + (0.6 * float(diagnosis_correct))


def _savings(baseline: int, current: int) -> float:
    if baseline <= 0:
        raise ValueError("baseline measurement must be positive")
    return 100.0 * (baseline - current) / baseline


def _optional_savings(baseline: int | None, current: int | None) -> float | None:
    if baseline is None or current is None:
        return None
    return _savings(baseline, current)


def _distribution(values: Iterable[float]) -> Distribution | None:
    ordered = sorted(values)
    if not ordered:
        return None
    p95_index = math.ceil(0.95 * len(ordered)) - 1
    return Distribution(
        count=len(ordered),
        minimum=ordered[0],
        median=statistics.median(ordered),
        p95=ordered[p95_index],
        maximum=ordered[-1],
        mean=statistics.fmean(ordered),
    )


def _percent(value: float) -> str:
    return f"{value:.2f}%"


def _distribution_median(distribution: Distribution | None) -> str:
    return "not recorded" if distribution is None else _percent(distribution.median)
