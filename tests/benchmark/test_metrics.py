import pytest

from benchmarks.models import (
    ArmMeasurement,
    BenchmarkFamily,
    BenchmarkScenario,
    GroundTruth,
    MeasurementSource,
)
from benchmarks.report import evaluate_case


def _scenario(
    *, systemsense_diagnosis: tuple[str, ...] = ("driver_mismatch",)
) -> BenchmarkScenario:
    return BenchmarkScenario(
        scenario_id="devices_driver",
        family=BenchmarkFamily.DEVICES_AUDIO,
        symptom="Audio disappeared after a driver update.",
        measurement_source=MeasurementSource.RECORDED_MODEL_RUN,
        baseline=ArmMeasurement(
            input_chars=10_000,
            input_tokens=1_000,
            elapsed_ms=100_000,
            tool_calls=10,
            evidence_ids=("ev_11111111111111111111111111111111",),
            diagnosis_codes=("driver_mismatch",),
        ),
        systemsense=ArmMeasurement(
            input_chars=3_000,
            input_tokens=400,
            elapsed_ms=30_000,
            tool_calls=3,
            evidence_ids=("ev_11111111111111111111111111111111",),
            diagnosis_codes=systemsense_diagnosis,
        ),
        systemsense_overhead_ms=10_000,
    )


def _truth() -> GroundTruth:
    return GroundTruth(
        scenario_id="devices_driver",
        required_evidence_ids=("ev_11111111111111111111111111111111",),
        accepted_diagnosis_codes=("driver_mismatch",),
    )


def test_metrics_include_overhead_and_compute_exact_savings() -> None:
    metrics = evaluate_case(_scenario(), _truth())

    assert metrics.savings_valid is True
    assert metrics.context_char_savings_pct == pytest.approx(70.0)
    assert metrics.token_savings_pct == pytest.approx(60.0)
    assert metrics.time_savings_pct == pytest.approx(60.0)
    assert metrics.tool_call_savings_pct == pytest.approx(70.0)
    assert metrics.baseline_quality == pytest.approx(1.0)
    assert metrics.systemsense_quality == pytest.approx(1.0)


def test_savings_are_invalid_when_diagnostic_quality_regresses() -> None:
    metrics = evaluate_case(_scenario(systemsense_diagnosis=("wrong",)), _truth())

    assert metrics.systemsense_quality < metrics.baseline_quality
    assert metrics.savings_valid is False
    assert metrics.invalid_reason == "diagnostic quality regressed"


def test_missing_recorded_tokens_remain_explicit() -> None:
    scenario = _scenario().model_copy(
        update={"systemsense": _scenario().systemsense.model_copy(update={"input_tokens": None})}
    )

    metrics = evaluate_case(scenario, _truth())

    assert metrics.token_savings_pct is None
