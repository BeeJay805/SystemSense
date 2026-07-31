import json
from pathlib import Path

from benchmarks.models import BenchmarkFamily, MeasurementSource
from benchmarks.report import build_report, render_markdown
from benchmarks.runner import load_benchmark_cases


def test_engineering_suite_covers_six_families_and_hides_ground_truth() -> None:
    cases = load_benchmark_cases()

    assert {scenario.family for scenario, _truth in cases} == set(BenchmarkFamily)
    assert len(cases) == 6
    for scenario_path in sorted((Path("benchmarks") / "scenarios").glob("*.json")):
        raw = json.loads(scenario_path.read_text(encoding="utf-8"))
        assert "required_evidence_ids" not in raw
        assert "accepted_diagnosis_codes" not in raw


def test_report_is_deterministic_and_labels_fixture_savings() -> None:
    cases = load_benchmark_cases()

    first = build_report(cases)
    second = build_report(cases)
    markdown = render_markdown(first)

    assert first == second
    assert first.measurement_sources == (MeasurementSource.ENGINEERING_FIXTURE,)
    assert first.aggregate.case_count == 6
    assert first.aggregate.valid_case_count == 6
    assert "engineering fixtures" in markdown.casefold()
    assert "not measured claude savings" in markdown.casefold()
    assert "Quality-gated" in markdown
