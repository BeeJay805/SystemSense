"""Load local benchmark recordings and emit a deterministic report."""

from pathlib import Path

from benchmarks.models import BenchmarkScenario, GroundTruth
from benchmarks.report import build_report, render_markdown

_ROOT = Path(__file__).resolve().parent


def load_benchmark_cases(
    *,
    scenario_dir: Path = _ROOT / "scenarios",
    ground_truth_dir: Path = _ROOT / "ground_truth",
) -> tuple[tuple[BenchmarkScenario, GroundTruth], ...]:
    cases: list[tuple[BenchmarkScenario, GroundTruth]] = []
    for scenario_path in sorted(scenario_dir.glob("*.json")):
        scenario = BenchmarkScenario.model_validate_json(scenario_path.read_text(encoding="utf-8"))
        truth_path = ground_truth_dir / scenario_path.name
        if not truth_path.is_file():
            raise ValueError(f"ground truth is missing for {scenario.scenario_id}")
        truth = GroundTruth.model_validate_json(truth_path.read_text(encoding="utf-8"))
        cases.append((scenario, truth))
    if not cases:
        raise ValueError("no benchmark scenarios were found")
    return tuple(cases)


def main() -> int:
    report = build_report(load_benchmark_cases())
    print(render_markdown(report))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
