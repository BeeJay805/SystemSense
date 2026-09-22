from benchmarks.local_episodes import run_local_episode_benchmark
from systemsense.evaluation.models import MeasurementSource, QualityLabel


def test_local_episode_benchmark_runs_five_synthetic_coordinator_journeys() -> None:
    suite = run_local_episode_benchmark()
    by_id = {episode.scenario_id: episode for episode in suite.episodes}

    assert set(by_id) == {
        "synthetic.device-problem",
        "synthetic.invalid-provider-output",
        "synthetic.memory-pressure",
        "synthetic.missing-telemetry",
        "synthetic.pending-restart",
    }
    assert all(
        episode.measurement_source is MeasurementSource.SIMULATION for episode in suite.episodes
    )
    assert all(episode.synthetic for episode in suite.episodes)
    assert all(episode.elapsed_ms > 0 for episode in suite.episodes)
    assert all(episode.review.quality_label is QualityLabel.UNKNOWN for episode in suite.episodes)
    assert {
        (episode.budget_ms, episode.max_rounds, episode.max_probes) for episode in suite.episodes
    } == {(2000, 2, 2)}
    assert by_id["synthetic.missing-telemetry"].probe_attempts.failures == 1
    assert by_id["synthetic.invalid-provider-output"].decision.failures >= 1
