from benchmarks.ab.contracts import ExperimentArm
from benchmarks.ab.schedule import create_balanced_schedule


def test_schedule_is_seeded_balanced_and_contains_both_arm_orders() -> None:
    first = create_balanced_schedule(
        scenario_ids=("application.a", "network.b"),
        repetitions=3,
        random_seed=42,
    )
    second = create_balanced_schedule(
        scenario_ids=("application.a", "network.b"),
        repetitions=3,
        random_seed=42,
    )

    assert first == second
    assert len(first.entries) == 6
    baseline_first = sum(entry.first_arm is ExperimentArm.BASELINE for entry in first.entries)
    assert baseline_first == 3
    assert {entry.first_arm for entry in first.entries} == {
        ExperimentArm.BASELINE,
        ExperimentArm.SYSTEMSENSE,
    }
    assert len(first.schedule_hash) == 64
