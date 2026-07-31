"""Frozen balanced arm-order schedules."""

import random

from pydantic import Field

from benchmarks.ab.contracts import (
    ExperimentArm,
    ExperimentModel,
    canonical_sha256,
)


class ScheduleEntry(ExperimentModel):
    sequence: int = Field(ge=1)
    pair_id: str
    scenario_id: str
    first_arm: ExperimentArm
    second_arm: ExperimentArm


class ExperimentSchedule(ExperimentModel):
    schema_version: int = 1
    random_seed: int
    repetitions: int = Field(ge=1)
    entries: tuple[ScheduleEntry, ...] = Field(min_length=1)
    schedule_hash: str


def create_balanced_schedule(
    *,
    scenario_ids: tuple[str, ...],
    repetitions: int,
    random_seed: int,
) -> ExperimentSchedule:
    if not scenario_ids or len(set(scenario_ids)) != len(scenario_ids):
        raise ValueError("scenario_ids must be non-empty and unique")
    if repetitions < 1:
        raise ValueError("repetitions must be positive")
    generator = random.Random(random_seed)
    pairs = [
        (scenario_id, repetition)
        for scenario_id in sorted(scenario_ids)
        for repetition in range(1, repetitions + 1)
    ]
    generator.shuffle(pairs)
    first_arms = [
        ExperimentArm.BASELINE if index % 2 == 0 else ExperimentArm.SYSTEMSENSE
        for index in range(len(pairs))
    ]
    generator.shuffle(first_arms)
    entries = tuple(
        ScheduleEntry(
            sequence=index,
            pair_id=f"{scenario_id}.r{repetition:02d}",
            scenario_id=scenario_id,
            first_arm=first_arm,
            second_arm=(
                ExperimentArm.SYSTEMSENSE
                if first_arm is ExperimentArm.BASELINE
                else ExperimentArm.BASELINE
            ),
        )
        for index, ((scenario_id, repetition), first_arm) in enumerate(
            zip(pairs, first_arms, strict=True),
            start=1,
        )
    )
    payload = {
        "random_seed": random_seed,
        "repetitions": repetitions,
        "entries": [entry.model_dump(mode="json") for entry in entries],
    }
    return ExperimentSchedule(
        random_seed=random_seed,
        repetitions=repetitions,
        entries=entries,
        schedule_hash=canonical_sha256(payload),
    )
