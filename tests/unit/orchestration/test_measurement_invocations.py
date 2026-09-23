import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import BaseModel, ConfigDict, Field

from systemsense.domain.probes import (
    MeasurementNeed,
    MeasurementWindow,
    Privilege,
    ProbeInvocation,
    ProbeLimits,
    ProbeManifest,
    ProbeSafety,
    SafetyClass,
)
from systemsense.orchestration.catalog import CatalogError
from systemsense.orchestration.invocations import (
    MeasurementRegistry,
    ObservabilityGap,
    RegisteredMeasurement,
    RegisteredTarget,
)
from systemsense.orchestration.scheduler import BoundedScheduler, Task, TaskContext, TaskStatus

NOW = datetime(2026, 9, 23, 12, 0, tzinfo=UTC)


class TargetParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    pid: int = Field(gt=0)
    window_start: datetime | None = None
    window_end: datetime | None = None


def _manifest(probe_id: str = "process.sample") -> ProbeManifest:
    return ProbeManifest(
        probe_id=probe_id,
        version=2,
        implementation_id=f"builtin.{probe_id}",
        question="What is the registered process sample?",
        safety=ProbeSafety(
            safety_class=SafetyClass.R1,
            privilege=Privilege.STANDARD,
            target_state_effect="none",
        ),
        input_model="TargetParametersV1",
        limits=ProbeLimits(timeout_ms=1000, max_output_bytes=1024, max_records=1),
        category="process",
    )


def test_measurement_registry_resolves_only_registered_capability_and_target() -> None:
    registry = MeasurementRegistry(
        (
            RegisteredMeasurement(
                manifest=_manifest(),
                parameter_model=TargetParameters,
                observable="cpu_percent",
                supports_window=True,
                targets=(RegisteredTarget(handle="process:a", parameters={"pid": 11}),),
            ),
        )
    )
    need = MeasurementNeed(
        capability_id="process.sample",
        observable="cpu_percent",
        target_handle="process:a",
        window=MeasurementWindow(start=NOW, end=NOW + timedelta(seconds=5)),
    )

    invocation = registry.resolve(need)

    assert isinstance(invocation, ProbeInvocation)
    assert invocation.probe_id == "process.sample"
    assert invocation.probe_version == 2
    assert invocation.parameters["pid"] == 11
    assert invocation.parameters["window_start"] == NOW.isoformat().replace("+00:00", "Z")
    assert isinstance(
        registry.resolve(need.model_copy(update={"capability_id": "missing.probe"})),
        ObservabilityGap,
    )
    assert isinstance(
        registry.resolve(need.model_copy(update={"target_handle": "process:missing"})),
        ObservabilityGap,
    )


def test_scheduler_deduplicates_only_identical_registered_invocations() -> None:
    registry = MeasurementRegistry(
        (
            RegisteredMeasurement(
                manifest=_manifest(),
                parameter_model=TargetParameters,
                observable="cpu_percent",
                supports_window=True,
                targets=(
                    RegisteredTarget(handle="process:a", parameters={"pid": 11}),
                    RegisteredTarget(handle="process:b", parameters={"pid": 12}),
                ),
            ),
        )
    )
    base = MeasurementNeed(
        capability_id="process.sample",
        observable="cpu_percent",
        target_handle="process:a",
        window=MeasurementWindow(start=NOW, end=NOW + timedelta(seconds=5)),
    )
    invocations = (
        registry.resolve(base),
        registry.resolve(base),
        registry.resolve(base.model_copy(update={"target_handle": "process:b"})),
        registry.resolve(
            base.model_copy(
                update={"window": MeasurementWindow(start=NOW, end=NOW + timedelta(seconds=6))}
            )
        ),
    )
    assert all(isinstance(item, ProbeInvocation) for item in invocations)
    executed: list[str] = []

    def collect(context: TaskContext) -> str:
        task_id = context.task_id
        executed.append(task_id)
        return task_id

    results = asyncio.run(
        BoundedScheduler().run(
            tuple(
                Task(task_id=str(index), action=collect, invocation=invocation)
                for index, invocation in enumerate(invocations)
                if isinstance(invocation, ProbeInvocation)
            )
        )
    )

    assert [item.status for item in results].count(TaskStatus.DEDUPLICATED) == 1
    assert results[1].deduplicated_from == results[0].task_id
    assert results[1].value == results[0].value
    assert len(executed) == 3


def test_measurement_registry_rejects_unregistered_command_parameter() -> None:
    class CommandParameters(BaseModel):
        model_config = ConfigDict(extra="forbid", frozen=True)
        command: str

    with pytest.raises(CatalogError, match="forbidden parameter field"):
        MeasurementRegistry(
            (
                RegisteredMeasurement(
                    manifest=_manifest(),
                    parameter_model=CommandParameters,
                    observable="cpu_percent",
                ),
            )
        )
