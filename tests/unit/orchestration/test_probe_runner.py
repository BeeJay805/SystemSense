import os
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from typing import cast

import pytest
from pydantic import BaseModel, ConfigDict

from systemsense.domain.ids import JsonValue
from systemsense.domain.probes import (
    MeasurementWindow,
    Privilege,
    ProbeLimits,
    ProbeManifest,
    ProbeSafety,
    SafetyClass,
    SelfWrite,
)
from systemsense.orchestration.probes import (
    ProbeDefinition,
    ProbeObservation,
    ProbeRunner,
    ProbeRunStatus,
)
from systemsense.orchestration.scheduler import HostWorkArbiter, ResourceBudget, ResourceClass
from systemsense.policy import PolicyDenied

_NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)
_STARTED = _NOW + timedelta(minutes=10)
_FINISHED = _STARTED + timedelta(seconds=2)
_SOURCE_OBSERVED = _NOW - timedelta(minutes=2)


class NoParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object containment")
def test_isolated_runner_quarantines_slot_when_job_exit_is_unverified(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from systemsense.orchestration.windows_probe_job import WindowsProbeJob

    class EchoParameters(BaseModel):
        model_config = ConfigDict(extra="forbid", frozen=True)
        message: str

    def deny_exit_proof(_job: WindowsProbeJob, _timeout_seconds: float) -> bool:
        raise PermissionError("job accounting unavailable")

    monkeypatch.setattr(WindowsProbeJob, "wait_until_empty", deny_exit_proof)

    def unused_handler(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        raise AssertionError("isolated probes must not use an in-process handler")

    definition = _definition(unused_handler)
    definition = replace(
        definition,
        manifest=definition.manifest.model_copy(
            update={
                "probe_id": "fixture.echo",
                "implementation_id": "builtin.fixture.echo",
                "input_model": "EchoParameters",
            }
        ),
        parameter_model=EchoParameters,
        handler=None,
        isolated=True,
    )
    arbiter = HostWorkArbiter(ResourceBudget(global_limit=1))
    slot = arbiter.try_acquire("case", "probe", ResourceClass.PROCESS, 0)
    assert slot is not None
    runner = ProbeRunner(definitions=(definition,))
    result = runner.run("fixture.echo", {"message": "x"}, host_slot=slot)
    slot.release()

    assert result.status is ProbeRunStatus.FAILED
    assert result.tree_exit_status == "unknown"
    assert arbiter.quarantined_count == 1
    assert arbiter.try_acquire("other", "probe", ResourceClass.PROCESS, 0) is None


def test_runner_prepares_and_executes_exact_registered_typed_invocation() -> None:
    calls: list[dict[str, JsonValue]] = []

    def collect(parameters: dict[str, JsonValue]) -> ProbeObservation:
        calls.append(parameters)
        return ProbeObservation(
            summary="sample", facts={"value": 1}, observed_at=_NOW, captured_at=_NOW
        )

    runner = ProbeRunner(definitions=(_definition(collect),))
    invocation = runner.prepare_invocation("fixture.snapshot", {}, expected_version=1)

    assert invocation.probe_version == 1
    assert invocation.parameters == {}
    completed = runner.run_invocation(invocation)
    assert completed.status is ProbeRunStatus.OK
    assert completed.tree_exit_status == "not_tracked"
    assert calls == [{}]
    with pytest.raises(PolicyDenied, match="version"):
        runner.prepare_invocation("fixture.snapshot", {}, expected_version=2)
    with pytest.raises(PolicyDenied, match="unknown"):
        runner.prepare_invocation("missing.snapshot", {}, expected_version=1)
    with pytest.raises(PolicyDenied, match="parameters"):
        runner.prepare_invocation("fixture.snapshot", {"command": "whoami"}, expected_version=1)
    stale = invocation.model_copy(update={"probe_version": 2})
    assert runner.run_invocation(stale).status is ProbeRunStatus.DENIED
    unregistered_observable = invocation.model_copy(update={"observable": "arbitrary.answer"})
    assert runner.run_invocation(unregistered_observable).status is ProbeRunStatus.DENIED
    assert calls == [{}]


def test_runner_requires_explicit_window_support_and_matching_window_fields() -> None:
    class WindowParameters(BaseModel):
        model_config = ConfigDict(extra="forbid", frozen=True)
        window_start: datetime | None = None
        window_end: datetime | None = None

    def collect(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        return ProbeObservation(summary="sample", facts={}, observed_at=_NOW, captured_at=_NOW)

    definition = replace(_definition(collect), parameter_model=WindowParameters)
    runner = ProbeRunner(definitions=(definition,))
    window = MeasurementWindow(start=_NOW, end=_NOW + timedelta(seconds=1))
    parameters: dict[str, JsonValue] = {
        "window_start": window.start.isoformat(),
        "window_end": window.end.isoformat(),
    }

    with pytest.raises(PolicyDenied, match="measurement window"):
        runner.prepare_invocation("fixture.snapshot", parameters, expected_version=1)
    with pytest.raises(PolicyDenied, match="does not support"):
        runner.prepare_invocation("fixture.snapshot", parameters, expected_version=1, window=window)


def test_probe_observation_requires_observation_and_capture_times() -> None:
    with pytest.raises(ValueError):
        ProbeObservation.model_validate({"summary": "untimed", "facts": {}})


def _definition(
    handler: object,
    *,
    max_output_bytes: int = 1024,
) -> ProbeDefinition:
    from systemsense.orchestration.probes import ProbeHandler

    assert callable(handler)
    return ProbeDefinition(
        manifest=ProbeManifest(
            probe_id="fixture.snapshot",
            version=1,
            implementation_id="builtin.fixture.snapshot",
            question="What fixture state exists?",
            safety=ProbeSafety(
                safety_class=SafetyClass.R1,
                privilege=Privilege.STANDARD,
                target_state_effect="none",
                self_writes=(SelfWrite.EVIDENCE_RECORD,),
            ),
            input_model="NoParametersV1",
            limits=ProbeLimits(
                timeout_ms=100,
                max_output_bytes=max_output_bytes,
                max_records=8,
            ),
            category="fixture",
        ),
        parameter_model=NoParameters,
        handler=cast("ProbeHandler", handler),
        isolated=False,
    )


def test_repeated_failure_opens_probe_circuit_until_cooldown() -> None:
    current = [_NOW]
    should_fail = [True]
    calls = [0]

    def collect(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        calls[0] += 1
        if should_fail[0]:
            raise RuntimeError("fixture failed")
        return ProbeObservation(
            summary="fixture recovered",
            facts={"value": 1},
            observed_at=_NOW,
            captured_at=_NOW,
        )

    runner = ProbeRunner(
        definitions=(_definition(collect),),
        now=lambda: current[0],
        circuit_failure_threshold=1,
        circuit_cooldown=timedelta(seconds=30),
    )

    failed = runner.run("fixture.snapshot", {})
    suppressed = runner.run("fixture.snapshot", {})
    should_fail[0] = False
    current[0] += timedelta(seconds=30)
    recovered = runner.run("fixture.snapshot", {})

    assert failed.status is ProbeRunStatus.FAILED
    assert suppressed.status is ProbeRunStatus.UNAVAILABLE
    assert suppressed.error == "probe circuit is open"
    assert recovered.status is ProbeRunStatus.OK
    assert calls == [2]


def test_probe_runner_truncates_oversized_normalized_output() -> None:
    def collect(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        return ProbeObservation(
            summary="large fixture",
            facts={"value": "x" * 200},
            observed_at=_NOW,
            captured_at=_NOW,
        )

    result = ProbeRunner(
        definitions=(_definition(collect, max_output_bytes=100),),
    ).run("fixture.snapshot", {})

    assert result.status is ProbeRunStatus.TRUNCATED
    assert result.observation is None
    assert result.error == "probe output exceeded registered limits"


def test_probe_runner_records_wall_times_and_preserves_source_observation_time() -> None:
    clock_values = iter((_STARTED, _STARTED, _FINISHED))

    def collect(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        return ProbeObservation(
            summary="delayed event",
            facts={"value": 1},
            observed_at=_SOURCE_OBSERVED,
            captured_at=_NOW,
        )

    result = ProbeRunner(
        definitions=(_definition(collect),),
        now=lambda: next(clock_values),
    ).run("fixture.snapshot", {})

    assert result.started_at == _STARTED
    assert result.finished_at == _FINISHED
    assert result.observation is not None
    assert result.observation.observed_at == _SOURCE_OBSERVED
    assert result.observation.captured_at == _FINISHED
