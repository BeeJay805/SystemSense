from datetime import UTC, datetime, timedelta
from typing import cast

from pydantic import BaseModel, ConfigDict

from systemsense.domain.ids import JsonValue
from systemsense.domain.probes import (
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

_NOW = datetime(2026, 7, 30, 12, 0, tzinfo=UTC)


class NoParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


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
        return ProbeObservation(summary="fixture recovered", facts={"value": 1})

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
        return ProbeObservation(summary="large fixture", facts={"value": "x" * 200})

    result = ProbeRunner(
        definitions=(_definition(collect, max_output_bytes=100),),
    ).run("fixture.snapshot", {})

    assert result.status is ProbeRunStatus.TRUNCATED
    assert result.observation is None
    assert result.error == "probe output exceeded registered limits"
