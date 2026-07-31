"""Registered typed probe execution with deadlines and output limits."""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from enum import StrEnum
from typing import cast

from pydantic import BaseModel, Field

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import ExecutionId, JsonValue
from systemsense.domain.probes import ProbeManifest
from systemsense.domain.time import UtcDateTime, utc_now
from systemsense.orchestration.catalog import ProbeCatalog
from systemsense.orchestration.circuit_breaker import CircuitBreaker
from systemsense.orchestration.executor import (
    ProbeExecutor,
    WorkerExecutionStatus,
)
from systemsense.policy import PolicyDenied, ProbePolicy


class ProbeObservation(FrozenModel):
    summary: str = Field(min_length=1, max_length=1000)
    facts: dict[str, JsonValue]
    limitations: tuple[str, ...] = ()


class ProbeRunStatus(StrEnum):
    OK = "ok"
    DENIED = "denied"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    TRUNCATED = "truncated"


class ProbeRun(FrozenModel):
    execution_id: ExecutionId
    probe_id: str
    status: ProbeRunStatus
    elapsed_ms: float = Field(ge=0)
    observation: ProbeObservation | None = None
    error: str | None = Field(default=None, max_length=4096)


type ProbeHandler = Callable[[dict[str, JsonValue]], ProbeObservation]


@dataclass(frozen=True, slots=True)
class ProbeDefinition:
    manifest: ProbeManifest
    parameter_model: type[BaseModel]
    handler: ProbeHandler | None
    isolated: bool

    def __post_init__(self) -> None:
        if self.isolated == (self.handler is not None):
            raise ValueError("isolated probes cannot have an in-process handler")


class ProbeRunner:
    def __init__(
        self,
        *,
        definitions: tuple[ProbeDefinition, ...],
        executor: ProbeExecutor | None = None,
        now: Callable[[], UtcDateTime] = utc_now,
        circuit_failure_threshold: int = 3,
        circuit_cooldown: timedelta = timedelta(minutes=5),
    ) -> None:
        implementation_ids = frozenset(
            definition.manifest.implementation_id for definition in definitions
        )
        catalog = ProbeCatalog(trusted_implementation_ids=implementation_ids)
        self._definitions: dict[str, ProbeDefinition] = {}
        for definition in definitions:
            probe_id = definition.manifest.probe_id
            if probe_id in self._definitions:
                raise ValueError(f"duplicate probe definition: {probe_id}")
            catalog.register(definition.manifest, definition.parameter_model)
            self._definitions[probe_id] = definition
        self._policy = ProbePolicy(catalog)
        self._executor = executor or ProbeExecutor()
        self._now = now
        self._circuits = {
            probe_id: CircuitBreaker(
                failure_threshold=circuit_failure_threshold,
                cooldown=circuit_cooldown,
            )
            for probe_id in self._definitions
        }

    @property
    def probe_ids(self) -> frozenset[str]:
        return frozenset(self._definitions)

    @property
    def isolated_probe_ids(self) -> frozenset[str]:
        return frozenset(
            probe_id for probe_id, definition in self._definitions.items() if definition.isolated
        )

    def manifest(self, probe_id: str) -> ProbeManifest | None:
        definition = self._definitions.get(probe_id)
        return None if definition is None else definition.manifest

    def run(
        self,
        probe_id: str,
        parameters: dict[str, JsonValue],
    ) -> ProbeRun:
        execution_id = ExecutionId.new()
        started = time.perf_counter()
        try:
            authorized = self._policy.authorize(probe_id, parameters)
        except PolicyDenied as error:
            return self._result(
                execution_id,
                probe_id,
                ProbeRunStatus.DENIED,
                started,
                error=str(error),
            )

        definition = self._definitions[probe_id]
        circuit = self._circuits[probe_id]
        if not circuit.allow(at=self._now()):
            return self._result(
                execution_id,
                probe_id,
                ProbeRunStatus.UNAVAILABLE,
                started,
                error="probe circuit is open",
            )
        typed_parameters = cast(
            "dict[str, JsonValue]",
            authorized.parameters.model_dump(mode="json"),
        )
        if definition.isolated:
            worker = self._executor.execute(
                probe_id,
                typed_parameters,
                timeout_ms=definition.manifest.limits.timeout_ms,
            )
            status = {
                WorkerExecutionStatus.OK: ProbeRunStatus.OK,
                WorkerExecutionStatus.DENIED: ProbeRunStatus.DENIED,
                WorkerExecutionStatus.FAILED: ProbeRunStatus.FAILED,
                WorkerExecutionStatus.TIMED_OUT: ProbeRunStatus.TIMED_OUT,
            }[worker.status]
            if status is not ProbeRunStatus.OK:
                return self._finished_result(
                    circuit,
                    execution_id,
                    probe_id,
                    status,
                    started,
                    error=worker.error,
                )
            if not worker.evidence:
                return self._finished_result(
                    circuit,
                    execution_id,
                    probe_id,
                    ProbeRunStatus.FAILED,
                    started,
                    error="worker returned no evidence",
                )
            try:
                observation = ProbeObservation.model_validate(worker.evidence[0])
            except ValueError as error:
                return self._finished_result(
                    circuit,
                    execution_id,
                    probe_id,
                    ProbeRunStatus.FAILED,
                    started,
                    error=f"worker evidence validation failed: {error}",
                )
        else:
            assert definition.handler is not None
            try:
                observation = definition.handler(typed_parameters)
            except Exception as error:
                return self._finished_result(
                    circuit,
                    execution_id,
                    probe_id,
                    ProbeRunStatus.FAILED,
                    started,
                    error=f"{type(error).__name__}: {error}",
                )

        serialized = observation.model_dump_json()
        record_count = sum(
            len(value) if isinstance(value, list) else 1 for value in observation.facts.values()
        )
        if (
            len(serialized.encode("utf-8")) > definition.manifest.limits.max_output_bytes
            or record_count > definition.manifest.limits.max_records
        ):
            return self._finished_result(
                circuit,
                execution_id,
                probe_id,
                ProbeRunStatus.TRUNCATED,
                started,
                error="probe output exceeded registered limits",
            )
        json.loads(serialized)
        return self._finished_result(
            circuit,
            execution_id,
            probe_id,
            ProbeRunStatus.OK,
            started,
            observation=observation,
        )

    def _finished_result(
        self,
        circuit: CircuitBreaker,
        execution_id: ExecutionId,
        probe_id: str,
        status: ProbeRunStatus,
        started: float,
        *,
        observation: ProbeObservation | None = None,
        error: str | None = None,
    ) -> ProbeRun:
        if status is ProbeRunStatus.OK:
            circuit.record_success()
        elif status is not ProbeRunStatus.DENIED:
            circuit.record_failure(at=self._now())
        return self._result(
            execution_id,
            probe_id,
            status,
            started,
            observation=observation,
            error=error,
        )

    @staticmethod
    def _result(
        execution_id: ExecutionId,
        probe_id: str,
        status: ProbeRunStatus,
        started: float,
        *,
        observation: ProbeObservation | None = None,
        error: str | None = None,
    ) -> ProbeRun:
        return ProbeRun(
            execution_id=execution_id,
            probe_id=probe_id,
            status=status,
            elapsed_ms=(time.perf_counter() - started) * 1000,
            observation=observation,
            error=error,
        )
