"""Registered typed probe execution with deadlines and output limits."""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import Literal, cast

from pydantic import BaseModel, Field

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import ExecutionId, JsonValue
from systemsense.domain.probes import (
    MeasurementNeed,
    MeasurementWindow,
    ProbeInvocation,
    ProbeManifest,
)
from systemsense.domain.time import UtcDateTime, utc_now
from systemsense.orchestration.catalog import ProbeCatalog
from systemsense.orchestration.circuit_breaker import CircuitBreaker
from systemsense.orchestration.executor import (
    CancellationSignal,
    ProbeExecutor,
    WorkerExecutionStatus,
)
from systemsense.orchestration.invocations import MeasurementRegistry
from systemsense.orchestration.scheduler import HostWorkSlot
from systemsense.policy import PolicyDenied, ProbePolicy


class ProbeObservation(FrozenModel):
    summary: str = Field(min_length=1, max_length=1000)
    facts: dict[str, JsonValue]
    limitations: tuple[str, ...] = ()
    observed_at: UtcDateTime
    captured_at: UtcDateTime
    # "bounded_interval" means observed_at is a collection-end upper bound,
    # not the instant the underlying metric was physically sampled.
    time_quality: Literal["exact", "bounded_interval"] = "exact"


class ProbeRunStatus(StrEnum):
    OK = "ok"
    DENIED = "denied"
    UNAVAILABLE = "unavailable"
    FAILED = "failed"
    TIMED_OUT = "timed_out"
    CANCELLED = "cancelled"
    TRUNCATED = "truncated"


class ProbeRun(FrozenModel):
    execution_id: ExecutionId
    probe_id: str
    status: ProbeRunStatus
    started_at: UtcDateTime
    finished_at: UtcDateTime
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
    observables: frozenset[str] = frozenset()
    supports_window: bool = False

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
        measurement_registry: MeasurementRegistry | None = None,
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
        self._measurement_registry = measurement_registry
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

    def prepare_invocation(
        self,
        probe_id: str,
        parameters: dict[str, JsonValue],
        *,
        expected_version: int,
        target_handle: str | None = None,
        window: MeasurementWindow | None = None,
        observable: str | None = None,
    ) -> ProbeInvocation:
        """Bind a request to the current manifest and its registered parameter model."""
        authorized = self._policy.authorize(probe_id, parameters)
        if authorized.manifest.version != expected_version:
            raise PolicyDenied("probe manifest version changed")
        requested_observable = probe_id if observable is None else observable
        if requested_observable not in {probe_id, *self._definitions[probe_id].observables}:
            raise PolicyDenied("observable is not registered for probe")
        typed = authorized.parameters.model_dump(mode="python")
        if window is None:
            if typed.get("window_start") is not None or typed.get("window_end") is not None:
                raise PolicyDenied("window parameters require a measurement window")
        elif (
            not self._definitions[probe_id].supports_window
            or not isinstance(typed.get("window_start"), datetime)
            or not isinstance(typed.get("window_end"), datetime)
            or typed["window_start"] != window.start
            or typed["window_end"] != window.end
        ):
            raise PolicyDenied("probe does not support the requested measurement window")
        invocation = ProbeInvocation(
            probe_id=probe_id,
            probe_version=authorized.manifest.version,
            observable=requested_observable,
            target_handle=target_handle,
            parameters=cast("dict[str, JsonValue]", authorized.parameters.model_dump(mode="json")),
            window=window,
        )
        if (
            target_handle is None
            and self._measurement_registry is not None
            and self._measurement_registry.requires_target_handle(probe_id)
        ):
            raise PolicyDenied("probe requires a registered target handle")
        if target_handle is not None:
            if self._measurement_registry is None:
                raise PolicyDenied("target handle has no registered binding")
            resolved = self._measurement_registry.resolve(
                MeasurementNeed(
                    capability_id=probe_id,
                    observable=requested_observable,
                    target_handle=target_handle,
                    window=window,
                )
            )
            if not isinstance(resolved, ProbeInvocation) or resolved != invocation:
                raise PolicyDenied("target handle does not match registered parameters")
        return invocation

    def run_invocation(
        self,
        invocation: ProbeInvocation,
        *,
        deadline_at: UtcDateTime | None = None,
        cancellation: CancellationSignal | None = None,
        host_slot: HostWorkSlot | None = None,
    ) -> ProbeRun:
        """Revalidate a typed invocation before entering the existing policy boundary."""
        try:
            prepared = self.prepare_invocation(
                invocation.probe_id,
                invocation.parameters,
                expected_version=invocation.probe_version,
                target_handle=invocation.target_handle,
                window=invocation.window,
                observable=invocation.observable,
            )
            if prepared != invocation:
                raise PolicyDenied("probe invocation differs from registered parameters")
        except PolicyDenied as error:
            return self._result(
                ExecutionId.new(),
                invocation.probe_id,
                ProbeRunStatus.DENIED,
                time.perf_counter(),
                started_at=self._now(),
                error=str(error),
            )
        return self.run(
            invocation.probe_id,
            invocation.parameters,
            deadline_at=deadline_at,
            cancellation=cancellation,
            host_slot=host_slot,
        )

    def run(
        self,
        probe_id: str,
        parameters: dict[str, JsonValue],
        *,
        deadline_at: UtcDateTime | None = None,
        cancellation: CancellationSignal | None = None,
        host_slot: HostWorkSlot | None = None,
    ) -> ProbeRun:
        execution_id = ExecutionId.new()
        started_at = self._now()
        started = time.perf_counter()
        try:
            authorized = self._policy.authorize(probe_id, parameters)
        except PolicyDenied as error:
            return self._result(
                execution_id,
                probe_id,
                ProbeRunStatus.DENIED,
                started,
                started_at=started_at,
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
                started_at=started_at,
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
                deadline_at=deadline_at,
                cancellation=cancellation,
            )
            if worker.tree_exit == "unknown" and host_slot is not None:
                host_slot.quarantine("child_tree_exit_unverified")
            status = {
                WorkerExecutionStatus.OK: ProbeRunStatus.OK,
                WorkerExecutionStatus.DENIED: ProbeRunStatus.DENIED,
                WorkerExecutionStatus.FAILED: ProbeRunStatus.FAILED,
                WorkerExecutionStatus.TIMED_OUT: ProbeRunStatus.TIMED_OUT,
                WorkerExecutionStatus.CANCELLED: ProbeRunStatus.CANCELLED,
            }[worker.status]
            if status is not ProbeRunStatus.OK:
                return self._finished_result(
                    circuit,
                    execution_id,
                    probe_id,
                    status,
                    started,
                    started_at=started_at,
                    error=worker.error,
                )
            if not worker.evidence:
                return self._finished_result(
                    circuit,
                    execution_id,
                    probe_id,
                    ProbeRunStatus.FAILED,
                    started,
                    started_at=started_at,
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
                    started_at=started_at,
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
                    started_at=started_at,
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
                started_at=started_at,
                error="probe output exceeded registered limits",
            )
        json.loads(serialized)
        return self._finished_result(
            circuit,
            execution_id,
            probe_id,
            ProbeRunStatus.OK,
            started,
            started_at=started_at,
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
        started_at: UtcDateTime,
        observation: ProbeObservation | None = None,
        error: str | None = None,
    ) -> ProbeRun:
        if status is ProbeRunStatus.OK:
            circuit.record_success()
        elif status not in {ProbeRunStatus.DENIED, ProbeRunStatus.CANCELLED}:
            circuit.record_failure(at=self._now())
        return self._result(
            execution_id,
            probe_id,
            status,
            started,
            started_at=started_at,
            observation=observation,
            error=error,
        )

    def _result(
        self,
        execution_id: ExecutionId,
        probe_id: str,
        status: ProbeRunStatus,
        started: float,
        *,
        started_at: UtcDateTime,
        observation: ProbeObservation | None = None,
        error: str | None = None,
    ) -> ProbeRun:
        finished_at = self._now()
        if observation is not None:
            observation = observation.model_copy(
                update={
                    "observed_at": observation.observed_at,
                    "captured_at": finished_at,
                }
            )
        return ProbeRun(
            execution_id=execution_id,
            probe_id=probe_id,
            status=status,
            started_at=started_at,
            finished_at=finished_at,
            elapsed_ms=(time.perf_counter() - started) * 1000,
            observation=observation,
            error=error,
        )
