"""Local admission of typed measurement needs to registered read-only probes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import cast

from pydantic import BaseModel, Field

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.ids import JsonValue
from systemsense.domain.probes import (
    MeasurementNeed,
    Privilege,
    ProbeInvocation,
    ProbeManifest,
    SafetyClass,
)
from systemsense.orchestration.catalog import ProbeCatalog


class ObservabilityGap(FrozenModel):
    need: MeasurementNeed
    reason: str = Field(min_length=1, max_length=1000)


@dataclass(frozen=True, slots=True)
class RegisteredTarget:
    handle: str
    parameters: dict[str, JsonValue]


@dataclass(frozen=True, slots=True)
class RegisteredMeasurement:
    manifest: ProbeManifest
    parameter_model: type[BaseModel]
    observable: str
    supports_window: bool = False
    targets: tuple[RegisteredTarget, ...] = ()


class MeasurementRegistry:
    """Resolve only locally admitted capabilities and opaque target handles."""

    def __init__(self, registrations: tuple[RegisteredMeasurement, ...]) -> None:
        catalog = ProbeCatalog(
            trusted_implementation_ids=frozenset(
                item.manifest.implementation_id for item in registrations
            )
        )
        self._registrations: dict[str, RegisteredMeasurement] = {}
        self._targets: dict[str, dict[str, dict[str, JsonValue]]] = {}
        for item in registrations:
            manifest = item.manifest
            if (
                manifest.safety.safety_class not in {SafetyClass.R0, SafetyClass.R1}
                or manifest.safety.privilege is not Privilege.STANDARD
                or manifest.safety.target_state_effect != "none"
                or manifest.safety.outbound_network
            ):
                raise ValueError("measurement capabilities must be standard-privilege read-only")
            if not item.observable or len(item.observable) > 120:
                raise ValueError("registered observable must be bounded")
            if item.supports_window and not {"window_start", "window_end"}.issubset(
                item.parameter_model.model_fields
            ):
                raise ValueError("window-capable probes require typed window parameters")
            catalog.register(manifest, item.parameter_model)
            self._registrations[manifest.probe_id] = item
            targets: dict[str, dict[str, JsonValue]] = {}
            for target in item.targets:
                if not target.handle or target.handle in targets:
                    raise ValueError("target handles must be nonempty and unique")
                parsed = item.parameter_model.model_validate(target.parameters)
                targets[target.handle] = cast(
                    "dict[str, JsonValue]", parsed.model_dump(mode="json")
                )
            self._targets[manifest.probe_id] = targets

    def requires_target_handle(self, capability_id: str) -> bool:
        """Whether this registered capability admits only registry-issued targets."""
        registration = self._registrations.get(capability_id)
        return registration is not None and bool(registration.targets)

    def resolve(self, need: MeasurementNeed) -> ProbeInvocation | ObservabilityGap:
        registration = self._registrations.get(need.capability_id)
        if registration is None:
            return ObservabilityGap(need=need, reason="capability is not registered")
        if need.observable != registration.observable:
            return ObservabilityGap(need=need, reason="observable is not registered for capability")
        if need.window is not None and not registration.supports_window:
            return ObservabilityGap(need=need, reason="measurement window is unsupported")
        if need.target_handle is not None:
            parameters = self._targets[need.capability_id].get(need.target_handle)
            if parameters is None:
                return ObservabilityGap(need=need, reason="target handle is not registered")
        else:
            try:
                parsed = registration.parameter_model.model_validate({})
            except ValueError:
                return ObservabilityGap(need=need, reason="capability requires a registered target")
            parameters = cast("dict[str, JsonValue]", parsed.model_dump(mode="json"))
        if need.window is not None:
            parameters = {
                **parameters,
                "window_start": need.window.start.isoformat(),
                "window_end": need.window.end.isoformat(),
            }
            parsed = registration.parameter_model.model_validate(parameters)
            parameters = cast("dict[str, JsonValue]", parsed.model_dump(mode="json"))
        return ProbeInvocation(
            probe_id=registration.manifest.probe_id,
            probe_version=registration.manifest.version,
            observable=need.observable,
            target_handle=need.target_handle,
            parameters=parameters,
            window=need.window,
        )
