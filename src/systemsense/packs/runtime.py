"""Built-in process-isolated read-only probe registry."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, model_serializer, model_validator

from systemsense.domain.evidence import Sensitivity
from systemsense.domain.probes import (
    Privilege,
    ProbeLimits,
    ProbeManifest,
    ProbeOutputFieldV1,
    ProbeSafety,
    ProbeToolMetadataV1,
    SafetyClass,
    SelfWrite,
)
from systemsense.domain.time import UtcDateTime
from systemsense.orchestration.probes import (
    ProbeDefinition,
    ProbeRunner,
)


class NoParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class LiveSampleWindowParametersV1(BaseModel):
    """Optional bounded live interval for fixed passive sampling."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    window_start: UtcDateTime | None = None
    window_end: UtcDateTime | None = None

    @model_validator(mode="after")
    def paired_window(self) -> LiveSampleWindowParametersV1:
        if (self.window_start is None) != (self.window_end is None):
            raise ValueError("live sample window endpoints must be paired")
        if self.window_start is not None and self.window_end is not None:
            seconds = (self.window_end - self.window_start).total_seconds()
            if not 5 <= seconds <= 20:
                raise ValueError("live sample window must last 5 to 20 seconds")
        return self

    @model_serializer
    def serialize(self) -> dict[str, str]:
        if self.window_start is None or self.window_end is None:
            return {}
        return {
            "window_start": self.window_start.isoformat(),
            "window_end": self.window_end.isoformat(),
        }


class TargetPressureParametersV1(BaseModel):
    """Internal-only identity resolved from a future trusted case binding."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    pid: StrictInt = Field(gt=0)
    creation_time: UtcDateTime


def default_probe_runner() -> ProbeRunner:
    return ProbeRunner(definitions=default_probe_definitions())


def default_probe_definitions() -> tuple[ProbeDefinition, ...]:
    return (
        _definition(
            probe_id="core.system",
            category="core",
            question="What are the current Windows and hardware identity facts?",
            max_records=32,
        ),
        _definition(
            probe_id="core.resources",
            category="core",
            question="What are the current CPU, memory, and disk resource facts?",
            max_records=32,
            discovery_outputs=(("resources.cpu_percent", "%"), ("resources.memory.percent", "%")),
            discovery_cost_ms=1_500,
            discovery_resource="cpu",
            discovery_purpose=(
                "Check current system pressure before choosing a narrower measurement."
            ),
        ),
        _definition(
            probe_id="application.snapshot",
            category="application",
            question="What bounded processes and registered service states exist?",
            max_records=1024,
        ),
        _definition(
            probe_id="network.snapshot",
            category="network",
            question="What local adapters and endpoints exist?",
            max_records=512,
        ),
        _definition(
            probe_id="devices.snapshot",
            category="devices",
            question="What device problem codes and signed drivers exist?",
            max_records=256,
        ),
        _definition(
            probe_id="display.mode",
            category="devices",
            question=(
                "What is the calling desktop's current display mode and reported refresh rate?"
            ),
            max_records=1,
            discovery_outputs=(("display_mode.refresh_hz", "Hz"),),
            discovery_cost_ms=1_000,
            discovery_resource="cpu",
            discovery_purpose=(
                "Check whether the active desktop refresh setting limits visible FPS."
            ),
        ),
        _definition(
            probe_id="servicing.snapshot",
            category="servicing",
            question="What installed updates and reboot-pending facts exist?",
            max_records=256,
        ),
        _definition(
            probe_id="local_ai.snapshot",
            category="local_ai",
            question="What GPU, Python, package, and CUDA metadata exists?",
            max_records=512,
        ),
        _definition(
            probe_id="storage.snapshot",
            category="storage",
            question=(
                "What logical-volume, partition, physical-disk, and exposed reliability facts "
                "exist?"
            ),
            max_records=512,
            discovery_outputs=(("volumes", None), ("physical_disks", None), ("reliability", None)),
            discovery_cost_ms=7_000,
            discovery_resource="disk",
            discovery_purpose=(
                "Inspect volume and disk identity and exposed reliability without stress I/O."
            ),
        ),
        _definition(
            probe_id="network.configuration",
            category="network",
            question="What fixed local route, DNS, gateway, DHCP, and proxy configuration exists?",
            max_records=512,
        ),
        _definition(
            probe_id="network.connectivity",
            category="network",
            version=3,
            question=(
                "What are the current WLAN association, IP, gateway, DNS, and WinINet proxy "
                "states and recent fixed-channel WLAN failures?"
            ),
            max_records=128,
            discovery_outputs=(
                ("connectivity.proxy", None),
                ("connectivity.wifi_interfaces", None),
                ("connectivity.default_routes", None),
            ),
            discovery_cost_ms=5_000,
            discovery_resource="network",
            discovery_sensitivity=Sensitivity.PERSONAL,
            discovery_purpose="Distinguish local Wi-Fi, IP, route, and proxy configuration states.",
        ),
        _definition(
            probe_id="power.snapshot",
            category="power",
            question="What local power-source, active-scheme, and processor power facts exist?",
            max_records=128,
        ),
        _definition(
            probe_id="security.snapshot",
            category="security",
            question="What fixed antivirus, firewall-profile, and UAC configuration facts exist?",
            max_records=128,
        ),
        _definition(
            probe_id="incident.events",
            category="events",
            question=(
                "What recent fixed-profile hardware, storage, service, application, and power "
                "events exist?"
            ),
            max_records=256,
        ),
        _definition(
            probe_id="network.listeners",
            category="network",
            question=(
                "Which bounded local TCP LISTEN endpoints exist, and which stable process "
                "identities own them?"
            ),
            max_records=1024,
        ),
        _definition(
            probe_id="pressure.sample",
            category="performance",
            version=2,
            question=(
                "What CPU, memory, disk-I/O, and process pressure is passively measured across "
                "three samples with fixed one-second delays?"
            ),
            max_records=128,
            timeout_ms=20_000,
            input_model="LiveSampleWindowParametersV1",
            parameter_model=LiveSampleWindowParametersV1,
        ),
        _definition(
            probe_id="application.target_pressure",
            category="performance",
            question="What bounded counters belong to one previously bound process identity?",
            max_records=3,
            timeout_ms=20_000,
            input_model="TargetPressureParametersV1",
            parameter_model=TargetPressureParametersV1,
        ),
        _definition(
            probe_id="gpu.telemetry.sample",
            category="local_ai",
            version=2,
            question=(
                "What NVIDIA utilization, memory, temperature, power, and clock telemetry is "
                "passively observed across three fixed samples?"
            ),
            max_records=64,
            input_model="LiveSampleWindowParametersV1",
            parameter_model=LiveSampleWindowParametersV1,
        ),
    )


def _definition(
    *,
    probe_id: str,
    category: str,
    question: str,
    max_records: int,
    timeout_ms: int = 15_000,
    version: int = 1,
    input_model: str = "NoParametersV1",
    parameter_model: type[BaseModel] = NoParameters,
    discovery_outputs: tuple[tuple[str, str | None], ...] = (),
    discovery_cost_ms: int = 0,
    discovery_resource: Literal["cpu", "disk", "gpu", "network", "process"] = "cpu",
    discovery_sensitivity: Sensitivity = Sensitivity.SYSTEM_METADATA,
    discovery_purpose: str = "",
) -> ProbeDefinition:
    manifest = ProbeManifest(
        probe_id=probe_id,
        version=version,
        implementation_id=f"builtin.{probe_id}",
        question=question,
        safety=ProbeSafety(
            safety_class=SafetyClass.R1,
            privilege=Privilege.STANDARD,
            target_state_effect="none",
            self_writes=(
                SelfWrite.AUDIT_RECORD,
                SelfWrite.EVIDENCE_RECORD,
            ),
        ),
        input_model=input_model,
        limits=ProbeLimits(
            timeout_ms=timeout_ms,
            max_output_bytes=262_144,
            max_records=max_records,
        ),
        category=category,
    )
    discovery = (
        ProbeToolMetadataV1(
            probe_id=probe_id,
            probe_version=version,
            observable_ids=(probe_id,),
            parameter_fields=tuple(parameter_model.model_fields),
            supports_window=False,
            outputs=tuple(
                ProbeOutputFieldV1(name=name, unit=unit) for name, unit in discovery_outputs
            ),
            estimated_cost_ms=discovery_cost_ms,
            resource_class=discovery_resource,
            sensitivity=discovery_sensitivity,
            network_effect="none",
            io_intensity="light",
            target_state_effect="none",
            self_writes=manifest.safety.self_writes,
            purpose=discovery_purpose,
        )
        if discovery_outputs
        else None
    )
    return ProbeDefinition(
        manifest=manifest,
        parameter_model=parameter_model,
        handler=None,
        isolated=True,
        discovery=discovery,
    )
