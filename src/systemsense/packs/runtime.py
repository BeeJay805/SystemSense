"""Built-in six-family probe registry and cheap local handlers."""

from __future__ import annotations

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
from systemsense.domain.time import utc_now
from systemsense.orchestration.probes import (
    ProbeDefinition,
    ProbeObservation,
    ProbeRunner,
)
from systemsense.packs.application.processes import PsutilProcessBackend
from systemsense.packs.application.services import PsutilServiceBackend
from systemsense.packs.core.resources import PsutilResourceBackend, collect_resources
from systemsense.packs.core.system import PsutilSystemBackend, collect_system_identity
from systemsense.packs.network.adapters import PsutilAdapterBackend
from systemsense.packs.network.connections import PsutilNetworkConnectionBackend


class NoParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def default_probe_runner() -> ProbeRunner:
    return ProbeRunner(definitions=default_probe_definitions())


def default_probe_definitions() -> tuple[ProbeDefinition, ...]:
    return (
        _definition(
            probe_id="core.system",
            category="core",
            question="What are the current Windows and hardware identity facts?",
            handler=_core_system,
            max_records=32,
        ),
        _definition(
            probe_id="core.resources",
            category="core",
            question="What are the current CPU, memory, and disk resource facts?",
            handler=_core_resources,
            max_records=32,
        ),
        _definition(
            probe_id="application.snapshot",
            category="application",
            question="What bounded processes and registered service states exist?",
            handler=_application_snapshot,
            max_records=256,
        ),
        _definition(
            probe_id="network.snapshot",
            category="network",
            question="What local adapters and endpoints exist?",
            handler=_network_snapshot,
            max_records=512,
        ),
        _definition(
            probe_id="devices.snapshot",
            category="devices",
            question="What device problem codes and signed drivers exist?",
            handler=None,
            max_records=256,
            isolated=True,
        ),
        _definition(
            probe_id="servicing.snapshot",
            category="servicing",
            question="What installed updates and reboot-pending facts exist?",
            handler=None,
            max_records=256,
            isolated=True,
        ),
        _definition(
            probe_id="local_ai.snapshot",
            category="local_ai",
            question="What GPU, Python, package, and CUDA metadata exists?",
            handler=None,
            max_records=512,
            isolated=True,
        ),
    )


def _definition(
    *,
    probe_id: str,
    category: str,
    question: str,
    handler: object,
    max_records: int,
    isolated: bool = False,
) -> ProbeDefinition:
    from systemsense.orchestration.probes import ProbeHandler

    typed_handler = None if handler is None else cast("ProbeHandler", handler)
    return ProbeDefinition(
        manifest=ProbeManifest(
            probe_id=probe_id,
            version=1,
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
            input_model="NoParametersV1",
            limits=ProbeLimits(
                timeout_ms=15_000,
                max_output_bytes=262_144,
                max_records=max_records,
            ),
            category=category,
        ),
        parameter_model=NoParameters,
        handler=typed_handler,
        isolated=isolated,
    )


def _core_system(_parameters: dict[str, JsonValue]) -> ProbeObservation:
    observation = collect_system_identity(PsutilSystemBackend(), captured_at=utc_now())
    return ProbeObservation(
        summary=(
            f"{observation.os_name} {observation.windows_build} on "
            f"{observation.architecture} with {observation.logical_cpu_count} logical CPUs"
        ),
        facts={"system": cast("JsonValue", observation.model_dump(mode="json"))},
    )


def _core_resources(_parameters: dict[str, JsonValue]) -> ProbeObservation:
    observation = collect_resources(PsutilResourceBackend(), captured_at=utc_now())
    return ProbeObservation(
        summary=(
            f"CPU {observation.cpu_percent:.1f}%; memory {observation.memory.percent:.1f}% used"
        ),
        facts={"resources": cast("JsonValue", observation.model_dump(mode="json"))},
    )


def _application_snapshot(_parameters: dict[str, JsonValue]) -> ProbeObservation:
    processes = PsutilProcessBackend().snapshots(max_records=128)
    service_names = frozenset({"AudioSrv", "Dnscache", "EventLog", "wuauserv"})
    limitations: list[str] = []
    try:
        services = PsutilServiceBackend().observations(service_names)
    except Exception as error:
        services = ()
        limitations.append(f"service snapshot unavailable: {type(error).__name__}")
    return ProbeObservation(
        summary=f"Observed {len(processes)} processes and {len(services)} registered services",
        facts={
            "processes": cast(
                "JsonValue",
                [process.model_dump(mode="json") for process in processes],
            ),
            "services": cast(
                "JsonValue",
                [service.model_dump(mode="json") for service in services],
            ),
        },
        limitations=tuple(limitations),
    )


def _network_snapshot(_parameters: dict[str, JsonValue]) -> ProbeObservation:
    adapters = PsutilAdapterBackend().adapters()
    connections = PsutilNetworkConnectionBackend().connections(max_records=128)
    return ProbeObservation(
        summary=(
            f"Observed {len(adapters)} adapters and {len(connections)} bounded local endpoints"
        ),
        facts={
            "adapters": cast(
                "JsonValue",
                [adapter.model_dump(mode="json") for adapter in adapters],
            ),
            "connections": cast(
                "JsonValue",
                [connection.model_dump(mode="json") for connection in connections],
            ),
        },
        limitations=("route and DNS registry snapshots are not included in this probe",),
    )
