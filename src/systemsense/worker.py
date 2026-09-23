"""One-request structured worker for fixed diagnostic probe IDs."""

import json
import os
import sys
import time
from collections.abc import Callable
from typing import cast

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from systemsense.domain.ids import JsonValue
from systemsense.domain.time import utc_now


class WorkerRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    probe_id: str
    parameters: dict[str, JsonValue]


class _EchoParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    message: str = Field(max_length=1000)


class _NoParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")


class _DelayParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    delay_ms: int = Field(ge=0, le=10_000)


class _OutputParameters(BaseModel):
    model_config = ConfigDict(extra="forbid")

    size: int = Field(ge=0, le=5_000_000)


def _emit(payload: dict[str, JsonValue]) -> None:
    print(
        json.dumps(
            {"type": "evidence", "payload": payload},
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ),
        flush=True,
    )


def _echo(parameters: dict[str, JsonValue]) -> None:
    typed = _EchoParameters.model_validate(parameters)
    _emit({"message": typed.message})


def _environment(parameters: dict[str, JsonValue]) -> None:
    _NoParameters.model_validate(parameters)
    keys: list[JsonValue] = list(sorted(os.environ))
    _emit({"keys": keys})


def _partial_then_sleep(parameters: dict[str, JsonValue]) -> None:
    typed = _DelayParameters.model_validate(parameters)
    _emit({"stage": "started"})
    time.sleep(typed.delay_ms / 1000)


def _false_success(parameters: dict[str, JsonValue]) -> None:
    _NoParameters.model_validate(parameters)
    print(json.dumps({"type": "result", "status": "ok"}), flush=True)
    raise SystemExit(7)


def _unbounded_output(parameters: dict[str, JsonValue]) -> None:
    typed = _OutputParameters.model_validate(parameters)
    _emit({"value": "x" * typed.size})


def _core_system(parameters: dict[str, JsonValue]) -> None:
    from systemsense.packs.core.system import PsutilSystemBackend, collect_system_identity

    _NoParameters.model_validate(parameters)
    observed_at = utc_now()
    observation = collect_system_identity(PsutilSystemBackend(), captured_at=observed_at)
    _emit(
        {
            "summary": (
                f"{observation.os_name} {observation.windows_build} on "
                f"{observation.architecture} with {observation.logical_cpu_count} logical CPUs"
            ),
            "observed_at": observation.captured_at.isoformat(),
            "captured_at": observation.captured_at.isoformat(),
            "facts": {"system": cast("JsonValue", observation.model_dump(mode="json"))},
            "limitations": [],
        }
    )


def _core_resources(parameters: dict[str, JsonValue]) -> None:
    from systemsense.packs.core.resources import PsutilResourceBackend, collect_resources

    _NoParameters.model_validate(parameters)
    observation = collect_resources(PsutilResourceBackend())
    _emit(
        {
            "summary": (
                f"CPU {observation.cpu_percent:.1f}%; memory {observation.memory.percent:.1f}% used"
            ),
            "observed_at": observation.captured_at.isoformat(),
            "captured_at": observation.captured_at.isoformat(),
            "facts": {"resources": cast("JsonValue", observation.model_dump(mode="json"))},
            "limitations": list(observation.limitations),
        }
    )


def _application_snapshot(parameters: dict[str, JsonValue]) -> None:
    from systemsense.platform.windows.deep_collectors import collect_application_topology

    _NoParameters.model_validate(parameters)
    observation = collect_application_topology()
    _emit(
        {
            "summary": (
                f"Observed {len(observation.processes)} processes, "
                f"{len(observation.services)} services, and "
                f"{len(observation.startup)} startup entries"
            ),
            "observed_at": observation.captured_at.isoformat(),
            "captured_at": observation.captured_at.isoformat(),
            "facts": {
                "processes": [
                    cast("JsonValue", item.model_dump(mode="json"))
                    for item in observation.processes
                ],
                "services": [
                    cast("JsonValue", item.model_dump(mode="json")) for item in observation.services
                ],
                "startup": [
                    cast("JsonValue", item.model_dump(mode="json")) for item in observation.startup
                ],
                "boot_time": observation.boot_time.isoformat(),
                "collection_status": observation.status.value,
                "omitted_counts": {
                    "processes": observation.omitted_process_count,
                    "services": observation.omitted_service_count,
                    "startup": observation.omitted_startup_count,
                },
            },
            "limitations": list(observation.limitations),
        }
    )


def _storage_snapshot(parameters: dict[str, JsonValue]) -> None:
    from systemsense.platform.windows.deep_collectors import collect_storage_snapshot

    _NoParameters.model_validate(parameters)
    observation = collect_storage_snapshot()
    _emit(
        {
            "summary": (
                f"Observed {len(observation.volumes)} volumes, "
                f"{len(observation.physical_disks)} physical disks, and "
                f"{len(observation.volume_mappings)} explicit mappings"
            ),
            "observed_at": observation.captured_at.isoformat(),
            "captured_at": observation.captured_at.isoformat(),
            "facts": {
                "volumes": [
                    cast("JsonValue", item.model_dump(mode="json")) for item in observation.volumes
                ],
                "partitions": [
                    cast("JsonValue", item.model_dump(mode="json"))
                    for item in observation.partitions
                ],
                "physical_disks": [
                    cast("JsonValue", item.model_dump(mode="json"))
                    for item in observation.physical_disks
                ],
                "volume_mappings": [
                    cast("JsonValue", item.model_dump(mode="json"))
                    for item in observation.volume_mappings
                ],
                "reliability": [
                    cast("JsonValue", item.model_dump(mode="json"))
                    for item in observation.reliability
                ],
                "collection_status": observation.status.value,
            },
            "limitations": list(observation.limitations),
        }
    )


def _network_configuration(parameters: dict[str, JsonValue]) -> None:
    from systemsense.platform.windows.deep_collectors import collect_network_configuration

    _NoParameters.model_validate(parameters)
    observation = collect_network_configuration()
    _emit(
        {
            "summary": (
                f"Observed {len(observation.routes)} routes and "
                f"{len(observation.adapters)} adapter configurations"
            ),
            "observed_at": observation.captured_at.isoformat(),
            "captured_at": observation.captured_at.isoformat(),
            "facts": {
                "routes": [
                    cast("JsonValue", item.model_dump(mode="json")) for item in observation.routes
                ],
                "adapter_configurations": [
                    cast("JsonValue", item.model_dump(mode="json")) for item in observation.adapters
                ],
                "proxy": cast("JsonValue", observation.proxy.model_dump(mode="json")),
                "collection_status": observation.status.value,
            },
            "limitations": list(observation.limitations),
        }
    )


def _network_connectivity(parameters: dict[str, JsonValue]) -> None:
    from systemsense.platform.windows.connectivity import collect_connectivity_snapshot

    _NoParameters.model_validate(parameters)
    observation = collect_connectivity_snapshot()
    _emit(
        {
            "summary": (
                f"Observed {len(observation.wifi_interfaces)} WLAN interfaces, "
                f"{len(observation.adapters)} IP adapters, and "
                f"{len(observation.recent_failures)} recent WLAN failures"
            ),
            "observed_at": observation.captured_at.isoformat(),
            "captured_at": observation.captured_at.isoformat(),
            "facts": {
                "connectivity": cast("JsonValue", observation.model_dump(mode="json")),
                "collection_status": observation.status.value,
            },
            "limitations": list(observation.limitations),
        }
    )


def _power_snapshot(parameters: dict[str, JsonValue]) -> None:
    from systemsense.platform.windows.deep_collectors import collect_power_snapshot

    _NoParameters.model_validate(parameters)
    observation = collect_power_snapshot()
    _emit(
        {
            "summary": (
                f"Observed power source {observation.ac_line_status}; "
                f"active scheme exposed={observation.active_scheme_guid is not None}"
            ),
            "observed_at": observation.captured_at.isoformat(),
            "captured_at": observation.captured_at.isoformat(),
            "facts": {"power": cast("JsonValue", observation.model_dump(mode="json"))},
            "limitations": list(observation.limitations),
        }
    )


def _security_snapshot(parameters: dict[str, JsonValue]) -> None:
    from systemsense.platform.windows.deep_collectors import collect_security_snapshot

    _NoParameters.model_validate(parameters)
    observation = collect_security_snapshot()
    _emit(
        {
            "summary": (
                f"Observed {len(observation.antivirus_products)} antivirus products and "
                f"{len(observation.firewall_profiles)} firewall profiles"
            ),
            "observed_at": observation.captured_at.isoformat(),
            "captured_at": observation.captured_at.isoformat(),
            "facts": {"security": cast("JsonValue", observation.model_dump(mode="json"))},
            "limitations": list(observation.limitations),
        }
    )


def _incident_events(parameters: dict[str, JsonValue]) -> None:
    from systemsense.platform.windows.deep_collectors import collect_incident_events

    _NoParameters.model_validate(parameters)
    observation = collect_incident_events()
    _emit(
        {
            "summary": f"Observed {len(observation.events)} fixed-profile incident events",
            # This envelope records the query result at collection time.  Each
            # event retains its own source timestamp for child evidence records.
            "observed_at": observation.captured_at.isoformat(),
            "captured_at": observation.captured_at.isoformat(),
            "facts": {
                "events": [
                    cast("JsonValue", item.model_dump(mode="json")) for item in observation.events
                ],
                "channel_status": cast("JsonValue", observation.channel_status),
            },
            "limitations": list(observation.limitations),
        }
    )


def _network_snapshot(parameters: dict[str, JsonValue]) -> None:
    from systemsense.packs.network.adapters import PsutilAdapterBackend
    from systemsense.packs.network.connections import PsutilNetworkConnectionBackend

    _NoParameters.model_validate(parameters)
    observed_at = utc_now()
    adapters = PsutilAdapterBackend().adapters()
    connections = PsutilNetworkConnectionBackend().connections(max_records=128)
    _emit(
        {
            "summary": (
                f"Observed {len(adapters)} adapters and {len(connections)} bounded local endpoints"
            ),
            "observed_at": observed_at.isoformat(),
            "captured_at": observed_at.isoformat(),
            "facts": {
                "adapters": [cast("JsonValue", item.model_dump(mode="json")) for item in adapters],
                "connections": [
                    cast("JsonValue", item.model_dump(mode="json")) for item in connections
                ],
            },
            "limitations": ["route and DNS registry snapshots are not included in this probe"],
        }
    )


def _devices_snapshot(parameters: dict[str, JsonValue]) -> None:
    from systemsense.packs.devices.drivers import WmiDriverBackend
    from systemsense.packs.devices.pnp import WmiDeviceBackend

    _NoParameters.model_validate(parameters)
    observed_at = utc_now()
    devices = WmiDeviceBackend().devices(max_records=64)
    drivers = WmiDriverBackend().drivers(max_records=64)
    _emit(
        {
            "summary": (f"Observed {len(devices)} devices and {len(drivers)} signed drivers"),
            "observed_at": observed_at.isoformat(),
            "captured_at": observed_at.isoformat(),
            "facts": {
                "devices": [cast("JsonValue", item.model_dump(mode="json")) for item in devices],
                "drivers": [cast("JsonValue", item.model_dump(mode="json")) for item in drivers],
            },
            "limitations": [],
        }
    )


def _servicing_snapshot(parameters: dict[str, JsonValue]) -> None:
    from systemsense.packs.servicing.history import (
        RegistryRebootBackend,
        WmiServicingBackend,
        assess_reboot_pending,
    )

    _NoParameters.model_validate(parameters)
    observed_at = utc_now()
    updates = WmiServicingBackend().updates(max_records=128)
    reboot = assess_reboot_pending(RegistryRebootBackend().sources())
    _emit(
        {
            "summary": (
                f"Observed {len(updates)} installed updates; "
                f"reboot pending={str(reboot.pending).lower()}"
            ),
            "observed_at": observed_at.isoformat(),
            "captured_at": observed_at.isoformat(),
            "facts": {
                "updates": [cast("JsonValue", item.model_dump(mode="json")) for item in updates],
                "reboot": cast("JsonValue", reboot.model_dump(mode="json")),
            },
            "limitations": [],
        }
    )


def _local_ai_snapshot(parameters: dict[str, JsonValue]) -> None:
    from systemsense.packs.local_ai.gpu import WmiGpuBackend
    from systemsense.packs.local_ai.packages import current_packages
    from systemsense.packs.local_ai.python import current_python_environment
    from systemsense.platform.windows.deep_collectors import collect_nvidia_telemetry

    _NoParameters.model_validate(parameters)
    observed_at = utc_now()
    gpus = WmiGpuBackend().gpus(max_records=8)
    nvidia = collect_nvidia_telemetry()
    python_environment = current_python_environment()
    packages = current_packages(max_records=256)
    captured_at = utc_now()
    limitations: list[JsonValue] = [
        "framework packages were not imported; CUDA facts are metadata-only",
    ]
    if nvidia.limitation is not None:
        limitations.append(nvidia.limitation)
    _emit(
        {
            "summary": (
                f"Observed {len(gpus)} GPUs, Python {python_environment.version}, "
                f"and {len(packages)} packages"
            ),
            "observed_at": observed_at.isoformat(),
            "captured_at": captured_at.isoformat(),
            "facts": {
                "gpus": [cast("JsonValue", item.model_dump(mode="json")) for item in gpus],
                "nvidia_telemetry": cast("JsonValue", nvidia.model_dump(mode="json")),
                "python": cast(
                    "JsonValue",
                    python_environment.model_dump(mode="json"),
                ),
                "packages": [cast("JsonValue", item.model_dump(mode="json")) for item in packages],
            },
            "limitations": limitations,
        }
    )


def _network_listeners(parameters: dict[str, JsonValue]) -> None:
    from systemsense.platform.windows.deep_collectors import collect_network_listeners

    _NoParameters.model_validate(parameters)
    observation = collect_network_listeners()
    _emit(
        {
            "summary": (
                f"Observed {len(observation.listeners)} bounded local TCP listeners with "
                "available owner identities"
            ),
            "observed_at": observation.captured_at.isoformat(),
            "captured_at": observation.captured_at.isoformat(),
            "facts": {
                "listeners": [
                    cast("JsonValue", item.model_dump(mode="json"))
                    for item in observation.listeners
                ],
                "omitted_listener_count": observation.omitted_listener_count,
                "collection_status": observation.status.value,
            },
            "limitations": list(observation.limitations),
        }
    )


def _pressure_sample(parameters: dict[str, JsonValue]) -> None:
    from systemsense.platform.windows.deep_collectors import collect_pressure_sample

    _NoParameters.model_validate(parameters)
    observation = collect_pressure_sample()
    _emit(
        {
            "summary": "Observed three passive resource samples with fixed one-second delays",
            "observed_at": observation.window_ended_at.isoformat(),
            "captured_at": observation.captured_at.isoformat(),
            "facts": {"pressure": cast("JsonValue", observation.model_dump(mode="json"))},
            "limitations": list(observation.limitations),
        }
    )


def _gpu_telemetry_sample(parameters: dict[str, JsonValue]) -> None:
    from systemsense.platform.windows.deep_collectors import collect_gpu_telemetry_sample

    _NoParameters.model_validate(parameters)
    observation = collect_gpu_telemetry_sample()
    _emit(
        {
            "summary": "Observed three passive NVIDIA telemetry samples",
            "observed_at": observation.window_ended_at.isoformat(),
            "captured_at": observation.captured_at.isoformat(),
            "facts": {
                "gpu_telemetry_sample": cast("JsonValue", observation.model_dump(mode="json"))
            },
            "limitations": list(observation.limitations),
        }
    )


type _Handler = Callable[[dict[str, JsonValue]], None]


def _event_log_query(parameters: dict[str, JsonValue]) -> None:
    from systemsense.platform.windows.eventlog import FixedEventLogAdapter, PyWin32EventLogBackend
    from systemsense.platform.windows.eventlog_runtime import EventLogQueryParameters

    query = EventLogQueryParameters.model_validate(parameters)
    result = FixedEventLogAdapter(PyWin32EventLogBackend()).query(
        query.channel,
        after_record_id=query.after_record_id,
        limit=query.limit,
    )
    _emit({"event_query": result.model_dump(mode="json")})


_HANDLERS: dict[str, _Handler] = {
    "application.snapshot": _application_snapshot,
    "core.resources": _core_resources,
    "core.system": _core_system,
    "devices.snapshot": _devices_snapshot,
    "eventlog.query": _event_log_query,
    "fixture.echo": _echo,
    "fixture.environment": _environment,
    "fixture.false_success": _false_success,
    "fixture.partial_then_sleep": _partial_then_sleep,
    "fixture.unbounded_output": _unbounded_output,
    "gpu.telemetry.sample": _gpu_telemetry_sample,
    "incident.events": _incident_events,
    "local_ai.snapshot": _local_ai_snapshot,
    "network.configuration": _network_configuration,
    "network.connectivity": _network_connectivity,
    "network.listeners": _network_listeners,
    "network.snapshot": _network_snapshot,
    "power.snapshot": _power_snapshot,
    "pressure.sample": _pressure_sample,
    "security.snapshot": _security_snapshot,
    "servicing.snapshot": _servicing_snapshot,
    "storage.snapshot": _storage_snapshot,
}
REGISTERED_PROBE_IDS = frozenset(_HANDLERS)


def main() -> int:
    request_line = sys.stdin.readline()
    try:
        request = WorkerRequest.model_validate_json(request_line)
        handler = _HANDLERS.get(request.probe_id)
        if handler is None:
            print(
                json.dumps({"type": "result", "status": "denied"}),
                flush=True,
            )
            return 2
        handler(request.parameters)
    except (ValidationError, ValueError) as error:
        print(
            json.dumps(
                {
                    "type": "result",
                    "status": "failed",
                    "error": f"{type(error).__name__}: {error}",
                }
            ),
            flush=True,
        )
        return 1
    except Exception as error:
        print(
            json.dumps(
                {
                    "type": "result",
                    "status": "failed",
                    "error": f"{type(error).__name__}: {error}",
                }
            ),
            flush=True,
        )
        return 1
    print(json.dumps({"type": "result", "status": "ok"}), flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
