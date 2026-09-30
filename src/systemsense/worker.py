"""One-request structured worker for fixed diagnostic probe IDs."""

import json
import os
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
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
    from systemsense.packs.core.system import (
        PsutilSystemBackend,
        SystemIdentity,
        collect_system_identity,
    )

    _NoParameters.model_validate(parameters)
    started_at = utc_now()
    initial = collect_system_identity(PsutilSystemBackend(), captured_at=started_at)
    captured_at = utc_now()
    observation = SystemIdentity.model_validate(
        {
            **initial.model_dump(mode="json"),
            "captured_at": captured_at.isoformat(),
            "uptime_seconds": max(0.0, (captured_at - initial.boot_time).total_seconds()),
        }
    )
    product = observation.os_name
    if observation.os_release is not None:
        product += f" {observation.os_release}"
    version = f"kernel {observation.os_version}"
    if observation.windows_build != observation.os_version:
        version += f"; build {observation.windows_build}"
    _emit(
        {
            "summary": (
                f"{product} ({version}) on "
                f"{observation.architecture} with {observation.logical_cpu_count} logical CPUs"
            ),
            "observed_at": observation.captured_at.isoformat(),
            "captured_at": observation.captured_at.isoformat(),
            "time_quality": "bounded_interval",
            "facts": {
                "system": cast("JsonValue", observation.model_dump(mode="json")),
                "collection_started_at": started_at.isoformat(),
                "collection_completed_at": captured_at.isoformat(),
            },
            "limitations": [
                "system identity fields were read over the collection interval",
                "disk capacities include at most eight mounted filesystems; additional ones "
                "may not have been inspected",
            ],
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
            "time_quality": "bounded_interval",
            "facts": {"resources": cast("JsonValue", observation.model_dump(mode="json"))},
            "limitations": [
                *observation.limitations,
                "CPU is an interval measurement; memory and disk were read at later instants",
            ],
        }
    )


def _application_snapshot(parameters: dict[str, JsonValue]) -> None:
    from systemsense.platform.windows.deep_collectors import collect_application_topology

    _NoParameters.model_validate(parameters)
    started_at = utc_now()
    observation = collect_application_topology()
    completed_at = utc_now()
    _emit(
        {
            "summary": (
                f"Observed {len(observation.processes)} processes, "
                f"{len(observation.services)} services, and "
                f"{len(observation.startup)} startup entries"
            ),
            "observed_at": completed_at.isoformat(),
            "captured_at": completed_at.isoformat(),
            "time_quality": "bounded_interval",
            "facts": {
                "collection_started_at": started_at.isoformat(),
                "collection_completed_at": completed_at.isoformat(),
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
            "limitations": [
                *observation.limitations,
                "Application topology fields were read over the collection interval",
            ],
        }
    )


def _storage_snapshot(parameters: dict[str, JsonValue]) -> None:
    from systemsense.platform.windows.deep_collectors import collect_storage_snapshot

    _NoParameters.model_validate(parameters)
    started_at = utc_now()
    observation = collect_storage_snapshot()
    completed_at = utc_now()
    _emit(
        {
            "summary": (
                f"Observed {len(observation.volumes)} volumes, "
                f"{len(observation.physical_disks)} physical disks, and "
                f"{len(observation.volume_mappings)} explicit mappings"
            ),
            "observed_at": completed_at.isoformat(),
            "captured_at": completed_at.isoformat(),
            "time_quality": "bounded_interval",
            "facts": {
                "collection_started_at": started_at.isoformat(),
                "collection_completed_at": completed_at.isoformat(),
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
            "limitations": [
                *observation.limitations,
                "Storage fields were read over the collection interval",
            ],
        }
    )


def _network_configuration(parameters: dict[str, JsonValue]) -> None:
    from systemsense.platform.windows.deep_collectors import collect_network_configuration

    _NoParameters.model_validate(parameters)
    started_at = utc_now()
    observation = collect_network_configuration()
    completed_at = utc_now()
    _emit(
        {
            "summary": (
                f"Observed {len(observation.routes)} routes and "
                f"{len(observation.adapters)} adapter configurations"
            ),
            "observed_at": completed_at.isoformat(),
            "captured_at": completed_at.isoformat(),
            "time_quality": "bounded_interval",
            "facts": {
                "collection_started_at": started_at.isoformat(),
                "collection_completed_at": completed_at.isoformat(),
                "routes": [
                    cast("JsonValue", item.model_dump(mode="json")) for item in observation.routes
                ],
                "adapter_configurations": [
                    cast("JsonValue", item.model_dump(mode="json")) for item in observation.adapters
                ],
                "proxy": cast("JsonValue", observation.proxy.model_dump(mode="json")),
                "collection_status": observation.status.value,
            },
            "limitations": [
                *observation.limitations,
                "Network configuration fields were read over the collection interval",
            ],
        }
    )


def _network_connectivity(parameters: dict[str, JsonValue]) -> None:
    from systemsense.platform.windows.connectivity import (
        collect_connectivity_snapshot,
        connectivity_preview,
    )

    _NoParameters.model_validate(parameters)
    started_at = utc_now()
    observation = collect_connectivity_snapshot()
    completed_at = utc_now()
    _emit(
        {
            "summary": (
                f"Observed {len(observation.wifi_interfaces)} WLAN interfaces, "
                f"{len(observation.adapters)} IP adapters, and "
                f"{len(observation.recent_failures)} recent WLAN failures"
            ),
            "observed_at": completed_at.isoformat(),
            "captured_at": completed_at.isoformat(),
            "time_quality": "bounded_interval",
            "facts": {
                "collection_started_at": started_at.isoformat(),
                "collection_completed_at": completed_at.isoformat(),
                "connectivity": connectivity_preview(observation),
                "connectivity_detail": cast("JsonValue", observation.model_dump(mode="json")),
                "collection_status": observation.status.value,
            },
            "limitations": [
                *observation.limitations,
                "Connectivity sources were read over the collection interval",
                "The model-facing connectivity fact is a bounded preview; omitted rows remain "
                "in the separate full local observation.",
            ],
        }
    )


def _power_snapshot(parameters: dict[str, JsonValue]) -> None:
    from systemsense.platform.windows.deep_collectors import collect_power_snapshot

    _NoParameters.model_validate(parameters)
    started_at = utc_now()
    observation = collect_power_snapshot()
    completed_at = utc_now()
    _emit(
        {
            "summary": (
                f"Observed power source {observation.ac_line_status}; "
                f"active scheme exposed={observation.active_scheme_guid is not None}"
            ),
            "observed_at": completed_at.isoformat(),
            "captured_at": completed_at.isoformat(),
            "time_quality": "bounded_interval",
            "facts": {
                "power": cast("JsonValue", observation.model_dump(mode="json")),
                "collection_started_at": started_at.isoformat(),
                "collection_completed_at": completed_at.isoformat(),
            },
            "limitations": [
                *observation.limitations,
                "Power fields were read over the collection interval",
            ],
        }
    )


def _security_snapshot(parameters: dict[str, JsonValue]) -> None:
    from systemsense.platform.windows.deep_collectors import collect_security_snapshot

    _NoParameters.model_validate(parameters)
    started_at = utc_now()
    observation = collect_security_snapshot()
    completed_at = utc_now()
    _emit(
        {
            "summary": (
                f"Observed {len(observation.antivirus_products)} antivirus products and "
                f"{len(observation.firewall_profiles)} firewall profiles"
            ),
            "observed_at": completed_at.isoformat(),
            "captured_at": completed_at.isoformat(),
            "time_quality": "bounded_interval",
            "facts": {
                "security": cast("JsonValue", observation.model_dump(mode="json")),
                "collection_started_at": started_at.isoformat(),
                "collection_completed_at": completed_at.isoformat(),
            },
            "limitations": [
                *observation.limitations,
                "Security fields were read over the collection interval",
            ],
        }
    )


def _incident_events(parameters: dict[str, JsonValue]) -> None:
    from systemsense.platform.windows.deep_collectors import collect_incident_events

    _NoParameters.model_validate(parameters)
    started_at = utc_now()
    observation = collect_incident_events()
    completed_at = utc_now()
    _emit(
        {
            "summary": f"Observed {len(observation.events)} fixed-profile incident events",
            # This envelope records the query result at collection time.  Each
            # event retains its own source timestamp for child evidence records.
            "observed_at": completed_at.isoformat(),
            "captured_at": completed_at.isoformat(),
            "time_quality": "bounded_interval",
            "facts": {
                "collection_started_at": started_at.isoformat(),
                "collection_completed_at": completed_at.isoformat(),
                "events": [
                    cast("JsonValue", item.model_dump(mode="json")) for item in observation.events
                ],
                "channel_status": cast("JsonValue", observation.channel_status),
            },
            "limitations": [
                *observation.limitations,
                "Event channels were queried over the collection interval; each event "
                "retains its source timestamp",
            ],
        }
    )


def _network_snapshot(parameters: dict[str, JsonValue]) -> None:
    from systemsense.packs.network.adapters import PsutilAdapterBackend
    from systemsense.packs.network.connections import PsutilNetworkConnectionBackend

    _NoParameters.model_validate(parameters)
    started_at = utc_now()
    adapters = PsutilAdapterBackend().adapters()
    connection_page = PsutilNetworkConnectionBackend().connections(max_records=129)
    captured_at = utc_now()
    connections = connection_page[:128]
    connections_truncated = len(connection_page) > 128
    limitations: list[JsonValue] = [
        "route and DNS registry snapshots are not included in this probe",
        "adapter and endpoint values were read over the collection interval",
    ]
    if connections_truncated:
        limitations.append(
            "endpoint inventory is the first 128 prioritized records; "
            "at least one endpoint was omitted"
        )
    _emit(
        {
            "summary": (
                f"Observed {len(adapters)} adapters and {len(connections)} bounded local endpoints"
            ),
            "observed_at": captured_at.isoformat(),
            "captured_at": captured_at.isoformat(),
            "time_quality": "bounded_interval",
            "facts": {
                "collection_started_at": started_at.isoformat(),
                "collection_completed_at": captured_at.isoformat(),
                "adapters": [cast("JsonValue", item.model_dump(mode="json")) for item in adapters],
                "connections": [
                    cast("JsonValue", item.model_dump(mode="json")) for item in connections
                ],
                "connections_truncated": connections_truncated,
            },
            "limitations": limitations,
        }
    )


def _devices_snapshot(parameters: dict[str, JsonValue]) -> None:
    from systemsense.packs.devices.drivers import WmiDriverBackend
    from systemsense.packs.devices.pnp import WmiDeviceBackend

    _NoParameters.model_validate(parameters)
    started_at = utc_now()
    device_page = WmiDeviceBackend().devices(max_records=65)
    driver_page = WmiDriverBackend().drivers(max_records=65)
    captured_at = utc_now()
    devices = device_page[:64]
    drivers = driver_page[:64]
    devices_truncated = len(device_page) > 64
    drivers_truncated = len(driver_page) > 64
    limitations: list[JsonValue] = [
        "WMI device and driver row instants are unknown within the collection interval"
    ]
    if devices_truncated:
        limitations.append(
            "device inventory is the first 64 valid WMI records; at least one device was omitted, "
            "so an unlisted target device was not inspected"
        )
    if drivers_truncated:
        limitations.append(
            "driver inventory is the first 64 valid WMI records; at least one driver was omitted, "
            "so an unlisted target driver was not inspected"
        )
    _emit(
        {
            "summary": (
                f"Observed the first {len(devices)} devices and "
                f"{len(drivers)} signed drivers in WMI enumeration order"
            ),
            "observed_at": captured_at.isoformat(),
            "captured_at": captured_at.isoformat(),
            "time_quality": "bounded_interval",
            "facts": {
                "devices": [cast("JsonValue", item.model_dump(mode="json")) for item in devices],
                "drivers": [cast("JsonValue", item.model_dump(mode="json")) for item in drivers],
                "devices_truncated": devices_truncated,
                "drivers_truncated": drivers_truncated,
                "collection_started_at": started_at.isoformat(),
                "collection_completed_at": captured_at.isoformat(),
            },
            "limitations": limitations,
        }
    )


def _display_mode(parameters: dict[str, JsonValue]) -> None:
    from systemsense.platform.windows.display_mode import collect_display_mode

    _NoParameters.model_validate(parameters)
    observation = collect_display_mode()
    _emit(
        {
            "summary": (
                "Observed current calling-desktop display mode"
                if observation.refresh_hz is not None
                else "Current calling-desktop display refresh unavailable"
            ),
            "observed_at": observation.observed_at.isoformat(),
            "captured_at": observation.captured_at.isoformat(),
            "time_quality": "bounded_interval",
            "facts": {
                "display_mode": cast("JsonValue", observation.model_dump(mode="json")),
                "collection_status": observation.status.value,
            },
            "limitations": list(observation.limitations),
        }
    )


def _servicing_snapshot(parameters: dict[str, JsonValue]) -> None:
    from systemsense.packs.servicing.history import (
        RegistryRebootBackend,
        WmiServicingBackend,
        assess_reboot_pending,
    )

    _NoParameters.model_validate(parameters)
    started_at = utc_now()
    update_page = WmiServicingBackend().updates(max_records=129)
    reboot = assess_reboot_pending(RegistryRebootBackend().sources())
    captured_at = utc_now()
    updates = update_page[:128]
    updates_truncated = len(update_page) > 128
    limitations: list[JsonValue] = [
        "update and reboot indicators were read over the collection interval"
    ]
    if updates_truncated:
        limitations.append(
            "installed update history is the first 128 newest entries; "
            "at least one update was omitted"
        )
    _emit(
        {
            "summary": (
                f"Observed {len(updates)} installed updates; "
                f"reboot pending={str(reboot.pending).lower()}"
            ),
            "observed_at": captured_at.isoformat(),
            "captured_at": captured_at.isoformat(),
            "time_quality": "bounded_interval",
            "facts": {
                "collection_started_at": started_at.isoformat(),
                "collection_completed_at": captured_at.isoformat(),
                "updates": [cast("JsonValue", item.model_dump(mode="json")) for item in updates],
                "reboot": cast("JsonValue", reboot.model_dump(mode="json")),
                "updates_truncated": updates_truncated,
            },
            "limitations": limitations,
        }
    )


def _local_ai_snapshot(parameters: dict[str, JsonValue]) -> None:
    from systemsense.packs.local_ai.gpu import WmiGpuBackend
    from systemsense.packs.local_ai.packages import current_packages
    from systemsense.packs.local_ai.python import current_python_environment
    from systemsense.platform.windows.deep_collectors import collect_nvidia_telemetry

    _NoParameters.model_validate(parameters)
    started_at = utc_now()
    gpus = WmiGpuBackend().gpus(max_records=8)
    nvidia = collect_nvidia_telemetry()
    python_environment = current_python_environment()
    packages = current_packages(max_records=256)
    captured_at = utc_now()
    limitations: list[JsonValue] = [
        "framework packages were not imported; CUDA facts are metadata-only",
        "component values were observed within the collection interval, not at one exact instant",
    ]
    if nvidia.limitation is not None:
        limitations.append(nvidia.limitation)
    _emit(
        {
            "summary": (
                f"Observed {len(gpus)} GPUs, Python {python_environment.version}, "
                f"and {len(packages)} packages"
            ),
            "observed_at": captured_at.isoformat(),
            "captured_at": captured_at.isoformat(),
            "time_quality": "bounded_interval",
            "facts": {
                "collection_started_at": started_at.isoformat(),
                "collection_completed_at": captured_at.isoformat(),
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
    started_at = utc_now()
    observation = collect_network_listeners()
    completed_at = utc_now()
    _emit(
        {
            "summary": (
                f"Observed {len(observation.listeners)} bounded local TCP listeners with "
                "available owner identities"
            ),
            "observed_at": completed_at.isoformat(),
            "captured_at": completed_at.isoformat(),
            "time_quality": "bounded_interval",
            "facts": {
                "collection_started_at": started_at.isoformat(),
                "collection_completed_at": completed_at.isoformat(),
                "listener_table_started_at": (
                    observation.listener_table_started_at.isoformat()
                    if observation.listener_table_started_at is not None
                    else None
                ),
                "listener_table_completed_at": (
                    observation.listener_table_completed_at.isoformat()
                    if observation.listener_table_completed_at is not None
                    else None
                ),
                "listeners": [
                    cast("JsonValue", item.model_dump(mode="json"))
                    for item in observation.listeners
                ],
                "omitted_listener_count": observation.omitted_listener_count,
                "collection_status": observation.status.value,
            },
            "limitations": [
                *observation.limitations,
                "Listener table and owner identities were read over the collection interval",
            ],
        }
    )


def _pressure_sample(parameters: dict[str, JsonValue]) -> None:
    from systemsense.packs.runtime import LiveSampleWindowParametersV1
    from systemsense.platform.windows.deep_collectors import collect_pressure_sample

    window = LiveSampleWindowParametersV1.model_validate(parameters)
    _await_live_sample_window(window, minimum_seconds=2)
    started_at = utc_now()
    observation = collect_pressure_sample()
    completed_at = utc_now()
    _verify_live_sample_window(
        window, observation.window_started_at, observation.window_ended_at, completed_at
    )
    _emit(
        {
            "summary": "Observed three passive resource samples with fixed one-second delays",
            "observed_at": completed_at.isoformat(),
            "captured_at": completed_at.isoformat(),
            "time_quality": "bounded_interval",
            "facts": {
                "pressure": cast("JsonValue", observation.model_dump(mode="json")),
                "collection_started_at": started_at.isoformat(),
                "collection_completed_at": completed_at.isoformat(),
            },
            "limitations": [
                *observation.limitations,
                "Pressure samples were taken at separate instants within the collection interval",
            ],
        }
    )


def _target_pressure(parameters: dict[str, JsonValue]) -> None:
    from systemsense.packs.runtime import TargetPressureParametersV1
    from systemsense.platform.windows.deep_collectors import collect_target_pressure

    target = TargetPressureParametersV1.model_validate(parameters)
    observation = collect_target_pressure(pid=target.pid, creation_time=target.creation_time)
    _emit(
        {
            "summary": f"Target process counter sampling was {observation.status.value}",
            "observed_at": observation.window_ended_at.isoformat(),
            "captured_at": observation.captured_at.isoformat(),
            "time_quality": "bounded_interval",
            "facts": {
                "target_pressure": cast("JsonValue", observation.model_dump(mode="json")),
            },
            "limitations": list(observation.limitations),
        }
    )


def _listener_owner_at_boundary(
    *, pid: int, creation_time: datetime, port: int
) -> dict[str, JsonValue]:
    """Check only the source-bound process and exact IPv4 listener at one boundary."""
    import psutil

    started = utc_now()
    try:
        process = psutil.Process(pid)
        before = datetime.fromtimestamp(process.create_time(), tz=UTC)
        if abs(before - creation_time) > timedelta(microseconds=2):
            status = "reused"
        else:
            connections = process.net_connections(kind="tcp4")
            # Use a fresh object: psutil may cache create_time on a Process.
            after = datetime.fromtimestamp(psutil.Process(pid).create_time(), tz=UTC)
            status = (
                "reused"
                if abs(after - creation_time) > timedelta(microseconds=2)
                else "verified"
                if any(
                    item.status == psutil.CONN_LISTEN
                    and item.laddr.port == port
                    and item.laddr.ip in {"127.0.0.1", "0.0.0.0"}
                    for item in connections
                )
                else "not_owned"
            )
    except psutil.AccessDenied:
        status = "permission_denied"
    except psutil.NoSuchProcess:
        status = "unavailable"
    except NotImplementedError:
        status = "unsupported"
    except OSError:
        status = "failed"
    observed = utc_now()
    if observed < started:
        raise ValueError("UTC clock moved backwards during listener ownership check")
    return {
        "status": status,
        "query_started_at": started.isoformat(),
        "observed_at": observed.isoformat(),
    }


def _listener_owner_pressure(parameters: dict[str, JsonValue]) -> None:
    """Replay the exact GET with process sampling and bounded ownership checks."""
    import http.client
    from concurrent.futures import ThreadPoolExecutor

    import psutil

    from systemsense.domain.owner_cpu import describe_owner_cpu
    from systemsense.packs.runtime import LoopbackOwnerPressureParametersV1
    from systemsense.platform.windows.deep_collectors import collect_target_pressure

    target = LoopbackOwnerPressureParametersV1.model_validate(parameters)
    before_ownership = _listener_owner_at_boundary(
        pid=target.pid, creation_time=target.creation_time, port=target.port
    )
    with ThreadPoolExecutor(max_workers=1) as executor:
        pressure = executor.submit(
            collect_target_pressure,
            pid=target.pid,
            creation_time=target.creation_time,
        )
        started = utc_now()
        connection = http.client.HTTPConnection("127.0.0.1", target.port, timeout=2)
        status: int | None = None
        nonce_match: bool | None = None
        error_type: str | None = None
        try:
            connection.request("GET", f"/health/{target.nonce}")
            response = connection.getresponse()
            status = response.status
            nonce_match = (
                response.read(65) == (target.nonce + "\n").encode() if status == 200 else None
            )
        except (OSError, TimeoutError) as error:
            error_type = type(error).__name__
        finally:
            connection.close()
            finished = utc_now()
        after_ownership = _listener_owner_at_boundary(
            pid=target.pid, creation_time=target.creation_time, port=target.port
        )
        observation = pressure.result()
    ownership_verified = before_ownership["status"] == after_ownership["status"] == "verified"
    logical_cpus = max(1, psutil.cpu_count(logical=True) or 1)
    coincident_core_loads: list[float] = []
    for previous, current in zip(observation.samples, observation.samples[1:], strict=False):
        duration = (current.observed_at - previous.observed_at).total_seconds()
        overlap = (
            min(current.observed_at, finished) - max(previous.observed_at, started)
        ).total_seconds()
        if (
            ownership_verified
            and duration > 0
            and overlap / duration >= 0.8
            and current.delta_status == "measured"
            and current.cpu_percent is not None
        ):
            coincident_core_loads.append(round(current.cpu_percent * logical_cpus / 100.0, 3))
    outcome = (
        "http_200_nonce_match"
        if status == 200 and nonce_match
        else "wrong_response"
        if status == 200
        else "http_503"
        if status == 503
        else "http_other_status"
        if status is not None
        else "connection_refused"
        if error_type == "ConnectionRefusedError"
        else "timeout"
        if error_type == "TimeoutError"
        else "request_error"
    )
    captured = utc_now()
    peak_logical_cores = max(coincident_core_loads) if coincident_core_loads else None
    coincident_summary = (
        f"source-bound process used up to {max(coincident_core_loads):.2f} logical CPU cores "
        f"across {len(coincident_core_loads)} overlapping sample intervals"
        if coincident_core_loads
        else "listener ownership was unverified; owner CPU overlap was unavailable"
        if not ownership_verified
        else "owner CPU overlap was unavailable"
    )
    _emit(
        {
            "summary": (
                f"Exact health GET replay was {outcome}; {coincident_summary}."
                + (
                    f" {describe_owner_cpu(peak_logical_cores)}"
                    if peak_logical_cores is not None
                    else ""
                )
            ),
            "observed_at": max(
                finished,
                observation.window_ended_at,
                datetime.fromisoformat(cast("str", after_ownership["observed_at"])),
            ).isoformat(),
            "captured_at": captured.isoformat(),
            "time_quality": "bounded_interval",
            "facts": {
                "loopback_replay": {
                    "target_handle": f"127.0.0.1:{target.port}",
                    "action": f"GET /health/{target.nonce}",
                    "outcome": outcome,
                    "http_status": status,
                    "nonce_match": nonce_match,
                    "error_type": error_type,
                    "request_started_at": started.isoformat(),
                    "request_finished_at": finished.isoformat(),
                },
                "target_pressure": cast("JsonValue", observation.model_dump(mode="json")),
                "listener_ownership": {
                    "schema_version": 1,
                    "target_pid": target.pid,
                    "target_creation_time": target.creation_time.isoformat(),
                    "target_handle": f"127.0.0.1:{target.port}",
                    "status": "verified_at_boundaries" if ownership_verified else "unverified",
                    "before_replay": before_ownership,
                    "after_replay": after_ownership,
                },
                "logical_cpu_count": logical_cpus,
                "coincident_owner_cpu": {
                    "status": "measured" if coincident_core_loads else "unavailable",
                    "sample_count": len(coincident_core_loads),
                    "peak_logical_cores": peak_logical_cores,
                    "mean_logical_cores": (
                        round(sum(coincident_core_loads) / len(coincident_core_loads), 3)
                        if coincident_core_loads
                        else None
                    ),
                    "minimum_request_overlap_fraction": 0.8,
                },
            },
            "limitations": [
                *observation.limitations,
                "Listener ownership was checked only before and after this replay; "
                "uninterrupted ownership and transitions between checks are unproven.",
                "Ownership checks query only the source-bound PID and exact IPv4 port; "
                "they do not identify a successor owner when that process relinquishes it.",
                *(
                    [
                        "Owner CPU attribution unavailable: listener ownership before replay was "
                        f"{before_ownership['status']} and after replay was "
                        f"{after_ownership['status']}. Raw counters describe only the source-bound "
                        "process, not the request's listener."
                    ]
                    if not ownership_verified
                    else []
                ),
                "Process CPU is concurrent with this GET, but other threads may contribute; "
                "process activity does not prove the request handler's internal cause.",
            ],
        }
    )


def _gpu_telemetry_sample(parameters: dict[str, JsonValue]) -> None:
    from systemsense.packs.runtime import LiveSampleWindowParametersV1
    from systemsense.platform.windows.deep_collectors import collect_gpu_telemetry_sample

    window = LiveSampleWindowParametersV1.model_validate(parameters)
    _await_live_sample_window(window, minimum_seconds=1)
    observation = collect_gpu_telemetry_sample()
    _verify_live_sample_window(
        window, observation.window_started_at, observation.window_ended_at, observation.captured_at
    )
    _emit(
        {
            "summary": "Observed three passive NVIDIA telemetry samples",
            "observed_at": observation.window_ended_at.isoformat(),
            "captured_at": observation.captured_at.isoformat(),
            "time_quality": "bounded_interval",
            "facts": {
                "gpu_telemetry_sample": cast("JsonValue", observation.model_dump(mode="json"))
            },
            "limitations": list(observation.limitations),
        }
    )


def _await_live_sample_window(window: object, *, minimum_seconds: int) -> None:
    from systemsense.packs.runtime import LiveSampleWindowParametersV1

    typed = LiveSampleWindowParametersV1.model_validate(window)
    if typed.window_start is None or typed.window_end is None:
        return
    now = utc_now()
    if typed.window_start - now > timedelta(seconds=30):
        raise ValueError("live sample window starts too far in the future")
    if now < typed.window_start:
        time.sleep((typed.window_start - now).total_seconds())
        now = utc_now()
    if now < typed.window_start or now + timedelta(seconds=minimum_seconds) >= typed.window_end:
        raise ValueError("live sample window has insufficient remaining time")


def _verify_live_sample_window(
    window: object, started_at: datetime, ended_at: datetime, captured_at: datetime
) -> None:
    from systemsense.packs.runtime import LiveSampleWindowParametersV1

    typed = LiveSampleWindowParametersV1.model_validate(window)
    if typed.window_start is None or typed.window_end is None:
        return
    if not (typed.window_start <= started_at <= ended_at <= captured_at <= typed.window_end):
        raise ValueError("actual sample collection fell outside live window")


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
    "application.target_pressure": _target_pressure,
    "network.listener_owner_pressure": _listener_owner_pressure,
    "core.resources": _core_resources,
    "core.system": _core_system,
    "devices.snapshot": _devices_snapshot,
    "display.mode": _display_mode,
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
