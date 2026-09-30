"""Synthetic registered-probe cases for the overnight adaptive-loop comparison.

The fixtures describe observations, not diagnoses or a policy. Every built-in
collector is substituted before an Investigator can execute a probe. The real
catalog, manifests, parameter schemas, scheduler, evidence store, and decision
loop remain in use. No model or host probe is started by importing this module.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol, cast

import psutil

from systemsense.application.bootstrap import default_capabilities, default_planner
from systemsense.application.case_service import CaseService
from systemsense.application.investigator import Investigator
from systemsense.application.runtime import DiagnosticRuntime, default_probe_scheduler
from systemsense.decision.baseline import KeywordBaselineDecisionProvider
from systemsense.domain.affected_task import ReportedAffectedTaskV1
from systemsense.domain.ids import JsonValue
from systemsense.inference.factory import AdvisoryProviders
from systemsense.orchestration.probes import ProbeDefinition, ProbeObservation, ProbeRunner
from systemsense.packs.runtime import LiveSampleWindowParametersV1, default_probe_definitions
from systemsense.platform.windows.deep_collectors import NvidiaGpuTelemetry
from systemsense.reasoning.deterministic import DeterministicReasoningProvider
from systemsense.storage.sqlite_store import SQLiteStore

_FIXTURE = Path(__file__).parent / "fixtures" / "overnight_cases.json"
_ID = re.compile(r"^case-[0-9a-f]{12}$")
_NETWORK = frozenset({"network.snapshot", "network.configuration", "network.connectivity"})
_APPLICATION = frozenset({"application.snapshot", "incident.events", "storage.snapshot"})
_PERFORMANCE = frozenset(
    {
        "core.resources",
        "local_ai.snapshot",
        "pressure.sample",
        "gpu.telemetry.sample",
        "power.snapshot",
    }
)
_ADDED_AFTER_OVERNIGHT_FREEZE = frozenset(
    {"network.listener_owner_pressure", "network.loopback_replay"}
)


class _Visible(Protocol):
    case_id: str
    visible_input_sha256: str
    initial_evidence_sha256: str
    action_contract_sha256: str
    budget_ms: int


def _canonical(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def _sha(value: object) -> str:
    return hashlib.sha256(_canonical(value)).hexdigest()


def load_cases(path: Path = _FIXTURE) -> dict[str, dict[str, Any]]:
    """Validate opaque recipes without reading the evaluator oracle."""

    raw: object = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(raw, dict):
        raise ValueError("invalid synthetic case file")
    payload = cast(dict[str, object], raw)
    if payload.get("schema_version") != 1:
        raise ValueError("invalid synthetic case file")
    rows = payload.get("cases")
    if not isinstance(rows, list):
        raise ValueError("expected twelve synthetic cases")
    typed_rows = cast(list[object], rows)
    if len(typed_rows) != 12:
        raise ValueError("expected twelve synthetic cases")
    cases: dict[str, dict[str, Any]] = {}
    for row in typed_rows:
        if not isinstance(row, dict):
            raise ValueError("case row must be an object")
        item = cast(dict[str, Any], row)
        case_id, objective, profile = (
            item.get("case_id"),
            item.get("objective"),
            item.get("profile"),
        )
        if not isinstance(case_id, str) or _ID.fullmatch(case_id) is None or case_id in cases:
            raise ValueError("duplicate or nonopaque case ID")
        if not isinstance(objective, str) or not objective or not isinstance(profile, dict):
            raise ValueError("case objective/profile missing")
        if set(item) not in (
            {
                "case_id",
                "objective",
                "budget_ms",
                "max_rounds",
                "max_probes",
                "profile",
            },
            {
                "case_id",
                "objective",
                "reported_task",
                "budget_ms",
                "max_rounds",
                "max_probes",
                "profile",
            },
        ):
            raise ValueError("case recipe has an unexpected field")
        if "reported_task" in item:
            ReportedAffectedTaskV1.model_validate(item["reported_task"])
        if item["budget_ms"] != 90_000 or item["max_rounds"] != 6 or item["max_probes"] != 8:
            raise ValueError("case budgets must match")
        cases[case_id] = item
    return cases


def case_contract(
    case_id: str, *, cases: Mapping[str, Mapping[str, Any]] | None = None
) -> dict[str, str]:
    """Bind visible objective, first built-in probe recipe, and unchanged catalog."""

    case = (cases or load_cases())[case_id]
    profile = case["profile"]
    if "wifi_status" in profile:
        first_probe = "network.connectivity"
        initial_keys = (
            "wifi_status",
            "association_state",
            "route_present",
            "dns_servers",
            "proxy_status",
            "proxy_enabled",
            "proxy_server",
        )
    elif "process_present" in profile:
        first_probe = "application.snapshot"
        initial_keys = ("process_present", "process_status")
    elif "baseline_cpu_percent" in profile:
        first_probe = "core.resources"
        initial_keys = ("baseline_cpu_percent",)
    else:
        first_probe = "gpu.telemetry.sample"
        initial_keys = (
            "telemetry_status",
            "gpu_index",
            "gpu_uuid",
            "temperature_c",
            "utilization_percent",
            "power_draw_w",
            "power_limit_w",
            "graphics_clock_mhz",
            "throttle_reasons_active",
        )
    # The frozen synthetic action contract names the catalog that existed when
    # these cases were sealed. A later source-bound loopback-only check cannot
    # be offered in this suite and must not rewrite its historical hash.
    definitions = tuple(
        item
        for item in default_probe_definitions()
        if item.manifest.probe_id not in _ADDED_AFTER_OVERNIGHT_FREEZE
    )
    return {
        "visible_input_sha256": _sha(
            {"objective": case["objective"], "reported_task": case.get("reported_task")}
        ),
        "initial_evidence_sha256": _sha(
            {"first_probe": first_probe, "profile": {key: profile[key] for key in initial_keys}}
        ),
        "action_contract_sha256": _sha(
            [
                {
                    "probe_id": item.manifest.probe_id,
                    "version": item.manifest.version,
                    "implementation_id": item.manifest.implementation_id,
                    "input_model": item.manifest.input_model,
                }
                for item in definitions
            ]
        ),
    }


def _stamp(now: datetime, minutes_ago: float = 0) -> str:
    return (now - timedelta(minutes=minutes_ago)).isoformat()


def _source_id(value: str) -> str:
    return "src_" + hashlib.sha256(value.encode()).hexdigest()


def _observation(
    *,
    summary: str,
    facts: Mapping[str, JsonValue],
    now: datetime,
    limitations: tuple[str, ...] = (),
    observed_at: datetime | None = None,
) -> ProbeObservation:
    return ProbeObservation(
        summary=summary,
        facts=dict(facts),
        observed_at=observed_at or now,
        captured_at=now,
        time_quality="bounded_interval",
        limitations=("Synthetic fixture; no Windows collector ran.", *limitations),
    )


def _unavailable(probe_id: str, now: datetime) -> ProbeObservation:
    return _observation(
        summary=f"No synthetic observation supplied for {probe_id}",
        facts={"collection_status": "unsupported"},
        now=now,
        limitations=("This case does not supply data for this registered probe.",),
    )


def _system_observation(now: datetime) -> ProbeObservation:
    from systemsense.packs.core.system import SystemIdentity

    boot_time = now - timedelta(days=2)
    system = SystemIdentity(
        captured_at=now,
        os_name="Windows",
        os_release="11",
        os_version="10.0.22631",
        windows_build="22631",
        architecture="AMD64",
        boot_time=boot_time,
        uptime_seconds=(now - boot_time).total_seconds(),
        logical_cpu_count=8,
        physical_cpu_count=4,
        total_memory_bytes=32_000_000_000,
        disks=(),
    )
    return _observation(
        summary="Observed synthetic Windows host identity",
        facts={
            "system": cast(JsonValue, system.model_dump(mode="json")),
            "collection_started_at": _stamp(now, 0.02),
            "collection_completed_at": _stamp(now),
        },
        now=now,
        limitations=("Host identity is fixture data.",),
    )


def _ordinary_resources(now: datetime) -> ProbeObservation:
    from systemsense.packs.core.resources import MemoryUsage, ResourceObservation

    resource = ResourceObservation(
        captured_at=now,
        cpu_sample_started_at=now - timedelta(seconds=0.2),
        cpu_sample_ended_at=now,
        cpu_sample_interval_seconds=0.2,
        cpu_percent=12,
        memory=MemoryUsage(total_bytes=32_000_000_000, available_bytes=18_000_000_000, percent=44),
        disks=(),
        omitted_disk_count=0,
        limitations=("Broad host resource status is not an affected-task outcome.",),
    )
    return _observation(
        summary="Observed synthetic current CPU and memory resources",
        facts={"resources": cast(JsonValue, resource.model_dump(mode="json"))},
        now=now,
        limitations=tuple(resource.limitations),
    )


def _network_observation(
    probe_id: str,
    profile: Mapping[str, Any],
    now: datetime,
    case_id: str,
) -> ProbeObservation:
    from systemsense.packs.network.routes import RouteObservation
    from systemsense.platform.windows.connectivity import (
        AdapterNetwork,
        ConnectivitySnapshot,
        ProxySettings,
        WifiInterface,
        connectivity_preview,
    )
    from systemsense.platform.windows.deep_collectors import (
        AdapterConfiguration,
        ComponentStatus,
        NetworkConfigurationSnapshot,
        ProxyConfiguration,
    )

    status = ComponentStatus(profile["wifi_status"])
    route = RouteObservation(
        destination="0.0.0.0",
        prefix_length=0,
        next_hop="192.0.2.1",
        interface_index=7,
        metric=25,
    )
    routes = (route,) if profile["route_present"] else ()
    adapters = (
        (
            AdapterNetwork(
                interface_index=7,
                description="Synthetic Wi-Fi adapter",
                ip_addresses=("192.0.2.42",),
                default_gateways=("192.0.2.1",),
                dns_servers=tuple(profile["dns_servers"]),
                dhcp_enabled=True,
            ),
        )
        if status is ComponentStatus.AVAILABLE
        else ()
    )
    if probe_id == "network.connectivity":
        proxy_status = ComponentStatus(profile["proxy_status"])
        snapshot = ConnectivitySnapshot(
            source_id=_source_id(case_id + ":connectivity"),
            captured_at=now,
            wifi_observed_at=now,
            wifi_status=status,
            wifi_interfaces=(
                WifiInterface(
                    interface_guid="{00000000-0000-0000-0000-000000000007}",
                    description="Synthetic Wi-Fi adapter",
                    association_state=profile["association_state"],
                    current_ssid="FixtureNet",
                    signal_quality_percent=81,
                ),
            )
            if status is ComponentStatus.AVAILABLE
            else (),
            omitted_wifi_count=0,
            addresses_observed_at=now,
            addresses_status=status,
            adapters=adapters,
            omitted_adapter_count=0,
            routes_observed_at=now,
            routes_status=status,
            default_routes=routes,
            omitted_route_count=0,
            proxy_observed_at=now,
            proxy_status=proxy_status,
            proxy=ProxySettings(
                manual_enabled=profile["proxy_enabled"],
                manual_server=profile["proxy_server"],
                auto_configured=False,
            )
            if proxy_status is ComponentStatus.AVAILABLE
            else None,
            wlan_events_observed_at=now,
            wlan_events_status=status,
            recent_failures=(),
            omitted_failure_count=0,
            status=status,
            limitations=("Local configuration does not test target reachability.",),
        )
        return _observation(
            summary="Observed synthetic local WLAN, route, DNS and WinINet proxy state",
            facts={
                "collection_started_at": _stamp(now, 0.02),
                "collection_completed_at": _stamp(now),
                "connectivity": connectivity_preview(snapshot),
                "connectivity_detail": cast(JsonValue, snapshot.model_dump(mode="json")),
                "collection_status": status.value,
            },
            now=now,
            limitations=(
                "WinINet state does not establish browser proxy use or service reachability.",
            ),
        )
    if probe_id == "network.configuration":
        config_status = ComponentStatus(profile["configuration_status"])
        snapshot = NetworkConfigurationSnapshot(
            collection_started_at=now - timedelta(seconds=1),
            captured_at=now,
            routes=routes if config_status is ComponentStatus.AVAILABLE else (),
            adapters=(
                AdapterConfiguration(
                    interface_index=7,
                    description="Synthetic Wi-Fi adapter",
                    dhcp_enabled=True,
                    dns_servers=tuple(profile["dns_servers"]),
                    default_gateways=("192.0.2.1",),
                ),
            )
            if config_status is ComponentStatus.AVAILABLE
            else (),
            proxy=ProxyConfiguration(
                enabled=profile["configuration_proxy_enabled"],
                server=profile["configuration_proxy_server"],
                status=config_status,
            ),
            status=config_status,
            limitations=("Local settings are not a target reachability measurement.",),
        )
        return _observation(
            summary="Observed synthetic route, DNS and proxy configuration",
            facts={
                "collection_started_at": _stamp(now, 0.02),
                "collection_completed_at": _stamp(now),
                "routes": cast(
                    JsonValue, [item.model_dump(mode="json") for item in snapshot.routes]
                ),
                "adapter_configurations": cast(
                    JsonValue, [item.model_dump(mode="json") for item in snapshot.adapters]
                ),
                "proxy": cast(JsonValue, snapshot.proxy.model_dump(mode="json")),
                "collection_status": config_status.value,
            },
            now=now,
            limitations=tuple(snapshot.limitations),
        )
    return _observation(
        summary="Observed synthetic local adapter inventory",
        facts={
            "collection_started_at": _stamp(now, 0.02),
            "collection_completed_at": _stamp(now),
            "adapters": [],
            "connections": [],
            "connections_truncated": False,
        },
        now=now,
        limitations=("Route, DNS and proxy settings are outside this probe.",),
    )


def _application_observation(
    probe_id: str,
    profile: Mapping[str, Any],
    now: datetime,
    case_id: str,
) -> ProbeObservation:
    from systemsense.platform.windows.deep_collectors import (
        ApplicationTopologySnapshot,
        ComponentStatus,
        DiskPartition,
        IncidentEventSnapshot,
        IncidentProfileEvent,
        PhysicalDisk,
        ProcessTopology,
        StorageSnapshot,
        StorageVolume,
        VolumeDiskMapping,
    )

    if probe_id == "application.snapshot":
        process = (
            (
                ProcessTopology(
                    pid=4242,
                    ppid=1,
                    name="PageDesk.exe",
                    creation_time=now - timedelta(minutes=4),
                    status=profile["process_status"],
                ),
            )
            if profile["process_present"]
            else ()
        )
        snapshot = ApplicationTopologySnapshot(
            collection_started_at=now - timedelta(seconds=1),
            captured_at=now,
            boot_time=now - timedelta(days=2),
            processes=process,
            services=(),
            startup=(),
            omitted_process_count=0,
            omitted_service_count=0,
            omitted_startup_count=0,
            status=ComponentStatus.PARTIAL,
            limitations=("A process inventory cannot reproduce the reported launch.",),
        )
        return _observation(
            summary=f"Observed {len(process)} matching synthetic process rows",
            facts={
                "collection_started_at": _stamp(now, 0.02),
                "collection_completed_at": _stamp(now),
                "processes": cast(
                    JsonValue, [p.model_dump(mode="json") for p in snapshot.processes]
                ),
                "services": [],
                "startup": [],
                "boot_time": snapshot.boot_time.isoformat(),
                "collection_status": snapshot.status.value,
                "omitted_counts": {"processes": 0, "services": 0, "startup": 0},
            },
            now=now,
            limitations=tuple(snapshot.limitations),
        )
    if probe_id == "incident.events":
        events_status = ComponentStatus(profile["events_status"])
        event = (
            (
                IncidentProfileEvent(
                    profile=profile["event_profile"],
                    channel="Application",
                    provider="Application Error",
                    event_id=profile["event_id"],
                    record_id=9150,
                    level=2,
                    observed_at=now - timedelta(minutes=profile["event_minutes_ago"]),
                    event_data={"AppName": profile["event_target"]},
                    rendered_message=f"Faulting application: {profile['event_target']}",
                    source_id=_source_id(case_id + ":event"),
                ),
            )
            if profile["event_profile"] is not None
            else ()
        )
        snapshot = IncidentEventSnapshot(
            collection_started_at=now - timedelta(seconds=1),
            captured_at=now,
            events=event,
            channel_status={"Application": events_status},
            limitations=("Event source time may precede the reported launch window.",),
        )
        return _observation(
            summary=f"Observed {len(event)} synthetic fixed-profile incident events",
            facts={
                "collection_started_at": _stamp(now, 0.02),
                "collection_completed_at": _stamp(now),
                "events": cast(JsonValue, [e.model_dump(mode="json") for e in snapshot.events]),
                "channel_status": {"Application": events_status.value},
            },
            now=now,
            limitations=tuple(snapshot.limitations),
        )
    total, free = int(profile["disk_total_bytes"]), int(profile["disk_free_bytes"])
    snapshot = StorageSnapshot(
        collection_started_at=now - timedelta(seconds=1),
        captured_at=now,
        volumes=(
            StorageVolume(volume_id="C:", filesystem="NTFS", total_bytes=total, free_bytes=free),
        ),
        partitions=(DiskPartition(partition_id="partition-0", disk_index=0),),
        physical_disks=(PhysicalDisk(disk_index=0, device_id="fixture-disk-0", size_bytes=total),),
        volume_mappings=(
            VolumeDiskMapping(volume_id="C:", partition_id="partition-0", disk_index=0),
        ),
        reliability=(),
        status=ComponentStatus(profile["storage_status"]),
        limitations=("Free space was observed after the reported failure, not during it.",),
    )
    return _observation(
        summary="Observed one synthetic logical volume and disk mapping",
        facts={
            "collection_started_at": _stamp(now, 0.02),
            "collection_completed_at": _stamp(now),
            "volumes": cast(JsonValue, [v.model_dump(mode="json") for v in snapshot.volumes]),
            "partitions": cast(JsonValue, [p.model_dump(mode="json") for p in snapshot.partitions]),
            "physical_disks": cast(
                JsonValue, [d.model_dump(mode="json") for d in snapshot.physical_disks]
            ),
            "volume_mappings": cast(
                JsonValue, [m.model_dump(mode="json") for m in snapshot.volume_mappings]
            ),
            "reliability": [],
            "collection_status": snapshot.status.value,
        },
        now=now,
        limitations=tuple(snapshot.limitations),
    )


def _gpu(profile: Mapping[str, Any], *, inventory: bool = False) -> NvidiaGpuTelemetry:
    return NvidiaGpuTelemetry.model_validate(
        {
            "index": profile["gpu_index"],
            "uuid": profile["gpu_uuid"],
            "name": "Fixture GPU",
            "driver_version": "555.1",
            "utilization_percent": profile["utilization_percent"],
            "memory_used_mib": 2048,
            "memory_free_mib": 8192,
            "temperature_c": profile["inventory_temperature_c"]
            if inventory
            else profile["temperature_c"],
            "power_draw_w": profile["power_draw_w"],
            "power_limit_w": profile["power_limit_w"],
            "graphics_clock_mhz": profile["graphics_clock_mhz"],
            "memory_clock_mhz": 7000,
            "throttle_reasons_active": (
                profile["inventory_throttle_reasons_active"]
                if inventory
                else profile["throttle_reasons_active"]
            ),
        }
    )


def _performance_observation(
    probe_id: str,
    profile: Mapping[str, Any],
    now: datetime,
    sample_intervals: tuple[tuple[datetime, datetime], ...] | None = None,
) -> ProbeObservation:
    from systemsense.packs.core.resources import MemoryUsage, ResourceObservation
    from systemsense.packs.local_ai.gpu import GpuObservation
    from systemsense.platform.windows.deep_collectors import (
        ComponentStatus,
        NvidiaTelemetrySeries,
        NvidiaTelemetrySnapshot,
        PowerSnapshot,
        PressureSample,
        PressureSnapshot,
    )

    status = ComponentStatus(profile["telemetry_status"])
    if probe_id == "gpu.telemetry.sample":
        if sample_intervals is None:
            raise ValueError("synthetic GPU sample times were not captured")
        frames = tuple(
            NvidiaTelemetrySnapshot(
                sample_started_at=started_at,
                captured_at=captured_at,
                status=status,
                gpus=(_gpu(profile),) if status is ComponentStatus.AVAILABLE else (),
                limitation=None
                if status is ComponentStatus.AVAILABLE
                else "NVIDIA telemetry unavailable",
            )
            for started_at, captured_at in sample_intervals
        )
        series = NvidiaTelemetrySeries(
            captured_at=now,
            window_started_at=sample_intervals[0][0],
            window_ended_at=sample_intervals[-1][1],
            inter_sample_delay_seconds=1,
            samples=frames,
            status=status,
            limitations=("No affected game or adapter identity was bound to these samples.",),
        )
        return _observation(
            summary="Observed three synthetic passive NVIDIA telemetry samples",
            facts={"gpu_telemetry_sample": cast(JsonValue, series.model_dump(mode="json"))},
            now=now,
            limitations=tuple(series.limitations),
        )
    if probe_id == "local_ai.snapshot":
        telemetry = NvidiaTelemetrySnapshot(
            sample_started_at=now - timedelta(seconds=1),
            captured_at=now,
            status=status,
            gpus=(_gpu(profile, inventory=True),) if status is ComponentStatus.AVAILABLE else (),
            limitation=None
            if status is ComponentStatus.AVAILABLE
            else "NVIDIA telemetry unavailable",
        )
        display = GpuObservation(
            name="Fixture GPU",
            vendor="NVIDIA",
            driver_version="555.1",
            adapter_ram_bytes=10_737_418_240,
            vendor_utility_available=status is ComponentStatus.AVAILABLE,
        )
        return _observation(
            summary="Observed synthetic GPU inventory and metadata",
            facts={
                "collection_started_at": _stamp(now, 0.02),
                "collection_completed_at": _stamp(now),
                "gpus": cast(JsonValue, [display.model_dump(mode="json")]),
                "nvidia_telemetry": cast(JsonValue, telemetry.model_dump(mode="json")),
                "python": {"version": "3.12"},
                "packages": [],
            },
            now=now,
            limitations=(
                "GPU metadata does not identify the adapter rendering the reported game.",
            ),
        )
    if probe_id == "pressure.sample":
        if sample_intervals is None:
            raise ValueError("synthetic pressure sample times were not captured")
        frames = tuple(
            PressureSample(
                collection_started_at=started_at,
                observed_at=captured_at,
                system_cpu_percent=profile["pressure_cpu_percent"],
                per_cpu_percent=(profile["pressure_cpu_percent"],),
                memory_percent=42,
                memory_available_bytes=16_000_000_000,
                swap_percent=0,
                disk_read_bytes_delta=0,
                disk_write_bytes_delta=0,
                processes=(),
                omitted_process_count=0,
            )
            for started_at, captured_at in sample_intervals
        )
        sample = PressureSnapshot(
            captured_at=now,
            window_started_at=sample_intervals[0][0],
            window_ended_at=sample_intervals[-1][1],
            inter_sample_delay_seconds=1,
            samples=frames,
            status=ComponentStatus.AVAILABLE,
            limitations=("System CPU samples are not a game frame-time measurement.",),
        )
        return _observation(
            summary="Observed three synthetic passive resource samples",
            facts={
                "pressure": cast(JsonValue, sample.model_dump(mode="json")),
                "collection_started_at": sample_intervals[0][0].isoformat(),
                "collection_completed_at": _stamp(now),
            },
            now=now,
            limitations=tuple(sample.limitations),
        )
    if probe_id == "power.snapshot":
        snapshot = PowerSnapshot(
            collection_started_at=now - timedelta(seconds=1),
            captured_at=now,
            ac_line_status=profile["ac_line_status"],
            active_scheme_guid=profile["power_scheme"],
            status=ComponentStatus.AVAILABLE
            if profile["power_scheme"]
            else ComponentStatus.PARTIAL,
            limitations=("Power scheme metadata does not establish a GPU power-cap cause.",),
        )
        return _observation(
            summary="Observed synthetic power-source and scheme metadata",
            facts={
                "power": cast(JsonValue, snapshot.model_dump(mode="json")),
                "collection_started_at": _stamp(now, 0.02),
                "collection_completed_at": _stamp(now),
            },
            now=now,
            limitations=tuple(snapshot.limitations),
        )
    resource = ResourceObservation(
        captured_at=now,
        cpu_sample_started_at=now - timedelta(seconds=0.2),
        cpu_sample_ended_at=now,
        cpu_sample_interval_seconds=0.2,
        cpu_percent=profile.get("baseline_cpu_percent", profile["pressure_cpu_percent"]),
        memory=MemoryUsage(total_bytes=32_000_000_000, available_bytes=18_000_000_000, percent=44),
        disks=(),
        omitted_disk_count=0,
        limitations=("Current system pressure does not measure game frame times.",),
    )
    return _observation(
        summary="Observed synthetic current CPU and memory resources",
        facts={"resources": cast(JsonValue, resource.model_dump(mode="json"))},
        now=now,
        limitations=tuple(resource.limitations),
    )


def synthetic_probe_runner(recipe: Mapping[str, Any]) -> ProbeRunner:
    """Keep every built-in manifest, while making host collection impossible.

    All definitions are converted to in-process synthetic handlers, including
    probes outside the case family. An unexpected choice yields an explicit
    unsupported observation; no isolated default worker remains reachable.
    """

    profile = cast(Mapping[str, Any], recipe["profile"])
    case_id = str(recipe["case_id"])

    def handler_for(probe_id: str) -> Callable[[dict[str, JsonValue]], ProbeObservation]:
        def collect(_parameters: dict[str, JsonValue]) -> ProbeObservation:
            sample_intervals: tuple[tuple[datetime, datetime], ...] | None = None
            if probe_id in {"pressure.sample", "gpu.telemetry.sample"}:
                window = LiveSampleWindowParametersV1.model_validate(_parameters)
                if window.window_start is not None and window.window_end is not None:
                    if datetime.now(UTC) > window.window_end:
                        raise ValueError("synthetic live sample window is unavailable")
                    wait_seconds = max(
                        0.0, (window.window_start - datetime.now(UTC)).total_seconds()
                    )
                    if wait_seconds > 3.1:
                        raise ValueError("synthetic live sample window is unavailable")
                    if wait_seconds:
                        time.sleep(wait_seconds)
                intervals: list[tuple[datetime, datetime]] = []
                for index in range(3):
                    if index:
                        time.sleep(1)
                    started_at = datetime.now(UTC)
                    captured_at = datetime.now(UTC)
                    intervals.append((started_at, captured_at))
                now = datetime.now(UTC)
                if (
                    window.window_start is not None
                    and window.window_end is not None
                    and (intervals[0][0] < window.window_start or now > window.window_end)
                ):
                    raise ValueError("synthetic samples cannot fit the registered live window")
                sample_intervals = tuple(intervals)
            else:
                now = datetime.now(UTC)
            if probe_id == "core.system":
                return _system_observation(now)
            if probe_id == "core.resources" and "telemetry_status" not in profile:
                return _ordinary_resources(now)
            if probe_id in _NETWORK and "wifi_status" in profile:
                return _network_observation(probe_id, profile, now, case_id)
            if probe_id in _APPLICATION and "process_present" in profile:
                return _application_observation(probe_id, profile, now, case_id)
            if probe_id in _PERFORMANCE and "telemetry_status" in profile:
                return _performance_observation(probe_id, profile, now, sample_intervals)
            return _unavailable(probe_id, now)

        return collect

    definitions: tuple[ProbeDefinition, ...] = tuple(
        replace(item, isolated=False, handler=handler_for(item.manifest.probe_id))
        for item in default_probe_definitions()
    )
    if any(item.isolated or item.handler is None for item in definitions):
        raise RuntimeError("unsafe synthetic probe registry")
    return ProbeRunner(definitions=definitions)


def build_investigator(
    store: SQLiteStore,
    recipe: Mapping[str, Any],
    providers: AdvisoryProviders | None = None,
) -> Investigator:
    """Build the ordinary investigation loop with substituted built-in collectors."""

    runner = synthetic_probe_runner(recipe)
    expected = frozenset(item.manifest.probe_id for item in default_probe_definitions())
    if runner.probe_ids != expected or runner.isolated_probe_ids:
        raise RuntimeError("synthetic registry does not cover every built-in collector")
    runtime = DiagnosticRuntime(
        store=store,
        case_service=CaseService(store, default_planner()),
        probe_runner=runner,
        scheduler=default_probe_scheduler(store),
    )
    return Investigator(
        store=store,
        runtime=runtime,
        capabilities=default_capabilities(),
        decision=providers.decision if providers is not None else KeywordBaselineDecisionProvider(),
        reasoning=providers.reasoning
        if providers is not None
        else DeterministicReasoningProvider(),
        knowledge=providers.knowledge if providers is not None else None,
        catalog_attention=providers.catalog_attention if providers is not None else None,
        frontier_ranker=providers.frontier_ranker if providers is not None else None,
        enable_scout_prefetch=False,
    )


def _process_resource_sample(phase: str) -> dict[str, object]:
    """One read-only local process-tree sample, never a peak or server total."""

    process = psutil.Process(os.getpid())
    try:
        members = (process, *process.children(recursive=True))
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        members = (process,)
    cpu_seconds = 0.0
    rss_bytes = 0
    observed = 0
    for member in members:
        try:
            times = member.cpu_times()
            cpu_seconds += float(times.user + times.system)
            rss_bytes += int(member.memory_info().rss)
            observed += 1
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return {
        "phase": phase,
        "observed_at": datetime.now(UTC).isoformat(),
        "process_count": observed,
        "cpu_seconds_sum": round(cpu_seconds, 6),
        "rss_bytes_sum": rss_bytes,
        "scope": "runner and live children at sample instant; excludes peaks and external server",
    }


def run_case(
    visible: _Visible,
    arm: str,
    attempt_dir: Path,
    *,
    providers: AdvisoryProviders | None = None,
) -> dict[str, object]:
    """Run one real Investigator episode; provider construction belongs to caller."""

    from benchmarks.overnight_suite import collect_case_custody

    recipe = load_cases()[visible.case_id]
    contract = case_contract(visible.case_id)
    if any(getattr(visible, name) != value for name, value in contract.items()):
        raise ValueError("visible case contract differs from frozen fixture")
    if visible.budget_ms != recipe["budget_ms"]:
        raise ValueError("case budget differs from frozen fixture")
    if (arm == "deterministic") != (providers is None):
        raise ValueError("arm/provider mismatch")
    if not attempt_dir.is_dir() or (attempt_dir / "case.db").exists():
        raise ValueError("attempt directory must exist and be empty of case.db")
    with SQLiteStore(attempt_dir / "case.db") as store:
        app = build_investigator(store, recipe, providers)
        state = app.create(
            objective=recipe["objective"],
            reported_task=ReportedAffectedTaskV1.model_validate(recipe["reported_task"])
            if "reported_task" in recipe
            else None,
            budget_ms=recipe["budget_ms"],
            max_rounds=recipe["max_rounds"],
            max_probes=recipe["max_probes"],
        )
        runtime_case_id = str(state.case_id)
        resources_before = _process_resource_sample("before_run")
        case_started_at = datetime.now(UTC).isoformat()
        try:
            state = app.run(runtime_case_id)
            status = "completed" if state.status.value == "complete" else "failed"
            failure_type: str | None = None
            failure_detail: str | None = None
        except Exception as error:
            state = app.repository.load(runtime_case_id)
            status, failure_type = "failed", type(error).__name__
            failure_detail = str(error)[:1000]
        case_finished_at = datetime.now(UTC).isoformat()
        resources_after = _process_resource_sample("after_run")
        custody = collect_case_custody(store, runtime_case_id)
        final_state = state.model_dump(mode="json")
        (attempt_dir / "final.json").write_text(
            json.dumps(final_state, indent=2, sort_keys=True), encoding="utf-8"
        )
        return {
            "case_id": visible.case_id,
            "runtime_case_id": runtime_case_id,
            "status": status,
            "contract": contract,
            "runtime": {
                "provider_calls": [item.model_dump(mode="json") for item in state.provider_calls],
                "raw_invalid_retries": None,
                "startup_ms": None,
                "resource_observations": [resources_before, resources_after],
                "failure_type": failure_type,
                "failure_detail": failure_detail,
                "outcome": state.outcome.value,
                "stop_reason": state.stop_reason,
                "case_started_at": case_started_at,
                "case_finished_at": case_finished_at,
            },
            "model_inputs": [],
            "custody": custody,
            "final_state": final_state,
        }
