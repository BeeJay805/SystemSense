"""Neutral local application factories, independent of optional transports."""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from systemsense.application.passive import PassiveRecorder, PassiveRecorderConfig

from systemsense.application.case_service import CaseService
from systemsense.application.runtime import (
    DiagnosticRuntime,
    default_probe_arbiter,
    default_probe_scheduler,
)
from systemsense.decision.baseline import KeywordBaselineDecisionProvider
from systemsense.decision.contracts import ProbeCapability
from systemsense.orchestration.planner import (
    ProbeCandidate,
    ProviderBackedPlanner,
)
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.packs.runtime import default_probe_runner
from systemsense.storage.sqlite_store import SQLiteStore


def default_database_path() -> Path:
    local_app_data = os.environ.get("LOCALAPPDATA")
    base = Path(local_app_data) if local_app_data else Path.cwd()
    return base / "SystemSense" / "systemsense.db"


def default_planner() -> ProviderBackedPlanner:
    return ProviderBackedPlanner(
        candidates=_default_probe_candidates(),
        provider=KeywordBaselineDecisionProvider(),
        minimum_value=0.25,
    )


def default_capabilities() -> tuple[ProbeCapability, ...]:
    return tuple(
        ProbeCapability(
            probe_id=c.probe_id,
            description=c.description,
            keywords=c.symptom_terms,
            target_traits=c.target_traits,
            common=c.common,
            baseline_priority=c.value,
            cost_ms=c.cost_ms,
            resource_class=c.resource_class,
            permission_class=c.permission_class,
            safety_class=c.safety_class,
        )
        for c in _default_probe_candidates()
    )


def default_investigator(store: SQLiteStore):
    from systemsense.application.investigator import Investigator
    from systemsense.reasoning.deterministic import DeterministicReasoningProvider

    return Investigator(
        store=store,
        runtime=default_case_runtime(store),
        capabilities=default_capabilities(),
        decision=KeywordBaselineDecisionProvider(),
        reasoning=DeterministicReasoningProvider(),
    )


def default_passive_recorder(store: SQLiteStore, config: PassiveRecorderConfig) -> PassiveRecorder:
    from systemsense.application.passive import PassiveRecorder
    from systemsense.platform.windows.eventlog_runtime import IsolatedEventLogAdapter

    return PassiveRecorder(
        store=store,
        runner=default_probe_runner(),
        event_log=IsolatedEventLogAdapter(managed=True),
        config=config,
        host_arbiter=default_probe_arbiter(store),
    )


def default_case_runtime(
    store: SQLiteStore,
    *,
    case_service: CaseService | None = None,
) -> DiagnosticRuntime:
    service = case_service or CaseService(store, default_planner())
    return DiagnosticRuntime(
        store=store,
        case_service=service,
        probe_runner=default_probe_runner(),
        scheduler=default_probe_scheduler(store),
    )


def default_workspace(database_path: Path | None = None):
    """Create the neutral local workspace used by CLI and transport adapters."""

    from systemsense.application.workspace import EvidenceWorkspace

    path = database_path or default_database_path()
    store = SQLiteStore(path)
    store.initialize()
    planner = default_planner()
    case_service = CaseService(store, planner)
    return EvidenceWorkspace(
        store=store,
        case_service=case_service,
        case_runtime=default_case_runtime(store, case_service=case_service),
    )


def _default_probe_candidates() -> tuple[ProbeCandidate, ...]:
    return (
        ProbeCandidate(
            probe_id="core.system",
            description="Operating system, build, architecture, boot time, and capabilities.",
            cost_ms=100,
            value=1.0,
            common=True,
            resource_class=ResourceClass.CPU,
        ),
        ProbeCandidate(
            probe_id="core.resources",
            description="Current CPU, memory, disk capacity, and bounded resource observations.",
            cost_ms=100,
            value=0.9,
            common=True,
            resource_class=ResourceClass.CPU,
        ),
        ProbeCandidate(
            probe_id="application.snapshot",
            description="Process and service snapshots with explicit process identities.",
            cost_ms=7000,
            value=0.9,
            symptom_terms=frozenset({"app", "application", "crash", "service"}),
            target_traits=frozenset({"application", "service"}),
            resource_class=ResourceClass.PROCESS,
        ),
        ProbeCandidate(
            probe_id="devices.snapshot",
            description="Devices, problem codes, and installed driver identities.",
            cost_ms=500,
            value=0.9,
            symptom_terms=frozenset({"audio", "device", "driver"}),
            target_traits=frozenset({"device"}),
            resource_class=ResourceClass.PROCESS,
        ),
        ProbeCandidate(
            probe_id="display.mode",
            description=(
                "Current calling-desktop display mode and reported refresh; "
                "does not measure game frames."
            ),
            cost_ms=500,
            value=0.85,
            symptom_terms=frozenset({"display", "refresh", "smoothness", "stutter", "fps"}),
            target_traits=frozenset({"display", "performance"}),
            resource_class=ResourceClass.CPU,
        ),
        ProbeCandidate(
            probe_id="network.snapshot",
            description="Network adapters and bounded local endpoints; no route or DNS snapshot.",
            cost_ms=300,
            value=0.8,
            symptom_terms=frozenset({"dns", "network", "port", "proxy"}),
            target_traits=frozenset({"network"}),
            resource_class=ResourceClass.NETWORK,
        ),
        ProbeCandidate(
            probe_id="servicing.snapshot",
            description="Windows servicing state, update history, and restart-pending indicators.",
            cost_ms=500,
            value=0.8,
            symptom_terms=frozenset({"servicing", "update", "windows update"}),
            resource_class=ResourceClass.DISK,
        ),
        ProbeCandidate(
            probe_id="local_ai.snapshot",
            description="GPU and Python runtime metadata; does not start inference or training.",
            cost_ms=500,
            value=0.9,
            symptom_terms=frozenset({"cuda", "gpu", "python", "torch"}),
            resource_class=ResourceClass.GPU,
        ),
        ProbeCandidate(
            probe_id="storage.snapshot",
            description="Volume-to-disk topology and exposed storage reliability counters.",
            cost_ms=1500,
            value=0.9,
            symptom_terms=frozenset({"disk", "drive", "filesystem", "storage", "volume"}),
            target_traits=frozenset({"storage"}),
            resource_class=ResourceClass.DISK,
        ),
        ProbeCandidate(
            probe_id="network.configuration",
            description="Read-only routes, DNS, gateways, DHCP, and proxy configuration.",
            cost_ms=1500,
            value=0.85,
            symptom_terms=frozenset({"dns", "gateway", "network", "proxy", "route"}),
            target_traits=frozenset({"network"}),
            resource_class=ResourceClass.NETWORK,
        ),
        ProbeCandidate(
            probe_id="network.connectivity",
            description=(
                "Current WLAN association, adapter addressing, default routes, WinINet proxy, "
                "and recent WLAN failure records; no active reachability test."
            ),
            cost_ms=1800,
            value=0.95,
            symptom_terms=frozenset(
                {"wifi", "wi-fi", "wireless", "internet", "network", "connect", "dns", "proxy"}
            ),
            target_traits=frozenset({"network"}),
            resource_class=ResourceClass.NETWORK,
        ),
        ProbeCandidate(
            probe_id="power.snapshot",
            description="Power source, active power scheme, and processor clock metadata.",
            cost_ms=2500,
            value=0.8,
            symptom_terms=frozenset({"battery", "power", "sleep", "thermal", "throttle"}),
            target_traits=frozenset({"power"}),
            resource_class=ResourceClass.PROCESS,
        ),
        ProbeCandidate(
            probe_id="security.snapshot",
            description="Security Center antivirus, firewall profiles, and UAC configuration.",
            cost_ms=1200,
            value=0.75,
            symptom_terms=frozenset({"antivirus", "defender", "firewall", "security", "uac"}),
            target_traits=frozenset({"security"}),
            resource_class=ResourceClass.PROCESS,
        ),
        ProbeCandidate(
            probe_id="incident.events",
            description="Recent fixed-profile hardware, storage, service, app, and power events.",
            cost_ms=1200,
            value=0.95,
            symptom_terms=frozenset(
                {"crash", "error", "event", "freeze", "hang", "hardware", "restart"}
            ),
            target_traits=frozenset({"incident"}),
            resource_class=ResourceClass.DISK,
        ),
        ProbeCandidate(
            probe_id="network.listeners",
            description="Bounded local TCP listeners with owning PID and process creation time.",
            cost_ms=1500,
            value=0.95,
            symptom_terms=frozenset(
                {"address in use", "bind", "listener", "network", "port", "socket"}
            ),
            target_traits=frozenset({"application", "network"}),
            resource_class=ResourceClass.NETWORK,
        ),
        ProbeCandidate(
            probe_id="pressure.sample",
            description=(
                "Three passive CPU, memory, disk-I/O, and process samples with fixed delays."
            ),
            cost_ms=10_000,
            value=0.95,
            symptom_terms=frozenset(
                {"cpu", "freeze", "hang", "memory", "pressure", "slow", "stutter"}
            ),
            target_traits=frozenset({"application", "performance"}),
            resource_class=ResourceClass.CPU,
        ),
        ProbeCandidate(
            probe_id="gpu.telemetry.sample",
            description=(
                "Three passive NVIDIA utilization, VRAM, thermal, power, and clock samples."
            ),
            cost_ms=2500,
            value=0.95,
            symptom_terms=frozenset({"clock", "cuda", "gpu", "thermal", "throttle", "vram"}),
            target_traits=frozenset({"gpu", "local_ai"}),
            resource_class=ResourceClass.GPU,
        ),
    )
