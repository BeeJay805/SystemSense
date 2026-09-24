"""Opt-in local pinned-Laya persisted-event to durable follow-up admission trial.

The observations are synthetic, read-only, and local. Production collection,
queue, provider, validation, scheduler, and SQLite admission code are exercised.
This measures latency and custody, never diagnostic utility. No host facts,
process list, model inputs, or private telemetry are exported.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import subprocess
import tempfile
import threading
import time
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast
from unittest.mock import patch

import psutil
from pydantic import BaseModel, ConfigDict

from systemsense.application.case_service import CaseService
from systemsense.application.investigation_state import InvestigationStatus
from systemsense.application.investigator import Investigator
from systemsense.application.runtime import DiagnosticRuntime
from systemsense.cli import _managed_laya_admission  # pyright: ignore[reportPrivateUsage]
from systemsense.decision.contracts import (
    DecisionRequest,
    DecisionResponse,
    DiagnosticPurpose,
    ProbeCapability,
    ProbeProposal,
)
from systemsense.decision.laya import LayaDecisionProvider
from systemsense.domain.ids import JsonValue
from systemsense.domain.probes import (
    Privilege,
    ProbeLimits,
    ProbeManifest,
    ProbeSafety,
    SafetyClass,
)
from systemsense.inference.factory import AdvisoryProviders, load_advisory_providers
from systemsense.inference.host_telemetry import read_host_telemetry
from systemsense.inference.managed_laya import ManagedLayaAdmission
from systemsense.inference.profile import (
    LocalInferenceProfile,
    ManagedGpuResources,
    load_inference_profile,
    propose_managed_v3_payload,
)
from systemsense.orchestration.planner import DeterministicPlanner, ProbeCandidate
from systemsense.orchestration.probes import (
    ProbeDefinition,
    ProbeObservation,
    ProbeRun,
    ProbeRunner,
)
from systemsense.orchestration.scheduler import ResourceClass
from systemsense.reasoning.unavailable import UnavailableReasoningProvider
from systemsense.storage.followup_admissions import FollowupAdmissionRepository
from systemsense.storage.investigations import InvestigationRepository
from systemsense.storage.sqlite_store import SQLiteStore

_NS_PER_MS = 1_000_000
# On Windows, monotonic_ns can have 15.625 ms resolution. perf_counter_ns
# provides the higher-resolution elapsed clock needed for phase timing.


class _NoParameters(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


def _definition(probe_id: str, category: str, collect: Any) -> ProbeDefinition:
    return ProbeDefinition(
        manifest=ProbeManifest(
            probe_id=probe_id,
            version=1,
            implementation_id=f"builtin.benchmark.{probe_id}",
            question=f"What is the synthetic {probe_id} state?",
            safety=ProbeSafety(
                safety_class=SafetyClass.R1,
                privilege=Privilege.STANDARD,
                target_state_effect="none",
            ),
            input_model="NoParametersV1",
            limits=ProbeLimits(timeout_ms=3000, max_output_bytes=32768, max_records=64),
            category=category,
        ),
        parameter_model=_NoParameters,
        handler=collect,
        isolated=False,
    )


def _percentile(values: list[float], fraction: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * fraction
    lower = math.floor(position)
    upper = math.ceil(position)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def summarize_attempts(attempts: list[dict[str, Any]]) -> dict[str, Any]:
    """One denominator entry per planned parent event, including every miss."""

    latencies = [
        (cast(int, item["admitted_ns"]) - cast(int, item["persisted_ns"])) / _NS_PER_MS
        for item in attempts
        if item.get("persisted_ns") is not None and item.get("admitted_ns") is not None
    ]
    misses = len(attempts) - len(latencies)
    return {
        "planned_attempts": len(attempts),
        "persisted_events": sum(item.get("persisted_ns") is not None for item in attempts),
        "admitted_followups": len(latencies),
        "misses": misses,
        "miss_reasons": dict(
            sorted(
                Counter(
                    str(item.get("miss_reason") or "unclassified")
                    for item in attempts
                    if item.get("admitted_ns") is None
                ).items()
            )
        ),
        "admitted_only_ms": {
            "count": len(latencies),
            "p50": _percentile(latencies, 0.5),
            "p95": _percentile(latencies, 0.95),
        },
        "all_attempt_p95_ms": None if misses else _percentile(latencies, 0.95),
    }


def _elapsed(item: dict[str, Any], start: str, end: str) -> float | None:
    earlier, later = item.get(start), item.get(end)
    if not isinstance(earlier, int) or not isinstance(later, int):
        return None
    return max(0.0, (later - earlier) / _NS_PER_MS)


def _phase_stats(records: list[dict[str, Any]], start: str, end: str) -> dict[str, Any]:
    values = [value for item in records if (value := _elapsed(item, start, end)) is not None]
    return {"count": len(values), "p50": _percentile(values, 0.5), "p95": _percentile(values, 0.95)}


def _attempt_detail(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "outcome": "admitted" if item.get("admitted_ns") is not None else "missed",
        "miss_reason": item.get("miss_reason"),
        "gpu_gate_reason": item.get("gpu_gate_reason"),
        "resource_wait_ms": item.get("resource_wait_ms", 0.0),
        "harness_error": item.get("harness_error"),
        "event_to_admission_ms": _elapsed(item, "persisted_ns", "admitted_ns"),
    }


def _laya_worker_processes() -> tuple[dict[str, int | None], ...]:
    return tuple(
        sorted(
            (
                {"pid": process.pid, "ppid": process.info.get("ppid")}
                for process in psutil.process_iter(("cmdline", "ppid"))
                if any(
                    Path(str(part)).name.casefold() == "laya_worker.py"
                    for part in (process.info["cmdline"] or ())
                )
            ),
            key=lambda item: item["pid"] if item["pid"] is not None else -1,
        )
    )


def _owned_laya_tree_pids(
    processes: tuple[dict[str, int | None], ...], owned_laya_pid: int | None
) -> frozenset[int]:
    """Trust only live worker-script descendants of the managed worker PID."""

    if owned_laya_pid is None:
        return frozenset()
    parents = {pid: item["ppid"] for item in processes if (pid := item["pid"]) is not None}
    if owned_laya_pid not in parents:
        return frozenset()
    owned = {owned_laya_pid}
    for _ in range(len(parents)):
        next_owned = {pid for pid, parent in parents.items() if parent in owned}
        if next_owned <= owned:
            break
        owned.update(next_owned)
    return frozenset(owned)


def _gpu_gate_reason(
    index: int, *, owned_laya_pid: int | None = None, allow_ambient_gpu: bool = False
) -> str | None:
    """Return a non-sensitive, explicit reason when local GPU work is denied."""

    try:
        for _ in range(2):
            laya_processes = _laya_worker_processes()
            owned_tree = _owned_laya_tree_pids(laya_processes, owned_laya_pid)
            observed = read_host_telemetry(gpu_device_index=index)
            if observed.free_vram_bytes < 8 * 1024**3:
                return "vram_headroom"
            sample = subprocess.run(
                [
                    "nvidia-smi",
                    "-i",
                    str(index),
                    "--query-gpu=utilization.gpu",
                    "--format=csv,noheader,nounits",
                ],
                capture_output=True,
                text=True,
                timeout=3,
                check=True,
                shell=False,
            )
            values = sample.stdout.strip().splitlines()
            utilization_limit = 50 if allow_ambient_gpu else 5
            if len(values) != 1 or int(values[0].strip()) > utilization_limit:
                return "gpu_utilization"
            processes = subprocess.run(
                [
                    "nvidia-smi",
                    "-i",
                    str(index),
                    "--query-compute-apps=pid,process_name,used_gpu_memory",
                    "--format=csv,noheader,nounits",
                ],
                capture_output=True,
                text=True,
                timeout=3,
                check=True,
                shell=False,
            )
            # WDDM often lists graphics processes with N/A memory. Any row is
            # ambiguous, including inaccessible PIDs. Only the explicit
            # non-isolated trial may proceed in their presence.
            for row in processes.stdout.strip().splitlines():
                pid_text = row.split(",", 1)[0].strip()
                if not allow_ambient_gpu and (
                    not pid_text.isdecimal() or int(pid_text) not in owned_tree
                ):
                    return "unowned_gpu_process_visible"
            if any(item["pid"] not in owned_tree for item in laya_processes):
                return "unowned_laya_worker_visible"
            time.sleep(0.25)
    except (OSError, ValueError, subprocess.SubprocessError, psutil.Error):
        return "gpu_telemetry_unavailable"
    return None


def _await_gpu_capacity(
    index: int,
    *,
    owned_laya_pid: int | None = None,
    allow_ambient_gpu: bool = False,
    max_wait_ms: int = 2000,
) -> tuple[str | None, float]:
    """Allow a bounded inter-trial settling period only in non-isolated mode."""

    if max_wait_ms < 0:
        raise ValueError("max_wait_ms must be nonnegative")
    started = time.perf_counter()
    deadline = started + max_wait_ms / 1000
    while True:
        reason = _gpu_gate_reason(
            index, owned_laya_pid=owned_laya_pid, allow_ambient_gpu=allow_ambient_gpu
        )
        waited_ms = (time.perf_counter() - started) * 1000
        if reason != "gpu_utilization" or not allow_ambient_gpu or time.perf_counter() >= deadline:
            return reason, waited_ms
        time.sleep(min(0.25, max(0.0, deadline - time.perf_counter())))


def _managed_providers(
    profile: LocalInferenceProfile,
) -> tuple[AdvisoryProviders, ManagedLayaAdmission]:
    if not profile.laya.enabled or profile.laya.device != "cuda":
        raise ValueError("benchmark requires enabled pinned CUDA Laya")
    if profile.schema_version != 3:
        observed = read_host_telemetry(gpu_device_index=profile.laya.cuda_device_index)
        profile = LocalInferenceProfile.model_validate(
            propose_managed_v3_payload(
                profile,
                decision_provider="laya",
                managed_resources=ManagedGpuResources(
                    gpu_device_index=observed.gpu_device_index, gpu_uuid=observed.gpu_uuid
                ),
            )
        )
    policy = profile.resolved_execution_policy()
    admission = _managed_laya_admission(policy)
    if admission is None:
        raise ValueError("managed GPU admission is unavailable")
    providers = load_advisory_providers(
        profile.inference,
        laya_config=profile.laya.runtime_config(),
        laya_timeout_seconds=profile.laya.timeout_seconds,
        execution_policy=policy,
        managed_admission=admission,
    )
    return providers, admission


def run_local_trial(store: SQLiteStore, provider: LayaDecisionProvider) -> dict[str, Any]:
    """One committed parent observation and one eligible registered child."""

    marks: dict[str, Any] = {}
    slow_started = threading.Event()

    def observe(name: str) -> ProbeObservation:
        now = datetime.now(UTC)
        return ProbeObservation(
            summary=f"Synthetic {name} observation",
            facts={"synthetic": name},
            observed_at=now,
            captured_at=now,
        )

    def parent(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        slow_started.wait(timeout=2)
        return observe("parent")

    def slow(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        slow_started.set()
        time.sleep(2)
        return observe("unrelated")

    def child(_parameters: dict[str, JsonValue]) -> ProbeObservation:
        marks["child_started_ns"] = time.perf_counter_ns()
        return observe("child")

    definitions = (
        _definition("core.system", "core", parent),
        _definition("storage.snapshot", "storage", slow),
        _definition("devices.snapshot", "devices", child),
    )
    capabilities = (
        ProbeCapability(
            probe_id="core.system",
            description="Synthetic system",
            cost_ms=1000,
            resource_class=ResourceClass.CPU,
        ),
        ProbeCapability(
            probe_id="storage.snapshot",
            description="Synthetic storage",
            cost_ms=1000,
            resource_class=ResourceClass.DISK,
        ),
        ProbeCapability(
            probe_id="devices.snapshot",
            description="Synthetic device",
            cost_ms=1000,
            resource_class=ResourceClass.PROCESS,
            keywords=frozenset({"fps"}),
        ),
    )
    runtime = DiagnosticRuntime(
        store=store,
        case_service=CaseService(
            store,
            DeterministicPlanner(
                candidates=tuple(
                    ProbeCandidate(
                        probe_id=item.probe_id, cost_ms=item.cost_ms, value=1, common=True
                    )
                    for item in capabilities
                )
            ),
        ),
        probe_runner=ProbeRunner(definitions=definitions),
    )
    app = Investigator(
        store=store,
        runtime=runtime,
        capabilities=capabilities,
        decision=provider,
        reasoning=UnavailableReasoningProvider(),
    )
    original_execute = runtime.execute_plan
    original_decide = provider.decide
    original_validate = DecisionResponse.validate_against
    original_admit = FollowupAdmissionRepository.admit
    case = app.create(
        objective="Synthetic device fps investigation", budget_ms=20_000, max_probes=3
    )
    case = InvestigationRepository(store).save(
        case.model_copy(update={"status": InvestigationStatus.RUNNING}),
        expected_version=case.state_version,
        event="benchmark_started",
        detail="synthetic local latency trial",
    )
    case_id = str(case.case_id)

    def execute(*args: Any, **kwargs: Any) -> Any:
        def persisted(run: ProbeRun) -> None:
            if run.probe_id == "core.system":
                marks["persisted_ns"] = time.perf_counter_ns()
                marks["parent_execution_id"] = str(run.execution_id)

        kwargs["on_persisted"] = persisted
        return original_execute(*args, **kwargs)

    def is_parent_followup(request: DecisionRequest) -> bool:
        parent_id = marks.get("parent_execution_id")
        return parent_id is not None and request.correlation_id.endswith(f":{parent_id}")

    def decide(request: DecisionRequest) -> DecisionResponse:
        if is_parent_followup(request):
            marks["inference_started_ns"] = time.perf_counter_ns()
        try:
            result = original_decide(request)
            if is_parent_followup(request):
                marks["degraded"] = result.degraded
            return result
        finally:
            if is_parent_followup(request):
                marks["inference_finished_ns"] = time.perf_counter_ns()

    def validate(response: DecisionResponse, request: DecisionRequest) -> DecisionResponse:
        if is_parent_followup(request):
            marks["validation_started_ns"] = time.perf_counter_ns()
        try:
            return original_validate(response, request)
        finally:
            if is_parent_followup(request):
                marks["validation_finished_ns"] = time.perf_counter_ns()

    def admit(repository: FollowupAdmissionRepository, **kwargs: Any) -> Any:
        if kwargs.get("case_id") == case_id:
            marks["admission_started_ns"] = time.perf_counter_ns()
        try:
            result = original_admit(repository, **kwargs)
            if kwargs.get("case_id") == case_id:
                marks["admitted_ns"] = time.perf_counter_ns()
            return result
        except Exception:
            if kwargs.get("case_id") == case_id:
                marks["admission_failed_ns"] = time.perf_counter_ns()
            raise

    cast(Any, runtime).execute_plan = execute
    cast(Any, provider).decide = decide
    try:
        with (
            patch.object(DecisionResponse, "validate_against", validate),
            patch.object(FollowupAdmissionRepository, "admit", admit),
        ):
            app._collect(  # pyright: ignore[reportPrivateUsage]
                case,
                (
                    ProbeProposal(
                        probe_id="core.system",
                        purpose=DiagnosticPurpose.CHECK_COVERAGE,
                        priority=1,
                        estimated_cost_ms=1000,
                        resource_class=ResourceClass.CPU,
                        dedupe_key="parent",
                    ),
                    ProbeProposal(
                        probe_id="storage.snapshot",
                        purpose=DiagnosticPurpose.CHECK_COVERAGE,
                        priority=1,
                        estimated_cost_ms=1000,
                        resource_class=ResourceClass.DISK,
                        dedupe_key="slow",
                    ),
                ),
                None,
                baseline=True,
            )
    except Exception as error:
        marks["harness_error"] = type(error).__name__
    finally:
        cast(Any, provider).decide = original_decide
        cast(Any, runtime).execute_plan = original_execute

    parent_id = marks.get("parent_execution_id")
    if parent_id is not None:
        row = store.connection.execute(
            "SELECT COUNT(*) FROM evidence WHERE case_id=? AND execution_id=?",
            (case_id, parent_id),
        ).fetchone()
        if row is None or int(row[0]) != 1:
            marks.pop("persisted_ns", None)
            marks["harness_error"] = "parent_evidence_custody_failed"
    admissions = store.connection.execute(
        "SELECT COUNT(*) FROM collection_followup_admissions WHERE case_id=? AND "
        "trigger_execution_id=?",
        (case_id, parent_id or ""),
    ).fetchone()
    if admissions is None or int(admissions[0]) != int("admitted_ns" in marks):
        marks.pop("admitted_ns", None)
        marks["harness_error"] = "admission_readback_mismatch"
    if "admitted_ns" not in marks:
        marks["miss_reason"] = (
            "parent_not_persisted"
            if "persisted_ns" not in marks
            else "provider_degraded"
            if marks.get("degraded")
            else "admission_rejected"
            if "admission_failed_ns" in marks
            else "followup_not_admitted"
        )
    return marks


def measure(
    profile_path: Path,
    output_path: Path,
    *,
    attempts: int = 3,
    allow_ambient_gpu: bool = False,
) -> dict[str, Any]:
    if not 1 <= attempts <= 8:
        raise ValueError("attempts must be between 1 and 8")
    if output_path.exists():
        raise FileExistsError(output_path)
    profile = load_inference_profile(profile_path)
    config = profile.laya.runtime_config()
    manifest = config.validate_install()
    report: dict[str, Any] = {
        "schema_version": 1,
        "kind": "local_pinned_laya_event_admission_v1",
        "scope": "synthetic local observations through production persisted follow-up path",
        "clock": "time.perf_counter_ns",
        "clock_resolution_ns": round(time.get_clock_info("perf_counter").resolution * 1e9),
        "diagnostic_utility_claim": False,
        "gpu_isolation": "unverified_ambient" if allow_ambient_gpu else "strict_idle",
        "engineering_target_admissible": not allow_ambient_gpu,
        "benchmark_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "profile_sha256": hashlib.sha256(profile_path.read_bytes()).hexdigest(),
        "weight_sha256": manifest.weight_sha256,
        "attempts_requested": attempts,
        "status": "blocked",
        "limitations": [
            "synthetic observations have no diagnostic correctness oracle",
            "pre-inference interval includes queue wait and request preparation",
            "post-validation interval includes snapshot and scheduler handoff",
            "prewarmed worker excludes cold model startup from event latency",
            "one local host and serial cases do not establish general host performance",
        ],
    }
    if allow_ambient_gpu:
        report["limitations"].append(
            "ambient GPU activity may affect latency; this run cannot qualify the 400 ms target"
        )
    try:
        initial_gate = _gpu_gate_reason(
            config.cuda_device_index, allow_ambient_gpu=allow_ambient_gpu
        )
        if initial_gate is not None:
            report["reason"] = initial_gate
            return report
        setup_started = time.perf_counter_ns()
        providers, admission = _managed_providers(profile)
        report["provider_setup_ms"] = (time.perf_counter_ns() - setup_started) / _NS_PER_MS
        try:
            prewarm_started = time.perf_counter_ns()
            providers.prewarm_laya(timeout_seconds=90)
            report["prewarm_ms"] = (time.perf_counter_ns() - prewarm_started) / _NS_PER_MS
            managed_status = admission.status
            report["managed_laya_after_prewarm"] = {
                "phase": managed_status.phase,
                "reason": managed_status.reason,
                "worker_pid": managed_status.worker_pid,
            }
            report["visible_laya_processes_after_prewarm"] = _laya_worker_processes()
            if type(providers.decision) is not LayaDecisionProvider:
                raise RuntimeError("managed pinned Laya decision unavailable")
            records: list[dict[str, Any]] = []
            with tempfile.TemporaryDirectory(prefix="systemsense-real-laya-latency-") as directory:
                for _ in range(attempts):
                    gate_reason, resource_wait_ms = _await_gpu_capacity(
                        config.cuda_device_index,
                        owned_laya_pid=admission.status.worker_pid,
                        allow_ambient_gpu=allow_ambient_gpu,
                    )
                    if gate_reason is not None:
                        records.append(
                            {
                                "persisted_ns": None,
                                "admitted_ns": None,
                                "miss_reason": "resource_gate_closed",
                                "gpu_gate_reason": gate_reason,
                                "resource_wait_ms": resource_wait_ms,
                            }
                        )
                        continue
                    with SQLiteStore(Path(directory) / f"case-{len(records) + 1}.db") as store:
                        record = run_local_trial(store, providers.decision)
                        record["resource_wait_ms"] = resource_wait_ms
                        records.append(record)
            report.update(summarize_attempts(records))
            phases = {
                "pre_inference_queue_and_request": ("persisted_ns", "inference_started_ns"),
                "inference": ("inference_started_ns", "inference_finished_ns"),
                "validation": ("validation_started_ns", "validation_finished_ns"),
                "post_validation_and_scheduler": ("validation_finished_ns", "admission_started_ns"),
                "admission_commit": ("admission_started_ns", "admitted_ns"),
            }
            report["phase_ms"] = {
                name: _phase_stats(records, start, end) for name, (start, end) in phases.items()
            }
            report["attempts_detail"] = [_attempt_detail(item) for item in records]
            report["status"] = (
                "complete"
                if report["misses"] == 0 and all("harness_error" not in item for item in records)
                else "partial"
            )
        finally:
            providers.close()
    except Exception as error:
        report["status"] = "failed"
        report["reason"] = type(error).__name__
    finally:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, sort_keys=True, allow_nan=False)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--attempts", type=int, default=3)
    parser.add_argument(
        "--allow-ambient-gpu",
        action="store_true",
        help="Run a capacity-bounded, non-isolated local trial; never qualifies latency",
    )
    args = parser.parse_args()
    result = measure(
        args.profile,
        args.output,
        attempts=args.attempts,
        allow_ambient_gpu=args.allow_ambient_gpu,
    )
    print(json.dumps({"output": str(args.output), "status": result["status"]}))
    if result["status"] != "complete":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
