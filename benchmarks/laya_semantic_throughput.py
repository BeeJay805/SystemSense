"""Opt-in pinned-Laya semantic-packet throughput on the current host only.

Synthetic evidence has no fault oracle. This measures worker throughput, not
probe utility, diagnostic accuracy, or suitability for an ordinary laptop.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import subprocess
import threading
import time
from collections.abc import Callable, Sequence
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import cast

import psutil

from systemsense.decision import semantic_packets
from systemsense.domain.ids import EvidenceId, JsonValue
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.inference.laya_runtime import (
    LayaAttentionResult,
    LayaRuntimeConfig,
    LayaSubprocessRuntime,
    LayaWorkerPresentation,
)
from systemsense.inference.profile import load_inference_profile

_PACKET_COUNT = 8
_CANDIDATE_COUNT = 20
_WARM_RUNS = 3
_MAX_TOTAL_SECONDS = 240
_DEFAULT_TOTAL_SECONDS = 180
_MIN_FREE_RAM_BYTES = 5 * 1024**3
_SYNTHETIC_METRICS: tuple[tuple[str, JsonValue], ...] = (
    ("gpu.clock", {"value": 450, "unit": "MHz"}),
    ("gpu.power_limit", {"value": 60, "unit": "percent"}),
    ("wifi.signal", {"value": -72, "unit": "dBm"}),
    ("network.packet_loss", {"value": 8, "unit": "percent"}),
    ("storage.read_latency", {"value": 85, "unit": "ms"}),
    ("process.cpu_usage", {"value": 72, "unit": "percent"}),
    ("driver.problem_code", 0),
    ("application.frame_time", {"value": 82, "unit": "ms"}),
    ("thermal.temperature", {"value": 94, "unit": "C"}),
    ("power.plan", "balanced"),
    ("process.memory_pressure", {"value": 88, "unit": "percent"}),
    ("disk.queue_depth", 9),
    ("network.adapter_state", "connected"),
    ("driver.version", "synthetic-1.0"),
    ("service.startup_type", "automatic"),
    ("application.gpu_engine", "integrated"),
)


def synthetic_workload(
    run_index: int, *, packet_count: int = _PACKET_COUNT
) -> tuple[dict[str, object], tuple[dict[str, str], ...], tuple[dict[str, str], ...]]:
    """Make 4/8/16 per-fact packets and 20 non-executable probe descriptions."""

    if run_index < 0:
        raise ValueError("run index must be nonnegative")
    if packet_count not in (4, 8, 16):
        raise ValueError("packet_count must be 4, 8, or 16")
    observed = datetime(2026, 1, 1, tzinfo=UTC) + timedelta(minutes=run_index)
    contexts = tuple(
        EvidenceContext(
            evidence_id=EvidenceId(root=f"ev_{run_index * 100 + index + 1:032x}"),
            observed_at=observed,
            captured_at=observed + timedelta(milliseconds=25),
            probe_id=f"synthetic.source.{index}",
            summary="Synthetic runtime-only measurement",
            facts={metric: value},
            status=EvidenceContextStatus.OBSERVED,
            case_scope="current_case",
            incident_relevant=True,
        )
        for index, (metric, value) in enumerate(_SYNTHETIC_METRICS[:packet_count])
    )
    evidence = semantic_packets.evidence_packets(contexts)
    candidates = tuple(
        {
            "probe_id": f"synthetic.probe.{run_index}.{index:02}",
            "description": (
                "Synthetic read-only investigation option "
                f"{index:02}: inspect {_SYNTHETIC_METRICS[index % packet_count][0]} "
                "and related synthetic context; no probe is executed"
            ),
        }
        for index in range(_CANDIDATE_COUNT)
    )
    state: dict[str, object] = {
        "attention_kind": "synthetic_semantic_throughput",
        "evidence_serializer": semantic_packets.SERIALIZER_ID,
        "symptom": f"Synthetic multi-component performance incident {run_index}",
        "coverage_notes": ("synthetic_runtime_only",),
    }
    return state, evidence, candidates


def packet_count_schedule(batch_size_index: int) -> tuple[int, ...]:
    """Rotate 4/8/16 positions within each worker to reduce warm-order bias."""

    if batch_size_index not in (0, 1, 2):
        raise ValueError("batch size index must be 0..2")
    sizes = (4, 8, 16)
    return tuple(
        sizes[(position + batch_size_index + repeat) % 3]
        for repeat in range(3)
        for position in range(3)
    )


def nearest_rank_percentile(values: list[float], percentile: int) -> float:
    if not values or not 0 < percentile <= 100:
        raise ValueError("percentile requires nonempty measurements and 1..100")
    ordered = sorted(values)
    return ordered[math.ceil(len(ordered) * percentile / 100) - 1]


def verify_attention(
    result: LayaAttentionResult,
    evidence: tuple[dict[str, str], ...],
    candidates: tuple[dict[str, str], ...],
) -> dict[str, int]:
    expected_evidence = tuple(item["fragment_id"] for item in evidence)
    expected_probes = tuple(item["probe_id"] for item in candidates)
    evidence_batches = tuple(item for item in result.microbatches if item.phase == "evidence")
    probe_batches = tuple(item for item in result.microbatches if item.phase == "probe")
    presented_evidence = tuple(item for batch in evidence_batches for item in batch.candidate_ids)
    presented_probes = tuple(item for batch in probe_batches for item in batch.candidate_ids)
    if presented_evidence != expected_evidence or presented_probes != expected_probes:
        raise ValueError("worker did not cover all synthetic candidate IDs in order")
    if set(result.considered_attention_page_ids) != {item["page_id"] for item in evidence} or set(
        result.considered_probe_ids
    ) != set(expected_probes):
        raise ValueError("worker attention coverage incomplete")
    if any(
        batch.cache_hit_ids or batch.inference_ids != batch.candidate_ids
        for batch in result.microbatches
    ):
        raise ValueError("cache hit or inference miss contaminated throughput")
    if any(batch.worker_presentation is None for batch in result.microbatches):
        raise ValueError("worker presentation attestation missing")
    for required in (
        "coverage_limited=false",
        "state_truncated_batches=0",
        "instruction_truncated_items=0",
    ):
        if required not in result.attention_notes:
            raise ValueError("truncation or coverage limit contaminated throughput")
    return {
        "judgments": len(expected_evidence) + len(expected_probes),
        "evidence_packets": len(expected_evidence),
        "probe_candidates": len(expected_probes),
        "cache_hits": 0,
    }


def write_exclusive(output_path: Path, report: dict[str, object]) -> None:
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)


def _gpu_sample() -> dict[str, int] | None:
    try:
        result = subprocess.run(
            [
                "nvidia-smi",
                "--query-gpu=memory.total,memory.used,memory.free,utilization.gpu",
                "--format=csv,noheader,nounits",
            ],
            capture_output=True,
            text=True,
            timeout=3,
            check=True,
        )
        values = [int(item.strip()) for item in result.stdout.splitlines()[0].split(",")]
        if len(values) != 4:
            return None
        return dict(
            zip(("total_mb", "used_mb", "free_mb", "utilization_percent"), values, strict=True)
        )
    except (OSError, subprocess.SubprocessError, ValueError, IndexError):
        return None


def _foreign_laya_workers() -> tuple[int, ...]:
    found: list[int] = []
    for process in psutil.process_iter(("pid", "cmdline")):
        try:
            raw_command: object = process.info.get("cmdline")
            command: Sequence[object] = (
                cast(Sequence[object], raw_command)
                if isinstance(raw_command, (list, tuple))
                else ()
            )
            if any("laya_worker.py" in str(part).casefold() for part in command):
                found.append(cast(int, process.info["pid"]))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return tuple(found)


def _owned_rss_bytes() -> int:
    parent = psutil.Process()
    total = 0
    for process in (parent, *parent.children(recursive=True)):
        try:
            total += process.memory_info().rss
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return total


def measure(
    profile_path: Path, output_path: Path, *, max_seconds: int = _DEFAULT_TOTAL_SECONDS
) -> dict[str, object]:
    """Run one cold first judgment and three distinct warm attention passes."""

    if not 30 <= max_seconds <= _MAX_TOTAL_SECONDS:
        raise ValueError("max_seconds must be 30..240")
    if output_path.exists():
        raise FileExistsError(output_path)
    profile = load_inference_profile(profile_path)
    if not profile.laya.enabled:
        raise RuntimeError("profile has no enabled pinned Laya")
    config = profile.laya.runtime_config()
    manifest = config.validate_install()
    gpu_before = _gpu_sample()
    if config.device == "cuda" and (
        gpu_before is None or gpu_before["free_mb"] < config.min_free_vram_mb + 1024
    ):
        raise RuntimeError("GPU availability gate rejected pinned Laya benchmark")
    foreign = _foreign_laya_workers()
    if foreign:
        raise RuntimeError("another Laya worker is running; benchmark will not take ownership")
    ram_before = psutil.virtual_memory().available
    if ram_before < _MIN_FREE_RAM_BYTES:
        raise RuntimeError("less than 5 GiB RAM available")

    started = time.monotonic()
    stop = threading.Event()
    samples: dict[str, object] = {
        "peak_owned_process_tree_rss_bytes": _owned_rss_bytes(),
        "peak_global_gpu_used_mb": gpu_before["used_mb"] if gpu_before else None,
        "rss_samples": 0,
        "gpu_samples": 0,
    }

    def sample() -> None:
        while not stop.wait(0.5):
            samples["peak_owned_process_tree_rss_bytes"] = max(
                cast(int, samples["peak_owned_process_tree_rss_bytes"]), _owned_rss_bytes()
            )
            samples["rss_samples"] = cast(int, samples["rss_samples"]) + 1
            gpu = _gpu_sample()
            if gpu is not None:
                samples["peak_global_gpu_used_mb"] = max(
                    cast(int, samples["peak_global_gpu_used_mb"] or 0), gpu["used_mb"]
                )
                samples["gpu_samples"] = cast(int, samples["gpu_samples"]) + 1

    monitor = threading.Thread(target=sample, daemon=True)
    runtime = LayaSubprocessRuntime(config)
    report: dict[str, object] = {
        "classification": "host_synthetic_semantic_packet_runtime_only",
        "status": "in_progress",
        "diagnostic_utility_claim": False,
        "ordinary_laptop_qualified": False,
        "training_admissible": False,
        "host": {"system": platform.system(), "release": platform.release()},
        "device": config.device,
        "precision": config.precision,
        "batch_size": config.max_candidates_per_batch,
        "model": {
            "repository": manifest.model_repository,
            "revision": manifest.model_revision,
            "weight_sha256": manifest.weight_sha256,
            "package_wheel_sha256": manifest.package_wheel_sha256,
        },
        "serializer": {
            "id": semantic_packets.SERIALIZER_ID,
            "source_sha256": hashlib.sha256(
                Path(semantic_packets.__file__).read_bytes()
            ).hexdigest(),
        },
        "profile_sha256": hashlib.sha256(profile_path.read_bytes()).hexdigest(),
        "benchmark_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "ram_available_before_bytes": ram_before,
        "gpu_before": gpu_before,
        "cold_first_judgment_seconds": None,
        "warm_runs": [],
        "failure": None,
        "limitations": [
            "synthetic packets and probe descriptions have no diagnostic oracle",
            "cold first judgment includes hash verification, model load, and one inference; "
            "pure startup is not isolated",
            "global GPU memory is sampled but WDDM does not provide owned-process VRAM here",
            "0.5-second sampling can miss shorter memory spikes",
            "one RTX 4090 desktop does not qualify everyday laptops",
        ],
    }
    monitor.start()
    try:
        cold_started = time.monotonic()
        runtime.rank(
            state={"attention_kind": "cold_readiness", "symptom": "synthetic startup"},
            candidates=(
                {"probe_id": "synthetic.cold.ready", "description": "Synthetic cold readiness"},
            ),
            timeout_seconds=min(90, max_seconds),
        )
        report["cold_first_judgment_seconds"] = time.monotonic() - cold_started
        warm: list[dict[str, object]] = []
        for run_index in range(_WARM_RUNS):
            remaining = max_seconds - (time.monotonic() - started)
            if remaining < 5:
                raise TimeoutError("overall benchmark deadline reached before warm pass")
            state, evidence, candidates = synthetic_workload(run_index)
            run_started = time.monotonic()
            result = runtime.attend(
                state=state,
                evidence=evidence,
                candidates=candidates,
                timeout_seconds=min(90, remaining),
            )
            elapsed = time.monotonic() - run_started
            record: dict[str, object] = {
                "run_index": run_index,
                "seconds": elapsed,
                "considered_pages": len(result.considered_attention_page_ids),
                "considered_probes": len(result.considered_probe_ids),
                "attention_notes": result.attention_notes,
            }
            warm.append(record)
            report["warm_runs"] = warm
            verified = verify_attention(result, evidence, candidates)
            record.update(verified)
            record["judgments_per_second"] = verified["judgments"] / elapsed
            record["probe_judgments_per_second"] = verified["probe_candidates"] / elapsed
        times = [cast(float, item["seconds"]) for item in warm]
        report["warm_latency_p50_seconds"] = nearest_rank_percentile(times, 50)
        report["warm_latency_p95_seconds"] = nearest_rank_percentile(times, 95)
        report["percentile_method"] = "nearest_rank_n_3"
        report["aggregate_warm_judgments_per_second"] = (
            _WARM_RUNS * (_PACKET_COUNT + _CANDIDATE_COUNT) / sum(times)
        )
        report["aggregate_warm_probe_judgments_per_second"] = (
            _WARM_RUNS * _CANDIDATE_COUNT / sum(times)
        )
        report["status"] = "complete"
    except Exception as error:
        report["status"] = "failed"
        report["failure"] = f"{type(error).__name__}: {error}"
    finally:
        stop.set()
        monitor.join(timeout=3)
        runtime.close()
        samples["peak_owned_process_tree_rss_bytes"] = max(
            cast(int, samples["peak_owned_process_tree_rss_bytes"]), _owned_rss_bytes()
        )
        report["resource_samples"] = samples
        report["gpu_after"] = _gpu_sample()
        report["total_seconds"] = time.monotonic() - started
        write_exclusive(output_path, report)
    return report


def summarize_sweep(attempts: list[dict[str, object]]) -> dict[str, dict[str, object]]:
    """Compute per-cell nearest-rank latency without counting failed runs as wins."""

    summary: dict[str, dict[str, object]] = {}
    for batch_size in (4, 8, 20):
        for packet_count in (4, 8, 16):
            cell = [
                item
                for item in attempts
                if item.get("batch_size") == batch_size and item.get("packet_count") == packet_count
            ]
            valid = [
                float(cast(float | int, item["seconds"]))
                for item in cell
                if item.get("status") == "complete"
                and isinstance(item.get("seconds"), (float, int))
            ]
            p50 = nearest_rank_percentile(valid, 50) if valid else None
            p95 = nearest_rank_percentile(valid, 95) if valid else None
            summary[f"batch_{batch_size}_packets_{packet_count}"] = {
                "attempts": len(cell),
                "valid": len(valid),
                "p50_seconds": p50,
                "p95_seconds": p95,
                "p95_below_400ms_with_three_valid_runs": (
                    len(valid) == 3 and p95 is not None and p95 < 0.4
                ),
                "planned_worker_calls_per_attempt": (
                    math.ceil(packet_count / batch_size) + math.ceil(_CANDIDATE_COUNT / batch_size)
                ),
            }
    return summary


def summarize_rank_calls(
    calls: list[dict[str, object]], *, evidence_count: int, probe_count: int, batch_size: int
) -> dict[str, float | int]:
    """Require one uncached worker call per planned batch in each attention phase."""

    expected = [
        ("evidence", min(batch_size, evidence_count - start))
        for start in range(0, evidence_count, batch_size)
    ] + [
        ("probe", min(batch_size, probe_count - start))
        for start in range(0, probe_count, batch_size)
    ]
    actual = [(item.get("phase"), item.get("candidates")) for item in calls]
    if actual != expected or any(item.get("status") != "complete" for item in calls):
        raise ValueError("worker-call phase or candidate coverage incomplete")
    evidence_batches = math.ceil(evidence_count / batch_size)
    evidence_seconds = sum(float(cast(float, item["seconds"])) for item in calls[:evidence_batches])
    probe_seconds = sum(float(cast(float, item["seconds"])) for item in calls[evidence_batches:])
    return {
        "worker_calls": len(calls),
        "evidence_worker_seconds": evidence_seconds,
        "probe_worker_seconds": probe_seconds,
        "worker_call_seconds": evidence_seconds + probe_seconds,
    }


class TimedLayaRuntime(LayaSubprocessRuntime):
    """Instrument the admitted worker without changing its requests or answers."""

    def __init__(self, config: LayaRuntimeConfig) -> None:
        super().__init__(config)
        self.rank_calls: list[dict[str, object]] = []

    def rank(
        self,
        *,
        state: dict[str, object],
        candidates: tuple[dict[str, str], ...],
        timeout_seconds: float,
        capture_exact_worker_call: Callable[[dict[str, object], LayaWorkerPresentation], None]
        | None = None,
    ) -> tuple[str, ...]:
        started = time.monotonic()
        record: dict[str, object] = {
            "phase": (
                "evidence" if state.get("attention_kind") == "evidence_relevance" else "probe"
            ),
            "candidates": len(candidates),
            "status": "in_progress",
        }
        self.rank_calls.append(record)
        try:
            result = super().rank(
                state=state,
                candidates=candidates,
                timeout_seconds=timeout_seconds,
                capture_exact_worker_call=capture_exact_worker_call,
            )
            record["status"] = "complete"
            return result
        except Exception as error:
            record["status"] = "failed"
            record["failure"] = f"{type(error).__name__}: {error}"
            raise
        finally:
            record["seconds"] = time.monotonic() - started


def measure_sweep(
    profile_path: Path, output_path: Path, *, max_seconds: int = _DEFAULT_TOTAL_SECONDS
) -> dict[str, object]:
    """Counterbalance 4/8/16 packet loads on one owned worker per batch size.

    Runtime batch size is fixed at construction. Three workers are therefore
    used sequentially, never concurrently; each performs one cold first
    judgment followed by nine distinct warm, all-miss attention passes.
    """

    if not 60 <= max_seconds <= _MAX_TOTAL_SECONDS:
        raise ValueError("sweep max_seconds must be 60..240")
    if output_path.exists():
        raise FileExistsError(output_path)
    profile = load_inference_profile(profile_path)
    if not profile.laya.enabled:
        raise RuntimeError("profile has no enabled pinned Laya")
    base_config = profile.laya.runtime_config()
    manifest = base_config.validate_install()
    gpu_before = _gpu_sample()
    if base_config.device == "cuda" and (
        gpu_before is None or gpu_before["free_mb"] < base_config.min_free_vram_mb + 1024
    ):
        raise RuntimeError("GPU availability gate rejected pinned Laya sweep")
    if _foreign_laya_workers():
        raise RuntimeError("another Laya worker is running; sweep will not take ownership")
    ram_before = psutil.virtual_memory().available
    if ram_before < _MIN_FREE_RAM_BYTES:
        raise RuntimeError("less than 5 GiB RAM available")

    started = time.monotonic()
    stop = threading.Event()
    samples: dict[str, object] = {
        "peak_owned_process_tree_rss_bytes": _owned_rss_bytes(),
        "peak_global_gpu_used_mb": gpu_before["used_mb"] if gpu_before else None,
        "rss_samples": 0,
        "gpu_samples": 0,
    }

    def sample() -> None:
        while not stop.wait(0.5):
            samples["peak_owned_process_tree_rss_bytes"] = max(
                cast(int, samples["peak_owned_process_tree_rss_bytes"]), _owned_rss_bytes()
            )
            samples["rss_samples"] = cast(int, samples["rss_samples"]) + 1
            gpu = _gpu_sample()
            if gpu is not None:
                samples["peak_global_gpu_used_mb"] = max(
                    cast(int, samples["peak_global_gpu_used_mb"] or 0), gpu["used_mb"]
                )
                samples["gpu_samples"] = cast(int, samples["gpu_samples"]) + 1

    attempts: list[dict[str, object]] = []
    cold: list[dict[str, object]] = []
    report: dict[str, object] = {
        "classification": "host_synthetic_semantic_packet_batch_sweep_only",
        "status": "in_progress",
        "diagnostic_utility_claim": False,
        "ordinary_laptop_qualified": False,
        "training_admissible": False,
        "host": {"system": platform.system(), "release": platform.release()},
        "device": base_config.device,
        "precision": base_config.precision,
        "batch_sizes": [4, 8, 20],
        "packet_counts": [4, 8, 16],
        "warm_repetitions_per_cell": 3,
        "model": {
            "repository": manifest.model_repository,
            "revision": manifest.model_revision,
            "weight_sha256": manifest.weight_sha256,
            "package_wheel_sha256": manifest.package_wheel_sha256,
        },
        "serializer": {
            "id": semantic_packets.SERIALIZER_ID,
            "source_sha256": hashlib.sha256(
                Path(semantic_packets.__file__).read_bytes()
            ).hexdigest(),
        },
        "profile_sha256": hashlib.sha256(profile_path.read_bytes()).hexdigest(),
        "benchmark_source_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "ram_available_before_bytes": ram_before,
        "gpu_before": gpu_before,
        "cold_first_judgments": cold,
        "attempts": attempts,
        "limitations": [
            "synthetic evidence has no useful-probe or diagnostic oracle",
            "cold first judgment includes startup, hash verification, and one inference",
            "one sequential worker per batch size; batch-size order is not counterbalanced",
            "packet-count order rotates within each batch-size worker",
            "global WDDM VRAM is not owned-worker VRAM",
            "0.5-second RSS and VRAM sampling may miss shorter spikes",
            "p95 uses nearest rank over only three repetitions per cell",
            "worker-call spans include IPC and Python preparation; GPU-only time is not isolated",
            "the 0.5-second nvidia-smi observer may perturb individual attempts",
            "one RTX 4090 desktop does not qualify everyday laptops",
        ],
    }
    monitor = threading.Thread(target=sample, daemon=True)
    monitor.start()
    try:
        for batch_index, batch_size in enumerate((4, 8, 20)):
            planned = packet_count_schedule(batch_index)
            gpu_now = _gpu_sample()
            reason: str | None = None
            if _foreign_laya_workers():
                reason = "another Laya worker appeared before this size"
            elif base_config.device == "cuda" and (
                gpu_now is None or gpu_now["free_mb"] < base_config.min_free_vram_mb + 1024
            ):
                reason = "GPU availability gate rejected this size"
            elif psutil.virtual_memory().available < _MIN_FREE_RAM_BYTES:
                reason = "RAM availability gate rejected this size"
            elif max_seconds - (time.monotonic() - started) < 30:
                reason = "overall deadline left too little time for this size"
            if reason is not None:
                cold.append({"batch_size": batch_size, "status": "skipped", "reason": reason})
                attempts.extend(
                    {
                        "batch_size": batch_size,
                        "packet_count": count,
                        "status": "skipped",
                        "reason": reason,
                    }
                    for count in planned
                )
                continue
            config = base_config.model_copy(update={"max_candidates_per_batch": batch_size})
            runtime = TimedLayaRuntime(config)
            failed_worker = False
            try:
                cold_started = time.monotonic()
                runtime.rank(
                    state={"attention_kind": "cold_readiness", "symptom": "synthetic startup"},
                    candidates=(
                        {
                            "probe_id": f"synthetic.cold.{batch_size}",
                            "description": "Synthetic cold readiness",
                        },
                    ),
                    timeout_seconds=min(90, max_seconds - (time.monotonic() - started)),
                )
                cold.append(
                    {
                        "batch_size": batch_size,
                        "status": "complete",
                        "seconds": time.monotonic() - cold_started,
                    }
                )
                for ordinal, packet_count in enumerate(planned):
                    remaining = max_seconds - (time.monotonic() - started)
                    if failed_worker or remaining < 5:
                        attempts.append(
                            {
                                "batch_size": batch_size,
                                "packet_count": packet_count,
                                "ordinal": ordinal,
                                "status": "skipped",
                                "reason": "prior worker failure or overall deadline",
                            }
                        )
                        continue
                    state, evidence, candidates = synthetic_workload(
                        batch_index * 100 + ordinal, packet_count=packet_count
                    )
                    runtime.rank_calls.clear()
                    run_started = time.monotonic()
                    attempt: dict[str, object] = {
                        "batch_size": batch_size,
                        "packet_count": packet_count,
                        "ordinal": ordinal,
                        "status": "in_progress",
                        "planned_worker_calls": (
                            math.ceil(packet_count / batch_size)
                            + math.ceil(_CANDIDATE_COUNT / batch_size)
                        ),
                        "gpu_before": _gpu_sample(),
                        "rss_before_bytes": _owned_rss_bytes(),
                    }
                    attempts.append(attempt)
                    try:
                        result = runtime.attend(
                            state=state,
                            evidence=evidence,
                            candidates=candidates,
                            timeout_seconds=min(90, remaining),
                        )
                        attempt.update(
                            {
                                "seconds": time.monotonic() - run_started,
                                "rank_calls": list(runtime.rank_calls),
                                "considered_pages": len(result.considered_attention_page_ids),
                                "considered_probes": len(result.considered_probe_ids),
                                "attention_notes": result.attention_notes,
                                "cache_hits": sum(
                                    len(item.cache_hit_ids) for item in result.microbatches
                                ),
                            }
                        )
                        verified = verify_attention(result, evidence, candidates)
                        call_summary = summarize_rank_calls(
                            runtime.rank_calls,
                            evidence_count=packet_count,
                            probe_count=_CANDIDATE_COUNT,
                            batch_size=batch_size,
                        )
                        attempt.update(verified)
                        attempt.update(call_summary)
                        attempt["non_worker_seconds"] = max(
                            0.0,
                            cast(float, attempt["seconds"])
                            - cast(float, call_summary["worker_call_seconds"]),
                        )
                        attempt["status"] = "complete"
                        attempt["judgments_per_second"] = verified["judgments"] / cast(
                            float, attempt["seconds"]
                        )
                    except Exception as error:
                        attempt["status"] = "failed"
                        attempt["failure"] = f"{type(error).__name__}: {error}"
                        attempt["rank_calls"] = list(runtime.rank_calls)
                        if "attention_notes" not in attempt:
                            failed_worker = True
                    finally:
                        attempt["gpu_after"] = _gpu_sample()
                        attempt["rss_after_bytes"] = _owned_rss_bytes()
            except Exception as error:
                cold.append(
                    {
                        "batch_size": batch_size,
                        "status": "failed",
                        "failure": f"{type(error).__name__}: {error}",
                    }
                )
                attempts.extend(
                    {
                        "batch_size": batch_size,
                        "packet_count": count,
                        "status": "skipped",
                        "reason": "cold worker failed",
                    }
                    for count in planned
                )
            finally:
                runtime.close()
        report["summary"] = summarize_sweep(attempts)
        report["status"] = (
            "complete"
            if len(attempts) == 27 and all(item["status"] == "complete" for item in attempts)
            else "partial_or_failed"
        )
    finally:
        stop.set()
        monitor.join(timeout=3)
        samples["peak_owned_process_tree_rss_bytes"] = max(
            cast(int, samples["peak_owned_process_tree_rss_bytes"]), _owned_rss_bytes()
        )
        report["resource_samples"] = samples
        report["gpu_after"] = _gpu_sample()
        report["total_seconds"] = time.monotonic() - started
        write_exclusive(output_path, report)
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--max-seconds", type=int, default=_DEFAULT_TOTAL_SECONDS)
    parser.add_argument("--sweep", action="store_true")
    args = parser.parse_args()
    report = (
        measure_sweep(args.profile, args.output, max_seconds=args.max_seconds)
        if args.sweep
        else measure(args.profile, args.output, max_seconds=args.max_seconds)
    )
    print(json.dumps(report, indent=2, sort_keys=True))
    if report["status"] != "complete":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
