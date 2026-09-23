"""Opt-in desktop CPU runtime measurement for pinned Laya attention.

This uses synthetic previews and registered probe names. It measures runtime
and host-process memory, not Windows probe-choice quality or laptop fitness.
No GPU, network call, model download, collector, or repair is started.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Protocol, cast

import psutil

from systemsense.application.bootstrap import default_capabilities
from systemsense.inference.laya_runtime import LayaSubprocessRuntime
from systemsense.inference.profile import load_inference_profile

_MIN_FREE_RAM_BYTES = 8 * 1024**3
_PAGE_COUNT = 54
_SWEEP_ORDERS = ((4, 8, 20), (8, 20, 4), (20, 4, 8))


def representative_batch(
    symptom: str,
) -> tuple[dict[str, object], tuple[dict[str, str], ...], tuple[dict[str, str], ...]]:
    """Create bounded, explicitly synthetic full-coverage attention input."""

    state: dict[str, object] = {
        "symptom": symptom,
        "coverage_notes": ("evidence_pages_are_bounded_previews", "synthetic_runtime_only"),
    }
    evidence = tuple(
        {
            "evidence_id": f"synthetic-evidence-{index // 3}",
            "page_id": f"synthetic-page-{index}",
            "fragment_id": f"synthetic-page-{index}:preview:0",
            "description": json.dumps(
                {
                    "projection": "bounded_preview_not_full_page",
                    "probe_id": ("gpu.telemetry.sample" if index % 3 == 0 else "pressure.sample"),
                    "status": "observed",
                    "facts": {
                        "sample": index,
                        "gpu_utilization_percent": (index * 7) % 100,
                        "cpu_percent": (index * 11) % 100,
                    },
                    "facts_omitted": 0,
                },
                separators=(",", ":"),
            ),
        }
        for index in range(_PAGE_COUNT)
    )
    candidates = tuple(
        {"probe_id": capability.probe_id, "description": capability.description[:240]}
        for capability in default_capabilities()
    )
    return state, evidence, candidates


def _owned_rss_bytes() -> int:
    parent = psutil.Process()
    processes = (parent, *parent.children(recursive=True))
    total = 0
    for process in processes:
        try:
            total += process.memory_info().rss
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return total


def _sample_owned_memory(stop: threading.Event, peak_rss: list[int]) -> None:
    while not stop.wait(0.05):
        peak_rss[0] = max(peak_rss[0], _owned_rss_bytes())


def _persist_sweep_report(
    output_path: Path, report: dict[str, object], *, reserve: bool = False
) -> None:
    """Exclusively reserve once, then atomically replace only this sweep's progress."""

    if reserve:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        with output_path.open("x", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        return
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=output_path.parent,
            prefix=f".{output_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary_path = Path(stream.name)
            json.dump(report, stream, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_path, output_path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


class _ObservedWorker(Protocol):
    def poll(self) -> int | None: ...

    def wait(self, timeout: float | None = None) -> int: ...


def _active_worker(runtime: LayaSubprocessRuntime) -> _ObservedWorker | None:
    """Observe this pinned adapter's owned process, without starting another one."""

    raw = getattr(runtime, "_process", None)
    if raw is None:
        return None
    worker = cast(_ObservedWorker, raw)
    try:
        return worker if worker.poll() is None else None
    except Exception:
        return None


def _worker_stopped(worker: _ObservedWorker) -> bool:
    try:
        worker.wait(timeout=2)
        return worker.poll() is not None
    except Exception:
        return False


def _model_input_complete(notes: tuple[str, ...]) -> bool:
    return all(
        [note for note in notes if note.startswith(prefix + "=")] == [expected]
        for prefix, expected in (
            ("state_truncated_batches", "state_truncated_batches=0"),
            ("instruction_truncated_items", "instruction_truncated_items=0"),
            ("coverage_limited", "coverage_limited=false"),
        )
    )


def measure(
    profile_path: Path, output_path: Path, *, timeout_seconds: float = 180
) -> dict[str, object]:
    """Measure three distinct states so warm passes cannot use rank-cache hits."""

    available_ram = psutil.virtual_memory().available
    if available_ram < _MIN_FREE_RAM_BYTES:
        raise RuntimeError("less than 8 GiB RAM available; CPU Laya measurement refused")
    if output_path.exists():
        raise FileExistsError(output_path)
    profile = load_inference_profile(profile_path)
    if not profile.laya.enabled:
        raise RuntimeError("profile has no enabled pinned Laya installation")
    config = profile.laya.runtime_config().model_copy(
        update={"device": "cpu", "precision": "float32"}
    )
    manifest = config.validate_install()
    baseline_rss = _owned_rss_bytes()
    runtime = LayaSubprocessRuntime(config)
    stop = threading.Event()
    peak_rss = 0

    def sample_memory() -> None:
        nonlocal peak_rss
        while not stop.wait(0.05):
            peak_rss = max(peak_rss, _owned_rss_bytes())

    monitor = threading.Thread(target=sample_memory, daemon=True)
    monitor.start()
    runs: list[dict[str, object]] = []
    failure: str | None = None
    try:
        for phase, symptom in (
            ("cold", "A game feels slow despite a capable graphics card"),
            ("warm_1", "A PDF viewer has slow page turns"),
            ("warm_2", "The wireless network loses its connection"),
        ):
            state, evidence, candidates = representative_batch(symptom)
            started = time.monotonic()
            result = runtime.attend(
                state=state,
                evidence=evidence,
                candidates=candidates,
                timeout_seconds=timeout_seconds,
            )
            elapsed = time.monotonic() - started
            if len(result.considered_attention_page_ids) != len(evidence) or len(
                result.considered_probe_ids
            ) != len(candidates):
                raise RuntimeError("CPU attention did not cover every synthetic page and probe")
            runs.append(
                {
                    "phase": phase,
                    "elapsed_seconds": elapsed,
                    "pages_considered": len(result.considered_attention_page_ids),
                    "probes_considered": len(result.considered_probe_ids),
                    "attention_notes": result.attention_notes,
                }
            )
    except Exception as error:
        # A missed deadline or worker failure is part of the qualification
        # denominator. Do not lose completed runs merely because a later pass fails.
        failure = type(error).__name__
    finally:
        stop.set()
        monitor.join(timeout=2)
        peak_rss = max(peak_rss, _owned_rss_bytes())
        runtime.close()
    report: dict[str, object] = {
        "classification": "desktop_cpu_synthetic_attention_runtime_only",
        "status": "complete" if failure is None else "failed",
        "failure_type": failure,
        "diagnostic_accuracy_claim": False,
        "ordinary_laptop_qualified": False,
        "device": "cpu",
        "precision": "float32",
        "threads": config.threads,
        "batch_size": config.max_candidates_per_batch,
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "physical_cpu_count": psutil.cpu_count(logical=False),
            "logical_cpu_count": psutil.cpu_count(logical=True),
            "total_ram_bytes": psutil.virtual_memory().total,
            "python_version": sys.version.split()[0],
        },
        "model": {
            "repository": manifest.model_repository,
            "revision": manifest.model_revision,
            "weight_sha256": manifest.weight_sha256,
            "package_version": manifest.package_version,
            "torch_version": manifest.torch_version,
            "transformers_version": manifest.transformers_version,
        },
        "baseline_owned_process_tree_rss_bytes": baseline_rss,
        "available_ram_bytes_before": available_ram,
        "peak_owned_process_tree_rss_bytes": peak_rss,
        "runs": runs,
        "limitations": (
            "synthetic previews do not test useful next-probe ranking",
            "desktop CPU and RAM do not establish ordinary-laptop behavior",
            "50 ms RSS sampling can miss shorter memory spikes",
            "warm passes use distinct symptoms but retain the same worker and model",
        ),
    }
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
    return report


def measure_sweep(
    profile_path: Path, output_path: Path, *, timeout_seconds: float = 180
) -> dict[str, object]:
    """Compare admitted CPU batch sizes without treating synthetic ranking as IT quality.

    Each of the three counterbalanced sessions per size uses a new worker for a
    cold pass, then reuses that worker for a distinct warm pass. Only one
    sweep-owned CPU worker is admitted at a time; unrelated workloads may still
    run. Incomplete coverage and timeouts stay in the output denominator.
    """

    if output_path.exists():
        raise FileExistsError(output_path)
    if not 0 < timeout_seconds <= 180:
        raise ValueError("timeout_seconds must be in (0, 180]")
    available_ram = psutil.virtual_memory().available
    if available_ram < _MIN_FREE_RAM_BYTES:
        raise RuntimeError("less than 8 GiB RAM available; CPU Laya measurement refused")
    profile = load_inference_profile(profile_path)
    if not profile.laya.enabled:
        raise RuntimeError("profile has no enabled pinned Laya installation")
    base_config = profile.laya.runtime_config().model_copy(
        update={"device": "cpu", "precision": "float32"}
    )
    manifest = base_config.validate_install()
    baseline_rss = _owned_rss_bytes()
    runs: list[dict[str, object]] = []
    report: dict[str, object] = {
        "classification": "host_cpu_synthetic_batch_sweep_only",
        "status": "in_progress",
        "diagnostic_accuracy_claim": False,
        "ordinary_laptop_qualified": False,
        "device": "cpu",
        "precision": "float32",
        "threads": base_config.threads,
        "batch_orders": [list(order) for order in _SWEEP_ORDERS],
        "host": {
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "processor": platform.processor(),
            "physical_cpu_count": psutil.cpu_count(logical=False),
            "logical_cpu_count": psutil.cpu_count(logical=True),
            "total_ram_bytes": psutil.virtual_memory().total,
            "python_version": sys.version.split()[0],
        },
        "model": {
            "repository": manifest.model_repository,
            "revision": manifest.model_revision,
            "weight_sha256": manifest.weight_sha256,
            "package_version": manifest.package_version,
            "torch_version": manifest.torch_version,
            "transformers_version": manifest.transformers_version,
        },
        "baseline_owned_process_tree_rss_bytes": baseline_rss,
        "available_ram_bytes_before": available_ram,
        "runs": runs,
        "limitations": [
            "synthetic previews do not test useful next-probe ranking",
            "one host does not establish ordinary-laptop fitness across devices",
            "the 8 GiB free-RAM safety gate excludes most 8 GiB laptops",
            "50 ms RSS sampling can miss shorter memory spikes",
            "cold includes worker launch and manifest/weight verification; warm retains the worker",
            "provider latency excludes investigation storage, graph, collection, and reasoning",
            "batch-size differences require held-out action-quality comparison",
            "other host workloads can affect timing and RSS; this sweep owns only its CPU worker",
        ],
    }
    _persist_sweep_report(output_path, report, reserve=True)

    planned = [
        (round_index, order_position, batch_size, phase)
        for round_index, order in enumerate(_SWEEP_ORDERS, start=1)
        for order_position, batch_size in enumerate(order, start=1)
        for phase in ("cold", "warm")
    ]
    stop_reason: str | None = None
    unsafe = False
    interruption: BaseException | None = None
    for round_index, order in enumerate(_SWEEP_ORDERS, start=1):
        for order_position, batch_size in enumerate(order, start=1):
            try:
                available_now = psutil.virtual_memory().available
            except Exception:
                available_now = 0
            if available_now < _MIN_FREE_RAM_BYTES:
                stop_reason, unsafe = "InsufficientAvailableRam", True
                break
            config = base_config.model_copy(update={"max_candidates_per_batch": batch_size})
            runtime = LayaSubprocessRuntime(config)
            worker: _ObservedWorker | None = None
            try:
                for phase, symptom in (
                    ("cold", f"Round {round_index} cold: A game feels slow"),
                    ("warm", f"Round {round_index} warm: A PDF viewer turns pages slowly"),
                ):
                    if phase == "warm" and (
                        worker is None or _active_worker(runtime) is not worker
                    ):
                        stop_reason, unsafe = "WorkerIdentityChanged", True
                        break
                    state, evidence, candidates = representative_batch(symptom)
                    stop = threading.Event()
                    peak_rss = [_owned_rss_bytes()]
                    monitor = threading.Thread(
                        target=_sample_owned_memory, args=(stop, peak_rss), daemon=True
                    )
                    monitor.start()
                    started = time.monotonic()
                    run: dict[str, object] = {
                        "round": round_index,
                        "order_position": order_position,
                        "batch_size": batch_size,
                        "phase": phase,
                        "status": "failed",
                        "failure_type": None,
                        "pages_considered": 0,
                        "probes_considered": 0,
                    }
                    try:
                        result = runtime.attend(
                            state=state,
                            evidence=evidence,
                            candidates=candidates,
                            timeout_seconds=timeout_seconds,
                        )
                        run["pages_considered"] = len(result.considered_attention_page_ids)
                        run["probes_considered"] = len(result.considered_probe_ids)
                        run["attention_notes"] = list(result.attention_notes)
                        run["ranked_probe_ids"] = list(result.ranked_probe_ids)
                        if (
                            len(result.considered_attention_page_ids) != len(evidence)
                            or set(result.considered_attention_page_ids)
                            != {item["page_id"] for item in evidence}
                            or len(result.considered_probe_ids) != len(candidates)
                            or set(result.considered_probe_ids)
                            != {item["probe_id"] for item in candidates}
                        ):
                            run["failure_type"] = "IncompleteCoverage"
                        elif len(result.ranked_probe_ids) != len(candidates) or set(
                            result.ranked_probe_ids
                        ) != {item["probe_id"] for item in candidates}:
                            run["failure_type"] = "InvalidRankedProbeIds"
                        elif not _model_input_complete(result.attention_notes):
                            run["failure_type"] = "IncompleteModelInput"
                        else:
                            current_worker = _active_worker(runtime)
                            if current_worker is None or (
                                worker is not None and current_worker is not worker
                            ):
                                run["failure_type"] = "WorkerIdentityChanged"
                                unsafe = True
                            else:
                                worker = current_worker
                                run["status"] = "complete"
                    except Exception as error:
                        run["failure_type"] = type(error).__name__
                        unsafe = True
                    except BaseException as error:
                        run["failure_type"] = type(error).__name__
                        run["status"] = "interrupted"
                        interruption = error
                        unsafe = True
                    finally:
                        run["elapsed_seconds"] = time.monotonic() - started
                        stop.set()
                        monitor.join(timeout=2)
                        run["peak_owned_process_tree_rss_bytes"] = max(
                            peak_rss[0], _owned_rss_bytes()
                        )
                        runs.append(run)
                        _persist_sweep_report(output_path, report)
                    if run["status"] != "complete":
                        stop_reason = str(run["failure_type"])
                        break
            finally:
                try:
                    runtime.close()
                    if worker is not None and not _worker_stopped(worker):
                        stop_reason, unsafe = "WorkerTeardownUnverified", True
                except Exception as error:
                    report["teardown_failure_type"] = type(error).__name__
                    stop_reason, unsafe = "WorkerTeardownUnverified", True
            if stop_reason is not None:
                break
        if stop_reason is not None:
            break

    if stop_reason is not None:
        report["stop_reason"] = stop_reason
        for round_index, order_position, batch_size, phase in planned[len(runs) :]:
            runs.append(
                {
                    "round": round_index,
                    "order_position": order_position,
                    "batch_size": batch_size,
                    "phase": phase,
                    "status": "not_run",
                    "skip_reason": stop_reason,
                }
            )
        report["status"] = "interrupted_or_unsafe" if unsafe else "failed"
    else:
        report["status"] = "complete"
    _persist_sweep_report(output_path, report)
    if interruption is not None:
        raise interruption
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=float, default=180)
    parser.add_argument(
        "--batch-sweep", action="store_true", help="run CPU 4/8/20 counterbalanced sweep"
    )
    args = parser.parse_args()
    report = (
        measure_sweep(args.profile, args.output, timeout_seconds=args.timeout_seconds)
        if args.batch_sweep
        else measure(args.profile, args.output, timeout_seconds=args.timeout_seconds)
    )
    print(json.dumps(report))
    if report["status"] != "complete":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
