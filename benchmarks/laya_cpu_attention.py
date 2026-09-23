"""Opt-in desktop CPU runtime measurement for pinned Laya attention.

This uses synthetic previews and registered probe names. It measures runtime
and host-process memory, not Windows probe-choice quality or laptop fitness.
No GPU, network call, model download, collector, or repair is started.
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
import threading
import time
from pathlib import Path

import psutil

from systemsense.application.bootstrap import default_capabilities
from systemsense.inference.laya_runtime import LayaSubprocessRuntime
from systemsense.inference.profile import load_inference_profile

_MIN_FREE_RAM_BYTES = 8 * 1024**3
_PAGE_COUNT = 54


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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--timeout-seconds", type=float, default=180)
    args = parser.parse_args()
    report = measure(args.profile, args.output, timeout_seconds=args.timeout_seconds)
    print(json.dumps(report))
    if report["status"] != "complete":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
