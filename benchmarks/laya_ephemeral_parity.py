"""Opt-in synthetic live-worker input parity; never save raw worker content.

This is a local test of the installed pinned worker and tokenizer, not training
admission, corpus parity, diagnostic accuracy, or consent to collect case data.
"""

from __future__ import annotations

import argparse
import json
import os
import time
from pathlib import Path

from benchmarks.laya_exact_batch_parity import (
    _local_qualification,  # pyright: ignore[reportPrivateUsage]
)
from benchmarks.laya_training_loader import verify_ephemeral_probe_batch
from systemsense.inference.laya_runtime import LayaSubprocessRuntime, LayaWorkerPresentation
from systemsense.inference.profile import load_inference_profile


def measure(profile_path: Path) -> dict[str, object]:
    profile = load_inference_profile(profile_path)
    if not profile.laya.enabled:
        raise ValueError("pinned Laya profile is disabled")
    config = profile.laya.runtime_config()
    config.validate_install()
    tokenizer, model_config, qualification = _local_qualification(config.model_path)
    if qualification.get("status") != "pass":
        raise ValueError("pinned install qualification failed")
    # Keep the harness independent of the throughput benchmark's psutil and
    # NVIDIA sampling imports. The pinned model interpreter needs only the
    # installed model stack plus SystemSense's ordinary runtime dependencies.
    state: dict[str, object] = {
        "attention_kind": "synthetic_parity_only",
        "symptom": "Synthetic application is slow",
    }
    evidence: tuple[dict[str, str], ...] = ()
    candidates = (
        {"probe_id": "synthetic.cpu", "description": "Inspect synthetic CPU usage"},
        {"probe_id": "synthetic.disk", "description": "Inspect synthetic disk latency"},
    )
    captured: dict[tuple[str, int], tuple[dict[str, object], LayaWorkerPresentation]] = {}

    def retain(
        phase: str, index: int, call: dict[str, object], proof: LayaWorkerPresentation
    ) -> None:
        key = (phase, index)
        if key in captured:
            raise ValueError("duplicate worker capture")
        captured[key] = (call, proof)

    runtime = LayaSubprocessRuntime(config)
    started = time.monotonic()
    try:
        attention = runtime.attend(
            state=state,
            evidence=evidence,
            candidates=candidates,
            timeout_seconds=90,
            capture_exact_worker_call=retain,
        )
        rows: list[dict[str, object]] = []
        covered = 0
        for batch in attention.microbatches:
            if batch.phase != "probe":
                continue
            call, proof = captured[("probe", batch.batch_index)]
            result = verify_ephemeral_probe_batch(
                attention,
                batch_index=batch.batch_index,
                exact_worker_call=call,
                worker_presentation=proof,
                tokenizer=tokenizer,
                cfg=model_config,
                qualification=qualification,
            )
            covered += len(result.candidate_ids)
            rows.append(
                {
                    "batch_index": batch.batch_index,
                    "candidate_count": len(result.candidate_ids),
                    "model_input_sha256": result.model_input_sha256,
                    "trainable": result.trainable,
                }
            )
        if covered != len(candidates):
            raise ValueError("probe candidates were not completely covered")
        return {
            "schema_version": 1,
            "classification": "synthetic_one_live_attention_worker_parity_only",
            "status": "pass",
            "trainable": False,
            "model_revision": qualification["model_revision"],
            "worker_sha256": qualification["worker_sha256"],
            "elapsed_seconds": time.monotonic() - started,
            "probe_batches": rows,
            "limitations": [
                "Synthetic input only; no Windows case or useful-action label.",
                "In-memory worker calls are discarded after parity; no corpus custody.",
                "Cached batches are unsupported by this parity check.",
            ],
        }
    finally:
        runtime.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    if args.output.exists():
        print('{"status":"error","reason":"output_exists","trainable":false}')
        return 2
    try:
        report = measure(args.profile)
    except (OSError, RuntimeError, TypeError, ValueError, KeyError):
        # Never echo exception text: a future non-synthetic caller might carry
        # machine paths or case content. The report itself contains hashes only.
        print('{"status":"error","reason":"live_parity_failed","trainable":false}')
        return 2
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, sort_keys=True, indent=2)
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
