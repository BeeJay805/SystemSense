"""Blinded real-Windows test-owned process and CPU task evaluation.

The evaluator alone reads recipes and independent measurements. Dyad receives
only the user objective and its registered read-only Windows observations.
Every created helper is restored to idle before it is stopped in finally.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import time
import traceback
from datetime import UTC, datetime
from pathlib import Path
from secrets import token_hex
from typing import Any

import psutil

from benchmarks.private_alpha_loopback import run_product_case
from systemsense.application.subscription_setup import load_desktop_subscription_providers

ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "benchmarks" / "fixtures" / "private_alpha_host_cases.json"
RECIPES = ROOT / "benchmarks" / "ground_truth" / "private_alpha_host_recipes.json"
CS_SOURCE = ROOT / "benchmarks" / "fixtures" / "owned_cpu_process.cs"
CSC = Path(r"C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe")


def _save(path: Path, value: object) -> None:
    if path.exists():
        raise FileExistsError(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True, default=str), encoding="utf-8")


def _sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _source_state() -> dict[str, object]:
    head = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout.strip()
    diff = subprocess.run(
        ["git", "diff", "HEAD", "--binary"], cwd=ROOT, capture_output=True, check=True
    ).stdout
    untracked = subprocess.run(
        ["git", "ls-files", "--others", "--exclude-standard"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout.splitlines()
    return {
        "head": head,
        "tracked_diff_sha256": hashlib.sha256(diff).hexdigest(),
        "untracked_paths": untracked,
    }


def _compile(output: Path) -> Path:
    if os.name != "nt" or not CSC.is_file():
        raise RuntimeError("Windows .NET Framework compiler is unavailable")
    base = output / "owned-helper.exe"
    subprocess.run(
        [str(CSC), "/nologo", "/optimize+", f"/out:{base}", str(CS_SOURCE)],
        cwd=output,
        capture_output=True,
        check=True,
    )
    return base


def _start(path: Path, mode: str, owned: list[subprocess.Popen[bytes]]) -> subprocess.Popen[bytes]:
    child = subprocess.Popen(
        [str(path), mode],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        creationflags=subprocess.CREATE_NO_WINDOW,
    )
    owned.append(child)
    time.sleep(0.2)
    if child.poll() is not None:
        raise RuntimeError(f"test-owned helper exited: {path.name}")
    process = psutil.Process(child.pid)
    process.cpu_affinity([psutil.Process().cpu_affinity()[0]])
    return child


def _stop(child: subprocess.Popen[bytes]) -> None:
    if child.poll() is not None:
        return
    child.terminate()
    try:
        child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        child.kill()
        child.wait(timeout=5)


def _measure(child: subprocess.Popen[bytes]) -> dict[str, object]:
    at = datetime.now(UTC).isoformat()
    if child.poll() is not None:
        return {"observed_at": at, "pid": child.pid, "running": False}
    process = psutil.Process(child.pid)
    return {
        "observed_at": at,
        "pid": child.pid,
        "running": child.poll() is None and process.is_running(),
        "name": process.name(),
        "creation_time": process.create_time(),
        "cpu_percent_of_one_core": process.cpu_percent(interval=1.05),
        "rss_bytes": process.memory_info().rss,
    }


def _pair(target: subprocess.Popen[bytes], control: subprocess.Popen[bytes]) -> dict[str, object]:
    return {"target": _measure(target), "control": _measure(control)}


def _check(pair: dict[str, Any], recipe: str, *, phase: str) -> None:
    target = pair["target"]
    control = pair["control"]
    if not control["running"]:
        raise RuntimeError(f"control was not running at {phase}")
    if recipe == "stopped":
        if target["running"]:
            raise RuntimeError(f"target was still running at {phase}")
    elif not target["running"]:
        raise RuntimeError(f"target was absent at {phase}")
    if recipe == "busy" and target["cpu_percent_of_one_core"] < 50:
        raise RuntimeError(f"target CPU activity was not established at {phase}")
    if (
        recipe in {"idle", "running", "idle_with_busy_control"}
        and target.get("cpu_percent_of_one_core", 0) > 10
    ):
        raise RuntimeError(f"target idle control drifted at {phase}")
    if recipe == "idle_with_busy_control" and control["cpu_percent_of_one_core"] < 50:
        raise RuntimeError(f"busy distractor was not established at {phase}")


def _run_case(
    output: Path,
    entry: dict[str, Any],
    recipe: str,
    base: Path,
    providers: Any,
) -> None:
    output.mkdir(exist_ok=False)
    fixture = output / "evaluator" / "fixture"
    fixture.mkdir(parents=True)
    nonce = token_hex(4)
    target_path = fixture / f"dyad-alpha-target-{nonce}.exe"
    control_path = fixture / f"dyad-alpha-control-{nonce}.exe"
    shutil.copy2(base, target_path)
    shutil.copy2(base, control_path)
    objective_template = str(entry["objective_template"])
    if objective_template.count("{target_exe}") != 1 or objective_template.count("{") != 1:
        raise ValueError("objective template must include one exact executable placeholder")
    objective = objective_template.replace("{target_exe}", target_path.name)
    _save(output / "intake.json", {"case_id": entry["case_id"], "objective": objective})
    owned: list[subprocess.Popen[bytes]] = []
    target: subprocess.Popen[bytes] | None = None
    control: subprocess.Popen[bytes] | None = None
    restored = False
    try:
        target = _start(target_path, "idle", owned)
        control = _start(control_path, "idle", owned)
        baseline = _pair(target, control)
        _save(output / "evaluator" / "baseline.json", baseline)
        _check(baseline, "idle", phase="baseline")
        if recipe in {"stopped", "busy"}:
            _stop(target)
            if recipe == "busy":
                target = _start(target_path, "busy", owned)
        if recipe == "idle_with_busy_control":
            _stop(control)
            control = _start(control_path, "busy", owned)
        during = _pair(target, control)
        _save(output / "evaluator" / "during.json", during)
        _check(during, recipe, phase="during")
        case_started = time.monotonic()
        try:
            case = run_product_case(
                output,
                objective,
                providers,
                synthetic_missing_access=False,
                budget_ms=int(entry["budget_ms"]),
                max_rounds=int(entry["max_rounds"]),
            )
        finally:
            _save(
                output / "evaluator" / "attempt-runtime.json",
                {"elapsed_ms": round((time.monotonic() - case_started) * 1000, 3)},
            )
        midpoint = _pair(target, control)
        _save(output / "evaluator" / "midpoint.json", midpoint)
        _check(midpoint, recipe, phase="midpoint")
        _save(
            output / "result-index.json",
            {"status": case["status"], "outcome": case["outcome"], "summary": case["summary"]},
        )
        if target.poll() is not None or recipe == "busy":
            _stop(target)
            target = _start(target_path, "idle", owned)
        if recipe == "idle_with_busy_control":
            _stop(control)
            control = _start(control_path, "idle", owned)
        restored_pair = _pair(target, control)
        _save(output / "evaluator" / "restored.json", restored_pair)
        _check(restored_pair, "idle", phase="restored")
        restored = True
    except Exception as error:
        _save(
            output / "evaluator" / "error.json",
            {
                "type": type(error).__name__,
                "message": str(error),
                "traceback": traceback.format_exc(),
            },
        )
        raise
    finally:
        # A product exception must not skip the independent healthy readback.
        # Keep the original exception as the attempt result if restoration
        # itself fails, and record that failure separately for the evaluator.
        if not restored and target is not None and control is not None:
            try:
                if target.poll() is not None or recipe == "busy":
                    _stop(target)
                    target = _start(target_path, "idle", owned)
                if recipe == "idle_with_busy_control":
                    _stop(control)
                    control = _start(control_path, "idle", owned)
                restored_pair = _pair(target, control)
                _save(output / "evaluator" / "restored.json", restored_pair)
                _check(restored_pair, "idle", phase="restored")
                restored = True
            except Exception as error:
                _save(
                    output / "evaluator" / "restoration-error.json",
                    {
                        "type": type(error).__name__,
                        "message": str(error),
                        "traceback": traceback.format_exc(),
                    },
                )
        # Always terminate exactly the test-owned subprocess objects, including
        # a stopped fault and any replacement used to verify restoration.
        for child in owned:
            _stop(child)
        _save(
            output / "evaluator" / "cleanup.json",
            {
                "restored_before_cleanup": restored,
                "owned_processes_exited": all(child.poll() is not None for child in owned),
                "owned_pids": [child.pid for child in owned],
            },
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--split", choices=("development", "holdout"), required=True)
    parser.add_argument("--route", choices=("model", "basic"), required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--case-id", action="append", default=[])
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    manifest = json.loads(MANIFEST.read_text(encoding="utf-8"))
    key = json.loads(RECIPES.read_text(encoding="utf-8"))
    if manifest["suite"] != key["suite"] or manifest["schema_version"] != key["schema_version"]:
        raise RuntimeError("frozen manifest and evaluator key differ")
    cases = [entry for entry in manifest["cases"] if entry["split"] == args.split]
    if len(cases) != 8 or len({entry["case_id"] for entry in cases}) != 8:
        raise RuntimeError("expected eight unique cases per frozen split")
    if args.case_id:
        requested = set(args.case_id)
        if len(requested) != len(args.case_id) or not requested.issubset(
            {entry["case_id"] for entry in cases}
        ):
            raise ValueError("requested case ID is repeated or absent from the frozen split")
        cases = [entry for entry in cases if entry["case_id"] in requested]
    _save(
        output / "run.json",
        {
            "route": args.route,
            "split": args.split,
            "started_at": datetime.now(UTC).isoformat(),
            "manifest_sha256": _sha(MANIFEST),
            "recipes_sha256": _sha(RECIPES),
            "fixture_source_sha256": _sha(CS_SOURCE),
            "source_state": _source_state(),
            "case_ids": [entry["case_id"] for entry in cases],
        },
    )
    base = _compile(output)
    cold_start = time.monotonic()
    providers = load_desktop_subscription_providers() if args.route == "model" else None
    _save(output / "setup.json", {"elapsed_ms": round((time.monotonic() - cold_start) * 1000, 3)})
    try:
        for entry in cases:
            case_id = str(entry["case_id"])
            print(f"{case_id} start", flush=True)
            try:
                _run_case(output / case_id, entry, str(key["recipes"][case_id]), base, providers)
            except Exception as error:
                print(f"{case_id} failed: {type(error).__name__}: {error}", flush=True)
            else:
                print(f"{case_id} complete", flush=True)
    finally:
        if providers is not None:
            providers.close()
        _save(output / "finished.json", {"finished_at": datetime.now(UTC).isoformat()})


if __name__ == "__main__":
    main()
