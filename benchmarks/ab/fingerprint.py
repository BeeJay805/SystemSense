"""Capture, read, and compare guest fingerprints after fault injection."""

import os
import subprocess
from pathlib import Path

from benchmarks.ab.contracts import ExperimentArm, MachineFingerprint


def load_fingerprint(path: Path) -> MachineFingerprint:
    if not path.is_file():
        raise ValueError(f"fingerprint is missing: {path}")
    return MachineFingerprint.model_validate_json(path.read_text(encoding="utf-8"))


def fingerprint_differences(
    baseline: MachineFingerprint,
    systemsense: MachineFingerprint,
) -> tuple[str, ...]:
    differences: list[str] = []
    if baseline.parent_snapshot_id != systemsense.parent_snapshot_id:
        differences.append("parent_snapshot_id")
    keys = set(baseline.state) | set(systemsense.state)
    differences.extend(
        f"state.{key}"
        for key in sorted(keys)
        if baseline.state.get(key) != systemsense.state.get(key)
    )
    return tuple(differences)


def capture_fingerprint(
    *,
    script_path: Path,
    arm: ExperimentArm,
    clone_id: str,
    parent_snapshot_id: str,
    scenario_root: Path,
    python_executable: Path,
    timeout_seconds: int = 180,
) -> MachineFingerprint:
    environment = {
        **os.environ,
        "SYSTEMSENSE_AB_PYTHON": str(python_executable.resolve()),
    }
    completed = subprocess.run(
        [
            "powershell.exe",
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(script_path.resolve()),
            "-Arm",
            arm.value,
            "-CloneId",
            clone_id,
            "-ParentSnapshotId",
            parent_snapshot_id,
            "-ScenarioRoot",
            str(scenario_root.resolve()),
        ],
        env=environment,
        capture_output=True,
        check=False,
        timeout=timeout_seconds,
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
    )
    if completed.returncode != 0:
        error = completed.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(f"fingerprint capture failed: {error}")
    return MachineFingerprint.model_validate_json(
        completed.stdout.decode("utf-8", errors="replace")
    )


def write_fingerprint(fingerprint: MachineFingerprint, path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(fingerprint.model_dump_json(indent=2) + "\n", encoding="utf-8")
