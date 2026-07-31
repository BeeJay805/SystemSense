"""Deterministic execution of scenario injection and hidden oracles."""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

from pydantic import Field

from benchmarks.ab.contracts import ExperimentModel
from benchmarks.ab.scenario import LoadedScenario


class ScriptExecution(ExperimentModel):
    script: str
    exit_code: int
    elapsed_ms: int = Field(ge=0)
    stdout: str
    stderr: str


class ScenarioExecutionQualification(ExperimentModel):
    broken_reproductions: int = Field(ge=0)
    reference_repairs: int = Field(ge=0)
    fixed_oracle_passes: int = Field(ge=0)
    cleanup_passed: bool
    executions: tuple[ScriptExecution, ...]


class ScenarioScriptError(RuntimeError):
    pass


def run_scenario_script(
    path: Path,
    *,
    state_directory: Path,
    python_executable: Path,
    timeout_seconds: int = 30,
) -> ScriptExecution:
    environment = {
        **os.environ,
        "SYSTEMSENSE_AB_STATE_DIR": str(state_directory.resolve()),
        "SYSTEMSENSE_AB_PYTHON": str(python_executable.resolve()),
    }
    state_directory.mkdir(parents=True, exist_ok=True)
    stdout_path = state_directory / f"runner-{path.stem}.stdout.log"
    stderr_path = state_directory / f"runner-{path.stem}.stderr.log"
    started = time.perf_counter()
    with stdout_path.open("wb") as stdout_file, stderr_path.open("wb") as stderr_file:
        completed = subprocess.run(
            [
                "powershell.exe",
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(path.resolve()),
            ],
            env=environment,
            stdout=stdout_file,
            stderr=stderr_file,
            check=False,
            timeout=timeout_seconds,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
    return ScriptExecution(
        script=path.name,
        exit_code=completed.returncode,
        elapsed_ms=round((time.perf_counter() - started) * 1000),
        stdout=stdout_path.read_text(encoding="utf-8", errors="replace").strip(),
        stderr=stderr_path.read_text(encoding="utf-8", errors="replace").strip(),
    )


def qualify_scenario_scripts(
    scenario: LoadedScenario,
    *,
    state_directory: Path,
    python_executable: Path,
) -> ScenarioExecutionQualification:
    executions: list[ScriptExecution] = []
    broken = 0
    repairs = 0
    fixed = 0
    fault_active = False
    cleanup_passed = False
    try:
        for _attempt in range(scenario.manifest.qualification_repetitions):
            _require_pass(
                executions,
                run_scenario_script(
                    scenario.script_paths["inject"],
                    state_directory=state_directory,
                    python_executable=python_executable,
                ),
            )
            fault_active = True
            _require_pass(
                executions,
                run_scenario_script(
                    scenario.script_paths["verify_broken"],
                    state_directory=state_directory,
                    python_executable=python_executable,
                ),
            )
            broken += 1
            _require_pass(
                executions,
                run_scenario_script(
                    scenario.script_paths["repair_reference"],
                    state_directory=state_directory,
                    python_executable=python_executable,
                ),
            )
            fault_active = False
            repairs += 1
            _require_pass(
                executions,
                run_scenario_script(
                    scenario.script_paths["verify_fixed"],
                    state_directory=state_directory,
                    python_executable=python_executable,
                ),
            )
            fixed += 1
        cleanup_passed = True
    finally:
        if fault_active:
            cleanup = run_scenario_script(
                scenario.script_paths["repair_reference"],
                state_directory=state_directory,
                python_executable=python_executable,
            )
            executions.append(cleanup)
            cleanup_passed = cleanup.exit_code == 0
    return ScenarioExecutionQualification(
        broken_reproductions=broken,
        reference_repairs=repairs,
        fixed_oracle_passes=fixed,
        cleanup_passed=cleanup_passed,
        executions=tuple(executions),
    )


def _require_pass(executions: list[ScriptExecution], execution: ScriptExecution) -> None:
    executions.append(execution)
    if execution.exit_code != 0:
        raise ScenarioScriptError(
            f"{execution.script} failed with exit code {execution.exit_code}: "
            f"{execution.stderr or execution.stdout}"
        )
