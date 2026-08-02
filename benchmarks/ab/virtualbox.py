"""Host-controlled VirtualBox execution with no benchmark files in the guest."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path, PureWindowsPath
from typing import cast

from benchmarks.ab.analysis import outcome_from_trace
from benchmarks.ab.codex_cli import CodexCliDebugger, CodexProcessResult
from benchmarks.ab.contracts import ExperimentArm, MachineFingerprint
from benchmarks.ab.fingerprint import fingerprint_differences, load_fingerprint, write_fingerprint
from benchmarks.ab.live_runner import authorize_paid_run
from benchmarks.ab.readiness import ExperimentConfig
from benchmarks.ab.recorder import RunTrace, TraceRecorder
from benchmarks.ab.scenario import LoadedScenario
from benchmarks.ab.tools import ToolManifest

_AGENT_ENVIRONMENT_KEYS = frozenset({"SYSTEMSENSE_DATABASE_PATH"})
_POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"


class VirtualBoxError(RuntimeError):
    """A guest command or VM experiment gate failed."""


class VirtualBoxGuest:
    """Run bounded commands through VirtualBox Guest Control."""

    def __init__(
        self,
        *,
        vbox_executable: Path,
        vm_name: str,
        username: str,
        password: str,
        process_runner: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
    ) -> None:
        self._vbox_executable = vbox_executable
        self._vm_name = vm_name
        self._username = username
        self._password = password
        self._process_runner = process_runner

    def run(
        self,
        command: tuple[str, ...],
        *,
        working_directory: Path,
        environment: dict[str, str],
        timeout_seconds: int,
    ) -> CodexProcessResult:
        """Implement the Codex process protocol using an allowlisted guest environment."""

        guest_environment = {
            key: value for key, value in environment.items() if key in _AGENT_ENVIRONMENT_KEYS
        }
        return self.execute(
            _closed_stdin_command(command),
            working_directory=str(working_directory),
            environment=guest_environment,
            timeout_seconds=timeout_seconds,
        )

    def execute(
        self,
        command: Sequence[str],
        *,
        working_directory: str | None = None,
        environment: Mapping[str, str] | None = None,
        timeout_seconds: int = 60,
    ) -> CodexProcessResult:
        if not command:
            raise ValueError("guest command cannot be empty")
        executable = str(command[0])
        invocation = [
            str(self._vbox_executable),
            "guestcontrol",
            self._vm_name,
            "run",
            f"--username={self._username}",
            f"--password={self._password}",
            f"--exe={executable}",
            f"--arg0={PureWindowsPath(executable).name}",
            "--wait-stdout",
            "--wait-stderr",
            f"--timeout={(timeout_seconds + 30) * 1000}",
        ]
        if working_directory is not None:
            invocation.append(f"--cwd={working_directory}")
        for key, value in sorted((environment or {}).items()):
            invocation.append(f"--putenv={key}={value}")
        invocation.extend(("--", *map(str, command[1:])))
        started = time.perf_counter()
        creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        try:
            completed = self._process_runner(
                tuple(invocation),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout_seconds + 45,
                creationflags=creation_flags,
            )
        except subprocess.TimeoutExpired as error:
            return CodexProcessResult(
                return_code=124,
                stdout=_timeout_text(error.stdout),
                stderr=(
                    _timeout_text(error.stderr) + "\nVirtualBox guest command timed out."
                ).strip(),
                elapsed_ms=round((time.perf_counter() - started) * 1000),
            )
        return CodexProcessResult(
            return_code=completed.returncode,
            stdout=completed.stdout,
            stderr=completed.stderr,
            elapsed_ms=round((time.perf_counter() - started) * 1000),
        )

    def powershell_script(
        self,
        source: str,
        *,
        arguments: Mapping[str, str | bool] | None = None,
        environment: Mapping[str, str] | None = None,
        timeout_seconds: int = 60,
    ) -> CodexProcessResult:
        source_base64 = base64.b64encode(source.encode("utf-8")).decode("ascii")
        rendered_arguments: list[str] = []
        for name, value in (arguments or {}).items():
            if isinstance(value, bool):
                if value:
                    rendered_arguments.append(f"-{name}")
            else:
                rendered_arguments.extend((f"-{name}", _powershell_literal(value)))
        wrapper = (
            "$source=[Text.Encoding]::UTF8.GetString("
            f"[Convert]::FromBase64String('{source_base64}'));"
            "$script=[ScriptBlock]::Create($source);"
            f"& $script {' '.join(rendered_arguments)}"
        )
        encoded = base64.b64encode(wrapper.encode("utf-16-le")).decode("ascii")
        return self.execute(
            (
                _POWERSHELL,
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-ExecutionPolicy",
                "Bypass",
                "-EncodedCommand",
                encoded,
            ),
            environment=environment,
            timeout_seconds=timeout_seconds,
        )

    def chatgpt_authenticated(self, codex_executable: str, agent_directory: str) -> bool:
        result = self.execute(
            (codex_executable, "login", "status"),
            working_directory=agent_directory,
            timeout_seconds=30,
        )
        return result.return_code == 0 and "Logged in using ChatGPT" in (
            result.stdout + result.stderr
        )


def capture_vm_fingerprint(
    guest: VirtualBoxGuest,
    *,
    script_path: Path,
    arm: ExperimentArm,
    clone_id: str,
    parent_snapshot_id: str,
    scenario_hash: str,
    python_executable: str,
) -> MachineFingerprint:
    result = guest.powershell_script(
        script_path.read_text(encoding="utf-8"),
        arguments={
            "Arm": arm.value,
            "CloneId": clone_id,
            "ParentSnapshotId": parent_snapshot_id,
            "ScenarioContentHash": scenario_hash,
        },
        environment={"SYSTEMSENSE_AB_PYTHON": python_executable},
        timeout_seconds=240,
    )
    if result.return_code != 0:
        raise VirtualBoxError(f"guest fingerprint failed: {result.stderr.strip()[:1000]}")
    return MachineFingerprint.model_validate_json(result.stdout)


def inject_port_conflict(
    guest: VirtualBoxGuest,
    *,
    script_path: Path,
    python_executable: str,
) -> dict[str, object]:
    result = guest.powershell_script(
        script_path.read_text(encoding="utf-8"),
        arguments={"Ephemeral": True},
        environment={"SYSTEMSENSE_AB_PYTHON": python_executable},
        timeout_seconds=30,
    )
    return _require_json_result(result, "fault injection")


def run_virtualbox_arm(
    *,
    guest: VirtualBoxGuest,
    config: ExperimentConfig,
    ready_path: Path,
    scenario: LoadedScenario,
    arm: ExperimentArm,
    pair_id: str,
    before_fingerprint_path: Path,
    tool_manifest: ToolManifest,
    output: Path,
    codex_executable: str,
    python_executable: str,
    agent_directory: str,
    database_path: str,
    allow_paid_run: bool,
    expected_stage: str,
) -> RunTrace:
    if scenario.content_hash != config.scenario_hash:
        raise VirtualBoxError("scenario bytes differ from the frozen experiment config")
    authenticated = guest.chatgpt_authenticated(codex_executable, agent_directory)
    ready = authorize_paid_run(
        ready_path=ready_path,
        config=config,
        allow_paid_run=allow_paid_run,
        api_key=None,
        subscription_authenticated=authenticated,
        expected_stage="canary" if expected_stage == "canary" else "benchmark",
    )
    before = load_fingerprint(before_fingerprint_path)
    expected_fingerprint = (
        ready.baseline_fingerprint_hash
        if arm is ExperimentArm.BASELINE
        else ready.systemsense_fingerprint_hash
    )
    if before.arm is not arm or before.comparison_hash() != expected_fingerprint:
        raise VirtualBoxError("run fingerprint does not match the authorized arm")
    expected_tool_hash = (
        ready.baseline_tool_manifest_hash
        if arm is ExperimentArm.BASELINE
        else ready.systemsense_tool_manifest_hash
    )
    if tool_manifest.arm is not arm or tool_manifest.manifest_hash() != expected_tool_hash:
        raise VirtualBoxError("current tool manifest differs from the authorized manifest")
    live_before = capture_vm_fingerprint(
        guest,
        script_path=Path(__file__).with_name("capture-fingerprint.ps1"),
        arm=arm,
        clone_id=before.clone_id,
        parent_snapshot_id=before.parent_snapshot_id,
        scenario_hash=scenario.content_hash,
        python_executable=python_executable,
    )
    live_differences = fingerprint_differences(before, live_before)
    if live_differences:
        raise VirtualBoxError(
            "live guest fingerprint differs from preflight: " + ", ".join(live_differences)
        )
    _require_broken(guest)
    _require_guest_path_absent(guest, database_path)
    _require_guest_directory_empty(guest, agent_directory)
    write_fingerprint(live_before, output.with_suffix(".live-before-fingerprint.json"))

    trace = CodexCliDebugger(
        executable=Path(codex_executable),
        process=guest,
        config=config,
        arm=arm,
        tool_manifest=tool_manifest,
        working_directory=Path(agent_directory),
        run_id=f"run_{uuid.uuid4().hex}",
        pair_id=pair_id,
        treatment_mcp_command=(
            Path(python_executable) if arm is ExperimentArm.SYSTEMSENSE else None
        ),
        treatment_mcp_args=("-m", "systemsense.mcp_server"),
        environment={"SYSTEMSENSE_DATABASE_PATH": database_path},
        raw_stdout_path=output.with_suffix(".raw.jsonl"),
        raw_stderr_path=output.with_suffix(".raw.stderr.txt"),
    ).run()

    oracle_started = time.perf_counter()
    try:
        oracle = _verify_fixed(guest, scenario=scenario, python_executable=python_executable)
    except VirtualBoxError as error:
        oracle = {"passed": False, "error": str(error)}
    finally:
        cleanup = _cleanup_port(guest)
    oracle_elapsed_ms = round((time.perf_counter() - oracle_started) * 1000)
    if cleanup.return_code != 0:
        raise VirtualBoxError(f"guest cleanup failed: {cleanup.stderr.strip()[:1000]}")
    collateral_started = time.perf_counter()
    after = capture_vm_fingerprint(
        guest,
        script_path=Path(__file__).with_name("capture-fingerprint.ps1"),
        arm=arm,
        clone_id=before.clone_id,
        parent_snapshot_id=before.parent_snapshot_id,
        scenario_hash=scenario.content_hash,
        python_executable=python_executable,
    )
    collateral_elapsed_ms = round((time.perf_counter() - collateral_started) * 1000)
    collateral_differences = tuple(
        item for item in fingerprint_differences(live_before, after) if item != "state.fault_state"
    )
    finished_at = datetime.now(UTC)
    scored = trace.model_copy(
        update={
            "finished_at": finished_at,
            "elapsed_ms": max(0, round((finished_at - trace.started_at).total_seconds() * 1000)),
            "oracle_elapsed_ms": oracle_elapsed_ms,
            "oracle_result": oracle,
            "oracle_passed": oracle.get("passed") is True,
            "collateral_check_elapsed_ms": collateral_elapsed_ms,
            "collateral_change_detected": bool(collateral_differences),
            "collateral_differences": collateral_differences,
        }
    )
    TraceRecorder.write(scored, output)
    write_fingerprint(after, output.with_suffix(".post-fingerprint.json"))
    outcome_path = output.with_suffix(".outcome.json")
    outcome_path.write_text(
        outcome_from_trace(scored).model_dump_json(indent=2) + "\n",
        encoding="utf-8",
    )
    return scored


def _require_broken(guest: VirtualBoxGuest) -> None:
    script = r"""
$listener = Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue |
    Select-Object -First 1
if (-not $listener) { throw "Expected port 8000 listener is absent." }
@{ passed = $true; observed = "address_in_use" } | ConvertTo-Json -Compress
"""
    _require_json_result(guest.powershell_script(script, timeout_seconds=30), "broken oracle")


def _require_guest_path_absent(guest: VirtualBoxGuest, path: str) -> None:
    script = (
        f"if (Test-Path -LiteralPath {_powershell_literal(path)}) "
        '{ throw "Guest database must be absent before the run." }; '
        "@{ passed = $true } | ConvertTo-Json -Compress"
    )
    _require_json_result(guest.powershell_script(script), "fresh database gate")


def _require_guest_directory_empty(guest: VirtualBoxGuest, path: str) -> None:
    literal_path = _powershell_literal(path)
    script = rf"""
if (-not (Test-Path -LiteralPath {literal_path} -PathType Container)) {{
    throw "Guest agent directory is absent."
}}
$itemCount = @(Get-ChildItem -LiteralPath {literal_path} -Force).Count
if ($itemCount -ne 0) {{ throw "Guest agent directory must be empty." }}
@{{ passed = $true; item_count = $itemCount }} | ConvertTo-Json -Compress
"""
    _require_json_result(guest.powershell_script(script), "empty agent workspace gate")


def _verify_fixed(
    guest: VirtualBoxGuest,
    *,
    scenario: LoadedScenario,
    python_executable: str,
) -> dict[str, object]:
    app_source = base64.b64encode(scenario.asset_paths[0].read_bytes()).decode("ascii")
    runner = f"import base64;exec(compile(base64.b64decode('{app_source}'),'app.py','exec'))"
    command_line = _powershell_literal(f'"{python_executable}" -c "{runner}"')
    script = rf"""
$commandLine = {command_line}
$created = Invoke-CimMethod -ClassName Win32_Process -MethodName Create `
    -Arguments @{{ CommandLine = $commandLine }}
if ($created.ReturnValue -ne 0 -or -not $created.ProcessId) {{
    throw "Health application failed to start."
}}
try {{
    $healthy = $false
    for ($attempt = 0; $attempt -lt 60; $attempt++) {{
        try {{
            $response = Invoke-WebRequest -Uri "http://127.0.0.1:8000/health" `
                -UseBasicParsing -TimeoutSec 1
            if ($response.StatusCode -eq 200 -and ([string]$response.Content).Trim() -eq "ok") {{
                $healthy = $true
                break
            }}
        }} catch {{}}
        Start-Sleep -Milliseconds 50
    }}
    if (-not $healthy) {{ throw "Health application did not return HTTP 200 ok." }}
    @{{ passed = $true; health = "ok" }} | ConvertTo-Json -Compress
}} finally {{
    Stop-Process -Id ([int]$created.ProcessId) -Force -ErrorAction SilentlyContinue
}}
"""
    return _require_json_result(
        guest.powershell_script(script, timeout_seconds=30),
        "fixed oracle",
    )


def _cleanup_port(guest: VirtualBoxGuest) -> CodexProcessResult:
    script = r"""
function Stop-Tree {
    param([int]$Root)
    Get-CimInstance Win32_Process -Filter "ParentProcessId = $Root" `
        -ErrorAction SilentlyContinue | ForEach-Object { Stop-Tree ([int]$_.ProcessId) }
    Stop-Process -Id $Root -Force -ErrorAction SilentlyContinue
}
Get-NetTCPConnection -LocalPort 8000 -State Listen -ErrorAction SilentlyContinue |
    Select-Object -ExpandProperty OwningProcess -Unique |
    ForEach-Object { Stop-Tree ([int]$_) }
@{ cleaned = $true } | ConvertTo-Json -Compress
"""
    return guest.powershell_script(script, timeout_seconds=30)


def _require_json_result(result: CodexProcessResult, label: str) -> dict[str, object]:
    if result.return_code != 0:
        detail = (result.stderr or result.stdout).strip()[:1000] or "no output"
        raise VirtualBoxError(f"{label} failed with exit code {result.return_code}: {detail}")
    try:
        raw: object = json.loads(result.stdout)
    except json.JSONDecodeError as error:
        raise VirtualBoxError(f"{label} returned invalid JSON") from error
    if not isinstance(raw, dict):
        raise VirtualBoxError(f"{label} returned a non-object")
    return cast("dict[str, object]", raw)


def _powershell_literal(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _closed_stdin_command(command: Sequence[str]) -> tuple[str, ...]:
    command_line = subprocess.list2cmdline(command) + " < NUL"
    command_base64 = base64.b64encode(command_line.encode("utf-8")).decode("ascii")
    wrapper = (
        "$command=[Text.Encoding]::UTF8.GetString("
        f"[Convert]::FromBase64String('{command_base64}'));"
        "& $env:ComSpec /d /s /c $command; exit $LASTEXITCODE"
    )
    encoded = base64.b64encode(wrapper.encode("utf-16-le")).decode("ascii")
    return (
        _POWERSHELL,
        "-NoLogo",
        "-NoProfile",
        "-NonInteractive",
        "-ExecutionPolicy",
        "Bypass",
        "-EncodedCommand",
        encoded,
    )


def _timeout_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    return value.decode("utf-8", errors="replace") if isinstance(value, bytes) else value
