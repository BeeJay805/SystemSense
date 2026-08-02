# pyright: reportPrivateUsage=false

import base64
import subprocess
from pathlib import Path

import pytest

from benchmarks.ab.codex_cli import CodexProcessResult
from benchmarks.ab.scenario import load_scenario
from benchmarks.ab.virtualbox import (
    VirtualBoxError,
    VirtualBoxGuest,
    _powershell_literal,
    _provision_guest_workspace,
    _require_guest_workspace_unchanged,
    _require_json_result,
    _verify_fixed,
)


class FakeRunner:
    def __init__(self) -> None:
        self.command: tuple[str, ...] = ()
        self.kwargs: dict[str, object] = {}

    def __call__(
        self,
        command: tuple[str, ...],
        **kwargs: object,
    ) -> subprocess.CompletedProcess[str]:
        self.command = command
        self.kwargs = kwargs
        return subprocess.CompletedProcess(command, 0, stdout="ok", stderr="")


class CapturingGuest:
    def __init__(self) -> None:
        self.source = ""

    def powershell_script(
        self,
        source: str,
        *,
        timeout_seconds: int = 60,
    ) -> CodexProcessResult:
        self.source = source
        return CodexProcessResult(
            return_code=0,
            stdout='{"passed":true,"health":"ok"}',
            stderr="",
            elapsed_ms=10,
        )


def test_virtualbox_codex_process_passes_only_allowlisted_guest_environment() -> None:
    runner = FakeRunner()
    guest = VirtualBoxGuest(
        vbox_executable=Path(r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"),
        vm_name="SystemSense-AB-Baseline",
        username="bench",
        password="guest-secret",
        process_runner=runner,
    )

    result = guest.run(
        (r"C:\Tools\Codex\codex.exe", "exec", "--json", "diagnose"),
        working_directory=Path(r"C:\AgentWorkspace"),
        environment={
            "SYSTEMSENSE_DATABASE_PATH": r"C:\Data\systemsense.db",
            "SYSTEMSENSE_AB_STATE_DIR": r"C:\hidden\fault",
            "OPENAI_API_KEY": "must-not-cross",
        },
        timeout_seconds=60,
    )

    assert result.return_code == 0
    assert "--putenv=SYSTEMSENSE_DATABASE_PATH=C:\\Data\\systemsense.db" in runner.command
    assert not any("SYSTEMSENSE_AB_STATE_DIR" in item for item in runner.command)
    assert not any("OPENAI_API_KEY" in item or "must-not-cross" in item for item in runner.command)
    assert "--cwd=C:\\AgentWorkspace" in runner.command
    assert runner.kwargs["stdin"] is subprocess.DEVNULL
    assert "--exe=C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" in runner.command
    assert runner.command[-2] == "-EncodedCommand"
    wrapper = base64.b64decode(runner.command[-1]).decode("utf-16-le")
    assert "& $env:ComSpec /d /s /c $command" in wrapper
    command_base64 = wrapper.split("FromBase64String('", 1)[1].split("')", 1)[0]
    command_line = base64.b64decode(command_base64).decode("utf-8")
    assert command_line.endswith(" < NUL")
    assert "codex.exe" in command_line


def test_virtualbox_powershell_script_is_encoded_instead_of_persisted() -> None:
    runner = FakeRunner()
    guest = VirtualBoxGuest(
        vbox_executable=Path("VBoxManage.exe"),
        vm_name="guest",
        username="bench",
        password="secret",
        process_runner=runner,
    )

    result = guest.powershell_script(
        'Write-Output "fault.pid"',
        arguments={"Ephemeral": True},
    )

    assert result.return_code == 0
    assert "-EncodedCommand" in runner.command
    assert not any("fault.pid" in item for item in runner.command)
    assert not any(item.endswith(".ps1") for item in runner.command)


def test_host_control_scripts_support_fileless_vm_execution() -> None:
    root = Path(__file__).resolve().parents[2] / "benchmarks" / "ab"
    fingerprint = (root / "capture-fingerprint.ps1").read_text(encoding="utf-8")
    injector = (root / "scenarios" / "port_conflict" / "inject.ps1").read_text(encoding="utf-8")

    assert "ScenarioContentHash" in fingerprint
    assert "Provide exactly one" in fingerprint
    assert '$_.Name -eq "BITS"' in fingerprint
    assert '"<trigger-managed>"' in fingerprint
    assert "[switch]$Ephemeral" in injector
    assert "if (-not $Ephemeral)" in injector


def test_failed_guest_json_result_reports_exit_code_and_stdout_fallback() -> None:
    result = CodexProcessResult(
        return_code=1,
        stdout="guest-side failure",
        stderr="",
        elapsed_ms=10,
    )

    with pytest.raises(
        VirtualBoxError,
        match="qualification failed with exit code 1: guest-side failure",
    ):
        _require_json_result(result, "qualification")


def test_powershell_literal_escapes_python_single_quotes() -> None:
    command = '"C:\\Python\\python.exe" -c "fn(\'payload\')"'

    assert _powershell_literal(command) == ("'\"C:\\Python\\python.exe\" -c \"fn(''payload'')\"'")


def test_fixed_oracle_escapes_embedded_python_before_powershell_parsing() -> None:
    scenario = load_scenario(
        Path(__file__).resolve().parents[2] / "benchmarks" / "ab" / "scenarios" / "port_conflict"
    )
    guest = CapturingGuest()

    result = _verify_fixed(
        guest,  # pyright: ignore[reportArgumentType]
        scenario=scenario,
        python_executable=r"C:\Tools\Python\python.exe",
    )

    assert result["passed"] is True
    assert "b64decode(''" in guest.source
    assert "''),''app.py'',''exec''" in guest.source


def test_guest_workspace_contains_only_public_scenario_assets() -> None:
    scenario = load_scenario(
        Path(__file__).resolve().parents[2] / "benchmarks" / "ab" / "scenarios" / "port_conflict"
    )
    guest = CapturingGuest()

    _provision_guest_workspace(
        guest,  # pyright: ignore[reportArgumentType]
        scenario=scenario,
        path=r"C:\AgentWorkspace",
    )

    payload = guest.source.split("FromBase64String('", 1)[1].split("')", 1)[0]
    decoded = base64.b64decode(payload).decode("utf-8")
    assert "app.py" in decoded
    assert "README.md" in decoded
    assert "verify-fixed.ps1" not in decoded
    assert "repair-reference.ps1" not in decoded


def test_guest_workspace_collateral_check_is_exact() -> None:
    scenario = load_scenario(
        Path(__file__).resolve().parents[2] / "benchmarks" / "ab" / "scenarios" / "port_conflict"
    )
    guest = CapturingGuest()

    _require_guest_workspace_unchanged(
        guest,  # pyright: ignore[reportArgumentType]
        scenario=scenario,
        path=r"C:\AgentWorkspace",
    )

    assert "unexpected" in guest.source
    assert "changed" in guest.source
