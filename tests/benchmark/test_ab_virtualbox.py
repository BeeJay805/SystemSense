import subprocess
from pathlib import Path

from benchmarks.ab.virtualbox import VirtualBoxGuest


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
    assert "[switch]$Ephemeral" in injector
    assert "if (-not $Ephemeral)" in injector
