from __future__ import annotations

import subprocess
from pathlib import Path

from benchmarks.vm_qualification_readiness import inspect_qualification_clone

VBOX = Path(r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe")
VM_ID = "82bab24b-e3b2-4b17-9d55-8c9198c53766"
SNAPSHOT_ID = "5ea81cfc-2fa3-4935-867e-b2041c3cddf3"
INFO = f'''name="SystemSense-Investigator-Qualification-20260922"
ostype="Windows 11 (64-bit)"
UUID="{VM_ID}"
VMState="poweroff"
nic1="nat"
cableconnected1="off"
'''


def test_reports_missing_snapshot_and_guest_control_limit_without_credentials() -> None:
    calls: list[list[str]] = []

    def run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        assert kwargs == {
            "capture_output": True,
            "text": True,
            "shell": False,
            "timeout": 15.0,
            "check": False,
        }
        if args[1:] == ["--version"]:
            return subprocess.CompletedProcess(args, 0, "7.2.14r174565\n", "")
        if args[1] == "showvminfo":
            return subprocess.CompletedProcess(args, 0, INFO, "")
        if args[1] == "snapshot":
            return subprocess.CompletedProcess(
                args, 1, "This machine does not have any snapshots\n", ""
            )
        if args[1] == "guestproperty":
            return subprocess.CompletedProcess(args, 0, "No value set!\n", "")
        raise AssertionError(args)

    report = inspect_qualification_clone(VBOX, VM_ID, run=run)

    assert report.classification == "read_only_host_readiness"
    assert report.vm_name == "SystemSense-Investigator-Qualification-20260922"
    assert report.snapshot_count == 0
    assert report.current_snapshot_uuid is None
    assert report.guest_additions_version is None
    assert not report.can_begin_episode
    assert "no_current_snapshot" in report.blockers
    assert "guest_login_unverified" in report.blockers
    assert "guest_additions_unverified" in report.blockers
    assert "guest_not_running" in report.blockers
    assert calls == [
        [str(VBOX), "--version"],
        [str(VBOX), "showvminfo", VM_ID, "--machinereadable"],
        [str(VBOX), "snapshot", VM_ID, "list", "--machinereadable"],
        [str(VBOX), "guestproperty", "get", VM_ID, "/VirtualBox/GuestAdd/Version"],
    ]


def test_snapshot_metadata_does_not_imply_authenticated_guest_control() -> None:
    info = INFO + f'CurrentSnapshotUUID="{SNAPSHOT_ID}"\nCurrentSnapshotName="Clean"\n'
    snapshots = f'SnapshotName="Clean"\nSnapshotUUID="{SNAPSHOT_ID}"\n'

    def run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        if args[1:] == ["--version"]:
            output = "7.2.14r174565\n"
        elif args[1] == "showvminfo":
            output = info
        elif args[1] == "snapshot":
            output = snapshots
        else:
            output = "Value: 7.2.14\n"
        return subprocess.CompletedProcess(args, 0, output, "")

    report = inspect_qualification_clone(VBOX, VM_ID, run=run)
    assert report.snapshot_count == 1
    assert report.current_snapshot_uuid is not None
    assert "no_current_snapshot" not in report.blockers
    assert "guest_additions_unverified" not in report.blockers
    assert "guest_login_unverified" in report.blockers
    assert "clean_reset_unverified" in report.blockers
    assert not report.can_begin_episode
