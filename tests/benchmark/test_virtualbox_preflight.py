from __future__ import annotations

import json
import subprocess
from pathlib import Path
from uuid import UUID

import pytest

from benchmarks.virtualbox_preflight import (
    CommandRunner,
    VBoxPreflightError,
    inspect_virtualbox_vm,
)

VM_UUID = "3adc5f85-85c0-445f-82f5-84876f48d71b"
SNAPSHOT_UUID = "5ea81cfc-2fa3-4935-867e-b2041c3cddf3"
MEDIA_UUID = "6c8cd254-c26b-4cb0-998b-0dc8819ab865"
VBOXMANAGE = Path(r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe")

INFO = f'''name="SystemSense-AB-Golden"
ostype="Windows 11 (64-bit)"
UUID="{VM_UUID}"
VMState="poweroff"
nic1="nat"
nic2="none"
cableconnected1="off"
CurrentSnapshotName="Clean"
CurrentSnapshotUUID="{SNAPSHOT_UUID}"
'''
SNAPSHOTS = f'''SnapshotName="Clean"
SnapshotUUID="{SNAPSHOT_UUID}"
SnapshotDescription="Clean base"
'''


def _runner(
    *,
    info: str = INFO,
    snapshots: str = SNAPSHOTS,
    guest_version: str = "Value: 7.2.14\n",
) -> tuple[list[list[str]], CommandRunner]:
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
            stdout = "7.2.14r174565\n"
        elif args[1:3] == ["showvminfo", VM_UUID]:
            stdout = info
        elif args[1:3] == ["snapshot", VM_UUID]:
            stdout = snapshots
        elif args[1:3] == ["guestproperty", "get"]:
            stdout = guest_version
        else:
            raise AssertionError(f"unexpected VBoxManage call: {args}")
        return subprocess.CompletedProcess(args, 0, stdout, "")

    return calls, run


def test_preflight_returns_structured_read_only_proof_and_exact_commands(tmp_path: Path) -> None:
    disk_path = tmp_path / "clean.vdi"
    disk_path.touch()
    info = INFO + _attachment(str(disk_path), MEDIA_UUID, port=0)
    calls, run = _runner(info=info)

    proof = inspect_virtualbox_vm(
        VBOXMANAGE, VM_UUID, expected_snapshot_uuid=SNAPSHOT_UUID, run=run
    )

    assert proof.classification == "virtualbox_preflight_only"
    assert proof.observed_at.tzinfo is not None
    assert proof.vm_uuid == UUID(VM_UUID)
    assert proof.vm_name == "SystemSense-AB-Golden"
    assert proof.state == "poweroff"
    assert proof.current_snapshot_uuid == UUID(SNAPSHOT_UUID)
    assert proof.guest_additions_observed_version == "7.2.14"
    assert proof.attached_media[0].path == disk_path
    assert proof.attached_media[0].exists
    assert proof.ready_for_disposable_clone
    assert not proof.guest_control_ready
    assert "guest_control_not_exercised" in proof.guest_control_blockers
    assert calls == [
        [str(VBOXMANAGE), "--version"],
        [str(VBOXMANAGE), "showvminfo", VM_UUID, "--machinereadable"],
        [str(VBOXMANAGE), "snapshot", VM_UUID, "list", "--machinereadable"],
        [
            str(VBOXMANAGE),
            "guestproperty",
            "get",
            VM_UUID,
            "/VirtualBox/GuestAdd/Version",
        ],
    ]


def test_preflight_never_uses_shell_or_mutating_arguments() -> None:
    calls, run = _runner()
    inspect_virtualbox_vm(VBOXMANAGE, VM_UUID, expected_snapshot_uuid=SNAPSHOT_UUID, run=run)

    assert all(
        not any(arg in {"startvm", "clonevm", "restore", "take", "delete"} for arg in call)
        for call in calls
    )


@pytest.mark.parametrize(
    "info",
    [
        INFO.replace(VM_UUID, "00000000-0000-0000-0000-000000000000"),
        INFO.replace('VMState="poweroff"\n', ""),
        INFO + 'VMState="running"\n',
        INFO.replace('name="SystemSense-AB-Golden"', 'name="broken\n'),
    ],
)
def test_preflight_rejects_mismatched_or_malformed_machine_output(info: str) -> None:
    _, run = _runner(info=info)

    with pytest.raises(VBoxPreflightError):
        inspect_virtualbox_vm(VBOXMANAGE, VM_UUID, expected_snapshot_uuid=SNAPSHOT_UUID, run=run)


def test_preflight_rejects_snapshot_tree_that_does_not_contain_current_snapshot() -> None:
    _, run = _runner(
        snapshots='SnapshotName="Other"\nSnapshotUUID="aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"\n'
    )

    with pytest.raises(VBoxPreflightError):
        inspect_virtualbox_vm(VBOXMANAGE, VM_UUID, expected_snapshot_uuid=SNAPSHOT_UUID, run=run)


def test_expected_snapshot_must_be_the_current_snapshot(tmp_path: Path) -> None:
    disk_path = tmp_path / "clean.vdi"
    disk_path.touch()
    other_snapshot = "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    snapshots = SNAPSHOTS + (f'SnapshotName-1="Other"\nSnapshotUUID-1="{other_snapshot}"\n')
    info = INFO + _attachment(str(disk_path), MEDIA_UUID, port=0)
    _, run = _runner(info=info, snapshots=snapshots)

    proof = inspect_virtualbox_vm(
        VBOXMANAGE, VM_UUID, expected_snapshot_uuid=other_snapshot, run=run
    )

    assert "expected_snapshot_not_current" in proof.blockers
    assert not proof.ready_for_disposable_clone


def test_missing_guest_additions_blocks_guest_control_not_source_clone(tmp_path: Path) -> None:
    disk_path = tmp_path / "clean.vdi"
    disk_path.touch()
    info = INFO + _attachment(str(disk_path), MEDIA_UUID, port=0)
    _, run = _runner(info=info, guest_version="No value set!\n")

    proof = inspect_virtualbox_vm(
        VBOXMANAGE, VM_UUID, expected_snapshot_uuid=SNAPSHOT_UUID, run=run
    )

    assert proof.guest_additions_observed_version is None
    assert proof.ready_for_disposable_clone
    assert not proof.guest_control_ready
    assert "guest_additions_unverified" in proof.guest_control_blockers


def test_connected_virtual_nic_blocks_isolated_qualification_readiness(tmp_path: Path) -> None:
    disk_path = tmp_path / "clean.vdi"
    disk_path.touch()
    info = INFO.replace('cableconnected1="off"', 'cableconnected1="on"')
    _calls, run = _runner(info=info + _attachment(str(disk_path), MEDIA_UUID, port=0))

    proof = inspect_virtualbox_vm(
        VBOXMANAGE, VM_UUID, expected_snapshot_uuid=SNAPSHOT_UUID, run=run
    )

    assert "network_adapter_connected" in proof.blockers
    assert not proof.ready_for_disposable_clone


def test_missing_attached_viso_is_reported_as_a_blocker() -> None:
    missing_viso = r"D:\SystemSense-AB\missing-win11.viso"
    info = INFO + _attachment(missing_viso, "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", port=1)
    _, run = _runner(info=info)

    proof = inspect_virtualbox_vm(
        VBOXMANAGE, VM_UUID, expected_snapshot_uuid=SNAPSHOT_UUID, run=run
    )

    assert any(not media.exists for media in proof.attached_media)
    assert "attached_media_missing" in proof.blockers
    assert not proof.ready_for_disposable_clone


def test_any_attached_viso_blocks_clone_readiness_even_if_file_exists(tmp_path: Path) -> None:
    viso_path = tmp_path / "installer.viso"
    viso_path.touch()
    info = INFO + _attachment(str(viso_path), "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", port=1)
    _, run = _runner(info=info)

    proof = inspect_virtualbox_vm(
        VBOXMANAGE, VM_UUID, expected_snapshot_uuid=SNAPSHOT_UUID, run=run
    )

    assert proof.attached_media[0].exists
    assert "auxiliary_optical_media_attached" in proof.blockers
    assert not proof.ready_for_disposable_clone


def test_guest_additions_version_must_match_host_tool_version(tmp_path: Path) -> None:
    disk_path = tmp_path / "clean.vdi"
    disk_path.touch()
    info = INFO + _attachment(str(disk_path), MEDIA_UUID, port=0)
    _, run = _runner(info=info, guest_version="Value: 7.1.10\n")

    proof = inspect_virtualbox_vm(
        VBOXMANAGE, VM_UUID, expected_snapshot_uuid=SNAPSHOT_UUID, run=run
    )

    assert proof.guest_additions_observed_version == "7.1.10"
    assert "guest_additions_version_mismatch" in proof.guest_control_blockers
    assert proof.ready_for_disposable_clone
    assert not proof.guest_control_ready


def test_missing_network_cable_state_fails_closed() -> None:
    _, run = _runner(info=INFO.replace('cableconnected1="off"\n', ""))

    with pytest.raises(VBoxPreflightError, match="cableconnected1"):
        inspect_virtualbox_vm(VBOXMANAGE, VM_UUID, expected_snapshot_uuid=SNAPSHOT_UUID, run=run)


def test_enabled_secondary_nic_without_cable_state_fails_closed(tmp_path: Path) -> None:
    disk_path = tmp_path / "clean.vdi"
    disk_path.touch()
    info = INFO.replace('nic2="none"', 'nic2="nat"')
    _, run = _runner(info=info + _attachment(str(disk_path), MEDIA_UUID, port=0))

    with pytest.raises(VBoxPreflightError, match="cableconnected2"):
        inspect_virtualbox_vm(VBOXMANAGE, VM_UUID, expected_snapshot_uuid=SNAPSHOT_UUID, run=run)


def test_uuid_input_must_be_a_canonical_uuid() -> None:
    _, run = _runner()

    with pytest.raises(VBoxPreflightError):
        inspect_virtualbox_vm(
            VBOXMANAGE,
            "SystemSense-AB-Golden;startvm",
            expected_snapshot_uuid=SNAPSHOT_UUID,
            run=run,
        )


def test_nonzero_cli_exit_fails_closed() -> None:
    calls: list[list[str]] = []

    def run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[str]:
        calls.append(args)
        return subprocess.CompletedProcess(args, 2, "", "not found")

    with pytest.raises(VBoxPreflightError, match="VBoxManage failed"):
        inspect_virtualbox_vm(VBOXMANAGE, VM_UUID, expected_snapshot_uuid=SNAPSHOT_UUID, run=run)


def test_duplicate_machine_readable_keys_are_rejected() -> None:
    _, run = _runner(info=INFO + 'VMState="running"\n')

    with pytest.raises(VBoxPreflightError, match="duplicate"):
        inspect_virtualbox_vm(VBOXMANAGE, VM_UUID, expected_snapshot_uuid=SNAPSHOT_UUID, run=run)


def _attachment(path: str, media_uuid: str, *, port: int) -> str:
    return (
        f'"SATA Controller-{port}-0"={json.dumps(path)}\n'
        f'"SATA Controller-ImageUUID-{port}-0"={json.dumps(media_uuid)}\n'
    )
