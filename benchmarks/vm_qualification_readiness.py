"""Read-only host readiness report for an existing VirtualBox qualification clone.

This deliberately does not try a guest login or claim that a snapshot is clean.
It cannot establish fault injection, an independent endpoint, or episode quality.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from uuid import UUID

from benchmarks.virtualbox_preflight import (
    CommandRunner,
    VBoxPreflightError,
    _parse_guest_additions,  # pyright: ignore[reportPrivateUsage]
    _parse_machine_readable,  # pyright: ignore[reportPrivateUsage]
    _parse_network_cable_states,  # pyright: ignore[reportPrivateUsage]
    _parse_snapshots,  # pyright: ignore[reportPrivateUsage]
    _parse_uuid,  # pyright: ignore[reportPrivateUsage]
    _required,  # pyright: ignore[reportPrivateUsage]
)

_NO_SNAPSHOTS = "This machine does not have any snapshots"
_GUEST_ADDITIONS_PROPERTY = "/VirtualBox/GuestAdd/Version"


@dataclass(frozen=True, slots=True)
class QualificationReadiness:
    schema_version: Literal[1]
    classification: Literal["read_only_host_readiness"]
    observed_at: datetime
    vm_uuid: UUID
    vm_name: str
    state: str
    snapshot_count: int
    current_snapshot_uuid: UUID | None
    guest_additions_version: str | None
    network_cable_states: tuple[tuple[int, str], ...]
    can_begin_episode: Literal[False]
    blockers: tuple[str, ...]

    def as_json(self) -> dict[str, object]:
        return {
            "schema_version": self.schema_version,
            "classification": self.classification,
            "observed_at": self.observed_at.isoformat(),
            "vm_uuid": str(self.vm_uuid),
            "vm_name": self.vm_name,
            "state": self.state,
            "snapshot_count": self.snapshot_count,
            "current_snapshot_uuid": (
                str(self.current_snapshot_uuid) if self.current_snapshot_uuid else None
            ),
            "guest_additions_version": self.guest_additions_version,
            "network_cable_states": self.network_cable_states,
            "can_begin_episode": self.can_begin_episode,
            "blockers": self.blockers,
        }


def inspect_qualification_clone(
    vboxmanage_path: str | Path,
    requested_vm_uuid: str,
    *,
    timeout_seconds: float = 15.0,
    run: CommandRunner | None = None,
) -> QualificationReadiness:
    """Inspect only fixed VirtualBox metadata calls; no guest credentials or writes."""

    executable = Path(vboxmanage_path)
    if not executable.is_absolute():
        raise VBoxPreflightError("VBoxManage path must be absolute")
    vm_uuid = _parse_uuid(requested_vm_uuid, "requested VM UUID")
    if timeout_seconds <= 0:
        raise VBoxPreflightError("timeout_seconds must be positive")
    execute = run or subprocess.run
    version = _invoke(execute, [str(executable), "--version"], timeout_seconds).strip()
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+r[0-9]+", version) is None:
        raise VBoxPreflightError("malformed VBoxManage version output")
    info_text = _invoke(
        execute,
        [str(executable), "showvminfo", str(vm_uuid), "--machinereadable"],
        timeout_seconds,
    )
    info = _parse_machine_readable(info_text, "showvminfo")
    if _parse_uuid(_required(info, "UUID", "showvminfo"), "reported VM UUID") != vm_uuid:
        raise VBoxPreflightError("requested VM UUID does not match VBoxManage output")
    vm_name = _required(info, "name", "showvminfo")
    guest_os_type = _required(info, "ostype", "showvminfo")
    state = _required(info, "VMState", "showvminfo")
    cable_states = _parse_network_cable_states(info)

    snapshot_args = [str(executable), "snapshot", str(vm_uuid), "list", "--machinereadable"]
    snapshot_result = _call(execute, snapshot_args, timeout_seconds)
    if snapshot_result.returncode == 1 and snapshot_result.stdout.strip() == _NO_SNAPSHOTS:
        snapshots = ()
    elif snapshot_result.returncode == 0:
        snapshots = _parse_snapshots(snapshot_result.stdout)
    else:
        raise VBoxPreflightError(f"VBoxManage snapshot list failed: {snapshot_result.returncode}")
    current_text = info.get("CurrentSnapshotUUID")
    current_uuid = _parse_uuid(current_text, "current snapshot UUID") if current_text else None

    guest_output = _invoke(
        execute,
        [str(executable), "guestproperty", "get", str(vm_uuid), _GUEST_ADDITIONS_PROPERTY],
        timeout_seconds,
    )
    guest_version = _parse_guest_additions(guest_output)
    blockers = ["guest_login_unverified", "clean_reset_unverified", "independent_oracle_unverified"]
    if current_uuid is None or current_uuid not in {item.uuid for item in snapshots}:
        blockers.append("no_current_snapshot")
    if state != "running":
        blockers.append("guest_not_running")
    if not guest_os_type.casefold().startswith("windows"):
        blockers.append("guest_os_not_windows")
    if guest_version is None:
        blockers.append("guest_additions_unverified")
    elif guest_version != version.split("r", maxsplit=1)[0]:
        blockers.append("guest_additions_version_mismatch")
    if any(cable != "off" for _, cable in cable_states):
        blockers.append("network_adapter_connected")

    return QualificationReadiness(
        schema_version=1,
        classification="read_only_host_readiness",
        observed_at=datetime.now(UTC),
        vm_uuid=vm_uuid,
        vm_name=vm_name,
        state=state,
        snapshot_count=len(snapshots),
        current_snapshot_uuid=current_uuid,
        guest_additions_version=guest_version,
        network_cable_states=cable_states,
        can_begin_episode=False,
        blockers=tuple(sorted(blockers)),
    )


def _call(
    run: CommandRunner, args: list[str], timeout_seconds: float
) -> subprocess.CompletedProcess[str]:
    try:
        return run(
            args,
            capture_output=True,
            text=True,
            shell=False,
            timeout=timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise VBoxPreflightError(f"VBoxManage invocation failed: {type(exc).__name__}") from exc


def _invoke(run: CommandRunner, args: list[str], timeout_seconds: float) -> str:
    result = _call(run, args, timeout_seconds)
    if result.returncode != 0:
        raise VBoxPreflightError(f"VBoxManage failed with exit code {result.returncode}")
    return result.stdout


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--vboxmanage", type=Path, required=True)
    parser.add_argument("--vm-uuid", required=True)
    args = parser.parse_args()
    report = inspect_qualification_clone(args.vboxmanage, args.vm_uuid)
    print(json.dumps(report.as_json(), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
