"""Read-only VirtualBox VM preflight for future controlled lab runs.

This module inspects an already registered VM. It never starts, stops, clones,
restores, or modifies a VM, and its output is only preflight evidence, not proof
that an independent fault rig has run.
"""

from __future__ import annotations

import json
import re
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Literal
from uuid import UUID

type CommandRunner = Callable[..., subprocess.CompletedProcess[str]]

_KEY_VALUE = re.compile(r'^(?P<key>"(?:[^"\\]|\\.)+"|[A-Za-z][A-Za-z0-9_-]*)=(?P<value>.*)$')
_SNAPSHOT_SUFFIX = re.compile(r"(?:-[0-9]+)*$")
_ATTACHED_MEDIUM = re.compile(r"^(?P<controller>.+)-ImageUUID-(?P<port>[0-9]+)-(?P<device>[0-9]+)$")
_NETWORK_CABLE = re.compile(r"^cableconnected(?P<index>[1-9][0-9]*)$")
_NETWORK_ADAPTER = re.compile(r"^nic(?P<index>[1-9][0-9]*)$")
_GUEST_ADDITIONS_PROPERTY = "/VirtualBox/GuestAdd/Version"
_ALLOWED_STATE = "poweroff"


class VBoxPreflightError(ValueError):
    """Raised when VirtualBox cannot provide trustworthy preflight evidence."""


@dataclass(frozen=True, slots=True)
class VBoxSnapshot:
    uuid: UUID
    name: str
    description: str | None


@dataclass(frozen=True, slots=True)
class VBoxAttachedMedium:
    controller: str
    port: int
    device: int
    uuid: UUID
    path: Path
    exists: bool

    @property
    def is_viso(self) -> bool:
        return self.path.suffix.casefold() == ".viso"


@dataclass(frozen=True, slots=True)
class VBoxVmPreflight:
    schema_version: int
    classification: Literal["virtualbox_preflight_only"]
    observed_at: datetime
    vboxmanage_path: str
    vboxmanage_version: str
    vm_uuid: UUID
    vm_name: str
    guest_os_type: str
    state: str
    snapshots: tuple[VBoxSnapshot, ...]
    attached_media: tuple[VBoxAttachedMedium, ...]
    network_cable_states: tuple[tuple[int, str], ...]
    current_snapshot_uuid: UUID | None
    current_snapshot_name: str | None
    guest_additions_observed_version: str | None
    blockers: tuple[str, ...]
    guest_control_blockers: tuple[str, ...]

    @property
    def ready_for_disposable_clone(self) -> bool:
        """Whether the powered-off source snapshot and clone configuration pass."""

        return not self.blockers

    @property
    def guest_control_ready(self) -> bool:
        """Whether this inspection established guest control (it never executes a guest action)."""

        return not self.guest_control_blockers


def inspect_virtualbox_vm(
    vboxmanage_path: str | Path,
    requested_vm_uuid: str,
    *,
    expected_snapshot_uuid: str,
    timeout_seconds: float = 15.0,
    run: CommandRunner | None = None,
) -> VBoxVmPreflight:
    """Return fail-closed proof using a fixed allowlist of read-only VBoxManage calls."""

    executable = Path(vboxmanage_path)
    if not executable.is_absolute():
        raise VBoxPreflightError("VBoxManage path must be absolute")
    vm_uuid = _parse_uuid(requested_vm_uuid, "requested VM UUID")
    expected_snapshot = _parse_uuid(expected_snapshot_uuid, "expected snapshot UUID")
    if timeout_seconds <= 0:
        raise VBoxPreflightError("timeout_seconds must be positive")
    execute = run or subprocess.run

    version_output = _invoke(execute, [str(executable), "--version"], timeout_seconds)
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+r[0-9]+", version_output.strip()):
        raise VBoxPreflightError("malformed VBoxManage version output")

    info_output = _invoke(
        execute,
        [str(executable), "showvminfo", str(vm_uuid), "--machinereadable"],
        timeout_seconds,
    )
    info = _parse_machine_readable(info_output, "showvminfo")
    reported_uuid = _parse_uuid(_required(info, "UUID", "showvminfo"), "reported VM UUID")
    if reported_uuid != vm_uuid:
        raise VBoxPreflightError("requested VM UUID does not match VBoxManage output")
    vm_name = _required(info, "name", "showvminfo")
    guest_os_type = _required(info, "ostype", "showvminfo")
    state = _required(info, "VMState", "showvminfo")

    snapshot_output = _invoke(
        execute,
        [str(executable), "snapshot", str(vm_uuid), "list", "--machinereadable"],
        timeout_seconds,
    )
    snapshots = _parse_snapshots(snapshot_output)
    attached_media = _parse_attached_media(info)
    network_cable_states = _parse_network_cable_states(info)
    current_uuid_text = info.get("CurrentSnapshotUUID")
    current_name = info.get("CurrentSnapshotName")
    current_uuid = (
        _parse_uuid(current_uuid_text, "current snapshot UUID") if current_uuid_text else None
    )
    snapshot_uuids = {snapshot.uuid for snapshot in snapshots}
    if current_uuid is not None and current_uuid not in snapshot_uuids:
        raise VBoxPreflightError("current snapshot is absent from the reported snapshot tree")
    if expected_snapshot not in snapshot_uuids:
        raise VBoxPreflightError("expected snapshot UUID is absent from the reported snapshot tree")

    guest_output = _invoke(
        execute,
        [
            str(executable),
            "guestproperty",
            "get",
            str(vm_uuid),
            _GUEST_ADDITIONS_PROPERTY,
        ],
        timeout_seconds,
    )
    guest_additions_version = _parse_guest_additions(guest_output)

    blockers: list[str] = []
    guest_control_blockers = ["guest_control_not_exercised"]
    if state != _ALLOWED_STATE:
        blockers.append("vm_not_powered_off")
    if not guest_os_type.casefold().startswith("windows"):
        blockers.append("guest_os_not_windows")
    if current_uuid is None or current_name is None:
        blockers.append("current_snapshot_unavailable")
    if current_uuid != expected_snapshot:
        blockers.append("expected_snapshot_not_current")
    if guest_additions_version is None:
        guest_control_blockers.append("guest_additions_unverified")
    elif guest_additions_version != version_output.strip().split("r", maxsplit=1)[0]:
        guest_control_blockers.append("guest_additions_version_mismatch")
    if state != "running":
        guest_control_blockers.append("vm_not_running_for_guest_control")
    if not attached_media:
        blockers.append("attached_media_unavailable")
    elif any(not medium.exists for medium in attached_media):
        blockers.append("attached_media_missing")
    if any(medium.is_viso for medium in attached_media):
        blockers.append("auxiliary_optical_media_attached")
    if any(state_value != "off" for _, state_value in network_cable_states):
        blockers.append("network_adapter_connected")

    return VBoxVmPreflight(
        schema_version=1,
        classification="virtualbox_preflight_only",
        observed_at=datetime.now(UTC),
        vboxmanage_path=str(executable),
        vboxmanage_version=version_output.strip(),
        vm_uuid=vm_uuid,
        vm_name=vm_name,
        guest_os_type=guest_os_type,
        state=state,
        snapshots=snapshots,
        attached_media=attached_media,
        network_cable_states=network_cable_states,
        current_snapshot_uuid=current_uuid,
        current_snapshot_name=current_name,
        guest_additions_observed_version=guest_additions_version,
        blockers=tuple(blockers),
        guest_control_blockers=tuple(guest_control_blockers),
    )


def _invoke(run: CommandRunner, args: list[str], timeout_seconds: float) -> str:
    try:
        result = run(
            args,
            capture_output=True,
            text=True,
            shell=False,
            timeout=timeout_seconds,
            check=False,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise VBoxPreflightError(f"VBoxManage invocation failed: {type(exc).__name__}") from exc
    if result.returncode != 0:
        raise VBoxPreflightError(f"VBoxManage failed with exit code {result.returncode}")
    return result.stdout


def _parse_machine_readable(output: str, command: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line_number, line in enumerate(output.splitlines(), start=1):
        if not line:
            continue
        if command == "showvminfo" and re.fullmatch(r" rec_screen[0-9]+", line):
            continue
        match = _KEY_VALUE.fullmatch(line)
        if match is None:
            raise VBoxPreflightError(f"malformed {command} output at line {line_number}")
        raw_key = match.group("key")
        if raw_key.startswith('"'):
            try:
                key = json.loads(raw_key)
            except json.JSONDecodeError as exc:
                raise VBoxPreflightError(f"malformed quoted {command} key") from exc
            if not isinstance(key, str):
                raise VBoxPreflightError(f"non-string {command} key")
        else:
            key = raw_key
        raw_value = match.group("value")
        if key in values:
            raise VBoxPreflightError(f"duplicate {command} key: {key}")
        if raw_value.startswith('"'):
            try:
                value = json.loads(raw_value)
            except json.JSONDecodeError as exc:
                raise VBoxPreflightError(f"malformed quoted {command} value: {key}") from exc
            if not isinstance(value, str):
                raise VBoxPreflightError(f"non-string {command} value: {key}")
        else:
            value = raw_value
        values[key] = value
    if not values:
        raise VBoxPreflightError(f"empty {command} output")
    return values


def _parse_snapshots(output: str) -> tuple[VBoxSnapshot, ...]:
    values = _parse_machine_readable(output, "snapshot list")
    names = _collect_snapshot_fields(values, "SnapshotName")
    uuids = _collect_snapshot_fields(values, "SnapshotUUID")
    descriptions = _collect_snapshot_fields(values, "SnapshotDescription")
    if not names or set(names) != set(uuids):
        raise VBoxPreflightError("snapshot names and UUIDs are missing or mismatched")
    if not set(descriptions).issubset(names):
        raise VBoxPreflightError("snapshot descriptions do not match snapshot entries")
    snapshots: list[VBoxSnapshot] = []
    for suffix, name in names.items():
        if not name:
            raise VBoxPreflightError("snapshot name is empty")
        snapshots.append(
            VBoxSnapshot(
                uuid=_parse_uuid(uuids[suffix], "snapshot UUID"),
                name=name,
                description=descriptions.get(suffix),
            )
        )
    if len({snapshot.uuid for snapshot in snapshots}) != len(snapshots):
        raise VBoxPreflightError("duplicate snapshot UUID")
    return tuple(snapshots)


def _collect_snapshot_fields(values: dict[str, str], base: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for key, value in values.items():
        if key == base:
            suffix = ""
        elif key.startswith(base + "-"):
            suffix = key[len(base) :]
            if _SNAPSHOT_SUFFIX.fullmatch(suffix) is None:
                raise VBoxPreflightError(f"malformed snapshot field: {key}")
        else:
            continue
        fields[suffix] = value
    return fields


def _parse_guest_additions(output: str) -> str | None:
    value = output.strip()
    if value == "No value set!":
        return None
    match = re.fullmatch(r"Value: ([0-9]+\.[0-9]+\.[0-9]+)", value)
    if match is None:
        raise VBoxPreflightError("malformed Guest Additions version output")
    return match.group(1)


def _parse_attached_media(values: dict[str, str]) -> tuple[VBoxAttachedMedium, ...]:
    media: list[VBoxAttachedMedium] = []
    for key, raw_uuid in values.items():
        match = _ATTACHED_MEDIUM.fullmatch(key)
        if match is None:
            continue
        path_key = f"{match.group('controller')}-{match.group('port')}-{match.group('device')}"
        path_value = values.get(path_key)
        if not path_value:
            raise VBoxPreflightError(f"missing path for attached medium field: {key}")
        medium_path = Path(path_value)
        media.append(
            VBoxAttachedMedium(
                controller=match.group("controller"),
                port=int(match.group("port")),
                device=int(match.group("device")),
                uuid=_parse_uuid(raw_uuid, "attached medium UUID"),
                path=medium_path,
                exists=medium_path.is_file(),
            )
        )
    return tuple(media)


def _parse_network_cable_states(values: dict[str, str]) -> tuple[tuple[int, str], ...]:
    states: list[tuple[int, str]] = []
    adapters: dict[int, str] = {}
    for key, value in values.items():
        adapter_match = _NETWORK_ADAPTER.fullmatch(key)
        if adapter_match is not None:
            adapters[int(adapter_match.group("index"))] = value.casefold()
        match = _NETWORK_CABLE.fullmatch(key)
        if match is not None:
            state_value = value.casefold()
            if state_value not in {"on", "off"}:
                raise VBoxPreflightError(f"invalid VirtualBox network cable state: {key}")
            states.append((int(match.group("index")), state_value))
    if not any(index == 1 for index, _ in states):
        raise VBoxPreflightError("missing required showvminfo field: cableconnected1")
    if 1 not in adapters:
        raise VBoxPreflightError("missing required showvminfo field: nic1")
    cable_indices = {index for index, _ in states}
    for index, mode in adapters.items():
        if mode != "none" and index not in cable_indices:
            raise VBoxPreflightError(f"missing cableconnected{index} for enabled network adapter")
    return tuple(sorted(states))


def _required(values: dict[str, str], key: str, command: str) -> str:
    value = values.get(key)
    if not value:
        raise VBoxPreflightError(f"missing required {command} field: {key}")
    return value


def _parse_uuid(value: str, label: str) -> UUID:
    try:
        return UUID(value)
    except (ValueError, AttributeError) as exc:
        raise VBoxPreflightError(f"invalid {label}") from exc
