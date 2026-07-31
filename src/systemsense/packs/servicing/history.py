"""Installed update history and read-only reboot-pending facts."""

import importlib
from collections.abc import Iterable, Mapping
from types import TracebackType
from typing import ClassVar, Protocol, cast

from pydantic import Field

from systemsense.domain.evidence import FrozenModel


class InstalledUpdate(FrozenModel):
    kb: str = Field(min_length=1, max_length=255)
    description: str = Field(max_length=1024)
    installed_on: str | None = Field(default=None, max_length=255)


class RebootPendingObservation(FrozenModel):
    pending: bool
    pending_sources: tuple[str, ...]
    checked_sources: tuple[str, ...]


def collect_update_history(
    updates: tuple[InstalledUpdate, ...],
    *,
    max_records: int = 256,
) -> tuple[InstalledUpdate, ...]:
    if not 1 <= max_records <= 1024:
        raise ValueError("max_records must be between 1 and 1024")
    ordered = sorted(
        updates,
        key=lambda update: update.installed_on or "",
        reverse=True,
    )
    return tuple(ordered[:max_records])


def assess_reboot_pending(
    sources: Mapping[str, bool],
) -> RebootPendingObservation:
    checked = tuple(sorted(sources))
    pending = tuple(name for name in checked if sources[name])
    return RebootPendingObservation(
        pending=bool(pending),
        pending_sources=pending,
        checked_sources=checked,
    )


class _WmiService(Protocol):
    def ExecQuery(self, query: str) -> Iterable[object]: ...


class _WmiClient(Protocol):
    def GetObject(self, path: str) -> _WmiService: ...


class _WmiUpdate(Protocol):
    HotFixID: str | None
    Description: str | None
    InstalledOn: str | None


class WmiServicingBackend:
    def updates(self, *, max_records: int = 256) -> tuple[InstalledUpdate, ...]:
        client = cast("_WmiClient", importlib.import_module("win32com.client"))
        service = client.GetObject(r"winmgmts:\\.\root\cimv2")
        rows = service.ExecQuery(
            "SELECT HotFixID,Description,InstalledOn FROM Win32_QuickFixEngineering"
        )
        updates: list[InstalledUpdate] = []
        for raw_row in rows:
            row = cast("_WmiUpdate", raw_row)
            if not row.HotFixID:
                continue
            updates.append(
                InstalledUpdate(
                    kb=str(row.HotFixID),
                    description=str(row.Description or ""),
                    installed_on=(None if row.InstalledOn is None else str(row.InstalledOn)),
                )
            )
            if len(updates) == max_records:
                break
        return collect_update_history(tuple(updates), max_records=max_records)


class _RegistryKey(Protocol):
    def __enter__(self) -> "_RegistryKey": ...

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> None: ...


class _WinReg(Protocol):
    HKEY_LOCAL_MACHINE: int
    KEY_READ: int

    def OpenKey(
        self,
        key: int,
        sub_key: str,
        reserved: int = 0,
        access: int = 0,
    ) -> _RegistryKey: ...

    def QueryValueEx(self, key: _RegistryKey, value_name: str) -> tuple[object, int]: ...


class RegistryRebootBackend:
    _presence_keys: ClassVar[dict[str, str]] = {
        "component_servicing": (
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing"
            r"\RebootPending"
        ),
        "windows_update": (
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update"
            r"\RebootRequired"
        ),
    }

    def sources(self) -> dict[str, bool]:
        registry = cast("_WinReg", importlib.import_module("winreg"))
        sources = {
            name: self._key_exists(registry, path) for name, path in self._presence_keys.items()
        }
        sources["pending_file_rename"] = self._value_exists(
            registry,
            r"SYSTEM\CurrentControlSet\Control\Session Manager",
            "PendingFileRenameOperations",
        )
        return sources

    @staticmethod
    def _key_exists(registry: _WinReg, path: str) -> bool:
        try:
            with registry.OpenKey(
                registry.HKEY_LOCAL_MACHINE,
                path,
                0,
                registry.KEY_READ,
            ):
                return True
        except OSError:
            return False

    @staticmethod
    def _value_exists(registry: _WinReg, path: str, name: str) -> bool:
        try:
            with registry.OpenKey(
                registry.HKEY_LOCAL_MACHINE,
                path,
                0,
                registry.KEY_READ,
            ) as key:
                value, _kind = registry.QueryValueEx(key, name)
                return bool(value)
        except OSError:
            return False
