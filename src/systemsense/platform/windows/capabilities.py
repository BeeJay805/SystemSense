"""Cached detection of optional Windows diagnostic capabilities."""

import ctypes
import os
import platform
import shutil
from collections.abc import Callable
from datetime import timedelta
from enum import StrEnum
from pathlib import Path
from typing import ClassVar, Protocol, cast

from pydantic import Field

from systemsense.domain.evidence import FrozenModel
from systemsense.domain.time import UtcDateTime, ensure_utc, utc_now


class CapabilityState(StrEnum):
    AVAILABLE = "available"
    UNAVAILABLE = "unavailable"
    DENIED = "denied"
    UNSUPPORTED = "unsupported"
    ERROR = "error"


class CapabilityProbe(FrozenModel):
    state: CapabilityState
    detail: str = Field(min_length=1, max_length=1000)


class SystemInfo(FrozenModel):
    platform: str = Field(min_length=1)
    windows_build: str | None = None
    architecture: str = Field(min_length=1)


class Capability(FrozenModel):
    name: str = Field(pattern=r"^[a-z][a-z0-9_.-]*$")
    state: CapabilityState
    detail: str = Field(min_length=1, max_length=1000)
    checked_at: UtcDateTime


class CapabilitySnapshot(FrozenModel):
    platform: str
    windows_build: str | None
    architecture: str
    captured_at: UtcDateTime
    expires_at: UtcDateTime
    capabilities: tuple[Capability, ...]

    def capability(self, name: str) -> Capability:
        for capability in self.capabilities:
            if capability.name == name:
                return capability
        raise KeyError(name)


class CapabilityBackend(Protocol):
    def system_info(self) -> SystemInfo: ...

    def probe_dll(self, name: str) -> CapabilityProbe: ...

    def probe_event_channel(self, name: str) -> CapabilityProbe: ...

    def probe_wer_access(self) -> CapabilityProbe: ...

    def probe_tool(self, name: str) -> CapabilityProbe: ...

    def probe_standard_user(self) -> CapabilityProbe: ...


class _Shell32(Protocol):
    def IsUserAnAdmin(self) -> int: ...


class CapabilityDetector:
    _dlls = ("wevtapi.dll", "setupapi.dll", "cfgmgr32.dll", "pdh.dll")
    _event_channels = (
        ("event_channel.application", "Application"),
        ("event_channel.system", "System"),
        (
            "event_channel.windows_update",
            "Microsoft-Windows-WindowsUpdateClient/Operational",
        ),
    )
    _tools = ("nvidia-smi.exe", "amd-smi.exe")

    def __init__(
        self,
        backend: CapabilityBackend,
        *,
        cache_ttl: timedelta = timedelta(minutes=5),
    ) -> None:
        if cache_ttl <= timedelta(0):
            raise ValueError("cache_ttl must be positive")
        self._backend = backend
        self._cache_ttl = cache_ttl
        self._cached: CapabilitySnapshot | None = None

    def detect(self, *, now: UtcDateTime | None = None) -> CapabilitySnapshot:
        checked_at = ensure_utc(now or utc_now())
        if self._cached is not None and checked_at < self._cached.expires_at:
            return self._cached

        try:
            system_info = self._backend.system_info()
        except Exception as error:
            system_info = SystemInfo(
                platform="unknown",
                windows_build=None,
                architecture="unknown",
            )
            system_error = f"{type(error).__name__}: {error}"
        else:
            system_error = None

        probes: list[Capability] = []
        if system_info.platform != "Windows":
            for name in self._capability_names():
                probes.append(
                    Capability(
                        name=name,
                        state=CapabilityState.UNSUPPORTED,
                        detail=f"requires Windows; detected {system_info.platform}",
                        checked_at=checked_at,
                    )
                )
        elif system_error is not None:
            for name in self._capability_names():
                probes.append(
                    Capability(
                        name=name,
                        state=CapabilityState.ERROR,
                        detail=system_error,
                        checked_at=checked_at,
                    )
                )
        else:
            for dll_name in self._dlls:
                capability_name = f"dll.{dll_name.removesuffix('.dll')}"
                probes.append(
                    self._safe_probe(
                        capability_name,
                        lambda name=dll_name: self._backend.probe_dll(name),
                        checked_at,
                    )
                )
            for capability_name, channel_name in self._event_channels:
                probes.append(
                    self._safe_probe(
                        capability_name,
                        lambda name=channel_name: self._backend.probe_event_channel(name),
                        checked_at,
                    )
                )
            probes.append(
                self._safe_probe(
                    "wer.report_archive",
                    self._backend.probe_wer_access,
                    checked_at,
                )
            )
            for tool_name in self._tools:
                capability_name = f"tool.{tool_name.removesuffix('.exe').replace('-', '_')}"
                probes.append(
                    self._safe_probe(
                        capability_name,
                        lambda name=tool_name: self._backend.probe_tool(name),
                        checked_at,
                    )
                )
            probes.append(
                self._safe_probe(
                    "permission.standard_user",
                    self._backend.probe_standard_user,
                    checked_at,
                )
            )

        snapshot = CapabilitySnapshot(
            platform=system_info.platform,
            windows_build=system_info.windows_build,
            architecture=system_info.architecture,
            captured_at=checked_at,
            expires_at=checked_at + self._cache_ttl,
            capabilities=tuple(probes),
        )
        self._cached = snapshot
        return snapshot

    @classmethod
    def _capability_names(cls) -> tuple[str, ...]:
        dlls = tuple(f"dll.{name.removesuffix('.dll')}" for name in cls._dlls)
        channels = tuple(name for name, _channel in cls._event_channels)
        tools = tuple(f"tool.{name.removesuffix('.exe').replace('-', '_')}" for name in cls._tools)
        return (*dlls, *channels, "wer.report_archive", *tools, "permission.standard_user")

    @staticmethod
    def _safe_probe(
        name: str,
        probe: Callable[[], CapabilityProbe],
        checked_at: UtcDateTime,
    ) -> Capability:
        try:
            result = probe()
        except PermissionError as error:
            result = CapabilityProbe(
                state=CapabilityState.DENIED,
                detail=f"PermissionError: {error}",
            )
        except Exception as error:
            result = CapabilityProbe(
                state=CapabilityState.ERROR,
                detail=f"{type(error).__name__}: {error}",
            )
        return Capability(
            name=name,
            state=result.state,
            detail=result.detail,
            checked_at=checked_at,
        )


class SystemCapabilityBackend:
    """Standard-library probes against fixed local Windows resources."""

    _channel_files: ClassVar[dict[str, str]] = {
        "Application": "Application.evtx",
        "System": "System.evtx",
        "Microsoft-Windows-WindowsUpdateClient/Operational": (
            "Microsoft-Windows-WindowsUpdateClient%4Operational.evtx"
        ),
    }
    _tools = frozenset({"nvidia-smi.exe", "amd-smi.exe"})

    def system_info(self) -> SystemInfo:
        return SystemInfo(
            platform=platform.system(),
            windows_build=platform.version() if platform.system() == "Windows" else None,
            architecture=platform.machine() or "unknown",
        )

    def probe_dll(self, name: str) -> CapabilityProbe:
        if platform.system() != "Windows":
            return self._unsupported()
        loader = cast(
            "Callable[[str], object] | None",
            getattr(ctypes, "WinDLL", None),
        )
        if loader is None:
            return CapabilityProbe(
                state=CapabilityState.UNSUPPORTED,
                detail="ctypes WinDLL loader is unavailable",
            )
        try:
            loader(name)
        except OSError as error:
            return CapabilityProbe(
                state=CapabilityState.UNAVAILABLE,
                detail=f"{name} could not be loaded: {error}",
            )
        return CapabilityProbe(
            state=CapabilityState.AVAILABLE,
            detail=f"{name} loaded successfully",
        )

    def probe_event_channel(self, name: str) -> CapabilityProbe:
        filename = self._channel_files.get(name)
        if filename is None:
            return CapabilityProbe(
                state=CapabilityState.UNSUPPORTED,
                detail="event channel is not registered",
            )
        event_path = (
            Path(os.environ.get("SystemRoot", r"C:\Windows"))
            / "System32"
            / "winevt"
            / "Logs"
            / filename
        )
        if not event_path.exists():
            return CapabilityProbe(
                state=CapabilityState.UNAVAILABLE,
                detail=f"{name} log file is absent",
            )
        if not os.access(event_path, os.R_OK):
            return CapabilityProbe(
                state=CapabilityState.DENIED,
                detail=f"{name} log file is not readable",
            )
        return CapabilityProbe(
            state=CapabilityState.AVAILABLE,
            detail=f"{name} log file is readable",
        )

    def probe_wer_access(self) -> CapabilityProbe:
        roots = tuple(
            Path(value) / "Microsoft" / "Windows" / "WER" / "ReportArchive"
            for value in (
                os.environ.get("ProgramData"),
                os.environ.get("LOCALAPPDATA"),
            )
            if value
        )
        existing = tuple(path for path in roots if path.exists())
        if not existing:
            return CapabilityProbe(
                state=CapabilityState.UNAVAILABLE,
                detail="no WER report archive is present",
            )
        if any(os.access(path, os.R_OK) for path in existing):
            return CapabilityProbe(
                state=CapabilityState.AVAILABLE,
                detail="at least one WER report archive is readable",
            )
        return CapabilityProbe(
            state=CapabilityState.DENIED,
            detail="WER report archives are not readable",
        )

    def probe_tool(self, name: str) -> CapabilityProbe:
        if name not in self._tools:
            return CapabilityProbe(
                state=CapabilityState.UNSUPPORTED,
                detail="vendor tool is not registered",
            )
        resolved = shutil.which(name)
        if resolved is None:
            return CapabilityProbe(
                state=CapabilityState.UNAVAILABLE,
                detail=f"{name} was not found",
            )
        return CapabilityProbe(
            state=CapabilityState.AVAILABLE,
            detail=f"{name} is available",
        )

    def probe_standard_user(self) -> CapabilityProbe:
        if platform.system() != "Windows":
            return self._unsupported()
        loader = cast(
            "Callable[[str], object] | None",
            getattr(ctypes, "WinDLL", None),
        )
        if loader is None:
            return self._unsupported()
        shell32 = cast("_Shell32", loader("shell32"))
        if shell32.IsUserAnAdmin() == 0:
            return CapabilityProbe(
                state=CapabilityState.AVAILABLE,
                detail="process is running without elevation",
            )
        return CapabilityProbe(
            state=CapabilityState.UNAVAILABLE,
            detail="process is elevated",
        )

    @staticmethod
    def _unsupported() -> CapabilityProbe:
        return CapabilityProbe(
            state=CapabilityState.UNSUPPORTED,
            detail="requires Windows",
        )
