"""Gated, current-user WinINet proxy backend.

The policy guard is mandatory and must authoritatively reject managed or
machine-wide settings. No application path currently constructs this backend.
The native bridge is loaded only when explicitly requested.
"""

from __future__ import annotations

import ctypes
import importlib
import os
import sys
from collections.abc import Callable
from ctypes import wintypes
from dataclasses import dataclass
from datetime import datetime
from typing import Protocol, cast

from systemsense.actions.wininet_proxy import ProxyState
from systemsense.domain.time import utc_now

# Windows SDK WinInet.h; query FLAGS_UI, restore/set using FLAGS.
_PER_CONNECTION_OPTION = 75
_SETTINGS_CHANGED = 39
_REFRESH = 37
_FLAGS = 1
_PROXY_SERVER = 2
_FLAGS_UI = 10
_DIRECT = 0x01
_PROXY = 0x02
_AUTO_URL = 0x04
_AUTO_DETECT = 0x08
_KNOWN_FLAGS = _DIRECT | _PROXY | _AUTO_URL | _AUTO_DETECT


@dataclass(frozen=True, slots=True)
class WinInetSnapshot:
    flags: int
    server: str


class WinInetBridge(Protocol):
    def query(self) -> WinInetSnapshot: ...
    def set_flags(self, flags: int) -> None: ...
    def notify(self) -> None: ...


class _OptionValue(ctypes.Union):
    _fields_ = [  # noqa: RUF012 - ctypes requires a mutable class-level field list
        ("dwValue", wintypes.DWORD),
        ("pszValue", ctypes.c_void_p),
        ("ftValue", wintypes.FILETIME),
    ]


class _Option(ctypes.Structure):
    _fields_ = [("dwOption", wintypes.DWORD), ("Value", _OptionValue)]


class _OptionList(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("pszConnection", ctypes.c_void_p),
        ("dwOptionCount", wintypes.DWORD),
        ("dwOptionError", wintypes.DWORD),
        ("pOptions", ctypes.POINTER(_Option)),
    ]


class NativeWinInetBridge:
    """Fixed LAN/default-user option calls; no arbitrary option or path API."""

    def __init__(self) -> None:
        if sys.platform != "win32":
            raise RuntimeError("WinINet is Windows-only")
        wininet = ctypes.WinDLL("wininet.dll", use_last_error=True)
        kernel = ctypes.WinDLL("kernel32.dll", use_last_error=True)
        self._query = wininet.InternetQueryOptionW
        self._query.argtypes = [
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.c_void_p,
            ctypes.POINTER(wintypes.DWORD),
        ]
        self._query.restype = wintypes.BOOL
        self._set = wininet.InternetSetOptionW
        self._set.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]
        self._set.restype = wintypes.BOOL
        self._free = kernel.GlobalFree
        self._free.argtypes = [ctypes.c_void_p]
        self._free.restype = ctypes.c_void_p

    @staticmethod
    def _options(option_ids: tuple[int, ...]) -> tuple[_OptionList, ctypes.Array[_Option]]:
        options = (_Option * len(option_ids))()
        for index, option_id in enumerate(option_ids):
            options[index].dwOption = option_id
        option_list = _OptionList(ctypes.sizeof(_OptionList), None, len(option_ids), 0, options)
        return option_list, options

    def _query_one(self, option_id: int) -> _Option:
        option_list, options = self._options((option_id,))
        size = wintypes.DWORD(ctypes.sizeof(option_list))
        if not self._query(
            None, _PER_CONNECTION_OPTION, ctypes.byref(option_list), ctypes.byref(size)
        ):
            raise OSError(ctypes.get_last_error(), "WinINet option query failed")
        if option_list.dwOptionError or size.value != ctypes.sizeof(option_list):
            raise RuntimeError("WinINet returned an unsupported option layout")
        return options[0]

    def query(self) -> WinInetSnapshot:
        # Windows 7+ UI flags reflect the user's setting; never fall back to
        # legacy flags on a modern supported host.
        flags = int(self._query_one(_FLAGS_UI).Value.dwValue)
        server_option = self._query_one(_PROXY_SERVER)
        address = server_option.Value.pszValue
        try:
            server = ctypes.wstring_at(address) if address else ""
        finally:
            if address and self._free(address):
                raise OSError(ctypes.get_last_error(), "GlobalFree failed")
        return WinInetSnapshot(flags, server)

    def set_flags(self, flags: int) -> None:
        option_list, options = self._options((_FLAGS,))
        options[0].Value.dwValue = flags
        if (
            not self._set(
                None, _PER_CONNECTION_OPTION, ctypes.byref(option_list), ctypes.sizeof(option_list)
            )
            or option_list.dwOptionError
        ):
            raise OSError(ctypes.get_last_error(), "WinINet flag update failed")

    def notify(self) -> None:
        for option in (_SETTINGS_CHANGED, _REFRESH):
            if not self._set(None, option, None, 0):
                raise OSError(ctypes.get_last_error(), "WinINet proxy notification failed")


def _interactive_current_sid() -> str:
    if sys.platform != "win32":
        raise RuntimeError("WinINet is Windows-only")
    kernel = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    session = wintypes.DWORD()
    process_session = kernel.ProcessIdToSessionId
    process_session.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    process_session.restype = wintypes.BOOL
    if not process_session(os.getpid(), ctypes.byref(session)) or session.value == 0:
        raise RuntimeError("WinINet repair requires an interactive user session")
    security = importlib.import_module("win32security")
    api = importlib.import_module("win32api")
    con = importlib.import_module("win32con")
    token = security.OpenProcessToken(api.GetCurrentProcess(), con.TOKEN_QUERY)
    try:
        user_sid = security.GetTokenInformation(token, security.TokenUser)[0]
        return cast(str, security.ConvertSidToStringSid(user_sid))
    finally:
        token.Close()


class NativeWinInetProxyBackend:
    """ProxyBackend with explicit policy and identity gates around every call.

    A policy guard is required rather than guessing from a subset of registry
    keys. Until an authoritative per-user/managed-policy guard is integrated,
    this class must not be wired to a repair route.
    """

    def __init__(
        self,
        *,
        policy_guard: Callable[[], bool],
        bridge: WinInetBridge | None = None,
        identity: Callable[[], str] = _interactive_current_sid,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._bridge = bridge if bridge is not None else NativeWinInetBridge()
        self._identity = identity
        self._policy_guard = policy_guard
        self._clock = clock
        self._snapshot: tuple[str, WinInetSnapshot] | None = None
        self._pre_disable: WinInetSnapshot | None = None
        self._post_disable: WinInetSnapshot | None = None

    def _admit(self) -> str:
        if not self._policy_guard():
            raise RuntimeError("proxy policy is managed or unknown")
        sid = self._identity()
        if not sid.startswith("S-1-5-21-"):
            raise RuntimeError("unsupported current-user identity")
        return sid

    @staticmethod
    def _validate(snapshot: WinInetSnapshot) -> None:
        if snapshot.flags & ~_KNOWN_FLAGS or not snapshot.flags & _DIRECT:
            raise RuntimeError("unsupported WinINet proxy flags")
        if snapshot.flags & _PROXY and not snapshot.server:
            raise RuntimeError("unsupported proxy without server")

    def current_user_sid(self) -> str:
        return self._admit()

    def read(self) -> ProxyState:
        sid = self._admit()
        snapshot = self._bridge.query()
        self._validate(snapshot)
        if self._admit() != sid:
            raise RuntimeError("current-user identity changed during read")
        self._snapshot = (sid, snapshot)
        return ProxyState(sid, bool(snapshot.flags & _PROXY), snapshot.server, self._clock())

    def set_enabled(self, value: bool) -> None:
        sid = self._admit()
        if self._snapshot is None:
            raise RuntimeError("no live proxy snapshot")
        if self._snapshot[0] != sid:
            raise RuntimeError("current-user identity changed")
        expected = self._post_disable if value else self._snapshot[1]
        if expected is None:
            raise RuntimeError("no prior disable snapshot for restore")
        live = self._bridge.query()
        self._validate(live)
        if live != expected:
            raise RuntimeError("proxy state changed before write")
        if value:
            if self._pre_disable is None or live.flags & _PROXY:
                raise RuntimeError("no matching disabled state to restore")
            target = self._pre_disable
        else:
            if not live.flags & _PROXY:
                raise RuntimeError("explicit proxy is already disabled")
            target = WinInetSnapshot((live.flags & ~_PROXY) | _DIRECT, live.server)
            self._pre_disable = live
            self._post_disable = target
        if self._admit() != sid:
            raise RuntimeError("current-user identity changed before write")
        self._bridge.set_flags(target.flags)
        self._bridge.notify()
        actual = self._bridge.query()
        self._validate(actual)
        if self._admit() != sid or actual != target:
            raise RuntimeError("WinINet post-write state is uncertain")
        self._snapshot = (sid, actual)
        if value:
            self._pre_disable = None
            self._post_disable = None
