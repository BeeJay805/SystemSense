"""Gated, current-user WinINet proxy backend.

The native bridge is loaded only when explicitly requested. No application
path currently constructs this backend or invokes its writer.
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

from systemsense.actions.wininet_policy import current_user_proxy_policy_allows_write
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
_WTS_CONNECT_STATE = 8
_WTS_ACTIVE = 0
_ERROR_NO_TOKEN = 1008
_TOKEN_QUERY = 0x0008


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


def _require_active_session(session_id: int) -> None:
    """Deny a disconnected or service session before a current-user write.

    WTSConnectState is a DWORD allocated by WTSQuerySessionInformationW. No
    fallback is safe when Remote Desktop Services cannot report its state.
    """
    if session_id == 0 or session_id == 0xFFFFFFFF:
        raise RuntimeError("WinINet repair requires an active user session")
    wts = ctypes.WinDLL("wtsapi32.dll", use_last_error=True)
    query = wts.WTSQuerySessionInformationW
    query.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_void_p),
        ctypes.POINTER(wintypes.DWORD),
    ]
    query.restype = wintypes.BOOL
    free = wts.WTSFreeMemory
    free.argtypes = [ctypes.c_void_p]
    free.restype = None
    buffer = ctypes.c_void_p()
    length = wintypes.DWORD()
    try:
        if not query(
            None, session_id, _WTS_CONNECT_STATE, ctypes.byref(buffer), ctypes.byref(length)
        ):
            raise RuntimeError("cannot establish an active user session")
        if not buffer.value or length.value != ctypes.sizeof(wintypes.DWORD):
            raise RuntimeError("invalid user session state")
        state = ctypes.cast(buffer, ctypes.POINTER(wintypes.DWORD)).contents.value
        if state != _WTS_ACTIVE:
            raise RuntimeError("WinINet repair requires an active user session")
    finally:
        if buffer.value:
            free(buffer)


def _require_no_thread_impersonation() -> None:
    """A process SID cannot authorize a write made as an impersonated thread."""
    kernel = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    security = ctypes.WinDLL("advapi32.dll", use_last_error=True)
    current_thread = kernel.GetCurrentThread
    current_thread.argtypes = []
    current_thread.restype = ctypes.c_void_p
    open_token = security.OpenThreadToken
    open_token.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        wintypes.BOOL,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    open_token.restype = wintypes.BOOL
    close = kernel.CloseHandle
    close.argtypes = [ctypes.c_void_p]
    close.restype = wintypes.BOOL
    token = ctypes.c_void_p()
    if open_token(current_thread(), _TOKEN_QUERY, True, ctypes.byref(token)):
        if token.value:
            close(token)
        raise RuntimeError("impersonated thread cannot authorize WinINet repair")
    if ctypes.get_last_error() != _ERROR_NO_TOKEN:
        raise RuntimeError("cannot establish current thread token state")


def _interactive_current_sid() -> str:
    if sys.platform != "win32":
        raise RuntimeError("WinINet is Windows-only")
    _require_no_thread_impersonation()
    kernel = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    session = wintypes.DWORD()
    process_session = kernel.ProcessIdToSessionId
    process_session.argtypes = [wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    process_session.restype = wintypes.BOOL
    if not process_session(os.getpid(), ctypes.byref(session)) or session.value == 0:
        raise RuntimeError("WinINet repair requires an interactive user session")
    _require_active_session(session.value)
    security = importlib.import_module("win32security")
    api = importlib.import_module("win32api")
    con = importlib.import_module("win32con")
    token = security.OpenProcessToken(api.GetCurrentProcess(), con.TOKEN_QUERY)
    try:
        if (
            security.GetTokenInformation(token, security.TokenSessionId) != session.value
            or security.GetTokenInformation(token, security.TokenType) != security.TokenPrimary
        ):
            raise RuntimeError("current-user token does not match active session")
        user_sid = security.GetTokenInformation(token, security.TokenUser)[0]
        sid = cast(str, security.ConvertSidToStringSid(user_sid))
        _require_no_thread_impersonation()
        _require_active_session(session.value)
        return sid
    finally:
        token.Close()


class NativeWinInetProxyBackend:
    """ProxyBackend with explicit policy and identity gates around every call.

    The default guard checks documented and ambiguous fixed policy locations.
    It is not a complete MDM/GPP/app-policy inventory; this class remains
    unexposed until an end-to-end repair is independently qualified.
    """

    def __init__(
        self,
        *,
        bridge: WinInetBridge | None = None,
        identity: Callable[[], str] = _interactive_current_sid,
        clock: Callable[[], datetime] = utc_now,
    ) -> None:
        self._bridge = bridge if bridge is not None else NativeWinInetBridge()
        self._identity = identity
        self._clock = clock
        self._snapshot: tuple[str, WinInetSnapshot] | None = None
        self._pre_disable: WinInetSnapshot | None = None
        self._post_disable: WinInetSnapshot | None = None

    def _admit(self) -> str:
        sid = self._identity()
        if not sid.startswith("S-1-5-21-"):
            raise RuntimeError("unsupported current-user identity")
        if not current_user_proxy_policy_allows_write():
            raise RuntimeError("proxy policy is managed or unknown")
        if self._identity() != sid:
            raise RuntimeError("current-user identity changed during policy check")
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
