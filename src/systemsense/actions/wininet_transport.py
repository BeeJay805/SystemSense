"""Opt-in, process-isolated WinINet transport for one owned HTTPS lab check.

This module is not wired into an application route. The trusted composition
root must admit endpoint ownership and externality before constructing it;
DNS syntax and a public-looking address are not proof of either property.
WinINet is intentionally used only inside an interactive current-user child,
never a service. The parent owns the hard deadline and kills a blocked child.
"""

from __future__ import annotations

import ctypes
import ipaddress
import json
import multiprocessing
import re
import socket
import sys
import time
from collections.abc import Callable
from ctypes import wintypes
from multiprocessing.connection import Connection
from typing import cast

from systemsense.actions.wininet_native import (
    NativeWinInetBridge,
    _interactive_current_sid,  # pyright: ignore[reportPrivateUsage]
)
from systemsense.actions.wininet_oracle import LabCheckDescriptor, LabWinInetResponse

_PRECONFIG = 0
_DIRECT = 1
_HTTP_SERVICE = 3
_HTTPS_PORT = 443
_SECURE = 0x00800000
_NO_AUTO_REDIRECT = 0x00200000
_NO_AUTH = 0x00040000
_NO_COOKIES = 0x00080000
_NO_UI = 0x00000200
_NO_CACHE_WRITE = 0x04000000
_RELOAD = 0x80000000
_REQUEST_FLAGS = (
    _SECURE | _NO_AUTO_REDIRECT | _NO_AUTH | _NO_COOKIES | _NO_UI | _NO_CACHE_WRITE | _RELOAD
)
_CONNECT_TIMEOUT = 2
_SEND_TIMEOUT = 5
_RECEIVE_TIMEOUT = 6
_CONNECT_RETRIES = 3
_SUPPRESS_SERVER_AUTH = 104
_HTTP_STATUS_NUMBER = 19 | 0x20000000
# Deadline and invalid-result codes are parent-generated, never accepted from a child.
_ERROR_CODE = re.compile(r"(?:wininet_[0-9]{1,5}|worker_error)")


def _failure(descriptor: LabCheckDescriptor, elapsed_ms: int, code: str) -> LabWinInetResponse:
    return LabWinInetResponse(
        status=None,
        body_bytes=0,
        redirected=False,
        final_host=descriptor.host,
        executing_user_sid=descriptor.expected_user_sid,
        elapsed_ms=max(0, elapsed_ms),
        error=code,
    )


def _validate_result(descriptor: LabCheckDescriptor, value: object) -> LabWinInetResponse:
    if not isinstance(value, dict):
        raise ValueError("invalid worker result")
    fields = cast(dict[str, object], value)
    if set(fields) != {
        "status",
        "body_bytes",
        "redirected",
        "final_host",
        "executing_user_sid",
        "elapsed_ms",
        "error",
    }:
        raise ValueError("invalid worker result")
    status = fields["status"]
    error = fields["error"]
    if (
        (status is not None and (type(status) is not int or not 100 <= status <= 599))
        or type(fields["body_bytes"]) is not int
        or fields["body_bytes"] not in (0, 1)
        or type(fields["redirected"]) is not bool
        or fields["final_host"] != descriptor.host
        or fields["executing_user_sid"] != descriptor.expected_user_sid
        or type(fields["elapsed_ms"]) is not int
        or not 0 <= fields["elapsed_ms"] <= 60_000
        or (error is not None and (type(error) is not str or _ERROR_CODE.fullmatch(error) is None))
    ):
        raise ValueError("invalid worker result")
    return LabWinInetResponse(
        status=status,
        body_bytes=cast(int, fields["body_bytes"]),
        redirected=fields["redirected"],
        final_host=cast(str, fields["final_host"]),
        executing_user_sid=cast(str, fields["executing_user_sid"]),
        elapsed_ms=fields["elapsed_ms"],
        error=error,
    )


def _worker_entry(
    descriptor: LabCheckDescriptor,
    sender: Connection,
    target: Callable[[LabCheckDescriptor], LabWinInetResponse],
) -> None:
    try:
        response = target(descriptor)
        if response.error is not None and _ERROR_CODE.fullmatch(response.error) is None:
            raise ValueError("unsafe worker error code")
        # Deliberately transmit only a fixed, small JSON record. Exception
        # strings and HTTP content never cross the process boundary.
        payload = json.dumps(
            {
                "status": response.status,
                "body_bytes": response.body_bytes,
                "redirected": response.redirected,
                "final_host": response.final_host,
                "executing_user_sid": response.executing_user_sid,
                "elapsed_ms": response.elapsed_ms,
                "error": response.error,
            },
            separators=(",", ":"),
        ).encode("ascii")
        if len(payload) <= 512:
            sender.send_bytes(payload)
    except Exception:
        try:
            sender.send_bytes(b'{"error":"worker_error"}')
        except (OSError, ValueError):
            pass
    finally:
        sender.close()


def _run_isolated(
    descriptor: LabCheckDescriptor,
    target: Callable[[LabCheckDescriptor], LabWinInetResponse],
) -> LabWinInetResponse:
    """Private isolation primitive; production always uses `_native_probe`."""
    started = time.monotonic()
    context = multiprocessing.get_context("spawn")
    receiver, sender = context.Pipe(duplex=False)
    process = context.Process(target=_worker_entry, args=(descriptor, sender, target), daemon=True)
    launched = False
    try:
        process.start()
        launched = True
        sender.close()
        remaining = descriptor.timeout_ms / 1000 - (time.monotonic() - started)
        process.join(max(0.0, remaining))
        if process.is_alive():
            return _failure(
                descriptor, round((time.monotonic() - started) * 1000), "deadline_exceeded"
            )
        elapsed_ms = round((time.monotonic() - started) * 1000)
        if elapsed_ms > descriptor.timeout_ms:
            return _failure(descriptor, elapsed_ms, "deadline_exceeded")
        if process.exitcode != 0 or not receiver.poll(0):
            return _failure(descriptor, elapsed_ms, "worker_error")
        try:
            payload = receiver.recv_bytes(512)
            value: object = json.loads(payload)
            if value == {"error": "worker_error"}:
                return _failure(descriptor, elapsed_ms, "worker_error")
            return _validate_result(descriptor, value)
        except (EOFError, OSError, ValueError, UnicodeDecodeError):
            return _failure(descriptor, elapsed_ms, "invalid_worker_result")
    finally:
        receiver.close()
        sender.close()
        if launched:
            if process.is_alive():
                process.kill()
                process.join(1)
                if process.is_alive():
                    raise RuntimeError("failed to terminate WinINet worker")
            process.close()


def _public_dns_only(host: str) -> None:
    """Additional fail-closed local-address guard, not endpoint ownership proof."""
    results = socket.getaddrinfo(host, _HTTPS_PORT, type=socket.SOCK_STREAM)
    addresses = {entry[4][0] for entry in results}
    if not addresses or any(not ipaddress.ip_address(value).is_global for value in addresses):
        raise RuntimeError("lab endpoint resolved to a non-public address")


def _manual_proxy_only() -> None:
    """Avoid unbounded WPAD/PAC fetches from PRECONFIG in this lab transport."""
    snapshot = NativeWinInetBridge().query()
    if snapshot.flags & ~0x03 or not snapshot.flags & 0x01:
        raise RuntimeError("automatic or unknown WinINet proxy setting")
    if snapshot.flags & 0x02 and not snapshot.server:
        raise RuntimeError("manual proxy has no server")


def _native_probe(
    descriptor: LabCheckDescriptor, *, access_type: int = _PRECONFIG
) -> LabWinInetResponse:
    """Perform exactly one metadata-only GET inside the current-user child."""
    started = time.monotonic()
    if access_type not in (_PRECONFIG, _DIRECT):
        raise ValueError("unsupported WinINet access type")
    if sys.platform != "win32":
        raise RuntimeError("WinINet requires Windows")
    if _interactive_current_sid() != descriptor.expected_user_sid:
        raise RuntimeError("lab worker identity mismatch")
    if access_type == _PRECONFIG:
        _manual_proxy_only()
    _public_dns_only(descriptor.host)
    if _interactive_current_sid() != descriptor.expected_user_sid:
        raise RuntimeError("lab worker identity changed")
    library = ctypes.WinDLL("wininet.dll", use_last_error=True)
    open_internet = library.InternetOpenW
    open_internet.argtypes = [
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
    ]
    open_internet.restype = ctypes.c_void_p
    connect = library.InternetConnectW
    connect.argtypes = [
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        wintypes.WORD,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        wintypes.DWORD,
        ctypes.c_size_t,
    ]
    connect.restype = ctypes.c_void_p
    open_request = library.HttpOpenRequestW
    open_request.argtypes = [
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_size_t,
    ]
    open_request.restype = ctypes.c_void_p
    set_option = library.InternetSetOptionW
    set_option.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.c_void_p, wintypes.DWORD]
    set_option.restype = wintypes.BOOL
    send = library.HttpSendRequestW
    send.argtypes = [
        ctypes.c_void_p,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    send.restype = wintypes.BOOL
    query = library.HttpQueryInfoW
    query.argtypes = [
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.c_void_p,
        ctypes.POINTER(wintypes.DWORD),
        ctypes.POINTER(wintypes.DWORD),
    ]
    query.restype = wintypes.BOOL
    read = library.InternetReadFile
    read.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(wintypes.DWORD),
    ]
    read.restype = wintypes.BOOL
    close = library.InternetCloseHandle
    close.argtypes = [ctypes.c_void_p]
    close.restype = wintypes.BOOL

    handles: list[int] = []
    result: LabWinInetResponse | None = None
    try:
        root = open_internet("SystemSense-LabOracle", access_type, None, None, 0)
        if not root:
            raise OSError(ctypes.get_last_error())
        handles.append(root)
        for option in (_CONNECT_TIMEOUT, _SEND_TIMEOUT, _RECEIVE_TIMEOUT):
            value = wintypes.DWORD(descriptor.timeout_ms)
            if not set_option(root, option, ctypes.byref(value), ctypes.sizeof(value)):
                raise OSError(ctypes.get_last_error())
        retries = wintypes.DWORD(1)
        if not set_option(root, _CONNECT_RETRIES, ctypes.byref(retries), ctypes.sizeof(retries)):
            raise OSError(ctypes.get_last_error())
        session = connect(root, descriptor.host, _HTTPS_PORT, None, None, _HTTP_SERVICE, 0, 0)
        if not session:
            raise OSError(ctypes.get_last_error())
        handles.append(session)
        request = open_request(session, "GET", descriptor.path, None, None, None, _REQUEST_FLAGS, 0)
        if not request:
            raise OSError(ctypes.get_last_error())
        handles.append(request)
        suppress_auth = wintypes.BOOL(1)
        if not set_option(
            request,
            _SUPPRESS_SERVER_AUTH,
            ctypes.byref(suppress_auth),
            ctypes.sizeof(suppress_auth),
        ):
            raise OSError(ctypes.get_last_error())
        if not send(request, None, 0, None, 0):
            raise OSError(ctypes.get_last_error())
        status = wintypes.DWORD()
        length = wintypes.DWORD(ctypes.sizeof(status))
        index = wintypes.DWORD()
        if not query(
            request,
            _HTTP_STATUS_NUMBER,
            ctypes.byref(status),
            ctypes.byref(length),
            ctypes.byref(index),
        ) or length.value != ctypes.sizeof(status):
            raise OSError(ctypes.get_last_error())
        content = ctypes.create_string_buffer(1)
        count = wintypes.DWORD()
        if not read(request, content, 1, ctypes.byref(count)) or count.value > 1:
            raise OSError(ctypes.get_last_error())
        if _interactive_current_sid() != descriptor.expected_user_sid:
            raise RuntimeError("lab worker identity changed")
        result = LabWinInetResponse(
            status=status.value,
            body_bytes=count.value,
            redirected=300 <= status.value < 400,
            final_host=descriptor.host,
            executing_user_sid=descriptor.expected_user_sid,
            elapsed_ms=round((time.monotonic() - started) * 1000),
            error=None,
        )
    except OSError as exc:
        code = exc.args[0] if exc.args and type(exc.args[0]) is int else 0
        result = _failure(descriptor, round((time.monotonic() - started) * 1000), f"wininet_{code}")
    finally:
        close_failed = False
        for handle in reversed(handles):
            if not close(handle):
                close_failed = True
        if close_failed:
            result = _failure(
                descriptor, round((time.monotonic() - started) * 1000), "worker_error"
            )
    return result


def _native_direct_probe(descriptor: LabCheckDescriptor) -> LabWinInetResponse:
    """Force same-stack proxy bypass against the same registered endpoint."""
    return _native_probe(descriptor, access_type=_DIRECT)


class _RegisteredProcessTransport:
    """A registered endpoint only; never accepts a caller URL or native handle."""

    def __init__(
        self,
        *,
        descriptor: LabCheckDescriptor,
        endpoint_admission: Callable[[LabCheckDescriptor], bool],
        current_user_sid: Callable[[], str] = _interactive_current_sid,
    ) -> None:
        self._descriptor = descriptor
        self._endpoint_admission = endpoint_admission
        self._current_user_sid = current_user_sid

    def _worker_target(self) -> Callable[[LabCheckDescriptor], LabWinInetResponse]:
        raise NotImplementedError

    def check(self, descriptor: LabCheckDescriptor) -> LabWinInetResponse:
        if descriptor != self._descriptor:
            raise ValueError("unregistered lab check descriptor")
        if self._current_user_sid() != descriptor.expected_user_sid:
            raise RuntimeError("current-user identity does not match lab check")
        if not self._endpoint_admission(descriptor):
            raise RuntimeError("lab endpoint not admitted")
        result = _run_isolated(descriptor, self._worker_target())
        if self._current_user_sid() != descriptor.expected_user_sid:
            raise RuntimeError("current-user identity changed during lab check")
        return result


class ProcessIsolatedWinInetTransport(_RegisteredProcessTransport):
    """Current-user PRECONFIG path. PAC/WPAD settings are refused."""

    def _worker_target(self) -> Callable[[LabCheckDescriptor], LabWinInetResponse]:
        return _native_probe


class ProcessIsolatedDirectWinInetTransport(_RegisteredProcessTransport):
    """Independent same-stack DIRECT path, bypassing WinINet proxy settings."""

    def _worker_target(self) -> Callable[[LabCheckDescriptor], LabWinInetResponse]:
        return _native_direct_probe
