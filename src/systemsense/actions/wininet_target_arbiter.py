"""Cross-process exclusion for the one registered WinINet user-proxy target."""

from __future__ import annotations

import ctypes
import json
import os
import re
from collections.abc import Generator
from contextlib import contextmanager
from hashlib import sha256
from threading import Lock

from systemsense.actions.contracts import ActionAuthorizationError

_LOCATOR = re.compile(r"wininet_proxy:S-1-5-21-((?:0|[1-9][0-9]*)-){3}(?:0|[1-9][0-9]*)")
_KEY = re.compile(r"[0-9a-f]{64}")
_ACQUIRED = 0
_ABANDONED = 0x80
_local_guard = Lock()
_local_active: set[str] = set()


def wininet_target_key(locator: str) -> str:
    """Return the durable target-lock key only for a canonical SID locator."""

    if _LOCATOR.fullmatch(locator) is None or any(
        int(part) > 0xFFFFFFFF for part in locator.split(":", 1)[1].split("-")[4:]
    ):
        raise ActionAuthorizationError("execution requires one canonical WinINet SID target")
    return sha256(json.dumps(locator, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


@contextmanager
def hold_wininet_target_exclusive(target_key: str) -> Generator[bool]:
    """Try the same target mutex used by writer and terminal reconciler.

    A contended, abandoned, or unavailable mutex grants no permission. The
    durable execution and journal checks remain necessary after process death.
    """

    if _KEY.fullmatch(target_key) is None:
        raise ActionAuthorizationError("invalid WinINet target key")
    if os.name != "nt":
        yield False
        return
    with _local_guard:
        if target_key in _local_active:
            duplicate = True
        else:
            _local_active.add(target_key)
            duplicate = False
    if duplicate:
        yield False
        return
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateMutexW.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p)
        kernel32.CreateMutexW.restype = ctypes.c_void_p
        kernel32.WaitForSingleObject.argtypes = (ctypes.c_void_p, ctypes.c_uint32)
        kernel32.WaitForSingleObject.restype = ctypes.c_uint32
        kernel32.ReleaseMutex.argtypes = (ctypes.c_void_p,)
        kernel32.ReleaseMutex.restype = ctypes.c_int
        kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
        kernel32.CloseHandle.restype = ctypes.c_int
        mutex_name = f"Global\\SystemSense.WinInetProxy.v1.{target_key}"
        handle = kernel32.CreateMutexW(None, False, mutex_name)
        if not handle:
            yield False
            return
        acquired = False
        try:
            status = kernel32.WaitForSingleObject(handle, 0)
            acquired = status in {_ACQUIRED, _ABANDONED}
            yield status == _ACQUIRED
        finally:
            if acquired:
                kernel32.ReleaseMutex(handle)
            kernel32.CloseHandle(handle)
    finally:
        with _local_guard:
            _local_active.remove(target_key)
