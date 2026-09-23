"""Process-wide exclusion shared by repair execution and terminal release."""

import ctypes
import os
from multiprocessing import get_context
from pathlib import Path

import pytest

from systemsense.actions.contracts import ActionAuthorizationError
from systemsense.actions.wininet_target_arbiter import (
    hold_wininet_target_exclusive,
    wininet_target_key,
)

SID = "S-1-5-21-1000-2000-3000-1001"
LOCATOR = f"wininet_proxy:{SID}"


def _contend(key: str, result_path: str) -> None:
    with hold_wininet_target_exclusive(key) as held:
        Path(result_path).write_text(str(held), encoding="ascii")


def _die_holding(key: str) -> None:
    with hold_wininet_target_exclusive(key) as held:
        if held is not True:
            os._exit(2)
        os._exit(0)


def test_target_key_rejects_noncanonical_locator() -> None:
    with pytest.raises(ActionAuthorizationError, match="canonical"):
        wininet_target_key("wininet_proxy:S-1-5-21-1-2-3-4/anything")


@pytest.mark.skipif(os.name != "nt", reason="Windows named mutex")
def test_nested_same_thread_acquisition_is_refused() -> None:
    key = wininet_target_key(LOCATOR)
    with hold_wininet_target_exclusive(key) as first:
        assert first is True
        with hold_wininet_target_exclusive(key) as second:
            assert second is False


@pytest.mark.skipif(os.name != "nt", reason="Windows named mutex")
def test_mutex_excludes_another_process_for_same_target(tmp_path: Path) -> None:
    key = wininet_target_key(LOCATOR)
    result = tmp_path / "contender.txt"
    with hold_wininet_target_exclusive(key) as held:
        assert held is True
        process = get_context("spawn").Process(target=_contend, args=(key, str(result)))
        process.start()
        process.join(10)
        assert process.exitcode == 0
        assert result.read_text(encoding="ascii") == "False"
    with hold_wininet_target_exclusive(key) as held:
        assert held is True


@pytest.mark.skipif(os.name != "nt", reason="Windows named mutex")
def test_abandoned_mutex_does_not_grant_target_exclusion() -> None:
    key = wininet_target_key(LOCATOR)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.argtypes = (ctypes.c_void_p, ctypes.c_int, ctypes.c_wchar_p)
    kernel32.CreateMutexW.restype = ctypes.c_void_p
    kernel32.CloseHandle.argtypes = (ctypes.c_void_p,)
    kernel32.CloseHandle.restype = ctypes.c_int
    handle = kernel32.CreateMutexW(None, False, f"Global\\SystemSense.WinInetProxy.v1.{key}")
    assert handle
    try:
        process = get_context("spawn").Process(target=_die_holding, args=(key,))
        process.start()
        process.join(10)
        assert process.exitcode == 0
        with hold_wininet_target_exclusive(key) as held:
            assert held is False
    finally:
        kernel32.CloseHandle(handle)
