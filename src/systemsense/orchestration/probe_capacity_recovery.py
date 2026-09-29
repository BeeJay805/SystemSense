"""Independent Windows proof for a named probe Job left by a dead custodian."""

from __future__ import annotations

import ctypes
from ctypes import wintypes
from typing import Any, cast

import pywintypes
import win32job

from systemsense.orchestration.probe_capacity_ledger import WorkerIdentity


class _FileTime(ctypes.Structure):
    _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]


def _identity_for_handle(handle: int, pid: int) -> WorkerIdentity:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    get_times = kernel32.GetProcessTimes
    get_times.argtypes = [
        wintypes.HANDLE,
        ctypes.POINTER(_FileTime),
        ctypes.POINTER(_FileTime),
        ctypes.POINTER(_FileTime),
        ctypes.POINTER(_FileTime),
    ]
    get_times.restype = wintypes.BOOL
    created, exited, kernel, user = (_FileTime() for _ in range(4))
    if not get_times(handle, created, exited, kernel, user):
        raise ctypes.WinError(ctypes.get_last_error())
    ticks = (int(created.high) << 32) | int(created.low)
    return WorkerIdentity(pid, (ticks - 116_444_736_000_000_000) * 100)


def current_process_identity() -> WorkerIdentity:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetCurrentProcessId.restype = wintypes.DWORD
    return _identity_for_handle(-1, int(kernel32.GetCurrentProcessId()))


def live_process_identity(pid: int) -> WorkerIdentity | None:
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    open_process = kernel32.OpenProcess
    open_process.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    open_process.restype = wintypes.HANDLE
    handle = open_process(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not handle:
        if ctypes.get_last_error() == 87:  # ERROR_INVALID_PARAMETER: PID absent
            return None
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        get_exit_code = kernel32.GetExitCodeProcess
        get_exit_code.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
        get_exit_code.restype = wintypes.BOOL
        exit_code = wintypes.DWORD()
        if not get_exit_code(handle, ctypes.byref(exit_code)):
            raise ctypes.WinError(ctypes.get_last_error())
        if exit_code.value != 259:  # STILL_ACTIVE
            return None
        return _identity_for_handle(int(handle), pid)
    finally:
        kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
        kernel32.CloseHandle.restype = wintypes.BOOL
        if not kernel32.CloseHandle(handle):
            raise ctypes.WinError(ctypes.get_last_error())


def prove_orphaned_job_exited(name: str, worker: WorkerIdentity, owner: WorkerIdentity) -> bool:
    """Require custodian exit, worker exit, and empty/destroyed exact Job.

    A named Job was created before launch, assigned before resume, and has
    KILL_ON_JOB_CLOSE. Missing Job means its last handle closed; a still-open
    Job is safe only when its active-process count is zero.
    """
    if live_process_identity(owner.pid) == owner:
        return False
    if live_process_identity(worker.pid) == worker:
        return False
    job_api: Any = win32job
    try:
        job: Any = job_api.OpenJobObject(job_api.JOB_OBJECT_QUERY, False, name)
    except pywintypes.error as error:
        if error.winerror == 2:  # ERROR_FILE_NOT_FOUND: Job object destroyed
            return True
        return False
    try:
        accounting: Any = job_api.QueryInformationJobObject(
            job, job_api.JobObjectBasicAccountingInformation
        )
        if not isinstance(accounting, dict):
            return False
        active = cast("dict[str, object]", accounting).get("ActiveProcesses")
        return type(active) is int and active == 0
    finally:
        job.Close()
