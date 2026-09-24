"""Custody of one suspended Windows probe worker and its CreateProcess children."""

from __future__ import annotations

import ctypes
import subprocess
import threading
from ctypes import wintypes
from typing import Any

import psutil
import win32api
import win32con
import win32job
import win32process


class WindowsProbeJob:
    """A private job whose last handle closes every ordinary worker descendant."""

    def __init__(self) -> None:
        job_api: Any = win32job
        self._job: Any = job_api.CreateJobObject(None, "")
        self._closed = False
        self._lock = threading.Lock()
        try:
            limits: dict[str, Any] = job_api.QueryInformationJobObject(
                self._job, job_api.JobObjectExtendedLimitInformation
            )
            limits["BasicLimitInformation"]["LimitFlags"] |= (
                job_api.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            )
            job_api.SetInformationJobObject(
                self._job, job_api.JobObjectExtendedLimitInformation, limits
            )
        except BaseException:
            self._job.Close()
            raise

    def assign_and_resume(self, worker: subprocess.Popen[bytes]) -> None:
        process_api: Any = win32process
        job_api: Any = win32job
        api: Any = win32api
        handle = getattr(worker, "_handle", None)
        if not isinstance(handle, int) or process_api.GetProcessId(handle) != worker.pid:
            raise RuntimeError("worker process handle does not match launched PID")
        threads = psutil.Process(worker.pid).threads()
        if len(threads) != 1:
            raise RuntimeError("suspended worker must have exactly one thread")
        thread_handle: Any = api.OpenThread(
            win32con.THREAD_SUSPEND_RESUME | win32con.THREAD_QUERY_INFORMATION,
            False,
            threads[0].id,
        )
        try:
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            get_owner = kernel32.GetProcessIdOfThread
            get_owner.argtypes = [wintypes.HANDLE]
            get_owner.restype = wintypes.DWORD
            if get_owner(int(thread_handle)) != worker.pid:
                raise RuntimeError("worker thread does not belong to launched process")
            job_api.AssignProcessToJobObject(self._job, handle)
            if process_api.GetProcessId(handle) != worker.pid:
                raise RuntimeError("assigned worker identity changed")
            if process_api.ResumeThread(thread_handle) != 1:
                raise RuntimeError("worker was not suspended exactly once")
        finally:
            thread_handle.Close()

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._job.Close()
                self._closed = True

    def terminate(self) -> None:
        """Terminate this private job if closing its handle did not succeed."""
        with self._lock:
            if not self._closed:
                job_api: Any = win32job
                job_api.TerminateJobObject(self._job, 1)
                self._job.Close()
                self._closed = True
