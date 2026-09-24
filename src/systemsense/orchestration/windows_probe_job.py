"""Custody of one suspended Windows probe worker and its CreateProcess children."""

from __future__ import annotations

import ctypes
import math
import subprocess
import threading
import time
from ctypes import wintypes
from typing import Any, cast

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
        self._assigned_worker: tuple[int, int] | None = None
        self._thread_handle: Any = None
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
        self.assign_suspended(worker)
        self.resume_assigned(worker)

    def assign_suspended(self, worker: subprocess.Popen[bytes]) -> None:
        """Assign the suspended worker before it can create descendants."""
        process_api: Any = win32process
        job_api: Any = win32job
        api: Any = win32api
        with self._lock:
            if self._closed or self._assigned_worker is not None:
                raise RuntimeError("job is closed or already has an assigned worker")
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
            except BaseException:
                thread_handle.Close()
                raise
            self._assigned_worker = (handle, worker.pid)
            self._thread_handle = thread_handle

    def resume_assigned(self, worker: subprocess.Popen[bytes]) -> None:
        """Resume only the worker assigned to this job."""
        process_api: Any = win32process
        with self._lock:
            if (
                self._closed
                or self._thread_handle is None
                or self._assigned_worker
                != (
                    getattr(worker, "_handle", None),
                    worker.pid,
                )
            ):
                raise RuntimeError("worker is not assigned to this open job")
            thread_handle = self._thread_handle
            try:
                if process_api.ResumeThread(thread_handle) != 1:
                    raise RuntimeError("worker was not suspended exactly once")
            finally:
                thread_handle.Close()
                self._thread_handle = None

    def wait_until_empty(self, timeout_seconds: float) -> bool:
        """Observe zero active processes while this job handle is still open."""
        if not math.isfinite(timeout_seconds) or not 0 <= timeout_seconds <= 5:
            raise ValueError("job drain timeout must be from 0 to 5 seconds")
        deadline = time.monotonic() + timeout_seconds
        job_api: Any = win32job
        while True:
            with self._lock:
                if self._closed:
                    raise RuntimeError("cannot query a closed job")
                accounting: Any = job_api.QueryInformationJobObject(
                    self._job, job_api.JobObjectBasicAccountingInformation
                )
            if not isinstance(accounting, dict):
                raise RuntimeError("job accounting returned an invalid response")
            active: Any = cast(dict[str, Any], accounting).get("ActiveProcesses")
            if not isinstance(active, int) or isinstance(active, bool) or active < 0:
                raise RuntimeError("job accounting returned invalid ActiveProcesses")
            if active == 0:
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(0.02, remaining))

    def close(self) -> None:
        with self._lock:
            if not self._closed:
                self._job.Close()
                self._closed = True
                if self._thread_handle is not None:
                    self._thread_handle.Close()
                    self._thread_handle = None

    def terminate(self) -> None:
        """Terminate this private job if closing its handle did not succeed."""
        with self._lock:
            if not self._closed:
                job_api: Any = win32job
                job_api.TerminateJobObject(self._job, 1)
                self._job.Close()
                self._closed = True
                if self._thread_handle is not None:
                    self._thread_handle.Close()
                    self._thread_handle = None

    def terminate_processes(self) -> None:
        """Terminate Job-owned processes, retaining the handle for drain verification."""
        with self._lock:
            if self._closed:
                raise RuntimeError("cannot terminate processes in a closed job")
            job_api: Any = win32job
            job_api.TerminateJobObject(self._job, 1)
