"""Trusted bridge between a durable probe reservation and one Windows Job.

This object is created by the scheduler, then passed only to the registered
isolated-probe executor. It gives models no launch or filesystem authority.
"""

from __future__ import annotations

import ctypes
import subprocess
import threading
from ctypes import wintypes
from typing import Any

import win32process

from systemsense.orchestration.probe_capacity_ledger import (
    CustodyVerifier,
    DurableProbeLedger,
    LaunchReceipt,
    Reservation,
    WorkerIdentity,
    WorkerReceipt,
)
from systemsense.orchestration.windows_probe_job import WindowsProbeJob


class _FileTime(ctypes.Structure):
    _fields_ = [("low", wintypes.DWORD), ("high", wintypes.DWORD)]


def _exact_worker_identity(process: subprocess.Popen[bytes]) -> WorkerIdentity:
    """Use the owned process handle, not a potentially reused PID lookup."""
    handle = getattr(process, "_handle", None)
    process_api: Any = win32process
    if not isinstance(handle, int) or process_api.GetProcessId(handle) != process.pid:
        raise RuntimeError("worker handle does not match its launched PID")
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
    created = _FileTime()
    exited = _FileTime()
    kernel = _FileTime()
    user = _FileTime()
    if not get_times(handle, created, exited, kernel, user):
        raise ctypes.WinError(ctypes.get_last_error())
    # FILETIME starts in 1601. Convert to Unix nanoseconds before storing in
    # SQLite's signed 64-bit INTEGER; raw FILETIME nanoseconds overflow it.
    filetime_ticks = (int(created.high) << 32) | int(created.low)
    creation_time_ns = (filetime_ticks - 116_444_736_000_000_000) * 100
    return WorkerIdentity(process.pid, creation_time_ns)


class _OwnedJobVerifier(CustodyVerifier):
    def __init__(self, job: WindowsProbeJob, process: subprocess.Popen[bytes]) -> None:
        self._job = job
        self._process = process

    def prove_empty_and_exited(self, identity: WorkerIdentity) -> bool:
        return (
            self._job.is_assigned_worker(self._process)
            and _exact_worker_identity(self._process) == identity
            and self._job.wait_until_empty(0)
            and self._process.poll() is not None
        )


class ProbeCapacityCustody:
    """One reservation whose uncertain launch or cleanup stays occupied."""

    def __init__(self, ledger: DurableProbeLedger, reservation: Reservation) -> None:
        self._ledger = ledger
        self._reservation = reservation
        self._intent: LaunchReceipt | None = None
        self._worker: WorkerReceipt | None = None
        self._verified = False
        self._released = False
        self._quarantined = False
        self._lock = threading.Lock()

    def record_launch_intent(self) -> None:
        with self._lock:
            if self._intent is not None or self._released or self._quarantined:
                raise RuntimeError("probe launch intent already recorded or closed")
            self._intent = self._ledger.record_launch_intent(self._reservation)

    def bind_suspended_worker(self, process: subprocess.Popen[bytes]) -> None:
        with self._lock:
            if self._intent is None or self._worker is not None or self._quarantined:
                raise RuntimeError("probe worker cannot be bound in this state")
            identity = _exact_worker_identity(process)
            self._worker = self._ledger.bind_suspended_worker(
                self._intent,
                pid=identity.pid,
                creation_time_ns=identity.creation_time_ns,
            )

    def confirm_job_assignment(self) -> None:
        with self._lock:
            if self._worker is None or self._quarantined:
                raise RuntimeError("probe worker is not bound")
            self._ledger.confirm_job_assignment(self._worker)

    def confirm_resume(self) -> None:
        with self._lock:
            if self._worker is None or self._quarantined:
                raise RuntimeError("probe worker is not bound")
            self._ledger.confirm_resume(self._worker)

    def record_tree_exit_proof(
        self, job: WindowsProbeJob, process: subprocess.Popen[bytes]
    ) -> None:
        with self._lock:
            if self._worker is None or self._quarantined:
                raise RuntimeError("probe worker is not bound")
            self._ledger.record_tree_exit_proof(self._worker, _OwnedJobVerifier(job, process))
            self._verified = True

    def quarantine(self, reason: str) -> bool:
        """Return False even when the durable quarantine write succeeds."""
        with self._lock:
            if self._released:
                return True
            self._quarantined = True
            receipt = self._worker or self._intent
            if receipt is not None:
                try:
                    self._ledger.quarantine(receipt, reason)
                except Exception:
                    # The reservation is not released. Unknown store state
                    # must continue consuming local capacity as well.
                    pass
            return False

    def release_or_quarantine(self) -> bool:
        """Release only prelaunch or independently proven worker-tree exit."""
        with self._lock:
            if self._released:
                return True
            if self._quarantined:
                return False
            if self._verified and self._worker is not None:
                try:
                    self._ledger.release_verified(self._worker)
                except Exception:
                    self._quarantined = True
                    return False
                self._released = True
                return True
            if self._intent is None:
                try:
                    self._ledger.release_prelaunch(self._reservation)
                except Exception:
                    self._quarantined = True
                    return False
                self._released = True
                return True
            self._quarantined = True
            receipt = self._worker or self._intent
            try:
                self._ledger.quarantine(receipt, "unverified_probe_tree_exit")
            except Exception:
                pass
            return False
