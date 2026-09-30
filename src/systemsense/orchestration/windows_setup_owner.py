"""Lifetime custody for the dedicated native setup backend only."""

from __future__ import annotations

import os
from typing import Any
from uuid import uuid4

import win32api
import win32job


class WindowsSetupOwner:
    """Protect children from creation, including before their inner Job assignment.

    The dedicated backend joins this outer Job before it may start any child.
    Its non-inheritable handle must remain alive until exit or proven release.
    Do not instantiate this in the desktop, investigator, or a shared test runner.
    """

    def __init__(self) -> None:
        self.name = f"Local\\SystemSense.LayaSetupOwner.{uuid4()}"
        self.owner_pid = os.getpid()
        job_api: Any = win32job
        self._job: Any = job_api.CreateJobObject(None, self.name)
        self._released = False
        try:
            if win32api.GetLastError() == 183:
                raise RuntimeError("setup owner Job already exists")
            limits: dict[str, Any] = job_api.QueryInformationJobObject(
                self._job, job_api.JobObjectExtendedLimitInformation
            )
            limits["BasicLimitInformation"]["LimitFlags"] |= (
                job_api.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            )
            job_api.SetInformationJobObject(
                self._job, job_api.JobObjectExtendedLimitInformation, limits
            )
            job_api.AssignProcessToJobObject(self._job, win32api.GetCurrentProcess())
        except BaseException:
            self._job.Close()
            raise

    def release_if_alone(self) -> bool:
        """Disarm only after the controller joined its worker and no child remains.

        A false result keeps kill-on-close protection. The caller must end the
        dedicated backend; it must never resume setup after attempting release.
        """
        if os.getpid() != self.owner_pid:
            raise RuntimeError("setup owner changed")
        if self._released:
            return True
        job_api: Any = win32job
        accounting: dict[str, Any] = job_api.QueryInformationJobObject(
            self._job, job_api.JobObjectBasicAccountingInformation
        )
        if accounting.get("ActiveProcesses") != 1:
            return False
        limits: dict[str, Any] = job_api.QueryInformationJobObject(
            self._job, job_api.JobObjectExtendedLimitInformation
        )
        limits["BasicLimitInformation"]["LimitFlags"] &= ~job_api.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        job_api.SetInformationJobObject(
            self._job, job_api.JobObjectExtendedLimitInformation, limits
        )
        self._job.Close()
        self._released = True
        return True
