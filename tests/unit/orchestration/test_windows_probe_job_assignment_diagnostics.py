from __future__ import annotations

# White-box Job API stage coverage mutates an uninitialized Job to isolate Windows boundaries.
# pyright: reportPrivateUsage=false
import threading
from types import SimpleNamespace
from typing import Any
from unittest.mock import patch

import pytest

from systemsense.orchestration import windows_probe_job as MODULE


class FakeThreadHandle:
    def __init__(self, *, fail_close: bool = False) -> None:
        self.fail_close = fail_close
        self.closed = False

    def __int__(self) -> int:
        return 71

    def Close(self) -> None:
        if self.fail_close:
            error = OSError(6, "secret handle detail")
            error.winerror = 6  # type: ignore[attr-defined]
            raise error
        self.closed = True


class FakeThreadFunction:
    argtypes: list[object]
    restype: object

    def __call__(self, _thread: int) -> int:
        return 123


class FakeKernel32:
    GetProcessIdOfThread = FakeThreadFunction()


def make_job() -> Any:
    job = object.__new__(MODULE.WindowsProbeJob)
    job._job = object()
    job._closed = False
    job._lock = threading.Lock()
    job._assigned_worker = None
    job._thread_handle = None
    return job


def patch_successful_setup(
    handle: FakeThreadHandle, *, assignment_error: BaseException | None = None
) -> tuple[Any, Any, Any, Any, Any]:
    def open_thread(*_args: Any) -> FakeThreadHandle:
        return handle

    def get_pid(_handle: int) -> int:
        return 123

    def process(_pid: int) -> SimpleNamespace:
        def threads() -> list[SimpleNamespace]:
            return [SimpleNamespace(id=456)]

        return SimpleNamespace(threads=threads)

    def win_dll(*_args: Any, **_kwargs: Any) -> FakeKernel32:
        return FakeKernel32()

    def assign(*_args: Any) -> None:
        if assignment_error is not None:
            raise assignment_error

    return (
        patch.object(MODULE.win32api, "OpenThread", open_thread),
        patch.object(MODULE.win32process, "GetProcessId", get_pid),
        patch.object(MODULE.psutil, "Process", process),
        patch.object(MODULE.ctypes, "WinDLL", win_dll),
        patch.object(MODULE.win32job, "AssignProcessToJobObject", assign),
    )


def test_job_assignment_failure_reports_stage_and_numeric_os_code_without_text():
    handle = FakeThreadHandle()
    error = OSError(5, "C:\\secret\\install path")
    error.winerror = 5  # type: ignore[attr-defined]
    contexts = patch_successful_setup(handle, assignment_error=error)
    with contexts[0], contexts[1], contexts[2], contexts[3], contexts[4]:
        with pytest.raises(MODULE.ProbeJobAssignmentError) as captured:
            make_job().assign_suspended(SimpleNamespace(_handle=999, pid=123))
    failure = captured.value
    assert failure.stage == "job_assign_process"
    assert failure.winerror == 5
    expected_type = "PermissionError" if isinstance(error, PermissionError) else "OSError"
    assert failure.exception_type == expected_type
    assert handle.closed
    assert "secret" not in str(failure)


@pytest.mark.parametrize("observed_count", [0, 2])
def test_thread_enumeration_failure_records_exact_count_before_assignment(
    observed_count: int,
) -> None:
    job = make_job()
    contexts = patch_successful_setup(FakeThreadHandle())

    def unexpected_threads(_pid: int) -> SimpleNamespace:
        def threads() -> list[SimpleNamespace]:
            return [SimpleNamespace(id=index) for index in range(observed_count)]

        return SimpleNamespace(threads=threads)

    with contexts[1], contexts[3], contexts[4]:
        with patch.object(MODULE.psutil, "Process", unexpected_threads):
            with pytest.raises(MODULE.ProbeJobAssignmentError) as captured:
                job.assign_suspended(SimpleNamespace(_handle=999, pid=123))
    assert captured.value.stage == "worker_thread_enumerate"
    assert captured.value.thread_count == observed_count


def test_thread_handle_close_failure_does_not_replace_primary_assignment_error():
    handle = FakeThreadHandle(fail_close=True)
    error = OSError(5, "primary secret")
    contexts = patch_successful_setup(handle, assignment_error=error)
    with contexts[0], contexts[1], contexts[2], contexts[3], contexts[4]:
        with pytest.raises(MODULE.ProbeJobAssignmentError) as captured:
            make_job().assign_suspended(SimpleNamespace(_handle=999, pid=123))
    assert captured.value.stage == "job_assign_process"
    expected_type = "PermissionError" if isinstance(error, PermissionError) else "OSError"
    assert captured.value.exception_type == expected_type
    assert captured.value.cleanup_exception_type == "OSError"
    assert captured.value.winerror is None
    assert captured.value.cleanup_winerror == 6
    assert "secret" not in str(captured.value)


def test_keyboard_interrupt_is_rethrown_after_thread_handle_cleanup():
    handle = FakeThreadHandle()
    contexts = patch_successful_setup(handle, assignment_error=KeyboardInterrupt())
    with contexts[0], contexts[1], contexts[2], contexts[3], contexts[4]:
        with pytest.raises(KeyboardInterrupt):
            make_job().assign_suspended(SimpleNamespace(_handle=999, pid=123))
    assert handle.closed
