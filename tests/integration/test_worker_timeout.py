import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, BinaryIO, cast

import psutil
import pytest
from pydantic import ValidationError

import systemsense.orchestration.executor as executor_module
from systemsense.orchestration.executor import (
    ProbeExecutor,
    WorkerExecution,
    WorkerExecutionStatus,
    WorkerTreeExitStatus,
)
from systemsense.orchestration.scheduler import BlockingCancellationToken

if TYPE_CHECKING:
    from systemsense.orchestration.windows_probe_job import WindowsProbeJob


def test_timeout_terminates_only_worker_and_preserves_partial_evidence() -> None:
    started = time.monotonic()

    result = ProbeExecutor().execute(
        "fixture.partial_then_sleep",
        {"delay_ms": 5000},
        timeout_ms=1000,
    )
    elapsed = time.monotonic() - started

    assert result.status is WorkerExecutionStatus.TIMED_OUT
    assert result.tree_exit is WorkerTreeExitStatus.VERIFIED_EMPTY
    assert result.evidence == ({"stage": "started"},)
    assert elapsed < 3.0


def test_cancellation_terminates_the_owned_worker_with_a_true_wall_bound() -> None:
    token = BlockingCancellationToken(threading.Event())
    results: list[WorkerExecution] = []
    started = time.monotonic()
    thread = threading.Thread(
        target=lambda: results.append(
            ProbeExecutor().execute(
                "fixture.partial_then_sleep",
                {"delay_ms": 5000},
                timeout_ms=10_000,
                cancellation=token,
            )
        )
    )
    thread.start()
    time.sleep(0.2)
    token.cancel()
    thread.join(timeout=1.5)

    assert not thread.is_alive()
    assert len(results) == 1
    result = results[0]
    assert result.status is WorkerExecutionStatus.CANCELLED
    assert time.monotonic() - started < 1.5


def test_nonzero_worker_exit_cannot_report_success() -> None:
    result = ProbeExecutor().execute("fixture.false_success", {}, timeout_ms=1000)

    assert result.status is WorkerExecutionStatus.FAILED
    assert result.tree_exit is WorkerTreeExitStatus.VERIFIED_EMPTY
    assert result.error == "worker exited with code 7"


def test_output_limit_stops_worker_without_buffering_unbounded_data() -> None:
    started = time.monotonic()
    result = ProbeExecutor().execute(
        "fixture.unbounded_output",
        {"size": 2_000_000},
        timeout_ms=5000,
    )

    assert result.status is WorkerExecutionStatus.FAILED
    assert result.error == "worker output exceeded limit"
    assert time.monotonic() - started < 1.5


def test_non_object_worker_messages_are_ignored_as_bounded_failure() -> None:
    evidence, status, error = ProbeExecutor._parse_output(  # pyright: ignore[reportPrivateUsage]
        '[]\n1\nnull\n"text"'
    )

    assert evidence == ()
    assert status is WorkerExecutionStatus.FAILED
    assert error is None


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object containment")
def test_timeout_reaps_worker_descendant_without_touching_unrelated_process(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    child_pid_file = tmp_path / "owned-child.pid"
    marker = str(tmp_path / "owned-child-marker")
    child_code = "import time; time.sleep(30)"
    worker_code = (
        "import pathlib,subprocess,sys,time; "
        f"child=subprocess.Popen([sys.executable,'-c',{child_code!r},{marker!r}], "
        "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
        f"pathlib.Path({str(child_pid_file)!r}).write_text(str(child.pid)); "
        "time.sleep(30)"
    )
    original_popen = subprocess.Popen
    unrelated = original_popen([sys.executable, "-c", child_code, "unrelated-sentinel"])

    def launch_fixture(_args: object, **kwargs: Any) -> subprocess.Popen[bytes]:
        return cast(
            "subprocess.Popen[bytes]", original_popen([sys.executable, "-c", worker_code], **kwargs)
        )

    monkeypatch.setattr(executor_module.subprocess, "Popen", launch_fixture)
    try:
        result = ProbeExecutor().execute("fixture.echo", {"message": "x"}, timeout_ms=1000)
        assert result.status is WorkerExecutionStatus.TIMED_OUT
        assert child_pid_file.exists(), "fixture worker did not spawn its child"
        child_pid = int(child_pid_file.read_text(encoding="utf-8"))
        for _ in range(40):
            if not psutil.pid_exists(child_pid):
                break
            time.sleep(0.05)
        assert not psutil.pid_exists(child_pid)
        assert unrelated.poll() is None
    finally:
        if child_pid_file.exists():
            child_pid = int(child_pid_file.read_text(encoding="utf-8"))
            try:
                child = psutil.Process(child_pid)
                if marker in child.cmdline():
                    child.kill()
                    child.wait(timeout=5)
            except psutil.NoSuchProcess:
                pass
        unrelated.kill()
        unrelated.wait(timeout=5)


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object containment")
def test_normal_worker_exit_reaps_lingering_descendant(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    child_pid_file = tmp_path / "normal-child.pid"
    marker = str(tmp_path / "normal-child-marker")
    child_code = "import time; time.sleep(30)"
    worker_code = (
        "import pathlib,subprocess,sys; "
        f"child=subprocess.Popen([sys.executable,'-c',{child_code!r},{marker!r}], "
        "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
        f"pathlib.Path({str(child_pid_file)!r}).write_text(str(child.pid))"
    )
    original_popen = subprocess.Popen

    def launch_fixture(_args: object, **kwargs: Any) -> subprocess.Popen[bytes]:
        return cast(
            "subprocess.Popen[bytes]", original_popen([sys.executable, "-c", worker_code], **kwargs)
        )

    monkeypatch.setattr(executor_module.subprocess, "Popen", launch_fixture)
    try:
        result = ProbeExecutor().execute("fixture.echo", {"message": "x"}, timeout_ms=5000)
        assert result.status is WorkerExecutionStatus.FAILED
        child_pid = int(child_pid_file.read_text(encoding="utf-8"))
        for _ in range(40):
            if not psutil.pid_exists(child_pid):
                break
            time.sleep(0.05)
        assert not psutil.pid_exists(child_pid)
    finally:
        if child_pid_file.exists():
            child_pid = int(child_pid_file.read_text(encoding="utf-8"))
            try:
                child = psutil.Process(child_pid)
                if marker in child.cmdline():
                    child.kill()
                    child.wait(timeout=5)
            except psutil.NoSuchProcess:
                pass


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object containment")
def test_failed_job_assignment_never_resumes_worker(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    from systemsense.orchestration.windows_probe_job import WindowsProbeJob

    ran_path = tmp_path / "worker-ran"
    original_popen = subprocess.Popen
    worker: subprocess.Popen[bytes] | None = None

    def launch_fixture(_args: object, **kwargs: Any) -> subprocess.Popen[bytes]:
        nonlocal worker
        worker = cast(
            "subprocess.Popen[bytes]",
            original_popen(
                [sys.executable, "-c", f"import pathlib; pathlib.Path({str(ran_path)!r}).touch()"],
                **kwargs,
            ),
        )
        return worker

    def reject_assignment(_job: WindowsProbeJob, _worker: subprocess.Popen[bytes]) -> None:
        raise RuntimeError("injected assignment failure")

    monkeypatch.setattr(executor_module.subprocess, "Popen", launch_fixture)
    monkeypatch.setattr(WindowsProbeJob, "assign_suspended", reject_assignment)
    result = ProbeExecutor().execute("fixture.echo", {"message": "x"}, timeout_ms=1000)
    assert result.status is WorkerExecutionStatus.FAILED
    assert result.error == "worker containment assignment failed"
    assert result.tree_exit is WorkerTreeExitStatus.VERIFIED_EMPTY
    assert worker is not None and worker.poll() is not None
    assert not ran_path.exists()


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object containment")
def test_unassigned_worker_exit_failure_is_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    from systemsense.orchestration.windows_probe_job import WindowsProbeJob

    original_popen = subprocess.Popen
    worker: subprocess.Popen[bytes] | None = None

    def launch_fixture(args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
        nonlocal worker
        worker = cast("subprocess.Popen[bytes]", original_popen(args, **kwargs))
        return worker

    def reject_assignment(_job: WindowsProbeJob, _worker: subprocess.Popen[bytes]) -> None:
        raise RuntimeError("injected assignment failure")

    def fail_exact_stop(_worker: subprocess.Popen[bytes]) -> None:
        raise RuntimeError("injected process stop failure")

    monkeypatch.setattr(executor_module.subprocess, "Popen", launch_fixture)
    monkeypatch.setattr(WindowsProbeJob, "assign_suspended", reject_assignment)
    monkeypatch.setattr(executor_module, "_stop_owned_process", fail_exact_stop)
    try:
        result = ProbeExecutor().execute("fixture.echo", {"message": "x"}, timeout_ms=1000)
        assert result.status is WorkerExecutionStatus.FAILED
        assert result.tree_exit is WorkerTreeExitStatus.UNKNOWN
    finally:
        if worker is not None:
            if worker.poll() is None:
                worker.kill()
            worker.wait(timeout=3)


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object containment")
def test_failed_assignment_reports_pipe_close_error(monkeypatch: pytest.MonkeyPatch) -> None:
    from systemsense.orchestration.windows_probe_job import WindowsProbeJob

    original_popen = subprocess.Popen
    worker: subprocess.Popen[bytes] | None = None

    class FailingClose:
        def __init__(self, stream: BinaryIO) -> None:
            self._stream = stream

        def close(self) -> None:
            self._stream.close()
            raise OSError("injected assignment pipe close failure")

    def launch_fixture(args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
        nonlocal worker
        worker = cast("subprocess.Popen[bytes]", original_popen(args, **kwargs))
        assert worker.stdout is not None
        worker.stdout = cast("BinaryIO", FailingClose(cast("BinaryIO", worker.stdout)))
        return worker

    def reject_assignment(_job: WindowsProbeJob, _worker: subprocess.Popen[bytes]) -> None:
        raise RuntimeError("injected assignment failure")

    monkeypatch.setattr(executor_module.subprocess, "Popen", launch_fixture)
    monkeypatch.setattr(WindowsProbeJob, "assign_suspended", reject_assignment)
    result = ProbeExecutor().execute("fixture.echo", {"message": "x"}, timeout_ms=1000)
    assert result.status is WorkerExecutionStatus.FAILED
    assert result.error == "worker containment cleanup failed"
    assert worker is not None and worker.stderr is not None and worker.stderr.closed


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object containment")
def test_job_close_error_returns_failed_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    from systemsense.orchestration.windows_probe_job import WindowsProbeJob

    original_close = WindowsProbeJob.close
    attempts = 0

    def fail_first_close(job: WindowsProbeJob) -> None:
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise RuntimeError("injected close failure")
        original_close(job)

    monkeypatch.setattr(WindowsProbeJob, "close", fail_first_close)
    result = ProbeExecutor().execute(
        "fixture.partial_then_sleep", {"delay_ms": 5000}, timeout_ms=1000
    )
    assert result.status is WorkerExecutionStatus.FAILED
    assert result.error == "worker containment cleanup failed"
    assert result.tree_exit is WorkerTreeExitStatus.VERIFIED_EMPTY
    assert attempts >= 2


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object containment")
def test_unverified_job_tree_exit_is_reported_as_unknown(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from systemsense.orchestration.windows_probe_job import WindowsProbeJob

    def deny_exit_proof(_job: WindowsProbeJob, _timeout_seconds: float) -> bool:
        raise PermissionError("job accounting unavailable")

    monkeypatch.setattr(WindowsProbeJob, "wait_until_empty", deny_exit_proof)
    result = ProbeExecutor().execute("fixture.echo", {"message": "x"}, timeout_ms=1000)

    assert result.status is WorkerExecutionStatus.FAILED
    assert result.tree_exit is WorkerTreeExitStatus.UNKNOWN


def test_denied_probe_has_no_launched_worker() -> None:
    result = ProbeExecutor().execute("not.registered", {}, timeout_ms=1000)

    assert result.tree_exit is WorkerTreeExitStatus.NOT_LAUNCHED


def test_unknown_tree_exit_cannot_report_success() -> None:
    with pytest.raises(ValidationError, match="unverified worker tree"):
        WorkerExecution(status=WorkerExecutionStatus.OK, tree_exit=WorkerTreeExitStatus.UNKNOWN)


class _RecordingCustody:
    def __init__(self, fail_at: str | None = None) -> None:
        self.events: list[str] = []
        self.fail_at = fail_at
        self.worker: subprocess.Popen[bytes] | None = None

    def _record(self, event: str) -> None:
        self.events.append(event)
        if self.fail_at == event:
            raise RuntimeError(f"injected {event} failure")

    def record_launch_intent(self) -> None:
        self._record("intent")

    def bind_suspended_worker(self, process: subprocess.Popen[bytes]) -> None:
        assert process.poll() is None
        self.worker = process
        self._record("bind")

    def confirm_job_assignment(self) -> None:
        self._record("assigned")

    def confirm_resume(self) -> None:
        self._record("resumed")

    def record_tree_exit_proof(self, job: object, process: subprocess.Popen[bytes]) -> None:
        assert cast("WindowsProbeJob", job).wait_until_empty(0)
        assert process.poll() is not None
        self._record("proof")


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object containment")
def test_durable_custody_hooks_follow_suspended_worker_lifecycle() -> None:
    custody = _RecordingCustody()

    result = ProbeExecutor().execute(
        "fixture.echo", {"message": "x"}, timeout_ms=1000, custody=custody
    )

    assert result.status is WorkerExecutionStatus.OK
    assert result.tree_exit is WorkerTreeExitStatus.VERIFIED_EMPTY
    assert custody.events == ["intent", "bind", "assigned", "resumed", "proof"]


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object containment")
@pytest.mark.parametrize("failed_stage", ["intent", "bind", "assigned", "resumed", "proof"])
def test_durable_custody_hook_failure_never_succeeds(failed_stage: str) -> None:
    custody = _RecordingCustody(failed_stage)

    result = ProbeExecutor().execute(
        "fixture.echo", {"message": "x"}, timeout_ms=1000, custody=custody
    )

    assert result.status is WorkerExecutionStatus.FAILED
    assert custody.events[-1] == failed_stage
    if custody.worker is not None:
        assert custody.worker.poll() is not None
    if failed_stage == "proof":
        assert result.tree_exit is WorkerTreeExitStatus.UNKNOWN
    if failed_stage == "intent":
        assert custody.events == ["intent"]
        assert result.tree_exit is WorkerTreeExitStatus.NOT_LAUNCHED


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object containment")
def test_failed_launch_intent_prevents_popen(monkeypatch: pytest.MonkeyPatch) -> None:
    custody = _RecordingCustody("intent")
    launches = 0
    original_popen = subprocess.Popen

    def count_launch(args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
        nonlocal launches
        launches += 1
        return cast("subprocess.Popen[bytes]", original_popen(args, **kwargs))

    monkeypatch.setattr(executor_module.subprocess, "Popen", count_launch)
    result = ProbeExecutor().execute(
        "fixture.echo", {"message": "x"}, timeout_ms=1000, custody=custody
    )

    assert result.status is WorkerExecutionStatus.FAILED
    assert result.tree_exit is WorkerTreeExitStatus.NOT_LAUNCHED
    assert launches == 0


def test_durable_custody_requires_windows_job_before_launch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    custody = _RecordingCustody()

    def no_job() -> None:
        return None

    def reject_launch(*_args: object, **_kwargs: object) -> None:
        raise AssertionError("Popen must not run without a Windows Job")

    monkeypatch.setattr(executor_module, "_new_windows_job", no_job)
    monkeypatch.setattr(executor_module.subprocess, "Popen", reject_launch)
    result = ProbeExecutor().execute(
        "fixture.echo", {"message": "x"}, timeout_ms=1000, custody=custody
    )

    assert result.status is WorkerExecutionStatus.FAILED
    assert result.error == "durable custody requires a Windows Job"
    assert result.tree_exit is WorkerTreeExitStatus.NOT_LAUNCHED
    assert custody.events == []


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object containment")
@pytest.mark.parametrize("launch_error", [OSError, ValueError])
def test_launch_failure_releases_job_and_returns_failed_execution(
    monkeypatch: pytest.MonkeyPatch, launch_error: type[Exception]
) -> None:
    from systemsense.orchestration.windows_probe_job import WindowsProbeJob

    original_close = WindowsProbeJob.close
    closed = False

    def record_close(job: WindowsProbeJob) -> None:
        nonlocal closed
        original_close(job)
        closed = True

    def fail_launch(_args: object, **_kwargs: Any) -> subprocess.Popen[bytes]:
        raise launch_error("injected launch failure")

    monkeypatch.setattr(WindowsProbeJob, "close", record_close)
    monkeypatch.setattr(executor_module.subprocess, "Popen", fail_launch)
    result = ProbeExecutor().execute("fixture.echo", {"message": "x"}, timeout_ms=1000)
    assert result.status is WorkerExecutionStatus.FAILED
    assert result.error == "worker launch failed"
    assert closed


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object containment")
def test_launch_and_job_close_failure_returns_bounded_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from systemsense.orchestration.windows_probe_job import WindowsProbeJob

    original_close = WindowsProbeJob.close

    def fail_close(job: WindowsProbeJob) -> None:
        original_close(job)
        raise RuntimeError("injected close failure")

    def fail_launch(_args: object, **_kwargs: Any) -> subprocess.Popen[bytes]:
        raise OSError("injected launch failure")

    monkeypatch.setattr(WindowsProbeJob, "close", fail_close)
    monkeypatch.setattr(executor_module.subprocess, "Popen", fail_launch)
    result = ProbeExecutor().execute("fixture.echo", {"message": "x"}, timeout_ms=1000)
    assert result.status is WorkerExecutionStatus.FAILED
    assert result.error == "worker containment cleanup failed"


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object containment")
@pytest.mark.parametrize("failed_start", [1, 2])
def test_reader_start_failure_reaps_worker_and_child(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, failed_start: int
) -> None:
    child_pid_file = tmp_path / "reader-start-child.pid"
    marker = str(tmp_path / "reader-start-child-marker")
    child_code = "import time; time.sleep(30)"
    worker_code = (
        "import pathlib,subprocess,sys,time; "
        f"child=subprocess.Popen([sys.executable,'-c',{child_code!r},{marker!r}], "
        "stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL); "
        f"pathlib.Path({str(child_pid_file)!r}).write_text(str(child.pid)); "
        "time.sleep(30)"
    )
    original_popen = subprocess.Popen
    original_start = threading.Thread.start
    worker: subprocess.Popen[bytes] | None = None
    starts = 0

    def launch_fixture(_args: object, **kwargs: Any) -> subprocess.Popen[bytes]:
        nonlocal worker
        worker = cast(
            "subprocess.Popen[bytes]", original_popen([sys.executable, "-c", worker_code], **kwargs)
        )
        return worker

    def fail_reader_start(thread: threading.Thread) -> None:
        nonlocal starts
        starts += 1
        if starts == failed_start:
            pid_text = ""
            for _ in range(200):
                if child_pid_file.exists():
                    pid_text = child_pid_file.read_text(encoding="utf-8").strip()
                    if pid_text.isdigit():
                        break
                time.sleep(0.005)
            assert pid_text.isdigit(), "fixture worker did not publish its child PID"
            raise RuntimeError("injected reader start failure")
        original_start(thread)

    monkeypatch.setattr(executor_module.subprocess, "Popen", launch_fixture)
    monkeypatch.setattr(threading.Thread, "start", fail_reader_start)
    try:
        result = ProbeExecutor().execute("fixture.echo", {"message": "x"}, timeout_ms=5000)
        assert result.status is WorkerExecutionStatus.FAILED
        assert result.error == "worker reader startup failed"
        child_pid = int(child_pid_file.read_text(encoding="utf-8"))
        for _ in range(40):
            if not psutil.pid_exists(child_pid):
                break
            time.sleep(0.05)
        assert not psutil.pid_exists(child_pid)
        assert worker is not None and worker.poll() is not None
    finally:
        if worker is not None and worker.poll() is None:
            worker.kill()
            worker.wait(timeout=5)
        if child_pid_file.exists():
            pid_text = child_pid_file.read_text(encoding="utf-8").strip()
            if pid_text.isdigit():
                try:
                    child = psutil.Process(int(pid_text))
                    if marker in child.cmdline():
                        child.kill()
                        child.wait(timeout=5)
                except psutil.NoSuchProcess:
                    pass


def test_reader_close_failure_is_bounded_and_closes_other_pipe(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    original_popen = subprocess.Popen
    worker: subprocess.Popen[bytes] | None = None

    class FailingClose:
        def __init__(self, stream: BinaryIO) -> None:
            self._stream = stream

        def read(self, size: int) -> bytes:
            return self._stream.read(size)

        def close(self) -> None:
            self._stream.close()
            raise OSError("injected stdout close failure")

    def launch_fixture(args: Any, **kwargs: Any) -> subprocess.Popen[bytes]:
        nonlocal worker
        worker = cast("subprocess.Popen[bytes]", original_popen(args, **kwargs))
        assert worker.stdout is not None
        worker.stdout = cast("BinaryIO", FailingClose(cast("BinaryIO", worker.stdout)))
        return worker

    monkeypatch.setattr(executor_module.subprocess, "Popen", launch_fixture)
    result = ProbeExecutor().execute("fixture.echo", {"message": "x"}, timeout_ms=1000)
    assert result.status is WorkerExecutionStatus.FAILED
    assert result.error == "worker pipe cleanup failed"
    assert worker is not None and worker.stderr is not None and worker.stderr.closed


@pytest.mark.skipif(os.name != "nt", reason="Windows Job Object containment")
@pytest.mark.parametrize("termination_fails", [False, True])
def test_persistent_job_close_failure_with_inherited_pipes_is_bounded(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, termination_fails: bool
) -> None:
    from systemsense.orchestration.windows_probe_job import WindowsProbeJob

    child_pid_file = tmp_path / "inherited-pipe-child.pid"
    marker = str(tmp_path / "inherited-pipe-child-marker")
    child_code = "import time; time.sleep(4)"
    worker_code = (
        "import pathlib,subprocess,sys,time; "
        f"child=subprocess.Popen([sys.executable,'-c',{child_code!r},{marker!r}]); "
        f"pathlib.Path({str(child_pid_file)!r}).write_text(str(child.pid)); "
        "time.sleep(30)"
    )
    original_popen = subprocess.Popen
    original_close = WindowsProbeJob.close
    unrelated = original_popen([sys.executable, "-c", "import time; time.sleep(10)"])
    jobs: list[WindowsProbeJob] = []

    def launch_fixture(_args: object, **kwargs: Any) -> subprocess.Popen[bytes]:
        return cast(
            "subprocess.Popen[bytes]", original_popen([sys.executable, "-c", worker_code], **kwargs)
        )

    def fail_close(job: WindowsProbeJob) -> None:
        if job not in jobs:
            jobs.append(job)
        raise OSError("injected persistent job close failure")

    def fail_terminate(_job: WindowsProbeJob) -> None:
        raise OSError("injected job termination failure")

    monkeypatch.setattr(executor_module.subprocess, "Popen", launch_fixture)
    monkeypatch.setattr(WindowsProbeJob, "close", fail_close)
    if termination_fails:
        monkeypatch.setattr(WindowsProbeJob, "terminate", fail_terminate)
        monkeypatch.setattr(WindowsProbeJob, "terminate_processes", fail_terminate)
    try:
        started = time.monotonic()
        result = ProbeExecutor().execute("fixture.echo", {"message": "x"}, timeout_ms=1000)
        elapsed = time.monotonic() - started
        assert result.status is WorkerExecutionStatus.FAILED
        assert result.error == "worker containment cleanup failed"
        assert elapsed < 2.5
        assert child_pid_file.exists()
        child_pid = int(child_pid_file.read_text(encoding="utf-8"))
        if not termination_fails:
            for _ in range(40):
                if not psutil.pid_exists(child_pid):
                    break
                time.sleep(0.05)
        assert psutil.pid_exists(child_pid) is termination_fails
        assert unrelated.poll() is None
    finally:
        for job in jobs:
            try:
                original_close(job)
            except OSError:
                pass
        if child_pid_file.exists():
            pid_text = child_pid_file.read_text(encoding="utf-8").strip()
            if pid_text.isdigit():
                try:
                    child = psutil.Process(int(pid_text))
                    if marker in child.cmdline():
                        child.kill()
                        child.wait(timeout=5)
                except psutil.NoSuchProcess:
                    pass
        unrelated.kill()
        unrelated.wait(timeout=5)
