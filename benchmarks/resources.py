"""Measured idle and case-operation resource usage."""

from __future__ import annotations

import json
import os
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Literal

import psutil
from pydantic import Field

from benchmarks.models import BenchmarkModel
from systemsense.application.bootstrap import default_case_runtime, default_planner
from systemsense.application.case_service import CaseService
from systemsense.application.workspace import EvidenceWorkspace
from systemsense.domain.cases import CaseKind
from systemsense.domain.time import utc_now
from systemsense.storage.sqlite_store import SQLiteStore


class IdleMeasurement(BenchmarkModel):
    process_scope: Literal["owned_systemsense_child"] = "owned_systemsense_child"
    runtime_scope: Literal["application_service_idle"] = "application_service_idle"
    process_id: int = Field(gt=0)
    process_name: str = Field(min_length=1, max_length=255)
    process_created_at: float = Field(gt=0)
    startup_rss_bytes: int = Field(gt=0)
    requested_duration_ms: float = Field(gt=0)
    sample_interval_ms: float = Field(gt=0)
    duration_ms: float = Field(ge=0)
    average_cpu_percent: float = Field(ge=0)
    peak_rss_bytes: int = Field(ge=0)
    sample_count: int = Field(ge=1)


class OperationMeasurement(BenchmarkModel):
    elapsed_ms: float = Field(ge=0)
    peak_rss_bytes: int = Field(ge=0)
    read_bytes: int = Field(ge=0)
    write_bytes: int = Field(ge=0)
    database_growth_bytes: int = Field(ge=0)


class ResourceReport(BenchmarkModel):
    idle: IdleMeasurement
    case_operation: OperationMeasurement


class _IdleHandshake(BenchmarkModel):
    process_id: int = Field(gt=0)
    process_created_at: float = Field(gt=0)
    runtime_scope: Literal["application_service_idle"]


_IDLE_CHILD = """
import json
import os
import sys
import time
from pathlib import Path

import psutil

from systemsense.application.bootstrap import default_investigator
from systemsense.application.service import ApplicationService

service = ApplicationService(Path(sys.argv[2]), factory=default_investigator)
try:
    process = psutil.Process()
    ready = Path(sys.argv[1])
    pending = ready.with_suffix(".pending")
    pending.write_text(
        json.dumps(
            {
                "process_id": os.getpid(),
                "process_created_at": process.create_time(),
                "runtime_scope": "application_service_idle",
            },
            separators=(",", ":"),
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    pending.replace(ready)
    time.sleep(float(sys.argv[3]))
finally:
    service.close()
"""
_IDLE_CHILD_STARTUP_TIMEOUT_SECONDS = 5.0


def measure_idle(
    *,
    duration_seconds: float,
    sample_interval_seconds: float,
) -> IdleMeasurement:
    if duration_seconds < 0.05 or duration_seconds > 60:
        raise ValueError("duration_seconds must be between 0.05 and 60")
    if sample_interval_seconds <= 0 or sample_interval_seconds > duration_seconds:
        raise ValueError("sample interval must be positive and no longer than duration")

    with tempfile.TemporaryDirectory(prefix="systemsense-idle-") as temporary:
        ready_path = Path(temporary) / "ready"
        creation_flags = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0
        child = subprocess.Popen(
            [
                sys.executable,
                "-c",
                _IDLE_CHILD,
                str(ready_path),
                str(Path(temporary) / "idle.db"),
                str(duration_seconds + 2.0),
            ],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
            text=True,
            creationflags=creation_flags,
        )
        process: psutil.Process | None = None
        try:
            process = _wait_for_idle_child(child, ready_path=ready_path)
            process_name = process.name()
            process_created_at = process.create_time()
            startup_rss_bytes = int(process.memory_info().rss)
            if "python" not in process_name.casefold():
                raise RuntimeError("idle benchmark target is not a Python process")
            if startup_rss_bytes < 16 * 1024 * 1024:
                raise RuntimeError("idle benchmark target did not load the SystemSense runtime")
            process.cpu_percent(interval=None)
            cpu_samples: list[float] = []
            rss_samples = [startup_rss_bytes]
            started = time.perf_counter()
            deadline = started + duration_seconds
            while True:
                remaining = deadline - time.perf_counter()
                if remaining <= 0:
                    break
                time.sleep(min(sample_interval_seconds, remaining))
                cpu_samples.append(max(0.0, float(process.cpu_percent(interval=None))))
                rss_samples.append(int(process.memory_info().rss))
            if not cpu_samples:
                cpu_samples.append(max(0.0, float(process.cpu_percent(interval=None))))
            return IdleMeasurement(
                process_id=process.pid,
                process_name=process_name,
                process_created_at=process_created_at,
                startup_rss_bytes=startup_rss_bytes,
                requested_duration_ms=duration_seconds * 1000,
                sample_interval_ms=sample_interval_seconds * 1000,
                duration_ms=(time.perf_counter() - started) * 1000,
                average_cpu_percent=statistics.fmean(cpu_samples),
                peak_rss_bytes=max(rss_samples),
                sample_count=len(cpu_samples),
            )
        finally:
            _stop_idle_child(child, target=process)
            if child.stderr is not None:
                child.stderr.close()


def _wait_for_idle_child(
    child: subprocess.Popen[str],
    *,
    ready_path: Path,
) -> psutil.Process:
    deadline = time.monotonic() + _IDLE_CHILD_STARTUP_TIMEOUT_SECONDS
    while not ready_path.is_file():
        if child.poll() is not None:
            raise RuntimeError(f"idle benchmark child exited with code {child.returncode}")
        if time.monotonic() >= deadline:
            raise TimeoutError("idle benchmark child did not initialize before its deadline")
        time.sleep(0.01)
    if ready_path.stat().st_size > 512:
        raise RuntimeError("idle benchmark child returned an oversized handshake")
    handshake = _IdleHandshake.model_validate_json(ready_path.read_text(encoding="utf-8"))
    target = psutil.Process(handshake.process_id)
    if abs(target.create_time() - handshake.process_created_at) > 0.01:
        raise RuntimeError("idle benchmark child identity changed before sampling")
    if target.pid != child.pid:
        try:
            descendants = psutil.Process(child.pid).children(recursive=True)
        except psutil.NoSuchProcess as error:
            raise RuntimeError(
                "idle benchmark launcher exited before identity validation"
            ) from error
        if all(item.pid != target.pid for item in descendants):
            raise RuntimeError("idle benchmark handshake did not identify an owned descendant")
    return target


def _stop_idle_child(
    child: subprocess.Popen[str],
    *,
    target: psutil.Process | None,
) -> None:
    owned: dict[int, psutil.Process] = {}
    if target is not None:
        owned[target.pid] = target
    try:
        launcher = psutil.Process(child.pid)
        for process in (*launcher.children(recursive=True), launcher):
            owned[process.pid] = process
    except psutil.NoSuchProcess:
        pass
    for process in reversed(tuple(owned.values())):
        try:
            process.terminate()
        except psutil.NoSuchProcess:
            pass
    _, alive = psutil.wait_procs(tuple(owned.values()), timeout=0.5)
    for process in alive:
        try:
            process.kill()
        except psutil.NoSuchProcess:
            pass
    psutil.wait_procs(alive, timeout=0.5)
    if child.poll() is None:
        child.kill()
    try:
        child.wait(timeout=0.5)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("idle benchmark child did not stop after kill") from error


def measure_operation(
    operation: Callable[[], None],
    *,
    database_path: Path,
    sample_interval_seconds: float = 0.01,
) -> OperationMeasurement:
    if sample_interval_seconds <= 0 or sample_interval_seconds > 1:
        raise ValueError("sample_interval_seconds must be between 0 and 1")
    process = psutil.Process()
    before_io = process.io_counters()
    before_database_bytes = _database_footprint(database_path)
    rss_samples = [int(process.memory_info().rss)]
    stop = threading.Event()

    def sample_memory() -> None:
        while not stop.wait(sample_interval_seconds):
            rss_samples.append(int(process.memory_info().rss))

    sampler = threading.Thread(
        target=sample_memory,
        name="systemsense-resource-sampler",
        daemon=True,
    )
    sampler.start()
    started = time.perf_counter()
    try:
        operation()
    finally:
        elapsed_ms = (time.perf_counter() - started) * 1000
        stop.set()
        sampler.join(timeout=1)
        rss_samples.append(int(process.memory_info().rss))
    after_io = process.io_counters()
    after_database_bytes = _database_footprint(database_path)
    return OperationMeasurement(
        elapsed_ms=elapsed_ms,
        peak_rss_bytes=max(rss_samples),
        read_bytes=max(0, int(after_io.read_bytes - before_io.read_bytes)),
        write_bytes=max(0, int(after_io.write_bytes - before_io.write_bytes)),
        database_growth_bytes=max(0, after_database_bytes - before_database_bytes),
    )


def run_resource_benchmark() -> ResourceReport:
    idle = measure_idle(
        duration_seconds=0.5,
        sample_interval_seconds=0.05,
    )
    with tempfile.TemporaryDirectory(prefix="systemsense-resource-") as temporary:
        database_path = Path(temporary) / "systemsense.db"

        def open_and_brief_case() -> None:
            with SQLiteStore(database_path) as store:
                case_service = CaseService(store, default_planner())
                workspace = EvidenceWorkspace(
                    store=store,
                    case_service=case_service,
                    case_runtime=default_case_runtime(
                        store,
                        case_service=case_service,
                    ),
                )
                opened = workspace.open_case(
                    kind=CaseKind.GENERAL,
                    symptom="resource benchmark",
                    target_traits=(),
                    budget_ms=1_000,
                    max_probes=8,
                    created_at=utc_now(),
                )
                workspace.get_case_brief(
                    case_id=opened.case.case_id,
                    max_chars=800,
                )

        case_operation = measure_operation(
            open_and_brief_case,
            database_path=database_path,
        )
    return ResourceReport(idle=idle, case_operation=case_operation)


def _database_footprint(database_path: Path) -> int:
    return sum(
        candidate.stat().st_size
        for candidate in (
            database_path,
            Path(f"{database_path}-wal"),
            Path(f"{database_path}-shm"),
        )
        if candidate.is_file()
    )


def main() -> int:
    print(
        json.dumps(
            run_resource_benchmark().model_dump(mode="json"),
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
