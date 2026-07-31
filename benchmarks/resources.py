"""Measured idle and case-operation resource usage."""

from __future__ import annotations

import json
import statistics
import tempfile
import threading
import time
from collections.abc import Callable
from pathlib import Path

import psutil
from pydantic import Field

from benchmarks.models import BenchmarkModel
from systemsense.application.case_service import CaseService
from systemsense.domain.cases import CaseKind
from systemsense.domain.time import utc_now
from systemsense.mcp_server import (
    MCPWorkspace,
    default_case_runtime,
    default_planner,
)
from systemsense.storage.sqlite_store import SQLiteStore


class IdleMeasurement(BenchmarkModel):
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


def measure_idle(
    *,
    duration_seconds: float,
    sample_interval_seconds: float,
) -> IdleMeasurement:
    if duration_seconds < 0.05 or duration_seconds > 60:
        raise ValueError("duration_seconds must be between 0.05 and 60")
    if sample_interval_seconds <= 0 or sample_interval_seconds > duration_seconds:
        raise ValueError("sample interval must be positive and no longer than duration")

    process = psutil.Process()
    process.cpu_percent(interval=None)
    cpu_samples: list[float] = []
    rss_samples = [int(process.memory_info().rss)]
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
        duration_ms=(time.perf_counter() - started) * 1000,
        average_cpu_percent=statistics.fmean(cpu_samples),
        peak_rss_bytes=max(rss_samples),
        sample_count=len(cpu_samples),
    )


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
                workspace = MCPWorkspace(
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
