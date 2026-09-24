"""CPU-only synthetic event-to-admission benchmark for the adaptive scheduler.

This exercises a real SQLite commit, bounded policy queue, fake inference,
validation, external task admission, and the production blocking scheduler. It
does not exercise Windows collectors, Laya weights, GPU, or diagnostic quality.
Every emitted event remains in the denominator, including rejected work.
"""

from __future__ import annotations

import argparse
import json
import math
import platform
import queue
import sqlite3
import tempfile
import threading
import time
from collections import Counter
from collections.abc import Callable
from contextlib import closing
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Protocol

from systemsense.orchestration.scheduler import (
    BlockingTaskOfferQueue,
    BoundedScheduler,
    ResourceBudget,
    ResourceClass,
    Task,
    TaskContext,
    TaskResult,
    TaskStatus,
)

_NS_PER_MS = 1_000_000


@dataclass(frozen=True, slots=True)
class LatencyConfig:
    event_count: int = 16
    queue_capacity: int = 16
    event_deadline_ms: int = 400
    unrelated_probe_ms: int = 500

    def __post_init__(self) -> None:
        if not 1 <= self.event_count <= 256:
            raise ValueError("event_count must be between 1 and 256")
        if not 1 <= self.queue_capacity <= 256:
            raise ValueError("queue_capacity must be between 1 and 256")
        if not 1 <= self.event_deadline_ms <= 10_000:
            raise ValueError("event_deadline_ms must be between 1 and 10000")
        if not 1 <= self.unrelated_probe_ms <= 10_000:
            raise ValueError("unrelated_probe_ms must be between 1 and 10000")


class FakeProvider(Protocol):
    @property
    def delay_ms(self) -> int: ...

    def rank(self, event_id: int, advertised_candidates: tuple[str, ...]) -> str: ...


@dataclass(frozen=True, slots=True)
class FakeFastProvider:
    """Repeatable fake policy; the delay is sleep time, not measured model latency."""

    delay_ms: int = 2
    invalid_every: int = 0
    fail_every: int = 0

    def __post_init__(self) -> None:
        if not 0 <= self.delay_ms <= 10_000:
            raise ValueError("delay_ms must be between 0 and 10000")
        if self.invalid_every < 0 or self.fail_every < 0:
            raise ValueError("fault frequency must be nonnegative")

    def rank(self, event_id: int, advertised_candidates: tuple[str, ...]) -> str:
        if self.delay_ms:
            time.sleep(self.delay_ms / 1000)
        if self.fail_every and event_id % self.fail_every == 0:
            raise RuntimeError("controlled fake provider failure")
        if self.invalid_every and event_id % self.invalid_every == 0:
            return "unadvertised-candidate"
        return advertised_candidates[0]


@dataclass(frozen=True, slots=True)
class FakeSlowProvider(FakeFastProvider):
    delay_ms: int = 60


@dataclass(slots=True)
class _Attempt:
    event_id: int
    emitted_ns: int | None = None
    persisted_ns: int | None = None
    queued_ns: int | None = None
    dequeued_ns: int | None = None
    inferred_ns: int | None = None
    validated_ns: int | None = None
    admitted_ns: int | None = None
    started_ns: int | None = None
    finished_ns: int | None = None
    miss_reason: str | None = None
    task_status: str | None = None


def run_trial(
    config: LatencyConfig,
    provider: FakeProvider,
    *,
    database_path: Path | None = None,
) -> dict[str, Any]:
    """Measure one fixed synthetic workload; persist every attempted event."""

    if database_path is None:
        with tempfile.TemporaryDirectory(prefix="systemsense-adaptive-latency-") as directory:
            return _run_trial(config, provider, Path(directory) / "events.sqlite3")
    return _run_trial(config, provider, database_path)


def _run_trial(
    config: LatencyConfig, provider: FakeProvider, database_path: Path
) -> dict[str, Any]:
    database_path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(database_path)) as connection:
        connection.execute(
            "CREATE TABLE IF NOT EXISTS benchmark_events "
            "(event_id INTEGER PRIMARY KEY, emitted_monotonic_ns INTEGER NOT NULL, "
            "payload TEXT NOT NULL)"
        )
        connection.commit()

    attempts = {event_id: _Attempt(event_id) for event_id in range(1, config.event_count + 1)}
    lock = threading.Lock()
    pending: queue.Queue[_Attempt | None] = queue.Queue(maxsize=config.queue_capacity)
    offers = BlockingTaskOfferQueue(max_pending=config.queue_capacity)
    slow_started = threading.Event()
    slow_times: dict[str, int] = {}
    unexpected: list[str] = []

    def mark_miss(attempt: _Attempt, reason: str) -> None:
        with lock:
            if attempt.admitted_ns is None and attempt.miss_reason is None:
                attempt.miss_reason = reason

    def producer() -> None:
        try:
            if not slow_started.wait(timeout=2):
                for attempt in attempts.values():
                    mark_miss(attempt, "scheduler_start_failed")
                return
            with closing(sqlite3.connect(database_path)) as connection:
                for attempt in attempts.values():
                    attempt.emitted_ns = time.monotonic_ns()
                    try:
                        connection.execute(
                            "INSERT INTO benchmark_events(event_id, emitted_monotonic_ns, payload) "
                            "VALUES (?, ?, ?)",
                            (attempt.event_id, attempt.emitted_ns, "synthetic-relevant-change"),
                        )
                        connection.commit()
                    except sqlite3.Error:
                        mark_miss(attempt, "persistence_failed")
                        continue
                    attempt.persisted_ns = time.monotonic_ns()
                    attempt.queued_ns = time.monotonic_ns()
                    try:
                        pending.put_nowait(attempt)
                    except queue.Full:
                        mark_miss(attempt, "queue_overload")
        except Exception as error:
            unexpected.append(type(error).__name__)
        finally:
            pending.put(None)

    def policy_worker() -> None:
        try:
            while True:
                attempt = pending.get()
                if attempt is None:
                    break
                attempt.dequeued_ns = time.monotonic_ns()
                assert attempt.persisted_ns is not None
                deadline_ns = attempt.persisted_ns + config.event_deadline_ms * _NS_PER_MS
                if attempt.dequeued_ns >= deadline_ns:
                    mark_miss(attempt, "queue_deadline")
                    continue
                advertised = (f"candidate:{attempt.event_id}",)
                try:
                    choice = provider.rank(attempt.event_id, advertised)
                except Exception:
                    attempt.inferred_ns = time.monotonic_ns()
                    mark_miss(attempt, "provider_failed")
                    continue
                attempt.inferred_ns = time.monotonic_ns()
                if choice not in advertised:
                    attempt.validated_ns = time.monotonic_ns()
                    mark_miss(attempt, "invalid_choice")
                    continue
                attempt.validated_ns = time.monotonic_ns()
                if attempt.validated_ns >= deadline_ns:
                    mark_miss(attempt, "inference_deadline")
                    continue

                def followup(_context: TaskContext, target: _Attempt = attempt) -> int:
                    target.started_ns = time.monotonic_ns()
                    target.finished_ns = time.monotonic_ns()
                    return target.event_id

                task = Task(
                    task_id=f"followup-{attempt.event_id}",
                    action=followup,
                    resource=ResourceClass.CPU,
                    timeout_seconds=1,
                )
                if not offers.offer_factory(lambda task=task: (task,)):
                    mark_miss(attempt, "offer_overload")
        except Exception as error:
            unexpected.append(type(error).__name__)
        finally:
            offers.close()

    def unrelated_slow_probe(_context: TaskContext) -> None:
        slow_times["started"] = time.monotonic_ns()
        slow_started.set()
        time.sleep(config.unrelated_probe_ms / 1000)
        slow_times["finished"] = time.monotonic_ns()

    def on_admitted(tasks: tuple[Task, ...]) -> bool:
        attempt = attempts[int(tasks[0].task_id.removeprefix("followup-"))]
        now_ns = time.monotonic_ns()
        assert attempt.persisted_ns is not None
        if now_ns >= attempt.persisted_ns + config.event_deadline_ms * _NS_PER_MS:
            mark_miss(attempt, "admission_deadline")
            return False
        attempt.admitted_ns = now_ns
        return True

    def on_result(result: TaskResult) -> None:
        if not result.task_id.startswith("followup-"):
            return
        attempt = attempts[int(result.task_id.removeprefix("followup-"))]
        attempt.task_status = result.status.value
        if result.status is not TaskStatus.SUCCEEDED and attempt.started_ns is None:
            mark_miss(attempt, "task_failed_before_start")

    worker_thread = threading.Thread(target=policy_worker, name="latency-policy", daemon=True)
    producer_thread = threading.Thread(target=producer, name="latency-producer", daemon=True)
    worker_thread.start()
    producer_thread.start()
    case_budget_ms = max(
        2_000,
        config.unrelated_probe_ms
        + config.event_count * max(1, provider.delay_ms) * 2
        + config.event_deadline_ms
        + 1_000,
    )
    scheduler = BoundedScheduler(
        budget=ResourceBudget(
            global_limit=2,
            per_resource={ResourceClass.CPU: 1, ResourceClass.DISK: 1},
            max_tasks=config.event_count + 1,
        )
    )
    scheduler.run_blocking(
        (Task("unrelated-slow-probe", unrelated_slow_probe, resource=ResourceClass.DISK),),
        case_deadline_at=datetime.now(UTC) + timedelta(milliseconds=case_budget_ms),
        on_result=on_result,
        on_admitted=on_admitted,
        external_offers=offers,
    )
    producer_thread.join(timeout=1)
    worker_thread.join(timeout=1)
    if producer_thread.is_alive() or worker_thread.is_alive():
        unexpected.append("benchmark_thread_did_not_exit")
    for attempt in attempts.values():
        if attempt.admitted_ns is None and attempt.miss_reason is None:
            attempt.miss_reason = "unclassified_miss"

    ordered = tuple(attempts.values())
    phase_pairs: dict[str, tuple[str, str]] = {
        "persistence": ("emitted_ns", "persisted_ns"),
        "queue": ("queued_ns", "dequeued_ns"),
        "inference": ("dequeued_ns", "inferred_ns"),
        "validation": ("inferred_ns", "validated_ns"),
        "admission": ("validated_ns", "admitted_ns"),
        "start": ("admitted_ns", "started_ns"),
        "execution": ("started_ns", "finished_ns"),
    }
    phase_ms = {
        name: _stats(
            [elapsed for attempt in ordered if (elapsed := _elapsed(attempt, *fields)) is not None]
        )
        for name, fields in phase_pairs.items()
    }
    admission_latencies = [
        elapsed
        for attempt in ordered
        if (elapsed := _elapsed(attempt, "persisted_ns", "admitted_ns")) is not None
    ]
    misses = sum(attempt.admitted_ns is None for attempt in ordered)
    report: dict[str, Any] = {
        "schema_version": 1,
        "kind": "synthetic_event_to_admission_v1",
        "scope": (
            "SQLite synthetic events + fake provider + production blocking scheduler; "
            "not Laya throughput, Windows probe latency, or diagnostic quality"
        ),
        "platform": platform.platform(),
        "provider": type(provider).__name__,
        "provider_delay_ms_configured": provider.delay_ms,
        "configuration": asdict(config),
        "attempts": len(ordered),
        "persisted": sum(item.persisted_ns is not None for item in ordered),
        "admitted": sum(item.admitted_ns is not None for item in ordered),
        "started": sum(item.started_ns is not None for item in ordered),
        "completed": sum(
            item.finished_ns is not None and item.task_status == TaskStatus.SUCCEEDED.value
            for item in ordered
        ),
        "misses": misses,
        "transport_ms": "not_applicable_local_fake",
        "miss_reasons": dict(
            sorted(Counter(item.miss_reason for item in ordered if item.miss_reason).items())
        ),
        "phase_ms": phase_ms,
        "event_to_admission_ms": _stats(admission_latencies),
        "all_attempt_p95_ms": None if misses else _percentile(admission_latencies, 0.95),
        "followup_before_unrelated_finish": any(
            item.started_ns is not None
            and "finished" in slow_times
            and item.started_ns < slow_times["finished"]
            for item in ordered
        ),
        "unrelated_probe_actual_ms": (
            (slow_times["finished"] - slow_times["started"]) / _NS_PER_MS
            if "finished" in slow_times
            else None
        ),
        "unexpected_harness_errors": unexpected,
        "attempts_detail": [
            {
                "event_id": item.event_id,
                "outcome": "admitted" if item.admitted_ns is not None else "missed",
                "miss_reason": item.miss_reason,
                "task_status": item.task_status,
                "phase_ms": {name: _elapsed(item, *fields) for name, fields in phase_pairs.items()},
                "event_to_admission_ms": _elapsed(item, "persisted_ns", "admitted_ns"),
                "event_to_start_ms": _elapsed(item, "persisted_ns", "started_ns"),
            }
            for item in ordered
        ],
    }
    return report


def _elapsed(attempt: _Attempt, start_field: str, end_field: str) -> float | None:
    start = getattr(attempt, start_field)
    end = getattr(attempt, end_field)
    if start is None or end is None:
        return None
    return max(0.0, (end - start) / _NS_PER_MS)


def _percentile(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * quantile
    lower = math.floor(position)
    upper = math.ceil(position)
    return ordered[lower] + (ordered[upper] - ordered[lower]) * (position - lower)


def _stats(values: list[float]) -> dict[str, float | int | None]:
    return {
        "count": len(values),
        "p50": _percentile(values, 0.5),
        "p95": _percentile(values, 0.95),
    }


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--events", type=int, default=16)
    parser.add_argument("--queue-capacity", type=int, default=16)
    parser.add_argument("--deadline-ms", type=int, default=400)
    parser.add_argument("--unrelated-probe-ms", type=int, default=500)
    parser.add_argument("--provider", choices=("fast", "slow"), default="fast")
    parser.add_argument("--provider-delay-ms", type=int)
    parser.add_argument("--output", type=Path, help="exclusive JSON report path; never overwrite")
    args = parser.parse_args(argv)
    if args.output is not None and args.output.exists():
        raise FileExistsError(f"benchmark report already exists: {args.output}")
    config = LatencyConfig(
        event_count=args.events,
        queue_capacity=args.queue_capacity,
        event_deadline_ms=args.deadline_ms,
        unrelated_probe_ms=args.unrelated_probe_ms,
    )
    provider_class: Callable[..., FakeProvider] = (
        FakeFastProvider if args.provider == "fast" else FakeSlowProvider
    )
    provider = (
        provider_class()
        if args.provider_delay_ms is None
        else provider_class(delay_ms=args.provider_delay_ms)
    )
    report = run_trial(config, provider)
    rendered = json.dumps(report, indent=2, sort_keys=True, allow_nan=False) + "\n"
    if args.output is None:
        print(rendered, end="")
        return
    with args.output.open("x", encoding="utf-8") as output:
        output.write(rendered)
    print(json.dumps({"output": str(args.output), "attempts": report["attempts"]}))


if __name__ == "__main__":
    main()
