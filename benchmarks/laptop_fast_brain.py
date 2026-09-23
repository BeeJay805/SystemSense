"""Opt-in, same-request CPU component profile for replaceable fast brains.

No provider is constructed at import time. The command-line path runs only the
deterministic providers unless both explicit CPU-Laya flags are supplied. This
does not measure diagnostic quality, power, or suitability for ordinary laptops.
Same-process synchronous deadlines are soft; isolated workers have an outer limit.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal, TypedDict, cast, get_args

import psutil

from benchmarks.decision_provider_profile import catalog_sha256, request_sha256
from systemsense.decision.baseline import KeywordBaselineDecisionProvider
from systemsense.decision.contracts import DecisionRequest, DecisionResponse, ProviderIdentity
from systemsense.decision.laya import LayaDecisionProvider
from systemsense.decision.provider import FastDecisionProvider
from systemsense.decision.typed_ranker import TypedFeatureDecisionProvider
from systemsense.inference.laya_runtime import LayaSubprocessRuntime
from systemsense.inference.profile import load_inference_profile

_MIN_LAYA_FREE_RAM_BYTES = 8 * 1024**3
_SAMPLE_INTERVAL_SECONDS = 0.01
_MAX_INPUT_BYTES = 1_000_000
_MAX_HANDSHAKE_CHARS = 4_096
_MAX_WORKER_OUTPUT_CHARS = 1_000_000
Phase = Literal["cold", "warm"]
Status = Literal[
    "complete",
    "deadline_miss",
    "coverage_failure",
    "degraded",
    "invalid_response",
    "call_error",
    "construction_error",
    "admission_refused",
    "not_run",
    "worker_timeout",
    "worker_error",
]


@dataclass(frozen=True, slots=True)
class ProviderSession:
    provider: FastDecisionProvider
    close: Callable[[], None] | None = None


@dataclass(frozen=True, slots=True)
class ProviderPlan:
    name: str
    factory: Callable[[], ProviderSession]
    attention_required: bool = False
    cpu_laya: bool = False
    fallback_identity: ProviderIdentity | None = None
    expected_provider_id: str | None = None


class SampleRecord(TypedDict):
    phase: Phase
    request_sha256: str
    catalog_sha256: str
    status: Status
    failure_type: str | None
    deadline_exceeded: bool | None
    coverage_complete: bool | None
    response_degraded: bool | None
    wall_ms: float | None
    owned_process_tree_cpu_seconds: float | None
    baseline_owned_process_tree_rss_bytes: int | None
    peak_owned_process_tree_rss_bytes: int | None
    final_owned_process_tree_rss_bytes: int | None
    supplied_pages: int
    ranked_pages: int
    considered_evidence: int
    proposal_count: int


class SummaryRecord(TypedDict):
    planned: int
    complete: int
    deadline_miss: int
    coverage_failure: int
    degraded: int
    other_failure_or_not_run: int
    wall_p50_ms: float | None
    wall_p95_ms: float | None
    complete_wall_p50_ms: float | None
    complete_wall_p95_ms: float | None
    max_sampled_owned_process_tree_rss_bytes: int | None


class ProviderRecord(TypedDict):
    provider_id: str | None
    request_hashes: tuple[str, ...]
    catalog_hashes: tuple[str, ...]
    samples: list[SampleRecord]
    summary: SummaryRecord
    teardown_error_type: str | None


class ComparisonReport(TypedDict):
    schema_version: Literal[1]
    classification: Literal["same_request_cpu_component_profile_only"]
    redaction_attestation: Literal["caller_attested_not_verified"]
    ordinary_laptop_qualified: Literal[False]
    diagnostic_quality_measured: Literal[False]
    resource_scope: Literal["whole_harness_process_tree_order_confounded"]
    providers: dict[str, ProviderRecord]
    limitations: tuple[str, ...]


class IsolatedProviderRecord(ProviderRecord):
    worker_pid: int | None
    worker_cleanup_confirmed: bool | None
    worker_cleanup_alive_pids: tuple[int, ...]
    worker_cleanup_error_type: str | None


class IsolatedComparisonReport(TypedDict):
    schema_version: Literal[3]
    classification: Literal["isolated_same_request_cpu_component_profile_only"]
    redaction_attestation: Literal["caller_attested_not_verified"]
    ordinary_laptop_qualified: Literal[False]
    diagnostic_quality_measured: Literal[False]
    resource_scope: Literal["sampled_worker_tree_windows_job_custody_sequential"]
    providers: dict[str, IsolatedProviderRecord]
    limitations: tuple[str, ...]


class WorkerTimeout(Exception):
    """A supervised worker exceeded its whole-run limit and was reaped."""

    def __init__(self, pid: int) -> None:
        super().__init__("worker exceeded whole-run timeout")
        self.pid = pid


class WorkerCleanupError(Exception):
    """Worker cleanup could not be verified; do not launch another provider."""

    def __init__(self, pid: int | None, alive_pids: tuple[int, ...], failure_type: str) -> None:
        super().__init__("worker cleanup could not be verified")
        self.pid = pid
        self.alive_pids = alive_pids
        self.failure_type = failure_type


class WorkerProtocolError(Exception):
    def __init__(self, pid: int) -> None:
        super().__init__("worker handshake failed")
        self.pid = pid


class WorkerOutputLimit(Exception):
    def __init__(self, pid: int) -> None:
        super().__init__("worker stdout exceeded the report limit")
        self.pid = pid


class WorkerOutputDecodeError(Exception):
    def __init__(self, pid: int) -> None:
        super().__init__("worker stdout is not valid UTF-8")
        self.pid = pid


class InputMismatch(ValueError):
    """Worker request or catalog differs from the supervisor's validated input."""


@dataclass(frozen=True, slots=True)
class ProcessIdentity:
    pid: int
    create_time: float


class _WindowsJob:
    """Own a suspended worker and its ordinary CreateProcess descendants."""

    def __init__(self) -> None:
        import win32job

        job_api: Any = win32job
        self._job: Any = job_api.CreateJobObject(None, "")
        self._close_lock = threading.Lock()
        self._closed = False
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

    def assign_and_resume(self, worker: subprocess.Popen[str], identity: ProcessIdentity) -> None:
        import ctypes
        from ctypes import wintypes

        import win32api
        import win32con
        import win32job
        import win32process

        api: Any = win32api
        job_api: Any = win32job
        process_api: Any = win32process
        process_handle = getattr(worker, "_handle", None)
        if (
            not isinstance(process_handle, int)
            or process_api.GetProcessId(process_handle) != identity.pid
        ):
            raise RuntimeError("worker process handle does not match launched PID")
        if _current_process(identity) is None:
            raise RuntimeError("suspended worker identity changed")
        job_api.AssignProcessToJobObject(self._job, process_handle)
        current = _current_process(identity)
        if current is None:
            raise RuntimeError("assigned worker identity changed")
        threads = current.threads()
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
            if get_owner(int(thread_handle)) != identity.pid:
                raise RuntimeError("primary thread no longer belongs to suspended worker")
            if _current_process(identity) is None:
                raise RuntimeError("worker identity changed before resume")
            prior_count = process_api.ResumeThread(thread_handle)
        finally:
            thread_handle.Close()
        if prior_count != 1:
            raise RuntimeError("worker primary thread was not suspended exactly once")

    def close(self) -> None:
        with self._close_lock:
            if not self._closed:
                self._job.Close()
                self._closed = True


class _OwnedResources:
    """Sample the current process and descendants, including short-lived children seen."""

    def __init__(self) -> None:
        self._root = psutil.Process()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._poll, daemon=True)
        self._baseline_cpu: dict[tuple[int, float], float] = {}
        self._max_cpu: dict[tuple[int, float], float] = {}
        self.baseline_rss = 0
        self.peak_rss = 0
        self.final_rss = 0

    def _snapshot(self, *, baseline: bool = False) -> None:
        try:
            processes = (self._root, *self._root.children(recursive=True))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            processes = (self._root,)
        rss = 0
        for process in processes:
            try:
                key = (process.pid, process.create_time())
                usage = process.cpu_times()
                cpu = float(usage.user + usage.system)
                rss += int(process.memory_info().rss)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            if baseline:
                self._baseline_cpu[key] = cpu
            self._max_cpu[key] = max(cpu, self._max_cpu.get(key, 0.0))
        if baseline:
            self.baseline_rss = rss
        self.final_rss = rss
        self.peak_rss = max(self.peak_rss, rss)

    def _poll(self) -> None:
        while not self._stop.wait(_SAMPLE_INTERVAL_SECONDS):
            self._snapshot()

    def start(self) -> None:
        self._snapshot(baseline=True)
        self._thread.start()

    def finish(self) -> float:
        self._stop.set()
        self._thread.join(timeout=1)
        self._snapshot()
        return max(
            0.0,
            sum(
                max(0.0, cpu - self._baseline_cpu.get(key, 0.0))
                for key, cpu in self._max_cpu.items()
            ),
        )


def _nearest_rank(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    return sorted(values)[math.ceil(quantile * len(values)) - 1]


def _summary(samples: list[SampleRecord]) -> SummaryRecord:
    walls = [sample["wall_ms"] for sample in samples if sample["wall_ms"] is not None]
    complete_walls = [
        sample["wall_ms"]
        for sample in samples
        if sample["status"] == "complete" and sample["wall_ms"] is not None
    ]
    peaks = [
        sample["peak_owned_process_tree_rss_bytes"]
        for sample in samples
        if sample["peak_owned_process_tree_rss_bytes"] is not None
    ]
    return {
        "planned": len(samples),
        "complete": sum(item["status"] == "complete" for item in samples),
        "deadline_miss": sum(item["deadline_exceeded"] is True for item in samples),
        "coverage_failure": sum(item["coverage_complete"] is False for item in samples),
        "degraded": sum(item["response_degraded"] is True for item in samples),
        "other_failure_or_not_run": sum(
            item["status"] not in {"complete", "deadline_miss", "coverage_failure", "degraded"}
            for item in samples
        ),
        "wall_p50_ms": _nearest_rank(walls, 0.5),
        "wall_p95_ms": _nearest_rank(walls, 0.95),
        "complete_wall_p50_ms": _nearest_rank(complete_walls, 0.5),
        "complete_wall_p95_ms": _nearest_rank(complete_walls, 0.95),
        "max_sampled_owned_process_tree_rss_bytes": max(peaks) if peaks else None,
    }


def _empty_sample(request: DecisionRequest, phase: Phase, status: Status) -> SampleRecord:
    pages = request.attention_context or request.evidence_context
    return {
        "phase": phase,
        "request_sha256": request_sha256(request),
        "catalog_sha256": catalog_sha256(request),
        "status": status,
        "failure_type": None,
        "deadline_exceeded": None,
        "coverage_complete": None,
        "response_degraded": None,
        "wall_ms": None,
        "owned_process_tree_cpu_seconds": None,
        "baseline_owned_process_tree_rss_bytes": None,
        "peak_owned_process_tree_rss_bytes": None,
        "final_owned_process_tree_rss_bytes": None,
        "supplied_pages": len(pages),
        "ranked_pages": 0,
        "considered_evidence": 0,
        "proposal_count": 0,
    }


def _run_call(
    request: DecisionRequest,
    phase: Phase,
    plan: ProviderPlan,
    session: ProviderSession | None,
    *,
    deadline_ms: float,
) -> tuple[SampleRecord, ProviderSession | None]:
    sample = _empty_sample(request, phase, "call_error")
    meter = _OwnedResources()
    meter.start()
    started = time.perf_counter_ns()
    response: object | None = None
    try:
        if session is None:
            try:
                session = plan.factory()
            except Exception as error:
                sample["status"] = "construction_error"
                sample["failure_type"] = type(error).__name__
        if session is not None:
            try:
                response = cast(object, session.provider.decide(request))
            except Exception as error:
                sample["failure_type"] = type(error).__name__
    finally:
        sample["wall_ms"] = (time.perf_counter_ns() - started) / 1_000_000
        sample["deadline_exceeded"] = sample["wall_ms"] > deadline_ms
        sample["owned_process_tree_cpu_seconds"] = meter.finish()
        sample["baseline_owned_process_tree_rss_bytes"] = meter.baseline_rss
        sample["peak_owned_process_tree_rss_bytes"] = meter.peak_rss
        sample["final_owned_process_tree_rss_bytes"] = meter.final_rss

    if response is None and session is not None and sample["failure_type"] is None:
        sample["status"], sample["failure_type"] = "invalid_response", "UnexpectedType"
    if response is not None and session is not None:
        if not isinstance(response, DecisionResponse):
            sample["status"], sample["failure_type"] = "invalid_response", "UnexpectedType"
        else:
            try:
                response = DecisionResponse.model_validate(
                    response.model_dump(mode="python", warnings="error")
                ).validate_against(request)
                if response.provider != session.provider.identity and not (
                    response.degraded
                    and plan.fallback_identity is not None
                    and response.provider == plan.fallback_identity
                ):
                    raise ValueError("provider identity mismatch")
                if sample["request_sha256"] != request_sha256(request):
                    raise ValueError("provider mutated frozen request")
            except Exception as error:
                sample["status"], sample["failure_type"] = "invalid_response", type(error).__name__
            else:
                pages = request.attention_context or request.evidence_context
                expected_pages = {f"{page.evidence_id}:{index}" for index, page in enumerate(pages)}
                sample["ranked_pages"] = len(response.ranked_attention_page_ids)
                sample["considered_evidence"] = response.considered_evidence_count
                sample["proposal_count"] = len(response.proposals)
                sample["response_degraded"] = response.degraded
                coverage_complete = not plan.attention_required or (
                    set(response.ranked_attention_page_ids) == expected_pages
                    and response.considered_evidence_count
                    == len({str(page.evidence_id) for page in pages})
                    and (
                        not plan.cpu_laya
                        or all(
                            sum(note.startswith(prefix) for note in response.attention_notes) == 1
                            and expected in response.attention_notes
                            for prefix, expected in (
                                ("coverage_limited=", "coverage_limited=false"),
                                ("state_truncated_batches=", "state_truncated_batches=0"),
                                ("instruction_truncated_items=", "instruction_truncated_items=0"),
                            )
                        )
                    )
                )
                sample["coverage_complete"] = coverage_complete if plan.attention_required else None
                if response.degraded:
                    sample["status"] = "degraded"
                elif not coverage_complete:
                    sample["status"] = "coverage_failure"
                else:
                    sample["status"] = "complete"
                if sample["deadline_exceeded"]:
                    sample["status"] = "deadline_miss"
    return sample, session


def compare_fast_brains(
    requests: tuple[DecisionRequest, ...],
    plans: tuple[ProviderPlan, ...],
    *,
    deadline_ms: float = 3_000,
    redaction_attested: bool = False,
) -> ComparisonReport:
    """Use one cold request and at least two distinct warm requests per provider.

    The attestation is caller-supplied, not a privacy audit. Raw requests are
    never emitted in the result. Every planned call stays in the denominator.
    """
    if not redaction_attested:
        raise ValueError("redaction attestation is required for profiling")
    if len(requests) < 3 or len(set(map(request_sha256, requests[1:]))) < 2:
        raise ValueError("at least two distinct warm requests are required")
    if not plans or len({plan.name for plan in plans}) != len(plans):
        raise ValueError("provider plans must have unique names")
    if not 0 < deadline_ms <= 180_000:
        raise ValueError("deadline_ms must be in (0, 180000]")
    if any(len(request.attention_context or request.evidence_context) > 64 for request in requests):
        raise ValueError("attention comparisons require at most 64 pages per request")
    serialized = tuple(request.model_dump_json() for request in requests)
    result: dict[str, ProviderRecord] = {}
    for plan in plans:
        samples: list[SampleRecord] = []
        session: ProviderSession | None = None
        teardown_error_type: str | None = None
        admitted = True
        if plan.cpu_laya:
            try:
                admitted = psutil.virtual_memory().available >= _MIN_LAYA_FREE_RAM_BYTES
            except Exception:
                admitted = False
        if not admitted:
            samples.append(_empty_sample(requests[0], "cold", "admission_refused"))
        else:
            try:
                for index, encoded in enumerate(serialized):
                    request = DecisionRequest.model_validate_json(encoded)
                    if index and session is None:
                        samples.append(_empty_sample(request, "warm", "not_run"))
                        continue
                    sample, session = _run_call(
                        request,
                        "cold" if index == 0 else "warm",
                        plan,
                        session,
                        deadline_ms=deadline_ms,
                    )
                    samples.append(sample)
            finally:
                if session is not None and session.close is not None:
                    try:
                        session.close()
                    except Exception as error:
                        teardown_error_type = type(error).__name__
        while len(samples) < len(requests):
            samples.append(_empty_sample(requests[len(samples)], "warm", "not_run"))
        result[plan.name] = {
            "provider_id": session.provider.identity.provider_id if session is not None else None,
            "request_hashes": tuple(request_sha256(request) for request in requests),
            "catalog_hashes": tuple(catalog_sha256(request) for request in requests),
            "samples": samples,
            "summary": _summary(samples),
            "teardown_error_type": teardown_error_type,
        }
    return {
        "schema_version": 1,
        "classification": "same_request_cpu_component_profile_only",
        "redaction_attestation": "caller_attested_not_verified",
        "ordinary_laptop_qualified": False,
        "diagnostic_quality_measured": False,
        "resource_scope": "whole_harness_process_tree_order_confounded",
        "providers": result,
        "limitations": (
            "Only the provider component is timed; collection, scheduling, diagnosis, and "
            "repair are excluded.",
            "A caller attests redaction; this harness cannot prove input privacy or source "
            "identity.",
            "Deadlines are soft for synchronous providers; a hung call may exceed the limit.",
            "10 ms process-tree samples can miss transient child memory and CPU use.",
            "Resource readings include the shared harness interpreter and allocations retained "
            "by earlier plans; do not rank provider RAM from these values.",
            "All-attempt latency includes failures; compare complete-only latency only alongside "
            "its completion denominator, not as a standalone speed win.",
            "Keyword routing has no attention-page coverage contract; its page counts remain "
            "visible.",
            "No hardware diversity, power, workload interference, held-out labels, or outcome "
            "quality is measured.",
        ),
    }


def _laya_session(profile_path: Path) -> ProviderSession:
    profile = load_inference_profile(profile_path)
    if not profile.laya.enabled:
        raise ValueError("profile must enable a pinned Laya installation")
    config = profile.laya.runtime_config().model_copy(
        update={"device": "cpu", "precision": "float32"}
    )
    config.validate_install()
    runtime = LayaSubprocessRuntime(config)
    return ProviderSession(
        LayaDecisionProvider(ranker=runtime, timeout_seconds=profile.laya.timeout_seconds),
        runtime.close,
    )


def _plans(*, allow_cpu_laya: bool, laya_profile: Path | None) -> tuple[ProviderPlan, ...]:
    plans = [
        ProviderPlan(
            "keyword",
            lambda: ProviderSession(KeywordBaselineDecisionProvider()),
            expected_provider_id=KeywordBaselineDecisionProvider().identity.provider_id,
        ),
        ProviderPlan(
            "typed-feature",
            lambda: ProviderSession(TypedFeatureDecisionProvider()),
            attention_required=True,
            expected_provider_id=TypedFeatureDecisionProvider().identity.provider_id,
        ),
    ]
    if allow_cpu_laya:
        assert laya_profile is not None
        plans.append(
            ProviderPlan(
                "cpu-laya",
                lambda: _laya_session(laya_profile),
                attention_required=True,
                cpu_laya=True,
                fallback_identity=KeywordBaselineDecisionProvider().identity,
                expected_provider_id="laya-local-decision",
            )
        )
    return tuple(plans)


def _read_requests(paths: tuple[Path, ...]) -> tuple[DecisionRequest, ...]:
    requests: list[DecisionRequest] = []
    if len(paths) > 64:
        raise ValueError("at most 64 request files are supported")
    for path in paths:
        with path.open("rb") as stream:
            encoded = stream.read(_MAX_INPUT_BYTES + 1)
        if len(encoded) > _MAX_INPUT_BYTES:
            raise ValueError("request JSON exceeds 1 MB")
        requests.append(DecisionRequest.model_validate_json(encoded))
    return tuple(requests)


def _current_process(identity: ProcessIdentity) -> psutil.Process | None:
    try:
        process = psutil.Process(identity.pid)
        if process.create_time() != identity.create_time:
            raise ValueError("process PID was reused")
    except psutil.NoSuchProcess:
        return None
    return process


def _read_with_timeout(
    worker: subprocess.Popen[str], reader: Callable[[], str], timeout_seconds: float
) -> str:
    results: list[str] = []
    failures: list[BaseException] = []

    def run() -> None:
        try:
            results.append(reader())
        except BaseException as error:
            failures.append(error)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(timeout_seconds)
    if thread.is_alive():
        raise subprocess.TimeoutExpired(worker.args, timeout_seconds)
    if failures:
        raise failures[0]
    return results[0]


def _read_handshake_line(worker: subprocess.Popen[str], timeout_seconds: float) -> str:
    stdout = worker.stdout
    assert stdout is not None
    try:
        line = _read_with_timeout(
            worker, lambda: stdout.readline(_MAX_HANDSHAKE_CHARS + 1), timeout_seconds
        )
    except UnicodeError as error:
        raise WorkerProtocolError(worker.pid) from error
    if len(line) > _MAX_HANDSHAKE_CHARS or not line.endswith("\n"):
        raise WorkerProtocolError(worker.pid)
    return line


def _read_worker_output(worker: subprocess.Popen[str], timeout_seconds: float) -> str:
    stdout = worker.stdout
    assert stdout is not None
    try:
        output = _read_with_timeout(
            worker, lambda: stdout.read(_MAX_WORKER_OUTPUT_CHARS + 1), timeout_seconds
        )
    except UnicodeError as error:
        raise WorkerOutputDecodeError(worker.pid) from error
    if len(output) > _MAX_WORKER_OUTPUT_CHARS:
        raise WorkerOutputLimit(worker.pid)
    return output


def _supervise_worker(
    command: tuple[str, ...], *, timeout_seconds: float, verify_handshake: bool = False
) -> tuple[str, int, int, int | None]:
    if os.name != "nt":
        raise RuntimeError("supervised workers require Windows Job Objects")
    import win32con

    started = time.monotonic()
    try:
        job = _WindowsJob()
    except Exception as error:
        raise WorkerCleanupError(None, (), type(error).__name__) from error
    try:
        worker = subprocess.Popen(
            command,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="strict",
            creationflags=win32con.CREATE_SUSPENDED,
        )
    except BaseException as error:
        job.close()
        raise WorkerCleanupError(None, (), type(error).__name__) from error
    try:
        launcher_identity: ProcessIdentity | None = ProcessIdentity(
            worker.pid, psutil.Process(worker.pid).create_time()
        )
    except psutil.Error:
        launcher_identity = None
    try:
        if launcher_identity is None:
            raise RuntimeError("suspended worker identity unavailable")
        job.assign_and_resume(worker, launcher_identity)
    except BaseException as error:
        try:
            worker.kill()
        except OSError:
            pass
        try:
            job.close()
            worker.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired) as cleanup_error:
            raise WorkerCleanupError(
                worker.pid, (worker.pid,), type(cleanup_error).__name__
            ) from error
        raise WorkerCleanupError(worker.pid, (), type(error).__name__) from error
    monitor_errors: list[str] = []

    def close_job_on_worker_exit() -> None:
        try:
            worker.wait()
            job.close()
        except Exception as error:
            monitor_errors.append(type(error).__name__)

    monitor = threading.Thread(target=close_job_on_worker_exit, daemon=True)
    monitor.start()
    verified_pid: int | None = None

    def close_custody() -> tuple[tuple[int, ...], str | None]:
        failure: str | None = None
        try:
            job.close()
        except Exception as error:
            failure = type(error).__name__
        try:
            worker.wait(timeout=5)
        except (subprocess.TimeoutExpired, OSError) as error:
            failure = type(error).__name__
        monitor.join(timeout=5)
        if monitor.is_alive():
            failure = "MonitorStillRunning"
        if monitor_errors:
            failure = monitor_errors[0]
        return ((worker.pid,) if failure else ()), failure

    try:
        if verify_handshake:
            remaining = max(0.001, timeout_seconds - (time.monotonic() - started))
            line = _read_handshake_line(worker, remaining)
            try:
                handshake = json.loads(line)
                candidate_pid = handshake["worker_pid"]
                if not isinstance(candidate_pid, int) or candidate_pid <= 0:
                    raise ValueError("invalid worker PID")
                actual = psutil.Process(candidate_pid)
                if candidate_pid != worker.pid and worker.pid not in (
                    process.pid for process in actual.parents()
                ):
                    raise ValueError("worker is outside launched process tree")
                verified_pid = candidate_pid
            except (ValueError, KeyError, TypeError, psutil.Error) as error:
                raise WorkerProtocolError(worker.pid) from error
            assert worker.stdin is not None
            worker.stdin.write("go\n")
            worker.stdin.flush()
            worker.stdin.close()
            worker.stdin = None
        remaining = max(0.001, timeout_seconds - (time.monotonic() - started))
        output = _read_worker_output(worker, remaining)
        remaining = max(0.001, timeout_seconds - (time.monotonic() - started))
        worker.wait(timeout=remaining)
        alive, failure = close_custody()
        if failure is not None:
            raise WorkerCleanupError(worker.pid, alive, failure)
        assert worker.stdout is not None
        worker.stdout.close()
    except subprocess.TimeoutExpired as error:
        alive, failure = close_custody()
        if failure is not None:
            raise WorkerCleanupError(worker.pid, alive, failure) from error
        raise WorkerTimeout(worker.pid) from error
    except (WorkerProtocolError, WorkerOutputLimit, WorkerOutputDecodeError) as error:
        alive, failure = close_custody()
        if failure is not None:
            raise WorkerCleanupError(worker.pid, alive, failure) from error
        raise
    except WorkerCleanupError:
        raise
    except BaseException as error:
        alive, failure = close_custody()
        if failure is not None:
            raise WorkerCleanupError(worker.pid, alive, failure) from error
        raise
    return output, worker.pid, worker.returncode, verified_pid


def _failed_worker_record(
    requests: tuple[DecisionRequest, ...],
    status: Status,
    pid: int | None,
    failure: str,
    *,
    cleanup_confirmed: bool | None = None,
    cleanup_alive_pids: tuple[int, ...] = (),
    cleanup_error_type: str | None = None,
) -> IsolatedProviderRecord:
    samples = [
        _empty_sample(request, "cold" if index == 0 else "warm", status)
        for index, request in enumerate(requests)
    ]
    for sample in samples:
        sample["failure_type"] = failure
    return {
        "provider_id": None,
        "request_hashes": tuple(request_sha256(request) for request in requests),
        "catalog_hashes": tuple(catalog_sha256(request) for request in requests),
        "samples": samples,
        "summary": _summary(samples),
        "teardown_error_type": None,
        "worker_pid": pid,
        "worker_cleanup_confirmed": cleanup_confirmed,
        "worker_cleanup_alive_pids": cleanup_alive_pids,
        "worker_cleanup_error_type": cleanup_error_type,
    }


def _validate_worker_record(
    record: object,
    requests: tuple[DecisionRequest, ...],
    expected_provider_id: str | None,
    attention_required: bool,
    deadline_ms: float,
) -> IsolatedProviderRecord:
    if not isinstance(record, dict) or set(cast(dict[str, Any], record)) != set(
        ProviderRecord.__annotations__
    ):
        raise ValueError("worker record shape mismatch")
    record_data = cast(dict[str, Any], record)
    raw_samples = cast(object, record_data.get("samples"))
    if not isinstance(raw_samples, list):
        raise ValueError("worker sample count mismatch")
    samples = cast(list[Any], raw_samples)
    if len(samples) != len(requests):
        raise ValueError("worker sample count mismatch")
    provider_id = record_data.get("provider_id")
    if provider_id is not None and not isinstance(provider_id, str):
        raise ValueError("worker provider ID is invalid")
    if expected_provider_id is not None and provider_id not in (None, expected_provider_id):
        raise ValueError("worker provider ID mismatch")
    if not isinstance(record_data.get("summary"), dict) or set(record_data["summary"]) != set(
        SummaryRecord.__annotations__
    ):
        raise ValueError("worker summary shape mismatch")
    teardown_error = record_data.get("teardown_error_type")
    if teardown_error is not None and not isinstance(teardown_error, str):
        raise ValueError("worker teardown error is invalid")
    for index, (sample, request) in enumerate(zip(samples, requests, strict=True)):
        phase: Phase = "cold" if index == 0 else "warm"
        expected = _empty_sample(request, phase, "not_run")
        if not isinstance(sample, dict) or set(cast(dict[str, Any], sample)) != set(expected):
            raise ValueError("worker sample shape mismatch")
        sample = cast(dict[str, Any], sample)
        if any(
            sample[key] != expected[key] for key in ("phase", "request_sha256", "catalog_sha256")
        ):
            raise ValueError("worker sample input mismatch")
        if sample["status"] not in get_args(Status):
            raise ValueError("worker sample status is invalid")
        if sample["failure_type"] is not None and not isinstance(sample["failure_type"], str):
            raise ValueError("worker sample failure type is invalid")
        if sample["supplied_pages"] != expected["supplied_pages"]:
            raise ValueError("worker sample page count mismatch")
        for key in ("deadline_exceeded", "coverage_complete", "response_degraded"):
            if sample[key] is not None and not isinstance(sample[key], bool):
                raise ValueError("worker sample flag is invalid")
        for key in (
            "wall_ms",
            "owned_process_tree_cpu_seconds",
            "baseline_owned_process_tree_rss_bytes",
            "peak_owned_process_tree_rss_bytes",
            "final_owned_process_tree_rss_bytes",
        ):
            value = sample[key]
            if value is not None and (
                not isinstance(value, (int, float))
                or isinstance(value, bool)
                or not math.isfinite(value)
                or value < 0
            ):
                raise ValueError("worker sample measurement is invalid")
        for key in ("supplied_pages", "ranked_pages", "considered_evidence", "proposal_count"):
            if not isinstance(sample[key], int) or isinstance(sample[key], bool) or sample[key] < 0:
                raise ValueError("worker sample count is invalid")
        pages = request.attention_context or request.evidence_context
        expected_evidence = len({str(page.evidence_id) for page in pages})
        if (
            sample["ranked_pages"] > len(pages)
            or sample["considered_evidence"] > expected_evidence
            or sample["proposal_count"] > min(128, request.max_probes)
        ):
            raise ValueError("worker sample count exceeds request")
        wall_ms = sample["wall_ms"]
        if sample["deadline_exceeded"] != (wall_ms > deadline_ms if wall_ms is not None else None):
            raise ValueError("worker sample deadline flag mismatch")
        if attention_required:
            if sample["coverage_complete"] is True and (
                sample["ranked_pages"] != len(pages)
                or sample["considered_evidence"] != expected_evidence
            ):
                raise ValueError("worker sample coverage count mismatch")
            if sample["status"] == "coverage_failure" and sample["coverage_complete"] is not False:
                raise ValueError("worker sample coverage status mismatch")
        elif sample["coverage_complete"] is not None:
            raise ValueError("worker sample unexpected coverage flag")
        if sample["status"] == "complete" and (
            wall_ms is None
            or sample["deadline_exceeded"] is not False
            or sample["response_degraded"] is not False
            or sample["failure_type"] is not None
            or (attention_required and sample["coverage_complete"] is not True)
        ):
            raise ValueError("worker sample success is unsupported")
    typed_samples = cast(list[SampleRecord], samples)
    if (
        expected_provider_id is not None
        and any(sample["status"] == "complete" for sample in typed_samples)
        and provider_id != expected_provider_id
    ):
        raise ValueError("complete worker sample lacks expected provider ID")
    if record_data.get("summary") != _summary(typed_samples):
        raise ValueError("worker summary mismatch")
    return cast(IsolatedProviderRecord, record)


def compare_fast_brains_isolated(
    request_paths: tuple[Path, ...],
    *,
    deadline_ms: float = 3_000,
    worker_timeout_ms: float = 30_000,
    redaction_attested: bool = False,
    allow_cpu_laya: bool = False,
    laya_profile: Path | None = None,
) -> IsolatedComparisonReport:
    """Profile whitelisted providers in separate, time-bounded processes."""
    if not redaction_attested:
        raise ValueError("redaction attestation is required for profiling")
    if os.name != "nt":
        raise RuntimeError("isolated profiling requires Windows Job Object custody")
    if allow_cpu_laya != (laya_profile is not None):
        raise ValueError("CPU Laya requires both explicit flags")
    if not 0 < deadline_ms <= 180_000 or not 0 < worker_timeout_ms <= 600_000:
        raise ValueError("invalid call deadline or worker timeout")
    requests = _read_requests(request_paths)
    if len(requests) < 3 or len(set(map(request_sha256, requests[1:]))) < 2:
        raise ValueError("at least two distinct warm requests are required")
    if any(len(request.attention_context or request.evidence_context) > 64 for request in requests):
        raise ValueError("attention comparisons require at most 64 pages per request")
    expected_requests = tuple(request_sha256(request) for request in requests)
    expected_catalogs = tuple(catalog_sha256(request) for request in requests)
    providers: dict[str, IsolatedProviderRecord] = {}
    plans = _plans(allow_cpu_laya=allow_cpu_laya, laya_profile=laya_profile)
    for plan in plans:
        command = [
            sys.executable,
            "-m",
            "benchmarks.laptop_fast_brain",
            "--_worker-provider",
            plan.name,
            "--redaction-attested",
            "--deadline-ms",
            str(deadline_ms),
        ]
        for path in request_paths:
            command.extend(("--request-json", str(path.resolve())))
        if plan.cpu_laya:
            assert laya_profile is not None
            command.extend(("--allow-cpu-laya", "--laya-profile", str(laya_profile.resolve())))
        try:
            output, pid, exit_code, verified_pid = _supervise_worker(
                tuple(command),
                timeout_seconds=worker_timeout_ms / 1_000,
                verify_handshake=True,
            )
        except WorkerTimeout as error:
            providers[plan.name] = _failed_worker_record(
                requests, "worker_timeout", error.pid, "WorkerTimeout", cleanup_confirmed=True
            )
            continue
        except WorkerCleanupError as error:
            providers[plan.name] = _failed_worker_record(
                requests,
                "worker_error",
                error.pid,
                "WorkerCleanupUnconfirmed",
                cleanup_confirmed=False,
                cleanup_alive_pids=error.alive_pids,
                cleanup_error_type=error.failure_type,
            )
            break
        except WorkerProtocolError as error:
            providers[plan.name] = _failed_worker_record(
                requests, "worker_error", error.pid, "WorkerProtocolError", cleanup_confirmed=True
            )
            continue
        except WorkerOutputLimit as error:
            providers[plan.name] = _failed_worker_record(
                requests, "worker_error", error.pid, "WorkerOutputLimit", cleanup_confirmed=True
            )
            continue
        except WorkerOutputDecodeError as error:
            providers[plan.name] = _failed_worker_record(
                requests,
                "worker_error",
                error.pid,
                "WorkerOutputDecodeError",
                cleanup_confirmed=True,
            )
            continue
        if exit_code != 0:
            providers[plan.name] = _failed_worker_record(
                requests, "worker_error", pid, "WorkerExit"
            )
            continue
        try:
            payload = json.loads(output)
            record = _validate_worker_record(
                payload["record"],
                requests,
                plan.expected_provider_id,
                plan.attention_required,
                deadline_ms,
            )
            worker_pid = payload["worker_pid"]
            if worker_pid != verified_pid:
                raise ValueError("worker PID does not match verified live worker")
            if tuple(record["request_hashes"]) != expected_requests:
                raise InputMismatch("worker request hashes mismatch")
            if tuple(record["catalog_hashes"]) != expected_catalogs:
                raise InputMismatch("worker catalog hashes mismatch")
            if len(record["samples"]) != len(requests):
                raise ValueError("worker request count mismatch")
        except InputMismatch:
            raise
        except (KeyError, TypeError, ValueError, json.JSONDecodeError):
            providers[plan.name] = _failed_worker_record(
                requests, "worker_error", pid, "InvalidWorkerReport"
            )
            continue
        record["worker_pid"] = worker_pid
        record["worker_cleanup_confirmed"] = True
        record["worker_cleanup_alive_pids"] = ()
        record["worker_cleanup_error_type"] = None
        providers[plan.name] = record
    for plan in plans:
        if plan.name not in providers:
            providers[plan.name] = _failed_worker_record(
                requests, "not_run", None, "PreviousWorkerCleanupUnconfirmed"
            )
    return {
        "schema_version": 3,
        "classification": "isolated_same_request_cpu_component_profile_only",
        "redaction_attestation": "caller_attested_not_verified",
        "ordinary_laptop_qualified": False,
        "diagnostic_quality_measured": False,
        "resource_scope": "sampled_worker_tree_windows_job_custody_sequential",
        "providers": providers,
        "limitations": (
            "Each provider runs in a fresh Windows Job Object, but sequential runs "
            "retain host-state order effects.",
            "Only the provider component is timed; collection, diagnosis, repair, "
            "and power are excluded.",
            "A caller attests redaction; input privacy is not independently verified.",
            "A request or catalog hash mismatch invalidates the comparison and emits no report.",
            f"Worker stdout is capped at {_MAX_WORKER_OUTPUT_CHARS} characters; "
            "over-limit output fails every request for that worker.",
            "Resource readings sample worker process trees, not Job Object counters; "
            "ten-millisecond sampling can miss transient child memory and CPU use.",
            "A timed-out worker loses per-call detail; all its requests remain failed "
            "in the denominator. Failed Job Object cleanup stops later providers.",
            "Job custody covers assigned processes and ordinary CreateProcess children; "
            "Win32_Process.Create is outside that inheritance rule.",
            "No held-out diagnostic outcomes, workload interference, or hardware "
            "diversity are measured.",
        ),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request-json", type=Path, action="append", required=True)
    parser.add_argument("--redaction-attested", action="store_true")
    parser.add_argument("--deadline-ms", type=float, default=3_000)
    parser.add_argument("--worker-timeout-ms", type=float, default=30_000)
    parser.add_argument("--isolated-processes", action="store_true")
    parser.add_argument(
        "--_worker-provider",
        choices=("keyword", "typed-feature", "cpu-laya"),
        help=argparse.SUPPRESS,
    )
    parser.add_argument("--allow-cpu-laya", action="store_true")
    parser.add_argument("--laya-profile", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if not args.redaction_attested:
        parser.error("--redaction-attested is required for caller-supplied requests")
    if args.allow_cpu_laya != (args.laya_profile is not None):
        parser.error("CPU Laya requires both --allow-cpu-laya and --laya-profile")
    if args.output is None and args._worker_provider is None:
        parser.error("--output is required")
    if args.output is not None and args.output.exists():
        parser.error("--output must name a new file")
    if args._worker_provider is not None and args.isolated_processes:
        parser.error("worker and supervisor modes are mutually exclusive")
    if args.isolated_processes:
        report: ComparisonReport | IsolatedComparisonReport = compare_fast_brains_isolated(
            tuple(args.request_json),
            deadline_ms=args.deadline_ms,
            worker_timeout_ms=args.worker_timeout_ms,
            redaction_attested=True,
            allow_cpu_laya=args.allow_cpu_laya,
            laya_profile=args.laya_profile,
        )
    else:
        requests = _read_requests(tuple(args.request_json))
        plans = _plans(allow_cpu_laya=args.allow_cpu_laya, laya_profile=args.laya_profile)
        if args._worker_provider is not None:
            matching = tuple(plan for plan in plans if plan.name == args._worker_provider)
            if not matching:
                parser.error("CPU Laya worker requires explicit CPU Laya flags")
            print(json.dumps({"worker_pid": os.getpid()}), flush=True)
            if sys.stdin.readline() != "go\n":
                raise ValueError("worker handshake was not released")
            worker_report = compare_fast_brains(
                requests, matching, deadline_ms=args.deadline_ms, redaction_attested=True
            )
            print(
                json.dumps(
                    {
                        "worker_pid": os.getpid(),
                        "record": worker_report["providers"][matching[0].name],
                    }
                )
            )
            return
        report = compare_fast_brains(
            requests, plans, deadline_ms=args.deadline_ms, redaction_attested=True
        )
    assert args.output is not None
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
    print(json.dumps({"output": str(args.output), "classification": report["classification"]}))


if __name__ == "__main__":
    main()
