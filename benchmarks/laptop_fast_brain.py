"""Opt-in, same-request CPU component profile for replaceable fast brains.

No provider is constructed at import time. The command-line path runs only the
deterministic providers unless both explicit CPU-Laya flags are supplied. This
does not measure diagnostic quality, power, or suitability for ordinary laptops.
Synchronous deadlines are soft; a blocking provider cannot be killed safely.
"""

from __future__ import annotations

import argparse
import json
import math
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Literal, TypedDict, cast

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


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request-json", type=Path, action="append", required=True)
    parser.add_argument("--redaction-attested", action="store_true")
    parser.add_argument("--deadline-ms", type=float, default=3_000)
    parser.add_argument("--allow-cpu-laya", action="store_true")
    parser.add_argument("--laya-profile", type=Path)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.redaction_attested:
        parser.error("--redaction-attested is required for caller-supplied requests")
    if args.allow_cpu_laya != (args.laya_profile is not None):
        parser.error("CPU Laya requires both --allow-cpu-laya and --laya-profile")
    if args.output.exists():
        parser.error("--output must name a new file")
    requests: list[DecisionRequest] = []
    for path in args.request_json:
        if path.stat().st_size > _MAX_INPUT_BYTES:
            parser.error("request JSON exceeds 1 MB")
        requests.append(DecisionRequest.model_validate_json(path.read_text(encoding="utf-8")))
    plans = [
        ProviderPlan("keyword", lambda: ProviderSession(KeywordBaselineDecisionProvider())),
        ProviderPlan(
            "typed-feature",
            lambda: ProviderSession(TypedFeatureDecisionProvider()),
            attention_required=True,
        ),
    ]
    if args.allow_cpu_laya:
        profile_path = args.laya_profile
        assert profile_path is not None
        plans.append(
            ProviderPlan(
                "cpu-laya",
                lambda: _laya_session(profile_path),
                attention_required=True,
                cpu_laya=True,
                fallback_identity=KeywordBaselineDecisionProvider().identity,
            )
        )
    report = compare_fast_brains(
        tuple(requests),
        tuple(plans),
        deadline_ms=args.deadline_ms,
        redaction_attested=True,
    )
    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("x", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2)
    print(json.dumps({"output": str(args.output), "classification": report["classification"]}))


if __name__ == "__main__":
    main()
