"""CPU-side timing of an injected fast-decision provider on frozen requests.

This is a component profiler, not a diagnostic benchmark or laptop-qualification
test. It starts no model, collector, GPU worker, or network client. A caller who
injects a provider remains responsible for that provider's own side effects.
Timeouts are soft: a synchronous provider cannot be interrupted safely here.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import time
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal

import psutil

from systemsense.application.bootstrap import default_capabilities
from systemsense.decision.baseline import KeywordBaselineDecisionProvider
from systemsense.decision.contracts import (
    DecisionRequest,
    DecisionResponse,
    ProbeCapability,
    ProviderIdentity,
)
from systemsense.decision.provider import FastDecisionProvider
from systemsense.decision.typed_ranker import TypedFeatureDecisionProvider
from systemsense.domain.ids import CaseId, EvidenceId
from systemsense.inference.context import EvidenceContext, EvidenceContextStatus
from systemsense.orchestration.scheduler import ResourceClass

CallPhase = Literal["cold", "warm"]
CallStatus = Literal["valid", "invalid_response", "timeout", "error"]


@dataclass(frozen=True, slots=True)
class CallSample:
    phase: CallPhase
    request_index: int
    request_sha256: str
    catalog_sha256: str
    status: CallStatus
    wall_ms: float
    process_rss_before_bytes: int
    process_rss_after_bytes: int
    error_type: str | None = None


@dataclass(frozen=True, slots=True)
class PhaseSummary:
    attempts: int
    valid_responses: int
    invalid_responses: int
    timeouts: int
    errors: int
    wall_p50_ms: float | None
    wall_p95_ms: float | None
    max_sampled_process_rss_bytes: int | None


@dataclass(frozen=True, slots=True)
class DecisionProviderProfile:
    schema_version: Literal[1]
    measurement_scope: Literal["provider_component_only"]
    workload_kind: Literal[
        "caller_supplied_frozen_requests",
        "synthetic_contract_smoke",
        "synthetic_broad_contract_smoke",
    ]
    diagnostic_quality_measured: Literal[False]
    provider: ProviderIdentity
    request_hashes: tuple[str, ...]
    catalog_hashes: tuple[str, ...]
    calls: tuple[CallSample, ...]
    cold: PhaseSummary
    warm: PhaseSummary
    limitations: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        payload = asdict(self)
        payload["provider"] = self.provider.model_dump(mode="json")
        return payload


def _canonical_request_json(request: DecisionRequest) -> str:
    payload = request.model_dump(mode="json")
    payload["target_traits"] = sorted(request.target_traits)
    payload["fresh_probe_ids"] = sorted(request.fresh_probe_ids)
    payload["completed_probe_ids"] = sorted(request.completed_probe_ids)
    for serialized, capability in zip(
        payload["available_probes"], request.available_probes, strict=True
    ):
        serialized["keywords"] = sorted(capability.keywords)
        serialized["target_traits"] = sorted(capability.target_traits)
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False
    )


def request_sha256(request: DecisionRequest) -> str:
    """Hash the complete typed request with unordered term sets normalized."""
    return hashlib.sha256(_canonical_request_json(request).encode("utf-8")).hexdigest()


def catalog_sha256(request: DecisionRequest) -> str:
    """Pin the ordered, complete provider-visible probe capability catalog."""
    payload = [
        {
            **capability.model_dump(mode="json"),
            "keywords": sorted(capability.keywords),
            "target_traits": sorted(capability.target_traits),
        }
        for capability in request.available_probes
    ]
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _nearest_rank(values: list[float], quantile: float) -> float | None:
    if not values:
        return None
    return sorted(values)[math.ceil(quantile * len(values)) - 1]


def _summary(samples: tuple[CallSample, ...]) -> PhaseSummary:
    rss = [
        value
        for sample in samples
        for value in (sample.process_rss_before_bytes, sample.process_rss_after_bytes)
    ]
    walls = [sample.wall_ms for sample in samples]
    return PhaseSummary(
        attempts=len(samples),
        valid_responses=sum(sample.status == "valid" for sample in samples),
        invalid_responses=sum(sample.status == "invalid_response" for sample in samples),
        timeouts=sum(sample.status == "timeout" for sample in samples),
        errors=sum(sample.status == "error" for sample in samples),
        wall_p50_ms=_nearest_rank(walls, 0.5),
        wall_p95_ms=_nearest_rank(walls, 0.95),
        max_sampled_process_rss_bytes=max(rss) if rss else None,
    )


def profile_decision_provider(
    provider: FastDecisionProvider,
    fixtures: tuple[DecisionRequest, ...],
    *,
    warm_repeats: int = 3,
    soft_timeout_ms: int | None = None,
    workload_kind: Literal[
        "caller_supplied_frozen_requests",
        "synthetic_contract_smoke",
        "synthetic_broad_contract_smoke",
    ] = "caller_supplied_frozen_requests",
) -> DecisionProviderProfile:
    """Call an existing provider once cold, then each frozen fixture per warm repeat.

    Timings include provider.decide only; RSS is this process sampled before and
    after each call, not a transient peak or a model-server process tree.
    """
    if not fixtures:
        raise ValueError("at least one frozen DecisionRequest fixture is required")
    if warm_repeats < 0:
        raise ValueError("warm_repeats must be nonnegative")
    if soft_timeout_ms is not None and soft_timeout_ms <= 0:
        raise ValueError("soft_timeout_ms must be positive")

    serialized = tuple(_canonical_request_json(request) for request in fixtures)
    hashes = tuple(hashlib.sha256(item.encode("utf-8")).hexdigest() for item in serialized)
    catalog_hashes = tuple(catalog_sha256(request) for request in fixtures)
    process = psutil.Process()
    samples: list[CallSample] = []

    def sample(phase: CallPhase, index: int) -> None:
        request = DecisionRequest.model_validate_json(serialized[index])
        before_rss = int(process.memory_info().rss)
        started_ns = time.perf_counter_ns()
        response: DecisionResponse | None = None
        raised: Exception | None = None
        try:
            response = provider.decide(request)
        except Exception as error:  # A failed call is still one measured attempt.
            raised = error
        wall_ms = (time.perf_counter_ns() - started_ns) / 1_000_000
        after_rss = int(process.memory_info().rss)

        status: CallStatus = "valid"
        error_type: str | None = None
        if isinstance(raised, TimeoutError):
            status, error_type = "timeout", type(raised).__name__
        elif raised is not None:
            status, error_type = "error", type(raised).__name__
        elif not isinstance(response, DecisionResponse):
            status, error_type = "invalid_response", "UnexpectedResponseType"
        else:
            try:
                validated = DecisionResponse.model_validate(
                    response.model_dump(mode="python", warnings="error")
                )
                validated.validate_against(request)
                if validated.provider != provider.identity:
                    raise ValueError("response provider identity differs from injected provider")
                if request_sha256(request) != hashes[index]:
                    raise ValueError("provider mutated the frozen request")
            except Exception as error:
                status, error_type = "invalid_response", type(error).__name__
        if status == "valid" and soft_timeout_ms is not None and wall_ms > soft_timeout_ms:
            status, error_type = "timeout", "SoftTimeout"
        samples.append(
            CallSample(
                phase=phase,
                request_index=index,
                request_sha256=hashes[index],
                catalog_sha256=catalog_hashes[index],
                status=status,
                wall_ms=wall_ms,
                process_rss_before_bytes=before_rss,
                process_rss_after_bytes=after_rss,
                error_type=error_type,
            )
        )

    sample("cold", 0)
    for _ in range(warm_repeats):
        for index in range(len(fixtures)):
            sample("warm", index)
    calls = tuple(samples)
    return DecisionProviderProfile(
        schema_version=1,
        measurement_scope="provider_component_only",
        workload_kind=workload_kind,
        diagnostic_quality_measured=False,
        provider=provider.identity,
        request_hashes=hashes,
        catalog_hashes=catalog_hashes,
        calls=calls,
        cold=_summary(tuple(call for call in calls if call.phase == "cold")),
        warm=_summary(tuple(call for call in calls if call.phase == "warm")),
        limitations=(
            "This times provider.decide only, not collection, scheduling, diagnosis, or repair.",
            "Cold is the first decide call on fixture zero after provider construction/import; "
            "warm aggregates all supplied fixtures, so use one fixture for matched cold/warm "
            "input.",
            "Process RSS is sampled before and after calls; transient peaks and external model "
            "servers are excluded.",
            "Soft timeouts label completed slow calls but cannot interrupt a hung synchronous "
            "provider.",
            "The harness does not constrain side effects of a caller-injected provider.",
            "No diagnostic quality or ordinary-laptop suitability is measured.",
        ),
    )


def demo_keyword_profile(*, warm_repeats: int = 3) -> DecisionProviderProfile:
    """Default smoke demonstration; no local model is loaded or contacted."""
    request = DecisionRequest(
        case_id=CaseId(root="case_" + "0" * 32),
        state_version=1,
        correlation_id="keyword_profile_demo",
        deadline_at=datetime(2100, 1, 1, tzinfo=UTC),
        symptom="Synthetic network symptom for timing only",
        available_probes=(
            ProbeCapability(
                probe_id="network.snapshot",
                description="Registered read-only network snapshot",
                keywords=frozenset({"network"}),
                cost_ms=10,
                resource_class=ResourceClass.NETWORK,
            ),
        ),
        budget_ms=100,
        max_probes=1,
    )
    return profile_decision_provider(
        KeywordBaselineDecisionProvider(),
        (request,),
        warm_repeats=warm_repeats,
        workload_kind="synthetic_contract_smoke",
    )


def synthetic_broad_request() -> DecisionRequest:
    """Fixed, synthetic 54-preview input over the registered 17-probe catalog.

    This does not collect or imply any real host measurements. It measures only
    how a provider handles a broad typed request shape.
    """
    capabilities = default_capabilities()
    snapshot_time = datetime(2026, 9, 22, 12, tzinfo=UTC)
    evidence_ids = tuple(EvidenceId(root=f"ev_{index:032x}") for index in range(54))
    statuses = (
        EvidenceContextStatus.OBSERVED,
        EvidenceContextStatus.PARTIAL,
        EvidenceContextStatus.UNAVAILABLE,
    )
    previews = tuple(
        EvidenceContext(
            evidence_id=evidence_ids[index],
            observed_at=snapshot_time + timedelta(seconds=index),
            captured_at=snapshot_time + timedelta(seconds=index),
            probe_id=capabilities[index % len(capabilities)].probe_id,
            summary="Synthetic bounded preview for provider timing; not a host observation.",
            facts={"synthetic.preview_index": index, "synthetic.fixture": "not_host_data"},
            status=statuses[index % len(statuses)],
        )
        for index in range(54)
    )
    return DecisionRequest(
        case_id=CaseId(root="case_" + "2" * 32),
        state_version=1,
        correlation_id="synthetic_broad_profile",
        deadline_at=datetime(2100, 1, 1, tzinfo=UTC),
        symptom="Synthetic Wi-Fi, PDF, printing, and game performance problem for timing only",
        evidence_ids=evidence_ids,
        evidence_context=previews,
        available_probes=capabilities,
        budget_ms=60_000,
        max_probes=8,
    )


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--request-json", type=Path, action="append", default=[])
    parser.add_argument("--synthetic-broad", action="store_true")
    parser.add_argument("--provider", choices=("keyword", "typed-feature"), default="keyword")
    parser.add_argument("--warm-repeats", type=int, default=3)
    args = parser.parse_args()
    provider: FastDecisionProvider = (
        TypedFeatureDecisionProvider()
        if args.provider == "typed-feature"
        else KeywordBaselineDecisionProvider()
    )
    if args.synthetic_broad and args.request_json:
        parser.error("--synthetic-broad cannot be combined with --request-json")
    if args.synthetic_broad:
        report = profile_decision_provider(
            provider,
            (synthetic_broad_request(),),
            warm_repeats=args.warm_repeats,
            workload_kind="synthetic_broad_contract_smoke",
        )
    elif args.request_json:
        fixtures = tuple(
            DecisionRequest.model_validate_json(path.read_text(encoding="utf-8"))
            for path in args.request_json
        )
        report = profile_decision_provider(provider, fixtures, warm_repeats=args.warm_repeats)
    else:
        if args.provider != "keyword":
            parser.error("--provider typed-feature requires at least one --request-json fixture")
        report = demo_keyword_profile(warm_repeats=args.warm_repeats)
    print(json.dumps(report.to_dict(), sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
