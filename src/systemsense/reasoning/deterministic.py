"""Reviewed deterministic reasoning rules that never infer an unobserved cause."""

from systemsense.decision.contracts import ProviderIdentity
from systemsense.domain.affected_task import LOOPBACK_TASK_SCOPES
from systemsense.domain.ids import JsonValue
from systemsense.domain.time import utc_now
from systemsense.inference.context import EvidenceContextStatus
from systemsense.reasoning.connectivity import assess_connectivity
from systemsense.reasoning.contracts import (
    Hypothesis,
    HypothesisStatus,
    ReasoningRequest,
    ReasoningResponse,
    ReasoningStatus,
)


class DeterministicReasoningProvider:
    """Describe evidence limitations and possible contribution without causal claims."""

    @property
    def identity(self) -> ProviderIdentity:
        return ProviderIdentity(
            provider_id="deterministic-reasoning",
            provider_version="1",
            role="reasoning",
        )

    def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
        limited = tuple(
            context.evidence_id
            for context in request.evidence_context
            if context.status
            in {
                EvidenceContextStatus.PARTIAL,
                EvidenceContextStatus.MISSING,
                EvidenceContextStatus.UNAVAILABLE,
                EvidenceContextStatus.DENIED,
                EvidenceContextStatus.STALE,
                EvidenceContextStatus.TRUNCATED,
                EvidenceContextStatus.FAILED,
                EvidenceContextStatus.UNSUPPORTED,
            }
        )
        hypotheses: list[Hypothesis] = []
        observed_context = tuple(
            context
            for context in request.evidence_context
            if context.status is EvidenceContextStatus.OBSERVED
        )
        memory_pressure = tuple(
            context.evidence_id
            for context in observed_context
            if _memory_percent(context.facts) >= 90
        )
        if memory_pressure:
            hypotheses.append(
                Hypothesis(
                    hypothesis_id="h_memory_pressure_observed",
                    statement=(
                        "Memory use at or above 90% was observed; whether it contributed remains "
                        "unresolved."
                    ),
                    status=HypothesisStatus.UNRESOLVED,
                    supporting_evidence_ids=memory_pressure,
                )
            )
        pending_restart = tuple(
            context.evidence_id for context in observed_context if _pending_restart(context.facts)
        )
        if pending_restart:
            hypotheses.append(
                Hypothesis(
                    hypothesis_id="h_pending_restart_observed",
                    statement=(
                        "A pending restart was observed; whether it contributed remains unresolved."
                    ),
                    status=HypothesisStatus.UNRESOLVED,
                    supporting_evidence_ids=pending_restart,
                )
            )
        device_problem = tuple(
            context.evidence_id
            for context in observed_context
            if _has_device_problem(context.facts)
        )
        if device_problem:
            hypotheses.append(
                Hypothesis(
                    hypothesis_id="h_device_problem_reported",
                    statement=(
                        "One or more devices reported nonzero problem codes; relevance remains "
                        "unresolved."
                    ),
                    status=HypothesisStatus.UNRESOLVED,
                    supporting_evidence_ids=device_problem,
                )
            )
        connectivity_hypotheses, connectivity_notes = assess_connectivity(request, now=utc_now())
        hypotheses.extend(connectivity_hypotheses)
        if limited:
            hypotheses.append(
                Hypothesis(
                    hypothesis_id="h_observability_gap",
                    statement=(
                        "Evidence availability limits may prevent the current observations from "
                        "distinguishing explanations."
                    ),
                    status=HypothesisStatus.UNRESOLVED,
                    supporting_evidence_ids=limited,
                )
            )

        status = (
            ReasoningStatus.UNRESOLVED
            if observed_context
            else ReasoningStatus.INSUFFICIENT_OBSERVABILITY
        )
        task_summary = _loopback_task_summary(request)
        response = ReasoningResponse(
            provider=self.identity,
            case_id=request.case_id,
            state_version=request.state_version,
            correlation_id=request.correlation_id,
            deadline_at=request.deadline_at,
            status=status,
            summary=task_summary
            or "The cause remains unknown; only reviewed observation rules were applied.",
            hypotheses=tuple(hypotheses),
            considered_evidence_ids=(
                (request.task_observation.evidence_id,)
                if task_summary is not None and request.task_observation is not None
                else ()
            ),
            context_notes=connectivity_notes,
        )
        return response.validate_against(request)


def _loopback_task_summary(request: ReasoningRequest) -> str | None:
    task = request.task_observation
    if (
        task is None
        or task.scope not in LOOPBACK_TASK_SCOPES
        or task.reported_task_relation != "exact_action_replayed"
        or task.collector_id != "task.loopback_http"
    ):
        return None
    result = {
        "http_200_nonce_match": (
            "Exact local health GET returned HTTP 200 with the matching nonce. "
            "No failure was reproduced in this replay; the earlier report's cause "
            "remains unverified. If it fails again, record the failure time and "
            "repeat this exact check."
        ),
        "http_503": (
            "Exact local health GET returned HTTP 503. The endpoint answered, but "
            "its application-internal reason remains unknown. Inspect the service's "
            "request logs for this health path at the GET time."
        ),
        "wrong_response": (
            "Exact local health GET returned HTTP 200, but its body did not match "
            "the expected nonce. The reason remains unknown. Inspect how the health "
            "endpoint generates its nonce response."
        ),
        "timeout": (
            "Exact local health GET timed out. Whether a listener was absent or a "
            "handler stalled during the request remains unknown; the cause is unresolved. "
            "Check listener state at the failure time, then inspect the handler if it "
            "is listening."
        ),
        "connection_refused": (
            "Exact local health GET was refused. Its request-time cause remains unknown. "
            "Check whether the service was listening on that port at the failure time."
        ),
    }.get(task.observed)
    if result is not None:
        return result
    return (
        f"Exact local health GET ended in {task.observed}; the request-time cause remains unknown."
    )


def _memory_percent(facts: dict[str, JsonValue]) -> float:
    direct = facts.get("resources.memory.percent")
    if isinstance(direct, int | float) and not isinstance(direct, bool):
        return float(direct)
    resources = facts.get("resources")
    if not isinstance(resources, dict):
        return 0
    memory = resources.get("memory")
    if not isinstance(memory, dict):
        return 0
    percent = memory.get("percent")
    if isinstance(percent, int | float) and not isinstance(percent, bool):
        return float(percent)
    return 0


def _pending_restart(facts: dict[str, JsonValue]) -> bool:
    direct = facts.get("reboot.pending")
    if isinstance(direct, bool):
        return direct
    observation = facts.get("reboot_pending")
    if isinstance(observation, dict) and observation.get("pending") is True:
        return True
    worker_observation = facts.get("reboot")
    return isinstance(worker_observation, dict) and worker_observation.get("pending") is True


def _has_device_problem(facts: dict[str, JsonValue]) -> bool:
    devices = facts.get("devices")
    if isinstance(devices, list):
        for device in devices:
            if not isinstance(device, dict):
                continue
            code = device.get("problem_code")
            if isinstance(code, int) and not isinstance(code, bool) and code > 0:
                return True
        return False
    codes = facts.get("devices.problem_codes")
    if not isinstance(codes, list):
        return False
    for code in codes:
        if isinstance(code, int) and not isinstance(code, bool) and code > 0:
            return True
    return False
