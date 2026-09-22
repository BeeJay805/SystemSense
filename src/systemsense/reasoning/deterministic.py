"""Reviewed deterministic reasoning rules that never infer an unobserved cause."""

from systemsense.decision.contracts import ProviderIdentity
from systemsense.domain.ids import JsonValue
from systemsense.inference.context import EvidenceContextStatus
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
        response = ReasoningResponse(
            provider=self.identity,
            case_id=request.case_id,
            state_version=request.state_version,
            correlation_id=request.correlation_id,
            deadline_at=request.deadline_at,
            status=status,
            summary="The cause remains unknown; only reviewed observation rules were applied.",
            hypotheses=tuple(hypotheses),
        )
        return response.validate_against(request)


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
