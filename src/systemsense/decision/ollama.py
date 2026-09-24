"""Optional local Ollama provider for bounded probe-ranking advice."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import cast

from pydantic import Field, ValidationError

from systemsense.decision.baseline import KeywordBaselineDecisionProvider
from systemsense.decision.contracts import (
    DecisionRequest,
    DecisionResponse,
    DiagnosticPurpose,
    ProbeProposal,
    ProviderIdentity,
    ResponseValidationError,
)
from systemsense.domain.evidence import FrozenModel
from systemsense.inference.ollama import JsonTransport, LocalInferenceError, OllamaChatClient
from systemsense.inference.settings import LocalInferenceConfig, ProviderStatus


class _SuggestedProbe(FrozenModel):
    probe_id: str = Field(min_length=1, max_length=120, pattern=r"^[a-z][a-z0-9_.-]*$")
    purpose: DiagnosticPurpose
    priority: float = Field(ge=0, le=1)
    depends_on: tuple[str, ...] = Field(default=(), max_length=16)


class _DecisionAdvice(FrozenModel):
    proposals: tuple[_SuggestedProbe, ...] = Field(default=(), max_length=128)
    requires_reasoning: bool = False
    stop_reason: str | None = Field(default=None, max_length=120)


class OllamaDecisionProvider:
    """Ask a local model for references, then rebuild every trusted field locally."""

    def __init__(
        self,
        config: LocalInferenceConfig,
        *,
        transport: JsonTransport | None = None,
        fallback: KeywordBaselineDecisionProvider | None = None,
    ) -> None:
        if not config.enabled or config.decision_model is None:
            raise ValueError("Ollama decision provider requires explicit enablement and a model")
        self._config = config
        self._model = config.decision_model
        self._client = OllamaChatClient(config=config, transport=transport)
        self._fallback = fallback or KeywordBaselineDecisionProvider()
        self._status = ProviderStatus(
            provider_id="ollama-local-decision",
            enabled=True,
            available=False,
            detail="not_checked",
        )

    @property
    def identity(self) -> ProviderIdentity:
        return ProviderIdentity(
            provider_id="ollama-local-decision",
            provider_version="1",
            role="fast_decision",
        )

    @property
    def status(self) -> ProviderStatus:
        return self._status

    def decide(self, request: DecisionRequest) -> DecisionResponse:
        timeout = self._timeout_for(request)
        if timeout is None:
            return self._degraded(request, "inference_budget_unavailable")
        prompt = json.dumps(
            {
                "task": "Rank only registered probes relevant to the observations.",
                "diagnostic_progress": [
                    item.model_dump(mode="json") for item in request.diagnostic_progress
                ],
                "symptom": request.symptom,
                "target_traits": sorted(request.target_traits),
                "evidence": [
                    context.model_dump(mode="json") for context in request.evidence_context
                ],
                "relationships": [
                    relation.model_dump(mode="json") for relation in request.relationships
                ],
                "completed_probe_ids": sorted(request.completed_probe_ids),
                "available_probes": [
                    capability.model_dump(mode="json")
                    for capability in request.available_probes
                    if capability.probe_id not in request.completed_probe_ids
                ],
                "max_probes": request.max_probes,
                "budget_ms": request.budget_ms,
            },
            separators=(",", ":"),
        )
        try:
            raw = self._client.complete(
                model=self._model,
                prompt=prompt,
                schema=cast(dict[str, object], _DecisionAdvice.model_json_schema()),
                timeout_seconds=timeout,
            )
            advice = _DecisionAdvice.model_validate(raw)
            capabilities = {probe.probe_id: probe for probe in request.available_probes}
            proposals = tuple(
                ProbeProposal(
                    probe_id=suggestion.probe_id,
                    purpose=suggestion.purpose,
                    priority=suggestion.priority,
                    estimated_cost_ms=capabilities[suggestion.probe_id].cost_ms,
                    resource_class=capabilities[suggestion.probe_id].resource_class,
                    dedupe_key=f"{suggestion.probe_id}:model",
                    permission_class=capabilities[suggestion.probe_id].permission_class,
                    safety_class=capabilities[suggestion.probe_id].safety_class,
                    depends_on=suggestion.depends_on,
                )
                for suggestion in advice.proposals
            )
            response = DecisionResponse(
                provider=self.identity,
                case_id=request.case_id,
                state_version=request.state_version,
                correlation_id=request.correlation_id,
                deadline_at=request.deadline_at,
                proposals=proposals,
                requires_reasoning=advice.requires_reasoning,
                stop_reason=advice.stop_reason,
            ).validate_against(request)
        except (KeyError, LocalInferenceError, ResponseValidationError, ValidationError):
            return self._degraded(request, "local_inference_invalid_or_unavailable")
        self._status = self._status.model_copy(update={"available": True, "detail": "ready"})
        return response

    def _timeout_for(self, request: DecisionRequest) -> float | None:
        remaining = (request.deadline_at - datetime.now(UTC)).total_seconds()
        timeout = min(self._config.timeout_seconds, remaining)
        return timeout if timeout > 0 else None

    def _degraded(self, request: DecisionRequest, detail: str) -> DecisionResponse:
        self._status = self._status.model_copy(update={"available": False, "detail": detail})
        baseline = self._fallback.decide(request)
        return baseline.model_copy(
            update={"degraded": True, "stop_reason": detail}
        ).validate_against(request)
