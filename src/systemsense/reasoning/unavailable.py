"""Deterministic degraded reasoning provider with no network behavior."""

from systemsense.decision.contracts import ProviderIdentity
from systemsense.reasoning.contracts import (
    ReasoningRequest,
    ReasoningResponse,
    ReasoningStatus,
)


class UnavailableReasoningProvider:
    @property
    def identity(self) -> ProviderIdentity:
        return ProviderIdentity(
            provider_id="reasoning-unavailable",
            provider_version="1",
            role="reasoning",
        )

    def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
        response = ReasoningResponse(
            provider=self.identity,
            case_id=request.case_id,
            state_version=request.state_version,
            correlation_id=request.correlation_id,
            deadline_at=request.deadline_at,
            status=ReasoningStatus.UNAVAILABLE,
            summary="No reasoning provider is available; no diagnosis was produced.",
            degraded=True,
        )
        return response.validate_against(request)
