"""Transparent provider call/failure measurement wrappers."""

from __future__ import annotations

from systemsense.decision.contracts import DecisionRequest, DecisionResponse, ProviderIdentity
from systemsense.decision.provider import FastDecisionProvider
from systemsense.evaluation.models import ProviderMeasurement
from systemsense.reasoning.contracts import ReasoningRequest, ReasoningResponse
from systemsense.reasoning.provider import ReasoningProvider


class TrackedDecisionProvider:
    def __init__(self, provider: FastDecisionProvider, *, model_id: str | None = None) -> None:
        self._provider = provider
        self._model_id = model_id
        self._calls = 0
        self._failures = 0

    @property
    def identity(self) -> ProviderIdentity:
        return self._provider.identity

    def decide(self, request: DecisionRequest) -> DecisionResponse:
        self._calls += 1
        try:
            response = self._provider.decide(request).validate_against(request)
        except Exception:
            self._failures += 1
            raise
        if response.degraded:
            self._failures += 1
        return response

    def measurement(self) -> ProviderMeasurement:
        return ProviderMeasurement(
            role="decision",
            provider_id=self.identity.provider_id,
            model_id=self._model_id,
            calls=self._calls,
            failures=self._failures,
        )


class TrackedReasoningProvider:
    def __init__(self, provider: ReasoningProvider, *, model_id: str | None = None) -> None:
        self._provider = provider
        self._model_id = model_id
        self._calls = 0
        self._failures = 0

    @property
    def identity(self) -> ProviderIdentity:
        return self._provider.identity

    def investigate(self, request: ReasoningRequest) -> ReasoningResponse:
        self._calls += 1
        try:
            response = self._provider.investigate(request).validate_against(request)
        except Exception:
            self._failures += 1
            raise
        if response.degraded:
            self._failures += 1
        return response

    def measurement(self) -> ProviderMeasurement:
        return ProviderMeasurement(
            role="reasoning",
            provider_id=self.identity.provider_id,
            model_id=self._model_id,
            calls=self._calls,
            failures=self._failures,
        )
