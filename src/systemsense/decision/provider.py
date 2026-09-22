"""Provider protocols for replaceable fast decision implementations."""

from typing import Protocol

from systemsense.decision.contracts import DecisionRequest, DecisionResponse, ProviderIdentity


class FastDecisionProvider(Protocol):
    @property
    def identity(self) -> ProviderIdentity: ...

    def decide(self, request: DecisionRequest) -> DecisionResponse: ...
