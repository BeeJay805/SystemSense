"""Provider protocol for local or future advisory reasoning implementations."""

from typing import Protocol

from systemsense.decision.contracts import ProviderIdentity
from systemsense.reasoning.contracts import ReasoningRequest, ReasoningResponse


class ReasoningProvider(Protocol):
    @property
    def identity(self) -> ProviderIdentity: ...

    def investigate(self, request: ReasoningRequest) -> ReasoningResponse: ...
