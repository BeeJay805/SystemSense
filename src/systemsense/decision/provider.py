"""Provider protocols for replaceable fast decision implementations."""

from typing import Protocol, runtime_checkable

from systemsense.decision.candidates import (
    CandidateDecisionGapV1,
    CandidateDecisionRequestV1,
    CandidateDecisionResponseV1,
)
from systemsense.decision.contracts import DecisionRequest, DecisionResponse, ProviderIdentity


class FastDecisionProvider(Protocol):
    @property
    def identity(self) -> ProviderIdentity: ...

    def decide(self, request: DecisionRequest) -> DecisionResponse: ...


@runtime_checkable
class CandidateDecisionProvider(Protocol):
    """Replaceable advisory ranker for locally admitted candidate identities."""

    @property
    def identity(self) -> ProviderIdentity: ...

    def decide_candidates(
        self, request: CandidateDecisionRequestV1
    ) -> CandidateDecisionResponseV1 | CandidateDecisionGapV1: ...
