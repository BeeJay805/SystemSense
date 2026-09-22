"""Typed reasoning-provider contracts and deterministic degraded behavior."""

from systemsense.reasoning.contracts import (
    Hypothesis,
    HypothesisStatus,
    ReasoningRequest,
    ReasoningResponse,
    ReasoningStatus,
    ReasoningValidationError,
)
from systemsense.reasoning.deterministic import DeterministicReasoningProvider
from systemsense.reasoning.ollama import OllamaReasoningProvider
from systemsense.reasoning.provider import ReasoningProvider
from systemsense.reasoning.unavailable import UnavailableReasoningProvider

__all__ = [
    "DeterministicReasoningProvider",
    "Hypothesis",
    "HypothesisStatus",
    "OllamaReasoningProvider",
    "ReasoningProvider",
    "ReasoningRequest",
    "ReasoningResponse",
    "ReasoningStatus",
    "ReasoningValidationError",
    "UnavailableReasoningProvider",
]
