"""Provider construction with deterministic no-inference defaults."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

from systemsense.decision.baseline import KeywordBaselineDecisionProvider
from systemsense.decision.laya import LayaDecisionProvider
from systemsense.decision.ollama import OllamaDecisionProvider
from systemsense.decision.provider import FastDecisionProvider
from systemsense.inference.laya_runtime import (
    LayaRanker,
    LayaRuntimeConfig,
    LayaSubprocessRuntime,
)
from systemsense.inference.ollama import JsonTransport
from systemsense.inference.settings import LocalInferenceConfig
from systemsense.knowledge import ReferenceKnowledgeGraph
from systemsense.reasoning.deterministic import DeterministicReasoningProvider
from systemsense.reasoning.ollama import OllamaReasoningProvider
from systemsense.reasoning.provider import ReasoningProvider


class LayaRuntimeResource(LayaRanker, Protocol):
    def close(self) -> None: ...


@dataclass(slots=True)
class AdvisoryProviders:
    decision: FastDecisionProvider
    reasoning: ReasoningProvider
    knowledge: ReferenceKnowledgeGraph
    _close_runtime: Callable[[], None] | None = field(default=None, repr=False)
    _closed: bool = field(default=False, init=False, repr=False)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        if self._close_runtime is not None:
            self._close_runtime()


def load_advisory_providers(
    config: LocalInferenceConfig,
    *,
    transport: JsonTransport | None = None,
    laya_config: LayaRuntimeConfig | None = None,
    laya_timeout_seconds: float = 60,
    laya_runtime_factory: Callable[[LayaRuntimeConfig], LayaRuntimeResource] = (
        LayaSubprocessRuntime
    ),
    knowledge: ReferenceKnowledgeGraph | None = None,
) -> AdvisoryProviders:
    decision: FastDecisionProvider = KeywordBaselineDecisionProvider()
    reasoning: ReasoningProvider = DeterministicReasoningProvider()
    runtime: LayaRuntimeResource | None = None
    if config.enabled and laya_config is not None:
        runtime = laya_runtime_factory(laya_config)
        decision = LayaDecisionProvider(
            ranker=runtime,
            timeout_seconds=laya_timeout_seconds,
        )
    elif config.enabled and config.decision_model is not None:
        decision = OllamaDecisionProvider(config, transport=transport)
    if config.enabled and config.reasoning_model is not None:
        reasoning = OllamaReasoningProvider(config, transport=transport)
    return AdvisoryProviders(
        decision=decision,
        reasoning=reasoning,
        knowledge=knowledge or ReferenceKnowledgeGraph.load_default(),
        _close_runtime=None if runtime is None else runtime.close,
    )


def create_providers(
    config: LocalInferenceConfig, *, transport: JsonTransport | None = None
) -> tuple[FastDecisionProvider, ReasoningProvider]:
    providers = load_advisory_providers(config, transport=transport)
    return providers.decision, providers.reasoning
