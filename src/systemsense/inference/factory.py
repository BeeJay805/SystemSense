"""Provider construction with deterministic no-inference defaults."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Literal, Protocol

from systemsense.decision.baseline import KeywordBaselineDecisionProvider
from systemsense.decision.laya import LayaDecisionProvider
from systemsense.decision.ollama import OllamaDecisionProvider
from systemsense.decision.provider import FastDecisionProvider
from systemsense.decision.typed_ranker import TypedFeatureDecisionProvider
from systemsense.inference.laya_runtime import (
    LayaRanker,
    LayaRuntimeConfig,
    LayaRuntimeError,
    LayaSubprocessRuntime,
)
from systemsense.inference.ollama import JsonTransport, LocalInferenceError, OllamaPreloadResult
from systemsense.inference.settings import LocalInferenceConfig
from systemsense.knowledge import ReferenceKnowledgeGraph
from systemsense.reasoning.deterministic import DeterministicReasoningProvider
from systemsense.reasoning.ollama import OllamaReasoningProvider
from systemsense.reasoning.provider import ReasoningProvider


class LayaRuntimeResource(LayaRanker, Protocol):
    def close(self) -> None: ...

    def prewarm(self, *, timeout_seconds: float) -> None: ...


@dataclass(slots=True)
class AdvisoryProviders:
    decision: FastDecisionProvider
    reasoning: ReasoningProvider
    knowledge: ReferenceKnowledgeGraph
    _close_runtime: Callable[[], None] | None = field(default=None, repr=False)
    _laya_runtime: LayaRuntimeResource | None = field(default=None, repr=False)
    _ollama_reasoner: OllamaReasoningProvider | None = field(default=None, repr=False)
    _closed: bool = field(default=False, init=False, repr=False)

    def prewarm_laya(self, *, timeout_seconds: float) -> None:
        if self._closed or self._laya_runtime is None:
            raise LayaRuntimeError("Laya prewarm requires an active configured local runtime")
        self._laya_runtime.prewarm(timeout_seconds=timeout_seconds)

    def prewarm_reasoning(self, *, timeout_seconds: float) -> OllamaPreloadResult:
        if self._closed or self._ollama_reasoner is None:
            raise LocalInferenceError("reasoning prewarm requires an active configured local model")
        return self._ollama_reasoner.prewarm(timeout_seconds=timeout_seconds)

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
    fast_provider: Literal["configured", "typed-feature"] = "configured",
    laya_timeout_seconds: float = 60,
    laya_runtime_factory: Callable[[LayaRuntimeConfig], LayaRuntimeResource] = (
        LayaSubprocessRuntime
    ),
    knowledge: ReferenceKnowledgeGraph | None = None,
) -> AdvisoryProviders:
    decision: FastDecisionProvider = KeywordBaselineDecisionProvider()
    reasoning: ReasoningProvider = DeterministicReasoningProvider()
    runtime: LayaRuntimeResource | None = None
    if fast_provider == "typed-feature":
        if not config.enabled or laya_config is not None or config.decision_model is not None:
            raise ValueError(
                "typed-feature requires enabled inference without another fast provider"
            )
        if config.reasoning_model is None or config.reasoning_digest is None:
            raise ValueError("typed-feature requires a pinned local reasoner")
        decision = TypedFeatureDecisionProvider()
    elif config.enabled and laya_config is not None:
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
        _laya_runtime=runtime,
        _ollama_reasoner=(reasoning if isinstance(reasoning, OllamaReasoningProvider) else None),
    )


def create_providers(
    config: LocalInferenceConfig, *, transport: JsonTransport | None = None
) -> tuple[FastDecisionProvider, ReasoningProvider]:
    providers = load_advisory_providers(config, transport=transport)
    return providers.decision, providers.reasoning
