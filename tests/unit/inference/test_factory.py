from pathlib import Path

import pytest

from systemsense.decision.baseline import KeywordBaselineDecisionProvider
from systemsense.decision.catalog_attention import (
    DeterministicCatalogFallback,
    LayaCatalogAttentionProvider,
)
from systemsense.decision.laya import LayaDecisionProvider
from systemsense.decision.ollama import OllamaDecisionProvider
from systemsense.decision.typed_ranker import TypedFeatureDecisionProvider
from systemsense.inference.factory import load_advisory_providers
from systemsense.inference.laya_runtime import LayaAttentionResult, LayaRuntimeConfig
from systemsense.inference.ollama import OllamaPreloadResult
from systemsense.inference.settings import LocalInferenceConfig
from systemsense.knowledge import ReferenceKnowledgeGraph
from systemsense.reasoning.deterministic import DeterministicReasoningProvider
from systemsense.reasoning.ollama import OllamaReasoningProvider


def test_factory_defaults_do_not_enable_inference() -> None:
    providers = load_advisory_providers(LocalInferenceConfig())
    assert isinstance(providers.decision, KeywordBaselineDecisionProvider)
    assert isinstance(providers.reasoning, DeterministicReasoningProvider)
    assert providers.catalog_attention is None


def test_factory_loads_roles_independently() -> None:
    decision_only = load_advisory_providers(
        LocalInferenceConfig(enabled=True, decision_model="decision-local")
    )
    assert isinstance(decision_only.decision, OllamaDecisionProvider)
    assert isinstance(decision_only.reasoning, DeterministicReasoningProvider)

    reasoning_only = load_advisory_providers(
        LocalInferenceConfig(enabled=True, reasoning_model="reasoning-local")
    )
    assert isinstance(reasoning_only.decision, KeywordBaselineDecisionProvider)
    assert isinstance(reasoning_only.reasoning, OllamaReasoningProvider)


def test_typed_feature_mode_keeps_local_reasoner_without_laya_startup() -> None:
    def unexpected_runtime(_config: LayaRuntimeConfig) -> _ClosableRanker:
        raise AssertionError("Laya must not start")

    providers = load_advisory_providers(
        LocalInferenceConfig(
            enabled=True, reasoning_model="qwen3.8:27b", reasoning_digest="2" * 64
        ),
        fast_provider="typed-feature",
        laya_runtime_factory=unexpected_runtime,
    )
    assert isinstance(providers.decision, TypedFeatureDecisionProvider)
    assert isinstance(providers.reasoning, OllamaReasoningProvider)
    providers.close()


def test_typed_feature_mode_requires_pinned_local_reasoner() -> None:
    with pytest.raises(ValueError, match="pinned local reasoner"):
        load_advisory_providers(
            LocalInferenceConfig(enabled=True, reasoning_model="qwen3.8:27b"),
            fast_provider="typed-feature",
        )


class _ClosableRanker:
    def __init__(self, _config: LayaRuntimeConfig) -> None:
        self.close_calls = 0
        self.prewarm_calls: list[float] = []

    def prewarm(self, *, timeout_seconds: float) -> None:
        self.prewarm_calls.append(timeout_seconds)

    def close(self) -> None:
        self.close_calls += 1

    def rank(
        self,
        *,
        state: dict[str, object],
        candidates: tuple[dict[str, str], ...],
        timeout_seconds: float,
    ) -> tuple[str, ...]:
        del state, timeout_seconds
        return tuple(item["probe_id"] for item in candidates)

    def attend(
        self,
        *,
        state: dict[str, object],
        evidence: tuple[dict[str, str], ...],
        candidates: tuple[dict[str, str], ...],
        timeout_seconds: float,
    ) -> LayaAttentionResult:
        del state, evidence, timeout_seconds
        probe_ids = tuple(item["probe_id"] for item in candidates)
        return LayaAttentionResult(
            ranked_probe_ids=probe_ids,
            considered_probe_ids=probe_ids,
        )


def test_factory_uses_one_laya_runtime_and_knowledge_graph_then_closes_once(
    tmp_path: Path,
) -> None:
    interpreter = (tmp_path / "python.exe").resolve()
    model = (tmp_path / "model").resolve()
    laya = LayaRuntimeConfig(interpreter_path=interpreter, model_path=model, threads=2)
    runtimes: list[_ClosableRanker] = []

    def create_runtime(config: LayaRuntimeConfig) -> _ClosableRanker:
        runtime = _ClosableRanker(config)
        runtimes.append(runtime)
        return runtime

    knowledge = ReferenceKnowledgeGraph.load_default()
    providers = load_advisory_providers(
        LocalInferenceConfig(
            enabled=True,
            reasoning_model="qwen3.8:27b",
            reasoning_digest="2" * 64,
        ),
        laya_config=laya,
        laya_timeout_seconds=60,
        laya_runtime_factory=create_runtime,
        knowledge=knowledge,
    )

    assert isinstance(providers.decision, LayaDecisionProvider)
    assert isinstance(providers.catalog_attention, LayaCatalogAttentionProvider)
    assert isinstance(providers.reasoning, OllamaReasoningProvider)
    assert providers.knowledge is knowledge
    assert len(runtimes) == 1

    providers.prewarm_laya(timeout_seconds=12)
    assert runtimes[0].prewarm_calls == [12]

    calls: list[float] = []

    def preload_reasoning(*, timeout_seconds: float) -> OllamaPreloadResult:
        calls.append(timeout_seconds)
        return OllamaPreloadResult(
            status="ready",
            model="qwen3.8:27b",
            digest="2" * 64,
            keep_alive_seconds=90,
            reason=None,
        )

    assert isinstance(providers.reasoning, OllamaReasoningProvider)
    providers.reasoning.prewarm = preload_reasoning  # type: ignore[method-assign]
    assert providers.prewarm_reasoning(timeout_seconds=15).status == "ready"
    assert calls == [15]

    providers.close()
    providers.close()

    assert runtimes[0].close_calls == 1


def test_factory_forwards_configured_laya_batch_limit_to_catalog_attention(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import systemsense.inference.factory as factory_module

    laya = LayaRuntimeConfig(
        interpreter_path=(tmp_path / "python.exe").resolve(),
        model_path=(tmp_path / "model").resolve(),
        max_candidates_per_batch=4,
    )
    captured: dict[str, object] = {}
    runtimes: list[_ClosableRanker] = []

    def create_runtime(config: LayaRuntimeConfig) -> _ClosableRanker:
        runtime = _ClosableRanker(config)
        runtimes.append(runtime)
        return runtime

    def create_adapter(
        *, ranker: object, timeout_seconds: float, max_candidates_per_batch: int
    ) -> DeterministicCatalogFallback:
        captured.update(
            ranker=ranker,
            timeout_seconds=timeout_seconds,
            max_candidates_per_batch=max_candidates_per_batch,
        )
        return DeterministicCatalogFallback()

    monkeypatch.setattr(factory_module, "LayaCatalogAttentionProvider", create_adapter)
    providers = load_advisory_providers(
        LocalInferenceConfig(enabled=True),
        laya_config=laya,
        laya_timeout_seconds=5,
        laya_runtime_factory=create_runtime,
    )

    assert captured["ranker"] is runtimes[0]
    assert captured["timeout_seconds"] == 1.5
    assert captured["max_candidates_per_batch"] == 4
    providers.close()
