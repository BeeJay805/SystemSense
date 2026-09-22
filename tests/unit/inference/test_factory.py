from pathlib import Path

from systemsense.decision.baseline import KeywordBaselineDecisionProvider
from systemsense.decision.laya import LayaDecisionProvider
from systemsense.decision.ollama import OllamaDecisionProvider
from systemsense.inference.factory import load_advisory_providers
from systemsense.inference.laya_runtime import LayaAttentionResult, LayaRuntimeConfig
from systemsense.inference.settings import LocalInferenceConfig
from systemsense.knowledge import ReferenceKnowledgeGraph
from systemsense.reasoning.deterministic import DeterministicReasoningProvider
from systemsense.reasoning.ollama import OllamaReasoningProvider


def test_factory_defaults_do_not_enable_inference() -> None:
    providers = load_advisory_providers(LocalInferenceConfig())
    assert isinstance(providers.decision, KeywordBaselineDecisionProvider)
    assert isinstance(providers.reasoning, DeterministicReasoningProvider)


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


class _ClosableRanker:
    def __init__(self, _config: LayaRuntimeConfig) -> None:
        self.close_calls = 0

    def close(self) -> None:
        self.close_calls += 1

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
    assert isinstance(providers.reasoning, OllamaReasoningProvider)
    assert providers.knowledge is knowledge
    assert len(runtimes) == 1

    providers.close()
    providers.close()

    assert runtimes[0].close_calls == 1
