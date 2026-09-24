"""Provider construction with deterministic no-inference defaults."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Literal, Protocol

from systemsense.decision.baseline import KeywordBaselineDecisionProvider
from systemsense.decision.catalog_attention import (
    CatalogAttentionProvider,
    CatalogMetadataRanker,
    LayaCatalogAttentionProvider,
)
from systemsense.decision.frontier_ranker import MixedFrontierRanker
from systemsense.decision.laya import LayaDecisionProvider
from systemsense.decision.ollama import OllamaDecisionProvider
from systemsense.decision.provider import FastDecisionProvider
from systemsense.decision.typed_ranker import TypedFeatureDecisionProvider
from systemsense.inference.laya_runtime import (
    LAYA_MODEL_WEIGHT_SHA256,
    LayaRanker,
    LayaRuntimeConfig,
    LayaRuntimeError,
    LayaSubprocessRuntime,
)
from systemsense.inference.managed_laya import ManagedLayaAdmission
from systemsense.inference.ollama import JsonTransport, LocalInferenceError, OllamaPreloadResult
from systemsense.inference.profile import InferenceExecutionPolicy, LocalInferenceProfile
from systemsense.inference.settings import LocalInferenceConfig
from systemsense.inference.tree_host_lease import TreeHostInferenceLeaseLedger
from systemsense.knowledge import ReferenceKnowledgeGraph
from systemsense.reasoning.deterministic import DeterministicReasoningProvider
from systemsense.reasoning.ollama import OllamaReasoningProvider
from systemsense.reasoning.provider import ReasoningProvider

if TYPE_CHECKING:
    from systemsense.inference.sequential_providers import SequentialAdvisoryRuntime


class LayaRuntimeResource(LayaRanker, CatalogMetadataRanker, Protocol):
    def close(self) -> None: ...

    def prewarm(self, *, timeout_seconds: float) -> None: ...


@dataclass(slots=True)
class AdvisoryProviders:
    decision: FastDecisionProvider
    reasoning: ReasoningProvider
    knowledge: ReferenceKnowledgeGraph
    catalog_attention: CatalogAttentionProvider | None = None
    frontier_ranker: MixedFrontierRanker | None = None
    configured_mode: str = "deterministic"
    effective_mode: str = "deterministic"
    degradation_reason: str | None = None
    _close_runtime: Callable[[], None] | None = field(default=None, repr=False)
    _laya_runtime: LayaRuntimeResource | None = field(default=None, repr=False)
    _ollama_reasoner: OllamaReasoningProvider | None = field(default=None, repr=False)
    _managed_admission: ManagedLayaAdmission | None = field(default=None, repr=False)
    _sequential_runtime: SequentialAdvisoryRuntime | None = field(default=None, repr=False)
    _reasoning_digest: str | None = field(default=None, repr=False)
    _close_timeout_seconds: float = field(default=30.0, repr=False)
    _closed: bool = field(default=False, init=False, repr=False)

    def runtime_status(self) -> dict[str, object]:
        """Report constructed roles and the managed worker's current state."""

        result: dict[str, object] = {
            "configured_mode": self.configured_mode,
            "effective_mode": self.effective_mode,
            "degradation_reason": self.degradation_reason,
            "reasoning_provider": (
                "ollama" if self._ollama_reasoner is not None else "deterministic"
            ),
            "decision_provider": (
                "laya"
                if isinstance(self.decision, LayaDecisionProvider)
                else "typed-feature"
                if isinstance(self.decision, TypedFeatureDecisionProvider)
                else "deterministic"
                if isinstance(self.decision, KeywordBaselineDecisionProvider)
                else "other"
            ),
            "neural_reasoning_status": (
                "not_checked" if self._ollama_reasoner is not None else "disabled"
            ),
            "concurrent_neural_brains": False,
        }
        if self._managed_admission is not None:
            status = self._managed_admission.status
            result["decision_status"] = {
                "unattached": "not_started",
                "ready": "not_started",
                "leased": "admitted_not_proven",
                "closing": "degraded",
                "quarantined": "quarantined",
                "closed": "closed",
            }[status.phase]
            result["decision_detail"] = status.reason
            if status.phase in ("closing", "quarantined"):
                result["degradation_reason"] = status.reason
        if self._sequential_runtime is not None:
            status = self._sequential_runtime.status
            fast_phase, fast_reason = self._sequential_runtime.role_status("fast")
            deep_phase, deep_reason = self._sequential_runtime.role_status("deep")
            result["active_role"] = status.active_role
            result["queued_fast"] = status.queued_fast
            result["queued_deep"] = status.queued_deep
            result["decision_status"] = fast_phase
            result["decision_detail"] = fast_reason
            result["neural_reasoning_status"] = deep_phase
            result["reasoning_detail"] = deep_reason
            result["reasoning_digest"] = self._reasoning_digest
            if status.quarantined_reason:
                result["degradation_reason"] = status.quarantined_reason
                result["coordinator_status"] = "quarantined"
        return result

    def prewarm_laya(self, *, timeout_seconds: float) -> None:
        if self._sequential_runtime is not None and not self._closed:
            self._sequential_runtime.ranker.prewarm(timeout_seconds=timeout_seconds)
            return
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
        if self._sequential_runtime is not None:
            self._closed = self._sequential_runtime.close(
                deadline_at=time.monotonic() + self._close_timeout_seconds
            )
            return
        if self._managed_admission is not None:
            status = self._managed_admission.close()
            self._closed = status.phase == "closed"
            return
        if self._close_runtime is not None:
            self._close_runtime()
        self._closed = True


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
    execution_policy: InferenceExecutionPolicy | None = None,
    managed_admission: ManagedLayaAdmission | None = None,
) -> AdvisoryProviders:
    if execution_policy is not None and execution_policy.managed_gpu:
        resources = execution_policy.managed_resources
        if (
            execution_policy.effective_mode != "managed-laya-cuda"
            or execution_policy.decision_provider != "laya"
            or execution_policy.reasoning_provider != "deterministic"
            or resources is None
            or managed_admission is None
            or laya_config is None
            or laya_config.device != "cuda"
            or laya_config.cuda_device_index != resources.gpu_device_index
            or config.enabled
            or config.allow_gpu
            or config.reasoning_model is not None
            or config.decision_model is not None
        ):
            raise ValueError("managed CUDA policy cannot start unowned model providers")
        admission_policy = managed_admission.policy
        if (
            admission_policy.gpu_device_index != resources.gpu_device_index
            or admission_policy.gpu_uuid != resources.gpu_uuid
            or admission_policy.peak_ram_bytes != resources.peak_ram_bytes
            or admission_policy.peak_vram_bytes != resources.peak_vram_bytes
            or admission_policy.ram_reserve_bytes != resources.ram_reserve_bytes
            or admission_policy.target_vram_reserve_bytes != resources.target_vram_reserve_bytes
            or admission_policy.max_telemetry_age_ms != resources.max_telemetry_age_ms
            or admission_policy.renew_interval_seconds != resources.renew_interval_seconds
        ):
            raise ValueError("managed CUDA controller differs from pinned profile")
        laya_config.validate_install()
        managed_runtime = LayaSubprocessRuntime(
            laya_config,
            startup_admission=managed_admission.startup_admission,
            call_admission=managed_admission.call_admission,
        )
        managed_admission.attach_runtime(managed_runtime)

        def close_managed() -> None:
            managed_admission.close()

        managed_decision = LayaDecisionProvider(
            ranker=managed_runtime,
            timeout_seconds=laya_timeout_seconds,
        )
        return AdvisoryProviders(
            decision=managed_decision,
            reasoning=DeterministicReasoningProvider(),
            knowledge=knowledge or ReferenceKnowledgeGraph.load_default(),
            catalog_attention=LayaCatalogAttentionProvider(
                ranker=managed_runtime,
                timeout_seconds=min(1.5, laya_timeout_seconds),
                max_candidates_per_batch=laya_config.max_candidates_per_batch,
            ),
            frontier_ranker=MixedFrontierRanker(
                ranker=managed_runtime,
                provider=managed_decision.identity,
                model_weight_sha256=LAYA_MODEL_WEIGHT_SHA256,
            ),
            configured_mode=execution_policy.configured_mode,
            effective_mode=execution_policy.effective_mode,
            _close_runtime=close_managed,
            _laya_runtime=managed_runtime,
            _managed_admission=managed_admission,
        )
    if managed_admission is not None:
        raise ValueError("managed controller requires a managed execution policy")
    if execution_policy is not None and execution_policy.effective_mode == "deterministic":
        return AdvisoryProviders(
            decision=KeywordBaselineDecisionProvider(),
            reasoning=DeterministicReasoningProvider(),
            knowledge=knowledge or ReferenceKnowledgeGraph.load_default(),
            configured_mode=execution_policy.configured_mode,
            effective_mode="deterministic",
            degradation_reason=execution_policy.degradation_reason,
        )
    if (
        execution_policy is not None
        and execution_policy.effective_mode == "typed-feature-deterministic"
    ):
        if (
            execution_policy.decision_provider != "typed-feature"
            or execution_policy.reasoning_provider != "deterministic"
            or execution_policy.managed_gpu
            or laya_config is not None
            or config.enabled
            or config.allow_gpu
            or config.reasoning_model is not None
            or config.decision_model is not None
        ):
            raise ValueError("typed-feature deterministic policy is inconsistent")
        return AdvisoryProviders(
            decision=TypedFeatureDecisionProvider(),
            reasoning=DeterministicReasoningProvider(),
            knowledge=knowledge or ReferenceKnowledgeGraph.load_default(),
            configured_mode=execution_policy.configured_mode,
            effective_mode=execution_policy.effective_mode,
        )
    if execution_policy is not None and execution_policy.effective_mode == "managed-laya-cuda":
        raise ValueError("managed CUDA policy is missing its controller")
    if config.allow_gpu or (laya_config is not None and laya_config.device == "cuda"):
        return AdvisoryProviders(
            decision=KeywordBaselineDecisionProvider(),
            reasoning=DeterministicReasoningProvider(),
            knowledge=knowledge or ReferenceKnowledgeGraph.load_default(),
            configured_mode="legacy_gpu_requested",
            effective_mode="deterministic",
            degradation_reason="legacy_gpu_profile_requires_v3",
        )
    decision: FastDecisionProvider = KeywordBaselineDecisionProvider()
    reasoning: ReasoningProvider = DeterministicReasoningProvider()
    runtime: LayaRuntimeResource | None = None
    catalog_attention: CatalogAttentionProvider | None = None
    frontier_ranker: MixedFrontierRanker | None = None
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
        catalog_attention = LayaCatalogAttentionProvider(
            ranker=runtime,
            timeout_seconds=min(1.5, laya_timeout_seconds),
            max_candidates_per_batch=laya_config.max_candidates_per_batch,
        )
        frontier_ranker = MixedFrontierRanker(
            ranker=runtime,
            provider=decision.identity,
            model_weight_sha256=LAYA_MODEL_WEIGHT_SHA256,
        )
    elif config.enabled and config.decision_model is not None:
        decision = OllamaDecisionProvider(config, transport=transport)
    if config.enabled and config.reasoning_model is not None:
        reasoning = OllamaReasoningProvider(config, transport=transport)
    configured_mode = (
        execution_policy.configured_mode
        if execution_policy is not None
        else "local-dual-brain"
        if runtime is not None and isinstance(reasoning, OllamaReasoningProvider)
        else "local-reasoner"
        if isinstance(reasoning, OllamaReasoningProvider)
        else "local-fast"
        if runtime is not None or isinstance(decision, TypedFeatureDecisionProvider)
        else "deterministic"
    )
    return AdvisoryProviders(
        decision=decision,
        reasoning=reasoning,
        knowledge=knowledge or ReferenceKnowledgeGraph.load_default(),
        catalog_attention=catalog_attention,
        frontier_ranker=frontier_ranker,
        configured_mode=configured_mode,
        effective_mode=configured_mode,
        _close_runtime=None if runtime is None else runtime.close,
        _laya_runtime=runtime,
        _ollama_reasoner=(reasoning if isinstance(reasoning, OllamaReasoningProvider) else None),
    )


def load_sequential_v4_providers(
    profile: LocalInferenceProfile,
    ledger: TreeHostInferenceLeaseLedger,
    *,
    knowledge: ReferenceKnowledgeGraph | None = None,
) -> AdvisoryProviders:
    """Construct an inactive v4 composite on one supplied tree-lease ledger.

    This is an explicit opt-in factory. The existing profile resolution keeps
    v4 deterministic until a caller deliberately chooses this path.
    """

    from systemsense.inference.sequential_providers import (
        SequentialAdvisoryRuntime,
        build_deep_session,
        build_fast_session,
        reasoning_config,
    )

    if profile.schema_version != 4:
        raise ValueError("sequential v4 requires a validated profile and tree-lease ledger")
    resources = profile.managed_resources
    pin = profile.managed_reasoning
    if resources is None or pin is None or resources.gpu_device_index != pin.gpu_device_index:
        raise ValueError("sequential v4 role resources do not share one pinned GPU")
    # Revalidate caller-supplied model instances; model_copy can bypass validators.
    profile = LocalInferenceProfile.model_validate(profile.model_dump(mode="json"))
    runtime = SequentialAdvisoryRuntime(
        fast_factory=lambda: build_fast_session(profile, ledger),
        deep_factory=lambda: build_deep_session(profile, ledger),
        reasoning_config=reasoning_config(profile),
    )
    config = reasoning_config(profile)
    decision = LayaDecisionProvider(
        ranker=runtime.ranker, timeout_seconds=profile.laya.timeout_seconds
    )
    reasoner = OllamaReasoningProvider(config, client=runtime.client)
    return AdvisoryProviders(
        decision=decision,
        reasoning=reasoner,
        knowledge=knowledge or ReferenceKnowledgeGraph.load_default(),
        catalog_attention=LayaCatalogAttentionProvider(
            ranker=runtime.ranker,
            timeout_seconds=min(1.5, profile.laya.timeout_seconds),
            max_candidates_per_batch=profile.laya.max_candidates_per_batch,
        ),
        frontier_ranker=MixedFrontierRanker(
            ranker=runtime.ranker,
            provider=decision.identity,
            model_weight_sha256=LAYA_MODEL_WEIGHT_SHA256,
        ),
        configured_mode="managed-local-sequential",
        effective_mode="managed-local-sequential",
        _ollama_reasoner=reasoner,
        _sequential_runtime=runtime,
        _reasoning_digest=pin.model_digest,
        _close_timeout_seconds=profile.investigation_budget_ms / 1000,
    )


def create_providers(
    config: LocalInferenceConfig, *, transport: JsonTransport | None = None
) -> tuple[FastDecisionProvider, ReasoningProvider]:
    providers = load_advisory_providers(config, transport=transport)
    return providers.decision, providers.reasoning
