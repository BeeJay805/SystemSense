"""Persistent, explicit local dual-brain configuration with no installation side effects."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Literal, cast
from urllib.parse import urlsplit

from pydantic import Field, model_validator

from systemsense.domain.evidence import FrozenModel
from systemsense.inference.laya_runtime import LayaRuntimeConfig, LayaRuntimeError
from systemsense.inference.settings import LocalInferenceConfig

_MAX_PROFILE_BYTES = 65_536

ConfiguredMode = Literal[
    "deterministic",
    "local-dual-brain",
    "typed-feature-local-reasoner",
    "managed-laya-cuda",
    "typed-feature-deterministic",
    "managed-local-sequential",
    "managed-local-warm",
]
EffectiveMode = ConfiguredMode


class ManagedGpuResources(FrozenModel):
    """Explicit local admission budget for one CUDA worker; ledger path is app-owned."""

    gpu_device_index: int = Field(ge=0, le=15)
    gpu_uuid: str = Field(
        pattern=r"^GPU-[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
    )
    peak_ram_bytes: int = Field(default=2 * 1024**3, ge=2 * 1024**3, le=512 * 1024**3)
    peak_vram_bytes: int = Field(
        default=int(2.5 * 1024**3), ge=int(2.5 * 1024**3), le=512 * 1024**3
    )
    ram_reserve_bytes: int = Field(default=4 * 1024**3, ge=4 * 1024**3, le=512 * 1024**3)
    target_vram_reserve_bytes: int = Field(default=6 * 1024**3, ge=6 * 1024**3, le=512 * 1024**3)
    max_telemetry_age_ms: int = Field(default=2000, ge=100, le=2000)
    renew_interval_seconds: float = Field(default=1.0, ge=0.01, le=30)


class InferenceExecutionPolicy(FrozenModel):
    """Resolved authority to start advisory providers, separate from configuration intent."""

    configured_mode: ConfiguredMode
    effective_mode: EffectiveMode
    degradation_reason: str | None = None
    decision_provider: Literal["deterministic", "laya", "typed-feature"]
    reasoning_provider: Literal["deterministic", "ollama"]
    managed_gpu: bool = False
    managed_resources: ManagedGpuResources | None = None


class DisabledReasoningReference(FrozenModel):
    """Historical model pin for human review; this shape has no activation flag."""

    model: str = Field(min_length=1, max_length=120)
    digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    endpoint: str

    @model_validator(mode="after")
    def validate_local_reference(self) -> DisabledReasoningReference:
        LocalInferenceConfig.model_validate(
            {
                "reasoning_model": self.model,
                "reasoning_digest": self.digest,
                "endpoint": self.endpoint,
            }
        )
        return self


class ManagedReasoningProfile(FrozenModel):
    """Pinned, dedicated Ollama service intent; this does not authorize startup."""

    executable: Path
    executable_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    models_dir: Path
    endpoint: str
    model: str = Field(min_length=1, max_length=120)
    model_digest: str = Field(pattern=r"^[0-9a-f]{64}$")
    gpu_device_index: int = Field(ge=0, le=15)
    peak_ram_bytes: int = Field(ge=1024**3, le=512 * 1024**3)
    peak_vram_bytes: int = Field(ge=1024**3, le=512 * 1024**3)
    ram_reserve_bytes: int = Field(ge=1024**3, le=512 * 1024**3)
    target_vram_reserve_bytes: int = Field(ge=1024**3, le=512 * 1024**3)
    context_tokens: int = Field(ge=2048, le=32768)
    output_tokens: int = Field(ge=128, le=4096)
    startup_timeout_seconds: float = Field(gt=0, le=30)
    call_timeout_seconds: float = Field(gt=0, le=180)
    idle_timeout_seconds: float = Field(gt=0, le=300)
    exit_timeout_seconds: float = Field(gt=0, le=30)

    @model_validator(mode="after")
    def validate_owned_service(self) -> ManagedReasoningProfile:
        LocalInferenceConfig.model_validate(
            {
                "endpoint": self.endpoint,
                "reasoning_model": self.model,
                "reasoning_digest": self.model_digest,
            }
        )
        parsed = urlsplit(self.endpoint)
        if parsed.port == 11434:
            raise ValueError("v4 requires a dedicated Ollama endpoint, not the shared default port")
        for label, path in (("executable", self.executable), ("models_dir", self.models_dir)):
            if not path.is_absolute() or path.resolve() != path:
                raise ValueError(f"v4 {label} must be a canonical absolute path")
        if not self.executable.is_file() or not self.models_dir.is_dir():
            raise ValueError("v4 dedicated Ollama executable or models directory is unavailable")
        if self.models_dir == self.executable.parent:
            raise ValueError("v4 models directory must be separate from the executable directory")
        if self.output_tokens >= self.context_tokens:
            raise ValueError("v4 output budget must be smaller than context budget")
        return self


class LayaProfile(FrozenModel):
    enabled: bool = False
    interpreter_path: Path | None = None
    model_path: Path | None = None
    device: Literal["cpu", "cuda"] = "cpu"
    precision: Literal["float32", "float16"] = "float32"
    cuda_device_index: int = Field(default=0, ge=0, le=15)
    min_free_vram_mb: int = Field(default=2048, ge=1024, le=16_384)
    threads: int = Field(default=2, ge=1, le=4)
    max_candidates_per_batch: int = Field(default=4, ge=1, le=20)
    timeout_seconds: float = Field(default=60, gt=0, le=180)

    def runtime_config(self) -> LayaRuntimeConfig:
        if not self.enabled or self.interpreter_path is None or self.model_path is None:
            raise ValueError("Laya is not enabled with complete local paths")
        return LayaRuntimeConfig(
            interpreter_path=self.interpreter_path,
            model_path=self.model_path,
            device=self.device,
            precision=self.precision,
            cuda_device_index=self.cuda_device_index,
            min_free_vram_mb=self.min_free_vram_mb,
            threads=self.threads,
            max_candidates_per_batch=self.max_candidates_per_batch,
        )


class LocalInferenceProfile(FrozenModel):
    """Versioned local-only profile loaded once for one CLI invocation."""

    schema_version: Literal[1, 2, 3, 4] = 1
    decision_provider: Literal["laya", "typed-feature"] = "laya"
    reasoning_provider: Literal["ollama", "deterministic"] = "ollama"
    profile_id: str = Field(
        default="deterministic-default",
        pattern=r"^[a-z][a-z0-9_.-]*$",
        max_length=80,
    )
    investigation_budget_ms: int = Field(default=30_000, ge=100, le=600_000)
    inference: LocalInferenceConfig = Field(default_factory=LocalInferenceConfig)
    laya: LayaProfile = Field(default_factory=LayaProfile)
    managed_resources: ManagedGpuResources | None = None
    managed_reasoning: ManagedReasoningProfile | None = None
    runtime_strategy: Literal["disabled", "sequential", "warm-independent"] = "disabled"
    gpu_total_vram_bytes: int | None = Field(default=None, ge=1024**3, le=512 * 1024**3)
    review_only_reasoning: DisabledReasoningReference | None = None

    @model_validator(mode="after")
    def validate_dual_brain(self) -> LocalInferenceProfile:
        if self.schema_version == 1 and self.decision_provider != "laya":
            raise ValueError("typed-feature decision provider requires schema_version 2")
        if self.schema_version == 4:
            if self.decision_provider != "laya" or self.reasoning_provider != "ollama":
                raise ValueError("v4 requires managed Laya and owned Ollama roles")
            if (
                self.inference.enabled
                or self.inference.allow_gpu
                or any(
                    value is not None
                    for value in (
                        self.inference.decision_model,
                        self.inference.reasoning_model,
                        self.inference.reasoning_digest,
                    )
                )
            ):
                raise ValueError("v4 prohibits unmanaged inference configuration")
            if self.review_only_reasoning is not None:
                raise ValueError("v4 requires an active managed reasoning pin")
            if self.managed_resources is None or self.managed_reasoning is None:
                raise ValueError("v4 requires pinned resources for both managed roles")
            if self.runtime_strategy == "warm-independent":
                if self.gpu_total_vram_bytes is None:
                    raise ValueError("warm profile requires pinned GPU VRAM capacity")
                combined = (
                    self.managed_resources.peak_vram_bytes
                    + self.managed_reasoning.peak_vram_bytes
                    + max(
                        self.managed_resources.target_vram_reserve_bytes,
                        self.managed_reasoning.target_vram_reserve_bytes,
                    )
                )
                if combined > self.gpu_total_vram_bytes:
                    raise ValueError("combined warm VRAM peaks and reserve exceed GPU capacity")
            if not self.laya.enabled or self.laya.device != "cuda":
                raise ValueError("v4 requires enabled CUDA Laya")
            if (
                self.laya.cuda_device_index != self.managed_resources.gpu_device_index
                or self.managed_reasoning.gpu_device_index
                != self.managed_resources.gpu_device_index
            ):
                raise ValueError("v4 GPU index must match across both managed roles")
            try:
                self.laya.runtime_config().validate_install()
            except (ValueError, LayaRuntimeError) as error:
                raise ValueError(f"v4 managed Laya install is incomplete: {error}") from error
            return self
        if self.runtime_strategy != "disabled" or self.gpu_total_vram_bytes is not None:
            raise ValueError("runtime strategy and GPU capacity require schema_version 4")
        if self.managed_reasoning is not None:
            raise ValueError("managed reasoning requires schema_version 4")
        if self.schema_version == 3:
            if self.reasoning_provider != "deterministic":
                raise ValueError("v3 requires deterministic reasoning provider")
            if self.inference.enabled or self.inference.allow_gpu:
                raise ValueError("v3 prohibits Ollama and unmanaged GPU inference")
            if (
                self.inference.reasoning_model is not None
                or self.inference.reasoning_digest is not None
            ):
                raise ValueError("v3 active inference cannot retain a reasoning model pin")
            if self.inference.decision_model is not None:
                raise ValueError("v3 active inference cannot retain a decision model pin")
            if self.decision_provider == "typed-feature":
                if self.laya.enabled:
                    raise ValueError("v3 typed-feature provider requires Laya disabled")
                if self.managed_resources is not None:
                    raise ValueError("v3 typed-feature provider cannot reserve managed resources")
                return self
            if not self.laya.enabled:
                raise ValueError("v3 managed Laya requires an enabled install")
            if self.laya.device != "cuda":
                raise ValueError("v3 managed Laya requires CUDA device")
            if self.managed_resources is None:
                raise ValueError("v3 managed Laya requires pinned managed resources")
            if self.managed_resources.gpu_device_index != self.laya.cuda_device_index:
                raise ValueError("v3 managed GPU index must match Laya CUDA index")
            try:
                self.laya.runtime_config().validate_install()
            except (ValueError, LayaRuntimeError) as error:
                raise ValueError(f"v3 managed Laya install is incomplete: {error}") from error
            return self
        if self.reasoning_provider != "ollama":
            raise ValueError("deterministic reasoning provider requires schema_version 3")
        if self.managed_resources is not None:
            raise ValueError("managed resources require schema_version 3")
        if self.review_only_reasoning is not None:
            raise ValueError("review-only reasoning reference requires schema_version 3")
        if not self.inference.enabled:
            if self.laya.enabled or self.decision_provider != "laya":
                raise ValueError(
                    "fast provider cannot be enabled while local inference is disabled"
                )
            return self
        if self.inference.reasoning_model is None:
            raise ValueError("enabled profile requires a pinned reasoning model")
        if self.inference.reasoning_digest is None:
            raise ValueError("enabled profile requires a reasoning model digest")
        if self.inference.decision_model is not None:
            raise ValueError("decision_model is ambiguous with the selected fast provider")
        if self.decision_provider == "typed-feature":
            if self.laya.enabled:
                raise ValueError("Laya must be disabled for the typed-feature decision provider")
            return self
        if not self.laya.enabled:
            raise ValueError("enabled profile requires the local Laya decision runtime")
        try:
            self.laya.runtime_config().validate_install()
        except (ValueError, LayaRuntimeError) as error:
            raise ValueError(f"Laya local install is incomplete or unadmitted: {error}") from error
        return self

    def resolved_execution_policy(self) -> InferenceExecutionPolicy:
        """Fail closed for legacy GPU requests; v3 never starts an Ollama reasoner."""

        if self.schema_version == 4:
            if self.runtime_strategy != "disabled":
                warm = self.runtime_strategy == "warm-independent"
                mode: ConfiguredMode = "managed-local-warm" if warm else "managed-local-sequential"
                return InferenceExecutionPolicy(
                    configured_mode=mode,
                    effective_mode=mode,
                    decision_provider="laya",
                    reasoning_provider="ollama",
                    managed_gpu=True,
                    managed_resources=self.managed_resources,
                )
            return InferenceExecutionPolicy(
                configured_mode="managed-local-sequential",
                effective_mode="deterministic",
                degradation_reason="joint_runtime_not_activated",
                decision_provider="deterministic",
                reasoning_provider="deterministic",
            )
        if self.schema_version == 3:
            if self.decision_provider == "laya":
                return InferenceExecutionPolicy(
                    configured_mode="managed-laya-cuda",
                    effective_mode="managed-laya-cuda",
                    decision_provider="laya",
                    reasoning_provider="deterministic",
                    managed_gpu=True,
                    managed_resources=self.managed_resources,
                )
            return InferenceExecutionPolicy(
                configured_mode="typed-feature-deterministic",
                effective_mode="typed-feature-deterministic",
                decision_provider="typed-feature",
                reasoning_provider="deterministic",
            )
        configured_mode: ConfiguredMode = "deterministic"
        if self.inference.enabled:
            configured_mode = (
                "typed-feature-local-reasoner"
                if self.decision_provider == "typed-feature"
                else "local-dual-brain"
            )
        if self.inference.allow_gpu or self.laya.device == "cuda":
            return InferenceExecutionPolicy(
                configured_mode=configured_mode,
                effective_mode="deterministic",
                degradation_reason="legacy_gpu_profile_requires_v3",
                decision_provider="deterministic",
                reasoning_provider="deterministic",
            )
        if not self.inference.enabled:
            return InferenceExecutionPolicy(
                configured_mode="deterministic",
                effective_mode="deterministic",
                decision_provider="deterministic",
                reasoning_provider="deterministic",
            )
        return InferenceExecutionPolicy(
            configured_mode=configured_mode,
            effective_mode=configured_mode,
            decision_provider=self.decision_provider,
            reasoning_provider="ollama",
        )

    def inference_status(self) -> dict[str, object]:
        policy = self.resolved_execution_policy()
        if policy.effective_mode == "deterministic":
            return {
                "enabled": False,
                "mode": "deterministic",
                "configured_mode": policy.configured_mode,
                "effective_mode": policy.effective_mode,
                "degradation_reason": policy.degradation_reason,
                "profile_id": self.profile_id,
            }
        if self.schema_version == 4:
            assert self.managed_reasoning is not None
            return {
                "enabled": True,
                "mode": policy.effective_mode,
                "configured_mode": policy.configured_mode,
                "effective_mode": policy.effective_mode,
                "degradation_reason": None,
                "profile_id": self.profile_id,
                "decision_provider": "laya",
                "decision_model": "laya-typed-decisions",
                "decision_device": self.laya.device,
                "decision_status": "not_started",
                "reasoning_provider": "ollama",
                "reasoning_model": self.managed_reasoning.model,
                "reasoning_digest": self.managed_reasoning.model_digest,
                "reasoning_status": "not_started",
                "endpoint": self.managed_reasoning.endpoint,
            }
        if self.schema_version == 3:
            status: dict[str, object] = {
                "enabled": True,
                "mode": policy.effective_mode,
                "configured_mode": policy.configured_mode,
                "effective_mode": policy.effective_mode,
                "degradation_reason": policy.degradation_reason,
                "profile_id": self.profile_id,
                "decision_provider": self.decision_provider,
                "reasoning_provider": "deterministic",
                "decision_status": "not_checked",
            }
            if self.decision_provider == "laya":
                status["decision_model"] = "laya-typed-decisions"
                status["decision_device"] = self.laya.device
                status["decision_precision"] = self.laya.precision
            return status
        if not self.inference.enabled:
            return {
                "enabled": False,
                "mode": "deterministic",
                "profile_id": self.profile_id,
            }
        status: dict[str, object] = {
            "enabled": True,
            "mode": (
                "typed-feature-local-reasoner"
                if self.decision_provider == "typed-feature"
                else "local-dual-brain"
            ),
            "profile_id": self.profile_id,
            "configured_mode": policy.configured_mode,
            "effective_mode": policy.effective_mode,
            "degradation_reason": policy.degradation_reason,
            "decision_status": "not_checked",
            "reasoning_model": self.inference.reasoning_model,
            "reasoning_digest": self.inference.reasoning_digest,
            "reasoning_status": "not_checked",
            "endpoint": self.inference.endpoint,
            "allow_gpu": self.inference.allow_gpu,
        }
        if self.decision_provider == "laya":
            status["decision_model"] = "laya-typed-decisions"
            status["decision_device"] = self.laya.device
            status["decision_precision"] = self.laya.precision
        else:
            status["decision_provider"] = "typed-feature-v3"
        return status


def propose_managed_v3_payload(
    legacy_profile: LocalInferenceProfile,
    *,
    decision_provider: Literal["laya", "typed-feature"] = "typed-feature",
    managed_resources: ManagedGpuResources | None = None,
) -> dict[str, object]:
    """Construct a separate validated review candidate; never mutate the source profile."""

    if legacy_profile.schema_version == 3:
        raise ValueError("v3 candidate requires a legacy source profile")
    candidate: dict[str, object] = {
        "schema_version": 3,
        "decision_provider": decision_provider,
        "reasoning_provider": "deterministic",
        "profile_id": f"{legacy_profile.profile_id}-v3"[:80],
        "investigation_budget_ms": legacy_profile.investigation_budget_ms,
        "inference": LocalInferenceConfig().model_dump(mode="json"),
        "laya": (
            legacy_profile.laya.model_dump(mode="json")
            if decision_provider == "laya"
            else LayaProfile().model_dump(mode="json")
        ),
    }
    if managed_resources is not None:
        candidate["managed_resources"] = managed_resources.model_dump(mode="json")
    if legacy_profile.inference.reasoning_model and legacy_profile.inference.reasoning_digest:
        candidate["review_only_reasoning"] = {
            "model": legacy_profile.inference.reasoning_model,
            "digest": legacy_profile.inference.reasoning_digest,
            "endpoint": legacy_profile.inference.endpoint,
        }
    return LocalInferenceProfile.model_validate(candidate).model_dump(mode="json")


def default_profile_path() -> Path:
    workspace_data = os.environ.get("SYSTEMSENSE_DATA_DIR")
    if workspace_data:
        return Path(workspace_data) / "inference-profile.json"
    local_app_data = os.environ.get("LOCALAPPDATA")
    base = Path(local_app_data) if local_app_data else Path.cwd()
    return base / "SystemSense" / "inference-profile.json"


def load_inference_profile(path: Path | None = None) -> LocalInferenceProfile:
    """Load a bounded profile; an absent implicit default stays safely disabled."""

    profile_path = default_profile_path() if path is None else path
    if not profile_path.exists():
        if path is None:
            return LocalInferenceProfile()
        raise ValueError(f"inference profile does not exist: {profile_path}")
    try:
        if profile_path.stat().st_size > _MAX_PROFILE_BYTES:
            raise ValueError("inference profile exceeds 65536 bytes")
        payload = cast(object, json.loads(profile_path.read_text(encoding="utf-8")))
        return LocalInferenceProfile.model_validate(payload)
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        if isinstance(error, ValueError) and str(error).startswith("inference profile exceeds"):
            raise
        raise ValueError(f"inference profile is invalid: {error}") from error
