"""Persistent, explicit local dual-brain configuration with no installation side effects."""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Literal, cast

from pydantic import Field, model_validator

from systemsense.domain.evidence import FrozenModel
from systemsense.inference.laya_runtime import LayaRuntimeConfig, LayaRuntimeError
from systemsense.inference.settings import LocalInferenceConfig

_MAX_PROFILE_BYTES = 65_536


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

    schema_version: Literal[1, 2] = 1
    decision_provider: Literal["laya", "typed-feature"] = "laya"
    profile_id: str = Field(
        default="deterministic-default",
        pattern=r"^[a-z][a-z0-9_.-]*$",
        max_length=80,
    )
    investigation_budget_ms: int = Field(default=30_000, ge=100, le=600_000)
    inference: LocalInferenceConfig = Field(default_factory=LocalInferenceConfig)
    laya: LayaProfile = Field(default_factory=LayaProfile)

    @model_validator(mode="after")
    def validate_dual_brain(self) -> LocalInferenceProfile:
        if self.schema_version == 1 and self.decision_provider != "laya":
            raise ValueError("typed-feature decision provider requires schema_version 2")
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

    def inference_status(self) -> dict[str, object]:
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
