import hashlib
import json
from pathlib import Path
from typing import cast

import pytest
from pydantic import ValidationError

from systemsense.inference.laya_runtime import (
    LAYA_MODEL_REVISION,
    LAYA_MODEL_WEIGHT_BYTES,
    LAYA_MODEL_WEIGHT_SHA256,
    LAYA_PACKAGE_VERSION,
    LayaRuntimeError,
)
from systemsense.inference.profile import (
    LocalInferenceProfile,
    default_profile_path,
    load_inference_profile,
)


def _laya_install(tmp_path: Path) -> tuple[Path, Path]:
    interpreter = tmp_path / "runtime" / "python.exe"
    interpreter.parent.mkdir(parents=True)
    interpreter.write_bytes(b"fixture")
    model = tmp_path / "model"
    (model / "tokenizer").mkdir(parents=True)
    (model / "encoder").mkdir()
    (model / "model.safetensors").write_bytes(b"fixture")
    (model / "rl_agent_config.json").write_text("{}", encoding="utf-8")
    (model / "INSTALL-MANIFEST.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "model_repository": "convaiinnovations/laya-typed-decisions",
                "model_revision": LAYA_MODEL_REVISION,
                "weight_sha256": LAYA_MODEL_WEIGHT_SHA256,
                "weight_bytes": LAYA_MODEL_WEIGHT_BYTES,
                "package_version": LAYA_PACKAGE_VERSION,
                "package_wheel_sha256": (
                    "4c57f64cbaf893bb5c7b4affddc2bf21a819f55df51941689f11868583be2903"
                ),
                "license": "Apache-2.0",
                "torch_version": "2.9.1",
                "transformers_version": "4.57.3",
                "device_policy": "cpu_only",
                "acquired_at": "2026-09-22T00:00:00Z",
            }
        ),
        encoding="utf-8",
    )
    return interpreter.resolve(), model.resolve()


def _enabled_payload(tmp_path: Path) -> dict[str, object]:
    interpreter, model = _laya_install(tmp_path)
    return {
        "schema_version": 1,
        "profile_id": "local-dual-brain",
        "investigation_budget_ms": 180_000,
        "inference": {
            "enabled": True,
            "endpoint": "http://127.0.0.1:11435/api/chat",
            "reasoning_model": "qwen3.8:27b",
            "reasoning_digest": "2" * 64,
            "allow_gpu": True,
            "keep_alive_seconds": 300,
            "timeout_seconds": 90,
            "context_tokens": 8192,
            "output_tokens": 1200,
            "cpu_threads": 4,
        },
        "laya": {
            "enabled": True,
            "interpreter_path": str(interpreter),
            "model_path": str(model),
            "device": "cpu",
            "cuda_device_index": 0,
            "min_free_vram_mb": 2048,
            "threads": 2,
            "max_candidates_per_batch": 4,
            "timeout_seconds": 60,
        },
    }


def test_absent_default_profile_is_disabled_without_creating_files(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))

    profile = load_inference_profile()

    assert profile.inference.enabled is False
    assert profile.laya.enabled is False
    assert profile.investigation_budget_ms == 30_000
    assert not default_profile_path().exists()


def test_default_profile_follows_workspace_data_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    workspace_data = tmp_path / "isolated-workspace"
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "real-user-profile"))
    monkeypatch.setenv("SYSTEMSENSE_DATA_DIR", str(workspace_data))

    assert default_profile_path() == workspace_data / "inference-profile.json"
    assert load_inference_profile().inference.enabled is False


def test_enabled_profile_requires_pinned_reasoning_and_admitted_laya_install(
    tmp_path: Path,
) -> None:
    payload = _enabled_payload(tmp_path)
    inference = dict(cast("dict[str, object]", payload["inference"]))
    inference["allow_gpu"] = False
    payload["inference"] = inference
    profile_path = tmp_path / "profile.json"
    profile_path.write_text(json.dumps(payload), encoding="utf-8")

    profile = load_inference_profile(profile_path)

    assert profile.inference.reasoning_model == "qwen3.8:27b"
    assert profile.inference.reasoning_digest == "2" * 64
    assert profile.laya.runtime_config().validate_install().model_revision == LAYA_MODEL_REVISION
    runtime = profile.laya.runtime_config()
    assert runtime.device == "cpu"
    assert runtime.cuda_device_index == 0
    assert runtime.min_free_vram_mb == 2048
    assert runtime.max_candidates_per_batch == 4
    assert profile.investigation_budget_ms == 180_000
    assert profile.inference_status()["decision_device"] == "cpu"


def test_v2_typed_feature_profile_needs_no_laya_install() -> None:
    payload = {
        "schema_version": 2,
        "decision_provider": "typed-feature",
        "inference": {
            "enabled": True,
            "reasoning_model": "qwen3.8:27b",
            "reasoning_digest": "2" * 64,
        },
    }

    profile = LocalInferenceProfile.model_validate(payload)

    assert profile.decision_provider == "typed-feature"
    assert profile.inference_status()["mode"] == "typed-feature-local-reasoner"
    assert profile.inference_status()["decision_provider"] == "typed-feature-v3"
    assert "decision_model" not in profile.inference_status()
    assert "decision_device" not in profile.inference_status()


def test_v1_rejects_typed_feature_and_v2_rejects_ambiguous_fast_providers(
    tmp_path: Path,
) -> None:
    payload = _enabled_payload(tmp_path)
    payload["decision_provider"] = "typed-feature"
    with pytest.raises(ValidationError, match="schema_version"):
        LocalInferenceProfile.model_validate(payload)

    payload["schema_version"] = 2
    with pytest.raises(ValidationError, match="Laya"):
        LocalInferenceProfile.model_validate(payload)

    payload["laya"] = {"enabled": False}
    inference = dict(cast("dict[str, object]", payload["inference"]))
    inference["decision_model"] = "legacy"
    payload["inference"] = inference
    with pytest.raises(ValidationError, match="decision_model"):
        LocalInferenceProfile.model_validate(payload)


def test_laya_cuda_profile_forwards_admission_and_batch_limits(tmp_path: Path) -> None:
    payload = _enabled_payload(tmp_path)
    laya = dict(cast("dict[str, object]", payload["laya"]))
    laya.update(
        {
            "device": "cuda",
            "precision": "float16",
            "cuda_device_index": 1,
            "min_free_vram_mb": 3072,
            "max_candidates_per_batch": 7,
        }
    )
    payload["laya"] = laya
    manifest_path = Path(cast(str, laya["model_path"])) / "INSTALL-MANIFEST.json"
    manifest = cast("dict[str, object]", json.loads(manifest_path.read_text(encoding="utf-8")))
    manifest["device_policy"] = "cpu_and_cuda"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")

    profile = LocalInferenceProfile.model_validate(payload)
    runtime = profile.laya.runtime_config()

    assert runtime.device == "cuda"
    assert runtime.precision == "float16"
    assert runtime.cuda_device_index == 1
    assert runtime.min_free_vram_mb == 3072
    assert runtime.max_candidates_per_batch == 7


def test_explicit_missing_profile_fails_and_never_silently_enables(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="does not exist"):
        load_inference_profile(tmp_path / "missing.json")


def test_enabled_profile_rejects_unpinned_model_or_missing_laya_path(tmp_path: Path) -> None:
    payload = _enabled_payload(tmp_path)
    inference = dict(cast("dict[str, object]", payload["inference"]))
    inference["reasoning_digest"] = None
    payload["inference"] = inference
    with pytest.raises(ValidationError, match="digest"):
        LocalInferenceProfile.model_validate(payload)

    payload = _enabled_payload(tmp_path / "second")
    laya = dict(cast("dict[str, object]", payload["laya"]))
    laya["interpreter_path"] = str(tmp_path / "absent.exe")
    payload["laya"] = laya
    with pytest.raises(ValidationError, match="incomplete"):
        LocalInferenceProfile.model_validate(payload)


def test_profile_rejects_remote_endpoint_cloud_alias_and_ambiguous_decision_model(
    tmp_path: Path,
) -> None:
    payload = _enabled_payload(tmp_path)
    inference = dict(cast("dict[str, object]", payload["inference"]))
    inference["endpoint"] = "https://example.com/api/chat"
    payload["inference"] = inference
    with pytest.raises(ValidationError, match="loopback"):
        LocalInferenceProfile.model_validate(payload)

    payload = _enabled_payload(tmp_path / "cloud")
    inference = dict(cast("dict[str, object]", payload["inference"]))
    inference["reasoning_model"] = "qwen:cloud"
    payload["inference"] = inference
    with pytest.raises(ValidationError, match="cloud"):
        LocalInferenceProfile.model_validate(payload)

    payload = _enabled_payload(tmp_path / "decision")
    inference = dict(cast("dict[str, object]", payload["inference"]))
    inference["decision_model"] = "second-decision-model"
    payload["inference"] = inference
    with pytest.raises(ValidationError, match="decision_model"):
        LocalInferenceProfile.model_validate(payload)


def test_legacy_gpu_request_resolves_to_deterministic_without_dual_brain_claim(
    tmp_path: Path,
) -> None:
    payload = _enabled_payload(tmp_path)
    profile = LocalInferenceProfile.model_validate(payload)

    policy = profile.resolved_execution_policy()

    assert policy.configured_mode == "local-dual-brain"
    assert policy.effective_mode == "deterministic"
    assert policy.degradation_reason == "legacy_gpu_profile_requires_v3"
    assert policy.decision_provider == "deterministic"
    assert policy.reasoning_provider == "deterministic"
    assert profile.inference_status()["mode"] == "deterministic"


def test_v3_managed_cuda_laya_is_explicitly_separate_from_reasoning(
    tmp_path: Path,
) -> None:
    payload = _enabled_payload(tmp_path)
    laya = dict(cast("dict[str, object]", payload["laya"]))
    laya["device"] = "cuda"
    laya["precision"] = "float16"
    payload["laya"] = laya
    manifest_path = Path(cast(str, laya["model_path"])) / "INSTALL-MANIFEST.json"
    manifest = cast("dict[str, object]", json.loads(manifest_path.read_text(encoding="utf-8")))
    manifest["device_policy"] = "cpu_and_cuda"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    payload.update(
        {
            "schema_version": 3,
            "reasoning_provider": "deterministic",
            "inference": {"enabled": False},
            "managed_resources": {
                "gpu_device_index": 0,
                "gpu_uuid": "GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            },
        }
    )

    profile = LocalInferenceProfile.model_validate(payload)
    policy = profile.resolved_execution_policy()

    assert policy.configured_mode == "managed-laya-cuda"
    assert policy.effective_mode == "managed-laya-cuda"
    assert policy.degradation_reason is None
    assert policy.decision_provider == "laya"
    assert policy.reasoning_provider == "deterministic"
    assert policy.managed_gpu is True
    assert policy.managed_resources is not None
    assert policy.managed_resources.gpu_uuid == "GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"
    assert policy.managed_resources.target_vram_reserve_bytes == 6 * 1024**3
    assert profile.inference_status()["mode"] == "managed-laya-cuda"
    assert "reasoning_model" not in profile.inference_status()


def test_v3_deterministic_fast_provider_needs_no_qwen_or_laya() -> None:
    profile = LocalInferenceProfile.model_validate(
        {
            "schema_version": 3,
            "decision_provider": "typed-feature",
            "reasoning_provider": "deterministic",
        }
    )

    policy = profile.resolved_execution_policy()
    assert policy.configured_mode == "typed-feature-deterministic"
    assert policy.effective_mode == "typed-feature-deterministic"
    assert policy.decision_provider == "typed-feature"
    assert policy.reasoning_provider == "deterministic"
    assert policy.managed_gpu is False


@pytest.mark.parametrize(
    "change",
    [
        {"reasoning_provider": "ollama"},
        {
            "inference": {
                "enabled": True,
                "reasoning_model": "qwen3.8:27b",
                "reasoning_digest": "2" * 64,
            }
        },
        {"inference": {"enabled": False, "allow_gpu": True}},
        {"decision_provider": "laya", "laya": {"enabled": False}},
    ],
)
def test_v3_rejects_unmanaged_or_incomplete_execution(change: dict[str, object]) -> None:
    payload: dict[str, object] = {
        "schema_version": 3,
        "decision_provider": "typed-feature",
        "reasoning_provider": "deterministic",
    }
    payload.update(change)
    with pytest.raises(ValidationError, match=r"v3|Laya"):
        LocalInferenceProfile.model_validate(payload)


def test_v3_candidate_from_legacy_is_pure_valid_and_review_only(tmp_path: Path) -> None:
    from systemsense.inference.profile import propose_managed_v3_payload

    legacy_payload = _enabled_payload(tmp_path)
    legacy = LocalInferenceProfile.model_validate(legacy_payload)
    before = legacy.model_dump(mode="json")

    candidate = propose_managed_v3_payload(legacy)
    profile = LocalInferenceProfile.model_validate(candidate)

    assert legacy.model_dump(mode="json") == before
    assert candidate is not legacy_payload
    assert profile.schema_version == 3
    assert profile.inference.enabled is False
    assert profile.decision_provider == "typed-feature"
    assert profile.review_only_reasoning is not None
    assert profile.review_only_reasoning.model == "qwen3.8:27b"
    assert profile.review_only_reasoning.digest == "2" * 64
    assert profile.inference_status()["mode"] == "typed-feature-deterministic"


def test_v3_candidate_cannot_promote_cpu_laya_to_managed_cuda(tmp_path: Path) -> None:
    from systemsense.inference.profile import propose_managed_v3_payload

    legacy = LocalInferenceProfile.model_validate(_enabled_payload(tmp_path))

    with pytest.raises(ValidationError, match="requires CUDA"):
        propose_managed_v3_payload(legacy, decision_provider="laya")


def test_v3_review_only_model_reference_rejects_remote_endpoint() -> None:
    with pytest.raises(ValidationError, match="loopback"):
        LocalInferenceProfile.model_validate(
            {
                "schema_version": 3,
                "decision_provider": "typed-feature",
                "reasoning_provider": "deterministic",
                "review_only_reasoning": {
                    "model": "qwen3.8:27b",
                    "digest": "2" * 64,
                    "endpoint": "https://example.com/api/chat",
                },
            }
        )


def test_v3_laya_requires_pinned_managed_resources(tmp_path: Path) -> None:
    payload = _enabled_payload(tmp_path)
    laya = dict(cast("dict[str, object]", payload["laya"]))
    laya["device"] = "cuda"
    payload.update(
        {
            "schema_version": 3,
            "reasoning_provider": "deterministic",
            "inference": {"enabled": False},
            "laya": laya,
        }
    )

    with pytest.raises(ValidationError, match="managed resources"):
        LocalInferenceProfile.model_validate(payload)


def test_v3_candidate_can_promote_admitted_cuda_laya_with_explicit_resources(
    tmp_path: Path,
) -> None:
    from systemsense.inference.profile import ManagedGpuResources, propose_managed_v3_payload

    payload = _enabled_payload(tmp_path)
    laya = dict(cast("dict[str, object]", payload["laya"]))
    laya["device"] = "cuda"
    laya["precision"] = "float16"
    payload["laya"] = laya
    manifest_path = Path(cast(str, laya["model_path"])) / "INSTALL-MANIFEST.json"
    manifest = cast("dict[str, object]", json.loads(manifest_path.read_text(encoding="utf-8")))
    manifest["device_policy"] = "cpu_and_cuda"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    legacy = LocalInferenceProfile.model_validate(payload)
    resources = ManagedGpuResources(
        gpu_device_index=0,
        gpu_uuid="GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
    )

    candidate = propose_managed_v3_payload(
        legacy, decision_provider="laya", managed_resources=resources
    )
    profile = LocalInferenceProfile.model_validate(candidate)

    assert profile.resolved_execution_policy().effective_mode == "managed-laya-cuda"
    assert profile.resolved_execution_policy().managed_resources == resources


def test_managed_resources_cannot_understate_measured_admission_floors() -> None:
    from systemsense.inference.profile import ManagedGpuResources

    with pytest.raises(ValidationError, match="peak_vram_bytes"):
        ManagedGpuResources(
            gpu_device_index=0,
            gpu_uuid="GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            peak_vram_bytes=1024,
        )


def test_managed_resources_cannot_supply_arbitrary_lease_path() -> None:
    from systemsense.inference.profile import ManagedGpuResources

    with pytest.raises(ValidationError, match="lease_path"):
        ManagedGpuResources.model_validate(
            {
                "gpu_device_index": 0,
                "gpu_uuid": "GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
                "lease_path": "C:/Windows/System32/arbitrary.sqlite3",
            }
        )


def _joint_v4_payload(tmp_path: Path) -> dict[str, object]:
    payload = _enabled_payload(tmp_path)
    laya = dict(cast("dict[str, object]", payload["laya"]))
    laya["device"] = "cuda"
    laya["precision"] = "float16"
    payload["laya"] = laya
    manifest_path = Path(cast(str, laya["model_path"])) / "INSTALL-MANIFEST.json"
    manifest = cast("dict[str, object]", json.loads(manifest_path.read_text(encoding="utf-8")))
    manifest["device_policy"] = "cpu_and_cuda"
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    executable = tmp_path / "owned-ollama" / "ollama.exe"
    executable.parent.mkdir()
    executable.write_bytes(b"fixture-ollama")
    models_dir = tmp_path / "owned-models"
    models_dir.mkdir()
    payload.update(
        {
            "schema_version": 4,
            "profile_id": "managed-local-sequential",
            "reasoning_provider": "ollama",
            "inference": {"enabled": False},
            "managed_resources": {
                "gpu_device_index": 0,
                "gpu_uuid": "GPU-aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa",
            },
            "managed_reasoning": {
                "executable": str(executable.resolve()),
                "executable_sha256": hashlib.sha256(b"fixture-ollama").hexdigest(),
                "models_dir": str(models_dir.resolve()),
                "endpoint": "http://127.0.0.1:11435/api/chat",
                "model": "qwen3.8:27b",
                "model_digest": "2" * 64,
                "gpu_device_index": 0,
                "peak_ram_bytes": 8 * 1024**3,
                "peak_vram_bytes": 22 * 1024**3,
                "ram_reserve_bytes": 4 * 1024**3,
                "target_vram_reserve_bytes": 2 * 1024**3,
                "context_tokens": 8192,
                "output_tokens": 1200,
                "startup_timeout_seconds": 15,
                "call_timeout_seconds": 90,
                "idle_timeout_seconds": 30,
                "exit_timeout_seconds": 3,
            },
        }
    )
    return payload


def test_v4_joint_profile_is_pinned_but_cannot_activate_without_composite_owner(
    tmp_path: Path,
) -> None:
    profile = LocalInferenceProfile.model_validate(_joint_v4_payload(tmp_path))

    assert profile.schema_version == 4
    assert profile.managed_reasoning is not None
    assert profile.managed_reasoning.model == "qwen3.8:27b"
    assert profile.managed_reasoning.target_vram_reserve_bytes == 2 * 1024**3
    policy = profile.resolved_execution_policy()
    assert policy.configured_mode == "managed-local-sequential"
    assert policy.effective_mode == "deterministic"
    assert policy.degradation_reason == "joint_runtime_not_activated"
    assert policy.decision_provider == "deterministic"
    assert policy.reasoning_provider == "deterministic"
    assert policy.managed_gpu is False
    assert profile.inference_status()["enabled"] is False


def test_v4_warm_profile_requires_explicit_opt_in_and_combined_headroom(tmp_path: Path) -> None:
    payload = _joint_v4_payload(tmp_path)
    payload["runtime_strategy"] = "warm-independent"
    payload["gpu_total_vram_bytes"] = 24 * 1024**3
    managed_reasoning = dict(cast("dict[str, object]", payload["managed_reasoning"]))
    managed_reasoning["peak_vram_bytes"] = 4 * 1024**3
    payload["managed_reasoning"] = managed_reasoning
    profile = LocalInferenceProfile.model_validate(payload)
    policy = profile.resolved_execution_policy()
    assert policy.configured_mode == "managed-local-warm"
    assert policy.effective_mode == "managed-local-warm"
    assert policy.decision_provider == "laya"
    assert policy.reasoning_provider == "ollama"

    resources = dict(cast("dict[str, object]", payload["managed_resources"]))
    reasoning = dict(managed_reasoning)
    resources["peak_vram_bytes"] = 20 * 1024**3
    reasoning["peak_vram_bytes"] = 20 * 1024**3
    payload["managed_resources"] = resources
    payload["managed_reasoning"] = reasoning
    with pytest.raises(ValidationError, match="combined warm VRAM"):
        LocalInferenceProfile.model_validate(payload)


def test_cli_warm_activation_prewarms_laya_and_closes_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import systemsense.cli as cli
    import systemsense.inference.factory as factory

    payload = _joint_v4_payload(tmp_path)
    payload["runtime_strategy"] = "warm-independent"
    payload["gpu_total_vram_bytes"] = 24 * 1024**3
    reasoning = dict(cast("dict[str, object]", payload["managed_reasoning"]))
    reasoning["peak_vram_bytes"] = 4 * 1024**3
    payload["managed_reasoning"] = reasoning
    profile = LocalInferenceProfile.model_validate(payload)
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))

    class Ledger:
        def __init__(self, *_args: object, **_kwargs: object) -> None:
            pass

        def migrate_from_v3(self) -> str:
            return "migrated"

    class Providers:
        closed = False
        warmed = False

        def prewarm_laya(self, *, timeout_seconds: float) -> None:
            assert timeout_seconds == profile.laya.timeout_seconds
            self.warmed = True
            raise LayaRuntimeError("denied")

        def close(self) -> None:
            self.closed = True

    providers = Providers()

    def fake_factory(*_args: object) -> Providers:
        return providers

    monkeypatch.setattr(cli, "TreeHostInferenceLeaseLedger", Ledger)
    monkeypatch.setattr(factory, "load_warm_v4_providers", fake_factory)
    with pytest.raises(ValueError, match="warm Laya startup failed"):
        cli._v4_providers(profile)  # pyright: ignore[reportPrivateUsage]
    assert providers.warmed
    assert providers.closed


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("endpoint", "https://example.com/api/chat", "loopback"),
        ("endpoint", "http://127.0.0.1:11434/api/chat", "dedicated"),
        ("model", "qwen:cloud", "cloud"),
        ("model_digest", "bad", "model_digest"),
        ("executable_sha256", "bad", "executable_sha256"),
        ("peak_vram_bytes", 0, "peak_vram_bytes"),
        ("target_vram_reserve_bytes", 0, "target_vram_reserve_bytes"),
        ("call_timeout_seconds", 0, "call_timeout_seconds"),
    ],
)
def test_v4_rejects_unpinned_or_unsafe_deep_config(
    tmp_path: Path, field: str, value: object, message: str
) -> None:
    payload = _joint_v4_payload(tmp_path)
    deep = dict(cast("dict[str, object]", payload["managed_reasoning"]))
    deep[field] = value
    payload["managed_reasoning"] = deep
    with pytest.raises(ValidationError, match=message):
        LocalInferenceProfile.model_validate(payload)


def test_v4_rejects_unmanaged_gpu_reasoning_and_device_mismatch(tmp_path: Path) -> None:
    payload = _joint_v4_payload(tmp_path)
    payload["inference"] = {"enabled": True, "allow_gpu": True}
    with pytest.raises(ValidationError, match="v4"):
        LocalInferenceProfile.model_validate(payload)

    payload = _joint_v4_payload(tmp_path / "mismatch")
    deep = dict(cast("dict[str, object]", payload["managed_reasoning"]))
    deep["gpu_device_index"] = 1
    payload["managed_reasoning"] = deep
    with pytest.raises(ValidationError, match="GPU index"):
        LocalInferenceProfile.model_validate(payload)


def test_pre_v4_profiles_reject_joint_fields(tmp_path: Path) -> None:
    payload = _joint_v4_payload(tmp_path)
    payload["schema_version"] = 3
    payload["reasoning_provider"] = "deterministic"
    with pytest.raises(ValidationError, match="schema_version 4"):
        LocalInferenceProfile.model_validate(payload)
