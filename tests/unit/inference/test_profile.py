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
