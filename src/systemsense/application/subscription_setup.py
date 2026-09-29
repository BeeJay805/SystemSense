"""Explicit desktop admission for the installed Laya and ChatGPT Sol providers.

The installed model and CLI are operator-owned prerequisites. This module never
downloads a model, logs in, selects a paid API, or silently falls back.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from systemsense.inference.codex import CodexInferenceConfig
from systemsense.inference.factory import AdvisoryProviders, load_advisory_providers
from systemsense.inference.host_lease import LeaseBudget
from systemsense.inference.host_telemetry import HostTelemetryUnavailable, read_host_telemetry
from systemsense.inference.laya_runtime import LayaRuntimeConfig, LayaRuntimeError
from systemsense.inference.managed_laya import ManagedLayaAdmission, ManagedLayaPolicy
from systemsense.inference.profile import InferenceExecutionPolicy, ManagedGpuResources
from systemsense.inference.settings import LocalInferenceConfig
from systemsense.inference.tree_host_lease import TreeHostInferenceLeaseLedger

_GIB = 1024**3


class SubscriptionSetupError(RuntimeError):
    """A requested model route cannot safely start; no case may fall back."""


def _model_start_failure(admission_reason: str) -> str:
    """Explain known resource denials without exposing an arbitrary worker error."""

    reason = admission_reason.split(";", 1)[0]
    if reason == "vram_headroom":
        return (
            "Insufficient free GPU memory for local Laya. "
            "Wait for other GPU work to finish, then restart Dyad."
        )
    if reason == "ram_headroom":
        return (
            "Insufficient free system memory for local Laya. "
            "Wait for other memory-heavy work to finish, then restart Dyad."
        )
    return "The local Laya model could not start safely."


def _codex_login_ready(executable: Path) -> bool:
    try:
        result = subprocess.run(
            [str(executable), "login", "status"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=5,
            check=False,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    return result.returncode == 0 and (
        result.stdout.strip() == b"Logged in using ChatGPT"
        or result.stderr.strip() == b"Logged in using ChatGPT"
    )


def load_desktop_subscription_providers() -> AdvisoryProviders:
    """Admit the fixed per-user Laya install and installed Codex ChatGPT route.

    The known runtime location is intentionally narrow. A user-selectable path
    cannot become model-provided execution authority. The worker verifies its
    exact pinned weights again before deserialization.
    """

    local_app_data = os.environ.get("LOCALAPPDATA")
    if not local_app_data or not Path(local_app_data).is_absolute():
        raise SubscriptionSetupError("The per-user model directory is unavailable.")
    root = Path(local_app_data).resolve() / "SystemSense"
    runtime_root = root / "runtimes" / "laya-0.3.5"
    laya = LayaRuntimeConfig(
        interpreter_path=runtime_root / "venv" / "Scripts" / "python.exe",
        model_path=runtime_root / "model",
        device="cuda",
        precision="float16",
        cuda_device_index=0,
        min_free_vram_mb=2048,
        threads=2,
        max_candidates_per_batch=4,
    )
    try:
        laya.validate_install()
    except (ValueError, LayaRuntimeError) as error:
        raise SubscriptionSetupError(
            "The pinned local Laya installation is unavailable."
        ) from error

    codex_found = shutil.which("codex.exe")
    if codex_found is None:
        raise SubscriptionSetupError("The installed Codex executable is unavailable on PATH.")
    codex = Path(codex_found).resolve()
    if codex.name.casefold() != "codex.exe" or not codex.is_file():
        raise SubscriptionSetupError("The installed Codex executable is invalid.")
    if not _codex_login_ready(codex):
        raise SubscriptionSetupError("Codex is not signed in with ChatGPT.")

    try:
        gpu = read_host_telemetry(gpu_device_index=0)
    except HostTelemetryUnavailable as error:
        raise SubscriptionSetupError("GPU admission telemetry is unavailable.") from error
    resources = ManagedGpuResources(gpu_device_index=0, gpu_uuid=gpu.gpu_uuid)
    ledger = TreeHostInferenceLeaseLedger(
        root / "host-gpu-lease-v3.sqlite3",
        LeaseBudget(
            cpu_slots=2,
            ram_bytes=resources.peak_ram_bytes + 6 * _GIB,
            vram_bytes=resources.peak_vram_bytes + 4 * _GIB,
            gpu_device_index=0,
        ),
    )
    migration = ledger.migrate_from_v3()
    if migration != "migrated":
        raise SubscriptionSetupError(f"Laya resource admission is blocked: {migration}.")
    admission = ManagedLayaAdmission(
        ManagedLayaPolicy(
            gpu_device_index=resources.gpu_device_index,
            gpu_uuid=resources.gpu_uuid,
            peak_ram_bytes=resources.peak_ram_bytes,
            peak_vram_bytes=resources.peak_vram_bytes,
            ram_reserve_bytes=resources.ram_reserve_bytes,
            target_vram_reserve_bytes=resources.target_vram_reserve_bytes,
            max_telemetry_age_ms=resources.max_telemetry_age_ms,
            renew_interval_seconds=resources.renew_interval_seconds,
        ),
        ledger,
    )
    policy = InferenceExecutionPolicy(
        configured_mode="managed-laya-cuda",
        effective_mode="managed-laya-cuda",
        decision_provider="laya",
        reasoning_provider="deterministic",
        managed_gpu=True,
        managed_resources=resources,
    )
    providers = load_advisory_providers(
        LocalInferenceConfig(enabled=False),
        laya_config=laya,
        laya_timeout_seconds=90,
        execution_policy=policy,
        managed_admission=admission,
    )
    try:
        providers.use_codex_subscription(
            CodexInferenceConfig(enabled=True, executable=codex, timeout_seconds=60)
        )
        providers.prewarm_laya(timeout_seconds=90)
    except Exception as error:
        admission_reason = admission.status.reason
        providers.close()
        raise SubscriptionSetupError(_model_start_failure(admission_reason)) from error
    return providers
