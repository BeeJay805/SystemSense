"""Subscription setup must distinguish ChatGPT login from other local states."""

from pathlib import Path
from subprocess import CompletedProcess
from types import SimpleNamespace
from typing import cast
from unittest.mock import Mock

import pytest

from systemsense.application import subscription_setup
from systemsense.application.subscription_setup import (
    _codex_login_ready,  # pyright: ignore[reportPrivateUsage]
    _model_start_failure,  # pyright: ignore[reportPrivateUsage]
)
from systemsense.inference.managed_laya import ManagedLayaAdmission


@pytest.mark.parametrize(
    ("admission_reason", "expected"),
    [
        (
            "vram_headroom;worker_exit_verified_no_lease",
            "Insufficient free GPU memory for local Laya. "
            "Wait for other GPU work to finish, then restart Dyad.",
        ),
        (
            "ram_headroom",
            "Insufficient free system memory for local Laya. "
            "Wait for other memory-heavy work to finish, then restart Dyad.",
        ),
        ("worker_identity_unavailable", "The local Laya model could not start safely."),
    ],
)
def test_model_setup_explains_known_resource_denial_without_guessing_other_failures(
    admission_reason: str, expected: str
) -> None:
    assert _model_start_failure(admission_reason) == expected


@pytest.mark.parametrize(
    ("stdout", "stderr", "code", "expected"),
    [
        (b"", b"Logged in using ChatGPT\n", 0, True),
        (b"Logged in using ChatGPT\n", b"", 0, True),
        (b"", b"Logged in using API key\n", 0, False),
        (b"", b"Logged in using ChatGPT\n", 1, False),
    ],
)
def test_codex_login_readiness_requires_successful_chatgpt_identity(
    monkeypatch: pytest.MonkeyPatch,
    stdout: bytes,
    stderr: bytes,
    code: int,
    expected: bool,
) -> None:
    def fake_run(*_args: object, **_kwargs: object) -> CompletedProcess[bytes]:
        return CompletedProcess([], code, stdout, stderr)

    monkeypatch.setattr(
        "systemsense.application.subscription_setup.subprocess.run",
        fake_run,
    )
    assert _codex_login_ready(Path("C:/installed/codex.exe")) is expected


def test_desktop_wires_bounded_headroom_safe_telemetry_reuse(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Desktop microbatches must reach the admission controller's guarded reuse path."""
    codex = tmp_path / "codex.exe"
    codex.touch()
    captured: dict[str, object] = {}
    providers = SimpleNamespace(
        use_codex_subscription=Mock(),
        prewarm_laya=Mock(),
    )

    def load(_config: object, **kwargs: object) -> object:
        captured.update(kwargs)
        return providers

    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))
    monkeypatch.setattr(
        subscription_setup.LayaRuntimeConfig, "validate_install", Mock(return_value=None)
    )
    monkeypatch.setattr(subscription_setup.shutil, "which", Mock(return_value=str(codex)))
    monkeypatch.setattr(subscription_setup, "_codex_login_ready", Mock(return_value=True))
    monkeypatch.setattr(
        subscription_setup,
        "read_host_telemetry",
        Mock(return_value=SimpleNamespace(gpu_uuid="GPU-00000000-0000-0000-0000-000000000001")),
    )
    monkeypatch.setattr(
        subscription_setup.TreeHostInferenceLeaseLedger,
        "migrate_from_v3",
        Mock(return_value="migrated"),
    )
    monkeypatch.setattr(subscription_setup, "load_advisory_providers", load)

    assert subscription_setup.load_desktop_subscription_providers() is providers
    admission = cast(ManagedLayaAdmission, captured["managed_admission"])
    reuse_ms = admission._call_telemetry_reuse_ms  # pyright: ignore[reportPrivateUsage]
    assert 0 < reuse_ms <= min(150, admission.policy.max_telemetry_age_ms)
