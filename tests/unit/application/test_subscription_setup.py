"""Subscription setup must distinguish ChatGPT login from other local states."""

from pathlib import Path
from subprocess import CompletedProcess

import pytest

from systemsense.application.subscription_setup import (
    _codex_login_ready,  # pyright: ignore[reportPrivateUsage]
    _model_start_failure,  # pyright: ignore[reportPrivateUsage]
)


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
