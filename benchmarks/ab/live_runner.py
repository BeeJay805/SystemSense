"""Authorization gate shared by all paid experiment entry points."""

from pathlib import Path
from typing import Literal

from benchmarks.ab.readiness import (
    ExperimentConfig,
    ReadinessError,
    ReadyArtifact,
    load_ready_artifact,
)


class PaidRunLockedError(RuntimeError):
    """A live call was attempted without explicit authorization or readiness."""


def authorize_paid_run(
    *,
    ready_path: Path,
    config: ExperimentConfig,
    allow_paid_run: bool,
    api_key: str | None,
    subscription_authenticated: bool = False,
    expected_stage: Literal["canary", "benchmark"] = "benchmark",
) -> ReadyArtifact:
    if not allow_paid_run:
        raise PaidRunLockedError(
            "paid model calls are locked; pass --allow-paid-run only after preflight"
        )
    if not api_key and not subscription_authenticated:
        raise PaidRunLockedError(
            "OPENAI_API_KEY or ChatGPT-authenticated Codex CLI is required for an "
            "authorized model run"
        )
    try:
        return load_ready_artifact(
            ready_path,
            expected_config=config,
            expected_stage=expected_stage,
        )
    except ReadinessError as error:
        raise PaidRunLockedError(str(error)) from error
