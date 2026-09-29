"""Real Windows checks for exact process routing and evaluator restoration."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from benchmarks import private_alpha_host

pytestmark = pytest.mark.skipif(
    os.name != "nt" or not private_alpha_host.CSC.is_file(),
    reason="test-owned Windows helper requires the .NET Framework compiler",
)


def _entry() -> dict[str, object]:
    return {
        "case_id": "regression",
        "objective_template": (
            "The PDF in {target_exe} is slow. Check this exact process CPU use."
        ),
        "budget_ms": 45_000,
        "max_rounds": 6,
    }


def _read(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def test_basic_exact_cpu_request_does_not_wait_for_manual_pdf_target(tmp_path: Path) -> None:
    base = private_alpha_host._compile(tmp_path)  # pyright: ignore[reportPrivateUsage]
    trial = tmp_path / "basic-exact-cpu"

    private_alpha_host._run_case(  # pyright: ignore[reportPrivateUsage]
        trial, _entry(), "idle", base, None
    )

    result = _read(trial / "result-index.json")
    cleanup = _read(trial / "evaluator" / "cleanup.json")
    assert result["status"] == "complete"
    assert "exact process" in str(result["summary"]).casefold()
    assert cleanup["restored_before_cleanup"] is True
    assert cleanup["owned_processes_exited"] is True


def test_evaluator_restores_owned_process_after_product_exception(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    base = private_alpha_host._compile(tmp_path)  # pyright: ignore[reportPrivateUsage]
    trial = tmp_path / "failed-product"

    def failed_product(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("fixture product failure")

    monkeypatch.setattr(private_alpha_host, "run_product_case", failed_product)
    with pytest.raises(RuntimeError, match="fixture product failure"):
        private_alpha_host._run_case(  # pyright: ignore[reportPrivateUsage]
            trial, _entry(), "stopped", base, None
        )

    cleanup = _read(trial / "evaluator" / "cleanup.json")
    restored = _read(trial / "evaluator" / "restored.json")
    assert cleanup["restored_before_cleanup"] is True
    assert cleanup["owned_processes_exited"] is True
    assert restored["target"]["running"] is True  # type: ignore[index]
    assert restored["control"]["running"] is True  # type: ignore[index]
