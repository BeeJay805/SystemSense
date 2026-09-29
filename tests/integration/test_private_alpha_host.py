"""Real Windows checks for exact process routing and evaluator restoration."""

from __future__ import annotations

import json
import os
from datetime import UTC, datetime
from pathlib import Path
from typing import cast

import pytest

from benchmarks import private_alpha_host
from systemsense.reasoning.deterministic import DeterministicReasoningProvider
from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration.test_investigator import investigator
from tests.unit.application.test_process_target_binding import (
    _snapshot,  # pyright: ignore[reportPrivateUsage]
)

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


@pytest.mark.parametrize("mode", ["running", "stopped"])
def test_direct_named_process_state_reports_supported_sample_only(
    tmp_path: Path, mode: str
) -> None:
    base = private_alpha_host._compile(tmp_path)  # pyright: ignore[reportPrivateUsage]
    trial = tmp_path / f"direct-process-{mode}"
    entry = {
        **_entry(),
        "objective_template": "Please check whether {target_exe} is running right now.",
    }

    private_alpha_host._run_case(  # pyright: ignore[reportPrivateUsage]
        trial, entry, mode, base, None
    )

    result = _read(trial / "result-index.json")
    cleanup = _read(trial / "evaluator" / "cleanup.json")
    assert result["status"] == "complete"
    assert result["outcome"] == "supported_explanation"
    assert "saved complete Windows process inventory" in str(result["summary"])
    assert "why it stopped" in str(result["summary"])
    report = _read(trial / "product-case.json")
    assessment = report["assessment"]
    assert isinstance(assessment, dict)
    assert assessment["claim_kind"] == "named_process_state"
    assert assessment["root_cause_proven"] is False
    snapshot_ids = {
        str(item["evidence_id"])
        for item in cast("list[dict[str, object]]", report["evidence"])
        if item.get("probe_id") == "application.snapshot"
    }
    assert assessment["evidence_ids"] == list(snapshot_ids)
    assert cleanup["restored_before_cleanup"] is True
    assert cleanup["owned_processes_exited"] is True


def test_causal_process_question_does_not_promote_state_sample_to_cause(
    tmp_path: Path,
) -> None:
    base = private_alpha_host._compile(tmp_path)  # pyright: ignore[reportPrivateUsage]
    trial = tmp_path / "causal-process"
    entry = {
        **_entry(),
        "objective_template": "Why did {target_exe} stop unexpectedly? Check if it is running now.",
    }

    private_alpha_host._run_case(  # pyright: ignore[reportPrivateUsage]
        trial, entry, "stopped", base, None
    )

    result = _read(trial / "result-index.json")
    cleanup = _read(trial / "evaluator" / "cleanup.json")
    assert result["status"] == "complete"
    assert result["outcome"] == "insufficient_observability"
    assert cleanup["restored_before_cleanup"] is True
    assert cleanup["owned_processes_exited"] is True


def test_incomplete_saved_inventory_cannot_answer_absence(tmp_path: Path) -> None:
    with SQLiteStore(tmp_path / "cases.db") as store:
        owner = investigator(store, reasoning=DeterministicReasoningProvider())
        state = owner.create(objective="Is sample.exe running right now?")
        _snapshot(  # pyright: ignore[reportPrivateUsage]
            store, state.case_id, processes=[], omitted=3, at=datetime.now(UTC)
        )
        state = state.model_copy(update={"completed_probe_ids": ("application.snapshot",)})

        assert owner._direct_process_state(state) is None  # pyright: ignore[reportPrivateUsage]


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
