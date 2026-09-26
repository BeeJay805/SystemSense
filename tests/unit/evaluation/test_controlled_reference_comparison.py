"""A frozen-menu comparator must not claim unobserved trajectory outcomes."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from benchmarks.controlled_reference_comparison import score_frozen_case
from systemsense.storage.candidate_decision_snapshots import CandidateDecisionSnapshotRepository
from systemsense.storage.sqlite_store import SQLiteStore
from tests.integration.synthetic_pilot_oracle import (
    PILOT_SCENARIOS,
    write_synthetic_recipe_binding,
)
from tests.unit.application.test_frontier_policy import CASE
from tests.unit.evaluation.test_frontier_pilot_export import (
    _fixture_worker_capture,  # pyright: ignore[reportPrivateUsage]
    _snapshots,  # pyright: ignore[reportPrivateUsage]
)


def test_same_menu_report_retains_unknowns_and_marks_unavailable_arms(tmp_path: Path) -> None:
    scenario = PILOT_SCENARIOS[1]
    binding = tmp_path / "hidden-recipe-binding.json"
    write_synthetic_recipe_binding(binding, str(CASE), scenario)
    with SQLiteStore(tmp_path / "case.db") as store:
        snapshot_id, uncaptured_id = _snapshots(store, laya=True)
        repository = CandidateDecisionSnapshotRepository(store)
        snapshot = repository.readback_frontier(snapshot_id)
        _attention, calls = _fixture_worker_capture(snapshot.request)
        repository.capture_frontier_worker_draft(snapshot_id, calls)

        report = score_frozen_case(store, str(CASE), scenario, binding_path=binding)

    assert report["scope"] == "frozen_menu_one_step_only"
    assert report["snapshot_count"] == 2
    assert report["compared_count"] == 1
    assert report["unscored"] == [{"snapshot_id": uncaptured_id, "reason": "capture_missing"}]
    assert report["actual_outcomes"] == {"unknown": 1}
    assert report["reference_outcomes"] == {"unknown": 1}
    assert report["known_pair_count"] == 0
    assert report["learning_candidate_count"] == 0
    assert report["training_admissible"] is False
    assert report["diagnostic_performance_admissible"] is False
    assert report["unavailable_arms"] == ["deep_only", "scout_off", "scout_on"]


def test_comparison_fails_closed_on_wrong_hidden_recipe_binding(tmp_path: Path) -> None:
    binding = tmp_path / "hidden-recipe-binding.json"
    write_synthetic_recipe_binding(binding, str(CASE), PILOT_SCENARIOS[0])
    with SQLiteStore(tmp_path / "case.db") as store:
        snapshot_id, _ = _snapshots(store, laya=True)
        repository = CandidateDecisionSnapshotRepository(store)
        snapshot = repository.readback_frontier(snapshot_id)
        _attention, calls = _fixture_worker_capture(snapshot.request)
        repository.capture_frontier_worker_draft(snapshot_id, calls)

        with pytest.raises(ValueError, match="hidden recipe binding"):
            score_frozen_case(store, str(CASE), PILOT_SCENARIOS[2], binding_path=binding)


def test_comparison_requires_at_least_one_captured_model_decision(tmp_path: Path) -> None:
    binding = tmp_path / "hidden-recipe-binding.json"
    write_synthetic_recipe_binding(binding, str(CASE), PILOT_SCENARIOS[0])
    with SQLiteStore(tmp_path / "case.db") as store:
        _snapshots(store, laya=True)

        with pytest.raises(ValueError, match="no exact Laya capture"):
            score_frozen_case(store, str(CASE), PILOT_SCENARIOS[0], binding_path=binding)


def test_cli_reads_exact_database_without_changing_source(tmp_path: Path) -> None:
    database = tmp_path / "case.db"
    binding = tmp_path / "hidden-recipe-binding.json"
    write_synthetic_recipe_binding(binding, str(CASE), PILOT_SCENARIOS[1])
    with SQLiteStore(database) as store:
        snapshot_id, _ = _snapshots(store, laya=True)
        repository = CandidateDecisionSnapshotRepository(store)
        snapshot = repository.readback_frontier(snapshot_id)
        _attention, calls = _fixture_worker_capture(snapshot.request)
        repository.capture_frontier_worker_draft(snapshot_id, calls)
    original_sha256 = hashlib.sha256(database.read_bytes()).hexdigest()
    root = Path(__file__).resolve().parents[3]
    existing_pythonpath = os.environ.get("PYTHONPATH", "")
    completed = subprocess.run(
        [
            sys.executable,
            "-m",
            "benchmarks.controlled_reference_comparison",
            "--database",
            str(database),
            "--case-id",
            str(CASE),
            "--scenario",
            "healthy_control",
            "--binding",
            str(binding),
        ],
        cwd=root,
        env={
            **os.environ,
            "PYTHONPATH": str(root / "src") + os.pathsep + existing_pythonpath,
        },
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )

    assert completed.returncode == 0, completed.stderr
    assert completed.stdout.strip()
    report = json.loads(completed.stdout)
    assert report["scope"] == "frozen_menu_one_step_only"
    assert report["snapshot_count"] == 2
    assert report["compared_count"] == 1
    assert report["actual_outcomes"] == {"unknown": 1}
    assert report["training_admissible"] is False
    assert hashlib.sha256(database.read_bytes()).hexdigest() == original_sha256
